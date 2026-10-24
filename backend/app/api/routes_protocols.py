"""Protocol session endpoints (docs/PROTOCOLS.md §5).

Five pages - Email, SSH, FTP, VoIP, SMB - are one query with a different
``protocol IN (...)`` filter, so this router serves all of them:

* ``GET  /api/analyses/{id}/protocols``            - sessions, filtered and paged
* ``GET  /api/analyses/{id}/protocols/summary``    - per-family totals for page headers
* ``GET  /api/analyses/{id}/protocols/{session_id}`` - one session
* ``POST /api/analyses/{id}/protocols/rescan``     - re-run the extraction

Nothing is inferred here: every row was produced by the extractor from TShark's own
dissection, and ``extracted`` says whether the capture has been through that stage at
all, so an empty page is never presented as a clean one.
"""

from __future__ import annotations

import json
import time
from typing import Any

from fastapi import APIRouter, Depends, Query

from app.api.deps import Pagination, get_ready_analysis, pagination
from app.core.errors import not_found, unprocessable
from app.core.logging import get_logger
from app.db import database as db
from app.services import protocol_analyzer
from app.services.jobs import jobs

log = get_logger("shadowpackets.api.protocols")

router = APIRouter(prefix="/api/analyses/{analysis_id}", tags=["protocols"])

FAMILIES = protocol_analyzer.FAMILIES
PROTOCOLS = protocol_analyzer.PROTOCOLS
SERVER_PORTS = protocol_analyzer.SERVER_PORTS
SESSION_CAP = protocol_analyzer.SESSION_CAP

DEFAULT_PAGE_SIZE = 100
MAX_SEARCH = 200

# Client-supplied sort keys mapped onto fixed SQL expressions. §5.1 pairs the key with
# an explicit direction: ``sort`` selects the allow-listed column and ``order`` the
# direction, defaulting to ``desc`` so the newest session comes first.
SORTABLE: dict[str, str] = {
    "start_time": "start_time",
    "bytes": "bytes",
    "packets": "packets",
    "duration": "duration",
}
DEFAULT_SORT = "start_time"

# §5.1: ``extracted`` says whether the analysis has actually been through the protocol
# stage. The stage records that itself (`protocol_analyzer.stage_ran`), so a build date
# - which cannot know whether this installation ran the stage - is never consulted.

# One sentence per family stating what the section is and what it is not (§5.1).
FAMILY_NOTES: dict[str, str] = {
    "email": (
        "Email sessions are the verbs, reply codes, identities and envelope addresses "
        "TShark dissected on the wire: message bodies are never copied, and an "
        "implicit-TLS mailbox (SMTPS/POP3S/IMAPS) is recorded as a TLS session rather "
        "than here."
    ),
    "ssh": (
        "SSH sessions are the identification banners, the algorithms offered before "
        "encryption began and a histogram of message types - every payload after the "
        "key exchange is encrypted and is not decrypted."
    ),
    "ftp": (
        "FTP sessions describe the control connection only: verbs, reply codes, "
        "identities and the names of files requested, never file contents, and each "
        "data connection is counted rather than followed."
    ),
    "voip": (
        "VoIP rows record SIP signalling and the RTP/RTCP media the dissector "
        "recognised: a media stream is not a call, a payload type is not translated "
        "into a codec, and no audio is extracted."
    ),
    "smb": (
        "SMB sessions are the commands, dialects, shares, file names and NT statuses "
        "TShark dissected; anything behind SMB signing or SMB3 encryption is not "
        "decrypted, so such a session shows endpoints, times and volume only."
    ),
}

GENERAL_NOTE = (
    "These rows report what TShark dissected in each protocol stream - commands, "
    "codes, identities, names, banners and algorithms - never payload contents or "
    "password values, and a protocol the dissector did not recognise on a "
    "non-standard port appears as no session at all."
)


def _escapable(value: str) -> str:
    """Escape LIKE wildcards so a literal ``%`` does not widen a search."""
    return value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def _like(value: str) -> str:
    return f"%{_escapable(value.strip())}%"


def _split_values(values: list[str] | None) -> list[str]:
    """Accept both ``?protocol=smtp&protocol=imap`` and ``?protocol=smtp,imap``."""
    out: list[str] = []
    for value in values or []:
        for part in str(value).split(","):
            text = part.strip().lower()
            if text and text not in out:
                out.append(text)
    return out


def _resolve_protocols(
    protocol: list[str] | None, family: str | None
) -> tuple[list[str], str | None]:
    """The effective protocol filter, in canonical (family) order.

    ``family`` is shorthand for that family's protocols; when both are given the
    explicit list is filtered to the family (so a page can narrow its own family), and
    an empty intersection is a validation error rather than a silently empty page.
    """
    requested = _split_values(protocol)
    family_name: str | None = None

    if family is not None:
        family_name = family.strip().lower()
        if family_name not in FAMILIES:
            raise unprocessable(
                "validation_error",
                f"Unknown family '{family}'.",
                {"allowed": sorted(FAMILIES)},
            )

    unknown = [name for name in requested if name not in PROTOCOLS]
    if unknown:
        raise unprocessable(
            "validation_error",
            f"Unknown protocol '{unknown[0]}'.",
            {"allowed": list(PROTOCOLS)},
        )

    if family_name is not None and requested:
        allowed = set(FAMILIES[family_name])
        selected = [name for name in requested if name in allowed]
        if not selected:
            raise unprocessable(
                "validation_error",
                f"None of {requested} belongs to the '{family_name}' family.",
                {"family": family_name, "protocols": list(FAMILIES[family_name])},
            )
    elif family_name is not None:
        selected = list(FAMILIES[family_name])
    elif requested:
        selected = list(requested)
    else:
        selected = list(PROTOCOLS)

    ordered = [name for name in PROTOCOLS if name in set(selected)]
    return ordered, family_name


def _resolve_sort(sort: str | None) -> str:
    key = (sort or DEFAULT_SORT).strip().lower()
    if key.startswith("-"):
        key = key[1:]
    if key not in SORTABLE:
        raise unprocessable(
            "validation_error",
            f"Cannot sort by '{sort}'.",
            {"allowed": sorted(SORTABLE)},
        )
    return SORTABLE[key]


def _resolve_order(order: str | None) -> str:
    """§5.1: ``asc`` or ``desc``, anything else a validation error, ``desc`` by default."""
    value = (order or "desc").strip().lower()
    if value not in {"asc", "desc"}:
        raise unprocessable(
            "validation_error",
            f"Unknown order '{order}'.",
            {"allowed": ["asc", "desc"]},
        )
    return value.upper()


def _check_search(q: str | None) -> str | None:
    if q is None:
        return None
    text = q.strip()
    if not text:
        raise unprocessable(
            "validation_error", "The search text must not be empty.", {"q": q}
        )
    if len(text) > MAX_SEARCH:
        raise unprocessable(
            "validation_error",
            f"The search text must be at most {MAX_SEARCH} characters.",
            {"q": q, "max_length": MAX_SEARCH},
        )
    return text


def _conditions(
    *,
    protocols: list[str],
    search: str | None,
    flagged: bool,
) -> tuple[list[str], list[Any]]:
    clauses = [f"protocol IN ({', '.join('?' for _ in protocols)})"]
    params: list[Any] = list(protocols)

    if search is not None:
        needle = _like(search)
        # The endpoint columns plus the detail JSON, which is where server names, file
        # names, paths, usernames and command arguments live.
        clauses.append(
            "(client_ip LIKE ? ESCAPE '\\' OR server_ip LIKE ? ESCAPE '\\' "
            "OR CAST(client_port AS TEXT) LIKE ? ESCAPE '\\' "
            "OR CAST(server_port AS TEXT) LIKE ? ESCAPE '\\' "
            "OR detail LIKE ? ESCAPE '\\' OR note LIKE ? ESCAPE '\\')"
        )
        params.extend([needle] * 6)

    if flagged:
        clauses.append("flags IS NOT NULL AND flags <> '[]'")

    return clauses, params


def _serialise(row) -> dict[str, Any]:
    """Row -> JSON-safe dict with ``detail`` and ``flags`` decoded."""
    data = dict(row)
    data["detail"] = _json_object(data.get("detail"))
    data["flags"] = _json_list(data.get("flags"))
    data["family"] = protocol_analyzer.PROTOCOL_FAMILY.get(data.get("protocol") or "", None)
    return data


def _json_object(raw: Any) -> dict:
    if isinstance(raw, dict):
        return raw
    if not isinstance(raw, str) or not raw:
        return {}
    try:
        value = json.loads(raw)
    except (json.JSONDecodeError, TypeError):
        return {}
    return value if isinstance(value, dict) else {}


def _json_list(raw: Any) -> list:
    if isinstance(raw, list):
        return raw
    if not isinstance(raw, str) or not raw:
        return []
    try:
        value = json.loads(raw)
    except (json.JSONDecodeError, TypeError):
        return []
    return [str(item) for item in value] if isinstance(value, list) else []


def _extracted(analysis_id: str) -> tuple[bool, int]:
    """``(extracted, stored_rows)`` for §5.1's honest-empty-page rule.

    The stage's own record decides it: with the record present the capture has been read
    for these protocols, so zero rows is a real, clean zero; without it the capture may
    never have been read at all, and the page offers the rescan instead of implying the
    capture held nothing.
    """
    total_row = db.query_one(
        "SELECT COUNT(*) AS n FROM protocol_sessions WHERE analysis_id = ?",
        (analysis_id,),
    )
    stored = int(total_row["n"]) if total_row else 0
    return protocol_analyzer.stage_ran(analysis_id), stored


def _family_note(family_name: str | None) -> str:
    if family_name is not None:
        return FAMILY_NOTES[family_name]
    return GENERAL_NOTE


# --------------------------------------------------------------------------
# list
# --------------------------------------------------------------------------

@router.get("/protocols")
def list_protocol_sessions(
    analysis_id: str,
    protocol: list[str] | None = Query(
        None, description="One protocol, repeated, or comma-separated"
    ),
    family: str | None = Query(None, description="email, ssh, ftp, voip or smb"),
    q: str | None = Query(None, description="Substring over endpoints, names, paths and args"),
    flagged: bool = Query(False, description="Only sessions carrying at least one flag"),
    sort: str | None = Query(None, description="start_time, bytes, packets or duration"),
    order: str | None = Query(
        None, description="Sort direction: desc (the default, newest first) or asc"
    ),
    page: Pagination = Depends(pagination),
) -> dict:
    """One page of protocol sessions, with the counts that describe the whole filter."""
    get_ready_analysis(analysis_id)      # 404 / 409 gate; the row itself is not needed
    protocols, family_name = _resolve_protocols(protocol, family)
    search = _check_search(q)
    sort_sql = _resolve_sort(sort)
    direction = _resolve_order(order)

    clauses, params = _conditions(protocols=protocols, search=search, flagged=flagged)
    where = " AND ".join(["analysis_id = ?", *clauses])
    values: list[Any] = [analysis_id, *params]

    totals = db.query_one(
        f"""
        SELECT COUNT(*) AS sessions,
               SUM(CASE WHEN flags IS NOT NULL AND flags <> '[]' THEN 1 ELSE 0 END) AS flagged,
               COALESCE(SUM(bytes), 0)  AS bytes,
               COALESCE(SUM(packets), 0) AS packets,
               MIN(start_time)          AS first_seen,
               MAX(end_time)            AS last_seen
          FROM protocol_sessions
         WHERE {where}
        """,
        values,
    )
    data = dict(totals) if totals else {}
    total = int(data.get("sessions") or 0)

    by_protocol = {
        row["protocol"]: int(row["n"])
        for row in db.query_all(
            f"""
            SELECT protocol, COUNT(*) AS n
              FROM protocol_sessions
             WHERE {where}
             GROUP BY protocol
             ORDER BY protocol ASC
            """,
            values,
        )
    }

    # §6: at most SESSION_CAP rows are read for one request, and a read cut by that cap
    # is reported rather than silently dropped.
    capped = total > SESSION_CAP
    offset = page.offset
    limit = min(page.page_size, max(0, SESSION_CAP - offset))
    rows = []
    if limit > 0:
        rows = db.query_all(
            f"""
            SELECT * FROM protocol_sessions
             WHERE {where}
             ORDER BY {sort_sql} {direction}, id {direction}
             LIMIT ? OFFSET ?
            """,
            [*values, limit, offset],
        )

    extracted, stored = _extracted(analysis_id)

    return {
        "analysis_id": analysis_id,
        "generated_at": time.time(),
        "family": family_name,
        "protocols": protocols,
        "total": total,
        "page": page.page,
        "page_size": page.page_size,
        "counts": {
            "by_protocol": by_protocol,
            "sessions": total,
            "flagged": int(data.get("flagged") or 0),
            "bytes": int(data.get("bytes") or 0),
            "packets": int(data.get("packets") or 0),
            "first_seen": data.get("first_seen"),
            "last_seen": data.get("last_seen"),
        },
        "note": _family_note(family_name),
        "extracted": extracted,
        "session_cap": SESSION_CAP,
        "capped": capped,
        "stored_rows": stored,
        "rows": [_serialise(row) for row in rows],
    }


# --------------------------------------------------------------------------
# summary
# --------------------------------------------------------------------------

@router.get("/protocols/summary")
def protocols_summary(analysis_id: str) -> dict:
    """Per-family totals, so a nav entry can show whether its protocol is present."""
    get_ready_analysis(analysis_id)

    rows = db.query_all(
        """
        SELECT protocol,
               COUNT(*)                 AS sessions,
               SUM(CASE WHEN flags IS NOT NULL AND flags <> '[]' THEN 1 ELSE 0 END) AS flagged,
               COALESCE(SUM(bytes), 0)  AS bytes,
               COALESCE(SUM(packets), 0) AS packets,
               MIN(start_time)          AS first_seen,
               MAX(end_time)            AS last_seen
          FROM protocol_sessions
         WHERE analysis_id = ?
         GROUP BY protocol
        """,
        (analysis_id,),
    )
    by_protocol = {row["protocol"]: dict(row) for row in rows}

    families: dict[str, dict] = {}
    for family_name, protocols in FAMILIES.items():
        sessions = flagged = bytes_total = packets = 0
        first_seen: float | None = None
        last_seen: float | None = None
        for name in protocols:
            row = by_protocol.get(name)
            if row is None:
                continue
            sessions += int(row["sessions"] or 0)
            flagged += int(row["flagged"] or 0)
            bytes_total += int(row["bytes"] or 0)
            packets += int(row["packets"] or 0)
            if row["first_seen"] is not None:
                first_seen = row["first_seen"] if first_seen is None else min(first_seen, row["first_seen"])
            if row["last_seen"] is not None:
                last_seen = row["last_seen"] if last_seen is None else max(last_seen, row["last_seen"])
        families[family_name] = {
            "protocols": list(protocols),
            "sessions": sessions,
            "flagged": flagged,
            "bytes": bytes_total,
            "packets": packets,
            "first_seen": first_seen,
            "last_seen": last_seen,
        }

    extracted, stored = _extracted(analysis_id)
    return {
        "analysis_id": analysis_id,
        "generated_at": time.time(),
        "extracted": extracted,
        "stored_rows": stored,
        "families": families,
        "note": GENERAL_NOTE,
    }


# --------------------------------------------------------------------------
# detail
# --------------------------------------------------------------------------

@router.get("/protocols/{session_id}")
def protocol_session_detail(analysis_id: str, session_id: int) -> dict:
    """One session: every stored column, its decoded detail, flags and where to look."""
    get_ready_analysis(analysis_id)
    row = db.query_one(
        "SELECT * FROM protocol_sessions WHERE analysis_id = ? AND id = ?",
        (analysis_id, session_id),
    )
    if row is None:
        raise not_found(
            "session_not_found",
            f"No protocol session {session_id} in this analysis.",
            {"session_id": session_id, "analysis_id": analysis_id},
        )

    data = _serialise(row)
    first_frame = data.get("first_frame")
    last_frame = data.get("last_frame")
    family_name = data.get("family")
    stream_id = data.get("stream_id")

    # The same shape every other pivot in this application uses: client routes, so a
    # reader can go from a session to its frames and to the page that lists its peers.
    links: list[dict] = []
    if first_frame is not None:
        links.append({"to": f"/packets?sel={first_frame}", "label": "first frame"})
    if last_frame is not None and last_frame != first_frame:
        links.append({"to": f"/packets?sel={last_frame}", "label": "last frame"})
    if stream_id is not None:
        links.append(
            {"to": f"/packets?mode=basic&stream_id={stream_id}", "label": f"stream {stream_id}"}
        )
    if family_name in protocol_analyzer.PAGE_BY_FAMILY:
        links.append(
            {
                "to": protocol_analyzer.PAGE_BY_FAMILY[family_name],
                "label": f"all {family_name} sessions",
            }
        )

    return {
        **data,
        "frame_numbers": {"first": first_frame, "last": last_frame},
        "links": links,
    }


# --------------------------------------------------------------------------
# rescan
# --------------------------------------------------------------------------

@router.post("/protocols/rescan", status_code=202)
def rescan_protocols(analysis_id: str) -> dict:
    """Re-run the extraction for a capture that is already indexed.

    Existing analyses were indexed before this stage existed and hold no rows (§2), so
    the page offers this rather than reporting an empty capture as a clean one. The
    extraction itself clears only ``protocol_sessions``; the job row and the analysis
    status are the job system's bookkeeping, exactly as they are for a full analysis.
    """
    from app.api.deps import capture_path

    row = get_ready_analysis(analysis_id)
    capture = capture_path(row)

    def worker(ctx) -> None:
        protocol_analyzer.analyze(ctx, analysis_id, capture)
        # The Dashboard's cached aggregates were read from these tables; the rescan
        # has just rewritten them, so the next summary request must recompute.
        from app.api.routes_analyses import clear_summary_cache

        clear_summary_cache(analysis_id)

    job_id = jobs.submit(analysis_id, worker, kind="protocol_rescan")
    log.info("queued protocol rescan %s for analysis %s", job_id, analysis_id)
    return {
        "analysis_id": analysis_id,
        "job_id": job_id,
        "kind": "protocol_rescan",
        "status": "queued",
    }


__all__ = [
    "FAMILIES",
    "GENERAL_NOTE",
    "PROTOCOLS",
    "SERVER_PORTS",
    "SORTABLE",
    "router",
]
