"""Credential endpoints (docs/CREDENTIALS.md §8).

Three routes serve the one table the scanner writes:

* ``GET  /api/analyses/{id}/credentials``          - findings, filtered and paged
* ``GET  /api/analyses/{id}/credentials/summary``  - counts and streams, no values
* ``POST /api/analyses/{id}/credentials/scan``     - re-run the scan as a job

Redaction is decided here, not by the client: the stored ``value`` column is
dropped from every item unless the request asks for it with ``reveal=1`` (§5), and
the summary route drops ``value_preview`` as well, so a page that only draws a
chart never receives a credential's characters. The ``scan`` block travels with
both read routes because an empty list means one of two very different things —
"the capture carried none" or "the scan is switched off" — and §10 requires the
page to be able to say which.
"""

from __future__ import annotations

import time
from typing import Any

from fastapi import APIRouter, Depends, Query

from app.api.deps import (
    MAX_PAGE_SIZE,
    Pagination,
    capture_path,
    get_ready_analysis,
    resolve_order,
    resolve_sort,
)
from app.core import runtime_settings
from app.core.errors import conflict, unprocessable
from app.core.logging import get_logger
from app.db import database as db
from app.services import credential_analyzer as ca
from app.services.jobs import jobs

log = get_logger("apackets.api.credentials")

router = APIRouter(prefix="/api/analyses/{analysis_id}", tags=["credentials"])

DEFAULT_PAGE_SIZE = 50          # §8.1: a credential page is read, not scrolled
DEFAULT_SORT = "confidence"

#: ``sort`` -> the SQL expression. §8.1's four keys, nothing interpolated: the
#: confidence expression is inverted (high is the largest) so that the default
#: ``desc`` means "highest confidence first", which is the order a reader wants.
SORTABLE: dict[str, str] = {
    "confidence": (
        "CASE confidence WHEN 'high' THEN 3 WHEN 'medium' THEN 2 WHEN 'low' THEN 1 ELSE 0 END"
    ),
    "kind": "kind",
    "protocol": "protocol",
    "created_at": "created_at",
}

#: §8.1's item, in the contract's own order. Written out rather than returned as
#: a row, because "the full value is not present anywhere in the JSON" has to be
#: a property of this function rather than of a client's discipline.
ITEM_COLUMNS: tuple[str, ...] = (
    "id", "kind", "value_preview", "value_length", "value_truncated",
    "protocol", "transport", "stream_id", "direction", "location",
    "source_field", "method", "confidence",
    "client_ip", "client_port", "server_ip", "server_port",
    "packet_first", "packet_last", "evidence", "note", "created_at",
)

NOTE = (
    "These rows are the cleartext credentials the capture carried in locations the "
    "dissectors decoded — the HTTP request line, headers and body, and the FTP, SMTP, "
    "POP3 and IMAP authentication commands. A finding is a lead: a value in a field "
    "called 'password' is a credential the wire carried, not proof that it worked or "
    "that it is current. Anything encrypted is not examined at all, so nothing here "
    "implies a TLS, SSH or STARTTLS session holds no credentials; only what the HTTP "
    "and protocol analysers kept can be found; and a value a scanner reports is a "
    "shape, not a validity check."
)


# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------

def page_params(
    page: int = Query(1, ge=1, description="1-based page number"),
    page_size: int = Query(
        DEFAULT_PAGE_SIZE, ge=1, le=MAX_PAGE_SIZE, description="Rows per page"
    ),
) -> Pagination:
    """§8.1's paging, with this router's own default page size of fifty."""
    return Pagination(page=page, page_size=page_size)


def _item(row: Any, *, reveal: bool) -> dict:
    """One stored row as §8.1's item, with the value withheld unless asked for."""
    data = {column: row[column] for column in ITEM_COLUMNS}
    data["value_truncated"] = bool(data.get("value_truncated"))
    # The unique view adds what the grouping knew: how many times the value was
    # seen and where, so one row can stand for several occurrences without
    # pretending there was only one.
    keys = row.keys() if hasattr(row, "keys") else ()
    for extra in ("occurrences", "stream_ids", "protocols", "locations"):
        if extra in keys:
            data[extra] = row[extra]
    if reveal:
        # Placed after the preview so the two can be compared in one glance.
        data["value"] = row["value"]
    return data


def _text_list(raw: Any) -> list[str]:
    """``GROUP_CONCAT(DISTINCT x)`` back to a list, in a stable order."""
    if not isinstance(raw, str) or not raw:
        return []
    return sorted({part for part in raw.split(",") if part})


def _int_list(raw: Any) -> list[int]:
    out: list[int] = []
    for part in _text_list(raw):
        try:
            out.append(int(part))
        except ValueError:  # pragma: no cover - the column is an integer
            continue
    return out


def _unique_total(where: str, params: list[Any]) -> int:
    """How many distinct (kind, value) pairs the filter selects."""
    row = db.query_one(
        f"SELECT COUNT(*) AS n FROM (SELECT 1 FROM credentials WHERE {where} GROUP BY kind, value)",
        params,
    )
    return int(row["n"]) if row else 0


def _unique_page(
    where: str,
    params: list[Any],
    *,
    sort_sql: str,
    direction: str,
    limit: int,
    offset: int,
) -> list[dict]:
    """One page of **distinct values**, each carrying the evidence that supports it.

    A credential is the value; the streams it crossed are where it was seen. This
    project's own lab capture authenticates seven times with one username and one
    password, and seven identical rows is not seven credentials — it is one
    credential seen seven times, which is what the row now says with
    ``occurrences`` and ``stream_ids``.

    The stored rows are untouched: every occurrence stays in ``credentials`` as the
    evidence a finding is answerable to, and this view is a projection of them. The
    representative row is the earliest occurrence, so the value, preview, method and
    source field shown are a real row's own rather than a mixture.
    """
    groups = db.query_all(
        f"""
        SELECT kind, value, MIN(id) AS id, COUNT(*) AS occurrences,
               MIN(stream_id) AS stream_id,
               MIN(packet_first) AS packet_first, MAX(packet_last) AS packet_last,
               GROUP_CONCAT(DISTINCT stream_id) AS stream_ids,
               GROUP_CONCAT(DISTINCT protocol) AS protocols,
               GROUP_CONCAT(DISTINCT location) AS locations
          FROM credentials
         WHERE {where}
         GROUP BY kind, value
         ORDER BY MAX({sort_sql}) {direction}, kind ASC, value ASC
         LIMIT ? OFFSET ?
        """,
        [*params, limit, offset],
    )
    if not groups:
        return []

    ids = [int(group["id"]) for group in groups]
    placeholders = ", ".join("?" for _ in ids)
    representatives = {
        int(row["id"]): row
        for row in db.query_all(f"SELECT * FROM credentials WHERE id IN ({placeholders})", ids)
    }

    items: list[dict] = []
    for group in groups:
        row = representatives.get(int(group["id"]))
        if row is None:  # pragma: no cover - the row would have to vanish mid-request
            continue
        merged = dict(row)
        merged["value"] = group["value"]
        merged["occurrences"] = int(group["occurrences"])
        merged["stream_ids"] = _int_list(group["stream_ids"])
        merged["protocols"] = _text_list(group["protocols"])
        merged["locations"] = _text_list(group["locations"])
        items.append(merged)
    return items


def _filters(
    analysis_id: str,
    *,
    kind: str | None,
    protocol: str | None,
    confidence: str | None,
    stream_id: int | None,
) -> tuple[str, list[Any]]:
    where = ["analysis_id = ?"]
    params: list[Any] = [analysis_id]

    if kind:
        name = kind.strip().lower()
        if name not in ca.KINDS:
            raise unprocessable(
                "validation_error", f"Unknown credential kind '{kind}'.", {"allowed": list(ca.KINDS)}
            )
        where.append("kind = ?")
        params.append(name)

    if protocol:
        name = protocol.strip().lower()
        if name not in ca.PROTOCOLS:
            raise unprocessable(
                "validation_error",
                f"Unknown protocol '{protocol}'.",
                {"allowed": list(ca.PROTOCOLS)},
            )
        where.append("protocol = ?")
        params.append(name)

    if confidence:
        level = confidence.strip().lower()
        if level not in ca.CONFIDENCE_LEVELS:
            raise unprocessable(
                "validation_error",
                f"Unknown confidence '{confidence}'.",
                {"allowed": list(ca.CONFIDENCE_LEVELS)},
            )
        where.append("confidence = ?")
        params.append(level)

    if stream_id is not None:
        where.append("stream_id = ?")
        params.append(stream_id)

    return " AND ".join(where), params


def _complete_counts(rows: list[Any], keys: tuple[str, ...]) -> dict[str, int]:
    """A count map with every key present, so a chart never has a hole in it."""
    counts = {key: 0 for key in keys}
    for row in rows:
        counts[str(row["name"])] = int(row["n"])
    return counts


def _grouped(where: str, params: list[Any], column: str, *, distinct: bool = False) -> list[Any]:
    """Counts per ``column``.

    ``distinct`` counts distinct **values** rather than stored rows, so the map
    beside a unique listing agrees with the listing: seven occurrences of one
    username are one username, not seven.
    """
    counted = "COUNT(DISTINCT value)" if distinct else "COUNT(*)"
    return db.query_all(
        f"SELECT {column} AS name, {counted} AS n FROM credentials"
        f" WHERE {where} GROUP BY {column} ORDER BY n DESC, name ASC",
        params,
    )


# --------------------------------------------------------------------------
# §8.1 list
# --------------------------------------------------------------------------

@router.get("/credentials")
def list_credentials(
    analysis_id: str,
    kind: str | None = Query(None, description="One of the stored kinds"),
    protocol: str | None = Query(None, description="http, ftp, smtp, pop3 or imap"),
    confidence: str | None = Query(None, description="high, medium or low"),
    stream_id: int | None = Query(None, ge=0, description="Only this stream"),
    unique: bool = Query(
        True,
        description=(
            "One row per distinct (kind, value) — the default — or every occurrence "
            "with unique=0"
        ),
    ),
    reveal: bool = Query(
        False, description="Include the full value; without it only a redacted preview is served"
    ),
    sort: str | None = Query(None, description="confidence, kind, protocol or created_at"),
    order: str | None = Query(None, description="Sort direction: desc (the default) or asc"),
    page: Pagination = Depends(page_params),
) -> dict:
    """One page of findings, with the counts that describe the whole filter."""
    get_ready_analysis(analysis_id)      # 404 / 409 gate; the row itself is not needed

    where, params = _filters(
        analysis_id,
        kind=kind,
        protocol=protocol,
        confidence=confidence,
        stream_id=stream_id,
    )
    sort_sql = resolve_sort(sort, SORTABLE, SORTABLE[DEFAULT_SORT])
    direction = resolve_order(order, "desc")

    if unique:
        total = _unique_total(where, params)
        rows = _unique_page(
            where,
            params,
            sort_sql=sort_sql,
            direction=direction,
            limit=page.limit,
            offset=page.offset,
        )
    else:
        total_row = db.query_one(f"SELECT COUNT(*) AS n FROM credentials WHERE {where}", params)
        total = int(total_row["n"]) if total_row else 0
        rows = [
            dict(row)
            for row in db.query_all(
                f"SELECT * FROM credentials WHERE {where}"
                f" ORDER BY {sort_sql} {direction}, id {direction} LIMIT ? OFFSET ?",
                [*params, page.limit, page.offset],
            )
        ]

    body = page.envelope([_item(row, reveal=reveal) for row in rows], total)
    scan = ca.scan_state(analysis_id)
    body.update(
        {
            "analysis_id": analysis_id,
            "generated_at": time.time(),
            "reveal": reveal,
            "unique": unique,
            # §8.1: whether MAX_FINDINGS stopped the stage storing everything it
            # matched, so a short list is never read as the whole truth.
            "capped": scan["capped"],
            "counts": {
                "total": total,
                "by_kind": _complete_counts(
                    _grouped(where, params, "kind", distinct=unique), ca.KINDS
                ),
                "by_confidence": _complete_counts(
                    _grouped(where, params, "confidence", distinct=unique),
                    ca.CONFIDENCE_LEVELS,
                ),
                # The number of stored occurrences behind those distinct values, so
                # "one credential seen seven times" can be told from "one credential".
                "occurrences": int(
                    (
                        db.query_one(
                            f"SELECT COUNT(*) AS n FROM credentials WHERE {where}", params
                        )
                        or {"n": 0}
                    )["n"]
                ),
            },
            "scan": scan,
            "note": NOTE,
        }
    )
    return body


# --------------------------------------------------------------------------
# §8.2 summary
# --------------------------------------------------------------------------

@router.get("/credentials/summary")
def credentials_summary(analysis_id: str) -> dict:
    """Counts by kind, protocol and confidence, the streams involved, and the scan state.

    No values at all appear in this response, not even previews: it exists so a
    page can describe a capture's credentials without any of them reaching a
    screen or a log.
    """
    get_ready_analysis(analysis_id)

    where = "analysis_id = ?"
    params: list[Any] = [analysis_id]

    # The headline figures count **distinct values**, matching the default listing:
    # one username used seven times is one credential seen seven times, and
    # ``occurrences`` carries the seven so the difference stays visible rather than
    # being averaged away.
    total = _unique_total(where, params)
    occurrence_row = db.query_one(f"SELECT COUNT(*) AS n FROM credentials WHERE {where}", params)
    occurrences = int(occurrence_row["n"]) if occurrence_row else 0

    streams = [
        {
            "stream_id": row["stream_id"],
            "protocol": row["protocol"],
            "findings": int(row["n"]),
        }
        for row in db.query_all(
            f"""
            SELECT stream_id, protocol, COUNT(*) AS n
              FROM credentials
             WHERE {where}
             GROUP BY stream_id, protocol
             ORDER BY n DESC, protocol ASC, stream_id ASC
            """,
            params,
        )
    ]

    by_kind = _complete_counts(_grouped(where, params, "kind", distinct=True), ca.KINDS)
    by_protocol = _complete_counts(_grouped(where, params, "protocol", distinct=True), ca.PROTOCOLS)
    by_confidence = _complete_counts(
        _grouped(where, params, "confidence", distinct=True), ca.CONFIDENCE_LEVELS
    )

    return {
        "analysis_id": analysis_id,
        "generated_at": time.time(),
        "total": total,
        "occurrences": occurrences,
        "by_kind": by_kind,
        "by_protocol": by_protocol,
        "by_confidence": by_confidence,
        "high_confidence": by_confidence.get("high", 0),
        # §8.2: ``streams`` is the per-(protocol, stream) breakdown, and
        # ``stream_count`` counts those pairs — one stream number carrying two
        # protocols is two sessions that happen to share a number, so it counts
        # twice.
        "streams": streams,
        "stream_count": len(streams),
        # §8.2's ``limits``: the caps that applied to this scan, in words, with the
        # ones that actually bit named by the run itself.
        "limits": ca.scan_limits(analysis_id),
        "scan": ca.scan_state(analysis_id),
        "note": NOTE,
    }


# --------------------------------------------------------------------------
# §8.3 rescan
# --------------------------------------------------------------------------

@router.post("/credentials/scan", status_code=202)
def scan_credentials(analysis_id: str) -> dict:
    """Re-run the credential scan for an already-analysed capture.

    The scan reads the rows the analysis already holds, so it needs no capture —
    but it is gated on the retained capture like every other rescan in this
    application, so a job queued from this route behaves exactly like one queued
    from the protocol page. When ``credential_scan_enabled`` is off the request is
    refused rather than queued, because the worker would decline to write anything
    and a 202 that produces nothing is a lie: the operator has to enable it first
    (§7).
    """
    row = get_ready_analysis(analysis_id)      # 404 / 409 gate
    if not runtime_settings.credential_scan_enabled():
        raise conflict(
            "credential_scan_disabled",
            "The credential scan is disabled by the setting 'credential_scan_enabled'; "
            "enable it in Settings before running a scan.",
            {"setting": "credential_scan_enabled", "analysis_id": analysis_id},
        )
    capture = capture_path(row)                # 410 when the capture is gone

    def worker(ctx) -> None:
        ca.analyze(ctx, analysis_id, capture)

    job_id = jobs.submit(analysis_id, worker, kind="credential_scan")
    log.info("queued credential scan %s for analysis %s", job_id, analysis_id)
    return {
        "analysis_id": analysis_id,
        "job_id": job_id,
        "kind": "credential_scan",
        "status": "queued",
    }


__all__ = ["DEFAULT_PAGE_SIZE", "DEFAULT_SORT", "ITEM_COLUMNS", "NOTE", "SORTABLE", "router"]
