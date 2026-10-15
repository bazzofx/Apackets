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
    if reveal:
        # Placed after the preview so the two can be compared in one glance.
        data["value"] = row["value"]
    return data


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


def _grouped(where: str, params: list[Any], column: str) -> list[Any]:
    return db.query_all(
        f"SELECT {column} AS name, COUNT(*) AS n FROM credentials"
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

    total_row = db.query_one(f"SELECT COUNT(*) AS n FROM credentials WHERE {where}", params)
    total = int(total_row["n"]) if total_row else 0

    rows = db.query_all(
        f"SELECT * FROM credentials WHERE {where}"
        f" ORDER BY {sort_sql} {direction}, id {direction} LIMIT ? OFFSET ?",
        [*params, page.limit, page.offset],
    )

    body = page.envelope([_item(row, reveal=reveal) for row in rows], total)
    body.update(
        {
            "analysis_id": analysis_id,
            "generated_at": time.time(),
            "reveal": reveal,
            "counts": {
                "total": total,
                "by_kind": _complete_counts(_grouped(where, params, "kind"), ca.KINDS),
                "by_confidence": _complete_counts(
                    _grouped(where, params, "confidence"), ca.CONFIDENCE_LEVELS
                ),
            },
            "scan": ca.scan_state(analysis_id),
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

    total_row = db.query_one(f"SELECT COUNT(*) AS n FROM credentials WHERE {where}", params)
    total = int(total_row["n"]) if total_row else 0

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
    stream_ids = sorted(
        {row["stream_id"] for row in db.query_all(
            f"SELECT DISTINCT stream_id FROM credentials WHERE {where}", params
        )},
        key=lambda value: (value is None, value),
    )

    by_kind = _complete_counts(_grouped(where, params, "kind"), ca.KINDS)
    by_protocol = _complete_counts(_grouped(where, params, "protocol"), ca.PROTOCOLS)
    by_confidence = _complete_counts(_grouped(where, params, "confidence"), ca.CONFIDENCE_LEVELS)

    return {
        "analysis_id": analysis_id,
        "generated_at": time.time(),
        "total": total,
        "by_kind": by_kind,
        "by_protocol": by_protocol,
        "by_confidence": by_confidence,
        "high_confidence": by_confidence.get("high", 0),
        # §8.2 asks for "the streams involved" and leaves the shape open. The count
        # is what a page header states; the ids and the per-stream breakdown are
        # here because they are what makes the count answerable.
        "streams": len(stream_ids),
        "stream_count": len(stream_ids),
        "stream_ids": stream_ids,
        "stream_details": streams,
        "scan": ca.scan_state(analysis_id),
        "note": NOTE,
        "limits": list(ca.CONTRACT_NOTES),
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
