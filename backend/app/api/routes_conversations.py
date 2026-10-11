"""Conversation and TCP stream endpoints.

Conversations come from the ``conversations`` table (derived from real frames in
``conversation_analyzer``); stream contents come from TShark's own ``follow``
reassembly via :mod:`app.services.stream_analyzer`.
"""

from __future__ import annotations

from typing import Literal

from fastapi import APIRouter, Depends, Query, Response

from app.api.deps import (
    Pagination,
    analysis_ready_row,
    pagination,
    resolve_order,
    resolve_sort,
)
from app.core.errors import bad_request
from app.core.logging import get_logger
from app.db import database as db
from app.services import stream_analyzer

log = get_logger("apackets.api.conversations")

router = APIRouter(prefix="/api/analyses/{analysis_id}", tags=["conversations"])

# Client-supplied sort keys mapped onto fixed SQL expressions — raw input never
# reaches the statement text.
SORTABLE = {
    "packets_total": "packets_total",
    "bytes_total": "bytes_total",
    "start_time": "start_time",
    "duration": "duration",
    "endpoint_a": "endpoint_a",
}
DEFAULT_SORT = "bytes_total"
DEFAULT_ORDER = "desc"

StreamMode = Literal["ascii", "hex", "raw"]


def _conditions(
    *,
    transport: str | None,
    ip: str | None,
    port: int | None,
    search: str | None,
) -> tuple[list[str], list]:
    clauses: list[str] = []
    params: list = []

    if transport:
        clauses.append("transport = ?")
        params.append(transport.lower())
    if ip:
        clauses.append("(ip_a = ? OR ip_b = ?)")
        params += [ip, ip]
    if port is not None:
        clauses.append("(port_a = ? OR port_b = ?)")
        params += [port, port]
    if search:
        needle = f"%{search}%"
        clauses.append(
            "(conv_id LIKE ? OR endpoint_a LIKE ? OR endpoint_b LIKE ? OR protocols LIKE ?)"
        )
        params += [needle, needle, needle, needle]

    return clauses, params


@router.get("/conversations")
def list_conversations(
    analysis_id: str,
    transport: str | None = Query(None, pattern="^(tcp|udp)$"),
    ip: str | None = None,
    port: int | None = Query(None, ge=0, le=65535),
    search: str | None = None,
    sort: str | None = None,
    order: str | None = None,
    page: Pagination = Depends(pagination),
) -> dict:
    """Paginated conversations, with ``total_bytes`` over the whole analysis."""
    analysis_ready_row(analysis_id)

    order_sql = resolve_sort(sort, SORTABLE, DEFAULT_SORT)
    direction = resolve_order(order, DEFAULT_ORDER)
    clauses, params = _conditions(transport=transport, ip=ip, port=port, search=search)

    where = " AND ".join(["analysis_id = ?", *clauses])
    count_row = db.query_one(
        f"SELECT COUNT(*) AS n FROM conversations WHERE {where}", (analysis_id, *params)
    )
    total = int(count_row["n"]) if count_row else 0

    rows = db.query_all(
        f"""
        SELECT * FROM conversations
         WHERE {where}
         ORDER BY {order_sql} {direction}, conv_id ASC
         LIMIT ? OFFSET ?
        """,
        (analysis_id, *params, page.limit, page.offset),
    )

    # Whole-set totals for this analysis, regardless of the active filters.
    overall = db.query_one(
        """
        SELECT COUNT(*) AS n, COALESCE(SUM(bytes_total), 0) AS b
          FROM conversations WHERE analysis_id = ?
        """,
        (analysis_id,),
    )

    return {
        **page.envelope([dict(r) for r in rows], total),
        "total_bytes": int(overall["b"]) if overall else 0,
        "total_conversations": int(overall["n"]) if overall else 0,
    }


@router.get("/streams/{stream_id}")
def get_stream(
    analysis_id: str,
    stream_id: int,
    mode: StreamMode = Query("ascii", description="Rendering of the reassembled bytes"),
) -> dict:
    """Stream metadata plus TShark's reassembled, direction-tagged payload."""
    analysis_ready_row(analysis_id)
    return stream_analyzer.get_stream(analysis_id, stream_id, mode)


@router.get("/streams/{stream_id}/search")
def search_stream(
    analysis_id: str,
    stream_id: int,
    q: str = Query(..., min_length=1, description="Substring to find in the stream"),
    mode: StreamMode = Query("ascii"),
) -> dict:
    """Case-insensitive search across the reassembled stream bytes."""
    analysis_ready_row(analysis_id)
    return stream_analyzer.search_stream(analysis_id, stream_id, q, mode)


@router.get("/streams/{stream_id}/export")
def export_stream(
    analysis_id: str,
    stream_id: int,
    mode: StreamMode = Query("ascii"),
    fmt: str = Query("txt", alias="format", description="txt | hex | csv | raw"),
) -> Response:
    """Download the reassembled stream in one of several formats."""
    analysis_ready_row(analysis_id)
    if fmt not in stream_analyzer.EXPORT_FORMATS:
        raise bad_request(
            "invalid_format",
            f"Unsupported export format '{fmt}'.",
            allowed=list(stream_analyzer.EXPORT_FORMATS),
        )

    payload, filename, media_type = stream_analyzer.export_stream(
        analysis_id, stream_id, mode, fmt
    )
    return Response(
        content=payload,
        media_type=media_type,
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
            "Content-Length": str(len(payload)),
            "X-Stream-Id": str(stream_id),
            "X-Stream-Mode": mode,
            "X-Stream-Format": fmt,
        },
    )
