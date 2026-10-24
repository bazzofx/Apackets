"""Packet explorer: listing, filtering, detail, neighbours and CSV export.

Two filtering paths are supported and they compose:

* **Structured filters** (``ip``, ``port``, ``transport``, …) become indexed SQL
  predicates against the ``packets`` table.
* **A Wireshark display filter** is compiled and executed by TShark against the
  retained capture, producing a set of matching frame numbers that is joined
  against the indexed rows. This keeps Wireshark's exact filter semantics while
  still serving results from SQLite.

An invalid display filter is always reported as invalid — never as "zero
results" — so the UI can tell the two apart.
"""

from __future__ import annotations

import csv
import io
import sqlite3
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, Query, Response

from app.api.deps import (
    Pagination,
    capture_path,
    pagination,
    resolve_order,
    resolve_sort,
)
from app.core.config import settings
from app.core.errors import unprocessable
from app.core.logging import get_logger
from app.db import database as db
from app.schemas import FilterRequest
from app.services import tshark

log = get_logger("shadowpackets.api.packets")

router = APIRouter(prefix="/api/analyses/{analysis_id}", tags=["packets"])

# Columns returned for packet summaries — never payloads.
SUMMARY_COLUMNS = (
    "number, time_epoch, time_relative, src_ip, src_port, dst_ip, dst_port, "
    "protocol, transport, frame_len, tcp_flags, info, protocols, eth_src, eth_dst, "
    "vlan_id, ttl, ip_version, dns_query, http_method, http_host, http_uri, "
    "http_status, tls_sni, tls_version, tcp_stream, udp_stream"
)

SORTABLE = {
    "number": "p.number",
    "time_epoch": "p.time_epoch",
    "time_relative": "p.time_relative",
    "src_ip": "p.src_ip",
    "dst_ip": "p.dst_ip",
    "src_port": "p.src_port",
    "dst_port": "p.dst_port",
    "protocol": "p.protocol",
    "frame_len": "p.frame_len",
    "length": "p.frame_len",
}

DEFAULT_SORT = "p.number"

MAX_FILTER_ROWS = 500_000


# --------------------------------------------------------------------------
# filter plumbing
# --------------------------------------------------------------------------

def _ready(analysis_id: str):
    """Analysis row that is completed and still has its capture on disk."""
    from app.api.deps import analysis_ready_row

    return analysis_ready_row(analysis_id)


def _display_filter_numbers(analysis_id: str, expr: str | None) -> list[int] | None:
    """Frame numbers matching a display filter, or None when no filter is set.

    Raises 422 for an invalid filter so the caller never mistakes a syntax error
    for an empty result set.
    """
    if not expr or not expr.strip():
        return None

    valid, reason = tshark.validate_filter(expr)
    if not valid:
        raise unprocessable(
            "invalid_filter",
            "That is not a valid Wireshark display filter.",
            reason=reason,
        )

    row = _ready(analysis_id)
    path = capture_path(row)
    try:
        return tshark.matching_frame_numbers(path, expr, limit=MAX_FILTER_ROWS)
    except tshark.TsharkTimeout as exc:
        raise unprocessable(
            "filter_timeout",
            "The display filter took too long to evaluate on this capture.",
            reason=str(exc),
        ) from exc
    except tshark.TsharkError as exc:
        raise unprocessable(
            "invalid_filter",
            "TShark rejected the display filter.",
            reason=str(exc),
        ) from exc


def _parse_time(value: str | None) -> float | None:
    """Accept epoch seconds or an ISO-8601 timestamp (contract §5)."""
    if value is None or value == "":
        return None
    text = value.strip()
    try:
        return float(text)
    except ValueError:
        pass
    candidate = text.replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(candidate)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.timestamp()


def _structured_conditions(
    *,
    ip: str | None,
    src_ip: str | None,
    dst_ip: str | None,
    port: int | None,
    src_port: int | None,
    dst_port: int | None,
    protocol: str | None,
    transport: str | None,
    tcp_flags: str | None,
    min_length: int | None,
    max_length: int | None,
    start_time: str | None,
    end_time: str | None,
    search: str | None,
    stream_id: int | None,
) -> tuple[list[str], list]:
    clauses: list[str] = []
    params: list = []

    if ip:
        clauses.append("(p.src_ip = ? OR p.dst_ip = ?)")
        params += [ip, ip]
    if src_ip:
        clauses.append("p.src_ip = ?")
        params.append(src_ip)
    if dst_ip:
        clauses.append("p.dst_ip = ?")
        params.append(dst_ip)
    if port is not None:
        clauses.append("(p.src_port = ? OR p.dst_port = ?)")
        params += [port, port]
    if src_port is not None:
        clauses.append("p.src_port = ?")
        params.append(src_port)
    if dst_port is not None:
        clauses.append("p.dst_port = ?")
        params.append(dst_port)
    if protocol:
        clauses.append("UPPER(p.protocol) = UPPER(?)")
        params.append(protocol)
    if transport:
        clauses.append("p.transport = ?")
        params.append(transport.lower())
    if tcp_flags:
        # tcp_flags stores Wireshark's flag string; a plain substring match lets
        # "SYN" match, and "SYN,ACK" style input still behaves sensibly.
        clauses.append("REPLACE(p.tcp_flags, '\u00b7', '.') LIKE ?")
        params.append(f"%{tcp_flags.replace(',', '')}%")
    if min_length is not None:
        clauses.append("p.frame_len >= ?")
        params.append(min_length)
    if max_length is not None:
        clauses.append("p.frame_len <= ?")
        params.append(max_length)

    start = _parse_time(start_time)
    if start is not None:
        clauses.append("p.time_epoch >= ?")
        params.append(start)
    end = _parse_time(end_time)
    if end is not None:
        clauses.append("p.time_epoch <= ?")
        params.append(end)

    if search:
        clauses.append("(p.info LIKE ? OR p.protocol LIKE ? OR p.src_ip LIKE ? OR p.dst_ip LIKE ?)")
        needle = f"%{search}%"
        params += [needle, needle, needle, needle]

    if stream_id is not None:
        clauses.append("(p.tcp_stream = ? OR p.udp_stream = ?)")
        params += [stream_id, stream_id]

    return clauses, params


def _query_packets(
    analysis_id: str,
    conds: list[str],
    params: list,
    order_sql: str,
    direction: str,
    *,
    page: Pagination | None = None,
    limit: int | None = None,
    offset: int = 0,
    filter_numbers: list[int] | None = None,
    conn: sqlite3.Connection | None = None,
) -> tuple[list[dict], int]:
    """Run the filtered, sorted, paginated query (optionally joining a filter set)."""
    own_conn = conn is None
    connection = conn or db.connect()
    try:
        # ``analysis_id`` is the first placeholder in the WHERE clause, so it must
        # be the first bound value.
        bound: list = [analysis_id, *params]
        where = " AND ".join(["p.analysis_id = ?", *conds])

        if filter_numbers is not None:
            # A temporary table keeps large display-filter result sets out of the
            # SQL statement text (SQLite caps host parameters per statement).
            connection.execute("DROP TABLE IF EXISTS temp._filter_numbers")
            connection.execute(
                "CREATE TEMP TABLE _filter_numbers (number INTEGER PRIMARY KEY)"
            )
            connection.executemany(
                "INSERT OR IGNORE INTO _filter_numbers (number) VALUES (?)",
                ((int(n),) for n in filter_numbers),
            )
            where += " AND p.number IN (SELECT number FROM _filter_numbers)"

        count_sql = f"SELECT COUNT(*) AS n FROM packets p WHERE {where}"
        total = int(connection.execute(count_sql, tuple(bound)).fetchone()["n"])

        sql = (
            f"SELECT {SUMMARY_COLUMNS} FROM packets p WHERE {where} "
            f"ORDER BY {order_sql} {direction} LIMIT ? OFFSET ?"
        )
        if page is not None:
            rows = connection.execute(sql, (*bound, page.limit, page.offset)).fetchall()
        else:
            rows = connection.execute(sql, (*bound, limit or 100, offset)).fetchall()

        return [dict(r) for r in rows], total
    finally:
        if own_conn:
            connection.close()


# --------------------------------------------------------------------------
# endpoints
# --------------------------------------------------------------------------

@router.get("/packets")
def list_packets(
    analysis_id: str,
    filter: str | None = Query(None, description="Wireshark display filter"),
    ip: str | None = None,
    src_ip: str | None = None,
    dst_ip: str | None = None,
    port: int | None = Query(None, ge=0, le=65535),
    src_port: int | None = Query(None, ge=0, le=65535),
    dst_port: int | None = Query(None, ge=0, le=65535),
    protocol: str | None = None,
    transport: str | None = Query(None, pattern="^(tcp|udp|sctp|other)?$"),
    tcp_flags: str | None = None,
    min_length: int | None = Query(None, ge=0),
    max_length: int | None = Query(None, ge=0),
    start_time: str | None = None,
    end_time: str | None = None,
    search: str | None = None,
    stream_id: int | None = None,
    sort: str | None = None,
    order: str | None = None,
    page: Pagination = Depends(pagination),
) -> dict:
    _ready(analysis_id)

    order_sql = resolve_sort(sort, SORTABLE, DEFAULT_SORT)
    direction = resolve_order(order, "asc")

    conds, params = _structured_conditions(
        ip=ip, src_ip=src_ip, dst_ip=dst_ip, port=port, src_port=src_port,
        dst_port=dst_port, protocol=protocol, transport=transport, tcp_flags=tcp_flags,
        min_length=min_length, max_length=max_length, start_time=start_time,
        end_time=end_time, search=search, stream_id=stream_id,
    )

    filter_numbers = _display_filter_numbers(analysis_id, filter)

    items, total = _query_packets(
        analysis_id, conds, params, order_sql, direction,
        page=page, filter_numbers=filter_numbers,
    )

    return {
        **page.envelope(items, total),
        "filter": filter or None,
        "filter_valid": True,
        "filter_error": None,
    }


@router.get("/packets/export.csv")
def export_packets_csv(
    analysis_id: str,
    filter: str | None = None,
    ip: str | None = None,
    src_ip: str | None = None,
    dst_ip: str | None = None,
    port: int | None = Query(None, ge=0, le=65535),
    src_port: int | None = Query(None, ge=0, le=65535),
    dst_port: int | None = Query(None, ge=0, le=65535),
    protocol: str | None = None,
    transport: str | None = Query(None, pattern="^(tcp|udp|sctp|other)?$"),
    tcp_flags: str | None = None,
    min_length: int | None = Query(None, ge=0),
    max_length: int | None = Query(None, ge=0),
    start_time: str | None = None,
    end_time: str | None = None,
    search: str | None = None,
    stream_id: int | None = None,
    sort: str | None = None,
    order: str | None = None,
) -> Response:
    """CSV of the current filter, capped so one request cannot exhaust memory."""
    _ready(analysis_id)
    order_sql = resolve_sort(sort, SORTABLE, DEFAULT_SORT)
    direction = resolve_order(order, "asc")

    conds, params = _structured_conditions(
        ip=ip, src_ip=src_ip, dst_ip=dst_ip, port=port, src_port=src_port,
        dst_port=dst_port, protocol=protocol, transport=transport, tcp_flags=tcp_flags,
        min_length=min_length, max_length=max_length, start_time=start_time,
        end_time=end_time, search=search, stream_id=stream_id,
    )
    filter_numbers = _display_filter_numbers(analysis_id, filter)

    rows, total = _query_packets(
        analysis_id, conds, params, order_sql, direction,
        limit=settings.max_export_rows, offset=0, filter_numbers=filter_numbers,
    )

    buffer = io.StringIO()
    writer = csv.writer(buffer, lineterminator="\n")
    writer.writerow(
        ["number", "time", "src_ip", "src_port", "dst_ip", "dst_port",
         "protocol", "length", "tcp_flags", "info"]
    )
    for row in rows:
        time_value = row.get("time_epoch")
        stamp = ""
        if time_value is not None:
            stamp = datetime.fromtimestamp(float(time_value), tz=timezone.utc).isoformat(
                timespec="microseconds"
            )
        writer.writerow(
            [
                row.get("number") or "",
                stamp,
                row.get("src_ip") or "",
                row.get("src_port") if row.get("src_port") is not None else "",
                row.get("dst_ip") or "",
                row.get("dst_port") if row.get("dst_port") is not None else "",
                row.get("protocol") or "",
                row.get("frame_len") if row.get("frame_len") is not None else "",
                (row.get("tcp_flags") or "").replace("\u00b7", "."),
                (row.get("info") or "").replace("\r", " ").replace("\n", " "),
            ]
        )

    truncated = total > len(rows)
    filename = f"packets-{analysis_id[:8]}.csv"
    headers = {
        "Content-Disposition": f'attachment; filename="{filename}"',
        "X-Total-Rows": str(total),
        "X-Exported-Rows": str(len(rows)),
    }
    if truncated:
        headers["X-Truncated"] = "true"
    return Response(
        content=buffer.getvalue(),
        media_type="text/csv; charset=utf-8",
        headers=headers,
    )


@router.post("/filter")
def apply_filter(analysis_id: str, body: FilterRequest) -> dict:
    """Validate a display filter and return the matching packets.

    Unlike ``GET /packets``, an invalid filter is reported in the body rather
    than as an error, so a filter bar can validate as the analyst types.
    """
    _ready(analysis_id)
    expr = body.filter or ""
    valid, reason = tshark.validate_filter(expr)

    if not valid:
        return {
            "valid": False,
            "reason": reason,
            "total": 0,
            "items": [],
            "page": body.page,
            "page_size": body.page_size,
            "pages": 0,
        }

    page = Pagination(page=body.page, page_size=body.page_size)
    filter_numbers = None
    if expr.strip():
        filter_numbers = _display_filter_numbers(analysis_id, expr)

    items, total = _query_packets(
        analysis_id, [], [], "p.number", "ASC",
        page=page, filter_numbers=filter_numbers,
    )
    return {
        "valid": True,
        "reason": None,
        "total": total,
        **page.envelope(items, total),
    }


@router.get("/packets/{packet_number}")
def get_packet(analysis_id: str, packet_number: int) -> dict:
    """Full decoded detail for one packet, from the retained capture."""
    row = _ready(analysis_id)

    summary = db.query_one(
        f"SELECT {SUMMARY_COLUMNS} FROM packets p WHERE p.analysis_id = ? AND p.number = ?",
        (analysis_id, packet_number),
    )
    if summary is None:
        from app.core.errors import not_found

        raise not_found(
            "packet_not_found",
            f"Packet {packet_number} is not present in this analysis.",
        )

    path = capture_path(row)
    detail = dict(summary)

    try:
        layers = tshark.packet_json(path, packet_number)
    except (tshark.TsharkError, tshark.TsharkTimeout) as exc:
        log.warning("could not decode packet %s: %s", packet_number, exc)
        layers = {}

    try:
        hex_rows, raw_hex = tshark.packet_hexdump(path, packet_number)
    except (tshark.TsharkError, tshark.TsharkTimeout) as exc:
        log.warning("could not read bytes for packet %s: %s", packet_number, exc)
        hex_rows, raw_hex = [], ""

    raw_text, truncated = tshark.render_ascii(raw_hex)

    protocols = (summary["protocols"] or "").split(":")
    order = [name for name in protocols if name]

    detail.update(
        {
            "layers": layers,
            "layer_order": order,
            "hex_dump": hex_rows,
            "raw_hex": raw_hex,
            "raw_text": raw_text,
            "raw_len": len(raw_hex) // 2,
            "raw_truncated": truncated,
        }
    )
    return detail


@router.get("/packets/{packet_number}/neighbors")
def packet_neighbors(
    analysis_id: str,
    packet_number: int,
    filter: str = Query(..., description="Display filter to step through"),
    direction: str = Query("next", pattern="^(next|prev)$"),
) -> dict:
    """Next/previous packet matching a filter — drives the packet-list navigation."""
    row = _ready(analysis_id)

    valid, reason = tshark.validate_filter(filter)
    if not valid:
        raise unprocessable(
            "invalid_filter", "That is not a valid Wireshark display filter.", reason=reason
        )

    path = capture_path(row)
    try:
        if direction == "next":
            found = tshark.first_matching_frame(path, filter, after=packet_number)
        else:
            found = tshark.first_matching_frame(path, filter, before=packet_number)
    except (tshark.TsharkError, tshark.TsharkTimeout) as exc:
        raise unprocessable(
            "filter_failed", "Could not evaluate the display filter.", reason=str(exc)
        ) from exc

    return {
        "packet_number": found,
        "direction": direction,
        "filter": filter,
        "boundary": found is None,
    }
