"""HTTP endpoints: transaction list, single transaction and filter dropdowns.

Transactions are read from the persisted ``http_transactions`` rows. The
``methods``/``hosts``/``status_classes`` blocks are computed from the same table
so the UI dropdowns always reflect what is actually stored.
"""

from __future__ import annotations

import sqlite3
from typing import Any

from fastapi import APIRouter, Depends, Query

from app.core.errors import ApiError, not_found
from app.core.logging import get_logger
from app.db import database as db
from app.api.deps import (
    Pagination,
    analysis_ready_row,
    json_or,
    pagination,
    resolve_order,
    resolve_sort,
)

log = get_logger("shadowpackets.api.http")

router = APIRouter(prefix="/api/analyses/{analysis_id}", tags=["http"])

SORTABLE = {
    "time_epoch": "time_epoch",
    "method": "method",
    "host": "host",
    "uri": "uri",
    "status_code": "status_code",
    "response_len": "response_len",
    "request_packet": "request_packet",
}

DEFAULT_SORT = "time_epoch"


def sort_expression(sort: str | None, allowed: dict[str, str], default: str) -> str:
    """Map a client sort key onto an allow-listed SQL expression.

    Delegates to the shared ``deps.resolve_sort``. That helper currently passes
    its ``details`` mapping positionally to ``bad_request``, which raises
    ``TypeError`` instead of the documented ``400 invalid_sort``; the fallback
    below keeps the contract until the core helper is fixed.
    """
    try:
        return resolve_sort(sort, allowed, default)
    except TypeError:
        key = (sort or "").strip().lstrip("-")
        if key not in allowed:
            raise ApiError(
                400, "invalid_sort", f"Cannot sort by '{sort}'.", {"allowed": sorted(allowed)}
            ) from None
        return allowed[key]


def sort_order(order: str | None, default: str = "desc") -> str:
    """``asc``/``desc`` (upper-cased) or ``400 invalid_order``."""
    try:
        return resolve_order(order, default)
    except TypeError:
        value = (order or default).strip().lower()
        if value not in {"asc", "desc"}:
            raise ApiError(
                400, "invalid_order", "Order must be 'asc' or 'desc'.", {"order": order}
            ) from None
        return value.upper()


def _serialise(row: sqlite3.Row) -> dict[str, Any]:
    """Row -> JSON-safe dict; JSON columns are parsed, NULL stays None."""
    data = dict(row)
    data["request_headers"] = json_or(data.get("request_headers"), {})
    data["response_headers"] = json_or(data.get("response_headers"), {})
    data["flags"] = json_or(data.get("flags"), [])
    return data


def _escapable(value: str) -> str:
    """Escape LIKE wildcards so a literal ``%`` does not widen a search."""
    return value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def _like(value: str) -> str:
    return f"%{_escapable(value.strip())}%"


def _status_predicate(status: str) -> tuple[str, list[Any]]:
    """Accept an exact code (``404``) or a class (``4xx``)."""
    value = status.strip().lower()
    if len(value) == 3 and value.endswith("xx") and value[0].isdigit():
        first = int(value[0])
        return "status_code >= ? AND status_code <= ?", [first * 100, first * 100 + 99]
    if value.endswith("xx") and value[:-2].isdigit():
        first = int(value[:-2])
        return "status_code >= ? AND status_code <= ?", [first * 100, first * 100 + 99]
    try:
        return "status_code = ?", [int(value, 0)]
    except ValueError:
        # Not a code or a class: match nothing rather than guess.
        return "0 = 1", []


@router.get("/http")
def list_http_transactions(
    analysis_id: str,
    page: Pagination = Depends(pagination),
    method: str | None = Query(None, description="Exact method, e.g. GET"),
    host: str | None = Query(None, description="Substring match on the Host header"),
    uri: str | None = Query(None, description="Substring match on the request URI"),
    status: str | None = Query(None, description="Exact code (404) or class (4xx)"),
    client_ip: str | None = Query(None),
    server_ip: str | None = Query(None),
    user_agent: str | None = Query(None, description="Substring match on the User-Agent"),
    search: str | None = Query(None, description="Substring over URI, host and user agent"),
    interesting: bool | None = Query(None, description="Only transactions carrying flags"),
    sort: str | None = Query(None),
    order: str | None = Query(None),
) -> dict:
    analysis_ready_row(analysis_id)

    where: list[str] = ["analysis_id = ?"]
    params: list[Any] = [analysis_id]

    if method:
        where.append("UPPER(method) = ?")
        params.append(method.strip().upper())
    if host:
        where.append("host LIKE ? ESCAPE '\\'")
        params.append(_like(host))
    if uri:
        where.append("uri LIKE ? ESCAPE '\\'")
        params.append(_like(uri))
    if status:
        clause, values = _status_predicate(status)
        where.append(clause)
        params.extend(values)
    if client_ip:
        where.append("client_ip = ?")
        params.append(client_ip)
    if server_ip:
        where.append("server_ip = ?")
        params.append(server_ip)
    if user_agent:
        where.append("user_agent LIKE ? ESCAPE '\\'")
        params.append(_like(user_agent))
    if search:
        where.append(
            "(uri LIKE ? ESCAPE '\\' OR host LIKE ? ESCAPE '\\' "
            "OR user_agent LIKE ? ESCAPE '\\' OR full_uri LIKE ? ESCAPE '\\')"
        )
        needle = _like(search)
        params.extend([needle, needle, needle, needle])
    if interesting is not None:
        if interesting:
            where.append("flags IS NOT NULL AND flags <> '[]'")
        else:
            where.append("(flags IS NULL OR flags = '[]')")

    clause = " AND ".join(where)
    total_row = db.query_one(
        f"SELECT COUNT(*) AS n FROM http_transactions WHERE {clause}", params
    )
    total = int(total_row["n"]) if total_row else 0

    sort_sql = sort_expression(sort, SORTABLE, DEFAULT_SORT)
    order_sql = sort_order(order, "asc")
    rows = db.query_all(
        f"SELECT * FROM http_transactions WHERE {clause} "
        f"ORDER BY {sort_sql} {order_sql}, id {order_sql} LIMIT ? OFFSET ?",
        [*params, page.limit, page.offset],
    )

    return {
        **page.envelope([_serialise(row) for row in rows], total),
        "methods": _distinct("method", analysis_id),
        "hosts": _distinct("host", analysis_id),
        "status_classes": _status_classes(analysis_id),
    }


@router.get("/http/{transaction_id}")
def http_transaction_detail(analysis_id: str, transaction_id: int) -> dict:
    """One transaction including header objects and body previews."""
    analysis_ready_row(analysis_id)
    row = db.query_one(
        "SELECT * FROM http_transactions WHERE analysis_id = ? AND id = ?",
        (analysis_id, transaction_id),
    )
    if row is None:
        raise not_found(
            "http_transaction_not_found",
            f"No HTTP transaction {transaction_id} in this analysis.",
        )
    return _serialise(row)


def _distinct(column: str, analysis_id: str) -> list[str]:
    """Distinct non-null values of a fixed column, for filter dropdowns."""
    if column not in {"method", "host"}:
        raise ValueError("unexpected column")
    rows = db.query_all(
        f"SELECT DISTINCT {column} AS v FROM http_transactions "
        f"WHERE analysis_id = ? AND {column} IS NOT NULL AND {column} <> '' ORDER BY v ASC",
        (analysis_id,),
    )
    return [row["v"] for row in rows]


def _status_classes(analysis_id: str) -> dict[str, int]:
    """``{"2xx": 12, "4xx": 3}`` computed from the stored status codes."""
    rows = db.query_all(
        """
        SELECT (status_code / 100) AS cls, COUNT(*) AS n
        FROM http_transactions
        WHERE analysis_id = ? AND status_code IS NOT NULL
        GROUP BY cls ORDER BY cls ASC
        """,
        (analysis_id,),
    )
    return {f"{int(row['cls'])}xx": int(row["n"]) for row in rows}
