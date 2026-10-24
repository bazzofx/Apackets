"""DNS endpoints: query list, single query, and per-domain aggregation.

The list endpoint answers from the persisted ``dns_queries`` rows only; the
``qtypes``/``rcodes``/``top_clients`` blocks are computed from the same table so
the UI filter dropdowns always reflect what is actually stored.
"""

from __future__ import annotations

import sqlite3
from typing import Any

from fastapi import APIRouter, Depends, Query

from app.core.errors import not_found
from app.core.logging import get_logger
from app.db import database as db
from app.api.routes_http import sort_expression, sort_order
from app.api.deps import (
    Pagination,
    analysis_ready_row,
    json_or,
    pagination,
)

log = get_logger("shadowpackets.api.dns")

router = APIRouter(prefix="/api/analyses/{analysis_id}", tags=["dns"])

SORTABLE = {
    "time_epoch": "time_epoch",
    "query_name": "query_name",
    "query_type": "query_type",
    "rcode_name": "rcode_name",
    "response_delay": "response_delay",
    "packet_number": "packet_number",
}

DEFAULT_SORT = "time_epoch"

JSON_COLUMNS = ("answers", "flags")

RCODE_LOOKUP = {
    "NOERROR": 0, "FORMERR": 1, "SERVFAIL": 2, "NXDOMAIN": 3,
    "NOTIMP": 4, "REFUSED": 5,
}


def _serialise(row: sqlite3.Row) -> dict[str, Any]:
    """Row -> JSON-safe dict; JSON columns are parsed, NULL stays None."""
    data = dict(row)
    data["answers"] = json_or(data.get("answers"), [])
    data["flags"] = json_or(data.get("flags"), [])
    return data


def _like(value: str) -> str:
    return f"%{value.strip()}%"


def _escapable(value: str) -> str:
    """Escape LIKE wildcards so a literal ``%`` in a domain does not widen a search."""
    return value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


@router.get("/dns")
def list_dns_queries(
    analysis_id: str,
    page: Pagination = Depends(pagination),
    domain: str | None = Query(None, description="Substring match on the query name"),
    client_ip: str | None = Query(None),
    server_ip: str | None = Query(None),
    qtype: str | None = Query(None, description="A, AAAA, TXT, ... or the numeric type"),
    rcode: str | None = Query(None, description="NXDOMAIN or the numeric rcode"),
    unanswered: bool | None = Query(None),
    nxdomain: bool | None = Query(None),
    suspicious: bool | None = Query(None, description="Only rows carrying lead flags"),
    search: str | None = Query(None, description="Substring over name, answers and type"),
    sort: str | None = Query(None),
    order: str | None = Query(None),
) -> dict:
    analysis_ready_row(analysis_id)

    where: list[str] = ["analysis_id = ?"]
    params: list[Any] = [analysis_id]

    if domain:
        where.append("query_name LIKE ? ESCAPE '\\'")
        params.append(_like(_escapable(domain)))
    if client_ip:
        where.append("client_ip = ?")
        params.append(client_ip)
    if server_ip:
        where.append("server_ip = ?")
        params.append(server_ip)
    if qtype:
        where.append("(query_type = ? OR query_type = ?)")
        params.append(qtype.strip().upper())
        params.append(qtype.strip())
    if rcode is not None and rcode != "":
        if rcode.strip().upper() in RCODE_LOOKUP:
            where.append("rcode = ?")
            params.append(RCODE_LOOKUP[rcode.strip().upper()])
        else:
            try:
                where.append("rcode = ?")
                params.append(int(rcode, 0))
            except ValueError:
                where.append("rcode_name = ?")
                params.append(rcode.strip().upper())
    if unanswered is not None:
        where.append("response_packet IS NULL" if unanswered else "response_packet IS NOT NULL")
    if nxdomain is not None:
        where.append("rcode = 3" if nxdomain else "(rcode IS NULL OR rcode <> 3)")
    if suspicious is not None:
        if suspicious:
            where.append("flags IS NOT NULL AND flags <> '[]'")
        else:
            where.append("(flags IS NULL OR flags = '[]')")
    if search:
        where.append(
            "(query_name LIKE ? ESCAPE '\\' OR answers LIKE ? ESCAPE '\\' OR query_type LIKE ? ESCAPE '\\')"
        )
        needle = _like(_escapable(search))
        params.extend([needle, needle, needle])

    clause = " AND ".join(where)
    total_row = db.query_one(f"SELECT COUNT(*) AS n FROM dns_queries WHERE {clause}", params)
    total = int(total_row["n"]) if total_row else 0

    order_sql = sort_order(order, "asc")
    sort_sql = sort_expression(sort, SORTABLE, DEFAULT_SORT)
    rows = db.query_all(
        f"SELECT * FROM dns_queries WHERE {clause} "
        f"ORDER BY {sort_sql} {order_sql}, id {order_sql} LIMIT ? OFFSET ?",
        [*params, page.limit, page.offset],
    )

    return {
        **page.envelope([_serialise(row) for row in rows], total),
        "qtypes": _distinct("query_type", analysis_id),
        "rcodes": _distinct("rcode_name", analysis_id),
        "top_clients": [
            {"client_ip": row["client_ip"], "count": int(row["n"])}
            for row in db.query_all(
                """
                SELECT client_ip, COUNT(*) AS n FROM dns_queries
                WHERE analysis_id = ? AND client_ip IS NOT NULL
                GROUP BY client_ip ORDER BY n DESC, client_ip ASC LIMIT 10
                """,
                (analysis_id,),
            )
        ],
    }


@router.get("/dns/domains")
def dns_domains(
    analysis_id: str,
    limit: int = Query(500, ge=1, le=5000, description="Maximum domains returned"),
    search: str | None = Query(None, description="Substring match on the query name"),
) -> dict:
    """Aggregated per-domain view derived from the stored query rows."""
    analysis_ready_row(analysis_id)

    where: list[str] = ["analysis_id = ?", "query_name IS NOT NULL"]
    params: list[Any] = [analysis_id]
    if search:
        where.append("query_name LIKE ? ESCAPE '\\'")
        params.append(_like(_escapable(search)))
    clause = " AND ".join(where)

    groups = db.query_all(
        f"""
        SELECT query_name,
               COUNT(*)                                AS queries,
               COUNT(DISTINCT client_ip)               AS clients,
               COUNT(DISTINCT CASE WHEN response_packet IS NOT NULL
                                   THEN response_packet END) AS answered,
               SUM(CASE WHEN rcode = 3 THEN 1 ELSE 0 END) AS nxdomain,
               MIN(time_epoch)                         AS first_seen,
               MAX(time_epoch)                         AS last_seen
        FROM dns_queries
        WHERE {clause}
        GROUP BY query_name
        ORDER BY queries DESC, query_name ASC
        LIMIT ?
        """,
        [*params, limit],
    )

    items: list[dict] = []
    for group in groups:
        name = group["query_name"]
        rcode_rows = db.query_all(
            """
            SELECT rcode_name, COUNT(*) AS n FROM dns_queries
            WHERE analysis_id = ? AND query_name = ? AND rcode_name IS NOT NULL
            GROUP BY rcode_name ORDER BY n DESC
            """,
            (analysis_id, name),
        )
        ips: list[str] = []
        for answer_row in db.query_all(
            """
            SELECT answer_ips FROM dns_queries
            WHERE analysis_id = ? AND query_name = ? AND answer_ips IS NOT NULL
            """,
            (analysis_id, name),
        ):
            for ip in (answer_row["answer_ips"] or "").split(","):
                ip = ip.strip()
                if ip and ip not in ips:
                    ips.append(ip)
        items.append(
            {
                "query_name": name,
                "queries": int(group["queries"]),
                "clients": int(group["clients"]),
                "answered": int(group["answered"] or 0),
                "nxdomain": int(group["nxdomain"] or 0),
                "rcodes": {row["rcode_name"]: int(row["n"]) for row in rcode_rows},
                "ips": ips,
                "first_seen": group["first_seen"],
                "last_seen": group["last_seen"],
            }
        )

    return {"items": items, "total": len(items)}


@router.get("/dns/{row_id}")
def dns_query_detail(analysis_id: str, row_id: int) -> dict:
    """One stored query row with its parsed answers."""
    analysis_ready_row(analysis_id)
    row = db.query_one(
        "SELECT * FROM dns_queries WHERE analysis_id = ? AND id = ?",
        (analysis_id, row_id),
    )
    if row is None:
        raise not_found("dns_query_not_found", f"No DNS row {row_id} in this analysis.")
    return _serialise(row)


def _distinct(column: str, analysis_id: str) -> list[str]:
    """Distinct non-null values of a fixed column, for filter dropdowns."""
    if column not in {"query_type", "rcode_name"}:
        raise ValueError("unexpected column")
    rows = db.query_all(
        f"SELECT DISTINCT {column} AS v FROM dns_queries "
        f"WHERE analysis_id = ? AND {column} IS NOT NULL ORDER BY v ASC",
        (analysis_id,),
    )
    return [row["v"] for row in rows]
