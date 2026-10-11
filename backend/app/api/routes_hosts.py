"""Host inventory endpoints.

The graph is built strictly from observed ``conversations`` rows — every edge is a
real conversation, never an inferred subnet or name-resolution relationship.
Node attributes are enriched from the ``hosts`` table when that row exists.
"""

from __future__ import annotations

import json

from fastapi import APIRouter, Depends, Query

from app.api.deps import (
    Pagination,
    analysis_ready_row,
    pagination,
    resolve_order,
    resolve_sort,
)
from app.core.errors import not_found
from app.core.logging import get_logger
from app.db import database as db
from app.services.host_analyzer import is_private_address

log = get_logger("apackets.api.hosts")

router = APIRouter(prefix="/api/analyses/{analysis_id}", tags=["hosts"])

# Client-supplied sort keys mapped onto fixed SQL expressions — raw input never
# reaches the statement text.
SORTABLE = {
    "ip": "ip",
    "packets_sent": "packets_sent",
    "bytes_sent": "bytes_sent",
    "bytes_received": "bytes_received",
    "first_seen": "first_seen",
    "last_seen": "last_seen",
    "peer_count": "peer_count",
}
DEFAULT_SORT = "ip"
DEFAULT_ORDER = "asc"

DETAIL_LIST_LIMIT = 50
GRAPH_MAX_PORTS = 5

# Columns stored as JSON text. They are exposed as parsed structures so that
# hosts responses match the other endpoints (dns ``answers``, http ``flags``,
# findings ``evidence``), instead of leaking raw JSON strings to clients.
JSON_COLUMNS: tuple[str, ...] = ("ports", "protocols", "dns_names", "tls_sni", "peers")


def _host_row(row) -> dict:
    """Serialise a ``hosts`` row, parsing its JSON columns."""
    data = json_or(dict(row))
    return data


def json_or(row: dict) -> dict:
    """Parse the JSON text columns of a host row in place."""
    for column in JSON_COLUMNS:
        if column not in row:
            continue
        raw = row[column]
        if raw is None:
            row[column] = [] if column != "protocols" else {}
            continue
        if not isinstance(raw, str):
            continue
        try:
            row[column] = json.loads(raw)
        except (json.JSONDecodeError, TypeError):
            # Malformed capture-derived JSON: expose an empty structure rather
            # than a string the client would have to re-parse.
            row[column] = {} if column == "protocols" else []
    return row


def _conditions(
    *,
    ip: str | None,
    search: str | None,
    is_private: bool | None,
    protocol: str | None,
) -> tuple[list[str], list]:
    clauses: list[str] = []
    params: list = []

    if ip:
        clauses.append("ip LIKE ?")
        params.append(f"%{ip}%")
    if search:
        needle = f"%{search}%"
        clauses.append(
            "(ip LIKE ? OR mac LIKE ? OR protocols LIKE ? OR dns_names LIKE ? OR tls_sni LIKE ?)"
        )
        params += [needle, needle, needle, needle, needle]
    if is_private is not None:
        clauses.append("is_private = ?")
        params.append(1 if is_private else 0)
    if protocol:
        # JSON-key aware match on the compact {"HTTP": 12} object.
        clauses.append("INSTR(protocols, '\"' || ? || '\":') > 0")
        params.append(protocol)

    return clauses, params


@router.get("/hosts")
def list_hosts(
    analysis_id: str,
    ip: str | None = None,
    search: str | None = None,
    is_private: bool | None = None,
    protocol: str | None = None,
    sort: str | None = None,
    order: str | None = None,
    page: Pagination = Depends(pagination),
) -> dict:
    """Paginated host inventory, with ``total_bytes`` for the whole analysis."""
    analysis_ready_row(analysis_id)

    order_sql = resolve_sort(sort, SORTABLE, DEFAULT_SORT)
    direction = resolve_order(order, DEFAULT_ORDER)
    clauses, params = _conditions(ip=ip, search=search, is_private=is_private, protocol=protocol)

    where = " AND ".join(["analysis_id = ?", *clauses])
    count_row = db.query_one(
        f"SELECT COUNT(*) AS n FROM hosts WHERE {where}", (analysis_id, *params)
    )
    total = int(count_row["n"]) if count_row else 0

    rows = db.query_all(
        f"""
        SELECT * FROM hosts
         WHERE {where}
         ORDER BY {order_sql} {direction}, ip ASC
         LIMIT ? OFFSET ?
        """,
        (analysis_id, *params, page.limit, page.offset),
    )

    overall = db.query_one(
        """
        SELECT COALESCE(SUM(bytes_sent), 0) AS b, COUNT(*) AS n
          FROM hosts WHERE analysis_id = ?
        """,
        (analysis_id,),
    )

    return {
        **page.envelope([_host_row(r) for r in rows], total),
        "total_bytes": int(overall["b"]) if overall else 0,
        "total_hosts": int(overall["n"]) if overall else 0,
    }


@router.get("/hosts/graph")
def host_graph(analysis_id: str) -> dict:
    """Conversation topology: one node per endpoint, one edge per IP pair.

    Declared before ``/hosts/{ip}`` so the literal path is not swallowed by the
    path parameter.
    """
    analysis_ready_row(analysis_id)

    conversations = [
        dict(row)
        for row in db.query_all(
            "SELECT * FROM conversations WHERE analysis_id = ? ORDER BY conv_id ASC",
            (analysis_id,),
        )
    ]
    host_rows = {
        row["ip"]: dict(row)
        for row in db.query_all("SELECT * FROM hosts WHERE analysis_id = ?", (analysis_id,))
    }

    edges: dict[tuple[str, str], dict] = {}
    node_totals: dict[str, dict[str, int]] = {}

    for row in conversations:
        ip_a = row.get("ip_a")
        ip_b = row.get("ip_b")
        if not ip_a or not ip_b or ip_a == ip_b:
            continue

        key = (ip_a, ip_b) if ip_a <= ip_b else (ip_b, ip_a)
        edge = edges.get(key)
        if edge is None:
            edge = {
                "packets": 0,
                "bytes": 0,
                "protocols": set(),
                "ports": {},
                "source": ip_a,
                "target": ip_b,
                "busiest_bytes": None,
                "conversations": 0,
            }
            edges[key] = edge

        byte_count = int(row.get("bytes_total") or 0)
        edge["packets"] += int(row.get("packets_total") or 0)
        edge["bytes"] += byte_count
        edge["conversations"] += 1
        for name in str(row.get("protocols") or "").split(","):
            if name:
                edge["protocols"].add(name)

        # The busiest conversation decides the edge's direction (source/target).
        if edge["busiest_bytes"] is None or byte_count > edge["busiest_bytes"]:
            edge["busiest_bytes"] = byte_count
            edge["source"] = ip_a
            edge["target"] = ip_b

        # Destination ports, counted in the edge's declared direction.
        if ip_a == edge["source"]:
            port, weight = row.get("port_b"), int(row.get("packets_a_to_b") or 0)
        else:
            port, weight = row.get("port_a"), int(row.get("packets_b_to_a") or 0)
        if port is not None:
            _bump_port(edge["ports"], int(port), weight)

        for ip, sent, received, bytes_sent, bytes_received in (
            (
                ip_a,
                int(row.get("packets_a_to_b") or 0),
                int(row.get("packets_b_to_a") or 0),
                int(row.get("bytes_a_to_b") or 0),
                int(row.get("bytes_b_to_a") or 0),
            ),
            (
                ip_b,
                int(row.get("packets_b_to_a") or 0),
                int(row.get("packets_a_to_b") or 0),
                int(row.get("bytes_b_to_a") or 0),
                int(row.get("bytes_a_to_b") or 0),
            ),
        ):
            if not ip:
                continue
            totals = node_totals.setdefault(ip, {"packets": 0, "bytes": 0})
            totals["packets"] += sent + received
            totals["bytes"] += bytes_sent + bytes_received

    nodes = []
    for ip in sorted(node_totals):
        row = host_rows.get(ip)
        if row is not None:
            packets = int(row.get("packets_sent") or 0) + int(row.get("packets_received") or 0)
            byte_count = int(row.get("bytes_sent") or 0) + int(row.get("bytes_received") or 0)
            private = row.get("is_private")
        else:
            totals = node_totals[ip]
            packets = totals["packets"]
            byte_count = totals["bytes"]
            private = is_private_address(ip)
        nodes.append(
            {
                "id": ip,
                "label": ip,
                "mac": (row or {}).get("mac"),
                "packets": packets,
                "bytes": byte_count,
                "is_private": None if private is None else bool(private),
            }
        )

    edge_items = [
        {
            "source": edge["source"],
            "target": edge["target"],
            "packets": edge["packets"],
            "bytes": edge["bytes"],
            "protocols": ",".join(sorted(edge["protocols"])),
            "ports": [
                port
                for port, _ in sorted(
                    edge["ports"].items(), key=lambda item: (-item[1], item[0])
                )[:GRAPH_MAX_PORTS]
            ],
            "conversations": edge["conversations"],
        }
        for edge in edges.values()
    ]
    edge_items.sort(key=lambda item: (-item["bytes"], item["source"], item["target"]))
    return {"nodes": nodes, "edges": edge_items}


def _bump_port(ports: dict[int, int], port: int, weight: int) -> None:
    ports[port] = ports.get(port, 0) + max(0, weight)


@router.get("/hosts/{ip}")
def get_host(analysis_id: str, ip: str) -> dict:
    """One host plus capped lists of everything else attributed to it."""
    analysis_ready_row(analysis_id)

    row = db.query_one(
        "SELECT * FROM hosts WHERE analysis_id = ? AND ip = ?", (analysis_id, ip)
    )
    if row is None:
        raise not_found(
            "host_not_found",
            f"Host {ip} is not present in this analysis.",
            ip=ip,
        )

    conversations = db.query_all(
        """
        SELECT * FROM conversations
         WHERE analysis_id = ? AND (ip_a = ? OR ip_b = ?)
         ORDER BY bytes_total DESC, conv_id ASC
         LIMIT ?
        """,
        (analysis_id, ip, ip, DETAIL_LIST_LIMIT),
    )
    dns_queries = db.query_all(
        """
        SELECT * FROM dns_queries
         WHERE analysis_id = ? AND (client_ip = ? OR server_ip = ?)
         ORDER BY time_epoch ASC
         LIMIT ?
        """,
        (analysis_id, ip, ip, DETAIL_LIST_LIMIT),
    )
    http_transactions = db.query_all(
        """
        SELECT * FROM http_transactions
         WHERE analysis_id = ? AND (client_ip = ? OR server_ip = ?)
         ORDER BY time_epoch ASC
         LIMIT ?
        """,
        (analysis_id, ip, ip, DETAIL_LIST_LIMIT),
    )
    tls_sessions = db.query_all(
        """
        SELECT * FROM tls_sessions
         WHERE analysis_id = ? AND (client_ip = ? OR server_ip = ?)
         ORDER BY time_epoch ASC
         LIMIT ?
        """,
        (analysis_id, ip, ip, DETAIL_LIST_LIMIT),
    )
    packet_row = db.query_one(
        "SELECT COUNT(*) AS n FROM packets WHERE analysis_id = ? AND (src_ip = ? OR dst_ip = ?)",
        (analysis_id, ip, ip),
    )

    return {
        **json_or(dict(row)),
        "packet_count": int(packet_row["n"]) if packet_row else 0,
        "conversations": [dict(r) for r in conversations],
        "dns_queries": [dict(r) for r in dns_queries],
        "http_transactions": [dict(r) for r in http_transactions],
        "tls_sessions": [dict(r) for r in tls_sessions],
        "detail_limit": DETAIL_LIST_LIMIT,
    }
