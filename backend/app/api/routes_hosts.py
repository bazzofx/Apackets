"""Host inventory endpoints.

The graph is built strictly from observed ``conversations`` rows — every edge is a
real conversation, never an inferred subnet or name-resolution relationship.
Node attributes are enriched from the ``hosts`` table when that row exists.

``GET /hosts/{ip}/lookup`` and ``POST /hosts/{ip}/lookup`` are the registration panel
(docs/IP_LOOKUP.md §5): the first is the panel's first paint and makes **no network
request at all**, the second is the only route in this application that sends an address
to a third party, and it does so only when a reader asks for it. The capture-local part
of the answer — the country from the installed DB-IP dataset and the names *this capture*
observed pointing at the address — is read here, from the analysis's own tables, and never
from a registry. Everything else lives in :mod:`app.services.ip_lookup`.
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
from app.core.errors import ApiError, not_found, unprocessable
from app.core.logging import get_logger
from app.db import database as db
from app.services import geoip, ip_lookup
from app.services.host_analyzer import address_scope, is_private_address

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
    data["scope"] = address_scope(data.get("ip"))
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
                # Precise classification (broadcast/multicast/loopback/…), derived
                # from the address itself so it needs no stored column.
                "scope": address_scope(ip),
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
        "scope": address_scope(row["ip"]),
        "packet_count": int(packet_row["n"]) if packet_row else 0,
        "conversations": [dict(r) for r in conversations],
        "dns_queries": [dict(r) for r in dns_queries],
        "http_transactions": [dict(r) for r in http_transactions],
        "tls_sessions": [dict(r) for r in tls_sessions],
        "detail_limit": DETAIL_LIST_LIMIT,
    }


# --------------------------------------------------------------------------
# registration lookup (docs/IP_LOOKUP.md §5)
# --------------------------------------------------------------------------

# §6's cap, taken from the service so one number lives in one place.
LOCAL_NAME_CAP = ip_lookup.LOCAL_NAME_CAP

#: §2/§5.1: a name is shown only when a capture row supports it. ``dns_queries.answer_ips``
#: is a comma-joined list, so the address is matched as a whole element rather than as a
#: substring - ``1.2.3.4`` must not be found inside ``1.2.3.40`` - and the element list is
#: padded with the delimiter on both sides so the first and last elements are matched too.
DNS_NAME_SQL = """
SELECT query_name AS name, COUNT(*) AS rows
  FROM dns_queries
 WHERE analysis_id = ?
   AND query_name IS NOT NULL AND TRIM(query_name) <> ''
   AND answer_ips IS NOT NULL
   AND (',' || REPLACE(answer_ips, ' ', '') || ',') LIKE '%,' || ? || ',%'
 GROUP BY query_name
"""

#: A SNI is sent by the *client* asking for a name, so it points **at** this address only
#: when this address is the session's server - which is what §2 asks for. (The ``hosts``
#: row's own ``tls_sni`` is keyed by the client, because that column answers the different
#: question "what did this host ask for".)
TLS_NAME_SQL = """
SELECT sni AS name, COUNT(*) AS rows
  FROM tls_sessions
 WHERE analysis_id = ?
   AND server_ip = ?
   AND sni IS NOT NULL AND TRIM(sni) <> ''
 GROUP BY sni
"""


def _captured_names(analysis_id: str, ip: str) -> list[dict]:
    """Every name this capture observed pointing at *ip*, with the rows that say so.

    Two sources and two provenance labels (§5.1): DNS answers that carry the address, and
    TLS SNI values of sessions where the address is the server. Ordered by the number of
    rows seen, so the cap keeps the names the capture saw most and not an arbitrary prefix.
    """
    found = [
        {"name": row["name"], "from": "dns_answer", "rows": int(row["rows"])}
        for row in db.query_all(DNS_NAME_SQL, (analysis_id, ip))
    ]
    found += [
        {"name": row["name"], "from": "tls_sni", "rows": int(row["rows"])}
        for row in db.query_all(TLS_NAME_SQL, (analysis_id, ip))
    ]
    found.sort(key=lambda item: (-item["rows"], item["name"], item["from"]))
    return found


def _local_country(ip: str) -> tuple[str | None, str | None]:
    """§3.1: the country the installed DB-IP dataset has for the address, and its source.

    This is ``docs/GEOGRAPHY.md``'s dataset, not the registry: registration is not
    location, so the two claims are shown side by side and never reconciled (§7). A
    non-public address is never offered to the dataset at all.
    """
    country = geoip.country_for(ip)
    if country is None:
        return None, None
    provenance = geoip.load_source() or {}
    label = " ".join(
        str(part) for part in (provenance.get("dataset"), provenance.get("dataset_month")) if part
    )
    return country, label or None


def _local_block(analysis_id: str, ip: str) -> dict:
    """§5.1's ``local`` block: everything the panel can say without a network request."""
    names = _captured_names(analysis_id, ip)
    kept = names[:LOCAL_NAME_CAP]
    country, source = _local_country(ip)
    return {
        "country": country,
        "country_source": source,
        "names": kept,
        "names_truncated": len(kept) < len(names),
    }


def _require_address(ip: str) -> str:
    """The address as §5.2 wants it, or ``422 validation_error``.

    Malformed input is refused here rather than reaching the service, so a typo can never
    become an egress attempt: nothing is sent and nothing is cached for it.
    """
    address = ip_lookup.parse_address(ip)
    if address is None:
        raise unprocessable(
            "validation_error",
            f"'{ip}' is not an IP address.",
            {"ip": ip, "expected": "an IPv4 or IPv6 address, e.g. 150.171.109.217"},
        )
    return str(address)


@router.get("/hosts/{ip}/lookup")
def get_host_lookup(analysis_id: str, ip: str) -> dict:
    """§5.1: the panel's first paint - cached record, capture-local names, class.

    **Never fetches anything.** A missing cache row is an answer (``record: null``), not a
    reason to go and ask, and no part of this response depends on the address having been
    looked up before.
    """
    analysis_ready_row(analysis_id)
    address = _require_address(ip)
    return ip_lookup.envelope(address, local=_local_block(analysis_id, address))


@router.post("/hosts/{ip}/lookup")
def post_host_lookup(analysis_id: str, ip: str) -> dict:
    """§5.2: look this one address up now and cache it, then return §5.1's envelope.

    This is the only route that takes capture-derived data off the host, and it sends the
    address alone - no capture, no filename, no analysis id, no timestamp - to at most two
    public services. A non-public address is answered from itself with ``200`` and
    ``lookup_possible: false`` and makes no request at all; nothing at all coming back from
    a public address is ``502 lookup_failed`` with the reasons, and writes nothing.
    """
    analysis_ready_row(analysis_id)
    address = _require_address(ip)

    try:
        ip_lookup.refresh(address)
    except ip_lookup.LookupFailed as exc:
        raise ApiError(
            502,
            "lookup_failed",
            str(exc),
            {"ip": address, "failures": list(exc.failures)},
        ) from exc

    return ip_lookup.envelope(address, local=_local_block(analysis_id, address))
