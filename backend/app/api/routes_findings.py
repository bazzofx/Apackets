"""Findings API.

* ``GET  /api/analyses/{id}/findings``            — paginated findings + counts
* ``GET  /api/analyses/{id}/findings/rules``      — rule catalogue with hit counts
* ``GET  /api/analyses/{id}/findings/{finding_id}`` — one finding, JSON columns parsed
* ``POST /api/analyses/{id}/findings/rescan``     — re-run the detection engine

Ordering is deliberate rather than alphabetical: findings sort high → medium →
low → informational through an explicit ``CASE`` expression, because the string
ordering of those labels (``high`` < ``informational`` < ``low`` < ``medium``)
would put the least urgent rows first.
"""

from __future__ import annotations

import json
import re
import socket
from functools import lru_cache
from pathlib import Path
from typing import Any, Iterator, Sequence

from fastapi import APIRouter, Depends, Query

from app.api import deps
from app.core.errors import ApiError, bad_request
from app.core.logging import get_logger
from app.db import database as db
from app.services import detection_engine, stream_analyzer, suricata_rules

log = get_logger("apackets.api.findings")

router = APIRouter(prefix="/api/analyses", tags=["findings"])

# Severity is an ordered vocabulary, so the rank is spelled out explicitly.
_SEVERITY_RANK_SQL = (
    "CASE severity "
    "WHEN 'high' THEN 0 "
    "WHEN 'medium' THEN 1 "
    "WHEN 'low' THEN 2 "
    "WHEN 'informational' THEN 3 "
    "ELSE 4 END"
)

# Sort allow-list: client input only ever selects one of these expressions.
# The contract fixes this list at severity, rule_id and title.
_SORT_COLUMNS: dict[str, str] = {
    "severity": _SEVERITY_RANK_SQL,
    "rule_id": "rule_id",
    "title": "title",
}

_JSON_ARRAY_FIELDS = ("packet_numbers",)
_JSON_OBJECT_FIELDS = ("evidence", "entities")


def _escape_like(term: str) -> str:
    """Neutralise LIKE wildcards so a search term is matched literally."""
    return term.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def _order_clause(sort: str | None, order: str | None) -> str:
    """ORDER BY clause from allow-listed columns only.

    ``deps.resolve_sort`` / ``deps.resolve_order`` are the shared helpers, but on
    this revision they build their error with a positional details dict, which
    ``errors.bad_request(code, message, **details)`` cannot accept — so an
    invalid sort raises ``TypeError`` (HTTP 500) instead of the documented
    ``400 invalid_sort``. The narrow fallback below preserves the documented
    contract; it can be deleted once ``deps.py`` passes ``details`` by keyword.
    """
    if not sort:
        # Documented default: severity high -> informational, then rule id, then id.
        return f"{_SEVERITY_RANK_SQL} ASC, rule_id ASC, id ASC"
    try:
        column = deps.resolve_sort(sort, _SORT_COLUMNS, "rule_id")
        direction = deps.resolve_order(order, "asc")
    except ApiError:
        raise
    except TypeError:
        key = sort.strip().lstrip("-")
        if key not in _SORT_COLUMNS:
            raise bad_request(
                "invalid_sort",
                f"Cannot sort by '{sort}'.",
                allowed=sorted(_SORT_COLUMNS),
            ) from None
        value = (order or "asc").strip().lower()
        if value not in {"asc", "desc"}:
            raise bad_request(
                "invalid_order",
                "Order must be 'asc' or 'desc'.",
                order=order,
            ) from None
        column, direction = _SORT_COLUMNS[key], value.upper()
    return f"{column} {direction}, id ASC"


def _serialise(row) -> dict:
    """A finding row with its JSON text columns parsed into real structures."""
    data = dict(row)
    for field in _JSON_ARRAY_FIELDS:
        parsed = deps.json_or(data.get(field), [])
        data[field] = parsed if isinstance(parsed, list) else []
    for field in _JSON_OBJECT_FIELDS:
        parsed = deps.json_or(data.get(field), {})
        data[field] = parsed if isinstance(parsed, dict) else {}

    entities = data.get("entities") or {}
    data["entities"] = {
        "ips": list(entities.get("ips") or []),
        "hostnames": list(entities.get("hostnames") or []),
        "ports": list(entities.get("ports") or []),
        "uris": list(entities.get("uris") or []),
    }
    data["packet_numbers"] = sorted(
        {int(number) for number in data["packet_numbers"] if isinstance(number, (int, float))}
    )
    return data


def _counts(analysis_id: str) -> dict[str, int]:
    counts = {name: 0 for name in detection_engine.SEVERITIES}
    rows = db.query_all(
        "SELECT severity, COUNT(*) AS n FROM findings WHERE analysis_id = ? GROUP BY severity",
        (analysis_id,),
    )
    for row in rows:
        counts[str(row["severity"])] = int(row["n"])
    return counts


@router.get("/{analysis_id}/findings")
def list_findings(
    analysis_id: str,
    pager: deps.Pagination = Depends(deps.pagination),
    sort: str | None = Query(None, description="severity | rule_id | title"),
    order: str | None = Query(None, description="asc | desc"),
    severity: str | None = Query(None),
    rule_id: str | None = Query(None),
    search: str | None = Query(None, description="Substring of title, reason or rule id"),
) -> dict:
    """Paginated findings for one analysis, with severity counts for the whole set."""
    deps.get_ready_analysis(analysis_id)

    where = ["analysis_id = ?"]
    params: list[object] = [analysis_id]

    if severity and severity.strip():
        where.append("severity = ?")
        params.append(severity.strip())
    if rule_id and rule_id.strip():
        where.append("rule_id = ?")
        params.append(rule_id.strip())
    if search and search.strip():
        term = f"%{_escape_like(search.strip())}%"
        where.append(
            "(title LIKE ? ESCAPE '\\' OR reason LIKE ? ESCAPE '\\' "
            "OR description LIKE ? ESCAPE '\\' OR rule_id LIKE ? ESCAPE '\\')"
        )
        params.extend([term, term, term, term])

    clause = " AND ".join(where)
    order_sql = _order_clause(sort, order)

    total_row = db.query_one(f"SELECT COUNT(*) AS n FROM findings WHERE {clause}", tuple(params))
    total = int(total_row["n"]) if total_row else 0

    rows = db.query_all(
        f"""
        SELECT id, analysis_id, rule_id, severity, title, description, reason,
               evidence, packet_numbers, entities, recommendation, created_at
        FROM findings WHERE {clause}
        ORDER BY {order_sql}
        LIMIT ? OFFSET ?
        """,
        tuple([*params, pager.limit, pager.offset]),
    )

    envelope = pager.envelope([_serialise(row) for row in rows], total)
    envelope["counts"] = _counts(analysis_id)
    return envelope


@router.get("/{analysis_id}/findings/rules")
def list_rules(analysis_id: str) -> dict:
    """Every rule in the catalogue with its hit count for this analysis."""
    deps.get_ready_analysis(analysis_id)
    return {"items": detection_engine.list_rules(analysis_id)}


@router.get("/{analysis_id}/findings/{finding_id}")
def get_finding(analysis_id: str, finding_id: str) -> dict:
    """One finding with ``evidence``, ``packet_numbers`` and ``entities`` parsed."""
    deps.get_ready_analysis(analysis_id)
    row = db.query_one(
        """
        SELECT id, analysis_id, rule_id, severity, title, description, reason,
               evidence, packet_numbers, entities, recommendation, created_at
        FROM findings WHERE id = ? AND analysis_id = ?
        """,
        (finding_id, analysis_id),
    )
    if row is None:
        raise ApiError(
            404,
            "finding_not_found",
            f"No finding with id {finding_id} in this analysis.",
            {"finding_id": finding_id, "analysis_id": analysis_id},
        )
    return _serialise(row)


@router.post("/{analysis_id}/findings/rescan")
def rescan_findings(analysis_id: str) -> dict:
    """Re-run the detection engine.

    The rules read the indexed tables, so this is fast enough to run inside the
    request. Findings are cleared and rewritten with deterministic ids, which
    makes repeated runs idempotent. The retained capture is only referenced so
    the result can report whether it is still on disk; it is never re-dissected,
    so a rescan still works when ``retain_uploads`` has purged the upload.
    """
    row = deps.get_ready_analysis(analysis_id)
    capture = Path(row["stored_path"])

    ctx = detection_engine.InlineJobContext(analysis_id=analysis_id)
    stats = detection_engine.analyze(ctx, analysis_id, capture)
    log.info(
        "rescan for %s produced %s finding(s)",
        analysis_id,
        stats.get("findings"),
    )
    return {
        "ok": True,
        "findings": int(stats.get("findings") or 0),
        "by_severity": stats.get("by_severity") or {},
        "rules_run": int(stats.get("rules_run") or 0),
        "rule_errors": stats.get("rule_errors") or {},
        "seconds": stats.get("seconds"),
    }


# ==========================================================================
# finding context
# ==========================================================================
#
# One call that returns everything the Findings workbench needs for a single
# alert: the finding itself, the packets that triggered it, the conversation(s)
# and stream content they belong to, the application-layer records, the files
# that were transferred, the endpoints involved, related findings and a short
# timeline. Correlation is by stream id and packet number first (both are
# recorded by the analyzers), falling back to the observed endpoint pairs.
#
# Every list is capped. The response reports the caps in ``limits`` and whether
# a cap actually bit in ``truncated``, so the UI can say "+N more" instead of
# silently dropping evidence.

# Packet summary columns, mirroring the packets list shape (never payloads).
_CONTEXT_PACKET_COLUMNS = (
    "number, time_epoch, time_relative, src_ip, src_port, dst_ip, dst_port, "
    "protocol, transport, frame_len, tcp_flags, info, protocols, eth_src, eth_dst, "
    "vlan_id, ttl, ip_version, dns_query, http_method, http_host, http_uri, "
    "http_status, tls_sni, tls_version, tcp_stream, udp_stream"
)

_CONTEXT_CAPS: dict[str, int] = {
    "packets": 50,
    "streams": 5,
    "http": 20,
    "dns": 20,
    "tls": 20,
    "objects": 25,
    "related": 10,
    "endpoints": 8,
    "timeline": 60,
}

_MAX_REQUESTED_PACKETS = 500
_HTTP_BODY_PREVIEW = 8192
_STREAM_CHUNK_PREVIEW = 200
_RELATED_SCAN_LIMIT = 500


def _in_clause(values: Sequence[Any]) -> str:
    return ", ".join("?" for _ in values)


@lru_cache(maxsize=256)
def _service_name(port: int | None, transport: str | None) -> str | None:
    """Service name for a port from the local services database.

    This is an operating-system lookup (like the top-ports panel), never a value
    derived from capture content.
    """
    if port is None:
        return None
    try:
        return socket.getservbyport(int(port), (transport or "tcp").lower())
    except (OSError, ValueError, TypeError):
        return None


def _context_finding_row(analysis_id: str, finding_id: str):
    row = db.query_one(
        """
        SELECT id, analysis_id, rule_id, severity, title, description, reason,
               evidence, packet_numbers, entities, recommendation, created_at
        FROM findings WHERE id = ? AND analysis_id = ?
        """,
        (finding_id, analysis_id),
    )
    if row is None:
        raise ApiError(
            404,
            "finding_not_found",
            f"No finding with id {finding_id} in this analysis.",
            {"finding_id": finding_id, "analysis_id": analysis_id},
        )
    return row


def _context_packets(
    analysis_id: str, numbers: Sequence[int], cap: int
) -> tuple[list[dict], bool, list[int]]:
    """The finding's own packets, in capture order."""
    if not numbers:
        return [], False, []
    wanted = list(numbers[:_MAX_REQUESTED_PACKETS])
    rows = db.query_all(
        f"""
        SELECT {_CONTEXT_PACKET_COLUMNS}
        FROM packets
        WHERE analysis_id = ? AND number IN ({_in_clause(wanted)})
        ORDER BY number
        """,
        tuple([analysis_id, *wanted]),
    )
    packets = [dict(row) for row in rows]
    truncated = len(packets) > cap
    selected = packets[:cap]
    packets = []
    for row in selected:
        row["alerting"] = True  # every packet here comes from the finding
        packets.append(row)
    return packets, truncated, [int(row["number"]) for row in packets]


def _stream_keys(packets: Sequence[dict]) -> list[tuple[str, int]]:
    """``(transport, stream_id)`` pairs observed in the finding's packets."""
    keys: list[tuple[str, int]] = []
    for row in packets:
        transport = str(row.get("transport") or "").lower()
        stream_id = row.get("tcp_stream") if transport == "tcp" else row.get("udp_stream")
        if stream_id is None:
            stream_id = row.get("tcp_stream")
            if stream_id is None:
                stream_id = row.get("udp_stream")
                transport = "udp" if stream_id is not None else transport
            else:
                transport = "tcp"
        if stream_id is None:
            continue
        key = (transport or "tcp", int(stream_id))
        if key not in keys:
            keys.append(key)
    return keys


def _context_conversations(
    analysis_id: str, packets: Sequence[dict], keys: Sequence[tuple[str, int]]
) -> list[dict]:
    """Conversations for the streams the alerting packets belong to."""
    if keys:
        clause = " OR ".join("(transport = ? AND stream_id = ?)" for _ in keys)
        params: list[Any] = [analysis_id]
        for transport, stream_id in keys:
            params.extend([transport, stream_id])
        rows = db.query_all(
            f"""
            SELECT * FROM conversations
            WHERE analysis_id = ? AND ({clause})
            ORDER BY bytes_total DESC
            """,
            tuple(params),
        )
        if rows:
            return [dict(row) for row in rows]

    # No stream id was recorded: match the observed endpoint pairs instead.
    pairs: list[tuple] = []
    for row in packets:
        if not row.get("src_ip") or not row.get("dst_ip"):
            continue
        pair = (row["src_ip"], row.get("src_port"), row["dst_ip"], row.get("dst_port"))
        if pair not in pairs:
            pairs.append(pair)
    if not pairs:
        return []

    clauses: list[str] = []
    params = [analysis_id]
    forward = (
        "((ip_a = ? AND (port_a = ? OR ? IS NULL))"
        " AND (ip_b = ? AND (port_b = ? OR ? IS NULL)))"
    )
    for src_ip, src_port, dst_ip, dst_port in pairs[:6]:
        clauses.append(f"({forward} OR {forward})")
        params.extend(
            [src_ip, src_port, src_port, dst_ip, dst_port, dst_port]
            + [dst_ip, dst_port, dst_port, src_ip, src_port, src_port]
        )
    rows = db.query_all(
        f"""
        SELECT * FROM conversations
        WHERE analysis_id = ? AND ({' OR '.join(clauses)})
        ORDER BY bytes_total DESC
        """,
        tuple(params),
    )
    return [dict(row) for row in rows]


def _stream_metadata(analysis_id: str, transport: str, stream_id: int) -> dict | None:
    row = db.query_one(
        "SELECT * FROM streams WHERE analysis_id = ? AND transport = ? AND stream_id = ?",
        (analysis_id, transport, stream_id),
    )
    if row is None:
        row = db.query_one(
            "SELECT * FROM streams WHERE analysis_id = ? AND stream_id = ?",
            (analysis_id, stream_id),
        )
    return dict(row) if row is not None else None

def _context_streams(
    analysis_id: str,
    keys: Sequence[tuple[str, int]],
    cap: int,
    *,
    include_follow: bool,
    mode: str,
) -> tuple[list[dict], bool]:
    """Stream metadata, plus TShark's reassembled follow content when asked for."""
    blocks: list[dict] = []
    truncated = False
    for transport, stream_id in keys:
        if len(blocks) >= cap:
            truncated = True
            break
        if include_follow:
            try:
                payload = stream_analyzer.get_stream(analysis_id, int(stream_id), mode)
            except ApiError as exc:
                # A missing capture or an unrecorded stream must not fail the
                # whole response: report it and keep the rest of the context.
                blocks.append(
                    {
                        "stream": _stream_metadata(analysis_id, transport, stream_id),
                        "follow": None,
                        "unavailable": {
                            "code": getattr(exc, "code", "stream_unavailable"),
                            "message": getattr(exc, "message", str(exc)),
                        },
                    }
                )
                continue
            follow = payload.get("follow")
            if isinstance(follow, dict):
                chunks = follow.get("chunks") or []
                if len(chunks) > _STREAM_CHUNK_PREVIEW:
                    follow = {
                        **follow,
                        "chunks": chunks[:_STREAM_CHUNK_PREVIEW],
                        "chunks_truncated": True,
                    }
            blocks.append({"stream": payload.get("stream"), "follow": follow})
            continue
        blocks.append(
            {
                "stream": _stream_metadata(analysis_id, transport, stream_id),
                "follow": None,
            }
        )
    return blocks, truncated


def _trim_body(value: Any) -> tuple[Any, bool]:
    if not isinstance(value, str):
        return value, False
    if len(value) <= _HTTP_BODY_PREVIEW:
        return value, False
    return value[:_HTTP_BODY_PREVIEW], True


def _context_http(
    analysis_id: str,
    keys: Sequence[tuple[str, int]],
    numbers: Sequence[int],
    cap: int,
) -> tuple[list[dict], bool]:
    clauses: list[str] = []
    params: list[Any] = [analysis_id]
    stream_ids = [stream_id for _transport, stream_id in keys]
    if stream_ids:
        clauses.append(f"stream_id IN ({_in_clause(stream_ids)})")
        params.extend(stream_ids)
    if numbers:
        clause = _in_clause(numbers)
        clauses.append(f"(request_packet IN ({clause}) OR response_packet IN ({clause}))")
        params.extend(numbers)
        params.extend(numbers)
    if not clauses:
        return [], False

    rows = db.query_all(
        f"""
        SELECT * FROM http_transactions
        WHERE analysis_id = ? AND ({' OR '.join(clauses)})
        ORDER BY time_epoch IS NULL, time_epoch, id
        LIMIT ?
        """,
        tuple([*params, cap + 1]),
    )
    truncated = len(rows) > cap
    items: list[dict] = []
    for row in rows[:cap]:
        item = dict(row)
        item["request_headers"] = deps.json_or(item.get("request_headers"), {})
        item["response_headers"] = deps.json_or(item.get("response_headers"), {})
        item["flags"] = deps.json_or(item.get("flags"), [])
        body_cut = False
        for field in ("request_body", "response_body"):
            trimmed, cut = _trim_body(item.get(field))
            item[field] = trimmed
            body_cut = body_cut or cut
        item["body_preview_truncated"] = body_cut or bool(item.get("response_body_truncated"))
        items.append(item)
    return items, truncated


def _context_dns(
    analysis_id: str,
    numbers: Sequence[int],
    entities: dict,
    cap: int,
) -> tuple[list[dict], bool]:
    clauses: list[str] = []
    params: list[Any] = [analysis_id]
    if numbers:
        clause = _in_clause(numbers)
        clauses.append(f"(packet_number IN ({clause}) OR response_packet IN ({clause}))")
        params.extend(numbers)
        params.extend(numbers)
    names = [str(name) for name in (entities.get("hostnames") or [])][:10]
    ips = [str(ip) for ip in (entities.get("ips") or [])][:10]
    if names and ips:
        clauses.append(
            f"(query_name IN ({_in_clause(names)}) AND client_ip IN ({_in_clause(ips)}))"
        )
        params.extend(names)
        params.extend(ips)
    if not clauses:
        return [], False

    rows = db.query_all(
        f"""
        SELECT * FROM dns_queries
        WHERE analysis_id = ? AND ({' OR '.join(clauses)})
        ORDER BY time_epoch IS NULL, time_epoch, id
        LIMIT ?
        """,
        tuple([*params, cap + 1]),
    )
    truncated = len(rows) > cap
    items = []
    for row in rows[:cap]:
        item = dict(row)
        item["answers"] = deps.json_or(item.get("answers"), [])
        item["flags"] = deps.json_or(item.get("flags"), [])
        items.append(item)
    return items, truncated


def _context_tls(
    analysis_id: str,
    keys: Sequence[tuple[str, int]],
    numbers: Sequence[int],
    packets: Sequence[dict],
    cap: int,
) -> tuple[list[dict], bool]:
    clauses: list[str] = []
    params: list[Any] = [analysis_id]
    stream_ids = [stream_id for _transport, stream_id in keys]
    if stream_ids:
        clauses.append(f"stream_id IN ({_in_clause(stream_ids)})")
        params.extend(stream_ids)
    if numbers:
        clause = _in_clause(numbers)
        clauses.append(f"(client_packet IN ({clause}) OR server_packet IN ({clause}))")
        params.extend(numbers)
        params.extend(numbers)
    pairs: list[tuple] = []
    for row in packets:
        if row.get("dst_ip") and row.get("dst_port"):
            pair = (row["dst_ip"], row["dst_port"])
            if pair not in pairs:
                pairs.append(pair)
    if pairs:
        parts = []
        for ip, port in pairs[:6]:
            parts.append("(server_ip = ? AND server_port = ?)")
            params.extend([ip, port])
        clauses.append(" OR ".join(parts))
    if not clauses:
        return [], False

    rows = db.query_all(
        f"""
        SELECT * FROM tls_sessions
        WHERE analysis_id = ? AND ({' OR '.join(clauses)})
        ORDER BY time_epoch IS NULL, time_epoch, id
        LIMIT ?
        """,
        tuple([*params, cap + 1]),
    )
    truncated = len(rows) > cap
    items = []
    for row in rows[:cap]:
        item = dict(row)
        item["flags"] = deps.json_or(item.get("flags"), [])
        items.append(item)
    return items, truncated

_OBJECT_SUFFIX_RE = re.compile(r"_\d+_(?=\.[^.]+$|$)")


def _object_key(filename: str) -> str:
    """Normalise an extracted filename so duplicates still match their URL.

    The extractor names repeated downloads ``<stem>_1_<ext>``, so
    ``fre_1_.php`` and ``fre.php`` must compare equal.
    """
    return _OBJECT_SUFFIX_RE.sub("", filename.strip().lower())


def _context_objects(
    analysis_id: str,
    keys: Sequence[tuple[str, int]],
    numbers: Sequence[int],
    http: Sequence[dict],
    cap: int,
) -> tuple[list[dict], bool]:
    """Files transferred over the streams the alert touches.

    Exact correlation uses ``stream_id`` then packet numbers. This capture
    pipeline currently stores HTTP objects uncorrelated (every link column is
    NULL), so a third, clearly-labelled match compares the object filename with
    the basename of the request URIs seen in the alert's own HTTP transactions.
    Inferred matches are marked ``match: "inferred-uri"`` and the UI says so.
    """
    matched: list[dict] = []
    seen: set[str] = set()

    def add(item: dict, match: str) -> None:
        identifier = str(item.get("id"))
        if identifier in seen:
            return
        seen.add(identifier)
        item["match"] = match
        matched.append(item)

    stream_ids = [stream_id for _transport, stream_id in keys]
    if stream_ids:
        for row in db.query_all(
            f"""
            SELECT * FROM objects
            WHERE analysis_id = ? AND stream_id IN ({_in_clause(stream_ids)})
            ORDER BY size DESC
            """,
            tuple([analysis_id, *stream_ids]),
        ):
            item = dict(row)
            item["packet_numbers"] = deps.json_or(item.get("packet_numbers"), [])
            add(item, "stream")

    wanted = {int(number) for number in numbers}
    if wanted:
        for row in db.query_all(
            "SELECT * FROM objects WHERE analysis_id = ? ORDER BY size DESC LIMIT ?",
            (analysis_id, _RELATED_SCAN_LIMIT),
        ):
            item = dict(row)
            item["packet_numbers"] = deps.json_or(item.get("packet_numbers"), [])
            numbers_in_object = {
                int(number)
                for number in item["packet_numbers"]
                if isinstance(number, (int, float))
            }
            if wanted & numbers_in_object:
                add(item, "packet")

    wanted_names = set()
    for transaction in http:
        uri = transaction.get("uri") or transaction.get("full_uri")
        if not uri:
            continue
        basename = str(uri).split("?")[0].rstrip("/").split("/")[-1]
        if basename:
            wanted_names.add(_object_key(basename))
    if wanted_names:
        for row in db.query_all(
            "SELECT * FROM objects WHERE analysis_id = ? ORDER BY size DESC LIMIT ?",
            (analysis_id, _RELATED_SCAN_LIMIT),
        ):
            item = dict(row)
            if str(item.get("id")) in seen:
                continue
            if _object_key(str(item.get("filename") or "")) in wanted_names:
                item["packet_numbers"] = deps.json_or(item.get("packet_numbers"), [])
                add(item, "inferred-uri")

    truncated = len(matched) > cap
    return matched[:cap], truncated


def _context_endpoints(
    analysis_id: str, packets: Sequence[dict], cap: int
) -> tuple[list[dict], bool]:
    """Source/destination cards: address, the ports involved, and host metadata."""
    grouped: dict[tuple[str, str], dict] = {}
    order: list[tuple[str, str]] = []
    for row in packets:
        transport = str(row.get("transport") or "").lower() or None
        sides = (
            (row.get("src_ip"), row.get("src_port"), "source"),
            (row.get("dst_ip"), row.get("dst_port"), "destination"),
        )
        for ip, port, direction in sides:
            if not ip:
                continue
            key = (str(ip), direction)
            entry = grouped.get(key)
            if entry is None:
                entry = {
                    "ip": str(ip),
                    "direction": direction,
                    "ports": [],
                    "packets_in_alert": 0,
                }
                grouped[key] = entry
                order.append(key)
            entry["packets_in_alert"] += 1
            if port is None:
                continue
            for known in entry["ports"]:
                if known["port"] == port:
                    known["packets"] += 1
                    break
            else:
                entry["ports"].append(
                    {
                        "port": port,
                        "transport": transport,
                        "service": _service_name(port, transport),
                        "packets": 1,
                    }
                )

    truncated = len(order) > cap
    endpoints: list[dict] = []
    for key in order[:cap]:
        entry = grouped[key]
        host = db.query_one(
            "SELECT * FROM hosts WHERE analysis_id = ? AND ip = ?", (analysis_id, entry["ip"])
        )
        host_row = dict(host) if host is not None else {}
        entry.update(
            {
                "mac": host_row.get("mac"),
                "hostnames": deps.json_or(host_row.get("dns_names"), []) or [],
                "tls_sni": deps.json_or(host_row.get("tls_sni"), []) or [],
                "is_private": host_row.get("is_private"),
                "first_seen": host_row.get("first_seen"),
                "last_seen": host_row.get("last_seen"),
                "packets_sent": host_row.get("packets_sent"),
                "packets_received": host_row.get("packets_received"),
                "bytes_sent": host_row.get("bytes_sent"),
                "bytes_received": host_row.get("bytes_received"),
            }
        )
        endpoints.append(entry)
    return endpoints, truncated

def _context_related(
    analysis_id: str, finding: dict, cap: int
) -> tuple[list[dict], bool]:
    """Other findings that share addresses, names, URIs or packets with this one."""
    entities = finding.get("entities") or {}
    ips = {str(value) for value in (entities.get("ips") or [])}
    hostnames = {str(value) for value in (entities.get("hostnames") or [])}
    uris = {str(value) for value in (entities.get("uris") or [])}
    numbers = {int(value) for value in (finding.get("packet_numbers") or [])}

    scored: list[tuple[int, dict]] = []
    rows = db.query_all(
        """
        SELECT id, analysis_id, rule_id, severity, title, description, reason,
               evidence, packet_numbers, entities, recommendation, created_at
        FROM findings
        WHERE analysis_id = ? AND id <> ?
        LIMIT ?
        """,
        (analysis_id, finding.get("id"), _RELATED_SCAN_LIMIT),
    )
    for row in rows:
        other = _serialise(row)
        other_entities = other.get("entities") or {}
        shared: list[str] = []
        for value in sorted(ips & {str(item) for item in (other_entities.get("ips") or [])})[:3]:
            shared.append(f"ip:{value}")
        for value in sorted(hostnames & {str(item) for item in (other_entities.get("hostnames") or [])})[:3]:
            shared.append(f"host:{value}")
        for value in sorted(uris & {str(item) for item in (other_entities.get("uris") or [])})[:3]:
            shared.append(f"uri:{value}")
        overlap = sorted(numbers & {int(item) for item in (other.get("packet_numbers") or [])})
        if overlap:
            shared.append(f"packet:{overlap[0]}")
        if shared:
            entry = {
                "id": other.get("id"),
                "rule_id": other.get("rule_id"),
                "severity": other.get("severity"),
                "title": other.get("title"),
                "created_at": other.get("created_at"),
                "shared": shared,
            }
            scored.append((len(shared), entry))

    scored.sort(key=lambda item: (-item[0], str(item[1].get("rule_id"))))
    return [entry for _score, entry in scored[:cap]], len(scored) > cap


def _context_timeline(
    packets: Sequence[dict],
    http: Sequence[dict],
    dns: Sequence[dict],
    tls: Sequence[dict],
    cap: int,
) -> tuple[list[dict], bool]:
    entries: list[dict] = []
    if packets:
        first = packets[0]
        entries.append(
            {
                "t": first.get("time_epoch"),
                "kind": "packet",
                "packet": first.get("number"),
                "label": f"first packet of the alert ({first.get('protocol') or 'frame'})",
            }
        )
        if len(packets) > 1:
            last = packets[-1]
            entries.append(
                {
                    "t": last.get("time_epoch"),
                    "kind": "packet",
                    "packet": last.get("number"),
                    "label": "last packet of the alert",
                }
            )
    for row in http:
        entries.append(
            {
                "t": row.get("time_epoch"),
                "kind": "http",
                "packet": row.get("request_packet"),
                "label": f"HTTP {row.get('method') or ''} {row.get('uri') or ''}".strip(),
            }
        )
    for row in dns:
        entries.append(
            {
                "t": row.get("time_epoch"),
                "kind": "dns",
                "packet": row.get("packet_number"),
                "label": f"DNS {row.get('query_type') or ''} {row.get('query_name') or ''}".strip(),
            }
        )
    for row in tls:
        entries.append(
            {
                "t": row.get("time_epoch"),
                "kind": "tls",
                "packet": row.get("client_packet"),
                "label": f"TLS {row.get('version') or ''} {row.get('sni') or ''}".strip(),
            }
        )
    entries = [entry for entry in entries if entry.get("t") is not None]
    entries.sort(key=lambda entry: float(entry["t"]))
    truncated = len(entries) > cap
    return entries[:cap], truncated


def _context_rule(finding: dict) -> dict | None:
    """The stored Suricata rule behind a ``suricata:<sid>`` finding."""
    rule_id = str(finding.get("rule_id") or "")
    if not rule_id.startswith("suricata:"):
        return None
    try:
        sid = int(rule_id.split(":", 1)[1])
    except (IndexError, ValueError):
        return None
    row = suricata_rules.get_rule(sid)
    if row is None:
        return None
    rule = dict(row)
    rule["options"] = deps.json_or(rule.get("options"), [])
    rule["unsupported"] = deps.json_or(rule.get("unsupported"), [])
    for field in ("enabled", "supported", "approximate"):
        rule[field] = bool(rule.get(field))
    return rule


def _context_detection_rule(finding: dict) -> dict | None:
    """The built-in rule behind a non-Suricata finding.

    The counterpart of _context_rule for the heuristics in detection_engine: it
    reports the rule's current configuration so the interface can show what fired
    and offer the editor, instead of sending the analyst to a settings page with
    no idea which rule to look for.
    """
    rule_id = str(finding.get("rule_id") or "")
    if not rule_id or rule_id.startswith("suricata:"):
        return None
    spec = detection_engine.RULES.get(rule_id)
    if spec is None:
        return None
    params = detection_engine.load_config().get(rule_id) or {}
    return {
        "rule_id": rule_id,
        "title": spec.title,
        "severity": spec.severity,
        "description": spec.description,
        "enabled": bool(params.get("enabled", True)),
        "threshold": spec.threshold_text(params),
        "thresholds": {key: value for key, value in params.items() if key != "enabled"},
        "defaults": dict(spec.defaults),
        "notes": spec.notes,
    }


def _context_analysis(row) -> dict:
    return {
        "id": row["id"],
        "original_filename": row["original_filename"],
        "status": row["status"],
        "packet_count": row["packet_count"],
        "bytes_total": row["bytes_total"],
        "capture_start": row["capture_start"],
        "capture_end": row["capture_end"],
        "duration": row["duration"],
        "file_type": row["file_type"],
        "encapsulation": row["encapsulation"],
        "finished_at": row["finished_at"],
    }


@router.get("/{analysis_id}/findings/{finding_id}/context")
def get_finding_context(
    analysis_id: str,
    finding_id: str,
    packets_limit: int = Query(_CONTEXT_CAPS["packets"], ge=1, le=500),
    streams_limit: int = Query(_CONTEXT_CAPS["streams"], ge=1, le=50),
    http_limit: int = Query(_CONTEXT_CAPS["http"], ge=1, le=200),
    dns_limit: int = Query(_CONTEXT_CAPS["dns"], ge=1, le=200),
    tls_limit: int = Query(_CONTEXT_CAPS["tls"], ge=1, le=200),
    objects_limit: int = Query(_CONTEXT_CAPS["objects"], ge=1, le=200),
    related_limit: int = Query(_CONTEXT_CAPS["related"], ge=1, le=50),
    include_follow: bool = Query(True, description="include TShark's reassembled stream text"),
    follow_mode: str = Query("ascii", pattern="^(ascii|hex|raw)$"),
) -> dict:
    """Everything needed to investigate one finding, in a single response.

    Correlation runs stream id first (recorded by the analyzers on packets,
    conversations, HTTP, TLS and objects) and falls back to the endpoint pairs
    observed in the finding's own packets. Lists are capped and the caps are
    reported so the UI can show "+N more" rather than hide evidence.
    """
    analysis_row = deps.get_ready_analysis(analysis_id)
    finding = _serialise(_context_finding_row(analysis_id, finding_id))

    numbers = [int(value) for value in (finding.get("packet_numbers") or [])]
    packets, packets_truncated, _returned = _context_packets(analysis_id, numbers, packets_limit)
    keys = _stream_keys(packets)
    conversations = _context_conversations(analysis_id, packets, keys)
    streams, streams_truncated = _context_streams(
        analysis_id, keys, streams_limit, include_follow=include_follow, mode=follow_mode
    )
    http, http_truncated = _context_http(analysis_id, keys, numbers, http_limit)
    dns, dns_truncated = _context_dns(analysis_id, numbers, finding.get("entities") or {}, dns_limit)
    tls, tls_truncated = _context_tls(analysis_id, keys, numbers, packets, tls_limit)
    objects, objects_truncated = _context_objects(analysis_id, keys, numbers, http, objects_limit)
    endpoints, endpoints_truncated = _context_endpoints(analysis_id, packets, _CONTEXT_CAPS["endpoints"])
    related, related_truncated = _context_related(analysis_id, finding, related_limit)
    timeline, timeline_truncated = _context_timeline(
        packets, http, dns, tls, _CONTEXT_CAPS["timeline"]
    )

    return {
        "finding": finding,
        "rule": _context_rule(finding),
        "detection_rule": _context_detection_rule(finding),
        "analysis": _context_analysis(analysis_row),
        "endpoints": endpoints,
        "packets": packets,
        "conversations": conversations,
        "streams": streams,
        "http": http,
        "dns": dns,
        "tls": tls,
        "objects": objects,
        "related": related,
        "timeline": timeline,
        "limits": {
            "packets": packets_limit,
            "streams": streams_limit,
            "http": http_limit,
            "dns": dns_limit,
            "tls": tls_limit,
            "objects": objects_limit,
            "related": related_limit,
            "endpoints": _CONTEXT_CAPS["endpoints"],
            "timeline": _CONTEXT_CAPS["timeline"],
        },
        "counts": {
            "packets": len(packets),
            "alerting_packets": len(numbers),
            "conversations": len(conversations),
            "streams": len(streams),
            "http": len(http),
            "dns": len(dns),
            "tls": len(tls),
            "objects": len(objects),
            "endpoints": len(endpoints),
            "related": len(related),
        },
        "truncated": {
            "packets": packets_truncated,
            "streams": streams_truncated,
            "http": http_truncated,
            "dns": dns_truncated,
            "tls": tls_truncated,
            "objects": objects_truncated,
            "endpoints": endpoints_truncated,
            "related": related_truncated,
            "timeline": timeline_truncated,
        },
        "follow_mode": follow_mode,
        "include_follow": include_follow,
    }

# ---------------------------------------------------------------------------
# Alert -> conversation linkage
#
# The Conversations flow already carries the conversation keys behind every node
# and band, so the only thing this endpoint has to do is answer: which
# conversations do the alerts belong to? The link is the frames each finding
# recorded -- frame numbers -> the packet index -> the TCP/UDP stream id -> the
# conversation key the flow uses (`transport:stream_id`). Nothing is inferred
# from similarity of addresses.
# ---------------------------------------------------------------------------

SEVERITY_ORDER: tuple[str, ...] = ("informational", "low", "medium", "high")

# Frame numbers are queried in chunks to stay well inside SQLite's parameter
# ceiling, and the total is capped so a pathological finding cannot make this
# endpoint expensive.
_SQL_CHUNK = 900
_MAX_LINK_PACKETS = 20000

ALERT_LINK_NOTE = (
    "Alerts are tied to conversations through the frames each finding records: the "
    "frame numbers are looked up in the packet index and their TCP/UDP stream id names "
    "the conversation. A finding with no frame numbers, whose frames are absent from "
    "the index, or whose frames carry no stream id cannot be placed on the diagram; "
    "those are counted in unlinked_findings rather than guessed at."
)


def _severities_at_least(minimum: str) -> tuple[str, ...]:
    value = (minimum or "medium").strip().lower()
    if value not in SEVERITY_ORDER:
        raise bad_request(
            "invalid_min_severity",
            "min_severity must be one of: " + ", ".join(SEVERITY_ORDER) + ".",
            {"min_severity": minimum},
        )
    return SEVERITY_ORDER[SEVERITY_ORDER.index(value) :]


def _chunks(values: Sequence[Any], size: int = _SQL_CHUNK) -> Iterator[Sequence[Any]]:
    for start in range(0, len(values), size):
        yield values[start : start + size]


def _loads(value: Any, fallback: Any) -> Any:
    if value is None:
        return fallback
    if isinstance(value, (list, dict)):
        return value
    try:
        return json.loads(value)
    except (TypeError, ValueError):
        return fallback


def _max_severity(current: str | None, candidate: str) -> str:
    """The more urgent of two severities; unknown labels never win."""
    if current is None:
        return candidate if candidate in SEVERITY_ORDER else "informational"
    if candidate not in SEVERITY_ORDER:
        return current
    return (
        candidate
        if SEVERITY_ORDER.index(candidate) > SEVERITY_ORDER.index(current)
        else current
    )


def _conversation_key(transport: Any, stream_id: Any) -> str | None:
    """The same key the frontend builds: `transport:String(stream_id)`."""
    if transport not in ("tcp", "udp") or stream_id is None:
        return None
    return f"{transport}:{stream_id}"


@router.get("/{analysis_id}/alerts/conversations")
def alert_conversations(
    analysis_id: str,
    min_severity: str = Query("medium", description="informational | low | medium | high"),
    source: str = Query("all", pattern="^(suricata|all)$"),
) -> dict:
    """Alerts above a severity, resolved to the conversations they belong to.

    Built for the Conversations flow highlight layer: `by_conversation` is keyed by
    the flow's own conversation key, so a band or node lights up by intersecting its
    `keys` with this map. `by_ip` is a fallback for conversations the diagram cannot
    address by stream id.

    ``source`` defaults to ``all`` — both the imported Suricata rules and the built-in
    detection engine. That default is deliberate: the Findings page shows both, so an
    overlay that silently answered for only one source would disagree with it (a
    capture whose medium findings are all built-in, such as ``dns_nxdomain_burst``,
    would report zero medium alerts). Pass ``source=suricata`` to isolate the imported
    rules; each alert's ``rule_id`` states which source it came from
    (``suricata:<sid>`` versus a built-in rule name).
    """
    deps.analysis_ready_row(analysis_id)
    severities = _severities_at_least(min_severity)
    source_clause = " AND rule_id LIKE 'suricata:%'" if source == "suricata" else ""

    placeholders = ", ".join("?" for _ in severities)
    rows = db.query_all(
        f"""
        SELECT id, rule_id, severity, title, reason, packet_numbers, entities
          FROM findings
         WHERE analysis_id = ?
           AND severity IN ({placeholders})
           {source_clause}
         ORDER BY {_SEVERITY_RANK_SQL}, rule_id, id
        """,
        [analysis_id, *severities],
    )

    # Every severity, so the UI can say "+N below the threshold are not shown".
    all_counts = {name: 0 for name in SEVERITY_ORDER}
    for row in db.query_all(
        f"""
        SELECT severity, COUNT(*) AS n
          FROM findings
         WHERE analysis_id = ? {source_clause}
         GROUP BY severity
        """,
        [analysis_id],
    ):
        key = str(row["severity"] or "").lower()
        if key in all_counts:
            all_counts[key] = int(row["n"])

    # Stream ids the diagram can actually address: only conversations that carry one
    # are reachable by key, so anything else is reported rather than fabricated.
    conversations: dict[str, dict[str, Any]] = {}
    for row in db.query_all(
        """
        SELECT conv_id, transport, stream_id, ip_a, ip_b, port_a, port_b
          FROM conversations
         WHERE analysis_id = ?
        """,
        (analysis_id,),
    ):
        key = _conversation_key(row["transport"], row["stream_id"])
        if key is not None and key not in conversations:
            conversations[key] = dict(row)

    # Frames -> stream ids, in capped chunks.
    findings_payload: list[dict[str, Any]] = []
    wanted: list[int] = []
    for row in rows:
        numbers = _loads(row["packet_numbers"], [])
        if not isinstance(numbers, list):
            numbers = []
        parsed: list[int] = []
        for number in numbers:
            try:
                parsed.append(int(number))
            except (TypeError, ValueError):
                continue
        findings_payload.append(
            {
                "finding_id": row["id"],
                "rule_id": row["rule_id"],
                "severity": str(row["severity"] or "").lower(),
                "title": row["title"],
                "packet_numbers": parsed,
            }
        )
        wanted.extend(parsed)

    wanted = sorted(set(wanted))
    truncated = len(wanted) > _MAX_LINK_PACKETS
    if truncated:
        wanted = wanted[:_MAX_LINK_PACKETS]

    frame_streams: dict[int, list[str]] = {}
    for chunk in _chunks(wanted):
        if not chunk:
            continue
        marks = ", ".join("?" for _ in chunk)
        for row in db.query_all(
            f"""
            SELECT number, tcp_stream, udp_stream
              FROM packets
             WHERE analysis_id = ? AND number IN ({marks})
            """,
            [analysis_id, *chunk],
        ):
            keys: list[str] = []
            tcp_key = _conversation_key("tcp", row["tcp_stream"])
            udp_key = _conversation_key("udp", row["udp_stream"])
            if tcp_key is not None:
                keys.append(tcp_key)
            if udp_key is not None:
                keys.append(udp_key)
            frame_streams[int(row["number"])] = keys

    by_conversation: dict[str, dict[str, Any]] = {}
    by_ip: dict[str, dict[str, Any]] = {}
    alerts: list[dict[str, Any]] = []
    unlinked = 0

    for item in findings_payload:
        keys: set[str] = set()
        for number in item["packet_numbers"]:
            for key in frame_streams.get(number, ()):
                if key in conversations:
                    keys.add(key)

        alerts.append(item)

        if keys:
            item["conversations"] = sorted(keys)
            item["linked_by"] = "packets"
        else:
            item["conversations"] = []
            item["linked_by"] = "none"
            unlinked += 1

        for key in keys:
            entry = by_conversation.get(key)
            if entry is None:
                entry = {
                    "severity": item["severity"],
                    "finding_ids": [],
                    "rules": [],
                    "titles": [],
                }
                by_conversation[key] = entry
            entry["severity"] = _max_severity(entry["severity"], item["severity"])
            if item["finding_id"] not in entry["finding_ids"]:
                entry["finding_ids"].append(item["finding_id"])
            if item["rule_id"] not in entry["rules"]:
                entry["rules"].append(item["rule_id"])
            if item["title"] not in entry["titles"]:
                entry["titles"].append(item["title"])

            conversation = conversations[key]
            for ip in (conversation.get("ip_a"), conversation.get("ip_b")):
                if not ip:
                    continue
                ip_entry = by_ip.get(ip)
                if ip_entry is None:
                    ip_entry = {"severity": item["severity"], "finding_ids": [], "conversations": []}
                    by_ip[ip] = ip_entry
                ip_entry["severity"] = _max_severity(ip_entry["severity"], item["severity"])
                if item["finding_id"] not in ip_entry["finding_ids"]:
                    ip_entry["finding_ids"].append(item["finding_id"])
                if key not in ip_entry["conversations"]:
                    ip_entry["conversations"].append(key)

    counts = {name: 0 for name in SEVERITY_ORDER}
    for item in alerts:
        if item["severity"] in counts:
            counts[item["severity"]] += 1

    for entry in by_conversation.values():
        entry["finding_ids"].sort()
        entry["rules"].sort()
    for entry in by_ip.values():
        entry["finding_ids"].sort()
        entry["conversations"].sort()

    return {
        "analysis_id": analysis_id,
        "min_severity": min_severity,
        "source": source,
        "counts": counts,
        "all_counts": all_counts,
        "alerts": alerts,
        "by_conversation": by_conversation,
        "by_ip": by_ip,
        "linked_conversations": len(by_conversation),
        "unlinked_findings": unlinked,
        "packets_scanned": len(wanted),
        "packets_truncated": truncated,
        "note": ALERT_LINK_NOTE,
    }
