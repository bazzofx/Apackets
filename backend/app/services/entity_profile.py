"""Per-entity answers for the Investigate section.

Where :mod:`app.services.threat_hunt` asks seventeen fixed questions of a whole
capture, this module asks *about one thing* — an address, a name or a URL that
appears in the capture — and answers with the same vocabulary: a headline count,
a chart drawn from real rows, an interpretation, a caveat, and links into the
pages that own the underlying data.

Two rules from ``docs/ENTITY_PROFILE.md`` §3 govern every number here:

* it is measured, never estimated. A question whose source table holds no rows
  for this analysis, or whose entity never appears in that layer, reports
  ``availability: "not_applicable"`` with the reason; a question that was
  computable but found nothing reports ``"empty"`` plus the thing that was
  measured. ``headline.value`` is therefore ``0`` only when the availability is
  not ``"ok"``, so a zero on screen always means "nothing matched" rather than
  "not computed";
* availability is not decoration. An address that simply never used DNS in this
  capture must not be shown as "asked for no names": the capture holds no
  evidence either way, so the question is ``not_applicable``.

Everything is a read-only SQL aggregate over ``packets``, ``conversations``,
``dns_queries``, ``http_transactions``, ``tls_sessions``, ``hosts``, ``findings``
and ``objects``. TShark is never invoked and nothing is added to the import
pipeline, so the section stays fast and keeps working after an upload has been
purged. No index, no ``ANALYZE`` and no write is performed.

Address classification comes from :mod:`app.services.host_analyzer`
(``address_scope`` for display, ``is_private_address`` for the private/public
split) and the well-known-port labels are the detection engine's own
:data:`~app.services.detection_engine.COMMON_PORTS`, so this section cannot
drift from the findings it sits next to.
"""

from __future__ import annotations

import json
import math
import re
import time
from dataclasses import dataclass, field
from typing import Any, Iterable, Sequence
from urllib.parse import quote

from app.core.logging import get_logger
from app.db import database as db
from app.services.detection_engine import COMMON_PORTS
from app.services.host_analyzer import address_scope, is_private_address

log = get_logger("shadowpackets.entity_profile")

# --------------------------------------------------------------------------
# caps and bounds (§3)
# --------------------------------------------------------------------------

PROFILE_CAP = 50       # rows in any `table` visual
BARS_CAP = 12          # bars in any `bars` visual
TIMELINE_CAP = 240     # buckets in a `timeline`
SCATTER_CAP = 200      # points in a `scatter`
HEATMAP_CAP = 15       # rows and columns in a `heatmap`
MATCH_CAP = 25         # search matches (the default `limit`)

KINDS: tuple[str, ...] = ("ip", "domain", "url")

#: How a kind is named in a sentence a reader will see.
KIND_NOUNS: dict[str, str] = {
    "ip": "address",
    "domain": "name",
    "url": "request URI",
}


def _noun(kind: str) -> str:
    return KIND_NOUNS.get(kind, kind)

DEFAULT_WINDOW = 60    # seconds per timeline bucket; the route exposes no override
MIN_WINDOW = 5
MAX_WINDOW = 3600

MIN_QUERY_LENGTH = 1
MAX_QUERY_LENGTH = 200
MAX_MATCH_LIMIT = 100

# Every row scan is bounded so a pathological capture cannot make the endpoint
# unbounded; when the bound bites it is stated in the visual's `note`.
ROW_SCAN_CAP = 20000
ENTITY_FRAME_CAP = 20000

# Presentation only — never a verdict.
TONE_INFO = "info"
TONE_WATCH = "watch"

_SEVERITY_RANK = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
    "informational": 4,
    "info": 4,
}

NO_RESPONSE = "no response recorded"

FAILED_REASON = "internal error while computing this question from the index"

# Inter-packet gaps, used to say whether activity was steady or bursty.
_GAP_EDGES: tuple[tuple[float, str], ...] = (
    (0.1, "under 0.1 s"),
    (1.0, "0.1-1 s"),
    (5.0, "1-5 s"),
    (60.0, "5-60 s"),
    (900.0, "1-15 min"),
    (math.inf, "15 min and over"),
)

# --------------------------------------------------------------------------
# small helpers
# --------------------------------------------------------------------------


def _to(path: str, **params: Any) -> str:
    """A link target built only from the parameters listed in §5.

    Every interpolated value is percent-encoded the way ``encodeURIComponent``
    would encode it, so a host name, URI or address cannot break out of the
    query string.
    """
    clean = {key: value for key, value in params.items() if value is not None and value != ""}
    if not clean:
        return path
    query = "&".join(f"{key}={quote(str(value), safe='')}" for key, value in clean.items())
    return f"{path}?{query}"


def _link(path: str, label: str) -> dict:
    return {"to": path, "label": label}


def _cap_note(shown: int, total: int, noun: str) -> str:
    """§3: a cap that bites is stated as ``showing <returned> of <total>``."""
    if total > shown:
        return f"showing {shown} of {total} {noun}"
    return ""


def _number(value: float) -> float | int:
    if isinstance(value, float) and value.is_integer():
        return int(value)
    return value


def _as_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _json_list(raw: Any) -> list:
    if isinstance(raw, list):
        return raw
    if not isinstance(raw, str) or not raw.strip():
        return []
    try:
        parsed = json.loads(raw)
    except (TypeError, ValueError):
        return []
    return parsed if isinstance(parsed, list) else []


def _json_dict(raw: Any) -> dict:
    if isinstance(raw, dict):
        return raw
    if not isinstance(raw, str) or not raw.strip():
        return {}
    try:
        parsed = json.loads(raw)
    except (TypeError, ValueError):
        return {}
    return parsed if isinstance(parsed, dict) else {}


def _split_values(raw: Any) -> list[str]:
    """``answer_ips``/``cnames`` are stored comma-joined, not as JSON."""
    if raw is None:
        return []
    return [part.strip() for part in str(raw).split(",") if part.strip()]


def _like_value(query: str) -> str:
    """A ``LIKE`` pattern for a literal substring, with ``%``/``_`` escaped."""
    escaped = query.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    return f"%{escaped}%"


def _scope_label(value: Any) -> str:
    return address_scope(value) or "unknown"


def _stamp(value: Any) -> str:
    """A capture timestamp the way a reader can use it: UTC, seconds precision.

    Every timestamp in the index is Unix epoch seconds, so rendering the raw
    number would only be readable to someone doing the arithmetic themselves.
    """
    if value is None:
        return ""
    try:
        moment = float(value)
    except (TypeError, ValueError):
        return ""
    return time.strftime("%Y-%m-%d %H:%M:%SZ", time.gmtime(moment))


def _port_label(port: Any) -> str:
    """``443`` reads better as ``443 (common port)``.

    "Common" is the detection engine's own well-known set, so a port is described
    here exactly as the findings next to it describe it. Nothing guesses a
    service name from a number.
    """
    return f"{port} (common port)" if _as_int(port) in COMMON_PORTS else str(port)


def _bucket_label(value: float, edges: Sequence[tuple[float, str]]) -> str:
    for limit, label in edges:
        if value < limit:
            return label
    return edges[-1][1]


def _series(
    events: Iterable[tuple[float | None, float]],
    window: int,
    cap: int = TIMELINE_CAP,
) -> tuple[list[dict], int]:
    """Bucket ``(timestamp, weight)`` pairs into a timeline, oldest first."""
    buckets: dict[int, float] = {}
    for moment, weight in events:
        if moment is None:
            continue
        index = int(math.floor(float(moment) / float(window)))
        buckets[index] = buckets.get(index, 0.0) + weight
    ordered = sorted(buckets.items())
    total = len(ordered)
    points = [
        {"t": float(index * window), "value": _number(value), "marker": False}
        for index, value in ordered[:cap]
    ]
    return points, total


def _private(value: Any) -> bool:
    return is_private_address(value) == 1


# --------------------------------------------------------------------------
# visual assembly — one helper per kind of §3, so the frontend's existing
# renderers draw these and the Threat Hunt cards with the same code
# --------------------------------------------------------------------------


def _visual(kind: str, title: str, **payload: Any) -> dict:
    visual = {"kind": kind, "title": title}
    visual.update(payload)
    visual.setdefault("note", "")
    return visual


def _bars(title: str, items: list[dict], unit: str, note: str = "") -> dict:
    return _visual("bars", title, items=items, unit=unit, note=note)


def _timeline(title: str, points: list[dict], unit: str, note: str = "") -> dict:
    return _visual("timeline", title, points=points, unit=unit, note=note)


def _histogram(title: str, buckets: list[dict], unit: str, note: str = "") -> dict:
    return _visual("histogram", title, buckets=buckets, unit=unit, note=note)


def _scatter(title: str, points: list[dict], x_label: str, y_label: str, note: str = "") -> dict:
    return _visual(
        "scatter", title, points=points, x_label=x_label, y_label=y_label, note=note
    )


def _heatmap(title: str, columns: list[str], rows: list[dict], unit: str, note: str = "") -> dict:
    return _visual("heatmap", title, columns=columns, rows=rows, unit=unit, note=note)


def _table(title: str, columns: list[str], rows: list[dict], note: str = "") -> dict:
    return _visual("table", title, columns=columns, rows=rows, note=note)


def _cell(text: Any, *, tone: str | None = None, to: str | None = None) -> dict:
    cell: dict[str, Any] = {"text": "" if text is None else str(text)}
    if tone:
        cell["tone"] = tone
    if to:
        cell["to"] = to
    return cell


def _ranked_bars(
    title: str, items: list[dict], unit: str, noun: str
) -> tuple[dict, int, int]:
    """Bars arrive sorted largest first and capped at :data:`BARS_CAP`.

    Returns ``(visual, shown, total)`` so the caller can both state the cap in
    the note and record it in the response's ``truncated`` map.
    """
    ordered = sorted(items, key=lambda item: (-float(item["value"]), str(item["label"])))
    total = len(ordered)
    shown_items = ordered[:BARS_CAP]
    return (
        _bars(title, shown_items, unit, _cap_note(len(shown_items), total, noun)),
        len(shown_items),
        total,
    )


def _capped_table(
    title: str,
    columns: list[str],
    rows: list[dict],
    noun: str,
    *,
    total: int | None = None,
) -> tuple[dict, int, int]:
    """A table capped at :data:`PROFILE_CAP` rows, cap stated in the note.

    ``rows`` may already be a capped prefix of the real list; ``total`` then
    states how many rows there really were, so the note and the response's
    ``truncated`` map report the cap that actually bit rather than the size of
    the slice the caller handed over.
    """
    real_total = len(rows) if total is None else int(total)
    shown_rows = rows[:PROFILE_CAP]
    return (
        _table(title, columns, shown_rows, _cap_note(len(shown_rows), real_total, noun)),
        len(shown_rows),
        real_total,
    )


def _capped_timeline(
    title: str, events: Iterable[tuple[float | None, float]], unit: str, window: int
) -> tuple[dict, int, int]:
    points, total = _series(events, window)
    return (
        _timeline(
            title,
            points,
            unit,
            _cap_note(len(points), total, f"bucket(s) of {window} s"),
        ),
        len(points),
        total,
    )


def _capped_scatter(
    title: str, points: list[dict], x_label: str, y_label: str, noun: str
) -> tuple[dict, int, int]:
    total = len(points)
    shown = points[:SCATTER_CAP]
    return (
        _scatter(title, shown, x_label, y_label, _cap_note(len(shown), total, noun)),
        len(shown),
        total,
    )


# --------------------------------------------------------------------------
# question specs
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class _Spec:
    id: str
    title: str
    question: str
    interpretation: str
    caveat: str
    shapes: tuple[str, ...]


@dataclass
class _Result:
    availability: str
    reason: str | None
    headline_value: float
    headline_label: str
    tone: str = TONE_INFO
    visuals: list[dict] = field(default_factory=list)
    links: list[dict] = field(default_factory=list)
    truncated: bool = False


def _not_applicable(reason: str) -> _Result:
    return _Result("not_applicable", reason, 0, "not computable from this capture")


def _empty(
    reason: str,
    *,
    visuals: list[dict] | None = None,
    links: list[dict] | None = None,
    label: str = "nothing matched",
    truncated: bool = False,
) -> _Result:
    return _Result("empty", reason, 0, label, TONE_INFO, visuals or [], links or [], truncated)


# --------------------------------------------------------------------------
# index context
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class _Index:
    """Row counts that decide whether a question can be computed at all."""

    analysis_id: str
    packets: int
    conversations: int
    dns: int
    http: int
    tls: int
    hosts: int
    findings: int
    objects: int

    @property
    def has_traffic(self) -> bool:
        return self.packets > 0


@dataclass
class _Ctx:
    """Everything a builder needs: the index, the entity, and small caches."""

    analysis_id: str
    kind: str
    entity: str
    window: int
    index: _Index
    cache: dict[str, Any] = field(default_factory=dict)

    def remember(self, key: str, factory) -> Any:
        if key not in self.cache:
            self.cache[key] = factory()
        return self.cache[key]


def _load_index(analysis_id: str) -> _Index:
    return _Index(
        analysis_id=analysis_id,
        packets=db.count(analysis_id, "packets"),
        conversations=db.count(analysis_id, "conversations"),
        dns=db.count(analysis_id, "dns_queries"),
        http=db.count(analysis_id, "http_transactions"),
        tls=db.count(analysis_id, "tls_sessions"),
        hosts=db.count(analysis_id, "hosts"),
        findings=db.count(analysis_id, "findings"),
        objects=db.count(analysis_id, "objects"),
    )


NO_PACKETS = "the packet index holds no rows for this capture"
NO_CONVERSATIONS = "the conversation index holds no rows for this capture"
NO_DNS = "the capture recorded no DNS queries"
NO_HTTP = "the capture recorded no HTTP transactions"
NO_TLS = "the capture recorded no TLS sessions"
NO_HOSTS = "the host index holds no rows for this capture"
NO_FINDINGS = "the capture recorded no findings"
NO_OBJECTS = "the capture recorded no extracted objects"


def _absent(ctx: _Ctx, layer: str) -> str:
    """The §3 reason for an entity that never appears in one layer."""
    return (
        f"this capture holds no {layer} row that names {ctx.entity!r}, so the capture "
        f"cannot answer it for this {_noun(ctx.kind)}"
    )


# --------------------------------------------------------------------------
# entity presence and the rows behind it
# --------------------------------------------------------------------------


def _entity_present(ctx: _Ctx) -> bool:
    """True when anything in the index names this entity at all.

    §2: an unknown entity is not an error — every question reports
    ``not_applicable``. This is the single check that decides that case, so a
    stale link cannot accidentally be answered with an invented zero.
    """
    aid, value = ctx.analysis_id, ctx.entity
    if ctx.kind == "ip":
        row = db.query_one(
            """
            SELECT
              EXISTS(SELECT 1 FROM hosts WHERE analysis_id = ? AND ip = ?)
              OR EXISTS(SELECT 1 FROM packets WHERE analysis_id = ? AND (src_ip = ? OR dst_ip = ?))
              OR EXISTS(SELECT 1 FROM conversations
                         WHERE analysis_id = ? AND (ip_a = ? OR ip_b = ?))
              OR EXISTS(SELECT 1 FROM dns_queries
                         WHERE analysis_id = ? AND (client_ip = ? OR server_ip = ?))
              OR EXISTS(SELECT 1 FROM tls_sessions
                         WHERE analysis_id = ? AND (client_ip = ? OR server_ip = ?))
              OR EXISTS(SELECT 1 FROM http_transactions
                         WHERE analysis_id = ? AND (client_ip = ? OR server_ip = ?))
              AS found
            """,
            (
                aid, value,
                aid, value, value,
                aid, value, value,
                aid, value, value,
                aid, value, value,
                aid, value, value,
            ),
        )
    elif ctx.kind == "domain":
        row = db.query_one(
            """
            SELECT
              EXISTS(SELECT 1 FROM dns_queries WHERE analysis_id = ? AND query_name = ? COLLATE NOCASE)
              OR EXISTS(SELECT 1 FROM http_transactions WHERE analysis_id = ? AND host = ? COLLATE NOCASE)
              OR EXISTS(SELECT 1 FROM tls_sessions WHERE analysis_id = ? AND sni = ? COLLATE NOCASE)
              AS found
            """,
            (aid, value, aid, value, aid, value),
        )
    else:
        row = db.query_one(
            "SELECT EXISTS(SELECT 1 FROM http_transactions "
            "WHERE analysis_id = ? AND uri = ?) AS found",
            (aid, value),
        )
    return bool(row and row["found"])


def _frames_for(ctx: _Ctx) -> tuple[list[int], bool]:
    """Frame numbers carrying this address, capped.

    ``packets.number`` is ``frame.number``, the same numbering the findings and
    the objects table record, so this set is what ties those rows to an address.
    """
    def build() -> tuple[list[int], bool]:
        if ctx.kind != "ip" or not ctx.index.packets:
            return [], False
        rows = db.query_all(
            """
            SELECT number FROM packets
             WHERE analysis_id = ? AND (src_ip = ? OR dst_ip = ?)
             ORDER BY number ASC
             LIMIT ?
            """,
            (ctx.analysis_id, ctx.entity, ctx.entity, ENTITY_FRAME_CAP + 1),
        )
        truncated = len(rows) > ENTITY_FRAME_CAP
        return [int(row["number"]) for row in rows[:ENTITY_FRAME_CAP]], truncated

    return ctx.remember("frames", build)


def _ip_conversations(ctx: _Ctx) -> list[dict]:
    """Every conversation this address took part in, with its own ports resolved."""
    def build() -> list[dict]:
        if ctx.kind != "ip" or not ctx.index.conversations:
            return []
        rows = db.query_all(
            """
            SELECT conv_id, transport, stream_id, ip_a, port_a, ip_b, port_b,
                   packets_a_to_b, bytes_a_to_b, packets_b_to_a, bytes_b_to_a,
                   packets_total, bytes_total, start_time, end_time, state
              FROM conversations
             WHERE analysis_id = ? AND (ip_a = ? OR ip_b = ?)
             ORDER BY bytes_total DESC, start_time IS NULL, start_time ASC, conv_id ASC
             LIMIT ?
            """,
            (ctx.analysis_id, ctx.entity, ctx.entity, ROW_SCAN_CAP),
        )
        out: list[dict] = []
        for row in rows:
            initiator = str(row["ip_a"]) == ctx.entity
            peer = str(row["ip_b"]) if initiator else str(row["ip_a"])
            packets = int(row["packets_a_to_b"] or 0) if initiator else int(row["packets_b_to_a"] or 0)
            bytes_sent = int(row["bytes_a_to_b"] or 0) if initiator else int(row["bytes_b_to_a"] or 0)
            received = int(row["packets_b_to_a"] or 0) if initiator else int(row["packets_a_to_b"] or 0)
            received_bytes = int(row["bytes_b_to_a"] or 0) if initiator else int(row["bytes_a_to_b"] or 0)
            out.append(
                {
                    "conv_id": row["conv_id"],
                    "transport": row["transport"],
                    "stream_id": row["stream_id"],
                    "peer": peer,
                    # `endpoint_b` is the side that received the flow, so `port_b` is
                    # the port the conversation was aimed at. That is the port this
                    # address offered when it was the responder, and the port it
                    # reached out to when it was the initiator — one field for both
                    # questions, so the two can never disagree.
                    "received_port": row["port_b"],
                    "role": "initiator" if initiator else "responder",
                    "packets": packets,
                    "bytes": bytes_sent,
                    "packets_received": received,
                    "bytes_received": received_bytes,
                    "packets_total": int(row["packets_total"] or 0),
                    "bytes_total": int(row["bytes_total"] or 0),
                    "start_time": row["start_time"],
                    "end_time": row["end_time"],
                    "state": row["state"],
                }
            )
        return out

    return ctx.remember("conversations", build)


def _stream_ids(ctx: _Ctx) -> set[int]:
    """The conversation stream ids this entity's own flows travelled in.

    For an address that is the streams of its conversations; for a name or a URI
    it is the streams its HTTP transactions were carried in, which is the only
    attribution §6 allows for an object.
    """
    def build() -> set[int]:
        if ctx.kind == "ip":
            return {
                int(item["stream_id"])
                for item in _ip_conversations(ctx)
                if item["stream_id"] is not None
            }
        return _http_stream_ids(ctx)

    return ctx.remember("stream_ids", build)


def _attributed_files(ctx: _Ctx, stream_ids: set[int], frames: set[int]) -> list[dict]:
    """Objects tied to the entity by ``stream_id`` or by a recorded frame.

    §6: an object is tied to an address only when its ``stream_id`` or its
    recorded frames do. Nothing is attributed to a guess.
    """
    def build() -> list[dict]:
        if not ctx.index.objects:
            return []
        rows = db.query_all(
            """
            SELECT id, filename, size, sha256, sha1, md5, protocol, content_type,
                   stream_id, packet_numbers, src_ip, dst_ip
              FROM objects
             WHERE analysis_id = ?
             ORDER BY size DESC, filename ASC
             LIMIT ?
            """,
            (ctx.analysis_id, ROW_SCAN_CAP),
        )
        out: list[dict] = []
        for row in rows:
            stream_id = row["stream_id"]
            numbers = _json_list(row["packet_numbers"])
            numbers = [int(value) for value in numbers if isinstance(value, (int, float))]
            by_stream = stream_id is not None and int(stream_id) in stream_ids
            by_frame = any(number in frames for number in numbers)
            if not (by_stream or by_frame):
                continue
            out.append(
                {
                    "id": row["id"],
                    "filename": str(row["filename"] or "(unnamed)"),
                    "size": int(row["size"] or 0),
                    "sha256": row["sha256"],
                    "sha1": row["sha1"],
                    "md5": row["md5"],
                    "protocol": row["protocol"],
                    "content_type": row["content_type"],
                    "stream_id": stream_id,
                    "frame": numbers[0] if numbers else None,
                    "via": "stream" if by_stream else "frame",
                }
            )
        return out

    return build()


def _unattributed_objects(analysis_id: str, total: int) -> int:
    """Objects with neither a stream nor a recorded frame (§6)."""
    if not total:
        return 0
    row = db.query_one(
        """
        SELECT COUNT(*) AS n FROM objects
         WHERE analysis_id = ? AND stream_id IS NULL
           AND (packet_numbers IS NULL OR packet_numbers IN ('[]', ''))
        """,
        (analysis_id,),
    )
    return _as_int(row["n"]) if row else 0


def _http_rows(ctx: _Ctx, *, role: str = "any") -> list[dict]:
    """HTTP transactions for this entity, per kind."""
    aid, value = ctx.analysis_id, ctx.entity
    if ctx.kind == "domain":
        where, params = "host = ? COLLATE NOCASE", (aid, value)
    elif ctx.kind == "url":
        where, params = "uri = ?", (aid, value)
    elif role == "client":
        where, params = "client_ip = ?", (aid, value)
    elif role == "server":
        where, params = "server_ip = ?", (aid, value)
    else:
        where, params = "(client_ip = ? OR server_ip = ?)", (aid, value, value)
    return db.query_all(
        f"""
        SELECT id, stream_id, time_epoch, client_ip, server_ip, method, host, uri,
               full_uri, status_code, status_text, user_agent, referer, content_type,
               request_len, response_len, response_body_size, flags
          FROM http_transactions
         WHERE analysis_id = ? AND {where}
         ORDER BY time_epoch IS NULL, time_epoch ASC, id ASC
         LIMIT ?
        """,
        (*params, ROW_SCAN_CAP),
    )


def _http_stream_ids(ctx: _Ctx) -> set[int]:
    def build() -> set[int]:
        if not ctx.index.http:
            return set()
        return {
            int(row["stream_id"])
            for row in _http_rows(ctx)
            if row["stream_id"] is not None
        }

    return ctx.remember("http_streams", build)


# --------------------------------------------------------------------------
# links
# --------------------------------------------------------------------------


def _entity_links(ctx: _Ctx, limit: int = 5) -> list[dict]:
    if ctx.kind == "ip":
        return [
            _link(_to("/packets", ip=ctx.entity), f"frames carrying {ctx.entity}"),
            _link(_to("/hosts", ip=ctx.entity), "host inventory"),
            _link(_to("/conversations", ip=ctx.entity, tab="info"), "conversations"),
        ][:limit]
    if ctx.kind == "domain":
        return [
            _link(_to("/dns", domain=ctx.entity), "DNS queries for this name"),
            _link(_to("/tls", sni=ctx.entity), "TLS handshakes with this SNI"),
            _link(_to("/http", host=ctx.entity), "HTTP requests to this host"),
        ][:limit]
    return [
        _link(_to("/http", uri=ctx.entity), "HTTP requests for this URI"),
        _link(_to("/packets", search=ctx.entity), "frames containing this URI"),
    ][:limit]


# ==========================================================================
# 4.1 — the `ip` questions
# ==========================================================================


def _q_volume_by_direction(ctx: _Ctx) -> _Result:
    if not ctx.index.hosts and not ctx.index.packets:
        return _not_applicable(
            f"{NO_HOSTS} and {NO_PACKETS}, so no byte total can be measured for {ctx.entity}"
        )

    host = db.query_one(
        """
        SELECT mac, dns_names, first_seen, last_seen, packets_sent, packets_received,
               bytes_sent, bytes_received
          FROM hosts WHERE analysis_id = ? AND ip = ?
        """,
        (ctx.analysis_id, ctx.entity),
    )
    if host is not None:
        sent = int(host["bytes_sent"] or 0)
        received = int(host["bytes_received"] or 0)
        packets_sent = int(host["packets_sent"] or 0)
        packets_received = int(host["packets_received"] or 0)
    else:
        row = db.query_one(
            """
            SELECT
              SUM(CASE WHEN src_ip = ? THEN 1 ELSE 0 END) AS packets_sent,
              SUM(CASE WHEN dst_ip = ? THEN 1 ELSE 0 END) AS packets_received,
              SUM(CASE WHEN src_ip = ? THEN COALESCE(frame_len, 0) ELSE 0 END) AS bytes_sent,
              SUM(CASE WHEN dst_ip = ? THEN COALESCE(frame_len, 0) ELSE 0 END) AS bytes_received
              FROM packets WHERE analysis_id = ? AND (src_ip = ? OR dst_ip = ?)
            """,
            (ctx.entity, ctx.entity, ctx.entity, ctx.entity, ctx.analysis_id, ctx.entity, ctx.entity),
        )
        if row is None or (int(row["packets_sent"] or 0) + int(row["packets_received"] or 0)) == 0:
            return _not_applicable(
                f"neither the host index nor the packet index holds a row for {ctx.entity} "
                f"in this capture"
            )
        sent = int(row["bytes_sent"] or 0)
        received = int(row["bytes_received"] or 0)
        packets_sent = int(row["packets_sent"] or 0)
        packets_received = int(row["packets_received"] or 0)

    total_bytes = sent + received
    total_packets = packets_sent + packets_received

    if total_packets == 0:
        return _empty(
            f"the index records {ctx.entity} but no frame in this capture carries it "
            f"(0 packets, 0 bytes)",
            links=_entity_links(ctx),
            label="byte(s) sent and received",
        )
    if total_bytes == 0:
        # A headline of 0 on an "ok" question would read as "nothing matched", so a
        # capture whose frames carry no recorded length reports empty instead.
        return _empty(
            f"{total_packets} frame(s) carry this address and the index recorded a length "
            f"for none of them, so no byte total can be measured",
            links=_entity_links(ctx),
            label="byte(s) sent and received",
        )

    bars, _shown, _total = _ranked_bars(
        "Bytes by direction",
        [
            {"label": "sent", "value": sent, "to": _to("/packets", src_ip=ctx.entity)},
            {"label": "received", "value": received, "to": _to("/packets", dst_ip=ctx.entity)},
        ],
        "bytes",
        "direction(s)",
    )
    share_sent = (sent / total_bytes * 100.0) if total_bytes else 0.0
    table, _s, _t = _capped_table(
        "Direction split",
        ["direction", "packets", "bytes", "share"],
        [
            {
                "cells": [
                    _cell("sent", to=_to("/packets", src_ip=ctx.entity)),
                    _cell(packets_sent),
                    _cell(f"{sent:,}"),
                    _cell(f"{share_sent:.1f}%"),
                ]
            },
            {
                "cells": [
                    _cell("received", to=_to("/packets", dst_ip=ctx.entity)),
                    _cell(packets_received),
                    _cell(f"{received:,}"),
                    _cell(f"{100.0 - share_sent:.1f}%"),
                ]
            },
        ],
        "direction(s)",
    )

    return _Result(
        "ok",
        None,
        total_bytes,
        f"byte(s) sent and received across {total_packets:,} frame(s)",
        TONE_INFO,
        [bars, table],
        _entity_links(ctx),
    )


def _q_activity_over_time(ctx: _Ctx) -> _Result:
    if not ctx.index.packets:
        return _not_applicable(NO_PACKETS)

    rows = db.query_all(
        """
        SELECT time_epoch FROM packets
         WHERE analysis_id = ? AND (src_ip = ? OR dst_ip = ?)
         ORDER BY time_epoch IS NULL, time_epoch ASC
         LIMIT ?
        """,
        (ctx.analysis_id, ctx.entity, ctx.entity, ROW_SCAN_CAP),
    )
    if not rows:
        return _not_applicable(_absent(ctx, "packet"))

    timeline, _shown, _total = _capped_timeline(
        f"Frames carrying this address per {ctx.window} s",
        ((row["time_epoch"], 1) for row in rows),
        "frames",
        ctx.window,
    )

    stamps = sorted(float(row["time_epoch"]) for row in rows if row["time_epoch"] is not None)
    counts: dict[str, int] = {}
    for earlier, later in zip(stamps, stamps[1:]):
        label = _bucket_label(later - earlier, _GAP_EDGES)
        counts[label] = counts.get(label, 0) + 1
    histogram = _histogram(
        "Gap between consecutive frames",
        [{"label": label, "value": counts[label]} for _edge, label in _GAP_EDGES if counts.get(label)],
        "gap(s)",
        f"{len(stamps)} timestamped frame(s); the distribution says steady or bursty",
    )

    if not timeline["points"]:
        return _empty(
            f"the {len(rows)} frame(s) carrying this address in this capture recorded no "
            f"usable timestamp",
            visuals=[timeline, histogram],
            links=_entity_links(ctx),
            label="frame(s) with a timeline",
        )

    return _Result(
        "ok",
        None,
        len(rows),
        "frame(s) carrying this address",
        TONE_INFO,
        [timeline, histogram],
        _entity_links(ctx),
        truncated=bool(timeline["note"]),
    )


def _q_connections(ctx: _Ctx) -> _Result:
    if not ctx.index.conversations:
        return _not_applicable(NO_CONVERSATIONS)
    if ctx.kind != "ip":
        return _not_applicable(
            "the conversation index is keyed by address, so it cannot answer this "
            f"for the {_noun(ctx.kind)} {ctx.entity!r}"
        )

    conversations = _ip_conversations(ctx)
    if not conversations:
        return _not_applicable(_absent(ctx, "conversation"))

    peer_counts: dict[str, int] = {}
    port_counts: dict[Any, int] = {}
    pair_counts: dict[tuple[str, Any], int] = {}
    for item in conversations:
        peer_counts[item["peer"]] = peer_counts.get(item["peer"], 0) + 1
        port_counts[item["received_port"]] = port_counts.get(item["received_port"], 0) + 1
        key = (item["peer"], item["received_port"])
        pair_counts[key] = pair_counts.get(key, 0) + 1

    top_peers = sorted(peer_counts.items(), key=lambda kv: (-kv[1], str(kv[0])))[:HEATMAP_CAP]
    top_ports = sorted(
        port_counts.items(), key=lambda kv: (-kv[1], -1 if kv[0] is None else int(kv[0]))
    )[:HEATMAP_CAP]
    heat_rows = [
        {
            "label": peer,
            "cells": [pair_counts.get((peer, port), 0) for port, _count in top_ports],
        }
        for peer, _count in top_peers
    ]
    heat_note_parts = []
    heat_truncated = False
    if len(peer_counts) > len(top_peers):
        heat_note_parts.append(f"showing {len(top_peers)} of {len(peer_counts)} peer(s)")
        heat_truncated = True
    if len(port_counts) > len(top_ports):
        heat_note_parts.append(f"showing {len(top_ports)} of {len(port_counts)} port(s)")
        heat_truncated = True
    heat_note_parts.append("cells count conversations whose receiving port was that column")
    heatmap = _heatmap(
        "Peers against ports",
        [str(port) for port, _count in top_ports],
        heat_rows,
        "conversations",
        "; ".join(heat_note_parts),
    )

    table_rows = []
    for item in conversations:
        stream = (
            _to("/conversations", stream=f"{item['transport']}:{item['stream_id']}")
            if item["stream_id"] is not None
            else None
        )
        table_rows.append(
            {
                "cells": [
                    _cell(item["peer"], tone=TONE_WATCH, to=stream),
                    _cell(item["received_port"] if item["received_port"] is not None else ""),
                    _cell(item["transport"]),
                    _cell(item["role"]),
                    _cell(f"{item['packets']:,} / {item['packets_received']:,}"),
                    _cell(f"{item['bytes']:,} / {item['bytes_received']:,}"),
                    _cell(item["state"] or ""),
                ]
            }
        )
    table, _shown, _total = _capped_table(
        "Conversations",
        ["peer", "receiving port", "transport", "role here", "packets out/in",
         "bytes out/in", "state"],
        table_rows,
        "conversation(s)",
    )

    links = [_link(_to("/conversations", ip=ctx.entity, tab="info"), "all conversations")]
    for peer, _count in top_peers[:4]:
        links.append(_link(_to("/hosts", ip=peer), peer))

    return _Result(
        "ok",
        None,
        len(conversations),
        "conversation(s) in this capture",
        TONE_INFO,
        [heatmap, table],
        links,
        truncated=heat_truncated or bool(table["note"]),
    )


def _q_peer_fanout(ctx: _Ctx) -> _Result:
    if not ctx.index.conversations:
        return _not_applicable(NO_CONVERSATIONS)
    if ctx.kind != "ip":
        return _not_applicable(
            "conversation peers are addresses, so this question is only answerable for "
            f"an address, not for the {_noun(ctx.kind)} {ctx.entity!r}"
        )

    conversations = _ip_conversations(ctx)
    if not conversations:
        return _not_applicable(_absent(ctx, "conversation"))

    per_peer: dict[str, dict] = {}
    for item in conversations:
        entry = per_peer.setdefault(
            item["peer"],
            {"peer": item["peer"], "conversations": 0, "packets": 0, "bytes": 0},
        )
        entry["conversations"] += 1
        entry["packets"] += item["packets"] + item["packets_received"]
        entry["bytes"] += item["bytes"] + item["bytes_received"]
    peers = sorted(
        per_peer.values(), key=lambda item: (-item["bytes"], -item["packets"], item["peer"])
    )

    bars, _shown, bars_total = _ranked_bars(
        "Bytes exchanged per peer",
        [
            {"label": item["peer"], "value": item["bytes"], "to": _to("/hosts", ip=item["peer"])}
            for item in peers
        ],
        "bytes",
        "peer(s)",
    )
    points = [
        {
            "x": item["packets"],
            "y": item["bytes"],
            "label": item["peer"],
            "to": _to("/hosts", ip=item["peer"]),
        }
        for item in peers
    ]
    scatter, _s, _t = _capped_scatter(
        "Packets against bytes, one point per peer",
        points,
        "packets",
        "bytes",
        "peer(s)",
    )

    links = [_link(_to("/conversations", ip=ctx.entity, tab="info"), "all conversations")]
    for item in peers[:4]:
        links.append(_link(_to("/hosts", ip=item["peer"]), item["peer"]))

    return _Result(
        "ok",
        None,
        len(peers),
        "distinct peer(s) in this capture",
        TONE_INFO,
        [bars, scatter],
        links,
        truncated=bool(bars["note"]) or bool(scatter["note"]),
    )


def _port_question(ctx: _Ctx, *, role: str) -> _Result:
    """``ports_offered`` (as responder) and ``ports_contacted`` (as initiator).

    ``conversations.endpoint_a`` is the side that initiated — the sender of the
    SYN for TCP — so the ports this address accepted traffic on are ``port_b`` of
    the conversations where it is ``ip_b``, and the ports it reached out to are
    ``port_b`` of the conversations where it is ``ip_a``.
    """
    if not ctx.index.conversations:
        return _not_applicable(NO_CONVERSATIONS)
    if ctx.kind != "ip":
        return _not_applicable(
            "a listening or contacted port belongs to an address, so this question is "
            f"only answerable for an address, not for the {_noun(ctx.kind)} {ctx.entity!r}"
        )

    conversations = _ip_conversations(ctx)
    if not conversations:
        return _not_applicable(_absent(ctx, "conversation"))

    wanted = "responder" if role == "responder" else "initiator"
    selected = [item for item in conversations if item["role"] == wanted]
    if not selected:
        other = "initiator" if role == "responder" else "responder"
        return _empty(
            f"this address is the {other} in all {len(conversations)} conversation(s) and "
            f"the {wanted} in none of them, so it was never seen "
            + ("accepting traffic on a port" if role == "responder" else "reaching out to a port"),
            links=_entity_links(ctx),
            label="port(s)",
        )

    counts: dict[Any, int] = {}
    for item in selected:
        # `received_port` is `port_b` of the conversation — the port the flow was
        # aimed at. When this address is the responder that is the port it was
        # contacted on (the one it offered), and when it is the initiator it is the
        # port it reached out to. Using one field for both keeps the two questions
        # from ever contradicting each other.
        key = item["received_port"]
        counts[key] = counts.get(key, 0) + 1
    ranked = sorted(counts.items(), key=lambda kv: (-kv[1], -1 if kv[0] is None else int(kv[0])))

    items = [
        {
            "label": _port_label(port),
            "value": count,
            "to": _to("/packets", ip=ctx.entity, port=port) if port is not None else None,
        }
        for port, count in ranked
    ]
    unit = "conversations accepted" if role == "responder" else "conversations initiated"
    bars, _shown, _total = _ranked_bars(
        "Ports this address accepted traffic on" if role == "responder" else "Ports this address reached out to",
        items,
        unit,
        "port(s)",
    )

    links = [_link(_to("/conversations", ip=ctx.entity, tab="info"), "all conversations")]
    for port, _count in ranked[:4]:
        if port is not None:
            links.append(_link(_to("/packets", ip=ctx.entity, port=port), f"port {port}"))

    label = (
        "port(s) accepted traffic"
        if role == "responder"
        else "port(s) reached out to"
    )
    return _Result("ok", None, len(ranked), label, TONE_INFO, [bars], links, bool(bars["note"]))


def _q_ports_offered(ctx: _Ctx) -> _Result:
    return _port_question(ctx, role="responder")


def _q_ports_contacted(ctx: _Ctx) -> _Result:
    return _port_question(ctx, role="initiator")


def _q_protocol_mix(ctx: _Ctx) -> _Result:
    if not ctx.index.packets:
        return _not_applicable(NO_PACKETS)
    if ctx.kind != "ip":
        return _not_applicable(
            f"protocol dissection belongs to frames, and this question is asked of an "
            f"address; see the profile of the peer address for the {_noun(ctx.kind)} {ctx.entity!r}"
        )

    rows = db.query_all(
        """
        SELECT COALESCE(protocol, '(no protocol dissected)') AS protocol,
               COUNT(*) AS frames, SUM(COALESCE(frame_len, 0)) AS bytes
          FROM packets
         WHERE analysis_id = ? AND (src_ip = ? OR dst_ip = ?)
         GROUP BY protocol
         ORDER BY frames DESC, protocol ASC
        """,
        (ctx.analysis_id, ctx.entity, ctx.entity),
    )
    if not rows:
        return _not_applicable(_absent(ctx, "packet"))

    bars, _shown, total = _ranked_bars(
        "Frames per dissected protocol",
        [{"label": str(row["protocol"]), "value": int(row["frames"])} for row in rows],
        "frames",
        "protocol(s)",
    )
    table, _s, _t = _capped_table(
        "Protocol, frames and bytes",
        ["protocol", "frames", "bytes"],
        [
            {
                "cells": [
                    _cell(row["protocol"]),
                    _cell(f"{int(row['frames']):,}"),
                    _cell(f"{int(row['bytes'] or 0):,}"),
                ]
            }
            for row in rows[:PROFILE_CAP]
        ],
        "protocol(s)",
        total=len(rows),
    )
    return _Result(
        "ok",
        None,
        total,
        "distinct dissected protocol(s)",
        TONE_INFO,
        [bars, table],
        _entity_links(ctx),
        truncated=bool(bars["note"]) or bool(table["note"]),
    )


def _q_domains_resolved(ctx: _Ctx) -> _Result:
    if not ctx.index.dns:
        return _not_applicable(NO_DNS)
    if ctx.kind != "ip":
        return _not_applicable(
            f"DNS queries are attributed to a client address; see the profile of the "
            f"resolver or client address for the {_noun(ctx.kind)} {ctx.entity!r}"
        )

    rows = db.query_all(
        """
        SELECT query_name, COUNT(*) AS queries, MAX(rcode_name) AS rcode,
               MAX(answer_ips) AS answer_ips, MIN(time_epoch) AS first_seen
          FROM dns_queries
         WHERE analysis_id = ? AND client_ip = ? AND query_name IS NOT NULL
         GROUP BY query_name
         ORDER BY queries DESC, query_name ASC
         LIMIT ?
        """,
        (ctx.analysis_id, ctx.entity, ROW_SCAN_CAP),
    )
    if not rows:
        present = db.query_one(
            "SELECT COUNT(*) AS n FROM dns_queries WHERE analysis_id = ? AND server_ip = ?",
            (ctx.analysis_id, ctx.entity),
        )
        if _as_int(present["n"] if present else 0) > 0:
            return _empty(
                f"this address appears in this capture's DNS rows as the resolver only — "
                f"{_as_int(present['n'])} query(s) were addressed to it and it asked "
                f"for no name itself",
                links=_entity_links(ctx),
                label="name(s) asked for",
            )
        return _not_applicable(_absent(ctx, "DNS"))

    table_rows = [
        {
            "cells": [
                _cell(
                    row["query_name"],
                    tone=TONE_WATCH,
                    to=_to("/dns", domain=row["query_name"]),
                ),
                _cell(int(row["queries"])),
                _cell(row["rcode"] or NO_RESPONSE),
                _cell(row["answer_ips"] or ""),
            ]
        }
        for row in rows[:PROFILE_CAP]
    ]
    table, _shown, total = _capped_table(
        "Names asked for",
        ["name", "queries", "answer", "addresses"],
        table_rows,
        "name(s)",
        total=len(rows),
    )
    links = [_link(_to("/dns", domain=row["query_name"]), str(row["query_name"])) for row in rows[:5]]
    return _Result(
        "ok",
        None,
        total,
        "distinct name(s) asked a resolver for",
        TONE_INFO,
        [table],
        links,
        truncated=bool(table["note"]),
    )


def _q_domains_contacted(ctx: _Ctx) -> _Result:
    if not ctx.index.tls:
        return _not_applicable(NO_TLS)
    if ctx.kind != "ip":
        return _not_applicable(
            f"a TLS server name belongs to the session's endpoints, so this question is "
            f"asked of an address; see the {_noun(ctx.kind)} profile of {ctx.entity!r}"
        )

    rows = db.query_all(
        """
        SELECT sni, COUNT(*) AS sessions, MAX(version) AS version, MAX(ja3) AS ja3
          FROM tls_sessions
         WHERE analysis_id = ? AND sni IS NOT NULL
           AND (client_ip = ? OR server_ip = ?)
         GROUP BY sni
         ORDER BY sessions DESC, sni ASC
         LIMIT ?
        """,
        (ctx.analysis_id, ctx.entity, ctx.entity, ROW_SCAN_CAP),
    )
    if not rows:
        present = db.query_one(
            "SELECT COUNT(*) AS n FROM tls_sessions WHERE analysis_id = ? AND (client_ip = ? OR server_ip = ?)",
            (ctx.analysis_id, ctx.entity, ctx.entity),
        )
        count = _as_int(present["n"] if present else 0)
        if count == 0:
            return _not_applicable(_absent(ctx, "TLS"))
        return _empty(
            f"this address is an endpoint of {count} TLS session(s) in this capture and none "
            f"of them recorded a server name (SNI), so no name can be reported",
            links=_entity_links(ctx),
            label="name(s) contacted over TLS",
        )

    table, _shown, total = _capped_table(
        "Server names presented to this address",
        ["name", "sessions", "version", "ja3"],
        [
            {
                "cells": [
                    _cell(row["sni"], tone=TONE_WATCH, to=_to("/tls", sni=row["sni"])),
                    _cell(int(row["sessions"])),
                    _cell(row["version"] or ""),
                    _cell(row["ja3"] or ""),
                ]
            }
            for row in rows[:PROFILE_CAP]
        ],
        "name(s)",
        total=len(rows),
    )
    links = [_link(_to("/tls", sni=row["sni"]), str(row["sni"])) for row in rows[:5]]
    return _Result(
        "ok",
        None,
        total,
        "distinct name(s) seen as SNI",
        TONE_INFO,
        [table],
        links,
        truncated=bool(table["note"]),
    )


def _q_dns_health(ctx: _Ctx) -> _Result:
    if not ctx.index.dns:
        return _not_applicable(NO_DNS)
    if ctx.kind != "ip":
        return _not_applicable(
            f"DNS health is measured for the client that asked, so this question is asked "
            f"of an address; see the {_noun(ctx.kind)} profile of {ctx.entity!r}"
        )

    queries = db.query_all(
        """
        SELECT COUNT(*) AS queries,
               SUM(CASE WHEN response_packet IS NULL THEN 1 ELSE 0 END) AS unanswered,
               SUM(CASE WHEN rcode_name = 'NXDOMAIN' THEN 1 ELSE 0 END) AS nxdomain,
               COUNT(DISTINCT server_ip) AS resolvers
          FROM dns_queries
         WHERE analysis_id = ? AND client_ip = ?
        """,
        (ctx.analysis_id, ctx.entity),
    )
    total_queries = _as_int(queries[0]["queries"] if queries else 0)
    if total_queries == 0:
        present = db.query_one(
            "SELECT COUNT(*) AS n FROM dns_queries WHERE analysis_id = ? AND server_ip = ?",
            (ctx.analysis_id, ctx.entity),
        )
        count = _as_int(present["n"] if present else 0)
        if count == 0:
            return _not_applicable(_absent(ctx, "DNS"))
        return _empty(
            f"this address answered {count} DNS query(s) in this capture and asked none, "
            f"so it has no query outcome to report",
            links=_entity_links(ctx),
            label="unanswered query(s)",
        )

    unanswered = _as_int(queries[0]["unanswered"])

    resolver_rows = db.query_all(
        """
        SELECT COALESCE(server_ip, '(no resolver recorded)') AS resolver,
               COUNT(*) AS queries,
               SUM(CASE WHEN response_packet IS NULL THEN 1 ELSE 0 END) AS unanswered
          FROM dns_queries
         WHERE analysis_id = ? AND client_ip = ?
         GROUP BY resolver
         ORDER BY queries DESC, resolver ASC
        """,
        (ctx.analysis_id, ctx.entity),
    )
    bars, _shown, _total = _ranked_bars(
        "Queries per resolver",
        [
            {
                "label": str(row["resolver"]),
                "value": int(row["queries"]),
                # `resolver` is a real address for every row TShark dissected; the
                # placeholder branch has no page to link to, so it gets no link.
                "to": _to("/hosts", ip=row["resolver"])
                if address_scope(row["resolver"])
                else None,
            }
            for row in resolver_rows
        ],
        "queries",
        "resolver(s)",
    )

    rcode_rows = db.query_all(
        """
        SELECT COALESCE(rcode_name, ?) AS rcode, COUNT(*) AS n
          FROM dns_queries
         WHERE analysis_id = ? AND client_ip = ?
         GROUP BY rcode
         ORDER BY n DESC, rcode ASC
        """,
        (NO_RESPONSE, ctx.analysis_id, ctx.entity),
    )
    table, _s, _t = _capped_table(
        "How the resolver answered",
        ["rcode", "queries"],
        [
            {"cells": [_cell(row["rcode"]), _cell(int(row["n"]))]}
            for row in rcode_rows[:PROFILE_CAP]
        ],
        "rcode(s)",
        total=len(rcode_rows),
    )

    nxdomain = _as_int(queries[0]["nxdomain"])
    links = [_link(_to("/dns", client_ip=ctx.entity), "DNS queries from this address")]
    if nxdomain:
        links.append(_link(_to("/dns", client_ip=ctx.entity, nxdomain="true"), "NXDOMAIN answers"))
    if unanswered:
        links.append(
            _link(_to("/dns", client_ip=ctx.entity, unanswered="true"), "unanswered queries")
        )

    visuals = [bars, table]
    if unanswered == 0:
        return _empty(
            f"all {total_queries} query(s) from this address were answered in this "
            f"capture (0 left unanswered, {nxdomain} NXDOMAIN)",
            visuals=visuals,
            links=links,
            label="unanswered query(s)",
        )

    return _Result(
        "ok",
        None,
        unanswered,
        f"query(s) with no response here, of {total_queries} asked",
        TONE_WATCH if nxdomain else TONE_INFO,
        visuals,
        links,
        truncated=bool(table["note"]),
    )


def _q_http_activity(ctx: _Ctx) -> _Result:
    if not ctx.index.http:
        return _not_applicable(NO_HTTP)

    rows = _http_rows(ctx)
    if not rows:
        return _not_applicable(_absent(ctx, "HTTP"))

    if ctx.kind == "ip":
        counts: dict[str, int] = {}
        for row in rows:
            name = str(row["host"] or row["server_ip"] or "")
            if name:
                counts[name] = counts.get(name, 0) + 1
        bar_title = "HTTP hosts used"
        bar_noun = "host(s)"
        bar_unit = "requests"
    else:
        # A name or a URI is one host, so the ranked axis that carries
        # information here is the path rather than the host.
        counts = {}
        for row in rows:
            path = str(row["uri"] or "(no URI recorded)")
            counts[path] = counts.get(path, 0) + 1
        bar_title = "Paths requested"
        bar_noun = "path(s)"
        bar_unit = "requests"

    bars, _shown, _total = _ranked_bars(
        bar_title,
        [
            {
                "label": name,
                "value": count,
                "to": _to("/http", host=name) if ctx.kind == "ip" else _to("/http", uri=name),
            }
            for name, count in sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))
        ],
        bar_unit,
        bar_noun,
    )

    table, _s, total = _capped_table(
        "HTTP requests",
        ["request", "method", "status", "bytes back", "frame"],
        [
            {
                "cells": [
                    _cell(
                        f"{row['host'] or row['server_ip'] or ''}{row['uri'] or ''}",
                        tone=TONE_WATCH,
                        to=_to("/http", tx=row["id"]),
                    ),
                    _cell(row["method"] or ""),
                    _cell(row["status_code"] if row["status_code"] is not None else NO_RESPONSE),
                    _cell(int(row["response_body_size"] or row["response_len"] or 0)),
                    _cell(
                        row["id"],
                        to=_to("/packets", stream_id=row["stream_id"]) if row["stream_id"] is not None else None,
                    ),
                ]
            }
            for row in rows[:PROFILE_CAP]
        ],
        "request(s)",
        total=len(rows),
    )

    links = [_link(_to("/http", search=ctx.entity), "HTTP transactions naming this entity")]
    for name in list({str(row["host"]) for row in rows if row["host"]})[:4]:
        links.append(_link(_to("/http", host=name), name))

    return _Result(
        "ok",
        None,
        len(rows),
        "HTTP request(s) involving this entity",
        TONE_INFO,
        [bars, table],
        links,
        truncated=bool(table["note"]) or bool(bars["note"]),
    )


def _q_clear_text_credentials(ctx: _Ctx) -> _Result:
    if not ctx.index.http:
        return _not_applicable(NO_HTTP)

    rows = _http_rows(ctx)
    if not rows:
        return _not_applicable(_absent(ctx, "HTTP"))

    flagged = []
    for row in rows:
        keywords = [
            token.split(":", 1)[1]
            for token in (str(value) for value in _json_list(row["flags"]))
            if token.split(":", 1)[0] == "cleartext_credentials" and ":" in token
        ]
        if keywords:
            flagged.append((row, keywords[0]))

    table, _shown, total = _capped_table(
        "Requests carrying a credential keyword in clear text",
        ["request", "method", "credential hint", "frame"],
        [
            {
                "cells": [
                    _cell(
                        f"{row['host'] or row['server_ip'] or ''}{row['uri'] or ''}",
                        tone="warn",
                        to=_to("/http", tx=row["id"]),
                    ),
                    _cell(row["method"] or ""),
                    _cell(keyword),
                    _cell(row["id"], to=_to("/packets", stream_id=row["stream_id"]))
                    if row["stream_id"] is not None
                    else _cell(row["id"]),
                ]
            }
            for row, keyword in flagged[:PROFILE_CAP]
        ],
        "request(s)",
        total=len(flagged),
    )

    links = [_link(_to("/http", interesting="true"), "flagged HTTP transactions in this capture")]
    for row, _keyword in flagged[:4]:
        if row["host"]:
            links.append(_link(_to("/http", host=str(row["host"])), str(row["host"])))

    if not flagged:
        return _empty(
            f"none of the {len(rows)} HTTP request(s) involving this entity carried a "
            f"credential keyword in its URI, headers or request body",
            visuals=[table],
            links=links,
            label="request(s) with a clear-text credential",
        )

    return _Result(
        "ok",
        None,
        len(flagged),
        "request(s) with a clear-text credential",
        TONE_WATCH,
        [table],
        links,
        truncated=bool(table["note"]),
    )


def _q_files(ctx: _Ctx) -> _Result:
    if not ctx.index.objects:
        return _not_applicable(NO_OBJECTS)

    stream_ids = set(_stream_ids(ctx))
    if ctx.kind == "ip":
        stream_ids |= _http_stream_ids(ctx)
    frames, _frames_truncated = _frames_for(ctx)
    frame_set = set(frames)

    if not stream_ids and not frame_set:
        return _not_applicable(
            f"this capture holds no conversation or frame that this {_noun(ctx.kind)} can be "
            f"tied to, so no extracted object can be attributed to {ctx.entity!r}"
        )

    files = _attributed_files(ctx, stream_ids, frame_set)
    if not files:
        return _empty(
            f"none of the {ctx.index.objects} extracted object(s) in this capture record a "
            f"stream or a frame belonging to this {_noun(ctx.kind)}",
            links=_entity_links(ctx),
            label="file(s) transferred",
        )

    table, _shown, total = _capped_table(
        "Files transferred",
        ["file", "size", "sha256", "via", "frame"],
        [
            {
                "cells": [
                    _cell(item["filename"], tone=TONE_WATCH, to=_to("/objects", search=item["filename"])),
                    _cell(f"{item['size']:,}"),
                    _cell(item["sha256"] or "(not hashed)"),
                    _cell(item["via"]),
                    _cell(
                        item["frame"],
                        to=_to("/packets", sel=item["frame"]) if item["frame"] is not None else None,
                    ),
                ]
            }
            for item in files[:PROFILE_CAP]
        ],
        "file(s)",
        total=len(files),
    )

    links = [_link(_to("/objects", search=item["filename"]), item["filename"]) for item in files[:5]]
    return _Result(
        "ok",
        None,
        total,
        "file(s) attributed to this entity",
        TONE_INFO,
        [table],
        links,
        truncated=bool(table["note"]),
    )


def _q_tls_fingerprints(ctx: _Ctx) -> _Result:
    if not ctx.index.tls:
        return _not_applicable(NO_TLS)

    row = db.query_one(
        "SELECT COUNT(*) AS n, SUM(ja3 IS NOT NULL) AS with_ja3 FROM tls_sessions WHERE analysis_id = ?",
        (ctx.analysis_id,),
    )
    if not _as_int(row["with_ja3"] if row else 0):
        return _not_applicable(
            "no TLS session in this capture recorded a JA3 fingerprint, so no client "
            "fingerprint can be reported"
        )
    if ctx.kind != "ip":
        return _not_applicable(
            f"a JA3/JA4 fingerprint belongs to a TLS endpoint, so this question is asked of "
            f"an address; see the {_noun(ctx.kind)} profile of {ctx.entity!r}"
        )

    rows = db.query_all(
        """
        SELECT COALESCE(ja3, '(no ja3)') AS ja3, COALESCE(ja4, '') AS ja4,
               COALESCE(version, '') AS version, COUNT(*) AS sessions,
               MAX(sni) AS sni, MAX(handshake_status) AS status
          FROM tls_sessions
         WHERE analysis_id = ? AND (client_ip = ? OR server_ip = ?)
         GROUP BY ja3, ja4, version
         ORDER BY sessions DESC, ja3 ASC
         LIMIT ?
        """,
        (ctx.analysis_id, ctx.entity, ctx.entity, ROW_SCAN_CAP),
    )
    if not rows:
        return _not_applicable(_absent(ctx, "TLS"))

    table, _shown, total = _capped_table(
        "TLS fingerprints presented at this address",
        ["ja3", "ja4", "version", "sessions", "example sni", "handshake"],
        [
            {
                "cells": [
                    _cell(row["ja3"], to=_to("/tls", ja3=row["ja3"]) if row["ja3"] != "(no ja3)" else None),
                    _cell(row["ja4"]),
                    _cell(row["version"]),
                    _cell(int(row["sessions"])),
                    _cell(row["sni"] or ""),
                    _cell(row["status"] or ""),
                ]
            }
            for row in rows[:PROFILE_CAP]
        ],
        "fingerprint(s)",
        total=len(rows),
    )
    fingerprints = {str(row["ja3"]) for row in rows if row["ja3"] != "(no ja3)"}
    links = [_link(_to("/tls", ja3=value), value) for value in sorted(fingerprints)][:5]
    return _Result(
        "ok",
        None,
        total,
        "distinct fingerprint(s) in this capture",
        TONE_INFO,
        [table],
        links,
        truncated=bool(table["note"]),
    )


def _q_fingerprint_peers(ctx: _Ctx) -> _Result:
    if not ctx.index.tls:
        return _not_applicable(NO_TLS)

    row = db.query_one(
        "SELECT SUM(ja3 IS NOT NULL) AS with_ja3 FROM tls_sessions WHERE analysis_id = ?",
        (ctx.analysis_id,),
    )
    if not _as_int(row["with_ja3"] if row else 0):
        return _not_applicable(
            "no TLS session in this capture recorded a JA3 fingerprint, so there is nothing "
            "to compare against"
        )
    if ctx.kind != "ip":
        return _not_applicable(
            f"fingerprint peers are addresses, so this question is asked of an address; see "
            f"the {_noun(ctx.kind)} profile of {ctx.entity!r}"
        )

    own = db.query_all(
        """
        SELECT DISTINCT ja3 FROM tls_sessions
         WHERE analysis_id = ? AND ja3 IS NOT NULL AND (client_ip = ? OR server_ip = ?)
        """,
        (ctx.analysis_id, ctx.entity, ctx.entity),
    )
    mine = [str(item["ja3"]) for item in own]
    if not mine:
        present = db.query_one(
            "SELECT COUNT(*) AS n FROM tls_sessions WHERE analysis_id = ? AND (client_ip = ? OR server_ip = ?)",
            (ctx.analysis_id, ctx.entity, ctx.entity),
        )
        if _as_int(present["n"] if present else 0) == 0:
            return _not_applicable(_absent(ctx, "TLS"))
        return _empty(
            "none of this address's TLS sessions recorded a JA3 fingerprint, so they cannot "
            "be compared with anything else in the capture",
            links=_entity_links(ctx),
            label="peer address(es) sharing a fingerprint",
        )

    placeholders = ", ".join("?" for _ in mine)
    rows = db.query_all(
        f"""
        SELECT t.ja3 AS ja3,
               CASE WHEN t.client_ip = ? THEN t.server_ip ELSE t.client_ip END AS peer,
               COUNT(*) AS sessions
          FROM tls_sessions t
         WHERE t.analysis_id = ? AND t.ja3 IN ({placeholders})
           AND (t.client_ip IS NOT NULL OR t.server_ip IS NOT NULL)
         GROUP BY t.ja3, peer
        """,
        (ctx.entity, ctx.analysis_id, *mine),
    )
    others: dict[tuple[str, str], int] = {}
    for item in rows:
        peer = item["peer"]
        if peer is None or str(peer) == ctx.entity:
            continue
        key = (str(item["ja3"]), str(peer))
        others[key] = others.get(key, 0) + int(item["sessions"])

    ranked = sorted(others.items(), key=lambda kv: (-kv[1], kv[0][0], kv[0][1]))

    table, _shown, total = _capped_table(
        "Other addresses presenting the same fingerprint",
        ["fingerprint", "address", "sessions"],
        [
            {
                "cells": [
                    _cell(ja3, to=_to("/tls", ja3=ja3)),
                    _cell(peer, to=_to("/hosts", ip=peer)),
                    _cell(sessions),
                ]
            }
            for (ja3, peer), sessions in ranked[:PROFILE_CAP]
        ],
        "peer(s)",
        total=len(ranked),
    )

    links = [_link(_to("/hosts", ip=peer), peer) for (_ja3, peer), _n in ranked[:5]]
    if not ranked:
        return _empty(
            f"the {len(mine)} fingerprint(s) this address presented appear for no other "
            f"address in this capture",
            visuals=[table],
            links=links,
            label="peer address(es) sharing a fingerprint",
        )

    return _Result(
        "ok",
        None,
        total,
        "other address(es) sharing a fingerprint",
        TONE_INFO,
        [table],
        links,
        truncated=bool(table["note"]),
    )


def _q_findings(ctx: _Ctx) -> _Result:
    if not ctx.index.findings:
        return _not_applicable(NO_FINDINGS)

    rows = db.query_all(
        """
        SELECT id, rule_id, severity, title, reason, entities, packet_numbers
          FROM findings
         WHERE analysis_id = ?
         ORDER BY rule_id ASC, id ASC
         LIMIT ?
        """,
        (ctx.analysis_id, ROW_SCAN_CAP),
    )

    frames, frames_truncated = _frames_for(ctx)
    frame_set = set(frames)

    matched: list[dict] = []
    for row in rows:
        entities = _json_dict(row["entities"])
        names: list[str] = []
        for key in ("ips", "hostnames", "uris"):
            names.extend(str(value) for value in (entities.get(key) or []))
        if ctx.kind == "domain":
            hit_name = any(name.lower() == ctx.entity.lower() for name in names)
        else:
            hit_name = any(name == ctx.entity for name in names)

        numbers = [int(value) for value in _json_list(row["packet_numbers"])
                   if isinstance(value, (int, float))]
        hit_frame = next((number for number in numbers if number in frame_set), None)
        if not hit_name and hit_frame is None:
            continue
        matched.append(
            {
                "id": row["id"],
                "rule_id": row["rule_id"],
                "severity": str(row["severity"] or ""),
                "title": row["title"],
                "reason": row["reason"],
                "frame": hit_frame,
                "named": hit_name,
            }
        )

    matched.sort(
        key=lambda item: (
            _SEVERITY_RANK.get(item["severity"].lower(), 9),
            str(item["rule_id"]),
            str(item["id"]),
        )
    )

    table, _shown, total = _capped_table(
        "Findings naming this entity",
        ["finding", "severity", "rule", "matched by", "frame"],
        [
            {
                "cells": [
                    _cell(
                        item["title"],
                        tone=TONE_WATCH,
                        to=_to(f"/findings/{quote(str(item['id']), safe='')}", tab="overview"),
                    ),
                    _cell(item["severity"]),
                    _cell(item["rule_id"]),
                    _cell("entity" if item["named"] else "frame"),
                    _cell(
                        item["frame"],
                        to=_to("/packets", sel=item["frame"]) if item["frame"] is not None else None,
                    ),
                ]
            }
            for item in matched[:PROFILE_CAP]
        ],
        "finding(s)",
        total=len(matched),
    )

    links = [
        _link(_to(f"/findings/{quote(str(item['id']), safe='')}", tab="overview"), item["rule_id"])
        for item in matched[:5]
    ]

    if not matched:
        detail = (
            f"none of the {len(rows)} finding(s) in this capture names this {_noun(ctx.kind)}"
            f"{' or carries one of its frames' if ctx.kind == 'ip' else ''}"
        )
        if frames_truncated:
            detail += (
                f"; only the first {ENTITY_FRAME_CAP} frames of this address were compared"
            )
        return _empty(detail, visuals=[table], links=links, label="finding(s) naming this entity")

    return _Result(
        "ok",
        None,
        total,
        "finding(s) naming this entity",
        TONE_WATCH,
        [table],
        links,
        truncated=bool(table["note"]),
    )


# ==========================================================================
# 4.2 — the `domain` questions
# ==========================================================================


def _q_domain_clients(ctx: _Ctx) -> _Result:
    if not ctx.index.dns:
        return _not_applicable(NO_DNS)

    rows = db.query_all(
        """
        SELECT COALESCE(client_ip, '(client not recorded)') AS client,
               COUNT(*) AS queries,
               SUM(CASE WHEN response_packet IS NULL THEN 1 ELSE 0 END) AS unanswered,
               MIN(time_epoch) AS first_seen, MAX(time_epoch) AS last_seen
          FROM dns_queries
         WHERE analysis_id = ? AND query_name = ? COLLATE NOCASE
         GROUP BY client
         ORDER BY queries DESC, client ASC
         LIMIT ?
        """,
        (ctx.analysis_id, ctx.entity, ROW_SCAN_CAP),
    )
    if not rows:
        return _not_applicable(_absent(ctx, "DNS"))

    bars, _shown, bars_total = _ranked_bars(
        "Queries per client",
        [
            {
                "label": str(row["client"]),
                "value": int(row["queries"]),
                "to": _to("/hosts", ip=row["client"]),
            }
            for row in rows
        ],
        "queries",
        "client(s)",
    )
    table, _s, total = _capped_table(
        "Clients that asked for this name",
        ["client", "queries", "unanswered", "first asked"],
        [
            {
                "cells": [
                    _cell(row["client"], tone=TONE_WATCH, to=_to("/dns", client_ip=row["client"])),
                    _cell(int(row["queries"])),
                    _cell(int(row["unanswered"] or 0)),
                    _cell(_stamp(row["first_seen"])),
                ]
            }
            for row in rows[:PROFILE_CAP]
        ],
        "client(s)",
        total=len(rows),
    )
    links = [_link(_to("/dns", domain=ctx.entity), "every query for this name")]
    for row in rows[:4]:
        links.append(_link(_to("/hosts", ip=row["client"]), str(row["client"])))

    return _Result(
        "ok",
        None,
        total,
        "distinct client(s) that asked",
        TONE_INFO,
        [bars, table],
        links,
        truncated=bool(bars["note"]) or bool(table["note"]),
    )


def _q_domain_answers(ctx: _Ctx) -> _Result:
    if not ctx.index.dns:
        return _not_applicable(NO_DNS)

    rows = db.query_all(
        """
        SELECT answer_ips, cnames, rcode_name FROM dns_queries
         WHERE analysis_id = ? AND query_name = ? COLLATE NOCASE
        """,
        (ctx.analysis_id, ctx.entity),
    )
    if not rows:
        return _not_applicable(_absent(ctx, "DNS"))

    answers: dict[str, int] = {}
    cnames: dict[str, int] = {}
    for row in rows:
        for value in _split_values(row["answer_ips"]):
            answers[value] = answers.get(value, 0) + 1
        for value in _split_values(row["cnames"]):
            cnames[value] = cnames.get(value, 0) + 1

    if not answers:
        answered = sum(1 for row in rows if row["rcode_name"] == "NOERROR")
        return _empty(
            f"none of the {len(rows)} DNS row(s) for this name carried an address in its "
            f"answer section ({answered} answered NOERROR overall)",
            links=_entity_links(ctx),
            label="address(es) this name resolved to",
        )

    bars, _shown, total = _ranked_bars(
        "Addresses this name resolved to",
        [{"label": value, "value": count, "to": _to("/hosts", ip=value)} for value, count in answers.items()],
        "answer(s)",
        "address(es)",
    )

    links = [_link(_to("/dns", domain=ctx.entity), "every query for this name")]
    for value in list(answers)[:4]:
        links.append(_link(_to("/hosts", ip=value), value))
    if cnames:
        links.append(_link(_to("/dns", search=next(iter(cnames))), "queries naming the CNAME"))

    return _Result(
        "ok",
        None,
        total,
        "distinct address(es) resolved in this capture",
        TONE_INFO,
        [bars],
        links,
        truncated=bool(bars["note"]),
    )


def _q_domain_rcodes(ctx: _Ctx) -> _Result:
    if not ctx.index.dns:
        return _not_applicable(NO_DNS)

    rows = db.query_all(
        """
        SELECT COALESCE(rcode_name, ?) AS rcode, COUNT(*) AS n
          FROM dns_queries
         WHERE analysis_id = ? AND query_name = ? COLLATE NOCASE
         GROUP BY rcode
         ORDER BY n DESC, rcode ASC
        """,
        (NO_RESPONSE, ctx.analysis_id, ctx.entity),
    )
    total_queries = sum(int(row["n"]) for row in rows)
    if total_queries == 0:
        return _not_applicable(_absent(ctx, "DNS"))

    recorded = [row for row in rows if row["rcode"] != NO_RESPONSE]
    bars, _shown, total = _ranked_bars(
        "How the resolver answered",
        [{"label": str(row["rcode"]), "value": int(row["n"])} for row in rows],
        "queries",
        "rcode(s)",
    )

    if not recorded:
        return _empty(
            f"all {total_queries} query(s) for this name went unanswered in this capture, "
            f"so no response code was recorded",
            visuals=[bars],
            links=_entity_links(ctx),
            label="distinct rcode(s) recorded",
        )

    return _Result(
        "ok",
        None,
        total,
        "distinct rcode(s) recorded",
        TONE_INFO,
        [bars],
        [_link(_to("/dns", domain=ctx.entity), "every query for this name")],
        truncated=bool(bars["note"]),
    )


def _q_domain_activity(ctx: _Ctx) -> _Result:
    if not ctx.index.dns:
        return _not_applicable(NO_DNS)

    rows = db.query_all(
        """
        SELECT time_epoch FROM dns_queries
         WHERE analysis_id = ? AND query_name = ? COLLATE NOCASE
         ORDER BY time_epoch IS NULL, time_epoch ASC
         LIMIT ?
        """,
        (ctx.analysis_id, ctx.entity, ROW_SCAN_CAP),
    )
    if not rows:
        return _not_applicable(_absent(ctx, "DNS"))

    timeline, shown, total = _capped_timeline(
        f"Queries for this name per {ctx.window} s",
        ((row["time_epoch"], 1) for row in rows),
        "queries",
        ctx.window,
    )
    link = [_link(_to("/dns", domain=ctx.entity), "every query for this name")]
    if not timeline["points"]:
        return _empty(
            f"the {len(rows)} DNS row(s) for this name recorded no usable timestamp",
            visuals=[timeline],
            links=link,
            label=f"bucket(s) of {ctx.window} s with a query",
        )
    return _Result(
        "ok",
        None,
        shown,
        f"bucket(s) of {ctx.window} s with a query",
        TONE_INFO,
        [timeline],
        link,
        truncated=bool(timeline["note"]),
    )


def _q_domain_tls(ctx: _Ctx) -> _Result:
    if not ctx.index.tls:
        return _not_applicable(NO_TLS)

    rows = db.query_all(
        """
        SELECT stream_id, time_epoch, client_ip, server_ip, version, ja3, ja4,
               handshake_status, selected_alpn, cert_subject
          FROM tls_sessions
         WHERE analysis_id = ? AND sni = ? COLLATE NOCASE
         ORDER BY time_epoch IS NULL, time_epoch ASC
         LIMIT ?
        """,
        (ctx.analysis_id, ctx.entity, ROW_SCAN_CAP),
    )
    if not rows:
        return _not_applicable(_absent(ctx, "TLS"))

    table, _shown, total = _capped_table(
        "TLS handshakes carrying this name",
        ["client", "server", "version", "alpn", "ja3", "handshake", "frame"],
        [
            {
                "cells": [
                    _cell(row["client_ip"], to=_to("/hosts", ip=row["client_ip"]) if row["client_ip"] else None),
                    _cell(row["server_ip"], to=_to("/hosts", ip=row["server_ip"]) if row["server_ip"] else None),
                    _cell(row["version"] or ""),
                    _cell(row["selected_alpn"] or ""),
                    _cell(row["ja3"] or ""),
                    _cell(row["handshake_status"] or ""),
                    _cell(
                        row["stream_id"],
                        to=_to("/packets", stream_id=row["stream_id"], transport="tcp")
                        if row["stream_id"] is not None
                        else None,
                    ),
                ]
            }
            for row in rows[:PROFILE_CAP]
        ],
        "handshake(s)",
        total=len(rows),
    )
    links = [_link(_to("/tls", sni=ctx.entity), "every handshake with this SNI")]
    for row in rows[:4]:
        if row["client_ip"]:
            links.append(_link(_to("/hosts", ip=row["client_ip"]), str(row["client_ip"])))

    return _Result(
        "ok",
        None,
        total,
        "TLS handshake(s) carrying this name",
        TONE_INFO,
        [table],
        links,
        truncated=bool(table["note"]),
    )


def _q_domain_http(ctx: _Ctx) -> _Result:
    if not ctx.index.http:
        return _not_applicable(NO_HTTP)

    rows = _http_rows(ctx)
    if not rows:
        return _not_applicable(_absent(ctx, "HTTP"))

    table, _shown, total = _capped_table(
        "HTTP requests addressed to this host",
        ["uri", "method", "status", "client", "bytes back"],
        [
            {
                "cells": [
                    _cell(row["uri"] or "", tone=TONE_WATCH, to=_to("/http", tx=row["id"])),
                    _cell(row["method"] or ""),
                    _cell(row["status_code"] if row["status_code"] is not None else NO_RESPONSE),
                    _cell(row["client_ip"], to=_to("/hosts", ip=row["client_ip"]) if row["client_ip"] else None),
                    _cell(int(row["response_body_size"] or row["response_len"] or 0)),
                ]
            }
            for row in rows[:PROFILE_CAP]
        ],
        "request(s)",
        total=len(rows),
    )
    links = [_link(_to("/http", host=ctx.entity), "every request to this host")]
    for row in rows[:4]:
        if row["client_ip"]:
            links.append(_link(_to("/hosts", ip=row["client_ip"]), str(row["client_ip"])))

    return _Result(
        "ok",
        None,
        total,
        "HTTP request(s) addressed to this host",
        TONE_INFO,
        [table],
        links,
        truncated=bool(table["note"]),
    )


# ==========================================================================
# 4.3 — the `url` questions
# ==========================================================================


def _q_url_clients(ctx: _Ctx) -> _Result:
    if not ctx.index.http:
        return _not_applicable(NO_HTTP)

    rows = _http_rows(ctx)
    if not rows:
        return _not_applicable(_absent(ctx, "HTTP"))

    per_client: dict[str, dict] = {}
    for row in rows:
        key = str(row["client_ip"] or "(client not recorded)")
        entry = per_client.setdefault(
            key, {"client": key, "requests": 0, "server": set(), "stream": set()}
        )
        entry["requests"] += 1
        if row["server_ip"]:
            entry["server"].add(str(row["server_ip"]))
        if row["stream_id"] is not None:
            entry["stream"].add(int(row["stream_id"]))

    ordered = sorted(per_client.values(), key=lambda item: (-item["requests"], item["client"]))
    bars, _shown, bars_total = _ranked_bars(
        "Requests per client",
        [
            {
                "label": item["client"],
                "value": item["requests"],
                "to": _to("/hosts", ip=item["client"]),
            }
            for item in ordered
        ],
        "requests",
        "client(s)",
    )
    table, _s, total = _capped_table(
        "Clients that requested this URL",
        ["client", "requests", "server", "conversation"],
        [
            {
                "cells": [
                    _cell(item["client"], tone=TONE_WATCH, to=_to("/http", client_ip=item["client"])),
                    _cell(item["requests"]),
                    _cell(", ".join(sorted(item["server"]))),
                    _cell(
                        ", ".join(str(value) for value in sorted(item["stream"])),
                        to=_to("/conversations", stream=f"tcp:{min(item['stream'])}")
                        if item["stream"]
                        else None,
                    ),
                ]
            }
            for item in ordered[:PROFILE_CAP]
        ],
        "client(s)",
        total=len(ordered),
    )
    links = [_link(_to("/http", uri=ctx.entity), "every request for this URI")]
    for item in ordered[:4]:
        links.append(_link(_to("/hosts", ip=item["client"]), item["client"]))

    return _Result(
        "ok",
        None,
        total,
        "distinct client(s) that requested it",
        TONE_INFO,
        [bars, table],
        links,
        truncated=bool(bars["note"]) or bool(table["note"]),
    )


def _q_url_status(ctx: _Ctx) -> _Result:
    if not ctx.index.http:
        return _not_applicable(NO_HTTP)

    rows = _http_rows(ctx)
    if not rows:
        return _not_applicable(_absent(ctx, "HTTP"))

    counts: dict[str, int] = {}
    answered = 0
    for row in rows:
        if row["status_code"] is None:
            counts[NO_RESPONSE] = counts.get(NO_RESPONSE, 0) + 1
            continue
        answered += 1
        text = str(row["status_text"] or "").strip()
        label = f"{int(row['status_code'])} {text}".strip()
        counts[label] = counts.get(label, 0) + 1

    bars, _shown, total = _ranked_bars(
        "How the server answered",
        [{"label": label, "value": count} for label, count in counts.items()],
        "responses",
        "status(es)",
    )
    links = [_link(_to("/http", uri=ctx.entity), "every request for this URI")]
    if not answered:
        return _empty(
            f"none of the {len(rows)} request(s) for this URI were answered in this capture, "
            f"so no status line was recorded",
            visuals=[bars],
            links=links,
            label="response(s) with a status line",
        )

    return _Result(
        "ok",
        None,
        answered,
        "response(s) with a status line",
        TONE_INFO,
        [bars],
        links,
        truncated=bool(bars["note"]),
    )


def _q_url_methods(ctx: _Ctx) -> _Result:
    if not ctx.index.http:
        return _not_applicable(NO_HTTP)

    rows = _http_rows(ctx)
    if not rows:
        return _not_applicable(_absent(ctx, "HTTP"))

    counts: dict[str, int] = {}
    for row in rows:
        label = str(row["method"] or "(no method recorded)")
        counts[label] = counts.get(label, 0) + 1

    bars, _shown, total = _ranked_bars(
        "Methods used",
        [{"label": label, "value": count} for label, count in counts.items()],
        "requests",
        "method(s)",
    )
    return _Result(
        "ok",
        None,
        total,
        "distinct method(s) used",
        TONE_INFO,
        [bars],
        [_link(_to("/http", uri=ctx.entity), "every request for this URI")],
        truncated=bool(bars["note"]),
    )


def _q_url_activity(ctx: _Ctx) -> _Result:
    if not ctx.index.http:
        return _not_applicable(NO_HTTP)

    rows = db.query_all(
        """
        SELECT time_epoch FROM http_transactions
         WHERE analysis_id = ? AND uri = ?
         ORDER BY time_epoch IS NULL, time_epoch ASC
         LIMIT ?
        """,
        (ctx.analysis_id, ctx.entity, ROW_SCAN_CAP),
    )
    if not rows:
        return _not_applicable(_absent(ctx, "HTTP"))

    timeline, shown, total = _capped_timeline(
        f"Requests for this URI per {ctx.window} s",
        ((row["time_epoch"], 1) for row in rows),
        "requests",
        ctx.window,
    )
    link = [_link(_to("/http", uri=ctx.entity), "every request for this URI")]
    if not timeline["points"]:
        return _empty(
            f"the {len(rows)} request(s) for this URI recorded no usable timestamp",
            visuals=[timeline],
            links=link,
            label=f"bucket(s) of {ctx.window} s with a request",
        )
    return _Result(
        "ok",
        None,
        shown,
        f"bucket(s) of {ctx.window} s with a request",
        TONE_INFO,
        [timeline],
        link,
        truncated=bool(timeline["note"]),
    )


def _q_url_request_shape(ctx: _Ctx) -> _Result:
    if not ctx.index.http:
        return _not_applicable(NO_HTTP)

    rows = _http_rows(ctx)
    if not rows:
        return _not_applicable(_absent(ctx, "HTTP"))

    if not any(row["user_agent"] or row["referer"] or row["content_type"] for row in rows):
        return _not_applicable(
            f"none of the {len(rows)} request(s) for this URI recorded a user agent, a "
            f"referer or a content type, so the request shape cannot be described"
        )

    shape: dict[tuple[str, str, str], int] = {}
    for row in rows:
        key = (
            str(row["user_agent"] or ""),
            str(row["referer"] or ""),
            str(row["content_type"] or ""),
        )
        shape[key] = shape.get(key, 0) + 1
    ordered = sorted(shape.items(), key=lambda kv: (-kv[1], kv[0]))
    agents = {key[0] for key in shape if key[0]}

    table, _shown, total = _capped_table(
        "Request shape, one row per distinct combination",
        ["user agent", "referer", "content type", "requests"],
        [
            {
                "cells": [
                    _cell(agent or "(none)"),
                    _cell(referer or "(none)"),
                    _cell(content_type or "(none)"),
                    _cell(count),
                ]
            }
            for (agent, referer, content_type), count in ordered[:PROFILE_CAP]
        ],
        "combination(s)",
        total=len(ordered),
    )
    links = [_link(_to("/http", uri=ctx.entity), "every request for this URI")]
    for agent in sorted(agents)[:3]:
        links.append(_link(_to("/http", user_agent=agent[:120]), agent[:60]))

    return _Result(
        "ok",
        None,
        len(ordered),
        f"distinct request shape(s) across {len(rows)} request(s)",
        TONE_INFO,
        [table],
        links,
        truncated=bool(table["note"]),
    )


# ==========================================================================
# question sets
# ==========================================================================

_IP_SPECS: tuple[_Spec, ...] = (
    _Spec(
        id="volume_by_direction",
        title="Volume by direction",
        question="How much did it send, and how much did it receive?",
        interpretation=(
            "The split between bytes leaving and bytes arriving is what makes a volume "
            "readable: a host that received far more than it sent was being served, while "
            "one that sent far more was providing or uploading."
        ),
        caveat=(
            "Direction is attributed by the addresses on each frame, not by who started the "
            "conversation. Bytes counted here include headers, retransmissions and both "
            "directions of every flow, so they are not the size of any payload."
        ),
        shapes=("bars", "table"),
    ),
    _Spec(
        id="activity_over_time",
        title="Activity over time",
        question="When was it active, and was the traffic steady or bursty?",
        interpretation=(
            "The gaps between consecutive frames separate a steady talker from a bursty "
            "one: a single wide gap or a run of sub-second frames says something happened "
            "at that moment rather than continuously."
        ),
        caveat=(
            "The capture window is the only window measured. Activity before it started or "
            "after it ended is invisible, and a capture that recorded only part of a "
            "conversation shows only the part it holds."
        ),
        shapes=("timeline", "histogram"),
    ),
    _Spec(
        id="connections",
        title="Conversations",
        question="How many conversations did it take part in, and with whom?",
        interpretation=(
            "Each row is a conversation the index actually assembled. Peer, ports and "
            "role here show who this address talked to and which side opened the flow."
        ),
        caveat=(
            "A conversation exists because frames exist, not because the endpoints agreed "
            "on anything: a flow that was reset, blocked or left half-open appears here "
            "exactly like a completed one."
        ),
        shapes=("heatmap", "table"),
    ),
    _Spec(
        id="peer_fanout",
        title="Peer fan-out",
        question="How many distinct peers did it talk to?",
        interpretation=(
            "Distinct peers, and how the bytes are distributed across them, show whether "
            "this address served one relationship or many."
        ),
        caveat=(
            "Fan-out is not a verdict. Gateways, resolvers, proxies and monitoring agents "
            "legitimately talk to everything, and a peer is only a peer if a conversation "
            "was captured."
        ),
        shapes=("bars", "scatter"),
    ),
    _Spec(
        id="ports_offered",
        title="Ports offered",
        question="Which ports did it listen on (traffic it accepted)?",
        interpretation=(
            "These are the ports this address was the responder on: the ones on which it "
            "was seen accepting traffic from another endpoint."
        ),
        caveat=(
            "Being the responder is not the same as listening. A reply observed on a port "
            "shows that something answered there, not what software answered, and a "
            "listening port that nothing in this capture contacted cannot appear."
        ),
        shapes=("bars",),
    ),
    _Spec(
        id="ports_contacted",
        title="Ports contacted",
        question="Which ports did it reach out to?",
        interpretation=(
            "These are the destination ports this address opened flows to — the services it "
            "used, in the order it used them."
        ),
        caveat=(
            "A contacted port does not establish that the service was reached. Refused, "
            "filtered and unanswered attempts appear here with the same port as a "
            "successful one."
        ),
        shapes=("bars",),
    ),
    _Spec(
        id="protocol_mix",
        title="Protocol mix",
        question="Which protocols did it speak, and in what proportion?",
        interpretation=(
            "The dissected protocol of every frame this address appears in. A frame whose "
            "protocol the dissector could not name is grouped as such rather than dropped."
        ),
        caveat=(
            "Frames are counted, not decoded. Encrypted payloads are not opened anywhere in "
            "ShadowPackets, so a TLS session shows as TLS whatever it carries."
        ),
        shapes=("bars", "table"),
    ),
    _Spec(
        id="domains_resolved",
        title="Names resolved",
        question="Which names did it ask a resolver for?",
        interpretation=(
            "The names this address asked DNS for, with the answer it received. These are "
            "names the capture recorded being requested, not names the address used."
        ),
        caveat=(
            "A name asked for is not a name contacted. Resolvers answer from cache, search "
            "suffixes and retries repeat names, and a name resolved here may never have "
            "been used for a connection."
        ),
        shapes=("table",),
    ),
    _Spec(
        id="domains_contacted",
        title="Names contacted over TLS",
        question="Which names did it contact over TLS?",
        interpretation=(
            "The server names it presented or was presented with in a TLS handshake. This "
            "is what the capture proves about which names this address talked to."
        ),
        caveat=(
            "Encrypted ClientHello and resumed sessions carry no readable name, and a "
            "capture that started mid-session recorded none. SNI names a destination, it "
            "does not prove what was exchanged."
        ),
        shapes=("table",),
    ),
    _Spec(
        id="dns_health",
        title="DNS health",
        question="How many of its queries went unanswered, and which resolvers did it use?",
        interpretation=(
            "Queries with no matching response, plus the resolvers they were sent to. A run "
            "of unanswered lookups is what a client sees when it is asking for something "
            "that is not there or when the reply never arrived."
        ),
        caveat=(
            "An unanswered query in the index may simply be a response the capture did not "
            "hold: an off-window reply, a dropped frame or a capture taken at the client."
        ),
        shapes=("bars", "table"),
    ),
    _Spec(
        id="http_activity",
        title="HTTP activity",
        question="Which HTTP hosts and paths did it use?",
        interpretation=(
            "Every HTTP transaction this address appears in, as client or as server, with "
            "the host, path, method and outcome the capture recorded."
        ),
        caveat=(
            "Only cleartext HTTP is present. HTTPS requests are not decrypted and never "
            "appear here, so an empty list is not an idle address."
        ),
        shapes=("bars", "table"),
    ),
    _Spec(
        id="clear_text_credentials",
        title="Clear-text credentials",
        question="Did anything it sent carry a credential in clear text?",
        interpretation=(
            "Requests whose URI, headers or body matched a credential keyword — a password "
            "field, an API key, a token or an authorization header — while travelling "
            "unencrypted."
        ),
        caveat=(
            "The keyword match is evidence of a parameter name, not of a working secret. "
            "The value may be a placeholder, an already-expired token or a public "
            "identifier, and the flag says nothing about whether the credential was "
            "accepted."
        ),
        shapes=("table",),
    ),
    _Spec(
        id="files",
        title="Files transferred",
        question="Which files did it transfer, and what are their hashes?",
        interpretation=(
            "Objects the capture extracted and tied to this address, either through the "
            "conversation they were carried in or through a frame this address appears on."
        ),
        caveat=(
            "A file is attributed only when its stream or its recorded frames do. Content "
            "is never executed or scored here, and a hash identifies bytes, not intent."
        ),
        shapes=("table",),
    ),
    _Spec(
        id="tls_fingerprints",
        title="TLS fingerprints",
        question="Which JA3/JA4 fingerprints did it present?",
        interpretation=(
            "The client fingerprints observed in this address's TLS handshakes. A "
            "fingerprint is a shape, and the same shape appears wherever the same client "
            "stack is used."
        ),
        caveat=(
            "A fingerprint identifies a TLS implementation, not a person or a program. "
            "Browsers share fingerprints by version, and a single fingerprint can be "
            "presented by thousands of unrelated clients."
        ),
        shapes=("table",),
    ),
    _Spec(
        id="fingerprint_peers",
        title="Fingerprint peers",
        question="Which other addresses present the same fingerprints?",
        interpretation=(
            "Other endpoints whose sessions carried the same fingerprint as this address's "
            "sessions, named by the peer of that session."
        ),
        caveat=(
            "Sharing a fingerprint is not sharing an identity. A common stack or a common "
            "library produces the same value, and the peer named here is the other end of "
            "a matching session, not a confirmed associate."
        ),
        shapes=("table",),
    ),
    _Spec(
        id="findings",
        title="Findings",
        question="Which detections and Suricata signatures name it?",
        interpretation=(
            "Findings whose recorded entities name this address, or whose recorded frame "
            "numbers include a frame this address appears on."
        ),
        caveat=(
            "A finding is a lead, not a verdict. Detections trade false negatives for false "
            "positives, an empty list means only that no rule matched here, and the "
            "signature says nothing about whether an attempt succeeded."
        ),
        shapes=("table",),
    ),
)

_DOMAIN_SPECS: tuple[_Spec, ...] = (
    _Spec(
        id="clients",
        title="Clients",
        question="Which addresses asked for this name?",
        interpretation=(
            "The addresses that sent the DNS queries for this name, with how many each "
            "asked and how many of those went unanswered."
        ),
        caveat=(
            "Asking for a name is not contacting it. Queries come from caches, updaters, "
            "browsers and malware alike, and this list says nothing about which of them "
            "used the answer."
        ),
        shapes=("bars", "table"),
    ),
    _Spec(
        id="answers",
        title="Answers",
        question="Which addresses did it resolve to in this capture?",
        interpretation=(
            "The addresses that appeared in the answer sections of this name's DNS "
            "responses, counted across every response recorded here."
        ),
        caveat=(
            "An answer is what the resolver said at that moment. Records are pooled on "
            "purpose by most resolvers and CDNs, and the address actually connected to may "
            "be a different one from any listed."
        ),
        shapes=("bars",),
    ),
    _Spec(
        id="rcodes",
        title="Response codes",
        question="How did the resolver answer?",
        interpretation=(
            "The response code of every DNS row for this name. Queries whose response is "
            "not in the capture are grouped as having no recorded response rather than "
            "being counted as failures."
        ),
        caveat=(
            "A response code describes the resolver's answer, not the name. NXDOMAIN from a "
            "search suffix, a typo or a stale cache entry looks the same as NXDOMAIN from a "
            "name that does not exist."
        ),
        shapes=("bars",),
    ),
    _Spec(
        id="activity_over_time",
        title="Activity over time",
        question="When was it asked for?",
        interpretation=(
            "Queries for this name bucket into the capture's timeline, which shows whether "
            "it was asked once at a moment or repeatedly across the window."
        ),
        caveat=(
            "Only the queries this capture holds are counted. Traffic before and after the "
            "capture window is invisible, and a name asked for mainly from cache produces "
            "few queries here."
        ),
        shapes=("timeline",),
    ),
    _Spec(
        id="tls_sessions",
        title="TLS sessions",
        question="Which handshakes carried it as SNI?",
        interpretation=(
            "The TLS handshakes that named this host, with the client and server addresses, "
            "the negotiated version and the client's fingerprint."
        ),
        caveat=(
            "The name in a ClientHello is supplied by the client and is not authenticated by "
            "the handshake. A capture starting mid-session shows no name at all, and "
            "encrypted ClientHello hides it by design."
        ),
        shapes=("table",),
    ),
    _Spec(
        id="http_transactions",
        title="HTTP transactions",
        question="Which HTTP requests were addressed to it?",
        interpretation=(
            "Cleartext HTTP transactions whose Host header is this name, with the path, "
            "method, client and outcome."
        ),
        caveat=(
            "Only HTTP is visible. A host served entirely over HTTPS shows an empty list "
            "here, and a Host header is supplied by the client rather than proven by the "
            "server."
        ),
        shapes=("table",),
    ),
    _Spec(
        id="files",
        title="Files fetched",
        question="Which files were fetched from it?",
        interpretation=(
            "Objects extracted from conversations with this host, attributed through the "
            "stream they were carried in or through a recorded frame."
        ),
        caveat=(
            "Attribution follows the stream and the recorded frames, so an object with "
            "neither cannot be tied to a host. Content is never executed or scored here."
        ),
        shapes=("table",),
    ),
    _Spec(
        id="findings",
        title="Findings",
        question="Which detections name it?",
        interpretation=(
            "Findings whose recorded entities list this name among the hostnames they "
            "reference."
        ),
        caveat=(
            "A finding is a lead, not a verdict, and it names the name a rule matched "
            "rather than proving that this name was contacted or that anything succeeded."
        ),
        shapes=("table",),
    ),
)

_URL_SPECS: tuple[_Spec, ...] = (
    _Spec(
        id="clients",
        title="Clients",
        question="Which addresses requested this URL?",
        interpretation=(
            "The client addresses recorded on requests for this URI, with the servers and "
            "conversations each request travelled in."
        ),
        caveat=(
            "A recorded client address is the source of the request, which behind a proxy "
            "or NAT is not the originator. Nothing here establishes who was at that address."
        ),
        shapes=("bars", "table"),
    ),
    _Spec(
        id="status_codes",
        title="Status codes",
        question="How did the server answer?",
        interpretation=(
            "The status line recorded on the responses to this URI. Requests with no "
            "response in the capture are grouped as having none rather than counted as "
            "failures."
        ),
        caveat=(
            "A status code describes one response to one request. Redirects, error pages "
            "and cached answers all appear here exactly as the server sent them."
        ),
        shapes=("bars",),
    ),
    _Spec(
        id="methods",
        title="Methods",
        question="Which methods were used?",
        interpretation=(
            "The HTTP methods recorded on requests for this URI, which distinguishes a "
            "plain fetch from a submission or a WebDAV-style verb."
        ),
        caveat=(
            "The method is what the client asked for, not what the server honoured. A "
            "method outside the common set is unusual, not malicious."
        ),
        shapes=("bars",),
    ),
    _Spec(
        id="activity_over_time",
        title="Activity over time",
        question="When was it requested?",
        interpretation=(
            "Requests for this URI on the capture's timeline, which shows a one-off fetch "
            "against something polled repeatedly."
        ),
        caveat=(
            "Only the requests this capture holds are counted, so periodic polling that "
            "started before or continued after the window appears truncated."
        ),
        shapes=("timeline",),
    ),
    _Spec(
        id="request_shape",
        title="Request shape",
        question="What did the requests look like — user agent, referer, content type?",
        interpretation=(
            "One row per distinct combination of user agent, referer and content type, "
            "which is how a browser fetch is told apart from a tool or a script."
        ),
        caveat=(
            "Headers are client-supplied and trivially forged. A user agent identifies a "
            "claimed client, never a confirmed one."
        ),
        shapes=("table",),
    ),
    _Spec(
        id="files",
        title="Files returned",
        question="Which files came back from it?",
        interpretation=(
            "Objects extracted from the conversations that carried requests for this URI, "
            "attributed through the stream or a recorded frame."
        ),
        caveat=(
            "Several URIs share a conversation, so an object attributed through a stream "
            "belongs to that conversation rather than certainly to this URI. A body with no "
            "recorded frame cannot be tied at all."
        ),
        shapes=("table",),
    ),
    _Spec(
        id="findings",
        title="Findings",
        question="Which detections name it?",
        interpretation=(
            "Findings whose recorded entities list this exact URI among the URIs they "
            "reference."
        ),
        caveat=(
            "A finding is a lead, not a verdict, and it names the URI a rule matched rather "
            "than proving the request was served or that anything succeeded."
        ),
        shapes=("table",),
    ),
)

_IP_BUILDERS = {
    "volume_by_direction": _q_volume_by_direction,
    "activity_over_time": _q_activity_over_time,
    "connections": _q_connections,
    "peer_fanout": _q_peer_fanout,
    "ports_offered": _q_ports_offered,
    "ports_contacted": _q_ports_contacted,
    "protocol_mix": _q_protocol_mix,
    "domains_resolved": _q_domains_resolved,
    "domains_contacted": _q_domains_contacted,
    "dns_health": _q_dns_health,
    "http_activity": _q_http_activity,
    "clear_text_credentials": _q_clear_text_credentials,
    "files": _q_files,
    "tls_fingerprints": _q_tls_fingerprints,
    "fingerprint_peers": _q_fingerprint_peers,
    "findings": _q_findings,
}

# §4.2/§4.3 reuse the same builders where the question is the same one asked of a
# name or a URI rather than of an address.
_DOMAIN_BUILDERS = {
    "clients": _q_domain_clients,
    "answers": _q_domain_answers,
    "rcodes": _q_domain_rcodes,
    "activity_over_time": _q_domain_activity,
    "tls_sessions": _q_domain_tls,
    "http_transactions": _q_domain_http,
    "files": _q_files,
    "findings": _q_findings,
}

_URL_BUILDERS = {
    "clients": _q_url_clients,
    "status_codes": _q_url_status,
    "methods": _q_url_methods,
    "activity_over_time": _q_url_activity,
    "request_shape": _q_url_request_shape,
    "files": _q_files,
    "findings": _q_findings,
}

SPECS: dict[str, tuple[_Spec, ...]] = {
    "ip": _IP_SPECS,
    "domain": _DOMAIN_SPECS,
    "url": _URL_SPECS,
}

BUILDERS: dict[str, dict[str, Any]] = {
    "ip": _IP_BUILDERS,
    "domain": _DOMAIN_BUILDERS,
    "url": _URL_BUILDERS,
}

SPEC_BY_ID: dict[str, dict[str, _Spec]] = {
    kind: {spec.id: spec for spec in specs} for kind, specs in SPECS.items()
}


# --------------------------------------------------------------------------
# rendering
# --------------------------------------------------------------------------


def _has_data(visual: dict) -> bool:
    return any(visual.get(key) for key in ("items", "points", "buckets", "rows"))


def _empty_visuals(spec: _Spec) -> list[dict]:
    """The §3 shapes this question declares, with no data."""
    payloads: dict[str, dict] = {
        "bars": {"items": []},
        "timeline": {"points": []},
        "histogram": {"buckets": []},
        "scatter": {"points": [], "x_label": "", "y_label": ""},
        "heatmap": {"columns": [], "rows": []},
        "table": {"columns": [], "rows": []},
    }
    visuals = []
    for kind in spec.shapes:
        visual = {"kind": kind, "title": spec.title, **payloads[kind]}
        visual.setdefault("unit", "")
        visual["note"] = ""
        visuals.append(visual)
    return visuals


def _render(spec: _Spec, result: _Result) -> dict:
    """Assemble one §3 question.

    An ``"ok"`` question never carries an empty chart, so a visual whose series
    came back empty is dropped rather than rendered as an empty axis. Nothing is
    invented to fill it: the builders only return ``"ok"`` when the collection
    behind the headline is non-empty, and ``headline.value`` is that
    collection's real size.
    """
    if result.availability == "ok":
        populated = [visual for visual in result.visuals if _has_data(visual)]
        if populated:
            result.visuals = populated
        elif not result.visuals:
            result.visuals = _empty_visuals(spec)
            log.warning("profile question %s reported ok with no data", spec.id)
    if result.availability == "not_applicable":
        result.visuals = []
        result.links = []

    if result.availability != "ok" and not result.reason:
        result.reason = FAILED_REASON

    return {
        "id": spec.id,
        "title": spec.title,
        "question": spec.question,
        "availability": result.availability,
        "availability_reason": result.reason,
        "headline": {
            "value": result.headline_value,
            "label": result.headline_label,
            "tone": result.tone,
        },
        "visuals": result.visuals,
        "interpretation": spec.interpretation,
        "caveat": spec.caveat,
        "links": result.links,
    }


# --------------------------------------------------------------------------
# summary
# --------------------------------------------------------------------------


def _summary_note_ip(ctx: _Ctx, mac: Any, objects: int) -> str | None:
    notes: list[str] = []
    if mac:
        row = db.query_one(
            "SELECT COUNT(*) AS n FROM hosts WHERE analysis_id = ? AND mac = ? AND ip <> ?",
            (ctx.analysis_id, mac, ctx.entity),
        )
        shared = _as_int(row["n"] if row else 0)
        if shared:
            notes.append(
                f"the MAC recorded for this address is shared with {shared} other "
                f"address(es) in this capture, so it does not identify the host"
            )
    unattributed = _unattributed_objects(ctx.analysis_id, objects)
    if unattributed:
        notes.append(
            f"{unattributed} of {objects} extracted object(s) record no stream and no frame, "
            f"so they cannot be tied to any address"
        )
    return " ".join(notes) or None


def _summary(ctx: _Ctx) -> dict:
    aid, value = ctx.analysis_id, ctx.entity

    if ctx.kind == "ip":
        host = db.query_one(
            """
            SELECT mac, first_seen, last_seen, packets_sent, packets_received,
                   bytes_sent, bytes_received, dns_names, is_private
              FROM hosts WHERE analysis_id = ? AND ip = ?
            """,
            (aid, value),
        )
        if host is not None:
            mac = host["mac"]
            first_seen = host["first_seen"]
            last_seen = host["last_seen"]
            packets = int(host["packets_sent"] or 0) + int(host["packets_received"] or 0)
            total_bytes = int(host["bytes_sent"] or 0) + int(host["bytes_received"] or 0)
            hostnames = [str(name) for name in _json_list(host["dns_names"])]
        else:
            row = db.query_one(
                """
                SELECT COUNT(*) AS packets, SUM(COALESCE(frame_len, 0)) AS bytes,
                       MIN(time_epoch) AS first_seen, MAX(time_epoch) AS last_seen,
                       MAX(eth_src) AS mac
                  FROM packets
                 WHERE analysis_id = ? AND (src_ip = ? OR dst_ip = ?)
                """,
                (aid, value, value),
            )
            mac = row["mac"] if row else None
            first_seen = row["first_seen"] if row else None
            last_seen = row["last_seen"] if row else None
            packets = _as_int(row["packets"] if row else 0)
            total_bytes = _as_int(row["bytes"] if row else 0)
            hostnames = []

        return {
            "label": value,
            "scope": address_scope(value),
            "mac": mac,
            "hostnames": hostnames,
            "first_seen": float(first_seen) if first_seen is not None else None,
            "last_seen": float(last_seen) if last_seen is not None else None,
            "packets": packets,
            "bytes": total_bytes,
            "note": _summary_note_ip(ctx, mac, ctx.index.objects),
        }

    # A name or a URI is not an endpoint: the packet and byte totals count the
    # frames that carried it, which the note states rather than leaving the
    # reader to assume that the name sent them.
    if ctx.kind == "domain":
        where = (
            "(dns_query = ? COLLATE NOCASE OR http_host = ? COLLATE NOCASE "
            "OR tls_sni = ? COLLATE NOCASE)"
        )
        params: tuple = (aid, value, value, value)
        note = (
            "a name, not an address: scope, MAC and host identity do not apply, and the "
            "packet and byte totals count the frames that carried this name in the DNS, "
            "HTTP or TLS layer"
        )
    else:
        where = "http_uri = ?"
        params = (aid, value)
        note = (
            "a request path, not an endpoint: scope, MAC and host identity do not apply, "
            "and the packet and byte totals count the frames that carried this URI"
        )

    row = db.query_one(
        f"""
        SELECT COUNT(*) AS packets, SUM(COALESCE(frame_len, 0)) AS bytes,
               MIN(time_epoch) AS first_seen, MAX(time_epoch) AS last_seen
          FROM packets
         WHERE analysis_id = ? AND {where}
        """,
        params,
    )
    packets = _as_int(row["packets"] if row else 0)
    if packets == 0:
        # No frame carries the name itself (a capture indexed without the name
        # columns, or an object-only match): fall back to the layer's own rows.
        if ctx.kind == "domain":
            fallback = db.query_one(
                """
                SELECT (SELECT COUNT(*) FROM dns_queries
                         WHERE analysis_id = ? AND query_name = ? COLLATE NOCASE)
                     + (SELECT COUNT(*) FROM http_transactions
                         WHERE analysis_id = ? AND host = ? COLLATE NOCASE)
                     + (SELECT COUNT(*) FROM tls_sessions
                         WHERE analysis_id = ? AND sni = ? COLLATE NOCASE) AS packets,
                       (SELECT MIN(time_epoch) FROM dns_queries
                         WHERE analysis_id = ? AND query_name = ? COLLATE NOCASE) AS dns_first,
                       (SELECT MAX(time_epoch) FROM dns_queries
                         WHERE analysis_id = ? AND query_name = ? COLLATE NOCASE) AS dns_last
                """,
                (aid, value, aid, value, aid, value, aid, value, aid, value),
            )
        else:
            fallback = db.query_one(
                "SELECT COUNT(*) AS packets, MIN(time_epoch) AS dns_first, "
                "MAX(time_epoch) AS dns_last FROM http_transactions "
                "WHERE analysis_id = ? AND uri = ?",
                (aid, value),
            )
        packets = _as_int(fallback["packets"] if fallback else 0)
        first_seen = fallback["dns_first"] if fallback else None
        last_seen = fallback["dns_last"] if fallback else None
        if packets:
            note += (
                "; the packet index recorded no frame carrying it, so this total counts the "
                "layer's own rows instead"
            )
    else:
        first_seen = row["first_seen"]
        last_seen = row["last_seen"]

    unattributed = _unattributed_objects(aid, ctx.index.objects)
    if unattributed:
        note += (
            f"; {unattributed} of {ctx.index.objects} extracted object(s) record no stream "
            f"and no frame, so they cannot be tied to any entity"
        )

    return {
        "label": value,
        "scope": None,
        "mac": None,
        "hostnames": [],
        "first_seen": float(first_seen) if first_seen is not None else None,
        "last_seen": float(last_seen) if last_seen is not None else None,
        "packets": packets,
        "bytes": _as_int(row["bytes"] if row else 0),
        "note": note,
    }


# --------------------------------------------------------------------------
# search (§2)
# --------------------------------------------------------------------------

_IPV4_SHAPE = re.compile(r"\d{1,3}(?:\.\d{1,3}){1,3}\Z")
_IPV6_SHAPE = re.compile(r"[0-9A-Fa-f:]{2,}\Z")


def _looks_like_address(query: str) -> bool:
    """§2: a query that looks like an address returns only ``ip`` matches.

    Two or more dotted decimal octets, each at most 255, is an address prefix
    (``3.173.21`` finds ``3.173.21.63``); a colon-separated hex group is an IPv6
    prefix. A single bare number is not an address and searches everything.
    """
    if "://" in query or query.startswith("/"):
        return False
    if _IPV4_SHAPE.match(query):
        return all(int(part) <= 255 for part in query.split("."))
    return ":" in query and bool(_IPV6_SHAPE.match(query))


def _match_to(kind: str, entity: str) -> str:
    return _to("/investigate", kind=kind, entity=entity)


def _ip_matches(analysis_id: str, query: str, limit: int) -> list[dict]:
    rows = db.query_all(
        """
        SELECT h.ip AS ip, h.mac AS mac, h.is_private AS is_private,
               h.bytes_sent + h.bytes_received AS total_bytes,
               (SELECT COUNT(*) FROM conversations c
                 WHERE c.analysis_id = h.analysis_id AND (c.ip_a = h.ip OR c.ip_b = h.ip))
                   AS conversations
          FROM hosts h
         WHERE h.analysis_id = ? AND h.ip LIKE ? ESCAPE '\\'
         ORDER BY total_bytes DESC, h.ip ASC
         LIMIT ?
        """,
        (analysis_id, _like_value(query), limit + 1),
    )
    return [
        {
            "kind": "ip",
            "entity": str(row["ip"]),
            "label": str(row["ip"]),
            "hint": (
                f"{_scope_label(row['ip'])} address · "
                f"{int(row['conversations'] or 0)} conversation(s)"
            ),
            "count": int(row["conversations"] or 0),
            "to": _match_to("ip", str(row["ip"])),
        }
        for row in rows
    ]


def _domain_matches(analysis_id: str, query: str, limit: int) -> list[dict]:
    pattern = _like_value(query)
    rows = db.query_all(
        """
        SELECT value, SUM(n) AS n FROM (
            SELECT query_name AS value, COUNT(*) AS n FROM dns_queries
             WHERE analysis_id = ? AND query_name LIKE ? ESCAPE '\\'
             GROUP BY query_name
            UNION ALL
            SELECT host AS value, COUNT(*) AS n FROM http_transactions
             WHERE analysis_id = ? AND host LIKE ? ESCAPE '\\'
             GROUP BY host
            UNION ALL
            SELECT sni AS value, COUNT(*) AS n FROM tls_sessions
             WHERE analysis_id = ? AND sni LIKE ? ESCAPE '\\'
             GROUP BY sni
        )
        GROUP BY value
        ORDER BY n DESC, value ASC
        LIMIT ?
        """,
        (analysis_id, pattern, analysis_id, pattern, analysis_id, pattern, limit + 1),
    )
    return [
        {
            "kind": "domain",
            "entity": str(row["value"]),
            "label": str(row["value"]),
            "hint": f"{int(row['n'])} name reference(s) in this capture",
            "count": int(row["n"]),
            "to": _match_to("domain", str(row["value"])),
        }
        for row in rows
    ]


def _url_matches(analysis_id: str, query: str, limit: int) -> list[dict]:
    rows = db.query_all(
        """
        SELECT uri, COUNT(*) AS n FROM http_transactions
         WHERE analysis_id = ? AND uri LIKE ? ESCAPE '\\'
         GROUP BY uri
         ORDER BY n DESC, uri ASC
         LIMIT ?
        """,
        (analysis_id, _like_value(query), limit + 1),
    )
    if not rows:
        return []

    uris = [str(row["uri"]) for row in rows[: limit + 1]]
    placeholders = ", ".join("?" for _ in uris)
    names: dict[str, tuple[str, int]] = {}
    for row in db.query_all(
        f"""
        SELECT uri, host, COUNT(*) AS n FROM http_transactions
         WHERE analysis_id = ? AND uri IN ({placeholders})
         GROUP BY uri, host
        """,
        (analysis_id, *uris),
    ):
        uri = str(row["uri"])
        host = row["host"]
        count = int(row["n"])
        if not host:
            continue
        current = names.get(uri)
        if current is None or count > current[1]:
            names[uri] = (str(host), count)

    out = []
    for row in rows:
        uri = str(row["uri"])
        host = names.get(uri)
        # §2: a URL's label is what to show rather than the value to pass back,
        # so the host is prefixed when the capture recorded one.
        label = f"{host[0]}{uri}" if host else uri
        out.append(
            {
                "kind": "url",
                "entity": uri,
                "label": label,
                "hint": f"{int(row['n'])} HTTP request(s)",
                "count": int(row["n"]),
                "to": _match_to("url", uri),
            }
        )
    return out


def search(analysis_id: str, query: str, limit: int = MATCH_CAP) -> dict:
    """Resolve one free-text query to the entities this analysis contains.

    Matching is a case-insensitive substring over the indexed value (§2), with
    the query's shape deciding which kinds are searched: an address-shaped query
    returns only addresses, one containing ``://`` or starting with ``/`` returns
    only URLs, and anything else searches all three. Every kind is capped at
    ``limit`` and the response says whether that cap bit.
    """
    query = str(query or "").strip()
    limit = max(1, min(MAX_MATCH_LIMIT, int(limit)))

    if not query:
        return {
            "analysis_id": analysis_id,
            "query": query,
            "matches": [],
            "truncated": False,
        }

    url_only = "://" in query or query.startswith("/")
    ip_only = _looks_like_address(query)

    collected: list[dict] = []
    overflow = False
    if not url_only:
        rows = _ip_matches(analysis_id, query, limit)
        overflow = overflow or len(rows) > limit
        collected.extend(rows[:limit])
    if not url_only and not ip_only:
        rows = _domain_matches(analysis_id, query, limit)
        overflow = overflow or len(rows) > limit
        collected.extend(rows[:limit])
    if not ip_only:
        rows = _url_matches(analysis_id, query, limit)
        overflow = overflow or len(rows) > limit
        collected.extend(rows[:limit])

    # One order across kinds: the count each match stands on, then the kind
    # order of §2 and the value, so the list is stable between calls.
    kind_order = {kind: index for index, kind in enumerate(KINDS)}
    collected.sort(key=lambda item: (-item["count"], kind_order[item["kind"]], item["entity"]))
    truncated = overflow or len(collected) > limit

    matches = collected[:limit]
    log.info(
        "profile search %s: %r -> %s match(es)%s",
        analysis_id,
        query,
        len(matches),
        " (truncated)" if truncated else "",
    )
    return {
        "analysis_id": analysis_id,
        "query": query,
        "matches": matches,
        "truncated": truncated,
    }


# --------------------------------------------------------------------------
# profile (§2, §4)
# --------------------------------------------------------------------------


def profile(
    analysis_id: str,
    kind: str,
    entity: str,
    *,
    window: int = DEFAULT_WINDOW,
) -> dict:
    """Every §4 question for one entity, in contract order.

    ``window`` is the seconds-per-bucket for the timelines; the route exposes no
    override for it, and this function clamps it so a direct call stays bounded.
    An entity the index does not contain is not an error: every question reports
    ``not_applicable`` with a reason, so a stale link explains itself.
    """
    kind = str(kind or "").strip().lower()
    if kind not in KINDS:
        raise ValueError(f"unknown profile kind {kind!r}")
    entity = str(entity or "").strip()
    window = max(MIN_WINDOW, min(MAX_WINDOW, int(window)))

    started = time.monotonic()
    index = _load_index(analysis_id)
    ctx = _Ctx(
        analysis_id=analysis_id,
        kind=kind,
        entity=entity,
        window=window,
        index=index,
    )

    known = bool(entity) and _entity_present(ctx)
    questions: list[dict] = []
    truncated: dict[str, bool] = {}

    for spec in SPECS[kind]:
        if not known:
            result = _not_applicable(
                f"this capture holds no row that names the {_noun(kind)} {entity!r}, so no "
                f"question can be answered for it here"
            )
        else:
            try:
                result = BUILDERS[kind][spec.id](ctx)
            except Exception:  # noqa: BLE001 - one bad question must not sink the page
                log.exception("profile question %s failed for %s", spec.id, analysis_id)
                result = _not_applicable(FAILED_REASON)
        rendered = _render(spec, result)
        questions.append(rendered)
        # Every question of this kind appears, so a reader of the map can tell
        # "nothing was capped" from "this question was not computed".
        truncated[spec.id] = bool(result.truncated)

    elapsed = time.monotonic() - started
    log.info(
        "profile %s %s %r: %s question(s) in %.3fs",
        analysis_id,
        kind,
        entity,
        len(questions),
        elapsed,
    )

    return {
        "analysis_id": analysis_id,
        "kind": kind,
        "entity": entity,
        "generated_at": time.time(),
        "summary": _summary(ctx) if known else {
            "label": entity,
            "scope": address_scope(entity) if kind == "ip" and entity else None,
            "mac": None,
            "hostnames": [],
            "first_seen": None,
            "last_seen": None,
            # §2's summary carries a number here, not a null, so an entity the
            # capture does not contain reports the count it found — none — and the
            # note says that this zero means "not found here" rather than "none
            # recorded". The questions below carry the same statement one by one.
            "packets": 0,
            "bytes": 0,
            "note": (
                f"this capture holds no row that names the {_noun(kind)} {entity!r}; the "
                f"zero totals above mean the capture holds nothing for it, and every "
                f"question below says so individually"
            ),
        },
        "questions": questions,
        "truncated": truncated,
    }


__all__ = [
    "KINDS",
    "MATCH_CAP",
    "MAX_MATCH_LIMIT",
    "MAX_QUERY_LENGTH",
    "MIN_QUERY_LENGTH",
    "PROFILE_CAP",
    "BARS_CAP",
    "TIMELINE_CAP",
    "SCATTER_CAP",
    "HEATMAP_CAP",
    "SPECS",
    "profile",
    "search",
]
