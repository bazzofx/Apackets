"""Conversation and TCP/UDP stream derivation.

Conversations are derived from the already-indexed ``packets`` table with SQL
rather than by parsing TShark's fixed-width ``-z conv`` tables. The ``packets``
rows carry the real per-frame lengths, ports and ``tcp.stream``/``udp.stream``
values for the very same capture, so the numbers stay consistent with the packet
list, and no fixed-width text parsing is involved.

Rules implemented here (contract §3):

* ``conv_id`` = ``"{transport}:{ip_a}:{port_a}-{ip_b}:{port_b}"``.
* ``endpoint_a`` is the side that initiated: the sender of the SYN for TCP, the
  sender of the first packet for UDP. When no SYN was observed on a TCP
  conversation the initiator is undeterminable, so the lexicographically smaller
  ``ip:port`` is used — a stability convention for the primary key, not a claim
  about direction.
* ``bytes_*`` are always sums of real ``frame_len`` values.
* ``state`` is derived from the flags observed in the frames — ``0x02`` SYN,
  ``0x10`` ACK, ``0x01`` FIN, ``0x04`` RST — never from request or response
  counts. UDP conversations never claim a TCP state. Two independent columns are
  consulted because the indexer's rendering of ``tcp.flags`` varies: the numeric
  bitmask and Wireshark's flag-string column (see :func:`_flag_bit`).
* ``protocols`` lists only application protocols actually observed in the
  conversation's frames.

The ``streams`` table is filled from the same conversation set, so a stream's
client is exactly the conversation's ``endpoint_a``.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from pathlib import Path

from app.core.logging import get_logger
from app.db import database as db
from app.services.jobs import JobContext

log = get_logger("shadowpackets.conversations")

BATCH_SIZE = 1000
CANCEL_CHECK_EVERY = 5000

# TCP flag bits, as reported by ``tcp.flags`` in ``packets.tcp_flags_raw``.
# ACK is 0x10 (16) and PSH is 0x08, so PSH+ACK is 24 and SYN+ACK is 18 (0x12).
TCP_FIN = 0x01
TCP_SYN = 0x02
TCP_RST = 0x04
TCP_ACK = 0x10
TCP_SYN_ACK = TCP_SYN | TCP_ACK


def _flag_bit(mask: int) -> str:
    """SQL predicate for "this frame carries every flag in ``mask``".

    ``tcp_flags_raw`` has been observed stored both as an integer and as its
    decimal text (``'18'``, ``'24'``); the explicit ``CAST`` yields the bitmask
    either way. The ``tcp_flags`` flag-string column is an independent signal for
    renderings the bitmask cannot express (for example ``0x0002``, which SQLite's
    ``CAST`` would read as 0).

    Wireshark's flag string uses ``F`` FIN, ``S`` SYN, ``R`` RST, ``A`` ACK along
    with ``P``/``U``/``E``/``C``, which never collide with those four, so
    requiring ``S`` *and* ``A`` together is exactly a SYN/ACK test.
    """
    bitmask = f"(CAST(p.tcp_flags_raw AS INTEGER) & {mask}) = {mask}"
    letters = [
        letter
        for bit, letter in ((TCP_SYN, "S"), (TCP_ACK, "A"), (TCP_FIN, "F"), (TCP_RST, "R"))
        if mask & bit
    ]
    text_test = " AND ".join(
        f"INSTR(COALESCE(p.tcp_flags, ''), '{letter}') > 0" for letter in letters
    )
    return f"({bitmask} OR ({text_test}))"


# Pre-built predicates: SYN-only has 0x02 set and 0x10 clear, SYN/ACK has both.
_SYN_TEST = _flag_bit(TCP_SYN)
_SYNACK_TEST = _flag_bit(TCP_SYN_ACK)
_FIN_TEST = _flag_bit(TCP_FIN)
_RST_TEST = _flag_bit(TCP_RST)


CONVERSATION_COLUMNS: tuple[str, ...] = (
    "analysis_id",
    "conv_id",
    "transport",
    "stream_id",
    "endpoint_a",
    "endpoint_b",
    "ip_a",
    "port_a",
    "ip_b",
    "port_b",
    "packets_a_to_b",
    "bytes_a_to_b",
    "packets_b_to_a",
    "bytes_b_to_a",
    "packets_total",
    "bytes_total",
    "start_time",
    "end_time",
    "duration",
    "state",
    "protocols",
)

STREAM_COLUMNS: tuple[str, ...] = (
    "analysis_id",
    "stream_id",
    "transport",
    "client_ip",
    "client_port",
    "server_ip",
    "server_port",
    "payload_bytes_client",
    "payload_bytes_server",
    "packets",
    "start_time",
    "end_time",
)

CONVERSATION_INSERT = (
    f"INSERT OR REPLACE INTO conversations ({', '.join(CONVERSATION_COLUMNS)}) "
    f"VALUES ({', '.join('?' for _ in CONVERSATION_COLUMNS)})"
)
STREAM_INSERT = (
    f"INSERT OR REPLACE INTO streams ({', '.join(STREAM_COLUMNS)}) "
    f"VALUES ({', '.join('?' for _ in STREAM_COLUMNS)})"
)

# One row per observed directed 4-tuple. Two directions per endpoint pair, so the
# result set is at most twice the number of conversations. Flag tests come from
# both the bitmask column and the flag string column (see the module docstring).
_GROUP_SQL = f"""
SELECT
    p.transport                                    AS transport,
    p.src_ip                                       AS src_ip,
    p.src_port                                     AS src_port,
    p.dst_ip                                       AS dst_ip,
    p.dst_port                                     AS dst_port,
    COUNT(*)                                       AS packets,
    COALESCE(SUM(p.frame_len), 0)                  AS bytes,
    MIN(p.time_epoch)                              AS start_time,
    MAX(p.time_epoch)                              AS end_time,
    MIN(p.number)                                  AS first_number,
    MIN(CASE WHEN {_SYN_TEST} THEN p.number END)   AS first_syn_number,
    MAX(CASE WHEN {_SYN_TEST} THEN 1 ELSE 0 END)   AS syn_seen,
    MAX(CASE WHEN {_SYNACK_TEST} THEN 1 ELSE 0 END) AS synack_seen,
    MAX(CASE WHEN {_FIN_TEST} THEN 1 ELSE 0 END)   AS fin_seen,
    MAX(CASE WHEN {_RST_TEST} THEN 1 ELSE 0 END)   AS rst_seen,
    COUNT(DISTINCT CASE WHEN p.transport = 'tcp' THEN p.tcp_stream
                        ELSE p.udp_stream END)     AS stream_ids,
    MIN(CASE WHEN p.transport = 'tcp' THEN p.tcp_stream
             ELSE p.udp_stream END)                AS stream_min,
    SUM(CASE WHEN (CASE WHEN p.transport = 'tcp' THEN p.tcp_stream
                        ELSE p.udp_stream END) IS NULL THEN 1 ELSE 0 END) AS stream_nulls,
    MAX(CASE WHEN p.http_method IS NOT NULL OR p.http_status IS NOT NULL
              OR p.http_uri IS NOT NULL OR p.http_host IS NOT NULL
             THEN 1 ELSE 0 END)                    AS has_http,
    MAX(CASE WHEN p.dns_query IS NOT NULL THEN 1 ELSE 0 END)       AS has_dns,
    MAX(CASE WHEN p.tls_sni IS NOT NULL OR p.tls_version IS NOT NULL
             THEN 1 ELSE 0 END)                    AS has_tls,
    MAX(CASE WHEN INSTR(':' || COALESCE(p.protocols, '') || ':', ':http:') > 0
             THEN 1 ELSE 0 END)                    AS chain_http,
    MAX(CASE WHEN INSTR(':' || COALESCE(p.protocols, '') || ':', ':dns:') > 0
             THEN 1 ELSE 0 END)                    AS chain_dns,
    MAX(CASE WHEN INSTR(':' || COALESCE(p.protocols, '') || ':', ':tls:') > 0
             THEN 1 ELSE 0 END)                    AS chain_tls
FROM packets p
WHERE p.analysis_id = ?
  AND p.transport IN ('tcp', 'udp')
  AND p.src_ip IS NOT NULL
  AND p.dst_ip IS NOT NULL
  AND p.src_port IS NOT NULL
  AND p.dst_port IS NOT NULL
GROUP BY p.transport, p.src_ip, p.src_port, p.dst_ip, p.dst_port
ORDER BY MIN(p.time_epoch)
"""

# Payload bytes per stream and per sending endpoint. TCP uses ``tcp.len`` (the
# segment payload); UDP subtracts the 8 byte header from ``udp.length`` and is
# guarded against values that would go negative on malformed frames.
_PAYLOAD_SQL = """
SELECT
    g.transport              AS transport,
    g.stream_id              AS stream_id,
    g.src_ip                 AS src_ip,
    g.src_port               AS src_port,
    SUM(g.packets)           AS packets,
    SUM(g.payload)           AS payload_bytes,
    MIN(g.time_epoch)        AS start_time,
    MAX(g.time_epoch)        AS end_time
FROM (
    SELECT
        p.transport AS transport,
        CASE WHEN p.transport = 'tcp' THEN p.tcp_stream ELSE p.udp_stream END AS stream_id,
        p.src_ip AS src_ip,
        p.src_port AS src_port,
        COUNT(*) AS packets,
        SUM(
            CASE
                WHEN p.transport = 'tcp' THEN COALESCE(p.tcp_len, 0)
                WHEN p.udp_len IS NULL THEN 0
                WHEN p.udp_len > 8 THEN p.udp_len - 8
                ELSE 0
            END
        ) AS payload,
        MIN(p.time_epoch) AS time_epoch
    FROM packets p
    WHERE p.analysis_id = ?
      AND p.transport IN ('tcp', 'udp')
      AND p.src_ip IS NOT NULL
      AND p.src_port IS NOT NULL
    GROUP BY p.transport, stream_id, p.src_ip, p.src_port
) AS g
WHERE g.stream_id IS NOT NULL
GROUP BY g.transport, g.stream_id, g.src_ip, g.src_port
"""


# --------------------------------------------------------------------------
# accumulation helpers
# --------------------------------------------------------------------------

Endpoint = tuple[str, int]


def _endpoint(ip: object, port: object) -> Endpoint | None:
    """``(ip, port)`` for a packet row, or ``None`` when either is unusable."""
    if ip is None or port is None:
        return None
    text = str(ip)
    if not text:
        return None
    try:
        number = int(port)
    except (TypeError, ValueError):
        return None
    return (text, number)


def _as_float(value: object) -> float | None:
    if value is None:
        return None
    try:
        return float(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return None


def _as_int(value: object) -> int:
    try:
        return int(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return 0


@dataclass
class _Direction:
    """Totals for one direction (always keyed by the *sending* endpoint)."""

    packets: int = 0
    bytes: int = 0
    start_time: float | None = None
    end_time: float | None = None

    def add(self, packets: int, byte_count: int, start: float | None, end: float | None) -> None:
        self.packets += packets
        self.bytes += byte_count
        if start is not None:
            self.start_time = start if self.start_time is None else min(self.start_time, start)
        if end is not None:
            self.end_time = end if self.end_time is None else max(self.end_time, end)


@dataclass
class _Conversation:
    transport: str
    first: Endpoint
    second: Endpoint
    directions: dict[Endpoint, _Direction] = field(default_factory=dict)

    # TCP state inputs.
    syn_seen: bool = False
    synack_seen: bool = False
    fin_seen: bool = False
    rst_seen: bool = False
    first_syn_number: int | None = None
    syn_origin: Endpoint | None = None
    first_number: int | None = None
    first_origin: Endpoint | None = None

    # Stream identity.
    stream_id: int | None = None
    stream_mixed: bool = False

    # Observed application protocols.
    protocols: set[str] = field(default_factory=set)

    def direction(self, endpoint: Endpoint) -> _Direction:
        return self.directions.setdefault(endpoint, _Direction())

    def note_syn(self, number: int, origin: Endpoint) -> None:
        if self.first_syn_number is None or number < self.first_syn_number:
            self.first_syn_number = number
            self.syn_origin = origin

    def note_first(self, number: int, origin: Endpoint) -> None:
        if self.first_number is None or number < self.first_number:
            self.first_number = number
            self.first_origin = origin

    def note_stream(self, count: int | None, nulls: int | None, value: object) -> None:
        """Track whether every packet in this conversation shares one stream id."""
        if self.stream_mixed:
            return
        count = _as_int(count)
        nulls = _as_int(nulls)
        if count != 1 or nulls != 0 or value is None:
            self.stream_mixed = True
            return
        candidate = _as_int(value)
        if self.stream_id is None:
            self.stream_id = candidate
        elif self.stream_id != candidate:
            self.stream_mixed = True

    # -- derived values ----------------------------------------------------

    def initiator(self) -> Endpoint:
        """Contract §3: SYN sender (TCP) / first sender (UDP), else the smaller one."""
        if self.transport == "tcp" and self.syn_origin is not None:
            return self.syn_origin
        if self.transport == "udp" and self.first_origin is not None:
            return self.first_origin
        return self.first

    def counterpart(self, endpoint: Endpoint) -> Endpoint:
        return self.second if endpoint == self.first else self.first

    def effective_stream_id(self) -> int | None:
        return None if self.stream_mixed else self.stream_id

    def state(self) -> str:
        """Observed TCP state; UDP never claims a TCP state."""
        if self.transport != "tcp":
            return "unknown"
        if self.syn_seen and self.synack_seen:
            return "established"
        if self.rst_seen:
            return "reset"
        if self.syn_seen and not self.synack_seen:
            return "half_open"
        if self.fin_seen and not self.rst_seen:
            return "closed"
        return "unknown"

    def protocol_list(self) -> str:
        names = set(self.protocols)
        names.add(self.transport)
        return ",".join(sorted(names))

    def window(self) -> tuple[float | None, float | None]:
        starts = [d.start_time for d in self.directions.values() if d.start_time is not None]
        ends = [d.end_time for d in self.directions.values() if d.end_time is not None]
        return (min(starts) if starts else None, max(ends) if ends else None)


def _conversation_rows(ctx: JobContext, analysis_id: str) -> list[_Conversation]:
    """Group the indexed packets into canonical, direction-merged conversations."""
    conversations: dict[tuple[str, Endpoint, Endpoint], _Conversation] = {}
    seen = 0

    conn = db.connect()
    try:
        cursor = conn.execute(_GROUP_SQL, (analysis_id,))
        cursor.row_factory = None  # tuples are cheaper than Row objects here
        for row in cursor:
            seen += 1
            if seen % CANCEL_CHECK_EVERY == 0:
                ctx.check_cancelled()
                ctx.set_stage(f"Grouping conversations ({seen:,} directional groups)")

            transport = row[0]
            source = _endpoint(row[1], row[2])
            target = _endpoint(row[3], row[4])
            if transport not in {"tcp", "udp"} or source is None or target is None:
                continue
            if source == target:
                # A frame addressed to itself carries no usable direction.
                continue

            first, second = (source, target) if source <= target else (target, source)
            verdict = conversations.get((transport, first, second))
            if verdict is None:
                verdict = _Conversation(transport=transport, first=first, second=second)
                conversations[(transport, first, second)] = verdict

            direction = verdict.direction(source)
            direction.add(
                _as_int(row[5]),
                _as_int(row[6]),
                _as_float(row[7]),
                _as_float(row[8]),
            )

            first_number = row[9]
            if first_number is not None:
                verdict.note_first(_as_int(first_number), source)
            syn_number = row[10]
            if syn_number is not None:
                verdict.note_syn(_as_int(syn_number), source)

            if _as_int(row[11]):
                verdict.syn_seen = True
            if _as_int(row[12]):
                verdict.synack_seen = True
            if _as_int(row[13]):
                verdict.fin_seen = True
            if _as_int(row[14]):
                verdict.rst_seen = True

            verdict.note_stream(row[15], row[17], row[16])

            if _as_int(row[18]) or _as_int(row[21]):
                verdict.protocols.add("http")
            if _as_int(row[19]) or _as_int(row[22]):
                verdict.protocols.add("dns")
            if _as_int(row[20]) or _as_int(row[23]):
                verdict.protocols.add("tls")
    finally:
        conn.close()

    log.debug("grouped %s directional rows into %s conversations", seen, len(conversations))
    return list(conversations.values())


def _conversation_tuple(analysis_id: str, conversation: _Conversation) -> tuple:
    endpoint_a = conversation.initiator()
    endpoint_b = conversation.counterpart(endpoint_a)

    to_b = conversation.directions.get(endpoint_a, _Direction())
    to_a = conversation.directions.get(endpoint_b, _Direction())

    start_time, end_time = conversation.window()
    duration = (
        (end_time - start_time)
        if start_time is not None and end_time is not None
        else None
    )

    return (
        analysis_id,
        f"{conversation.transport}:{endpoint_a[0]}:{endpoint_a[1]}"
        f"-{endpoint_b[0]}:{endpoint_b[1]}",
        conversation.transport,
        conversation.effective_stream_id(),
        f"{endpoint_a[0]}:{endpoint_a[1]}",
        f"{endpoint_b[0]}:{endpoint_b[1]}",
        endpoint_a[0],
        endpoint_a[1],
        endpoint_b[0],
        endpoint_b[1],
        to_b.packets,
        to_b.bytes,
        to_a.packets,
        to_a.bytes,
        to_b.packets + to_a.packets,
        to_b.bytes + to_a.bytes,
        start_time,
        end_time,
        duration,
        conversation.state(),
        conversation.protocol_list(),
    )


def _stream_rows(
    ctx: JobContext,
    analysis_id: str,
    conversations: list[_Conversation],
) -> list[tuple]:
    """One row per ``(transport, stream_id)``, from the same conversation set."""
    owners: dict[tuple[str, int], _Conversation] = {}
    for conversation in conversations:
        stream_id = conversation.effective_stream_id()
        if stream_id is None:
            continue
        key = (conversation.transport, stream_id)
        if key in owners:
            log.debug(
                "stream %s/%s is claimed by more than one conversation",
                conversation.transport,
                stream_id,
            )
            continue
        owners[key] = conversation

    if not owners:
        return []

    accumulated: dict[tuple[str, int], dict] = {}
    conn = db.connect()
    try:
        cursor = conn.execute(_PAYLOAD_SQL, (analysis_id,))
        cursor.row_factory = None
        row_index = 0
        for row in cursor:
            row_index += 1
            if row_index % CANCEL_CHECK_EVERY == 0:
                ctx.check_cancelled()

            key = (row[0], _as_int(row[1]))
            conversation = owners.get(key)
            if conversation is None:
                continue
            sender = _endpoint(row[2], row[3])
            if sender is None:
                continue

            client = conversation.initiator()
            server = conversation.counterpart(client)
            if sender not in (client, server):
                # Should not happen: a stream's frames only carry its two ends.
                log.debug("stream %s/%s has an unexpected sender %s", row[0], row[1], sender)
                continue

            entry = accumulated.get(key)
            if entry is None:
                entry = {
                    "payload_client": 0,
                    "payload_server": 0,
                    "packets": 0,
                    "start_time": None,
                    "end_time": None,
                }
                accumulated[key] = entry

            payload = _as_int(row[5])
            if sender == client:
                entry["payload_client"] += payload
            else:
                entry["payload_server"] += payload

            entry["packets"] += _as_int(row[4])
            start = _as_float(row[6])
            end = _as_float(row[7])
            if start is not None:
                entry["start_time"] = (
                    start if entry["start_time"] is None else min(entry["start_time"], start)
                )
            if end is not None:
                entry["end_time"] = (
                    end if entry["end_time"] is None else max(entry["end_time"], end)
                )
    finally:
        conn.close()

    rows: list[tuple] = []
    for (transport, stream_id), conversation in sorted(
        owners.items(), key=lambda item: (item[0][0], item[0][1])
    ):
        entry = accumulated.get((transport, stream_id))
        if entry is None:
            entry = {
                "payload_client": 0,
                "payload_server": 0,
                "packets": 0,
                "start_time": None,
                "end_time": None,
            }
        client = conversation.initiator()
        server = conversation.counterpart(client)
        rows.append(
            (
                analysis_id,
                stream_id,
                transport,
                client[0],
                client[1],
                server[0],
                server[1],
                entry["payload_client"],
                entry["payload_server"],
                entry["packets"],
                entry["start_time"],
                entry["end_time"],
            )
        )
    return rows


def _flush(ctx: JobContext, conn, insert_sql: str, rows: list[tuple]) -> None:
    for index in range(0, len(rows), BATCH_SIZE):
        # One explicit transaction per batch keeps the WAL small and the analysis
        # cancellable between batches.
        conn.execute("BEGIN")
        conn.executemany(insert_sql, rows[index : index + BATCH_SIZE])
        conn.commit()
        ctx.check_cancelled()


def _persist(
    ctx: JobContext,
    analysis_id: str,
    conversation_rows: list[tuple],
    stream_rows: list[tuple],
) -> None:
    """Replace both tables for this analysis in batched transactions."""
    conn = db.connect()
    try:
        # Idempotence: a re-run starts from an empty slate for this analysis.
        conn.execute("BEGIN")
        conn.execute("DELETE FROM conversations WHERE analysis_id = ?", (analysis_id,))
        conn.execute("DELETE FROM streams WHERE analysis_id = ?", (analysis_id,))
        conn.commit()

        _flush(ctx, conn, CONVERSATION_INSERT, conversation_rows)
        _flush(ctx, conn, STREAM_INSERT, stream_rows)
    finally:
        conn.close()


def analyze(ctx: JobContext, analysis_id: str, capture_path: Path) -> dict:
    """Populate ``conversations`` and ``streams`` for one analysis.

    ``capture_path`` is not read here: every number comes from the packets that
    are already indexed for this analysis, which keeps the results consistent
    with the packet list and avoids a second dissection pass.
    """
    started = time.monotonic()
    ctx.set_stage("Grouping conversations")

    conversations = _conversation_rows(ctx, analysis_id)
    ctx.check_cancelled()

    conversation_rows = [_conversation_tuple(analysis_id, c) for c in conversations]
    stream_rows = _stream_rows(ctx, analysis_id, conversations)

    ctx.set_stage(f"Persisting {len(conversation_rows)} conversations")
    _persist(ctx, analysis_id, conversation_rows, stream_rows)

    elapsed = time.monotonic() - started
    states: dict[str, int] = {}
    for row in conversation_rows:
        states[row[19]] = states.get(row[19], 0) + 1

    counters = {
        "conversations": len(conversation_rows),
        "streams": len(stream_rows),
        "tcp_conversations": sum(1 for r in conversation_rows if r[2] == "tcp"),
        "udp_conversations": sum(1 for r in conversation_rows if r[2] == "udp"),
        "bytes_total": sum(r[15] for r in conversation_rows),
        "states": states,
        "seconds": round(elapsed, 2),
    }
    log.info(
        "conversations %s: %s conversations, %s streams in %.2fs",
        analysis_id,
        counters["conversations"],
        counters["streams"],
        elapsed,
    )
    return counters


__all__ = [
    "CONVERSATION_COLUMNS",
    "STREAM_COLUMNS",
    "analyze",
]
