"""Packet indexing.

Streams every packet's summary fields out of TShark into the compact ``packets``
table. The full dissection is *not* stored: ``GET /packets/{n}`` re-runs TShark
against the retained capture, which keeps the database small and guarantees the
detail view matches the original bytes.
"""

from __future__ import annotations

import sqlite3
import time
from pathlib import Path

from app.core.logging import get_logger
from app.db import database as db
from app.services import tshark
from app.services.jobs import JobContext

log = get_logger("apackets.indexer")

# Column order of the INSERT below — keep the two in sync.
COLUMNS: tuple[str, ...] = (
    "analysis_id",
    "number",
    "time_epoch",
    "time_relative",
    "frame_len",
    "cap_len",
    "protocols",
    "protocol",
    "info",
    "eth_src",
    "eth_dst",
    "vlan_id",
    "ip_version",
    "src_ip",
    "dst_ip",
    "src_port",
    "dst_port",
    "transport",
    "tcp_flags",
    "tcp_flags_raw",
    "tcp_stream",
    "udp_stream",
    "ttl",
    "ip_id",
    "tcp_seq",
    "tcp_ack",
    "tcp_window",
    "tcp_len",
    "udp_len",
    "dns_query",
    "dns_qtype",
    "dns_rcode",
    "http_method",
    "http_host",
    "http_uri",
    "http_status",
    "tls_sni",
    "tls_version",
)

# TShark fields feeding the columns above, in the same order after the first two.
_TSHARK_FIELDS: tuple[str, ...] = (
    "frame.number",
    "frame.time_epoch",
    "frame.time_relative",
    "frame.len",
    "frame.cap_len",
    "frame.protocols",
    "_ws.col.Protocol",
    "_ws.col.Info",
    "eth.src",
    "eth.dst",
    "vlan.id",
    "ip.version",
    "ip.src",
    "ip.dst",
    "ipv6.src",
    "ipv6.dst",
    "tcp.srcport",
    "tcp.dstport",
    "udp.srcport",
    "udp.dstport",
    "tcp.flags.str",
    "tcp.flags",
    "tcp.stream",
    "udp.stream",
    "ip.ttl",
    "ipv6.hlim",
    "ip.id",
    "tcp.seq",
    "tcp.ack",
    "tcp.window_size_value",
    "tcp.len",
    "udp.length",
    "dns.qry.name",
    "dns.qry.type",
    "dns.flags.rcode",
    "http.request.method",
    "http.host",
    "http.request.uri",
    "http.response.code",
    "tls.handshake.extensions_server_name",
    "tls.handshake.version",
)

INSERT_SQL = (
    f"INSERT OR REPLACE INTO packets ({', '.join(COLUMNS)}) "
    f"VALUES ({', '.join('?' for _ in COLUMNS)})"
)

BATCH_SIZE = 1000
MAX_FIELD_LEN = 4000


def _int(value: str | None) -> int | None:
    """Parse an integer field.

    TShark renders some integer fields in hexadecimal in ``-T fields`` output —
    notably ``tcp.flags`` (``0x0012``) and ``ip.id`` (``0x1c46``) — so a plain
    ``int()`` would silently drop them. ``int(text, 0)`` auto-detects the base;
    the decimal fallback covers values with leading zeros, which ``base=0``
    rejects as malformed octal.
    """
    if not value:
        return None
    text = value.strip()
    if not text:
        return None
    try:
        return int(text, 0)
    except ValueError:
        pass
    try:
        return int(float(text))
    except (TypeError, ValueError):
        return None


def _float(value: str | None) -> float | None:
    if not value:
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _text(value: str | None) -> str | None:
    if not value:
        return None
    if len(value) > MAX_FIELD_LEN:
        return value[:MAX_FIELD_LEN]
    return value


def build_row(analysis_id: str, fields: list[str]) -> tuple | None:
    """Map one TShark field row onto the ``packets`` columns."""
    # Pad missing trailing fields: TShark omits empty trailing columns.
    if len(fields) < len(_TSHARK_FIELDS):
        fields = [*fields, *([""] * (len(_TSHARK_FIELDS) - len(fields)))]

    (
        number,
        time_epoch,
        time_relative,
        frame_len,
        cap_len,
        protocols,
        protocol,
        info,
        eth_src,
        eth_dst,
        vlan_id,
        ip_version,
        ip_src,
        ip_dst,
        ipv6_src,
        ipv6_dst,
        tcp_srcport,
        tcp_dstport,
        udp_srcport,
        udp_dstport,
        tcp_flags,
        tcp_flags_raw,
        tcp_stream,
        udp_stream,
        ttl,
        hop_limit,
        ip_id,
        tcp_seq,
        tcp_ack,
        tcp_window,
        tcp_len,
        udp_len,
        dns_query,
        dns_qtype,
        dns_rcode,
        http_method,
        http_host,
        http_uri,
        http_status,
        tls_sni,
        tls_version,
    ) = fields[: len(_TSHARK_FIELDS)]

    packet_number = _int(number)
    if packet_number is None:
        return None

    src_ip = ip_src or ipv6_src or None
    dst_ip = ip_dst or ipv6_dst or None

    src_port = _int(tcp_srcport) if tcp_srcport else _int(udp_srcport)
    dst_port = _int(tcp_dstport) if tcp_dstport else _int(udp_dstport)

    if tcp_srcport or tcp_dstport:
        transport = "tcp"
    elif udp_srcport or udp_dstport:
        transport = "udp"
    elif protocols and ":sctp" in f":{protocols}":
        transport = "sctp"
    else:
        transport = None

    version = _int(ip_version)
    if version is None and (ipv6_src or ipv6_dst):
        version = 6

    return (
        analysis_id,
        packet_number,
        _float(time_epoch),
        _float(time_relative),
        _int(frame_len),
        _int(cap_len),
        _text(protocols),
        _text(protocol),
        _text(info),
        _text(eth_src),
        _text(eth_dst),
        _int(vlan_id),
        version,
        _text(src_ip),
        _text(dst_ip),
        src_port,
        dst_port,
        transport,
        _text(tcp_flags),
        _int(tcp_flags_raw),
        _int(tcp_stream),
        _int(udp_stream),
        _int(ttl) if ttl else _int(hop_limit),
        _int(ip_id),
        _int(tcp_seq),
        _int(tcp_ack),
        _int(tcp_window),
        _int(tcp_len),
        _int(udp_len),
        _text(dns_query),
        _text(dns_qtype),
        _text(dns_rcode),
        _text(http_method),
        _text(http_host),
        _text(http_uri),
        _int(http_status),
        _text(tls_sni),
        _text(tls_version),
    )


def index_packets(
    ctx: JobContext,
    analysis_id: str,
    capture_path: Path,
    *,
    expected_packets: int | None = None,
    progress_base: float = 5.0,
    progress_span: float = 45.0,
) -> dict:
    """Extract and persist packet summaries. Returns aggregate counters."""
    started = time.monotonic()

    with db.get_conn() as conn:
        conn.execute("DELETE FROM packets WHERE analysis_id = ?", (analysis_id,))

    buffer: list[tuple] = []
    indexed = 0
    skipped = 0
    conn = db.connect()
    try:
        conn.execute("BEGIN")
        for fields in tshark.stream_fields(
            capture_path,
            _TSHARK_FIELDS,
            cancel_event=ctx.cancel_event,
        ):
            row = build_row(analysis_id, fields)
            if row is None:
                skipped += 1
                continue
            buffer.append(row)
            indexed += 1

            if len(buffer) >= BATCH_SIZE:
                conn.executemany(INSERT_SQL, buffer)
                buffer.clear()
                conn.commit()
                conn.execute("BEGIN")

            if indexed % 5000 == 0:
                ctx.check_cancelled()
                if expected_packets:
                    done = min(indexed / expected_packets, 1.0)
                    ctx.set_stage(
                        f"Indexing packets ({indexed:,} of ~{expected_packets:,})",
                        progress_base + progress_span * done,
                    )
                else:
                    ctx.set_stage(f"Indexing packets ({indexed:,})", progress_base)

        if buffer:
            conn.executemany(INSERT_SQL, buffer)
            buffer.clear()
        conn.commit()
    finally:
        conn.close()

    aggregates = _aggregate(analysis_id)
    elapsed = time.monotonic() - started
    log.info(
        "indexed %s packets (%s skipped) in %.1fs for %s",
        indexed,
        skipped,
        elapsed,
        analysis_id,
    )
    return {
        "packets_indexed": indexed,
        "packets_skipped": skipped,
        "seconds": round(elapsed, 2),
        **aggregates,
    }


def _aggregate(analysis_id: str) -> dict:
    row = db.query_one(
        """
        SELECT
            COUNT(*)                          AS packets,
            COALESCE(SUM(frame_len), 0)       AS bytes_total,
            MIN(time_epoch)                   AS start_time,
            MAX(time_epoch)                   AS end_time,
            COUNT(DISTINCT src_ip)            AS src_ips,
            COUNT(DISTINCT dst_ip)            AS dst_ips,
            SUM(CASE WHEN transport = 'tcp' THEN 1 ELSE 0 END) AS tcp_packets,
            SUM(CASE WHEN transport = 'udp' THEN 1 ELSE 0 END) AS udp_packets,
            SUM(CASE WHEN dns_query IS NOT NULL THEN 1 ELSE 0 END) AS dns_packets,
            SUM(CASE WHEN http_method IS NOT NULL OR http_status IS NOT NULL THEN 1 ELSE 0 END) AS http_packets,
            SUM(CASE WHEN tls_sni IS NOT NULL OR tls_version IS NOT NULL THEN 1 ELSE 0 END) AS tls_packets
        FROM packets WHERE analysis_id = ?
        """,
        (analysis_id,),
    )
    if row is None:
        return {}
    data = dict(row)
    if data.get("start_time") is not None and data.get("end_time") is not None:
        data["duration"] = float(data["end_time"]) - float(data["start_time"])
    else:
        data["duration"] = None
    return data


def count_packets(analysis_id: str) -> int:
    row = db.query_one(
        "SELECT COUNT(*) AS n FROM packets WHERE analysis_id = ?", (analysis_id,)
    )
    return int(row["n"]) if row else 0


def insert_rows(conn: sqlite3.Connection, rows: list[tuple]) -> None:
    """Helper for tests and sibling services."""
    if rows:
        conn.executemany(INSERT_SQL, rows)


__all__ = [
    "COLUMNS",
    "build_row",
    "count_packets",
    "index_packets",
    "_TSHARK_FIELDS",
]
