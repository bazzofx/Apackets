"""Host inventory: one row per observed IP address.

Everything here is a real aggregate over the indexed ``packets`` rows — frame
counts, frame lengths, observed ports, MACs and display protocols — joined with
the DNS/TLS tables when those stages have run. Peer relationships come only from
observed ``conversations`` rows; nothing is inferred from name resolution,
subnet membership or any other guess.

Private-address classification is implemented locally with :mod:`ipaddress`
(RFC1918, RFC4193, loopback, link-local) so no external data is needed.
"""

from __future__ import annotations

import ipaddress
import json
import time
from pathlib import Path

from app.core.logging import get_logger
from app.db import database as db
from app.services.jobs import JobContext

log = get_logger("apackets.hosts")

BATCH_SIZE = 1000
CANCEL_CHECK_EVERY = 5000
MAX_PORTS = 15
MAX_PEERS = 25
MAX_NAMES = 100

# RFC1918 / loopback / link-local (IPv4) and RFC4193 / loopback / link-local (IPv6).
_IPV4_PRIVATE = (
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
)
_IPV6_PRIVATE = (
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fe80::/10"),
)

HOST_COLUMNS: tuple[str, ...] = (
    "analysis_id",
    "ip",
    "mac",
    "first_seen",
    "last_seen",
    "packets_sent",
    "packets_received",
    "bytes_sent",
    "bytes_received",
    "ports",
    "protocols",
    "dns_names",
    "tls_sni",
    "is_private",
    "ip_version",
    "peer_count",
    "peers",
)

HOST_INSERT = (
    f"INSERT OR REPLACE INTO hosts ({', '.join(HOST_COLUMNS)}) "
    f"VALUES ({', '.join('?' for _ in HOST_COLUMNS)})"
)

# --- packet-level aggregates (two rows per frame: sender and receiver) ------

_HOST_SQL = """
SELECT
    ip,
    SUM(sent)           AS packets_sent,
    SUM(received)       AS packets_received,
    SUM(bytes_sent)     AS bytes_sent,
    SUM(bytes_received) AS bytes_received,
    MIN(first_seen)     AS first_seen,
    MAX(last_seen)      AS last_seen
FROM (
    SELECT src_ip AS ip, 1 AS sent, 0 AS received,
           COALESCE(frame_len, 0) AS bytes_sent, 0 AS bytes_received,
           time_epoch AS first_seen, time_epoch AS last_seen
      FROM packets
     WHERE analysis_id = ? AND src_ip IS NOT NULL
    UNION ALL
    SELECT dst_ip, 0, 1, 0, COALESCE(frame_len, 0), time_epoch, time_epoch
      FROM packets
     WHERE analysis_id = ? AND dst_ip IS NOT NULL
)
GROUP BY ip
"""

_MAC_SQL = """
SELECT ip, mac, SUM(n) AS n, MAX(from_src) AS from_src
FROM (
    SELECT src_ip AS ip, eth_src AS mac, 1 AS from_src, COUNT(*) AS n
      FROM packets
     WHERE analysis_id = ? AND src_ip IS NOT NULL AND eth_src IS NOT NULL
     GROUP BY src_ip, eth_src
    UNION ALL
    SELECT dst_ip, eth_dst, 0, COUNT(*)
      FROM packets
     WHERE analysis_id = ? AND dst_ip IS NOT NULL AND eth_dst IS NOT NULL
     GROUP BY dst_ip, eth_dst
)
GROUP BY ip, mac
"""

_PROTOCOL_SQL = """
SELECT ip, protocol, SUM(n) AS n
FROM (
    SELECT src_ip AS ip, protocol, COUNT(*) AS n
      FROM packets
     WHERE analysis_id = ? AND src_ip IS NOT NULL AND protocol IS NOT NULL
     GROUP BY src_ip, protocol
    UNION ALL
    SELECT dst_ip, protocol, COUNT(*)
      FROM packets
     WHERE analysis_id = ? AND dst_ip IS NOT NULL AND protocol IS NOT NULL
     GROUP BY dst_ip, protocol
)
GROUP BY ip, protocol
"""

_PORT_SQL = """
SELECT ip, port, direction, SUM(n) AS n
FROM (
    SELECT src_ip AS ip, src_port AS port, 'src' AS direction, COUNT(*) AS n
      FROM packets
     WHERE analysis_id = ? AND src_ip IS NOT NULL AND src_port IS NOT NULL
     GROUP BY src_ip, src_port
    UNION ALL
    SELECT dst_ip, dst_port, 'dst', COUNT(*)
      FROM packets
     WHERE analysis_id = ? AND dst_ip IS NOT NULL AND dst_port IS NOT NULL
     GROUP BY dst_ip, dst_port
)
GROUP BY ip, port, direction
"""

# --- names -----------------------------------------------------------------

# Preferred source: the dns_queries table, which merges answers into queries.
_DNS_QUERY_SQL = """
SELECT client_ip AS ip, query_name AS name
  FROM dns_queries
 WHERE analysis_id = ? AND client_ip IS NOT NULL AND query_name IS NOT NULL
"""

_DNS_ANSWER_SQL = """
SELECT query_name AS name, answer_ips AS ips
  FROM dns_queries
 WHERE analysis_id = ? AND query_name IS NOT NULL AND answer_ips IS NOT NULL
"""

# Independent of stage ordering: the query packet itself carries the name.
_DNS_PACKET_SQL = """
SELECT src_ip AS ip, dns_query AS name
  FROM packets
 WHERE analysis_id = ? AND src_ip IS NOT NULL AND dns_query IS NOT NULL
"""

_TLS_SESSION_SQL = """
SELECT client_ip AS ip, sni AS name
  FROM tls_sessions
 WHERE analysis_id = ? AND client_ip IS NOT NULL AND sni IS NOT NULL
"""

_TLS_PACKET_SQL = """
SELECT src_ip AS ip, tls_sni AS name
  FROM packets
 WHERE analysis_id = ? AND src_ip IS NOT NULL AND tls_sni IS NOT NULL
"""

# --- topology --------------------------------------------------------------

_PEER_SQL = """
SELECT ip, peer, SUM(packets) AS packets
FROM (
    SELECT ip_a AS ip, ip_b AS peer, packets_total AS packets
      FROM conversations WHERE analysis_id = ?
    UNION ALL
    SELECT ip_b, ip_a, packets_total
      FROM conversations WHERE analysis_id = ?
)
GROUP BY ip, peer
"""


# --------------------------------------------------------------------------
# address classification
# --------------------------------------------------------------------------

def parse_address(value: object) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    """Best-effort address parse; ``None`` for anything that is not an address."""
    if value is None:
        return None
    try:
        return ipaddress.ip_address(str(value).strip())
    except ValueError:
        return None


def ip_version_of(value: object) -> int | None:
    address = parse_address(value)
    return None if address is None else address.version


def is_private_address(value: object) -> int | None:
    """``1`` for RFC1918/RFC4193/loopback/link-local, ``0`` otherwise, ``None`` unknown."""
    address = parse_address(value)
    if address is None:
        return None
    if address.version == 6 and address.ipv4_mapped is not None:
        address = address.ipv4_mapped
    networks = _IPV4_PRIVATE if address.version == 4 else _IPV6_PRIVATE
    return 1 if any(address in network for network in networks) else 0


# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------

def _as_int(value: object) -> int:
    try:
        return int(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return 0


def _as_float(value: object) -> float | None:
    if value is None:
        return None
    try:
        return float(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return None


def _text(value: object) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


class _Host:
    """Accumulator for one IP address."""

    __slots__ = (
        "ip",
        "mac_candidates",
        "first_seen",
        "last_seen",
        "packets_sent",
        "packets_received",
        "bytes_sent",
        "bytes_received",
        "ports",
        "protocols",
        "dns_names",
        "tls_sni",
        "peers",
    )

    def __init__(self, ip: str) -> None:
        self.ip = ip
        self.mac_candidates: dict[str, tuple[int, int]] = {}
        self.first_seen: float | None = None
        self.last_seen: float | None = None
        self.packets_sent = 0
        self.packets_received = 0
        self.bytes_sent = 0
        self.bytes_received = 0
        self.ports: dict[tuple[int, str], int] = {}
        self.protocols: dict[str, int] = {}
        self.dns_names: set[str] = set()
        self.tls_sni: set[str] = set()
        self.peers: dict[str, int] = {}

    def touch(self, first: float | None, last: float | None) -> None:
        if first is not None:
            self.first_seen = first if self.first_seen is None else min(self.first_seen, first)
        if last is not None:
            self.last_seen = last if self.last_seen is None else max(self.last_seen, last)

    def mac(self) -> str | None:
        if not self.mac_candidates:
            return None
        # Most frequent wins; an eth.src observation breaks a tie.
        return max(
            self.mac_candidates,
            key=lambda mac: (
                self.mac_candidates[mac][0],
                self.mac_candidates[mac][1],
                mac,
            ),
        )

    def port_list(self) -> list[dict]:
        ordered = sorted(
            self.ports.items(),
            key=lambda item: (-item[1], item[0][0], item[0][1]),
        )
        return [
            {"port": port, "count": count, "direction": direction}
            for (port, direction), count in ordered[:MAX_PORTS]
        ]

    def protocol_map(self) -> dict[str, int]:
        return dict(
            sorted(self.protocols.items(), key=lambda item: (-item[1], item[0]))
        )

    def peer_list(self) -> list[str]:
        return sorted(
            self.peers,
            key=lambda peer: (-self.peers[peer], peer),
        )[:MAX_PEERS]

    def row(self, analysis_id: str) -> tuple:
        return (
            analysis_id,
            self.ip,
            self.mac(),
            self.first_seen,
            self.last_seen,
            self.packets_sent,
            self.packets_received,
            self.bytes_sent,
            self.bytes_received,
            json.dumps(self.port_list(), separators=(",", ":")),
            json.dumps(self.protocol_map(), separators=(",", ":")),
            json.dumps(sorted(self.dns_names)[:MAX_NAMES], separators=(",", ":")),
            json.dumps(sorted(self.tls_sni)[:MAX_NAMES], separators=(",", ":")),
            is_private_address(self.ip),
            ip_version_of(self.ip),
            len(self.peers),
            json.dumps(self.peer_list(), separators=(",", ":")),
        )


def _hosts(ctx: JobContext, analysis_id: str) -> dict[str, _Host]:
    hosts: dict[str, _Host] = {}

    def ensure(ip: object) -> _Host | None:
        text = _text(ip)
        if text is None:
            return None
        host = hosts.get(text)
        if host is None:
            host = _Host(text)
            hosts[text] = host
        return host

    conn = db.connect()
    try:
        cursor = conn.execute(_HOST_SQL, (analysis_id, analysis_id))
        cursor.row_factory = None
        counted = 0
        for row in cursor:
            counted += 1
            if counted % CANCEL_CHECK_EVERY == 0:
                ctx.check_cancelled()
                ctx.set_stage(f"Building host statistics ({counted:,} addresses)")
            host = ensure(row[0])
            if host is None:
                continue
            host.packets_sent += _as_int(row[1])
            host.packets_received += _as_int(row[2])
            host.bytes_sent += _as_int(row[3])
            host.bytes_received += _as_int(row[4])
            host.touch(_as_float(row[5]), _as_float(row[6]))

        ctx.check_cancelled()

        both = (analysis_id, analysis_id)
        single = (analysis_id,)

        for row in _rows(ctx, conn, _MAC_SQL, both):
            host = ensure(row[0])
            mac = _text(row[1])
            if host is None or mac is None:
                continue
            seen_as_src = _as_int(row[3])
            host.mac_candidates[mac] = (_as_int(row[2]), seen_as_src)

        for row in _rows(ctx, conn, _PROTOCOL_SQL, both):
            host = ensure(row[0])
            name = _text(row[1])
            if host is None or name is None:
                continue
            host.protocols[name] = host.protocols.get(name, 0) + _as_int(row[2])

        for row in _rows(ctx, conn, _PORT_SQL, both):
            host = ensure(row[0])
            if host is None:
                continue
            key = (_as_int(row[1]), str(row[2] or "dst"))
            host.ports[key] = host.ports.get(key, 0) + _as_int(row[3])

        ctx.check_cancelled()

        # --- DNS names: queried by this host, or answered with this host's IP.
        for row in _rows(ctx, conn, _DNS_QUERY_SQL, single):
            host = ensure(row[0])
            name = _text(row[1])
            if host is not None and name:
                host.dns_names.add(name)

        for row in _rows(ctx, conn, _DNS_PACKET_SQL, single):
            host = ensure(row[0])
            name = _text(row[1])
            if host is not None and name:
                host.dns_names.add(name)

        for row in _rows(ctx, conn, _DNS_ANSWER_SQL, single):
            name = _text(row[0])
            if name is None:
                continue
            for candidate in str(row[1]).split(","):
                holder = hosts.get(candidate.strip())
                if holder is not None:
                    holder.dns_names.add(name)

        # --- TLS SNI: client hellos sent by this host.
        for row in _rows(ctx, conn, _TLS_SESSION_SQL, single):
            host = ensure(row[0])
            name = _text(row[1])
            if host is not None and name:
                host.tls_sni.add(name)

        for row in _rows(ctx, conn, _TLS_PACKET_SQL, single):
            host = ensure(row[0])
            name = _text(row[1])
            if host is not None and name:
                host.tls_sni.add(name)

        ctx.check_cancelled()

        # --- peers, strictly from observed conversations.
        for row in _rows(ctx, conn, _PEER_SQL, both):
            host = ensure(row[0])
            peer = _text(row[1])
            if host is None or peer is None or peer == host.ip:
                continue
            host.peers[peer] = host.peers.get(peer, 0) + _as_int(row[2])
    finally:
        conn.close()

    return hosts


def _rows(ctx: JobContext, conn, sql: str, params: tuple):
    """Stream one aggregate query, staying cancellable between rows."""
    cursor = conn.execute(sql, params)
    cursor.row_factory = None
    for index, row in enumerate(cursor, start=1):
        if index % CANCEL_CHECK_EVERY == 0:
            ctx.check_cancelled()
        yield row


def analyze(ctx: JobContext, analysis_id: str, capture_path: Path) -> dict:
    """Populate ``hosts`` for one analysis. Returns simple counters."""
    started = time.monotonic()
    ctx.set_stage("Building host statistics")

    hosts = _hosts(ctx, analysis_id)
    rows = [host.row(analysis_id) for host in hosts.values()]

    ctx.check_cancelled()
    ctx.set_stage(f"Persisting {len(rows)} hosts")

    conn = db.connect()
    try:
        conn.execute("BEGIN")
        conn.execute("DELETE FROM hosts WHERE analysis_id = ?", (analysis_id,))
        conn.commit()

        for index in range(0, len(rows), BATCH_SIZE):
            conn.execute("BEGIN")
            conn.executemany(HOST_INSERT, rows[index : index + BATCH_SIZE])
            conn.commit()
            ctx.check_cancelled()
    finally:
        conn.close()

    elapsed = time.monotonic() - started
    private = sum(1 for row in rows if row[13] == 1)
    counters = {
        "hosts": len(rows),
        "private_hosts": private,
        "public_hosts": sum(1 for row in rows if row[13] == 0),
        "hosts_with_mac": sum(1 for row in rows if row[2]),
        "hosts_with_peers": sum(1 for row in rows if _as_int(row[15]) > 0),
        "bytes_total": sum(_as_int(row[7]) for row in rows),
        "seconds": round(elapsed, 2),
    }
    log.info(
        "hosts %s: %s hosts (%s private) in %.2fs",
        analysis_id,
        counters["hosts"],
        private,
        elapsed,
    )
    return counters


__all__ = [
    "HOST_COLUMNS",
    "analyze",
    "ip_version_of",
    "is_private_address",
    "parse_address",
]
