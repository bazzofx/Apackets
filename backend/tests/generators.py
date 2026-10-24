"""Deterministic PCAP capture generators for the ShadowPackets test suite.

Every builder in this module writes a real, TShark-readable capture file and
returns its :class:`pathlib.Path`. The library is **self-contained, offline and
reproducible**:

* no network access is ever performed (packets are only *built*, never sent),
* no wall-clock time is ever used — every packet gets an explicit ``time=`` from
  a deterministic clock, so calling a builder twice produces byte-identical
  files (asserted in the test suite),
* every address, port, sequence number and DNS transaction id is a fixed
  constant taken from the table below.

Fixed addresses and MACs
------------------------

=========================  ====================  =====================  ====
role                       IPv4                  IPv6                   MAC
=========================  ====================  =====================  ====
client / workstation       ``10.0.0.10``         ``2001:db8::10``       ``02:00:00:00:00:0a``
server / web host          ``10.0.0.20``         ``2001:db8::20``       ``02:00:00:00:00:14``
second host (udp peer)     ``10.0.0.30``         ``2001:db8::30``       ``02:00:00:00:00:1e``
gateway / router            ``10.0.0.1``         ``2001:db8::1``        ``02:00:00:00:00:01``
DNS resolver (public)       ``8.8.8.8``          ``2001:4860:4860::8888``  ``02:00:00:00:00:08``
scanner / hostile source   ``10.0.0.66``         ``2001:db8::66``       ``02:00:00:00:00:42``
DNS burst client           ``10.0.0.77``         —                      ``02:00:00:00:00:4d``
external web server        ``93.184.216.34``     —                      ``02:00:00:00:00:22``
=========================  ====================  =====================  ====

The MAC addresses are locally administered (``02:`` prefix) and deliberately
synthetic — they never collide with real hardware.

Time base
---------
``BASE_EPOCH = 1700000000.0`` (2023-11-14T22:13:20Z). Each builder uses a
private :class:`_Clock` that hands out ``base + n * step`` so packet order and
inter-packet spacing are fixed. :func:`combined_capture` offsets whole sections
by fixed amounts and writes the merged list sorted by time.

Expected values
---------------
:func:`expected` returns the documented, non-obvious expectations for a capture
(for example the exact reassembled bytes of :func:`retransmission_capture` and
the SHA-256 of the object produced by :func:`http_object_capture`) so tests do
not have to duplicate those constants.

Environment
-----------
Scapy needs a writable cache directory. This module sets ``XDG_CACHE_HOME`` to
``<repo>/.cache`` (creating it) *before* importing scapy, so importers — and
``conftest.py`` — do not need the caller to export anything.
"""

from __future__ import annotations

import hashlib
import logging
import os
import random
import socket
import struct
import tempfile
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------------
# Cache bootstrap. MUST run before scapy is imported: scapy refuses to start if
# it cannot create its cache directory (it writes it on import).
# ---------------------------------------------------------------------------
REPO_ROOT = Path(__file__).resolve().parents[2]
_CACHE_DIR = REPO_ROOT / ".cache"
try:
    _CACHE_DIR.mkdir(parents=True, exist_ok=True)
except OSError:  # pragma: no cover - read-only checkout
    _CACHE_DIR = Path(tempfile.gettempdir()) / "shadowpackets-cache"
    _CACHE_DIR.mkdir(parents=True, exist_ok=True)
os.environ.setdefault("XDG_CACHE_HOME", str(_CACHE_DIR))

from scapy.config import conf  # noqa: E402
from scapy.layers.dns import DNS, DNSQR, DNSRR  # noqa: E402
from scapy.layers.inet import ICMP, IP, TCP, UDP  # noqa: E402
from scapy.layers.inet6 import (  # noqa: E402
    ICMPv6EchoReply,
    ICMPv6EchoRequest,
    IPv6,
)
from scapy.layers.l2 import Ether  # noqa: E402
from scapy.packet import Packet, Raw  # noqa: E402

conf.verb = 0
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

__all__ = [
    "ALL_BUILDERS",
    "BASE_EPOCH",
    "PDF_SHA256",
    "TMP_ROOT",
    "build_all",
    "combined_capture",
    "der_bit_string",
    "der_explicit",
    "der_integer",
    "der_null",
    "der_octet_string",
    "der_oid",
    "der_printable_string",
    "der_sequence",
    "der_set",
    "der_utc_time",
    "der_utf8_string",
    "dns_capture",
    "empty_capture",
    "expected",
    "failed_connections_capture",
    "http_capture",
    "http_object_capture",
    "ipv6_capture",
    "large_capture",
    "malformed_capture",
    "pcap_bytes",
    "retransmission_capture",
    "syn_scan_capture",
    "tls_alert",
    "tls_capture",
    "tls_certificate",
    "tls_client_hello",
    "tls_server_hello",
    "tls_server_hello_done",
    "truncated_capture",
    "udp_capture",
    "write_pcap",
    "x509_self_signed_der",
]

# ---------------------------------------------------------------------------
# constants
# ---------------------------------------------------------------------------

BASE_EPOCH: float = 1_700_000_000.0  # 2023-11-14T22:13:20Z, fixed forever
TMP_ROOT: Path = Path(tempfile.gettempdir()) / "shadowpackets-captures"

CLIENT_IP = "10.0.0.10"
CLIENT_MAC = "02:00:00:00:00:0a"
SERVER_IP = "10.0.0.20"
SERVER_MAC = "02:00:00:00:00:14"
HOST_B_IP = "10.0.0.30"
HOST_B_MAC = "02:00:00:00:00:1e"
GATEWAY_IP = "10.0.0.1"
GATEWAY_MAC = "02:00:00:00:00:01"
DNS_IP = "8.8.8.8"
DNS_MAC = "02:00:00:00:00:08"
SCANNER_IP = "10.0.0.66"
SCANNER_MAC = "02:00:00:00:00:42"
# ARP host discovery. A local `nmap -sn` sweep never opens a port: it asks the
# link who holds each address, so the probed address lives in the ARP payload
# and in TShark's summary line, never in `ip.dst`.
BROADCAST_MAC = "ff:ff:ff:ff:ff:ff"
ARP_ETHERNET_TYPE = 0x0806
ARP_REQUEST = 1
ARP_REPLY = 2
ARP_SWEEP_TARGETS = tuple(f"10.0.0.{n}" for n in range(100, 140))
ARP_SWEEP_LIVE = ("10.0.0.100", "10.0.0.101", "10.0.0.102")
BURST_IP = "10.0.0.77"
BURST_MAC = "02:00:00:00:00:4d"
EXTERNAL_IP = "93.184.216.34"
EXTERNAL_MAC = "02:00:00:00:00:22"

CLIENT6 = "2001:db8::10"
CLIENT6_MAC = "02:00:00:00:00:0a"
SERVER6 = "2001:db8::20"
SERVER6_MAC = "02:00:00:00:00:14"
HOST_B6 = "2001:db8::30"
HOST_B6_MAC = "02:00:00:00:00:1e"
GATEWAY6 = "2001:db8::1"
GATEWAY6_MAC = "02:00:00:00:00:01"
DNS6 = "2001:4860:4860::8888"
DNS6_MAC = "02:00:00:00:00:08"
SCANNER6 = "2001:db8::66"
SCANNER6_MAC = "02:00:00:00:00:42"

DNS_PORT = 53
HTTP_PORT = 80
HTTPS_PORT = 443

_PCAP_MAGIC = 0xA1B2C3D4
_PCAP_VERSION = (2, 4)
_PCAP_SNAPLEN = 65535
_DLT_EN10MB = 1

_PCAP_GLOBAL_HEADER = struct.pack(
    "<IHHiIII", _PCAP_MAGIC, _PCAP_VERSION[0], _PCAP_VERSION[1], 0, 0, _PCAP_SNAPLEN, _DLT_EN10MB
)


# ---------------------------------------------------------------------------
# pcap writing
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Frame:
    """An already-serialised Ethernet frame plus its explicit timestamp.

    Recognised by :func:`write_pcap` in place of a scapy packet. The bulk
    builder (:func:`large_capture`) uses it because scapy's build/serialise
    round trip costs ~1 ms per packet, which would make a 20000-packet capture
    take 20 seconds instead of ~1. The bytes produced by
    :func:`_raw_tcp_frame`/:func:`_raw_udp_frame` are validated against scapy's
    own output for identical field values.
    """

    data: bytes
    time: float


def pcap_bytes(packets: Iterable[Frame | Packet]) -> bytes:
    """Serialise ``packets`` into a classic libpcap (little-endian) file image.

    Each item is either a ``scapy`` packet or a pre-serialised :class:`Frame`,
    and either way it must carry an explicit ``.time`` attribute; a packet
    without one is a programming error in this module, because falling back to
    the wall clock would make the output non-reproducible.

    The image is assembled in memory and returned as ``bytes`` so callers can
    post-process it (:func:`truncated_capture`, :func:`malformed_capture`).
    """
    blob = bytearray(_PCAP_GLOBAL_HEADER)
    for item in packets:
        if isinstance(item, Frame):
            raw = item.data
            stamp: float | None = item.time
        elif isinstance(item, Packet):
            raw = bytes(item)
            stamp = getattr(item, "time", None)
        else:  # pragma: no cover - defensive
            raise TypeError(f"cannot write {type(item).__name__} into a pcap file")
        if stamp is None:
            raise ValueError(
                "packet has no explicit timestamp; every generated packet must "
                "carry a fixed .time attribute"
            )
        seconds = int(stamp)
        micros = int(round((float(stamp) - seconds) * 1_000_000))
        if micros >= 1_000_000:
            seconds += 1
            micros -= 1_000_000
        blob += struct.pack("<IIII", seconds, micros, len(raw), len(raw))
        blob += raw
    return bytes(blob)


def write_pcap(path: Path, packets: Iterable[Frame | Packet]) -> Path:
    """Write ``packets`` to ``path`` as a classic pcap file and return ``path``.

    Byte-for-byte deterministic: identity of the output depends only on the
    packet list, never on the clock, the environment or the machine.
    """
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(pcap_bytes(packets))
    return path


def _output_path(dest: Path | None, name: str) -> Path:
    """``<dest or TMP_ROOT>/<name>.pcap``, with the directory created."""
    root = Path(dest) if dest is not None else TMP_ROOT
    root.mkdir(parents=True, exist_ok=True)
    return root / f"{name}.pcap"


class _Clock:
    """Deterministic timestamp/ip-id source shared by all packets of a builder."""

    def __init__(self, base: float = BASE_EPOCH, step: float = 0.002) -> None:
        self.base = float(base)
        self.step = float(step)
        self._n = 0
        self._ip_id = 0x1000

    def tick(self) -> float:
        """Next timestamp: ``base + n * step`` (strictly increasing)."""
        stamp = self.base + self._n * self.step
        self._n += 1
        return stamp

    def ip_id(self) -> int:
        """Next IPv4 identification value (fixed sequence, never random)."""
        self._ip_id = (self._ip_id + 1) & 0xFFFF or 1
        return self._ip_id


@dataclass(frozen=True)
class Peer:
    """A fixed MAC/IP/port triple."""

    ip: str
    mac: str
    port: int = 0


CLIENT = Peer(CLIENT_IP, CLIENT_MAC)
SERVER = Peer(SERVER_IP, SERVER_MAC)
HOST_B = Peer(HOST_B_IP, HOST_B_MAC)
SCANNER = Peer(SCANNER_IP, SCANNER_MAC)
EXTERNAL = Peer(EXTERNAL_IP, EXTERNAL_MAC)
DNS_SERVER = Peer(DNS_IP, DNS_MAC, DNS_PORT)
CLIENT6_PEER = Peer(CLIENT6, CLIENT6_MAC)
SERVER6_PEER = Peer(SERVER6, SERVER6_MAC)
HOST_B6_PEER = Peer(HOST_B6, HOST_B6_MAC)
SCANNER6_PEER = Peer(SCANNER6, SCANNER6_MAC)
DNS6_SERVER = Peer(DNS6, DNS6_MAC, DNS_PORT)


# ---------------------------------------------------------------------------
# layer helpers
# ---------------------------------------------------------------------------

def _net(
    src: Peer,
    dst: Peer,
    payload: Packet,
    clock: _Clock,
    *,
    ipv6: bool = False,
    ttl: int = 64,
    ip_id: int | None = None,
) -> Packet:
    """``Ether/IP|<IPv6>/payload`` with a fixed timestamp and IP id."""
    if ipv6:
        network: Packet = IPv6(src=src.ip, dst=dst.ip, hlim=ttl, tc=0, fl=0)
    else:
        network = IP(
            src=src.ip,
            dst=dst.ip,
            ttl=ttl,
            id=clock.ip_id() if ip_id is None else ip_id,
            flags="DF",
            frag=0,
        )
    packet = Ether(src=src.mac, dst=dst.mac) / network / payload
    packet.time = clock.tick()
    return packet


def _udp_frame(
    src: Peer,
    sport: int,
    dst: Peer,
    dport: int,
    payload: bytes,
    clock: _Clock,
    *,
    ipv6: bool = False,
    ttl: int = 64,
) -> Packet:
    return _net(
        src,
        dst,
        UDP(sport=sport, dport=dport) / Raw(load=payload),
        clock,
        ipv6=ipv6,
        ttl=ttl,
    )


def _icmp_frame(
    src: Peer,
    dst: Peer,
    *,
    echo_reply: bool,
    ident: int,
    seq: int,
    clock: _Clock,
) -> Packet:
    icmp = ICMP(type=0 if echo_reply else 8, id=ident, seq=seq)
    return _net(src, dst, icmp / Raw(load=b"SHADOWPACKETS-ICMP-PAYLOAD-0123456"), clock)


def _icmpv6_frame(
    src: Peer,
    dst: Peer,
    *,
    echo_reply: bool,
    ident: int,
    seq: int,
    clock: _Clock,
) -> Packet:
    icmp6: Packet = (
        ICMPv6EchoReply(id=ident, seq=seq) if echo_reply else ICMPv6EchoRequest(id=ident, seq=seq)
    )
    return _net(src, dst, icmp6 / Raw(load=b"SHADOWPACKETS-ICMPV6-PAYLOAD-0123"), clock, ipv6=True)


def _fill(size: int, tag: bytes) -> bytes:
    """Deterministic pseudo-random byte filler (SHA-256 chained, no RNG state)."""
    out = bytearray()
    counter = 0
    while len(out) < size:
        out += hashlib.sha256(tag + counter.to_bytes(4, "big")).digest()
        counter += 1
    return bytes(out[:size])


# ---------------------------------------------------------------------------
# pre-serialised frame encoders (fast path for the large capture)
# ---------------------------------------------------------------------------
# These emit exactly the bytes scapy emits for the same field values (asserted
# against a scapy-built packet in the test suite) without scapy's per-packet
# build/copy overhead, which would make a 20000-packet capture take ~20 s.

_TCP_FIN = 0x01
_TCP_SYN = 0x02
_TCP_RST = 0x04
_TCP_PSH = 0x08
_TCP_ACK = 0x10
_IPPROTO_TCP = 6
_IPPROTO_UDP = 17


def _mac_bytes(mac: str) -> bytes:
    """``"02:00:00:00:00:0a"`` -> 6 raw bytes."""
    return bytes.fromhex(mac.replace(":", "").replace("-", ""))


def _checksum16(data: bytes) -> int:
    """Internet checksum (RFC 1071) over ``data``."""
    if len(data) % 2:
        data += b"\x00"
    total = sum(struct.unpack(f">{len(data) // 2}H", data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def _ether_ipv4(
    src: Peer,
    dst: Peer,
    protocol: int,
    payload: bytes,
    *,
    ip_id: int,
    ttl: int = 64,
) -> bytes:
    """Ethernet II + IPv4 (20-byte header, DF set) + ``payload``."""
    header = struct.pack(
        ">BBHHHBBH4s4s",
        0x45,
        0x00,
        20 + len(payload),
        ip_id & 0xFFFF,
        0x4000,  # Don't Fragment
        ttl,
        protocol,
        0,
        socket.inet_aton(src.ip),
        socket.inet_aton(dst.ip),
    )
    header = header[:10] + struct.pack(">H", _checksum16(header)) + header[12:]
    return (
        struct.pack(">6s6sH", _mac_bytes(dst.mac), _mac_bytes(src.mac), 0x0800) + header + payload
    )


def _tcp_segment(
    src: Peer,
    dst: Peer,
    sport: int,
    dport: int,
    seq: int,
    ack: int,
    flags: int,
    payload: bytes,
    *,
    window: int = 64240,
) -> bytes:
    """A 20-byte-header TCP segment with a correct checksum."""
    header = struct.pack(
        ">HHIIHHHH",
        sport,
        dport,
        seq & 0xFFFFFFFF,
        ack & 0xFFFFFFFF,
        (5 << 12) | flags,
        window,
        0,
        0,
    )
    pseudo = (
        socket.inet_aton(src.ip)
        + socket.inet_aton(dst.ip)
        + struct.pack(">BBH", 0, _IPPROTO_TCP, len(header) + len(payload))
    )
    header = header[:16] + struct.pack(">H", _checksum16(pseudo + header + payload)) + header[18:]
    return header + payload


def _udp_datagram(
    src: Peer,
    dst: Peer,
    sport: int,
    dport: int,
    payload: bytes,
) -> bytes:
    """A UDP datagram with a correct checksum (``0xFFFF`` when it computes to 0)."""
    length = 8 + len(payload)
    header = struct.pack(">HHHH", sport, dport, length, 0)
    pseudo = (
        socket.inet_aton(src.ip)
        + socket.inet_aton(dst.ip)
        + struct.pack(">BBH", 0, _IPPROTO_UDP, length)
    )
    checksum = _checksum16(pseudo + header + payload) or 0xFFFF
    return header[:6] + struct.pack(">H", checksum) + payload


def _raw_tcp_frame(
    src: Peer,
    sport: int,
    dst: Peer,
    dport: int,
    seq: int,
    ack: int,
    flags: int,
    payload: bytes,
    stamp: float,
    *,
    ip_id: int,
    ttl: int = 64,
) -> Frame:
    """One Ethernet/IPv4/TCP frame as a pre-serialised :class:`Frame`."""
    segment = _tcp_segment(src, dst, sport, dport, seq, ack, flags, payload)
    return Frame(_ether_ipv4(src, dst, _IPPROTO_TCP, segment, ip_id=ip_id, ttl=ttl), stamp)


def _raw_udp_frame(
    src: Peer,
    sport: int,
    dst: Peer,
    dport: int,
    payload: bytes,
    stamp: float,
    *,
    ip_id: int,
    ttl: int = 64,
) -> Frame:
    """One Ethernet/IPv4/UDP frame as a pre-serialised :class:`Frame`."""
    datagram = _udp_datagram(src, dst, sport, dport, payload)
    return Frame(_ether_ipv4(src, dst, _IPPROTO_UDP, datagram, ip_id=ip_id, ttl=ttl), stamp)


# ---------------------------------------------------------------------------
# TCP conversation helper
# ---------------------------------------------------------------------------

class TcpFlow:
    """A deterministic TCP conversation with correct sequence/ack bookkeeping.

    The helper exists so builders never hand-maintain sequence numbers: payload
    length is added to the sender's ``next`` sequence, and every packet's ACK
    field is the peer's ``next`` sequence, exactly as a real stack behaves.
    Packets are appended to :attr:`packets` in emission order.
    """

    def __init__(
        self,
        client: tuple[str, str, int],
        server: tuple[str, str, int],
        clock: _Clock,
        *,
        isn_client: int = 0x1A2B3C4D,
        isn_server: int = 0x5E6F7A8B,
        window: int = 64240,
        ipv6: bool = False,
        ttl: int = 64,
        ip_id: int = 0x4000,
    ) -> None:
        self.c_ip, self.c_mac, self.c_port = client
        self.s_ip, self.s_mac, self.s_port = server
        self.clock = clock
        self.window = window
        self.ipv6 = ipv6
        self.ttl = ttl
        self._ip_id = ip_id
        self.isn_client = isn_client
        self.isn_server = isn_server
        self.next_cseq = isn_client + 1
        self.next_sseq = isn_server + 1
        self.packets: list[Packet] = []

    # -- internals ---------------------------------------------------------
    def _ip_id_next(self) -> int:
        self._ip_id = (self._ip_id + 1) & 0xFFFF or 1
        return self._ip_id

    def _emit(
        self,
        from_client: bool,
        flags: str,
        payload: bytes = b"",
        *,
        seq: int | None = None,
        ack: int | None = None,
        window: int | None = None,
        options: Sequence[tuple[str, Any]] | None = None,
        ttl: int | None = None,
    ) -> Packet:
        if from_client:
            src_ip, dst_ip = self.c_ip, self.s_ip
            src_mac, dst_mac = self.c_mac, self.s_mac
            sport, dport = self.c_port, self.s_port
            seq = self.next_cseq if seq is None else seq
            ack = self.next_sseq if ack is None else ack
        else:
            src_ip, dst_ip = self.s_ip, self.c_ip
            src_mac, dst_mac = self.s_mac, self.c_mac
            sport, dport = self.s_port, self.c_port
            seq = self.next_sseq if seq is None else seq
            ack = self.next_cseq if ack is None else ack

        if self.ipv6:
            network: Packet = IPv6(src=src_ip, dst=dst_ip, hlim=self.ttl if ttl is None else ttl)
        else:
            network = IP(
                src=src_ip,
                dst=dst_ip,
                ttl=self.ttl if ttl is None else ttl,
                id=self._ip_id_next(),
                flags="DF",
                frag=0,
            )

        tcp = TCP(
            sport=sport,
            dport=dport,
            seq=seq,
            ack=ack,
            flags=flags,
            window=self.window if window is None else window,
            options=list(options) if options else [],
        )
        layer: Packet = tcp / Raw(load=payload) if payload else tcp
        packet = Ether(src=src_mac, dst=dst_mac) / network / layer
        packet.time = self.clock.tick()
        self.packets.append(packet)
        return packet

    # -- public API --------------------------------------------------------
    def syn(self) -> Packet:
        """Client SYN (with the usual MSS/SAckOK/WScale/NOP option block)."""
        options: list[tuple[str, Any]] = [("MSS", 1460), ("SAckOK", b""), ("WScale", 7), ("NOP", None)]
        return self._emit(True, "S", seq=self.isn_client, ack=0, options=options)

    def syn_ack(self) -> Packet:
        """Server SYN/ACK, acknowledging the client SYN."""
        options: list[tuple[str, Any]] = [("MSS", 1460), ("SAckOK", b""), ("WScale", 7), ("NOP", None)]
        return self._emit(False, "SA", seq=self.isn_server, options=options)

    def ack(self, from_client: bool = True, *, ack_value: int | None = None) -> Packet:
        """Bare ACK with no payload (``ack_value`` forces a stale/duplicate ACK)."""
        return self._emit(from_client, "A", ack=ack_value)

    def syn_retransmit(self) -> Packet:
        """A byte-identical retransmission of the client SYN (no reply expected)."""
        options: list[tuple[str, Any]] = [("MSS", 1460), ("SAckOK", b"")]
        return self._emit(True, "S", seq=self.isn_client, ack=0, options=options)

    def handshake(self) -> list[Packet]:
        """SYN, SYN/ACK, ACK — the completed three-way handshake."""
        return [self.syn(), self.syn_ack(), self.ack(True)]

    def data(
        self,
        from_client: bool,
        payload: bytes,
        *,
        seq: int | None = None,
        flags: str = "PA",
        ack: int | None = None,
        window: int | None = None,
    ) -> Packet:
        """Data segment; advances the sender's sequence when ``seq`` is implied.

        Passing an explicit ``seq`` (as the retransmission/out-of-order builder
        does) leaves the bookkeeping untouched, which is how a duplicate
        segment is expressed.
        """
        packet = self._emit(from_client, flags, payload, seq=seq, ack=ack, window=window)
        if seq is None:
            if from_client:
                self.next_cseq += len(payload)
            else:
                self.next_sseq += len(payload)
        return packet

    def fin(self, from_client: bool = True) -> Packet:
        """FIN/ACK; consumes one sequence number like the real thing."""
        packet = self._emit(from_client, "FA")
        if from_client:
            self.next_cseq += 1
        else:
            self.next_sseq += 1
        return packet

    def rst(self, from_client: bool = True) -> Packet:
        """RST/ACK."""
        return self._emit(from_client, "RA")

    def close(self) -> list[Packet]:
        """Client FIN → server ACK → server FIN → client ACK."""
        return [self.fin(True), self.ack(False), self.fin(False), self.ack(True)]

    def request_response(self, request: bytes, response: bytes) -> list[Packet]:
        """One request/response pair, returned so callers can collect it."""
        return [self.data(True, request), self.data(False, response)]


# ---------------------------------------------------------------------------
# HTTP helpers
# ---------------------------------------------------------------------------

_CRLF = b"\r\n"

_UA_LONG = (
    "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/118.0 "
    "ShadowPackets-Synthetic-Agent/1.0 (unusual; long; +http://agent.invalid/notes) "
    "build=20231114-extremely-long-user-agent-value-for-parser-tests"
)


def _arp_frame(
    src_mac: str,
    dst_mac: str,
    sender_ip: str,
    target_ip: str,
    *,
    reply: bool,
    stamp: float,
) -> Frame:
    """One Ethernet II + ARP frame as a pre-serialised :class:`Frame`.

    ARP carries no IP layer, which is exactly why a local sweep is invisible to
    anything that reads IP addresses: the probed address exists only inside the ARP
    payload, and only in TShark's summary line once indexed.
    """
    operation = ARP_REPLY if reply else ARP_REQUEST
    target_hw = _mac_bytes(dst_mac) if reply else b"\x00" * 6
    arp = struct.pack(
        ">HHBBH6s4s6s4s",
        1,                        # htype: Ethernet
        0x0800,                   # ptype: IPv4
        6,                        # hlen
        4,                        # plen
        operation,
        _mac_bytes(src_mac),
        socket.inet_aton(sender_ip),
        target_hw,
        socket.inet_aton(target_ip),
    )
    ethernet = struct.pack(
        ">6s6sH", _mac_bytes(dst_mac), _mac_bytes(src_mac), ARP_ETHERNET_TYPE
    )
    return Frame(ethernet + arp, stamp)


def _http_message(start_line: str, headers: Sequence[tuple[str, str]], body: bytes) -> bytes:
    out = bytearray(start_line.encode("ascii") + _CRLF)
    for name, value in headers:
        out += f"{name}: {value}".encode("ascii") + _CRLF
    out += _CRLF
    out += body
    return bytes(out)


def _http_request(
    method: str,
    uri: str,
    host: str,
    *,
    headers: Sequence[tuple[str, str]] = (),
    body: bytes = b"",
) -> bytes:
    """A complete HTTP/1.1 request; ``Content-Length`` is added when needed."""
    all_headers: list[tuple[str, str]] = [("Host", host), *headers]
    if body and not any(name.lower() == "content-length" for name, _ in all_headers):
        all_headers.append(("Content-Length", str(len(body))))
    return _http_message(f"{method} {uri} HTTP/1.1", all_headers, body)


def _http_response(
    status: int,
    reason: str,
    *,
    headers: Sequence[tuple[str, str]] = (),
    body: bytes = b"",
) -> bytes:
    """A complete HTTP/1.1 response; ``Content-Length`` is always present."""
    all_headers: list[tuple[str, str]] = [("Server", "Apache/2.4.58 (Unix)"), *headers]
    if not any(name.lower() == "content-length" for name, _ in all_headers):
        all_headers.append(("Content-Length", str(len(body))))
    return _http_message(f"HTTP/1.1 {status} {reason}", all_headers, body)


_INDEX_HTML = (
    b"<!DOCTYPE html>\n<html><head><title>ShadowPackets Test Server</title></head>\n"
    b"<body><h1>It works</h1>\n<p>Synthetic page generated for deterministic capture tests.</p>\n"
    b"</body></html>\n"
)
_NOT_FOUND_HTML = (
    b"<!DOCTYPE html>\n<html><head><title>404 Not Found</title></head>\n"
    b"<body><h1>Not Found</h1><p>/does-not-exist</p></body></html>\n"
)
_SERVER_ERROR_HTML = (
    b"<!DOCTYPE html>\n<html><head><title>500 Internal Server Error</title></head>\n"
    b"<body><h1>Internal Server Error</h1></body></html>\n"
)
_LOGIN_JSON = b'{"ok":true,"user":"admin","token":"SHADOWPACKETS-SYNTHETIC-TOKEN"}'
_DAV_XML = (
    b'<?xml version="1.0" encoding="utf-8"?>\n'
    b'<D:multistatus xmlns:D="DAV:"><D:response><D:href>/dav/</D:href>'
    b"<D:propstat><D:status>HTTP/1.1 200 OK</D:status></D:propstat>"
    b"</D:response></D:multistatus>\n"
)


def _minimal_pdf() -> bytes:
    """A small but genuinely valid PDF (correct xref offsets), ~3.5 KB.

    The padding is inside the content stream so object offsets stay consistent;
    the file opens in a viewer and is big enough for object extraction to have
    something meaningful to store.
    """
    padding = b"% SHADOWPACKETS-PADDING-" + _fill(3000, b"shadowpackets-pdf-padding") + b"\n"
    content = (
        b"BT /F1 18 Tf 72 720 Td (ShadowPackets synthetic object test payload) Tj ET\n"
        + padding
    )
    objects: list[bytes] = [
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] "
        b"/Resources << /Font << /F1 5 0 R >> >> /Contents 4 0 R >>",
        b"<< /Length " + str(len(content)).encode("ascii") + b" >>\nstream\n" + content + b"endstream",
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
    ]
    out = bytearray(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
    offsets: list[int] = []
    for number, body in enumerate(objects, start=1):
        offsets.append(len(out))
        out += str(number).encode("ascii") + b" 0 obj\n" + body + b"\nendobj\n"
    xref_offset = len(out)
    out += b"xref\n0 " + str(len(objects) + 1).encode("ascii") + b"\n0000000000 65535 f \n"
    for offset in offsets:
        out += f"{offset:010d} 00000 n \n".encode("ascii")
    out += (
        b"trailer\n<< /Size "
        + str(len(objects) + 1).encode("ascii")
        + b" /Root 1 0 R >>\nstartxref\n"
        + str(xref_offset).encode("ascii")
        + b"\n%%EOF\n"
    )
    return bytes(out)


PDF_BYTES: bytes = _minimal_pdf()
PDF_SHA256: str = hashlib.sha256(PDF_BYTES).hexdigest()

HTTP_OBJECT_FILENAME = "payload.bin"
HTTP_OBJECT_HOST = "files.example.com"
HTTP_OBJECT_URI = "/objects/payload.bin"
HTTP_OBJECT_BYTES: bytes = (
    b"SHADOWPACKETS-EXTRACTABLE-OBJECT-BEGIN\n"
    + b"".join(
        f"line-{index:03d}-".encode("ascii") + _fill(24, f"obj{index}".encode("ascii")) + b"\n"
        for index in range(6)
    )
    + b"SHADOWPACKETS-EXTRACTABLE-OBJECT-END\n"
)
HTTP_OBJECT_SHA256: str = hashlib.sha256(HTTP_OBJECT_BYTES).hexdigest()


# ---------------------------------------------------------------------------
# 1. HTTP
# ---------------------------------------------------------------------------

def _http_transaction_table() -> list[dict[str, Any]]:
    """The nine HTTP transactions, with the exact bytes of each message.

    One table, used both to build :func:`_http_packets`/:func:`_http_contents`
    and to populate :func:`expected` ``"http"`` — so the documented stream ids,
    frame numbers and payload bytes are derived from the capture rather than
    written out twice and allowed to drift. ``stream`` is the client port
    offset: the six core transactions use client port 51000 (``tcp.stream == 0``)
    and the three unusual ones use client port 51001 (``tcp.stream == 1``).
    """
    agent = (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) ShadowPacketsTest/1.0"
    )
    return [
        {
            "stream": 0,
            "client_port": 51000,
            "method": "GET",
            "uri": "/index.html",
            "status": 200,
            "description": "200 OK with an HTML body",
            "request": _http_request(
                "GET", "/index.html", "www.example.com",
                headers=[("User-Agent", agent),
                         ("Accept", "text/html,application/xhtml+xml"),
                         ("Accept-Language", "en-US,en;q=0.9")],
            ),
            "response": _http_response(
                200, "OK",
                headers=[("Date", "Tue, 14 Nov 2023 22:13:20 GMT"),
                         ("Content-Type", "text/html; charset=utf-8"),
                         ("Connection", "keep-alive")],
                body=_INDEX_HTML,
            ),
        },
        {
            "stream": 0,
            "client_port": 51000,
            "method": "GET",
            "uri": "/does-not-exist",
            "status": 404,
            "description": "404 Not Found",
            "request": _http_request(
                "GET", "/does-not-exist", "www.example.com",
                headers=[("User-Agent", agent)],
            ),
            "response": _http_response(
                404, "Not Found",
                headers=[("Content-Type", "text/html; charset=utf-8"),
                         ("Connection", "keep-alive")],
                body=_NOT_FOUND_HTML,
            ),
        },
        {
            "stream": 0,
            "client_port": 51000,
            "method": "GET",
            "uri": "/broken",
            "status": 500,
            "description": "500 Internal Server Error",
            "request": _http_request(
                "GET", "/broken", "www.example.com",
                headers=[("User-Agent", "ShadowPacketsProbe/0.9"), ("Accept", "*/*")],
            ),
            "response": _http_response(
                500, "Internal Server Error",
                headers=[("Content-Type", "text/html; charset=utf-8"),
                         ("Connection", "keep-alive")],
                body=_SERVER_ERROR_HTML,
            ),
        },
        {
            "stream": 0,
            "client_port": 51000,
            "method": "POST",
            "uri": "/login",
            "status": 200,
            "description": "plaintext credentials in a form body",
            "request": _http_request(
                "POST", "/login", "www.example.com",
                headers=[("User-Agent", "ShadowPacketsProbe/0.9"),
                         ("Content-Type", "application/x-www-form-urlencoded")],
                body=b"username=admin&password=secret123",
            ),
            "response": _http_response(
                200, "OK",
                headers=[("Content-Type", "application/json"),
                         ("Connection", "keep-alive")],
                body=_LOGIN_JSON,
            ),
        },
        {
            "stream": 0,
            "client_port": 51000,
            "method": "GET",
            "uri": "/../../etc/passwd",
            "status": 400,
            "description": "path-traversal-shaped request URI",
            "request": _http_request(
                "GET", "/../../etc/passwd", "www.example.com",
                headers=[("User-Agent", "ShadowPacketsProbe/0.9")],
            ),
            "response": _http_response(
                400, "Bad Request",
                headers=[("Content-Type", "text/html; charset=utf-8"),
                         ("Connection", "keep-alive")],
                body=b"<html><body><h1>400 Bad Request</h1></body></html>\n",
            ),
        },
        {
            "stream": 0,
            "client_port": 51000,
            "method": "GET",
            "uri": "/download/report.pdf",
            "status": 200,
            "description": "binary attachment (real PDF)",
            "request": _http_request(
                "GET", "/download/report.pdf", "www.example.com",
                headers=[("User-Agent", agent), ("Accept", "application/pdf,*/*")],
            ),
            "response": _http_response(
                200, "OK",
                headers=[("Content-Type", "application/pdf"),
                         ("Content-Disposition", 'attachment; filename="report.pdf"'),
                         ("Connection", "close")],
                body=PDF_BYTES,
            ),
        },
        {
            "stream": 1,
            "client_port": 51001,
            "method": "GET",
            "uri": "/status",
            "status": 200,
            "description": "Host header is a literal IP address",
            "host": SERVER_IP,
            "request": _http_request(
                "GET", "/status", SERVER_IP,
                headers=[("User-Agent", "curl/8.4.0"), ("Accept", "*/*")],
            ),
            "response": _http_response(
                200, "OK",
                headers=[("Content-Type", "text/plain"),
                         ("Connection", "keep-alive")],
                body=b"status=ok; host-header-was-literal-ip\n",
            ),
        },
        {
            "stream": 1,
            "client_port": 51001,
            "method": "PROPFIND",
            "uri": "/dav/",
            "status": 207,
            "description": "unusual HTTP method",
            "request": _http_request(
                "PROPFIND", "/dav/", "www.example.com",
                headers=[("User-Agent", "Microsoft-WebDAV-MiniRedir/10.0.19041"),
                         ("Depth", "1"),
                         ("Content-Type", "text/xml; charset=utf-8")],
                body=_DAV_XML,
            ),
            "response": _http_response(
                207, "Multi-Status",
                headers=[("Content-Type", "application/xml; charset=utf-8"),
                         ("Connection", "keep-alive")],
                body=_DAV_XML,
            ),
        },
        {
            "stream": 1,
            "client_port": 51001,
            "method": "GET",
            "uri": "/long-agent.txt",
            "status": 200,
            "description": "long/unusual User-Agent",
            "request": _http_request(
                "GET", "/long-agent.txt", "www.example.com",
                headers=[("User-Agent", _UA_LONG),
                         ("Accept", "text/plain"),
                         ("X-ShadowPackets-Test", "unusual-user-agent")],
            ),
            "response": _http_response(
                200, "OK",
                headers=[("Content-Type", "text/plain"), ("Connection", "close")],
                body=b"unusual user agent received\n",
            ),
        },
    ]


def _http_contents(base: float = BASE_EPOCH) -> tuple[list[Packet], list[dict[str, Any]]]:
    """Build the HTTP packets **and** the transaction metadata for the capture.

    Each record gains the real ``request_frame``/``response_frame`` numbers
    (1-based ``frame.number`` values) as the packets are emitted, so the
    documented expectations always describe the file that was actually written.
    """
    clock = _Clock(base, 0.004)
    packets: list[Packet] = []
    records: list[dict[str, Any]] = []

    flow_settings: dict[int, dict[str, Any]] = {
        0: {"client_port": 51000, "isn_client": 0x2A2B2C2D, "isn_server": 0x6A6B6C6D},
        1: {"client_port": 51001, "isn_client": 0x3A3B3C3D, "isn_server": 0x7A7B7C7D},
    }

    for stream_id in (0, 1):
        settings = flow_settings[stream_id]
        flow = TcpFlow(
            (CLIENT_IP, CLIENT_MAC, settings["client_port"]),
            (SERVER_IP, SERVER_MAC, HTTP_PORT),
            clock,
            isn_client=settings["isn_client"],
            isn_server=settings["isn_server"],
        )
        packets += flow.handshake()
        for entry in _http_transaction_table():
            if entry["stream"] != stream_id:
                continue
            record = dict(entry)
            record["request_frame"] = len(packets) + 1
            packets.append(flow.data(True, entry["request"]))
            record["response_frame"] = len(packets) + 1
            packets.append(flow.data(False, entry["response"]))
            records.append(record)
        packets += flow.close()
    return packets, records


def _http_packets(base: float = BASE_EPOCH) -> list[Packet]:
    """Build the HTTP capture's packet list (see :func:`http_capture`)."""
    return _http_contents(base)[0]


def http_capture(dest: Path | None = None) -> Path:
    """Cleartext HTTP over two TCP streams: 32 packets, 9 transactions.

    Contents (all on port 80, client ``10.0.0.10`` → server ``10.0.0.20``):

    * stream 0 (client port 51000, keep-alive, full handshake and close):
      ``GET /index.html`` → 200 HTML, ``GET /does-not-exist`` → 404,
      ``GET /broken`` → 500, ``POST /login`` with the plaintext body
      ``username=admin&password=secret123`` → 200 JSON,
      ``GET /../../etc/passwd`` (path-traversal-shaped URI) → 400,
      ``GET /download/report.pdf`` → 200 with a real ~3.5 KB PDF body and
      ``Content-Disposition: attachment; filename="report.pdf"``.
    * stream 1 (client port 51001): ``GET /status`` whose ``Host`` header is the
      literal IP ``10.0.0.20``, ``PROPFIND /dav/`` (unusual method) → 207, and
      ``GET /long-agent.txt`` with a ~250 character unusual ``User-Agent``.

    Exercises: `http` transactions, methods/hosts/URIs/status codes, cleartext
    credentials in a request body, traversal-shaped URIs, attachments and
    binary body extraction.
    """
    return write_pcap(_output_path(dest, "http"), _http_packets())


# ---------------------------------------------------------------------------
# 2. DNS
# ---------------------------------------------------------------------------

LONG_LABEL = "verylongsinglelabelusedfordnslabeldetection"  # 42 chars
LONG_LABEL_DOMAIN = f"{LONG_LABEL}.example.com"
MULTI_LABEL_DOMAIN = "api.eu-west-1.multi.sub.example.com"
BURST_DOMAIN_TEMPLATE = "burst-{index:04d}.example.com"
BURST_QUERIES = 120
NXDOMAIN_DOMAIN = "missing.example.com"


def _dns_pair(
    clock: _Clock,
    client: Peer,
    sport: int,
    dns_id: int,
    name: str,
    qtype: str,
    *,
    answers: Sequence[tuple[str, str, int]] = (),
    rcode: int = 0,
    ipv6: bool = False,
) -> list[Packet]:
    """One DNS query and its matching response (same transaction id)."""
    resolver = DNS6_SERVER if ipv6 else DNS_SERVER
    query = _net(
        client,
        resolver,
        UDP(sport=sport, dport=DNS_PORT)
        / DNS(id=dns_id, qr=0, opcode=0, rd=1, qd=DNSQR(qname=name, qtype=qtype)),
        clock,
        ipv6=ipv6,
    )
    # NOTE: the answer records are passed as a *list*. Assigning a chained
    # packet (``a / b``) to ``an`` makes scapy count the whole chain as one
    # record, which silently produced ancount=1 and left the extra answers as
    # trailing bytes — verified fixed with ``tshark -e dns.count.answers``.
    records = [
        DNSRR(rrname=name, type=record_type, ttl=ttl, rdata=rdata)
        for record_type, rdata, ttl in answers
    ]
    reply_kwargs: dict[str, Any] = {}
    if records:
        reply_kwargs["an"] = records
    reply = _net(
        resolver,
        client,
        UDP(sport=DNS_PORT, dport=sport)
        / DNS(
            id=dns_id,
            qr=1,
            aa=1 if rcode == 0 else 0,
            rd=1,
            ra=1,
            rcode=rcode,
            qd=DNSQR(qname=name, qtype=qtype),
            **reply_kwargs,
        ),
        clock,
        ipv6=ipv6,
    )
    return [query, reply]


def _dns_packets(base: float = BASE_EPOCH) -> list[Packet]:
    """Build the DNS capture's packet list (see :func:`dns_capture`)."""
    clock = _Clock(base, 0.003)
    packets: list[Packet] = []

    # Named queries from the workstation (client port 53000).
    packets += _dns_pair(clock, CLIENT, 53000, 0x1001, "example.com", "A",
                         answers=[("A", "93.184.216.34", 300)])
    packets += _dns_pair(clock, CLIENT, 53001, 0x1002, NXDOMAIN_DOMAIN, "A", rcode=3)
    packets += _dns_pair(clock, CLIENT, 53002, 0x1003, LONG_LABEL_DOMAIN, "A",
                         answers=[("A", "203.0.113.5", 120)])
    packets += _dns_pair(clock, CLIENT, 53003, 0x1004, MULTI_LABEL_DOMAIN, "A",
                         answers=[("A", "93.184.216.34", 300),
                                  ("A", "93.184.216.35", 300),
                                  ("A", "203.0.113.10", 60)])
    packets += _dns_pair(clock, CLIENT, 53004, 0x1005, "txt.example.com", "TXT",
                         answers=[("TXT", "v=spf1 -all", 300)])

    # High-volume burst: 120 queries from a single client (10.0.0.77).
    burst = Peer(BURST_IP, BURST_MAC)
    for index in range(BURST_QUERIES):
        packets += _dns_pair(
            clock,
            burst,
            53000 + index,
            0x2000 + index,
            BURST_DOMAIN_TEMPLATE.format(index=index),
            "A",
            answers=[("A", "93.184.216.34", 60)],
        )
    return packets


def dns_capture(dest: Path | None = None) -> Path:
    """UDP DNS between fixed clients and resolver ``8.8.8.8:53``.

    Contents (250 packets = 125 query/response pairs):

    * ``example.com`` A → ``93.184.216.34`` (id ``0x1001``)
    * ``missing.example.com`` A → **NXDOMAIN**, rcode 3
    * ``verylongsinglelabelusedfordnslabeldetection.example.com`` — a single
      **42-character** label (the ``dns_long_labels`` rule triggers at 40)
    * ``api.eu-west-1.multi.sub.example.com`` — several sub-labels, answered
      with **three** A records
    * ``txt.example.com`` TXT → ``v=spf1 -all``
    * a **burst of 120 queries** (``burst-0000 … burst-0119.example.com``) from
      one client ``10.0.0.77``, exceeding the ``dns_high_volume`` threshold of
      100

    All queries come from port 53000+ and each is answered by the same
    transaction id, so query/response merging can be tested.
    """
    return write_pcap(_output_path(dest, "dns"), _dns_packets())


# ---------------------------------------------------------------------------
# 3. TLS (with a hand-encoded DER X.509 certificate)
# ---------------------------------------------------------------------------

# -- minimal DER encoder ----------------------------------------------------

def _der_length(length: int) -> bytes:
    """DER definite length (short form, or long form above 127)."""
    if length < 0x80:
        return bytes([length])
    encoded = length.to_bytes((length.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(encoded)]) + encoded


def _der_tlv(tag: int, content: bytes) -> bytes:
    return bytes([tag]) + _der_length(len(content)) + content


def der_sequence(*items: bytes) -> bytes:
    """DER ``SEQUENCE`` (tag 0x30)."""
    return _der_tlv(0x30, b"".join(items))


def der_set(*items: bytes) -> bytes:
    """DER ``SET``/``SET OF`` (tag 0x31)."""
    return _der_tlv(0x31, b"".join(items))


def der_integer(value: int) -> bytes:
    """DER ``INTEGER`` (tag 0x02), minimal two's-complement encoding."""
    if value == 0:
        return _der_tlv(0x02, b"\x00")
    body = value.to_bytes((value.bit_length() + 8) // 8, "big")
    while len(body) > 1 and body[0] == 0x00 and body[1] < 0x80:
        body = body[1:]
    return _der_tlv(0x02, body)


def der_oid(dotted: str) -> bytes:
    """DER ``OBJECT IDENTIFIER`` (tag 0x06), base-128 sub-identifiers."""
    parts = [int(part) for part in dotted.split(".")]
    if len(parts) < 2:
        raise ValueError(f"OID needs at least two arcs: {dotted!r}")
    body = bytearray([40 * parts[0] + parts[1]])
    for part in parts[2:]:
        groups = [part & 0x7F]
        part >>= 7
        while part:
            groups.append(0x80 | (part & 0x7F))
            part >>= 7
        body += bytes(reversed(groups))
    return _der_tlv(0x06, bytes(body))


def der_utc_time(text: str) -> bytes:
    """DER ``UTCTime`` (tag 0x17), e.g. ``230101000000Z``."""
    return _der_tlv(0x17, text.encode("ascii"))


def der_printable_string(text: str) -> bytes:
    """DER ``PrintableString`` (tag 0x13)."""
    return _der_tlv(0x13, text.encode("ascii"))


def der_utf8_string(text: str) -> bytes:
    """DER ``UTF8String`` (tag 0x0C)."""
    return _der_tlv(0x0C, text.encode("utf-8"))


def der_bit_string(data: bytes, unused_bits: int = 0) -> bytes:
    """DER ``BIT STRING`` (tag 0x03)."""
    return _der_tlv(0x03, bytes([unused_bits]) + data)


def der_octet_string(data: bytes) -> bytes:
    """DER ``OCTET STRING`` (tag 0x04)."""
    return _der_tlv(0x04, data)


def der_null() -> bytes:
    """DER ``NULL`` (tag 0x05)."""
    return _der_tlv(0x05, b"")


def der_explicit(tag_number: int, content: bytes) -> bytes:
    """Context-tagged explicit wrapper, e.g. ``[0] EXPLICIT`` → 0xA0."""
    return _der_tlv(0xA0 | tag_number, content)


OID_SHA256_WITH_RSA = "1.2.840.113549.1.1.11"
OID_RSA_ENCRYPTION = "1.2.840.113549.1.1.1"
OID_COMMON_NAME = "2.5.4.3"
OID_SERIAL_NUMBER = "2.5.4.5"
OID_ORGANIZATION = "2.5.4.10"
OID_ORGANIZATIONAL_UNIT = "2.5.4.11"
OID_COUNTRY = "2.5.4.6"

CERT_SUBJECT_CN = "secure.example.com"
CERT_SUBJECT_O = "ShadowPackets Test Lab"
CERT_SUBJECT_OU = "Synthetic Captures"
CERT_SUBJECT_C = "US"
CERT_SUBJECT_SERIAL_RDN = "SHADOWPACKETS-TEST-0001"
CERT_NOT_BEFORE = "230101000000Z"  # 2023-01-01T00:00:00Z
CERT_NOT_AFTER = "330101000000Z"  # 2033-01-01T00:00:00Z
CERT_SERIAL = 0x0A0B0C0D0E0F1011
CERT_SERIAL_TEXT = f"{CERT_SERIAL:X}"
#: Subject DN as TShark renders it (RFC 2253 order: most specific RDN first).
#: ``C`` and ``serialNumber`` are PrintableStrings, O/OU/CN are UTF8Strings.
CERT_SUBJECT_DN = (
    f"CN={CERT_SUBJECT_CN}, serialNumber={CERT_SUBJECT_SERIAL_RDN}, "
    f"OU={CERT_SUBJECT_OU}, O={CERT_SUBJECT_O}, C={CERT_SUBJECT_C}"
)


def _rsa_modulus(seed: bytes = b"shadowpackets-test-modulus", bits: int = 2048) -> int:
    """A fixed 2048-bit odd modulus (not a real key — nothing is encrypted)."""
    material = bytearray()
    counter = 0
    while len(material) < bits // 8:
        material += hashlib.sha256(seed + counter.to_bytes(4, "big")).digest()
        counter += 1
    value = int.from_bytes(bytes(material[: bits // 8]), "big")
    return value | (1 << (bits - 1)) | 1


def _rdn(oid: str, value: bytes) -> bytes:
    """One ``RelativeDistinguishedName``: ``SET { SEQUENCE { oid, value } }``."""
    return der_set(der_sequence(der_oid(oid), value))


def _name_sequence() -> bytes:
    """The self-signed subject/issuer ``Name`` (a ``RDNSequence``).

    ``C`` and ``serialNumber`` use PrintableString, ``O``/``OU``/``CN`` use
    UTF8String, so TShark emits both ``x509sat.PrintableString`` and
    ``x509sat.uTF8String`` (its legacy spelling) for this certificate.
    """
    return der_sequence(
        _rdn(OID_COUNTRY, der_printable_string(CERT_SUBJECT_C)),
        _rdn(OID_ORGANIZATION, der_utf8_string(CERT_SUBJECT_O)),
        _rdn(OID_ORGANIZATIONAL_UNIT, der_utf8_string(CERT_SUBJECT_OU)),
        _rdn(OID_SERIAL_NUMBER, der_printable_string(CERT_SUBJECT_SERIAL_RDN)),
        _rdn(OID_COMMON_NAME, der_utf8_string(CERT_SUBJECT_CN)),
    )


def x509_self_signed_der() -> bytes:
    """A small, structurally valid, hand-encoded self-signed X.509 (v3) cert.

    The encoding is complete for the fields TShark reports: ``version`` [0]
    EXPLICIT, ``serialNumber``, ``signature`` AlgorithmIdentifier,
    ``issuer``/``subject`` RDNSequences (PrintableString country name and
    serialNumber, UTF8String O/OU/CN), ``validity`` with two UTCTimes, and a
    ``subjectPublicKeyInfo`` holding an rsaEncryption AlgorithmIdentifier and a
    BIT STRING that wraps a well-formed ``RSAPublicKey`` SEQUENCE.

    The signature BIT STRING contains deterministic filler, not a real RSA
    signature: the certificate is never verified, only dissected. No key
    material, no network and no clock are involved.
    """
    modulus = _rsa_modulus()
    public_key = der_sequence(der_integer(modulus), der_integer(65537))
    spki = der_sequence(
        der_sequence(der_oid(OID_RSA_ENCRYPTION), der_null()),
        der_bit_string(public_key),
    )
    algorithm = der_sequence(der_oid(OID_SHA256_WITH_RSA), der_null())
    name = _name_sequence()
    tbs = der_sequence(
        der_explicit(0, der_integer(2)),  # version v3
        der_integer(CERT_SERIAL),
        algorithm,
        name,  # issuer (self-signed == subject)
        der_sequence(der_utc_time(CERT_NOT_BEFORE), der_utc_time(CERT_NOT_AFTER)),
        name,  # subject
        spki,
    )
    signature = _fill(256, b"shadowpackets-test-signature")
    return der_sequence(tbs, algorithm, der_bit_string(signature))


X509_DER: bytes = x509_self_signed_der()

# -- TLS wire format --------------------------------------------------------

TLS_CONTENT_CHANGE_CIPHER_SPEC = 0x14
TLS_CONTENT_ALERT = 0x15
TLS_CONTENT_HANDSHAKE = 0x16
TLS_CONTENT_APPLICATION_DATA = 0x17

TLS_HS_CLIENT_HELLO = 0x01
TLS_HS_SERVER_HELLO = 0x02
TLS_HS_CERTIFICATE = 0x0B
TLS_HS_SERVER_HELLO_DONE = 0x0E

TLS_VERSION_1_2 = b"\x03\x03"
TLS_RECORD_VERSION = b"\x03\x01"  # record-layer version a TLS 1.2 client sends

SNI_PRIMARY = "secure.example.com"
SNI_ALERT = "tls-alert.example.com"
ALPN_OFFERS = ("h2", "http/1.1")
ALPN_SELECTED = "h2"
CIPHER_SUITES = (0xC02F, 0xC030, 0xC013, 0xC014, 0x009C, 0x002F, 0x0035, 0x000A)

#: Fixed 32-byte client/server randoms (a real handshake uses fresh randoms;
#: fixed values are what make this capture byte-reproducible).
TLS_CLIENT_RANDOM = bytes(range(32))
TLS_SERVER_RANDOM = bytes(range(0x40, 0x60))

TLS_ALERT_FATAL_HANDSHAKE_FAILURE = b"\x02\x28"  # fatal, handshake_failure(40)


def _u16(value: int) -> bytes:
    return value.to_bytes(2, "big")


def _u24(value: int) -> bytes:
    return value.to_bytes(3, "big")


def _tls_extension(ext_type: int, data: bytes) -> bytes:
    return _u16(ext_type) + _u16(len(data)) + data


def _tls_record(content_type: int, payload: bytes, *, version: bytes = TLS_RECORD_VERSION) -> bytes:
    return bytes([content_type]) + version + _u16(len(payload)) + payload


def _tls_handshake(message_type: int, body: bytes) -> bytes:
    return bytes([message_type]) + _u24(len(body)) + body


def _ext_server_name(host: str) -> bytes:
    encoded = host.encode("ascii")
    return _tls_extension(0x0000, _u16(len(encoded) + 3) + b"\x00" + _u16(len(encoded)) + encoded)


def _ext_alpn(protocols: Sequence[str]) -> bytes:
    listing = b"".join(bytes([len(item)]) + item.encode("ascii") for item in protocols)
    return _tls_extension(0x0010, _u16(len(listing)) + listing)


def _ext_supported_groups() -> bytes:
    groups = (0x001D, 0x0017, 0x0018)  # x25519, secp256r1, secp384r1
    return _tls_extension(0x000A, _u16(2 * len(groups)) + b"".join(_u16(g) for g in groups))


def _ext_ec_point_formats() -> bytes:
    return _tls_extension(0x000B, b"\x01\x00")


def _ext_signature_algorithms() -> bytes:
    schemes = (0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601)
    return _tls_extension(0x000D, _u16(2 * len(schemes)) + b"".join(_u16(s) for s in schemes))


def _ext_extended_master_secret() -> bytes:
    return _tls_extension(0x0017, b"")


def tls_client_hello(
    *,
    sni: str | None,
    alpn: Sequence[str] = ALPN_OFFERS,
    random_bytes: bytes = TLS_CLIENT_RANDOM,
    cipher_suites: Sequence[int] = CIPHER_SUITES,
) -> bytes:
    """A TLS 1.2 ClientHello record (``legacy_version`` 0x0303).

    ``sni=None`` omits the ``server_name`` extension entirely — that is the
    "ClientHello without SNI" case. The ``supported_versions`` extension is
    deliberately absent so TShark reports the client version as TLS 1.2.
    """
    extensions = bytearray()
    if sni is not None:
        extensions += _ext_server_name(sni)
    extensions += _ext_supported_groups()
    extensions += _ext_ec_point_formats()
    extensions += _ext_signature_algorithms()
    extensions += _ext_extended_master_secret()
    extensions += _ext_alpn(alpn)

    body = (
        TLS_VERSION_1_2
        + random_bytes
        + b"\x00"  # empty session id
        + _u16(2 * len(cipher_suites))
        + b"".join(_u16(suite) for suite in cipher_suites)
        + b"\x01\x00"  # one compression method: null
        + _u16(len(extensions))
        + bytes(extensions)
    )
    return _tls_record(TLS_CONTENT_HANDSHAKE, _tls_handshake(TLS_HS_CLIENT_HELLO, body))


def tls_server_hello(*, alpn: str | None = ALPN_SELECTED) -> bytes:
    """A TLS 1.2 ServerHello record selecting ``0xC02F`` and ``h2`` when offered."""
    extensions = _ext_alpn([alpn]) if alpn else b""
    body = (
        TLS_VERSION_1_2
        + TLS_SERVER_RANDOM
        + b"\x00"
        + _u16(0xC02F)
        + b"\x00"
        + _u16(len(extensions))
        + extensions
    )
    return _tls_record(TLS_CONTENT_HANDSHAKE, _tls_handshake(TLS_HS_SERVER_HELLO, body))


def tls_certificate(der: bytes = X509_DER) -> bytes:
    """A TLS 1.2 Certificate record carrying one DER X.509 certificate."""
    entry = _u24(len(der)) + der
    return _tls_record(TLS_CONTENT_HANDSHAKE, _tls_handshake(TLS_HS_CERTIFICATE, _u24(len(entry)) + entry))


def tls_server_hello_done() -> bytes:
    """A TLS 1.2 ServerHelloDone record (empty body)."""
    return _tls_record(TLS_CONTENT_HANDSHAKE, _tls_handshake(TLS_HS_SERVER_HELLO_DONE, b""))


def tls_alert(level: int = 2, description: int = 40) -> bytes:
    """A TLS Alert record (default: fatal / handshake_failure)."""
    return _tls_record(TLS_CONTENT_ALERT, bytes([level, description]))


def _tls_packets(base: float = BASE_EPOCH) -> list[Packet]:
    """Build the TLS capture's packet list (see :func:`tls_capture`)."""
    clock = _Clock(base, 0.005)
    packets: list[Packet] = []

    # Stream 0: real handshake, SNI + ALPN, certificate with a DER X.509.
    primary = TcpFlow((CLIENT_IP, CLIENT_MAC, 52000), (SERVER_IP, SERVER_MAC, HTTPS_PORT), clock,
                      isn_client=0x4A4B4C4D, isn_server=0x8A8B8C8D)
    packets += primary.handshake()
    packets.append(primary.data(True, tls_client_hello(sni=SNI_PRIMARY)))
    packets.append(primary.data(False, tls_server_hello()))
    packets.append(primary.data(False, tls_certificate()))
    packets.append(primary.data(False, tls_server_hello_done()))
    packets.append(primary.ack(True))
    packets += primary.close()

    # Stream 1: ClientHello with NO server_name extension at all.
    no_sni = TcpFlow((CLIENT_IP, CLIENT_MAC, 52001), (SERVER_IP, SERVER_MAC, HTTPS_PORT), clock,
                     isn_client=0x5B5C5D5E, isn_server=0x9B9C9D9E)
    packets += no_sni.handshake()
    packets.append(no_sni.data(True, tls_client_hello(sni=None, random_bytes=bytes(range(32, 64)))))
    packets += no_sni.close()

    # Stream 2: ClientHello answered with a fatal TLS alert record.
    alert = TcpFlow((CLIENT_IP, CLIENT_MAC, 52002), (SERVER_IP, SERVER_MAC, HTTPS_PORT), clock,
                    isn_client=0x6C6D6E6F, isn_server=0xACADAEAF)
    packets += alert.handshake()
    packets.append(alert.data(True, tls_client_hello(sni=SNI_ALERT, random_bytes=bytes(range(64, 96)))))
    packets.append(alert.data(False, tls_alert()))
    packets += alert.close()
    return packets


def tls_capture(dest: Path | None = None) -> Path:
    """TLS over three TCP streams to ``10.0.0.20:443``.

    Contents:

    * **stream 0** (client port 52000) — full three-way handshake, then a
      **TLS 1.2 ClientHello** carrying a ``server_name`` (SNI) extension for
      ``secure.example.com`` and an ALPN extension offering ``h2`` and
      ``http/1.1``; the server answers with ServerHello (``0xC02F``, ALPN
      ``h2``), a **Certificate** message holding a real hand-encoded DER X.509
      certificate (:func:`x509_self_signed_der`, subject == issuer
      ``CN=secure.example.com``), and ServerHelloDone.
    * **stream 1** (client port 52001) — a ClientHello with **no SNI extension
      at all**.
    * **stream 2** (client port 52002) — a ClientHello (SNI
      ``tls-alert.example.com``) answered with a **TLS alert record**
      (fatal, ``handshake_failure``).

    Exercises: ``tls.handshake.type`` 1/2/11/14, ``extensions_server_name``,
    ALPN, JA3/JA3S, X.509 subject/issuer/validity dissection and alert records.
    """
    return write_pcap(_output_path(dest, "tls"), _tls_packets())


# ---------------------------------------------------------------------------
# 4. SYN scan
# ---------------------------------------------------------------------------

SCAN_PORTS: tuple[int, ...] = (
    20, 21, 22, 23, 25, 53, 110, 111, 135, 139,
    143, 443, 445, 993, 995, 1433, 1521, 2049, 3306, 3389,
    5432, 5900, 5985, 6379, 8080, 8443, 8888, 9000, 9200, 10000,
    11211, 27017, 5000, 5060, 5222, 6000, 7001, 8081, 8000, 8008,
)


def _syn_scan_packets(base: float = BASE_EPOCH) -> list[Packet]:
    """Build the SYN-scan packet list (see :func:`syn_scan_capture`)."""
    clock = _Clock(base, 0.1)  # 40 scan probes inside 4 seconds
    packets: list[Packet] = []
    scanner = Peer(SCANNER_IP, SCANNER_MAC)
    target = Peer(SERVER_IP, SERVER_MAC)

    for index, port in enumerate(SCAN_PORTS):
        flow = TcpFlow(
            (SCANNER_IP, SCANNER_MAC, 40000 + index),
            (SERVER_IP, SERVER_MAC, port),
            clock,
            isn_client=0x10000000 + index * 0x1000,
            isn_server=0x20000000 + index * 0x1000,
        )
        packets.append(flow.syn())

    # Contrasting completed handshake plus a request/response on port 80.
    normal = TcpFlow((SCANNER_IP, SCANNER_MAC, 45000), (SERVER_IP, SERVER_MAC, HTTP_PORT), clock,
                     isn_client=0x7F7F0001, isn_server=0x7F7F0002)
    packets += normal.handshake()
    packets.append(
        normal.data(True, _http_request("GET", "/scan-contrast", SERVER_IP,
                                        headers=[("User-Agent", "ShadowPacketsPortScanner/1.0")]))
    )
    packets.append(
        normal.data(False, _http_response(200, "OK",
                                          headers=[("Content-Type", "text/plain"),
                                                   ("Connection", "close")],
                                          body=b"completed-handshake-ok\n"))
    )
    packets += normal.close()
    return packets


def syn_scan_capture(dest: Path | None = None) -> Path:
    """A horizontal SYN scan plus one normal conversation for contrast.

    Contents (49 packets):

    * ``10.0.0.66`` sends **40 SYN-only** probes (one per source port, one per
      destination port from :data:`SCAN_PORTS`) to ``10.0.0.20`` within
      4 seconds, with **no responses at all** — filtered ports.
    * one **completed** three-way handshake from the same source to
      ``10.0.0.20:80``, followed by ``GET /scan-contrast`` → 200 and a clean
      close, so a detector can show that not all traffic is scan-like.

    TShark reports 41 frames for ``tcp.flags.syn == 1 && tcp.flags.ack == 0``
    (the 40 probes plus the initial SYN of the contrast handshake), 1 SYN/ACK,
    and 40 distinct destination ports excluding port 80.

    Exceeds the ``tcp_syn_scan`` thresholds (≥20 distinct destination ports
    within 10 s, ≥80 % SYN-only).
    """
    return write_pcap(_output_path(dest, "syn_scan"), _syn_scan_packets())


# ---------------------------------------------------------------------------
# 5. Failed connections
# ---------------------------------------------------------------------------

FAILED_CONNECTION_ATTEMPTS = 15
FAILED_CONNECTION_PORT = 445


def _arp_sweep_packets(base: float = BASE_EPOCH) -> list[Frame]:
    """Build the ARP host-discovery packet list (see :func:`arp_sweep_capture`)."""
    clock = _Clock(base, 0.05)  # 40 probes inside two seconds
    packets: list[Frame] = []

    for target in ARP_SWEEP_TARGETS:
        packets.append(
            _arp_frame(
                SCANNER_MAC, BROADCAST_MAC, SCANNER_IP, target,
                reply=False, stamp=clock.tick(),
            )
        )

    for index, host in enumerate(ARP_SWEEP_LIVE):
        packets.append(
            _arp_frame(
                f"02:00:00:00:01:{index:02x}", SCANNER_MAC, host, SCANNER_IP,
                reply=True, stamp=clock.tick(),
            )
        )

    # Contrast: the ordinary workstation resolves its gateway once and is answered,
    # so a source with one unanswered probe is not mistaken for a sweep.
    packets.append(
        _arp_frame(CLIENT_MAC, BROADCAST_MAC, CLIENT_IP, GATEWAY_IP,
                   reply=False, stamp=clock.tick())
    )
    packets.append(
        _arp_frame(GATEWAY_MAC, CLIENT_MAC, GATEWAY_IP, CLIENT_IP,
                   reply=True, stamp=clock.tick())
    )
    return packets


def arp_sweep_capture(dest: Path | None = None) -> Path:
    """A local ARP host-discovery sweep of 40 addresses, plus one normal lookup.

    Contents:

    * ``10.0.0.66`` asks "who has" for 40 distinct addresses in :data:`ARP_SWEEP_TARGETS`
      inside two seconds, with **no TCP frame at all** - the shape a local
      ``nmap -sn`` produces, and the reason a port-based detector sees nothing.
    * three of those addresses (``10.0.0.100``-``.102``) answer, so ``37`` probes are
      left unanswered and the sweep is still unmistakable.
    * the client resolves its gateway once and is answered, as a control.
    """
    return write_pcap(_output_path(dest, "arp_sweep"), _arp_sweep_packets())


def _failed_connections_packets(base: float = BASE_EPOCH) -> list[Packet]:
    """Build the failed-connections packet list (see the builder's docstring)."""
    clock = _Clock(base, 0.5)
    packets: list[Packet] = []
    for index in range(FAILED_CONNECTION_ATTEMPTS):
        flow = TcpFlow(
            (SCANNER_IP, SCANNER_MAC, 41000 + index),
            (SERVER_IP, SERVER_MAC, FAILED_CONNECTION_PORT),
            clock,
            isn_client=0x30000000 + index * 0x2000,
            isn_server=0x40000000 + index * 0x2000,
        )
        # Retransmission of the same SYN, exactly like a stack that gives up:
        # every SYN is unanswered, so no SYN/ACK and no RST ever appears.
        packets.append(flow.syn())
        packets.append(flow.syn_retransmit())
    return packets


def failed_connections_capture(dest: Path | None = None) -> Path:
    """Repeated unanswered SYNs to one destination.

    ``10.0.0.66`` makes **15 connection attempts** to
    ``10.0.0.20:445`` (each one a SYN plus one retransmitted SYN, 30 packets
    total) and **never receives a SYN/ACK, RST or any other reply** — 100 %
    SYN-only traffic for that destination.
    Exceeds the ``repeated_failed_connections`` threshold (≥10 unanswered SYNs).
    """
    return write_pcap(_output_path(dest, "failed_connections"), _failed_connections_packets())


# ---------------------------------------------------------------------------
# 6. IPv6 (plus a dual-stack IPv4 pair)
# ---------------------------------------------------------------------------

def _ipv6_packets(base: float = BASE_EPOCH) -> list[Packet]:
    """Build the IPv6 capture's packet list (see :func:`ipv6_capture`)."""
    clock = _Clock(base, 0.01)
    packets: list[Packet] = []

    # Dual-stack pair: an IPv4 ICMP echo exchange first, so one file has both
    # ip.version 4 and ip.version 6.
    packets.append(_icmp_frame(CLIENT, SERVER, echo_reply=False, ident=0x0A0A, seq=1, clock=clock))
    packets.append(_icmp_frame(SERVER, CLIENT, echo_reply=True, ident=0x0A0A, seq=1, clock=clock))

    # IPv6 TCP: handshake plus a payload each way.
    flow = TcpFlow((CLIENT6, CLIENT6_MAC, 51000), (SERVER6, SERVER6_MAC, 8080), clock,
                   isn_client=0x11223344, isn_server=0x55667788, ipv6=True)
    packets += flow.handshake()
    packets.append(flow.data(True, b"IPV6-TCP-CLIENT-PAYLOAD-0001\n"))
    packets.append(flow.data(False, b"IPV6-TCP-SERVER-PAYLOAD-0001\n"))
    packets += flow.close()

    # IPv6 UDP: request and reply.
    packets.append(_udp_frame(Peer(CLIENT6, CLIENT6_MAC), 4000, Peer(SERVER6, SERVER6_MAC), 4001,
                              b"IPV6-UDP-REQUEST-0001", clock, ipv6=True))
    packets.append(_udp_frame(Peer(SERVER6, SERVER6_MAC), 4001, Peer(CLIENT6, CLIENT6_MAC), 4000,
                              b"IPV6-UDP-REPLY-0001", clock, ipv6=True))

    # ICMPv6 echo exchange.
    packets.append(_icmpv6_frame(Peer(CLIENT6, CLIENT6_MAC), Peer(SERVER6, SERVER6_MAC),
                                 echo_reply=False, ident=0x1B1B, seq=1, clock=clock))
    packets.append(_icmpv6_frame(Peer(SERVER6, SERVER6_MAC), Peer(CLIENT6, CLIENT6_MAC),
                                 echo_reply=True, ident=0x1B1B, seq=1, clock=clock))
    return packets


def ipv6_capture(dest: Path | None = None) -> Path:
    """IPv6 TCP, IPv6 UDP and ICMPv6, plus a dual-stack IPv4 pair.

    Contents (15 packets):

    * IPv4 ICMP echo request/reply between ``10.0.0.10`` and ``10.0.0.20`` so
      ``ip.version`` **4** and **6** both appear in one file;
    * IPv6 TCP ``[2001:db8::10]:51000`` → ``[2001:db8::20]:8080`` — handshake,
      one payload each way, clean close;
    * IPv6 UDP ``[2001:db8::10]:4000`` ↔ ``[2001:db8::20]:4001`` (request and
      reply;
    * ICMPv6 echo request (type 128) / echo reply (type 129) between the same
      hosts.
    """
    return write_pcap(_output_path(dest, "ipv6"), _ipv6_packets())


# ---------------------------------------------------------------------------
# 7. Plain UDP
# ---------------------------------------------------------------------------

def _udp_packets(base: float = BASE_EPOCH) -> list[Packet]:
    """Build the plain-UDP capture's packet list (see :func:`udp_capture`)."""
    clock = _Clock(base, 0.05)
    packets: list[Packet] = []

    client_a = Peer(CLIENT_IP, CLIENT_MAC)
    client_b = Peer("10.0.0.11", "02:00:00:00:00:0b")
    client_c = Peer("10.0.0.12", "02:00:00:00:00:0c")
    server = Peer(HOST_B_IP, HOST_B_MAC)

    # Flow 1: 10.0.0.10:40000 <-> 10.0.0.30:40001, one datagram each way.
    packets.append(_udp_frame(client_a, 40000, server, 40001, b"UDP-FLOW-ONE-REQUEST", clock))
    packets.append(_udp_frame(server, 40001, client_a, 40000, b"UDP-FLOW-ONE-RESPONSE", clock))

    # Flow 2: 10.0.0.11:50000 -> 10.0.0.30:50001, two datagrams each way.
    packets.append(_udp_frame(client_b, 50000, server, 50001, b"UDP-FLOW-TWO-DATAGRAM-1", clock))
    packets.append(_udp_frame(client_b, 50000, server, 50001, b"UDP-FLOW-TWO-DATAGRAM-2", clock))
    packets.append(_udp_frame(server, 50001, client_b, 50000, b"UDP-FLOW-TWO-REPLY-1", clock))
    packets.append(_udp_frame(server, 50001, client_b, 50000, b"UDP-FLOW-TWO-REPLY-2", clock))

    # Flow 3: host-to-host 10.0.0.12:60000 <-> 10.0.0.13:60001.
    peer_d = Peer("10.0.0.13", "02:00:00:00:00:0d")
    packets.append(_udp_frame(client_c, 60000, peer_d, 60001, b"UDP-FLOW-THREE-PING", clock))
    packets.append(_udp_frame(peer_d, 60001, client_c, 60000, b"UDP-FLOW-THREE-PONG", clock))

    # Flow 4: single datagram to a rarely used port pair.
    packets.append(_udp_frame(client_c, 60002, server, 60003, b"UDP-FLOW-FOUR-SINGLE", clock))

    # Flow 5: larger datagram to exercise payload length handling.
    packets.append(_udp_frame(server, 61000, client_a, 61001, _fill(600, b"udp-flow-five"), clock))
    return packets


def udp_capture(dest: Path | None = None) -> Path:
    """Ten plain UDP datagrams over five distinct port pairs — **no DNS**.

    Contents: ``10.0.0.10:40000 ↔ 10.0.0.30:40001`` (one datagram each way),
    ``10.0.0.11:50000 → 10.0.0.30:50001`` (two each way),
    ``10.0.0.12:60000 ↔ 10.0.0.13:60001`` (one each way),
    ``10.0.0.12:60002 → 10.0.0.30:60003`` (single datagram), and a 600-byte
    datagram ``10.0.0.30:61000 → 10.0.0.10:61001``.

    Exercises: UDP conversation aggregation without DNS interference, uni- and
    bidirectional flows, and multi-datagram flows.
    """
    return write_pcap(_output_path(dest, "udp"), _udp_packets())


# ---------------------------------------------------------------------------
# 8. Retransmission / out-of-order / duplicate ACK
# ---------------------------------------------------------------------------

RETRANSMISSION_STREAM = 0
RT_CHUNK_A = b"CLIENT-SEGMENT-ONE;"
RT_CHUNK_B = b"CLIENT-SEGMENT-TWO;"
RT_CHUNK_C = b"CLIENT-SEGMENT-THREE;"
RT_CHUNK_D = b"CLIENT-SEGMENT-FOUR;"
RT_SERVER_CHUNK = b"SERVER-RESPONSE-ONE;"
#: Exactly what ``tshark -z follow,tcp,raw,0`` must report for node0 -> node1.
RT_EXPECTED_CLIENT_PAYLOAD: bytes = RT_CHUNK_A + RT_CHUNK_B + RT_CHUNK_C + RT_CHUNK_D
#: Exactly what it must report for node1 -> node0.
RT_EXPECTED_SERVER_PAYLOAD: bytes = RT_SERVER_CHUNK


def _retransmission_packets(base: float = BASE_EPOCH) -> list[Packet]:
    """Build the retransmission packet list (see the builder's docstring)."""
    clock = _Clock(base, 0.01)
    flow = TcpFlow((CLIENT_IP, CLIENT_MAC, 51000), (SERVER_IP, SERVER_MAC, HTTP_PORT), clock,
                   isn_client=0x11110000, isn_server=0x22220000)
    packets: list[Packet] = []
    packets += flow.handshake()

    base_seq = flow.isn_client + 1
    seq_b = base_seq + len(RT_CHUNK_A)
    seq_c = seq_b + len(RT_CHUNK_B)

    # 4: A in order (advances next_cseq to seq_b).
    packets.append(flow.data(True, RT_CHUNK_A))
    # 5: server ACKs A.
    packets.append(flow.ack(False))
    # 6: C arrives ahead of B (out-of-order: its seq jumps past the missing B).
    packets.append(flow.data(True, RT_CHUNK_C, seq=seq_c))
    # 7: duplicate ACK #1 — the server still wants B.
    packets.append(flow.ack(False, ack_value=seq_b))
    # 8: B fills the gap. An explicit seq is used so the segment is not counted
    #    twice, therefore the flow's own cursor is advanced by hand afterwards.
    packets.append(flow.data(True, RT_CHUNK_B, seq=seq_b))
    flow.next_cseq = seq_c + len(RT_CHUNK_C)
    # 9: server ACKs everything it now holds (ack = end of C).
    packets.append(flow.ack(False))
    # 10: B is retransmitted with identical bytes — reassembly must not duplicate.
    packets.append(flow.data(True, RT_CHUNK_B, seq=seq_b))
    # 11: duplicate ACK #2 (same ACK number as the previous server ACK).
    packets.append(flow.ack(False))
    # 12: D continues the stream.
    packets.append(flow.data(True, RT_CHUNK_D))
    # 13: server ACKs D.
    packets.append(flow.ack(False))
    # 14: server payload.
    packets.append(flow.data(False, RT_SERVER_CHUNK))
    # 15: client ACKs the server payload.
    packets.append(flow.ack(True))
    packets += flow.close()
    return packets


def retransmission_capture(dest: Path | None = None) -> Path:
    """One TCP stream with a retransmission, an out-of-order segment and dup ACKs.

    Stream 0 (``10.0.0.10:51000`` → ``10.0.0.20:80``) is built so the
    reassembled payload is exactly known:

    * **client → server must be** ``b"CLIENT-SEGMENT-ONE;" +
      b"CLIENT-SEGMENT-TWO;" + b"CLIENT-SEGMENT-THREE;" +
      b"CLIENT-SEGMENT-FOUR;"`` (79 bytes) — ``SEGMENT-THREE`` arrived before
      ``SEGMENT-TWO`` and must be reordered, and the retransmitted
      ``SEGMENT-TWO`` must **not** appear twice.
    * **server → client must be** ``b"SERVER-RESPONSE-ONE;"`` (20 bytes).

    Frame-by-frame: 1-3 handshake; 4 A; 5 ACK; 6 **C out of order**; 7
    **duplicate ACK #1**; 8 B (gap filled); 9 ACK; 10 **B retransmitted**;
    11 **duplicate ACK #2**; 12 D; 13 ACK; 14 server payload; 15 ACK; 16-19
    four-way close. 19 packets in total.

    :func:`expected` ``"retransmission"`` returns the exact byte strings.
    """
    return write_pcap(_output_path(dest, "retransmission"), _retransmission_packets())


# ---------------------------------------------------------------------------
# 9. Malformed / 10. empty / 11. truncated
# ---------------------------------------------------------------------------

MALFORMED_VALID_PACKETS = 3
MALFORMED_TRUNCATED_DECLARED = 200
MALFORMED_TRUNCATED_PRESENT = 20


def malformed_capture(dest: Path | None = None) -> Path:
    """Three valid packets, one garbage record, one truncated record.

    Layout of the file (classic little-endian pcap):

    1. a valid 24-byte global header;
    2. 3 valid Ethernet/IPv4/TCP frames (a handshake) that TShark reads
       normally;
    3. a record whose header is well formed but whose payload is 40 bytes of
       ``0xDD`` — TShark dissects it as Ethernet II with an unknown ethertype
       (malformed-ish content, valid framing);
    4. a record header declaring ``200`` bytes of captured data
       (``MALFORMED_TRUNCATED_DECLARED``) with only ``20`` bytes present, so
       TShark reports ``cut short in the middle of a packet``.

    The point is that the pipeline must not crash on any of it: at least the
    three valid frames are readable, the truncated tail is reported as an error
    by TShark, and the process still exits with a usable (possibly empty)
    partial result.
    """
    path = _output_path(dest, "malformed")
    packets = TcpFlow((CLIENT_IP, CLIENT_MAC, 51000), (SERVER_IP, SERVER_MAC, HTTP_PORT),
                      _Clock(BASE_EPOCH, 0.01)).handshake()
    blob = bytearray(pcap_bytes(packets))
    # Garbage record: correctly framed, nonsense bytes.
    garbage = b"\xdd" * 40
    blob += struct.pack("<IIII", int(BASE_EPOCH) + 10, 0, len(garbage), len(garbage)) + garbage
    # Truncated record: header claims 200 bytes, file ends after 20.
    blob += struct.pack("<IIII", int(BASE_EPOCH) + 11, 0, MALFORMED_TRUNCATED_DECLARED,
                        MALFORMED_TRUNCATED_DECLARED)
    blob += b"\x00" * MALFORMED_TRUNCATED_PRESENT
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(bytes(blob))
    return path


def empty_capture(dest: Path | None = None) -> Path:
    """A valid pcap file with a 24-byte global header and **zero** packets."""
    return write_pcap(_output_path(dest, "empty"), [])


TRUNCATED_PACKETS = 5
TRUNCATED_CUT_BYTES = 37


def _truncated_packets(base: float = BASE_EPOCH) -> list[Packet]:
    """Five frames: handshake, request, response — see the builder's docstring."""
    clock = _Clock(base, 0.01)
    flow = TcpFlow((CLIENT_IP, CLIENT_MAC, 51000), (SERVER_IP, SERVER_MAC, HTTP_PORT), clock,
                   isn_client=0x33330000, isn_server=0x44440000)
    packets = flow.handshake()
    packets.append(flow.data(True, _http_request("GET", "/truncated.html", "www.example.com",
                                                 headers=[("User-Agent", "ShadowPacketsTruncation/1.0")])))
    packets.append(flow.data(False, _http_response(200, "OK",
                                                   headers=[("Content-Type", "text/html")],
                                                   body=b"<html><body>truncated</body></html>\n")))
    return packets


def truncated_capture(dest: Path | None = None) -> Path:
    """A valid capture with its tail cut off **in the middle of a packet**.

    Five frames (SYN/SYN-ACK/ACK, ``GET /truncated.html``, its 200 response) are
    written normally, then the last ``TRUNCATED_CUT_BYTES`` (37) bytes are
    removed, so the final record header advertises more captured data than the
    file holds. TShark reports ``The file ... appears to have been cut short in
    the middle of a packet`` and the first four frames stay readable.

    Exercises: upload/parse error handling for damaged captures.
    """
    path = _output_path(dest, "truncated")
    blob = pcap_bytes(_truncated_packets())
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(blob[: len(blob) - TRUNCATED_CUT_BYTES])
    return path


# ---------------------------------------------------------------------------
# 12. HTTP object extraction
# ---------------------------------------------------------------------------

def http_object_request() -> bytes:
    """The exact ``GET`` request bytes sent in :func:`http_object_capture`."""
    return _http_request(
        "GET", HTTP_OBJECT_URI, HTTP_OBJECT_HOST,
        headers=[("User-Agent", "ShadowPacketsObjectTest/1.0"), ("Accept", "*/*")],
    )


def http_object_response() -> bytes:
    """The exact 200 response bytes (headers + body) of :func:`http_object_capture`."""
    return _http_response(
        200, "OK",
        headers=[("Content-Type", "application/octet-stream"), ("Connection", "close")],
        body=HTTP_OBJECT_BYTES,
    )


def _http_object_packets(base: float = BASE_EPOCH) -> list[Packet]:
    """Build the HTTP object capture's packet list.

    Frame layout (all on ``tcp.stream == 0``): 1-3 handshake, **4** request,
    **5** response carrying the object, 6-9 four-way close.
    """
    clock = _Clock(base, 0.01)
    flow = TcpFlow((CLIENT_IP, CLIENT_MAC, 51000), (SERVER_IP, SERVER_MAC, HTTP_PORT), clock,
                   isn_client=0x55550000, isn_server=0x66660000)
    packets = flow.handshake()
    packets.append(flow.data(True, http_object_request()))
    packets.append(flow.data(False, http_object_response()))
    packets += flow.close()
    return packets


def http_object_capture(dest: Path | None = None) -> Path:
    """One small HTTP object that ``tshark --export-objects http`` must extract.

    Contents: handshake, ``GET /objects/payload.bin`` (Host
    ``files.example.com``) → ``200 OK``, ``Content-Type:
    application/octet-stream`` and a 270-byte deterministic body. TShark writes
    it to ``payload.bin``; the byte content and SHA-256 are exposed through
    :func:`expected` ``"http_object"``.
    """
    return write_pcap(_output_path(dest, "http_object"), _http_object_packets())


# ---------------------------------------------------------------------------
# 13. Large capture
# ---------------------------------------------------------------------------

LARGE_DEFAULT_PACKETS = 20000
LARGE_SPAN_SECONDS = 1800.0
LARGE_SEED = 20240501
_LARGE_SRC_PORTS = 2000
_LARGE_DST_BUCKETS = 10


def _large_payload(index: int, size: int) -> bytes:
    return _fill(size, f"large-{index}".encode("ascii"))


def _large_packets(count: int, base: float = BASE_EPOCH) -> list[Frame | Packet]:
    """Build ``count`` packets over thousands of distinct port pairs.

    The list is built once and written once (:func:`write_pcap` assembles the
    whole image in memory) and almost every frame goes through the
    pre-serialised fast path, so the default 20000-packet capture is generated
    in about a second. Only the DNS packets use scapy, because their payload is
    a real wire-format DNS message.
    """
    if count <= 0:
        return []
    clock = _Clock(base, 0.0)
    rng = random.Random(LARGE_SEED)
    packets: list[Frame | Packet] = []
    server = Peer(SERVER_IP, SERVER_MAC)
    client = Peer(CLIENT_IP, CLIENT_MAC)

    for index in range(count):
        stamp = base + LARGE_SPAN_SECONDS * (index / count) + rng.random() * 0.05
        src_port = 20000 + (index % _LARGE_SRC_PORTS)
        dst_port = 30000 + ((index // _LARGE_SRC_PORTS) % _LARGE_DST_BUCKETS)
        forward = index % 2 == 0
        size = 40 + rng.randrange(0, 660)
        payload = _large_payload(index, size)
        kind = index % 20
        ip_id = (0x2000 + index) & 0xFFFF

        if kind in (0, 1):  # DNS query/response on port 53 (real wire format)
            name = f"host-{index:05d}.bulk.example.com"
            sport = 53000 + (index % 1000)
            dns_id = (index % 0xFFFF) or 1
            if kind == 0:
                packet: Frame | Packet = _net(
                    client, DNS_SERVER,
                    UDP(sport=sport, dport=DNS_PORT)
                    / DNS(id=dns_id, qr=0, rd=1, qd=DNSQR(qname=name, qtype="A")),
                    clock, ip_id=ip_id,
                )
            else:
                packet = _net(
                    DNS_SERVER, client,
                    UDP(sport=DNS_PORT, dport=sport)
                    / DNS(id=dns_id, qr=1, rd=1, ra=1, qd=DNSQR(qname=name, qtype="A"),
                          an=DNSRR(rrname=name, type="A", ttl=60, rdata="93.184.216.34")),
                    clock, ip_id=ip_id,
                )
        elif kind == 2:  # HTTP request on port 80
            sport = 20000 + (index % _LARGE_SRC_PORTS)
            packet = _raw_tcp_frame(
                client, sport, server, HTTP_PORT, 0x10000000 + index, 0,
                _TCP_PSH | _TCP_ACK,
                _http_request("GET", f"/bulk/{index}.html", "bulk.example.com",
                              headers=[("User-Agent", "ShadowPacketsBulk/1.0")]),
                stamp, ip_id=ip_id,
            )
        elif kind == 3:  # HTTP response on port 80
            sport = 20000 + (index % _LARGE_SRC_PORTS)
            body = f"<html><body>bulk object {index}</body></html>\n".encode("ascii")
            packet = _raw_tcp_frame(
                server, HTTP_PORT, client, sport, 0x20000000 + index, 0x10000000 + index,
                _TCP_PSH | _TCP_ACK,
                _http_response(200, "OK", headers=[("Content-Type", "text/html")], body=body),
                stamp, ip_id=ip_id,
            )
        elif kind in (4, 5, 6):  # TCP control packets on the generated pair
            flags = {4: _TCP_SYN, 5: _TCP_SYN | _TCP_ACK, 6: _TCP_FIN | _TCP_ACK}[kind]
            if forward:
                packet = _raw_tcp_frame(client, src_port, server, dst_port,
                                        0x30000000 + index, 0x40000000 + index, flags, b"",
                                        stamp, ip_id=ip_id)
            else:
                packet = _raw_tcp_frame(server, dst_port, client, src_port,
                                        0x40000000 + index, 0x30000000 + index, flags, b"",
                                        stamp, ip_id=ip_id)
        elif kind % 2:  # plain UDP
            if forward:
                packet = _raw_udp_frame(client, src_port, server, dst_port, payload, stamp,
                                        ip_id=ip_id)
            else:
                packet = _raw_udp_frame(server, dst_port, client, src_port, payload, stamp,
                                        ip_id=ip_id)
        else:  # plain TCP payload
            if forward:
                packet = _raw_tcp_frame(client, src_port, server, dst_port, 0x50000000 + index,
                                        0x60000000 + index, _TCP_PSH | _TCP_ACK, payload,
                                        stamp, ip_id=ip_id)
            else:
                packet = _raw_tcp_frame(server, dst_port, client, src_port, 0x50000000 + index,
                                        0x60000000 + index, _TCP_PSH | _TCP_ACK, payload,
                                        stamp, ip_id=ip_id)

        if isinstance(packet, Packet):  # Frames already carry their timestamp
            packet.time = stamp
        packets.append(packet)
    return packets


def large_capture(dest: Path | None = None, packets: int = LARGE_DEFAULT_PACKETS) -> Path:
    """A large, realistic capture for pagination, filters and performance tests.

    Default **20000 packets** spread over ``1800`` seconds (≈11 packets/s) with
    deterministic jitter. Port reuse is structured so that
    ``src_port = 20000 + (i % 2000)`` and
    ``dst_port = 30000 + ((i // 2000) % 10)``.

    Measured composition of the default capture (TShark): 11000 TCP packets,
    9000 UDP packets, 2000 ``http`` packets, 2000 ``dns`` packets, and
    **16300 distinct (ip, port) endpoint pairs** (9200 TCP + 7100 UDP) — several
    thousand distinct ports on each side, and one packet per most pairs.

    Per packet index ``i``: ``i % 20 == 0`` is a DNS query and ``== 1`` its
    response, ``== 2/3`` are an HTTP request and its 200 response, ``== 4/5/6``
    are TCP SYN / SYN-ACK / FIN-ACK, odd ``i`` is plain UDP and even ``i`` is
    plain TCP, carrying 40-700 deterministic payload bytes in either direction.

    ``packets`` is overridable for faster tests; the shape stays the same.
    Generation is a single pass over ``count`` packets followed by one file
    write and takes about a second for the default size.
    """
    return write_pcap(_output_path(dest, "large"), _large_packets(packets))


# ---------------------------------------------------------------------------
# 14. Combined
# ---------------------------------------------------------------------------

#: Section offsets inside :func:`combined_capture`, in seconds from ``BASE_EPOCH``.
COMBINED_SECTION_OFFSETS: dict[str, float] = {
    "http": 0.0,
    "dns": 600.0,
    "tls": 1200.0,
    "syn_scan": 1800.0,
    "ipv6": 2400.0,
}


def _combined_packets(base: float = BASE_EPOCH) -> list[Packet]:
    """Merge the HTTP, DNS, TLS, SYN-scan and IPv6 packet lists, time-sorted.

    Ports never collide between sections (HTTP 51000/51001, DNS 53000+,
    TLS 52000-52002, scan 40000+/45000), so per-protocol stream ids stay
    stable and the sections remain individually testable.
    """
    merged: list[Packet] = []
    merged += _http_packets(base + COMBINED_SECTION_OFFSETS["http"])
    merged += _dns_packets(base + COMBINED_SECTION_OFFSETS["dns"])
    merged += _tls_packets(base + COMBINED_SECTION_OFFSETS["tls"])
    merged += _syn_scan_packets(base + COMBINED_SECTION_OFFSETS["syn_scan"])
    merged += _ipv6_packets(base + COMBINED_SECTION_OFFSETS["ipv6"])
    merged.sort(key=lambda packet: float(packet.time))
    return merged


def combined_capture(dest: Path | None = None) -> Path:
    """One capture containing HTTP, DNS, TLS, a SYN scan and IPv6 traffic.

    Sections (offset from ``BASE_EPOCH``, see :data:`COMBINED_SECTION_OFFSETS`):
    the full HTTP capture at +0 s, DNS at +600 s, TLS (including the DER
    certificate) at +1200 s, the 40-port SYN scan at +1800 s and the IPv6 +
    dual-stack traffic at +2400 s. Packets are written sorted by time.

    Exercises: the whole analysis pipeline end to end on a single file —
    HTTP/DNS/TLS analyzers, host and conversation aggregation, detection rules
    and IPv4/IPv6 packets coexisting.
    """
    return write_pcap(_output_path(dest, "combined"), _combined_packets())


# ---------------------------------------------------------------------------
# registry / build-all
# ---------------------------------------------------------------------------

#: Registry of every capture: the key order matches the documented fixture
#: contract exactly (``http, dns, tls, syn_scan, failed_connections, ipv6, udp,
#: retransmission, http_object, combined, empty, malformed, truncated, large``),
#: and ``build_all()`` returns the same keys.
ALL_BUILDERS: dict[str, Callable[[Path | None], Path]] = {
    "http": http_capture,
    "dns": dns_capture,
    "tls": tls_capture,
    "syn_scan": syn_scan_capture,
    "arp_sweep": arp_sweep_capture,
    "failed_connections": failed_connections_capture,
    "ipv6": ipv6_capture,
    "udp": udp_capture,
    "retransmission": retransmission_capture,
    "http_object": http_object_capture,
    "combined": combined_capture,
    "empty": empty_capture,
    "malformed": malformed_capture,
    "truncated": truncated_capture,
    "large": lambda dest=None: large_capture(dest),
}


def build_all(dest: Path | None = None) -> dict[str, Path]:
    """Build every capture into ``dest`` (default :data:`TMP_ROOT`).

    Returns a stable ``{name: path}`` mapping matching :data:`ALL_BUILDERS`.
    Each builder is called exactly once, and the same call always produces the
    same bytes.
    """
    return {name: builder(dest) for name, builder in ALL_BUILDERS.items()}


def expected(capture_name: str) -> dict[str, Any]:
    """Documented expectations for a capture whose content is not obvious.

    Known names: ``"retransmission"``, ``"http"``, ``"http_object"``, ``"dns"``,
    ``"tls"``, ``"syn_scan"``, ``"failed_connections"``, ``"ipv6"``, ``"udp"``,
    ``"malformed"``, ``"empty"``, ``"truncated"``, ``"large"``, ``"combined"``.
    Every value is derived from the same constants the builders use, so a test
    can never drift from the generator.
    """
    try:
        factory = _EXPECTATIONS[capture_name]
    except KeyError:
        raise KeyError(
            f"no documented expectations for {capture_name!r}; "
            f"known names: {sorted(_EXPECTATIONS)}"
        ) from None
    return factory()


def _http_expectations() -> dict[str, Any]:
    """Expectations for :func:`http_capture`, derived from the built packets.

    ``transactions`` carries the exact request/response bytes, the ``tcp.stream``
    id and the 1-based frame numbers of both messages, so a test can assert on
    reassembled payloads without re-deriving anything. ``request_bytes`` /
    ``response_bytes`` are the ``/index.html`` pair for the common case.
    """
    _packets, records = _http_contents()
    first = next(record for record in records if record["uri"] == "/index.html")
    return {
        "file": "http.pcap",
        "streams": 2,
        "packets": len(_packets),
        "host": "www.example.com",
        "literal_ip_host": SERVER_IP,
        "client_ip": CLIENT_IP,
        "server_ip": SERVER_IP,
        "server_port": HTTP_PORT,
        # --- exact bytes of the first exchange, with its stream and frames ---
        "request_bytes": first["request"],
        "request_stream": first["stream"],
        "request_frame": first["request_frame"],
        "response_bytes": first["response"],
        "response_stream": first["stream"],
        "response_frame": first["response_frame"],
        # --- compact list (same order as `transactions`) ---------------------
        "requests": [
            {
                "stream": record["stream"],
                "method": record["method"],
                "uri": record["uri"],
                "status": record["status"],
            }
            for record in records
        ],
        # --- full transaction records ----------------------------------------
        "transactions": records,
        "streams_by_uri": {record["uri"]: record["stream"] for record in records},
        "login_body": b"username=admin&password=secret123",
        "pdf_filename": "report.pdf",
        "pdf_size": len(PDF_BYTES),
        "pdf_sha256": PDF_SHA256,
        "long_user_agent": _UA_LONG,
        "long_user_agent_length": len(_UA_LONG),
    }


def _dns_expectations() -> dict[str, Any]:
    return {
        "file": "dns.pcap",
        "packets": len(_dns_packets()),
        "queries": 5 + BURST_QUERIES,
        "resolver": DNS_IP,
        "client": CLIENT_IP,
        "burst_client": BURST_IP,
        "burst_client_queries": BURST_QUERIES,
        "resolver_answer": "93.184.216.34",
        "nxdomain_name": NXDOMAIN_DOMAIN,
        "nxdomain_rcode": 3,
        "long_label": LONG_LABEL,
        "long_label_length": len(LONG_LABEL),
        "long_label_domain": LONG_LABEL_DOMAIN,
        "multi_label_domain": MULTI_LABEL_DOMAIN,
        "multi_label_answers": ["93.184.216.34", "93.184.216.35", "203.0.113.10"],
        "txt_name": "txt.example.com",
        "txt_value": "v=spf1 -all",
        "burst_domain_first": BURST_DOMAIN_TEMPLATE.format(index=0),
        "burst_domain_last": BURST_DOMAIN_TEMPLATE.format(index=BURST_QUERIES - 1),
    }


def _tls_expectations() -> dict[str, Any]:
    return {
        "file": "tls.pcap",
        "packets": len(_tls_packets()),
        "streams": {"sni_and_cert": 0, "no_sni": 1, "alert": 2},
        "server_ip": SERVER_IP,
        "server_port": HTTPS_PORT,
        "sni": SNI_PRIMARY,
        "sni_alert_stream": SNI_ALERT,
        "alpn_offered": list(ALPN_OFFERS),
        "alpn_selected": ALPN_SELECTED,
        "client_version": "TLS 1.2",
        "cipher_suite_hex": "0xc02f",
        "cert_der": X509_DER,
        "cert_der_sha256": hashlib.sha256(X509_DER).hexdigest(),
        "cert_der_size": len(X509_DER),
        "cert_subject_cn": CERT_SUBJECT_CN,
        "cert_subject_ou": CERT_SUBJECT_OU,
        "cert_subject_o": CERT_SUBJECT_O,
        "cert_subject_c": CERT_SUBJECT_C,
        "cert_subject_serial_rdn": CERT_SUBJECT_SERIAL_RDN,
        "cert_subject_dn": CERT_SUBJECT_DN,
        # TShark prints UTCTime values as "2033-01-01 00:00:00 (UTC)"; the
        # raw DER values are the strings below.
        "cert_not_before": "2023-01-01 00:00:00 (UTC)",
        "cert_not_after": "2033-01-01 00:00:00 (UTC)",
        "cert_not_before_der": CERT_NOT_BEFORE,
        "cert_not_after_der": CERT_NOT_AFTER,
        "cert_serial": CERT_SERIAL_TEXT,
        "alert": "fatal/handshake_failure (level 2, description 40)",
    }


def _retransmission_expectations() -> dict[str, Any]:
    return {
        "file": "retransmission.pcap",
        "stream_id": RETRANSMISSION_STREAM,
        "packets": len(_retransmission_packets()),
        "client_payload": RT_EXPECTED_CLIENT_PAYLOAD,
        "client_payload_hex": RT_EXPECTED_CLIENT_PAYLOAD.hex(),
        "client_payload_size": len(RT_EXPECTED_CLIENT_PAYLOAD),
        "server_payload": RT_EXPECTED_SERVER_PAYLOAD,
        "server_payload_hex": RT_EXPECTED_SERVER_PAYLOAD.hex(),
        "server_payload_size": len(RT_EXPECTED_SERVER_PAYLOAD),
        "retransmitted_chunk": RT_CHUNK_B,
        "out_of_order_chunk": RT_CHUNK_C,
        "frames": {
            "handshake": [1, 2, 3],
            "chunk_a": 4,
            "ack_a": 5,
            "out_of_order_c": 6,
            "duplicate_ack_1": 7,
            "chunk_b": 8,
            "ack_ab_c": 9,
            "retransmitted_b": 10,
            "duplicate_ack_2": 11,
            "chunk_d": 12,
            "ack_d": 13,
            "server_payload": 14,
            "ack_server_payload": 15,
            "close": [16, 17, 18, 19],
        },
    }


def _http_object_expectations() -> dict[str, Any]:
    return {
        "file": "http_object.pcap",
        "packets": len(_http_object_packets()),
        "host": HTTP_OBJECT_HOST,
        "uri": HTTP_OBJECT_URI,
        "exported_filename": HTTP_OBJECT_FILENAME,
        "content_type": "application/octet-stream",
        "size": len(HTTP_OBJECT_BYTES),
        "sha256": HTTP_OBJECT_SHA256,
        "bytes": HTTP_OBJECT_BYTES,
        # --- exact wire bytes, so tests never re-derive them ------------------
        "stream_id": 0,
        "request_bytes": http_object_request(),
        "request_frame": 4,
        "response_bytes": http_object_response(),
        "response_frame": 5,
    }


def _arp_sweep_expectations() -> dict[str, Any]:
    return {
        "file": "arp_sweep.pcap",
        "packets": len(_arp_sweep_packets()),
        "sweeper": SCANNER_IP,
        "targets": list(ARP_SWEEP_TARGETS),
        "probed": len(ARP_SWEEP_TARGETS),
        "answered": len(ARP_SWEEP_LIVE),
        "unanswered": len(ARP_SWEEP_TARGETS) - len(ARP_SWEEP_LIVE),
        "arp_requests": len(ARP_SWEEP_TARGETS) + 1,
        "arp_replies": len(ARP_SWEEP_LIVE) + 1,
        "tcp_frames": 0,
    }


def _syn_scan_expectations() -> dict[str, Any]:
    return {
        "file": "syn_scan.pcap",
        "packets": len(_syn_scan_packets()),
        "scanner": SCANNER_IP,
        "target": SERVER_IP,
        "ports": list(SCAN_PORTS),
        "distinct_dst_ports": len(set(SCAN_PORTS)),
        # 40 probes; TShark's "tcp.flags.syn == 1 && tcp.flags.ack == 0" filter
        # matches 41 frames because the contrast handshake also starts with a
        # SYN-only packet.
        "scan_syn_only_packets": len(SCAN_PORTS),
        "syn_only_packets": len(SCAN_PORTS) + 1,
        "syn_ack_packets": 1,
        "completed_handshake_port": HTTP_PORT,
        "completed_handshake_uri": "/scan-contrast",
    }


def _failed_connections_expectations() -> dict[str, Any]:
    return {
        "file": "failed_connections.pcap",
        "packets": len(_failed_connections_packets()),
        "client": SCANNER_IP,
        "server": SERVER_IP,
        "dst_port": FAILED_CONNECTION_PORT,
        "attempts": FAILED_CONNECTION_ATTEMPTS,
        "syn_packets": 2 * FAILED_CONNECTION_ATTEMPTS,
        "syn_ack_packets": 0,
    }


def _ipv6_expectations() -> dict[str, Any]:
    return {
        "file": "ipv6.pcap",
        "packets": len(_ipv6_packets()),
        "client6": CLIENT6,
        "server6": SERVER6,
        "tcp_port": 8080,
        "udp_ports": (4000, 4001),
        "icmpv6_echo_id": 0x1B1B,
        "ipv4_pair": (CLIENT_IP, SERVER_IP),
    }


def _udp_expectations() -> dict[str, Any]:
    return {
        "file": "udp.pcap",
        "packets": len(_udp_packets()),
        "flows": [
            ("10.0.0.10", 40000, "10.0.0.30", 40001),
            ("10.0.0.11", 50000, "10.0.0.30", 50001),
            ("10.0.0.12", 60000, "10.0.0.13", 60001),
            ("10.0.0.12", 60002, "10.0.0.30", 60003),
            ("10.0.0.30", 61000, "10.0.0.10", 61001),
        ],
        "dns_packets": 0,
    }


def _malformed_expectations() -> dict[str, Any]:
    return {
        "file": "malformed.pcap",
        "valid_packets": MALFORMED_VALID_PACKETS,
        "garbage_record_bytes": 40,
        "truncated_declared_bytes": MALFORMED_TRUNCATED_DECLARED,
        "truncated_present_bytes": MALFORMED_TRUNCATED_PRESENT,
    }


def _empty_expectations() -> dict[str, Any]:
    return {"file": "empty.pcap", "packets": 0, "file_size": 24}


def _truncated_expectations() -> dict[str, Any]:
    return {
        "file": "truncated.pcap",
        "full_packets": TRUNCATED_PACKETS,
        "cut_bytes": TRUNCATED_CUT_BYTES,
        "readable_packets": TRUNCATED_PACKETS - 1,
    }


def _large_expectations() -> dict[str, Any]:
    return {
        "file": "large.pcap",
        "packets": LARGE_DEFAULT_PACKETS,
        "span_seconds": LARGE_SPAN_SECONDS,
        # Measured with TShark on the default capture.
        "tcp_packets": 11000,
        "udp_packets": 9000,
        "http_packets": 2000,
        "dns_packets": 2000,
        "distinct_endpoint_pairs": 16300,
        "distinct_tcp_endpoint_pairs": 9200,
        "distinct_udp_endpoint_pairs": 7100,
        "src_port_range": (20000, 20000 + _LARGE_SRC_PORTS - 1),
        "dst_port_range": (30000, 30000 + _LARGE_DST_BUCKETS - 1),
        "seed": LARGE_SEED,
    }


def _combined_expectations() -> dict[str, Any]:
    return {
        "file": "combined.pcap",
        "packets": len(_combined_packets()),
        "section_offsets": dict(COMBINED_SECTION_OFFSETS),
        "sections": {
            "http": len(_http_packets()),
            "dns": len(_dns_packets()),
            "tls": len(_tls_packets()),
            "syn_scan": len(_syn_scan_packets()),
            "ipv6": len(_ipv6_packets()),
        },
        "tls_cert_der_sha256": hashlib.sha256(X509_DER).hexdigest(),
        "http_object_sha256": HTTP_OBJECT_SHA256,
    }


_EXPECTATIONS: dict[str, Callable[[], dict[str, Any]]] = {
    "http": _http_expectations,
    "dns": _dns_expectations,
    "tls": _tls_expectations,
    "syn_scan": _syn_scan_expectations,
    "arp_sweep": _arp_sweep_expectations,
    "failed_connections": _failed_connections_expectations,
    "ipv6": _ipv6_expectations,
    "udp": _udp_expectations,
    "retransmission": _retransmission_expectations,
    "malformed": _malformed_expectations,
    "empty": _empty_expectations,
    "truncated": _truncated_expectations,
    "http_object": _http_object_expectations,
    "large": _large_expectations,
    "combined": _combined_expectations,
}
