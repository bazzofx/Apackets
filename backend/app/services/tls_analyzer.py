"""TLS session metadata.

TLS payloads are **not** decrypted: this module records what TShark dissects from
the handshake, plus the built-in JA3/JA3S/JA4 fingerprints (TShark 4.6.8 computes
them itself). A version, SNI, ALPN or certificate value that TShark did not decode
is left NULL - never guessed.

Sessions are grouped by ``tcp.stream``; the client is the peer that sent the
ClientHello. When no ClientHello was captured the client/server columns stay NULL
and the handshake status records what was actually seen.
"""

from __future__ import annotations

import json
import sqlite3
import time
from dataclasses import dataclass, field
from pathlib import Path

from app.core.logging import get_logger
from app.db import database as db
from app.services import tshark
from app.services.jobs import JobContext

log = get_logger("shadowpackets.tls")

# Column order of the INSERT below - keep the two in sync.
COLUMNS: tuple[str, ...] = (
    "analysis_id",
    "stream_id",
    "client_ip",
    "client_port",
    "server_ip",
    "server_port",
    "client_packet",
    "server_packet",
    "time_epoch",
    "client_version",
    "server_version",
    "version",
    "sni",
    "alpn",
    "selected_alpn",
    "cipher_suite",
    "ja3",
    "ja3_full",
    "ja3s",
    "ja4",
    "cert_subject",
    "cert_issuer",
    "cert_not_before",
    "cert_not_after",
    "cert_serial",
    "handshake_status",
    "alert",
    "record_count",
    "flags",
)

# ``tls.handshake.extensions.supported_version`` is used in addition to the
# required fields because a TLS 1.3 ClientHello carries the legacy 0x0303 in
# ``tls.handshake.version``; the extension value is the real one.
_TSHARK_FIELDS: tuple[str, ...] = (
    "frame.number",
    "frame.time_epoch",
    "tcp.stream",
    "ip.src",
    "tcp.srcport",
    "ip.dst",
    "tcp.dstport",
    "tls.handshake.type",
    "tls.handshake.extensions_server_name",
    "tls.handshake.version",
    "tls.handshake.extensions_alpn_str",
    "tls.handshake.ciphersuite",
    "tls.record.version",
    "tls.alert_message.desc",
    "tls.handshake.ja3",
    "tls.handshake.ja3_full",
    "tls.handshake.ja3s",
    "tls.handshake.ja4",
    "tls.handshake.extensions.supported_version",
    "x509sat.uTF8String",
    "x509ce.dNSName",
    "x509af.serialNumber",
    "x509af.utcTime",
    "x509af.generalizedTime",
    "x509af.issuer",
    "x509af.subject",
)

INSERT_SQL = (
    f"INSERT INTO tls_sessions ({', '.join(COLUMNS)}) "
    f"VALUES ({', '.join('?' for _ in COLUMNS)})"
)

BATCH_SIZE = 1000
CANCEL_EVERY = 5000
FIELD_SEPARATOR = "\x1f"

CLIENT_HELLO = 1
SERVER_HELLO = 2
CERTIFICATE = 11

# Numeric TLS/SSL version -> display string.
VERSION_NAMES = {
    0x0002: "SSL 3.0",
    0x0301: "TLS 1.0",
    0x0302: "TLS 1.1",
    0x0303: "TLS 1.2",
    0x0304: "TLS 1.3",
}

LEGACY_VERSIONS = {"SSL 3.0", "TLS 1.0"}

STATUS_COMPLETE = "complete"
STATUS_CLIENT_ONLY = "client_hello_only"
STATUS_SERVER_ONLY = "server_hello_only"
STATUS_ALERT = "alert"
STATUS_UNKNOWN = "unknown"

# --------------------------------------------------------------------------
# parsing helpers
# --------------------------------------------------------------------------

def _split(value: str | None) -> list[str]:
    if not value:
        return []
    return [part.strip() for part in value.split(FIELD_SEPARATOR) if part.strip()]


def _first(value: str | None) -> str | None:
    parts = _split(value)
    return parts[0] if parts else None


def _int(value: str | None) -> int | None:
    if value is None or not value.strip():
        return None
    try:
        return int(value.strip(), 0)
    except ValueError:
        try:
            return int(float(value.strip()))
        except ValueError:
            return None


def _float(value: str | None) -> float | None:
    if value is None or not value.strip():
        return None
    try:
        return float(value.strip())
    except ValueError:
        return None


def version_name(raw: str | None) -> str | None:
    """Map a TShark version value onto its display string.

    ``0x0303`` -> ``TLS 1.2``; an already-decoded string is kept as-is; an
    unknown numeric value is shown as its raw hexadecimal form.
    """
    value = _first(raw)
    if value is None:
        return None
    number = _int(value)
    if number is None:
        return value
    if number in VERSION_NAMES:
        return VERSION_NAMES[number]
    return f"0x{number:04x}"


def best_version(values: list[str]) -> str | None:
    """Highest *known* TLS version out of an offered list; NULL when unknown.

    Unknown/GREASE values are ignored rather than reported as a version.
    """
    known = [number for number in (_int(value) for value in values)
             if number is not None and number in VERSION_NAMES]
    if not known:
        return None
    return VERSION_NAMES[max(known)]


@dataclass
class TlsFrame:
    """One TShark row for a TLS frame."""

    packet: int
    time_epoch: float | None = None
    stream_id: int | None = None
    src_ip: str | None = None
    src_port: int | None = None
    dst_ip: str | None = None
    dst_port: int | None = None
    handshake_types: list[int] = field(default_factory=list)
    server_name: str | None = None
    handshake_version: str | None = None
    supported_versions: list[str] = field(default_factory=list)
    alpn: list[str] = field(default_factory=list)
    cipher_suites: list[str] = field(default_factory=list)
    record_versions: list[str] = field(default_factory=list)
    alerts: list[str] = field(default_factory=list)
    ja3: str | None = None
    ja3_full: str | None = None
    ja3s: str | None = None
    ja4: str | None = None
    serials: list[str] = field(default_factory=list)
    times: list[str] = field(default_factory=list)
    subjects: list[str] = field(default_factory=list)
    issuers: list[str] = field(default_factory=list)
    dns_names: list[str] = field(default_factory=list)
    record_count: int = 0

    def has(self, handshake_type: int) -> bool:
        return handshake_type in self.handshake_types

    @property
    def carries_certificate(self) -> bool:
        return self.has(CERTIFICATE) or bool(self.serials)


@dataclass
class TlsSession:
    """A persisted ``tls_sessions`` row."""

    stream_id: int | None = None
    client_ip: str | None = None
    client_port: int | None = None
    server_ip: str | None = None
    server_port: int | None = None
    client_packet: int | None = None
    server_packet: int | None = None
    time_epoch: float | None = None
    client_version: str | None = None
    server_version: str | None = None
    version: str | None = None
    sni: str | None = None
    alpn: str | None = None
    selected_alpn: str | None = None
    cipher_suite: str | None = None
    ja3: str | None = None
    ja3_full: str | None = None
    ja3s: str | None = None
    ja4: str | None = None
    cert_subject: str | None = None
    cert_issuer: str | None = None
    cert_not_before: str | None = None
    cert_not_after: str | None = None
    cert_serial: str | None = None
    handshake_status: str = STATUS_UNKNOWN
    alert: str | None = None
    record_count: int = 0
    flags: list[str] = field(default_factory=list)


def _build_frame(fields: list[str]) -> TlsFrame | None:
    if len(fields) < len(_TSHARK_FIELDS):
        fields = [*fields, *([""] * (len(_TSHARK_FIELDS) - len(fields)))]

    (
        number, time_epoch, stream_id, src_ip, src_port, dst_ip, dst_port,
        handshake_type, server_name, handshake_version, alpn, cipher_suites,
        record_versions, alerts, ja3, ja3_full, ja3s, ja4, supported_versions,
        utf8_strings, dns_names, serials, utc_times, generalized_times,
        issuers, subjects,
    ) = fields[: len(_TSHARK_FIELDS)]

    packet = _int(number)
    if packet is None:
        return None

    types = [value for value in (_int(v) for v in _split(handshake_type)) if value is not None]
    records = _split(record_versions)

    frame = TlsFrame(
        packet=packet,
        time_epoch=_float(time_epoch),
        stream_id=_int(stream_id),
        src_ip=_first(src_ip),
        src_port=_int(_first(src_port)),
        dst_ip=_first(dst_ip),
        dst_port=_int(_first(dst_port)),
        handshake_types=types,
        server_name=_first(server_name),
        handshake_version=_first(handshake_version),
        supported_versions=_split(supported_versions),
        alpn=_split(alpn),
        cipher_suites=_split(cipher_suites),
        record_versions=records,
        alerts=_split(alerts),
        ja3=_first(ja3),
        ja3_full=_first(ja3_full),
        ja3s=_first(ja3s),
        ja4=_first(ja4),
        serials=_split(serials),
        times=[*_split(utc_times), *_split(generalized_times)],
        subjects=_split(subjects),
        issuers=_split(issuers),
        dns_names=_split(dns_names),
        record_count=len(records),
    )
    if not frame.handshake_types and not records and not frame.alerts:
        return None  # nothing TLS-specific in this frame
    return frame

def collect_frames(capture_path: Path, ctx: JobContext) -> list[TlsFrame]:
    """Stream every TLS frame in capture order."""
    frames: list[TlsFrame] = []
    scanned = 0
    for fields in tshark.stream_fields(
        capture_path,
        _TSHARK_FIELDS,
        display_filter="tls",
        occurrence="a",
        aggregator=FIELD_SEPARATOR,
        cancel_event=ctx.cancel_event,
    ):
        scanned += 1
        try:
            frame = _build_frame(fields)
        except Exception as exc:  # a malformed row must never abort the analysis
            log.debug("skipping malformed tls row: %s", exc)
            frame = None
        if frame is not None:
            frames.append(frame)
        if scanned % CANCEL_EVERY == 0:
            ctx.check_cancelled()
            ctx.set_stage(f"Analyzing TLS ({scanned:,} packets)")
    frames.sort(key=lambda frame: frame.packet)
    return frames


def _looks_like_time(value: str) -> bool:
    """TShark renders a validity time as ``YYYY-MM-DD HH:MM:SS (UTC)``.

    Values it cannot represent (it prints ``Not representable``) are dropped
    rather than stored as a timestamp.
    """
    return len(value) >= 19 and value[:4].isdigit() and value[4] == "-"


def _dn(values: list[str]) -> str | None:
    """First real distinguished name, ignoring ASN.1 CHOICE indices.

    TShark 4.6.8 exposes ``x509af.subject``/``x509af.issuer`` as the numeric index
    of the selected CHOICE alternative (``0`` = rdnSequence), which is not a name;
    those values are dropped so the column stays NULL instead of holding "0".
    """
    for value in values:
        if value.isdigit():
            continue
        return value
    return None


def build_sessions(frames: list[TlsFrame]) -> list[TlsSession]:
    """Group TLS frames by ``tcp.stream`` into one session row each."""
    grouped: dict[int | None, list[TlsFrame]] = {}
    for frame in frames:
        grouped.setdefault(frame.stream_id, []).append(frame)

    sessions = [_session_from(stream_id, group) for stream_id, group in grouped.items()]
    sessions.sort(key=lambda session: session.time_epoch or 0.0)
    return sessions


def _session_from(stream_id: int | None, group: list[TlsFrame]) -> TlsSession:
    session = TlsSession(stream_id=stream_id, time_epoch=group[0].time_epoch)
    session.record_count = sum(frame.record_count for frame in group)

    client_frame = next((f for f in group if f.has(CLIENT_HELLO)), None)
    server_frame = next((f for f in group if f.has(SERVER_HELLO)), None)
    cert_frames = [f for f in group if f.carries_certificate]

    if client_frame is not None:
        # The client is the peer that sent the ClientHello.
        session.client_ip = client_frame.src_ip
        session.client_port = client_frame.src_port
        session.server_ip = client_frame.dst_ip
        session.server_port = client_frame.dst_port
        session.client_packet = client_frame.packet
        session.time_epoch = client_frame.time_epoch
        session.sni = client_frame.server_name
        session.ja3 = client_frame.ja3
        session.ja3_full = client_frame.ja3_full
        session.ja4 = client_frame.ja4
        session.client_version = (
            best_version(client_frame.supported_versions)
            or version_name(client_frame.handshake_version)
        )
    # Without a ClientHello nothing identifies the client, so those columns stay
    # NULL rather than being guessed from the packet direction.

    if server_frame is not None:
        session.server_packet = server_frame.packet
        session.server_version = (
            best_version(server_frame.supported_versions)
            or version_name(server_frame.handshake_version)
        )
        session.ja3s = server_frame.ja3s
        if server_frame.cipher_suites:
            session.cipher_suite = server_frame.cipher_suites[0]
        if server_frame.alpn:
            session.selected_alpn = server_frame.alpn[0]

    session.version = session.server_version or session.client_version

    offered = client_frame.alpn if client_frame is not None else []
    if not offered and server_frame is not None:
        offered = server_frame.alpn
    if offered:
        session.alpn = ",".join(offered)

    if cert_frames:
        for frame in cert_frames:
            if frame.serials:
                session.cert_serial = frame.serials[0]  # leaf certificate comes first
                break
        times = [t for frame in cert_frames for t in frame.times if _looks_like_time(t)]
        if times:
            # TShark renders validity times as "YYYY-MM-DD HH:MM:SS (UTC)", which
            # sorts lexicographically; the earliest is notBefore, latest notAfter.
            session.cert_not_before = min(times)
            session.cert_not_after = max(times)
        session.cert_subject = _dn([v for frame in cert_frames for v in frame.subjects])
        session.cert_issuer = _dn([v for frame in cert_frames for v in frame.issuers])

    session.alert = _alert_text(group)
    session.handshake_status = _handshake_status(client_frame, server_frame, session.alert)
    session.flags = compute_flags(session, client_frame, cert_frames)
    return session


def _alert_text(group: list[TlsFrame]) -> str | None:
    seen: list[str] = []
    for frame in group:
        for value in frame.alerts:
            if value not in seen:
                seen.append(value)
    return ",".join(seen) if seen else None


def _handshake_status(
    client_frame: TlsFrame | None, server_frame: TlsFrame | None, alert: str | None
) -> str:
    if client_frame is not None and server_frame is not None:
        return STATUS_COMPLETE
    if alert is not None:
        return STATUS_ALERT
    if client_frame is not None:
        return STATUS_CLIENT_ONLY
    if server_frame is not None:
        return STATUS_SERVER_ONLY
    return STATUS_UNKNOWN


def compute_flags(
    session: TlsSession, client_frame: TlsFrame | None, cert_frames: list[TlsFrame]
) -> list[str]:
    """Investigative leads - never a verdict."""
    flags: list[str] = []

    if client_frame is not None and not session.sni:
        flags.append(
            "sni_absent:no SNI in the ClientHello "
            "(an encrypted ClientHello or a non-SNI client may explain this)"
        )
    if client_frame is not None and not cert_frames:
        flags.append("no_certificate")
    if session.version in LEGACY_VERSIONS:
        flags.append("tls10_or_older")
    if session.cert_subject and session.cert_issuer and session.cert_subject == session.cert_issuer:
        flags.append("self_signed_suspected")
    if session.alert is not None:
        flags.append("alert")
    if session.handshake_status != STATUS_COMPLETE:
        flags.append("incomplete_handshake")
    return flags

# --------------------------------------------------------------------------
# persistence
# --------------------------------------------------------------------------

def to_sql_row(analysis_id: str, session: TlsSession) -> tuple:
    return (
        analysis_id,
        session.stream_id,
        session.client_ip,
        session.client_port,
        session.server_ip,
        session.server_port,
        session.client_packet,
        session.server_packet,
        session.time_epoch,
        session.client_version,
        session.server_version,
        session.version,
        session.sni,
        session.alpn,
        session.selected_alpn,
        session.cipher_suite,
        session.ja3,
        session.ja3_full,
        session.ja3s,
        session.ja4,
        session.cert_subject,
        session.cert_issuer,
        session.cert_not_before,
        session.cert_not_after,
        session.cert_serial,
        session.handshake_status,
        session.alert,
        session.record_count,
        json.dumps(session.flags, separators=(",", ":")),
    )


def analyze(ctx: JobContext, analysis_id: str, capture_path: Path) -> dict:
    """Extract TLS session metadata from ``capture_path`` and persist it."""
    started = time.monotonic()
    ctx.set_stage("Analyzing TLS")

    with db.get_conn() as conn:
        conn.execute("DELETE FROM tls_sessions WHERE analysis_id = ?", (analysis_id,))

    frames = collect_frames(capture_path, ctx)
    ctx.check_cancelled()
    sessions = build_sessions(frames)

    conn: sqlite3.Connection = db.connect()
    inserted = 0
    try:
        conn.execute("BEGIN")
        buffer: list[tuple] = []
        for session in sessions:
            buffer.append(to_sql_row(analysis_id, session))
            if len(buffer) >= BATCH_SIZE:
                conn.executemany(INSERT_SQL, buffer)
                inserted += len(buffer)
                buffer.clear()
                conn.commit()
                conn.execute("BEGIN")
                ctx.check_cancelled()
        if buffer:
            conn.executemany(INSERT_SQL, buffer)
            inserted += len(buffer)
            buffer.clear()
        conn.commit()
    finally:
        conn.close()

    counters = _counters(analysis_id, inserted)
    elapsed = time.monotonic() - started
    log.info("tls analysis for %s: %s in %.1fs", analysis_id, counters, elapsed)
    return {**counters, "tls_frames": len(frames), "seconds": round(elapsed, 2)}


def _counters(analysis_id: str, sessions: int) -> dict:
    row = db.query_one(
        """
        SELECT
            SUM(CASE WHEN handshake_status = 'complete' THEN 1 ELSE 0 END) AS complete,
            SUM(CASE WHEN sni IS NOT NULL AND sni <> '' THEN 1 ELSE 0 END) AS with_sni,
            SUM(CASE WHEN alert IS NOT NULL THEN 1 ELSE 0 END)             AS alerts,
            SUM(CASE WHEN flags IS NOT NULL AND flags <> '[]' THEN 1 ELSE 0 END) AS flagged
        FROM tls_sessions
        WHERE analysis_id = ?
        """,
        (analysis_id,),
    )
    data = dict(row) if row else {}
    return {
        "tls_sessions": sessions,
        "tls_complete": int(data.get("complete") or 0),
        "tls_with_sni": int(data.get("with_sni") or 0),
        "tls_alerts": int(data.get("alerts") or 0),
        "tls_flagged": int(data.get("flagged") or 0),
    }


__all__ = [
    "COLUMNS",
    "TlsFrame",
    "TlsSession",
    "VERSION_NAMES",
    "analyze",
    "best_version",
    "build_sessions",
    "collect_frames",
    "compute_flags",
    "to_sql_row",
    "version_name",
]
