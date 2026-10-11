"""HTTP request/response transaction analysis.

A single packet carries either a request or a response, so transactions are built
per ``tcp.stream``: a request frame opens a pending transaction and the next
response on that stream closes it. Keep-alive streams therefore produce one
transaction per request, and a request with no observed response keeps
``response_packet`` NULL - a status is never invented.

Headers come from TShark's ``http.request.line`` / ``http.response.line`` fields
aggregated with an ASCII unit-separator (a comma would collide with real header
values). Bodies are read from TShark's authoritative stream reassembly
(``-z follow,tcp,raw``), split per HTTP message and decoded only when the
resulting byte counts match the observed transactions.
"""

from __future__ import annotations

import ipaddress
import json
import re
import sqlite3
import time
from dataclasses import dataclass, field
from pathlib import Path

from app.core.config import settings
from app.core.logging import get_logger
from app.db import database as db
from app.services import tshark
from app.services.jobs import JobContext

log = get_logger("apackets.http")

# Column order of the INSERT below - keep the two in sync.
COLUMNS: tuple[str, ...] = (
    "analysis_id",
    "stream_id",
    "request_packet",
    "response_packet",
    "time_epoch",
    "response_time",
    "client_ip",
    "client_port",
    "server_ip",
    "server_port",
    "method",
    "host",
    "uri",
    "full_uri",
    "version",
    "status_code",
    "status_text",
    "user_agent",
    "referer",
    "content_type",
    "server_header",
    "request_len",
    "response_len",
    "request_headers",
    "response_headers",
    "request_body",
    "response_body",
    "request_body_size",
    "response_body_size",
    "response_body_truncated",
    "flags",
)

_TSHARK_FIELDS: tuple[str, ...] = (
    "frame.number",
    "frame.time_epoch",
    "tcp.stream",
    "ip.src",
    "tcp.srcport",
    "ip.dst",
    "tcp.dstport",
    "http.request.method",
    "http.request.uri",
    "http.request.version",
    "http.host",
    "http.response.code",
    "http.response.phrase",
    "http.user_agent",
    "http.referer",
    "http.content_type",
    "http.server",
    "http.content_length",
    "http.request.full_uri",
)

_LINE_FIELDS: tuple[str, ...] = (
    "frame.number",
    "http.request.line",
    "http.response.line",
)

INSERT_SQL = (
    f"INSERT INTO http_transactions ({', '.join(COLUMNS)}) "
    f"VALUES ({', '.join('?' for _ in COLUMNS)})"
)

BATCH_SIZE = 1000
CANCEL_EVERY = 5000

# TShark's aggregator takes a single character; \x1f cannot occur in a header.
HEADER_SEPARATOR = "\x1f"
# TShark escapes CR/LF inside field values as the two-character sequence below.
_LINE_END = "\\r\\n"

COMMON_METHODS = {"GET", "POST", "HEAD", "OPTIONS", "PUT", "DELETE", "PATCH"}

SUSPICIOUS_PATH_PATTERNS = (
    "../", "/etc/passwd", "cmd=", "exec", "eval", ".php?", "union select",
    "<script", "/admin", "/shell", "wget ", "curl ",
)

CREDENTIAL_KEYWORDS = (
    "password", "passwd", "pwd", "pass=", "token=", "api_key", "apikey",
    "secret", "authorization:", "user=",
)

TOOL_USER_AGENTS = (
    "sqlmap", "nikto", "nmap", "masscan", "curl", "wget", "python-requests",
    "go-http-client", "hydra", "dirbuster", "gobuster",
)

_BINARY_TYPE_PREFIXES = ("image/", "audio/", "video/", "font/")
_BINARY_TYPES = {
    "application/octet-stream", "application/zip", "application/gzip",
    "application/x-gzip", "application/x-7z-compressed", "application/x-rar-compressed",
    "application/x-tar", "application/x-bzip2", "application/pdf", "application/wasm",
    "application/x-dosexec", "application/x-msdownload", "application/x-executable",
}

_CONTENT_LENGTH_RE = re.compile(rb"^content-length\s*:\s*(\d+)", re.IGNORECASE)
_TRANSFER_ENCODING_RE = re.compile(rb"^transfer-encoding\s*:\s*(.+)$", re.IGNORECASE)
_STATUS_RE = re.compile(rb"^HTTP/\d\.\d\s+(\d{3})")

@dataclass
class HttpFrame:
    """One TShark HTTP row (either a request frame or a response frame)."""

    packet: int
    time_epoch: float | None = None
    stream_id: int | None = None
    src_ip: str | None = None
    src_port: int | None = None
    dst_ip: str | None = None
    dst_port: int | None = None
    method: str | None = None
    uri: str | None = None
    version: str | None = None
    host: str | None = None
    full_uri: str | None = None
    status_code: int | None = None
    status_text: str | None = None
    user_agent: str | None = None
    referer: str | None = None
    content_type: str | None = None
    server_header: str | None = None
    content_length: int | None = None
    request_headers: dict[str, str] = field(default_factory=dict)
    response_headers: dict[str, str] = field(default_factory=dict)

    @property
    def is_request(self) -> bool:
        return self.method is not None

    @property
    def is_response(self) -> bool:
        return self.status_code is not None


@dataclass
class Transaction:
    """A persisted ``http_transactions`` row."""

    stream_id: int | None = None
    request: HttpFrame | None = None
    response: HttpFrame | None = None
    request_len: int | None = None
    response_len: int | None = None
    request_body: str | None = None
    response_body: str | None = None
    request_body_size: int | None = None
    response_body_size: int | None = None
    response_body_truncated: int = 0
    flags: list[str] = field(default_factory=list)

    @property
    def sort_packet(self) -> int:
        for frame in (self.request, self.response):
            if frame is not None:
                return frame.packet
        return 0


# --------------------------------------------------------------------------
# parsing helpers
# --------------------------------------------------------------------------

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


def _text(value: str | None) -> str | None:
    if value is None:
        return None
    value = value.strip("\x00")
    return value or None


def parse_header_lines(raw: str | None, separator: str = HEADER_SEPARATOR) -> dict[str, str]:
    """Header block -> dict.

    TShark emits one value per ``http.*.line`` occurrence, joined with the
    aggregator. Values keep literal ``\\r\\n`` escapes, which are dropped here.
    Duplicate header names are suffixed so nothing is silently lost.
    """
    if not raw:
        return {}

    parts = raw.split(separator) if separator in raw else [raw]
    headers: dict[str, str] = {}
    last_key: str | None = None
    for part in parts:
        for line in part.split(_LINE_END):
            line = line.strip().strip(",").strip()
            if not line:
                continue
            if ":" not in line:
                # Only reachable in the degraded fallback below, where the comma
                # aggregator splits a value such as "Accept: a, b": reattach the
                # fragment to the header it belongs to rather than dropping it.
                if last_key is not None:
                    headers[last_key] = f"{headers[last_key]}, {line}"
                continue
            name, _, value = line.partition(":")
            name = name.strip()
            if not name:
                continue
            key = name
            suffix = 2
            while key in headers:
                key = f"{name}#{suffix}"
                suffix += 1
            headers[key] = value.strip()
            last_key = key
    return headers


def _build_frame(fields: list[str]) -> HttpFrame | None:
    if len(fields) < len(_TSHARK_FIELDS):
        fields = [*fields, *([""] * (len(_TSHARK_FIELDS) - len(fields)))]

    (
        number, time_epoch, stream_id, src_ip, src_port, dst_ip, dst_port,
        method, uri, version, host, status_code, status_text, user_agent,
        referer, content_type, server_header, content_length, full_uri,
    ) = fields[: len(_TSHARK_FIELDS)]

    packet = _int(number)
    if packet is None:
        return None

    frame = HttpFrame(
        packet=packet,
        time_epoch=_float(time_epoch),
        stream_id=_int(stream_id),
        src_ip=_text(src_ip),
        src_port=_int(src_port),
        dst_ip=_text(dst_ip),
        dst_port=_int(dst_port),
        method=(_text(method) or "").upper() or None,
        uri=_text(uri),
        version=_text(version),
        host=_text(host),
        status_code=_int(status_code),
        status_text=_text(status_text),
        user_agent=_text(user_agent),
        referer=_text(referer),
        content_type=_text(content_type),
        server_header=_text(server_header),
        content_length=_int(content_length),
        full_uri=_text(full_uri),
    )
    if not frame.is_request and not frame.is_response:
        return None  # a frame TShark matched but did not dissect as HTTP
    return frame

def collect_frames(capture_path: Path, ctx: JobContext) -> list[HttpFrame]:
    """Stream every HTTP frame in capture order and attach its header block."""
    frames: list[HttpFrame] = []
    scanned = 0

    for fields in tshark.stream_fields(
        capture_path,
        _TSHARK_FIELDS,
        display_filter="http",
        occurrence="f",
        cancel_event=ctx.cancel_event,
    ):
        scanned += 1
        frame = _build_frame(fields)
        if frame is not None:
            frames.append(frame)
        if scanned % CANCEL_EVERY == 0:
            ctx.check_cancelled()
            ctx.set_stage(f"Analyzing HTTP ({scanned:,} packets)")

    headers_by_packet = _collect_header_blocks(capture_path, ctx)
    for frame in frames:
        block = headers_by_packet.get(frame.packet)
        if block is not None:
            frame.request_headers, frame.response_headers = block
    return frames


def _collect_header_blocks(
    capture_path: Path, ctx: JobContext
) -> dict[int, tuple[dict[str, str], dict[str, str]]]:
    """Second pass: the multi-valued header-line fields, keyed by packet number.

    ``occurrence`` is one global TShark option, so the header lines need their own
    pass with ``occurrence=a``; the scalar fields keep ``occurrence=f`` semantics
    in the first pass.
    """
    blocks: dict[int, tuple[dict[str, str], dict[str, str]]] = {}

    def _consume(aggregator: str) -> None:
        for fields in tshark.stream_fields(
            capture_path,
            _LINE_FIELDS,
            display_filter="http",
            occurrence="a",
            aggregator=aggregator,
            cancel_event=ctx.cancel_event,
        ):
            if len(fields) < len(_LINE_FIELDS):
                fields = [*fields, *([""] * (len(_LINE_FIELDS) - len(fields)))]
            packet = _int(fields[0])
            if packet is None:
                continue
            blocks[packet] = (
                parse_header_lines(fields[1], separator=aggregator),
                parse_header_lines(fields[2], separator=aggregator),
            )

    try:
        _consume(HEADER_SEPARATOR)
    except tshark.TsharkError as exc:
        # Older builds may reject the aggregator option; retry with the default
        # comma and split on the literal CR/LF escapes instead.
        log.warning("header aggregator unsupported (%s); falling back", exc)
        blocks.clear()
        _consume(",")
    return blocks


def build_transactions(frames: list[HttpFrame]) -> list[Transaction]:
    """Pair request frames with the next response frame on the same stream."""
    transactions: list[Transaction] = []
    pending: dict[int | None, list[int]] = {}

    for frame in sorted(frames, key=lambda item: item.packet):
        if frame.is_request:
            transactions.append(Transaction(stream_id=frame.stream_id, request=frame))
            pending.setdefault(frame.stream_id, []).append(len(transactions) - 1)
        elif frame.is_response:
            queue = pending.get(frame.stream_id)
            if queue:
                transactions[queue.pop(0)].response = frame
                if not queue:
                    pending.pop(frame.stream_id, None)
            else:
                # A response whose request was not captured stays its own row.
                transactions.append(Transaction(stream_id=frame.stream_id, response=frame))

    transactions.sort(key=lambda item: item.sort_packet)
    return transactions

# --------------------------------------------------------------------------
# bodies (TShark stream reassembly)
# --------------------------------------------------------------------------

def _header_length(head: bytes) -> int | None:
    """Declared body length; ``None`` when absent, ``-1`` when chunked."""
    for raw_line in head.split(b"\r\n"):
        match = _CONTENT_LENGTH_RE.match(raw_line)
        if match:
            return int(match.group(1))
        if _TRANSFER_ENCODING_RE.match(raw_line):
            return -1
    return None


def _chunked(data: bytes, pos: int) -> tuple[bytes, int] | None:
    """Decode a chunked body starting at ``pos``; ``None`` when malformed."""
    body = bytearray()
    while True:
        end = data.find(b"\r\n", pos)
        if end == -1:
            return None
        try:
            size = int(data[pos:end].split(b";")[0].strip(), 16)
        except ValueError:
            return None
        pos = end + 2
        if size == 0:
            trailer_end = data.find(b"\r\n", pos)
            return bytes(body), (trailer_end + 2 if trailer_end != -1 else pos)
        body += data[pos : pos + size]
        pos += size
        if data[pos : pos + 2] != b"\r\n":
            return None
        pos += 2


def split_messages(data: bytes, *, response: bool) -> list[tuple[bytes, bytes]] | None:
    """Split reassembled one-direction bytes into ``(head, body)`` messages.

    Returns ``None`` when the stream cannot be parsed cleanly - the caller then
    stores no bodies rather than a guess.
    """
    messages: list[tuple[bytes, bytes]] = []
    pos = 0
    while pos < len(data):
        end = data.find(b"\r\n\r\n", pos)
        if end == -1:
            break
        head = data[pos:end]
        body_start = end + 4
        length = _header_length(head)

        if response:
            match = _STATUS_RE.match(head)
            if match and match.group(1).startswith((b"1", b"204", b"304")):
                length = 0

        if length is None:
            body = b""
        elif length == -1:
            decoded = _chunked(data, body_start)
            if decoded is None:
                return None
            body, pos = decoded
            messages.append((head, body))
            continue
        else:
            body = data[body_start : body_start + length]
            if len(body) < length:
                break  # truncated capture: stop rather than mis-attribute

        messages.append((head, body))
        pos = body_start + len(body)
    return messages


def _decode_preview(
    body: bytes, content_type: str | None, limit: int
) -> tuple[str | None, bool]:
    """Decoded preview plus the truncated flag; binary types get a printable view."""
    if not body:
        return None, False

    kind = (content_type or "").split(";")[0].strip().lower()
    is_binary = kind in _BINARY_TYPES or kind.startswith(_BINARY_TYPE_PREFIXES)

    if is_binary:
        text, truncated = tshark.render_ascii(body.hex(), limit=limit)
        return (text or None), truncated

    window = body[:limit]
    truncated = len(body) > limit
    return window.decode("utf-8", errors="replace"), truncated


def attach_bodies(
    transactions: list[Transaction], capture_path: Path, ctx: JobContext
) -> int:
    """Fill bodies and message lengths from TShark's stream reassembly.

    Bodies are attached only when every parsed message lines up with the observed
    transactions, so a stream that cannot be reassembled cleanly yields NULLs.
    """
    by_stream: dict[int, list[Transaction]] = {}
    for transaction in transactions:
        if transaction.stream_id is None:
            continue
        by_stream.setdefault(transaction.stream_id, []).append(transaction)

    limit = int(settings.body_preview_bytes)
    attached = 0

    for stream_id, group in by_stream.items():
        ctx.check_cancelled()
        try:
            follow = tshark.follow_stream(
                capture_path, stream_id, mode="ascii", cancel_event=ctx.cancel_event
            )
        except (tshark.TsharkError, tshark.TsharkTimeout) as exc:
            log.debug("stream %s reassembly unavailable: %s", stream_id, exc)
            continue
        if not follow.chunks:
            continue

        client_direction = _client_direction(
            follow,
            _first_value(group, "src_ip"),
            _first_value(group, "src_port"),
        )

        request_bytes = bytearray()
        response_bytes = bytearray()
        for chunk in follow.chunks:
            try:
                payload = bytes.fromhex(chunk.hex)
            except ValueError:
                continue
            target = request_bytes if chunk.direction == client_direction else response_bytes
            target += payload

        requests = split_messages(bytes(request_bytes), response=False)
        responses = split_messages(bytes(response_bytes), response=True)
        if requests is None or responses is None:
            continue

        request_rows = [t for t in group if t.request is not None]
        response_rows = [t for t in group if t.response is not None]
        if len(requests) != len(request_rows) or len(responses) != len(response_rows):
            log.debug(
                "stream %s: %s parsed requests vs %s rows, %s parsed responses vs %s rows",
                stream_id, len(requests), len(request_rows),
                len(responses), len(response_rows),
            )
            continue

        for transaction, (head, body) in zip(request_rows, requests):
            content_type = transaction.request.content_type if transaction.request else None
            transaction.request_len = len(head) + 4 + len(body)
            transaction.request_body_size = len(body)
            transaction.request_body, _ = _decode_preview(body, content_type, limit)

        for transaction, (head, body) in zip(response_rows, responses):
            content_type = transaction.response.content_type if transaction.response else None
            transaction.response_len = len(head) + 4 + len(body)
            transaction.response_body_size = len(body)
            preview, truncated = _decode_preview(body, content_type, limit)
            transaction.response_body = preview
            transaction.response_body_truncated = int(truncated)

        attached += 1

    return attached


def _first_value(transactions: list[Transaction], attribute: str) -> object:
    for transaction in transactions:
        frame = transaction.request or transaction.response
        if frame is not None:
            return getattr(frame, attribute)
    return None


def _client_direction(follow: tshark.FollowStream, ip: object, port: object) -> int:
    """Which follow direction is client -> server (0 = node0, 1 = node1)."""
    if ip is None or port is None:
        return 0
    for endpoint in (f"{ip}:{port}", f"[{ip}]:{port}"):
        if follow.node0 == endpoint:
            return 0
        if follow.node1 == endpoint:
            return 1
    # node0 is the peer that sent the first packet in the stream (normally the
    # client); the arity check above still guards against a wrong guess.
    return 0

# --------------------------------------------------------------------------
# flags
# --------------------------------------------------------------------------

def _headers_text(headers: dict[str, str]) -> str:
    return "\n".join(f"{name}: {value}" for name, value in headers.items())


def _is_ip_host(host: str | None) -> bool:
    if not host:
        return False
    candidate = host.strip()
    if candidate.startswith("[") and "]" in candidate:  # [::1]:8080
        candidate = candidate[1 : candidate.index("]")]
    else:
        candidate = candidate.split(":")[0]
    try:
        ipaddress.ip_address(candidate)
    except ValueError:
        return False
    return True


def compute_flags(transaction: Transaction) -> list[str]:
    """Investigative leads - never a verdict."""
    flags: list[str] = []
    request = transaction.request
    response = transaction.response

    status = response.status_code if response is not None else None
    if status is not None:
        if 500 <= status <= 599:
            flags.append("server_error")
        elif 400 <= status <= 499:
            flags.append("client_error")

    if request is not None and request.method and request.method not in COMMON_METHODS:
        flags.append("unusual_method")

    uri = (request.uri if request is not None else None) or ""
    haystack = (uri + "\n" + _headers_text(request.request_headers if request else {})).lower()
    for pattern in SUSPICIOUS_PATH_PATTERNS:
        if pattern in haystack:
            flags.append("suspicious_path")
            break

    if request is not None and _is_ip_host(request.host):
        flags.append("ip_host")

    credential_text = (
        uri
        + "\n"
        + _headers_text(request.request_headers if request else {})
        + "\n"
        + (transaction.request_body or "")
    )
    # normalise dashes so "X-Api-Key" matches the "api_key" lead
    credential_text = credential_text.lower().replace("-", "_")
    for keyword in CREDENTIAL_KEYWORDS:
        if keyword in credential_text:
            flags.append(f"cleartext_credentials:{keyword}")
            break

    user_agent = request.user_agent if request is not None else None
    if not user_agent:
        flags.append("unusual_user_agent:missing")
    elif len(user_agent) > 200:
        flags.append("unusual_user_agent:long")
    else:
        lowered_agent = user_agent.lower()
        for signature in TOOL_USER_AGENTS:
            if signature in lowered_agent:
                flags.append(f"unusual_user_agent:{signature}")
                break

    return flags


# --------------------------------------------------------------------------
# persistence
# --------------------------------------------------------------------------

def to_sql_row(analysis_id: str, transaction: Transaction) -> tuple:
    request = transaction.request
    response = transaction.response
    host = request.host if request is not None else None
    uri = request.uri if request is not None else None

    full_uri = request.full_uri if request is not None else None
    if not full_uri and host and uri:
        full_uri = f"http://{host}{uri}"

    content_type = None
    if response is not None and response.content_type:
        content_type = response.content_type
    elif request is not None:
        content_type = request.content_type

    return (
        analysis_id,
        transaction.stream_id,
        request.packet if request is not None else None,
        response.packet if response is not None else None,
        request.time_epoch if request is not None else (
            response.time_epoch if response is not None else None
        ),
        response.time_epoch if response is not None else None,
        request.src_ip if request is not None else None,
        request.src_port if request is not None else None,
        request.dst_ip if request is not None else None,
        request.dst_port if request is not None else None,
        request.method if request is not None else None,
        host,
        uri,
        full_uri,
        request.version if request is not None else None,
        response.status_code if response is not None else None,
        response.status_text if response is not None else None,
        request.user_agent if request is not None else None,
        request.referer if request is not None else None,
        content_type,
        response.server_header if response is not None else None,
        transaction.request_len,
        transaction.response_len,
        json.dumps(request.request_headers, separators=(",", ":"))
        if request and request.request_headers else None,
        json.dumps(response.response_headers, separators=(",", ":"))
        if response and response.response_headers else None,
        transaction.request_body,
        transaction.response_body,
        transaction.request_body_size,
        transaction.response_body_size,
        transaction.response_body_truncated,
        json.dumps(transaction.flags, separators=(",", ":")),
    )

def analyze(ctx: JobContext, analysis_id: str, capture_path: Path) -> dict:
    """Extract HTTP transactions from ``capture_path`` and persist them."""
    started = time.monotonic()
    ctx.set_stage("Analyzing HTTP")

    with db.get_conn() as conn:
        conn.execute("DELETE FROM http_transactions WHERE analysis_id = ?", (analysis_id,))

    frames = collect_frames(capture_path, ctx)
    transactions = build_transactions(frames)
    ctx.check_cancelled()
    ctx.set_stage("Reassembling HTTP bodies")
    attach_bodies(transactions, capture_path, ctx)

    for transaction in transactions:
        transaction.flags = compute_flags(transaction)

    conn: sqlite3.Connection = db.connect()
    inserted = 0
    try:
        conn.execute("BEGIN")
        buffer: list[tuple] = []
        for transaction in transactions:
            buffer.append(to_sql_row(analysis_id, transaction))
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
    log.info("http analysis for %s: %s in %.1fs", analysis_id, counters, elapsed)
    return {
        **counters,
        "http_analyzed": inserted,
        "http_frames": len(frames),
        "seconds": round(elapsed, 2),
    }


def _counters(analysis_id: str, transactions: int) -> dict:
    row = db.query_one(
        """
        SELECT
            SUM(CASE WHEN request_packet IS NOT NULL THEN 1 ELSE 0 END)  AS requests,
            SUM(CASE WHEN response_packet IS NOT NULL THEN 1 ELSE 0 END) AS responses,
            SUM(CASE WHEN status_code >= 500 AND status_code <= 599 THEN 1 ELSE 0 END) AS s5,
            SUM(CASE WHEN status_code >= 400 AND status_code <= 499 THEN 1 ELSE 0 END) AS s4,
            SUM(CASE WHEN flags IS NOT NULL AND flags <> '[]' THEN 1 ELSE 0 END) AS flagged
        FROM http_transactions
        WHERE analysis_id = ?
        """,
        (analysis_id,),
    )
    data = dict(row) if row else {}
    return {
        "http_transactions": transactions,
        "http_requests": int(data.get("requests") or 0),
        "http_responses": int(data.get("responses") or 0),
        "http_5xx": int(data.get("s5") or 0),
        "http_4xx": int(data.get("s4") or 0),
        "http_flagged": int(data.get("flagged") or 0),
    }


__all__ = [
    "COLUMNS",
    "HttpFrame",
    "Transaction",
    "analyze",
    "attach_bodies",
    "build_transactions",
    "collect_frames",
    "compute_flags",
    "parse_header_lines",
    "split_messages",
    "to_sql_row",
]
