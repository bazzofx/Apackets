"""Suricata-compatible rule matching over the data APackets already indexed.

This is a *matcher*, not the Suricata IDS: there is no Suricata binary in this
project and none is required. Every rule is evaluated against the fields TShark
extracted during the packet/HTTP/DNS/TLS stages, which is what makes the feature
work on a workstation without libpcap privileges.

Honesty rules baked into the implementation:

* A rule is only evaluated when every one of its options can be honoured. Rules
  using options we cannot evaluate (``flowbits``, ``threshold``, ``pkt_data``,
  ``byte_test``, engine events, unindexed protocols ...) are stored with
  ``supported = 0`` and reported as *skipped* - never partially matched.
* A rule whose content has no buffer selector (plain payload matching) is
  evaluated against the reassembled text fields we do have and is marked
  ``approximate``, both in the rule table and in every finding it produces.
* Findings say what was observed ("consistent with", "worth reviewing") and
  never assert a verdict.
"""

from __future__ import annotations

import json
import re
import sqlite3
import time
from dataclasses import dataclass, field
from typing import Any, Iterable, Iterator, Sequence

from app.core.logging import get_logger
from app.db import database as db
from app.services import suricata_rules as sr
from app.services.detection_engine import finding_id

log = get_logger("apackets.suricata.engine")

# Buffers that only exist for a completed HTTP transaction.
HTTP_ONLY_BUFFERS: frozenset[str] = frozenset(
    {
        "http.user_agent",
        "http.referer",
        "http.header",
        "http.request_header",
        "http.response_header",
        "http.request_body",
        "http.response_body",
        "http.cookie",
        "http.protocol",
    }
)
REQUEST_SIDE_BUFFERS: frozenset[str] = frozenset(
    {"http.uri", "http.raw_uri", "http.host", "http.method", "http.request_body", "http.cookie"}
)
RESPONSE_SIDE_BUFFERS: frozenset[str] = frozenset({"http.response_body", "http.status_code"})

MAX_PACKET_NUMBERS = 50
MAX_ENTITIES = 25
EXCERPT = 120

TCP_FIN = 0x01
TCP_SYN = 0x02
TCP_RST = 0x04
TCP_PSH = 0x08
TCP_ACK = 0x10

ALERTING_ACTIONS = frozenset({"alert", "drop", "reject", "rejectsrc", "rejectdst", "rejectboth"})

_TCP_FLAG_BITS: dict[str, int] = {
    "F": TCP_FIN,
    "S": TCP_SYN,
    "R": TCP_RST,
    "P": TCP_PSH,
    "A": TCP_ACK,
}


# --------------------------------------------------------------------------
# compiled rules
# --------------------------------------------------------------------------


@dataclass
class CompiledRule:
    sid: int
    rev: int
    msg: str
    severity: str
    action: str
    protocol: str
    direction: str
    raw: str
    classtype: str | None = None
    reference: str | None = None
    source: str | None = None
    category: str | None = None
    approximate: bool = False
    src_addr: sr.AddressExpr | None = None
    dst_addr: sr.AddressExpr | None = None
    src_port: sr.PortExpr | None = None
    dst_port: sr.PortExpr | None = None
    contents: list[dict[str, Any]] = field(default_factory=list)
    regexes: list[dict[str, Any]] = field(default_factory=list)
    flow: dict[str, bool] = field(default_factory=dict)
    flags: str | None = None
    dsize: dict[str, Any] | None = None
    ttl: dict[str, Any] | None = None
    scope: str = "packet"

    @property
    def rule_id(self) -> str:
        return f"suricata:{self.sid}"

    @property
    def buffers(self) -> set[str]:
        names = {str(opt.get("buffer") or "") for opt in self.contents + self.regexes}
        return {name for name in names if name}


def _rule_scope(contents: Sequence[dict[str, Any]], regexes: Sequence[dict[str, Any]]) -> str:
    for option in list(contents) + list(regexes):
        if str(option.get("buffer") or "") in HTTP_ONLY_BUFFERS:
            return "http"
    return "packet"


def load_rules(*, include_unsupported: bool = False) -> tuple[list[CompiledRule], dict[str, int]]:
    """Read enabled rules and compile their bindings."""
    variables = sr.variables_from_config()
    where = "enabled = 1"
    if not include_unsupported:
        where += " AND supported = 1"
    rows = db.query_all(f"SELECT * FROM suricata_rules WHERE {where} ORDER BY sid")

    compiled: list[CompiledRule] = []
    skipped: dict[str, int] = {"pass": 0, "unsupported_binding": 0}
    for row in rows:
        action = str(row["action"] or "alert")
        if action not in ALERTING_ACTIONS:
            # `pass` rules steer Suricata's inspection flow; without a rule
            # engine there is nothing to steer, and calling them alerts would be
            # wrong.
            skipped["pass"] += 1
            continue

        try:
            options = json.loads(row["options"] or "[]")
        except (TypeError, ValueError):
            options = []
        contents = [opt for opt in options if opt.get("kind") == "content"]
        regexes = [opt for opt in options if opt.get("kind") == "pcre"]
        flow: dict[str, bool] = {}
        flags = None
        dsize = None
        ttl = None
        for option in options:
            kind = option.get("kind")
            if kind == "flow":
                flow = dict(option.get("value") or {})
            elif kind == "flags":
                flags = str(option.get("value") or "")
            elif kind == "dsize":
                dsize = option
            elif kind == "ttl":
                ttl = option

        rule = CompiledRule(
            sid=int(row["sid"]),
            rev=int(row["rev"] or 1),
            msg=str(row["msg"] or f"Suricata rule {row['sid']}"),
            severity=str(row["severity"] or "informational"),
            action=action,
            protocol=str(row["protocol"] or "any"),
            direction=str(row["direction"] or "->"),
            raw=str(row["raw"] or ""),
            classtype=row["classtype"],
            reference=row["reference"],
            source=row["source"],
            category=row["category"],
            approximate=bool(row["approximate"]),
            contents=contents,
            regexes=regexes,
            flow=flow,
            flags=flags,
            dsize=dsize,
            ttl=ttl,
        )

        src_addr = sr.parse_address_expr(str(row["src_net"]), variables)
        dst_addr = sr.parse_address_expr(str(row["dst_net"]), variables)
        src_port = sr.parse_port_expr(str(row["src_port"]), variables)
        dst_port = sr.parse_port_expr(str(row["dst_port"]), variables)
        if any(
            expr.unsupported_reason
            for expr in (src_addr, dst_addr, src_port, dst_port)
        ):
            skipped["unsupported_binding"] += 1
            continue
        rule.src_addr = src_addr
        rule.dst_addr = dst_addr
        rule.src_port = src_port
        rule.dst_port = dst_port
        rule.scope = _rule_scope(contents, regexes)
        compiled.append(rule)

    log.info(
        "suricata: %s rules loaded (%s packet scope, %s http scope), skipped: %s",
        len(compiled),
        sum(1 for rule in compiled if rule.scope == "packet"),
        sum(1 for rule in compiled if rule.scope == "http"),
        skipped,
    )
    return compiled, skipped

# --------------------------------------------------------------------------
# inspection buffers
# --------------------------------------------------------------------------


def _text(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value)
    return text if text else None


def packet_buffers(row: sqlite3.Row | dict[str, Any]) -> dict[str, str]:
    """Buffers available for a single packet row."""
    buffers: dict[str, str] = {}
    mapping = {
        "http.uri": "http_uri",
        "http.raw_uri": "http_uri",
        "http.host": "http_host",
        "http.method": "http_method",
        "dns.query": "dns_query",
        "tls.sni": "tls_sni",
    }
    for buffer, column in mapping.items():
        value = _text(row[column]) if column in row.keys() else None
        if value:
            buffers[buffer] = value
    status = row["http_status"] if "http_status" in row.keys() else None
    if status is not None:
        buffers["http.status_code"] = str(status)
    # The default buffer is what we can honestly see for this packet.
    fields = [
        _text(row[key])
        for key in ("info", "http_method", "http_uri", "http_host", "dns_query", "tls_sni")
        if key in row.keys()
    ]
    joined = " ".join(value for value in fields if value)
    if joined:
        buffers[""] = joined
    return buffers


def _headers_text(raw: Any) -> str | None:
    if not raw:
        return None
    try:
        parsed = json.loads(raw)
    except (TypeError, ValueError):
        return _text(raw)
    if isinstance(parsed, dict):
        return "\n".join(f"{key}: {value}" for key, value in parsed.items())
    return _text(raw)


def _header_value(raw: Any, name: str) -> str | None:
    if not raw:
        return None
    try:
        parsed = json.loads(raw)
    except (TypeError, ValueError):
        return None
    if not isinstance(parsed, dict):
        return None
    wanted = name.lower()
    for key, value in parsed.items():
        if str(key).lower() == wanted:
            return _text(value)
    return None


def http_buffers(row: sqlite3.Row | dict[str, Any]) -> dict[str, str]:
    """Buffers available for one reassembled HTTP transaction."""
    buffers: dict[str, str] = {}
    mapping = {
        "http.uri": "uri",
        "http.raw_uri": "uri",
        "http.host": "host",
        "http.method": "method",
        "http.user_agent": "user_agent",
        "http.referer": "referer",
        "http.protocol": "version",
        "http.request_body": "request_body",
        "http.response_body": "response_body",
    }
    for buffer, column in mapping.items():
        value = _text(row[column]) if column in row.keys() else None
        if value:
            buffers[buffer] = value
    status = row["status_code"] if "status_code" in row.keys() else None
    if status is not None:
        buffers["http.status_code"] = str(status)
    request_headers = _headers_text(row["request_headers"] if "request_headers" in row.keys() else None)
    response_headers = _headers_text(
        row["response_headers"] if "response_headers" in row.keys() else None
    )
    if request_headers:
        buffers["http.request_header"] = request_headers
        buffers["http.header"] = request_headers
    if response_headers:
        buffers["http.response_header"] = response_headers
        existing = buffers.get("http.header")
        buffers["http.header"] = f"{existing}\n{response_headers}" if existing else response_headers
    cookie = _header_value(
        row["request_headers"] if "request_headers" in row.keys() else None, "cookie"
    )
    if cookie:
        buffers["http.cookie"] = cookie
    full_uri = _text(row["full_uri"]) if "full_uri" in row.keys() else None
    if full_uri:
        buffers.setdefault("http.uri", full_uri)
    # Default buffer: everything we can see for this transaction.
    fields = [
        buffers.get("http.method"),
        buffers.get("http.host"),
        buffers.get("http.uri"),
        buffers.get("http.user_agent"),
        buffers.get("http.request_body"),
        buffers.get("http.response_body"),
    ]
    joined = " ".join(value for value in fields if value)
    if joined:
        buffers[""] = joined
    return buffers


# --------------------------------------------------------------------------
# matching primitives
# --------------------------------------------------------------------------


def _within_range(value: int | None, check: dict[str, Any] | None) -> bool:
    if check is None:
        return True
    if value is None:
        return False
    op = check.get("op")
    if op == ">":
        return value > int(check["value"])
    if op == "<":
        return value < int(check["value"])
    if op == "range":
        return int(check["low"]) <= value <= int(check["high"])
    return value == int(check.get("value", -1))


def _bytes_equal(candidate: bytes, needle: bytes, nocase: bool) -> bool:
    """Re-check bytes that are about to be displayed against the condition's needle."""
    if len(candidate) != len(needle):
        return False
    if nocase:
        return candidate.lower() == needle.lower()
    return candidate == needle


def _find_offset(
    haystack: bytes,
    needle: bytes,
    *,
    nocase: bool,
    startswith: bool,
    endswith: bool,
) -> int | None:
    """The byte offset of ``needle`` in ``haystack``, or ``None``.

    ``nocase`` folds through ``bytes.lower()`` — Suricata's ASCII-only case
    folding. The anchors are resolved here instead of by trimming the buffer, so
    the offset a record carries is always an offset in the buffer itself.
    """
    if not needle or len(haystack) < len(needle):
        return None
    if startswith:
        return 0 if _bytes_equal(haystack[: len(needle)], needle, nocase) else None
    if endswith:
        last = len(haystack) - len(needle)
        return last if _bytes_equal(haystack[last:], needle, nocase) else None
    found = haystack.lower().find(needle.lower()) if nocase else haystack.find(needle)
    return found if found >= 0 else None


def matched_evidence(option: dict[str, Any], buffers: dict[str, str]) -> dict[str, Any] | None:
    """The exact bytes that satisfied one ``content`` condition, from its own buffer.

    ``None`` means the condition was not satisfied — either the bytes are not
    there, or the buffer does not exist for this packet/transaction at all. No
    other field is ever substituted for a missing buffer: a match must be reported
    from the buffer the rule named, or not at all.

    Otherwise one record, which is what the finding stores and the interface shows:

    ==================  =======================================================
    ``buffer``          the buffer inspected, e.g. ``http.request_body``
    ``offset``          byte offset of the match **within that buffer**
    ``matched``         the bytes found there, re-read from the buffer
    ``matched_text``    those bytes as text, for display
    ``matched_hex``     those bytes in hex, so the encoding is verifiable
    ``encoding``        ``hex`` (``|3A|``) or ``text``, as the rule wrote it
    ``excerpt``         the buffer around the match — never a URI or a header
    ``evidence_error``  set instead when the matched bytes could not be confirmed
    ==================  =======================================================
    """
    buffer_name = str(option.get("buffer") or "")
    haystack = buffers.get(buffer_name)
    if haystack is None:
        return None

    raw_hex = option.get("bytes")
    if raw_hex:
        try:
            needle = bytes.fromhex(str(raw_hex))
        except ValueError:  # pragma: no cover - validated at import time
            return None
        encoding = "hex"
    else:
        needle = str(option.get("value") or "").encode("utf-8")
        encoding = "text"
    if not needle:
        return None

    # Suricata's offset/depth window applies to the buffer being inspected, and
    # offsets are reported against that same buffer, so the window is a view of
    # it and `start` is added back to the answer.
    data = haystack.encode("utf-8")
    start = max(0, int(option.get("offset") or 0))
    window = data[start:]
    depth = option.get("depth")
    if depth is not None and int(depth) >= 0:
        window = window[: int(depth)]

    nocase = bool(option.get("nocase"))
    index = _find_offset(
        window,
        needle,
        nocase=nocase,
        startswith=bool(option.get("startswith")),
        endswith=bool(option.get("endswith")),
    )
    if index is None:
        return None

    offset = start + index
    matched = data[offset: offset + len(needle)]
    record: dict[str, Any] = {
        "buffer": buffer_name or "(fields)",
        "offset": offset,
        "length": len(needle),
        "encoding": encoding,
        "matched": matched,
        "matched_text": matched.decode("utf-8", "replace"),
        "matched_hex": matched.hex(),
        "excerpt": "",
    }
    # The bytes that are about to be displayed are verified against the condition
    # they supposedly satisfied, so a match can never be reported with bytes that
    # do not satisfy the rule, or with bytes from another field.
    if not _bytes_equal(matched, needle, nocase):
        record["evidence_error"] = (
            f"the bytes at offset {offset} of {record['buffer']} do not satisfy the "
            "content condition"
        )
        return record
    record["excerpt"] = _excerpt_at(data, offset, len(needle))
    return record


def _excerpt(value: str) -> str:
    text = " ".join(value.split())
    return text[:EXCERPT]


def _excerpt_at(data: bytes, offset: int, length: int, limit: int = EXCERPT) -> str:
    """``limit`` characters of the buffer a match came from, centred on that match."""
    head = max(0, (limit - length) // 2)
    span = data[max(0, offset - head): offset + length + head]
    return _excerpt(span.decode("utf-8", "replace"))


def _content_matches(option: dict[str, Any], buffers: dict[str, str]) -> dict[str, Any] | None:
    """One ``content`` condition: its evidence record, or ``None`` when it fails."""
    buffer_name = str(option.get("buffer") or "")
    if buffers.get(buffer_name) is None:
        # The buffer does not exist for this packet/transaction at all. Suricata
        # cannot match a buffer that is not there, negated content included.
        return None
    if option.get("negated"):
        if matched_evidence(option, buffers) is not None:
            return None
        # Absence is what satisfied the condition, so there are no matched bytes
        # to show; the record says so rather than borrowing a neighbouring field.
        return {
            "buffer": buffer_name or "(fields)",
            "negated": True,
            "offset": None,
            "length": 0,
            "encoding": "negated",
            "matched": b"",
            "matched_text": "",
            "matched_hex": "",
            "excerpt": "",
        }
    return matched_evidence(option, buffers)


def matched_regex_evidence(option: dict[str, Any], buffers: dict[str, str]) -> dict[str, Any] | None:
    """The match a ``pcre`` option found, with its own buffer, bytes and offset."""
    buffer_name = str(option.get("buffer") or "")
    haystack = buffers.get(buffer_name)
    if haystack is None:
        return None
    try:
        compiled = re.compile(str(option.get("pattern") or ""), int(option.get("flags") or 0))
    except re.error:  # pragma: no cover - validated at import time
        return None
    found = compiled.search(haystack)
    if found is None:
        return None

    # The buffer is bytes on the wire; the pattern ran over its text, so the
    # offset is converted to the byte offset of the same match.
    data = haystack.encode("utf-8")
    offset = len(haystack[: found.start()].encode("utf-8"))
    matched = haystack[found.start(): found.end()].encode("utf-8")
    record: dict[str, Any] = {
        "buffer": buffer_name or "(fields)",
        "offset": offset,
        "length": len(matched),
        "encoding": "pcre",
        "matched": matched,
        "matched_text": matched.decode("utf-8", "replace"),
        "matched_hex": matched.hex(),
        "excerpt": _excerpt_at(data, offset, len(matched)),
    }
    # A pattern with a lookbehind or an anchor cannot be re-checked in isolation,
    # so a failure here is reported as an extraction error rather than papered over.
    if matched and compiled.match(record["matched_text"]) is None:
        record["evidence_error"] = (
            f"the bytes at offset {offset} of {record['buffer']} could not be "
            "re-checked against the pattern"
        )
    return record


def _persisted(record: dict[str, Any]) -> dict[str, Any]:
    """The record as it is stored: ``evidence`` is JSON, so raw bytes are dropped.

    ``matched_hex`` and ``matched_text`` carry the same bytes in a form JSON can
    hold, so nothing is lost by dropping the ``bytes`` object.
    """
    return {key: value for key, value in record.items() if key != "matched"}


def _evidence_fields(records: list[dict[str, Any]]) -> dict[str, Any]:
    """The hit's own view of its evidence: the buffers, and the first match.

    Every field here is taken from the record of a condition that was satisfied,
    so the excerpt the interface shows and the buffer it names are the same
    buffer that the rule inspected.
    """
    first = records[0]
    return {
        "fields": [record["buffer"] for record in records],
        "buffer": first["buffer"],
        "offset": first.get("offset"),
        "matched": first.get("matched_text") or "",
        "matched_hex": first.get("matched_hex") or "",
        "excerpt": first.get("excerpt") or "",
        "conditions": [_persisted(record) for record in records],
    }


def _parse_flags(raw: Any) -> int:
    if raw is None:
        return 0
    text = str(raw)
    value = 0
    for char in text:
        value |= _TCP_FLAG_BITS.get(char.upper(), 0)
    return value


def _flow_satisfied(rule: CompiledRule, context: dict[str, Any]) -> bool:
    """Approximate Suricata's ``flow`` option against what we know."""
    flow = rule.flow
    if not flow:
        return True
    if flow.get("stateless") or flow.get("no_stream"):
        return True
    if flow.get("established") and context.get("transport") == "tcp":
        bits = int(context.get("tcp_bits") or 0)
        if bits and not (bits & TCP_ACK):
            return False
    if flow.get("not_established") and flow.get("established"):
        return False
    # Direction is already constrained by src/dst matching for `->` rules; for
    # the HTTP pass the buffers themselves say which side of the exchange we
    # looked at.
    return True


def _protocol_matches(protocol: str, context: dict[str, Any]) -> bool:
    transport = str(context.get("transport") or "").lower()
    packet_protocol = str(context.get("protocol") or "").upper()
    if protocol in {"any", "ip"}:
        return True
    if protocol == "ipv6":
        return int(context.get("ip_version") or 0) == 6
    if protocol == "icmp":
        return "ICMP" in packet_protocol
    if protocol == "icmpv6":
        return "ICMPV6" in packet_protocol or "ICMPV6" in packet_protocol.replace(" ", "")
    if protocol in {"tcp", "udp"}:
        return transport == protocol
    if protocol == "http":
        return bool(
            context.get("http_method")
            or context.get("http_uri")
            or context.get("http_host")
            or packet_protocol.startswith("HTTP")
        )
    if protocol == "dns":
        return bool(context.get("dns_query")) or packet_protocol.startswith("DNS")
    if protocol == "tls":
        return bool(context.get("tls_sni")) or packet_protocol.startswith("TLS")
    return False

# --------------------------------------------------------------------------
# rule evaluation
# --------------------------------------------------------------------------


def _address_pair_matches(rule: CompiledRule, context: dict[str, Any]) -> bool:
    src_ip = context.get("src_ip")
    dst_ip = context.get("dst_ip")
    src_port = context.get("src_port")
    dst_port = context.get("dst_port")

    forward = bool(
        rule.src_addr
        and rule.dst_addr
        and rule.src_addr.matches(src_ip)
        and rule.dst_addr.matches(dst_ip)
        and (rule.src_port is None or rule.src_port.matches(src_port))
        and (rule.dst_port is None or rule.dst_port.matches(dst_port))
    )
    if forward:
        return True
    if rule.direction != "<>":
        return False
    return bool(
        rule.src_addr
        and rule.dst_addr
        and rule.src_addr.matches(dst_ip)
        and rule.dst_addr.matches(src_ip)
        and (rule.src_port is None or rule.src_port.matches(dst_port))
        and (rule.dst_port is None or rule.dst_port.matches(src_port))
    )


def evaluate_rule(rule: CompiledRule, context: dict[str, Any], buffers: dict[str, str]) -> list[dict[str, Any]] | None:
    """Return one evidence record per satisfied condition, or None when no match.

    Each record names the buffer that condition inspected and carries the bytes
    and offset found in it, so a finding can only ever show evidence from the
    buffer that actually satisfied the rule.
    """
    if not _protocol_matches(rule.protocol, context):
        return None
    if not _address_pair_matches(rule, context):
        return None
    if not _flow_satisfied(rule, context):
        return None
    if rule.flags:
        bits = int(context.get("tcp_bits") or 0)
        if bits:
            for char in rule.flags.replace(",", "").strip():
                code = char.upper()
                if code == "0":
                    continue
                wanted = _TCP_FLAG_BITS.get(code)
                if wanted is None:
                    return None
                if not bits & wanted:
                    return None
    if rule.dsize and not _within_range(context.get("frame_len"), rule.dsize):
        return None
    if rule.ttl and not _within_range(context.get("ttl"), rule.ttl):
        return None

    matched: list[dict[str, Any]] = []
    for option in rule.contents:
        record = _content_matches(option, buffers)
        if record is None:
            return None
        matched.append(record)
    for option in rule.regexes:
        record = matched_regex_evidence(option, buffers)
        if record is None:
            return None
        matched.append(record)
    return matched


# --------------------------------------------------------------------------
# findings
# --------------------------------------------------------------------------


def _entities(
    ips: Iterable[str] = (),
    hostnames: Iterable[str] = (),
    ports: Iterable[Any] = (),
    uris: Iterable[str] = (),
) -> dict[str, list[Any]]:
    def clean(values: Iterable[Any], limit: int = MAX_ENTITIES) -> list[Any]:
        seen: list[Any] = []
        for value in values:
            if value in (None, ""):
                continue
            if value not in seen:
                seen.append(value)
            if len(seen) >= limit:
                break
        return seen

    return {
        "ips": clean(ips),
        "hostnames": clean(hostnames),
        "ports": clean(ports),
        "uris": clean(uris),
    }


def _packet_sample(numbers: Iterable[Any]) -> list[int]:
    out: list[int] = []
    for number in numbers:
        try:
            value = int(number)
        except (TypeError, ValueError):
            continue
        if value not in out:
            out.append(value)
        if len(out) >= MAX_PACKET_NUMBERS:
            break
    return out


def _reason(rule: CompiledRule, hits: list[dict[str, Any]], basis: str) -> str:
    total = len(hits)
    first = hits[0]
    where = first.get("where") or "the capture"
    fields = sorted({name for hit in hits for name in hit.get("fields", []) if name})
    field_text = ", ".join(fields[:6]) if fields else "the rule's field set"
    delay = ""
    if first.get("time_epoch"):
        delay = f" First match at epoch {float(first['time_epoch']):.3f}."
    return (
        f"Suricata rule {rule.sid} (rev {rule.rev}"
        + (f", classtype {rule.classtype}" if rule.classtype else "")
        + f") matched {total} time(s) in this capture, involving {where}.{delay} "
        f"Matched on {field_text}. Evaluation basis: {basis}. "
        "This is a signature match only - it is consistent with the described activity but is "
        "not by itself proof that the traffic was malicious."
    )


def _recommendation(rule: CompiledRule, hits: list[dict[str, Any]]) -> str:
    hostnames = sorted({str(hit.get("host")) for hit in hits if hit.get("host")})[:3]
    scope = ", ".join(hostnames) if hostnames else "the hosts involved"
    return (
        f"Review the referenced packets in the packet view ({scope}), confirm whether the "
        "request was expected for that service, and compare the server response (status code, "
        "body) for evidence that the attempt succeeded. If the systems are not yours to test, "
        "escalate to the owner of the destination host. Reference: "
        + (rule.reference or f"suricata sid {rule.sid}")
        + "."
    )


def _finding(rule: CompiledRule, analysis_id: str, key: str, hits: list[dict[str, Any]]) -> dict[str, Any]:
    basis = (
        "TShark-extracted fields (payload bytes are not reconstructed)"
        if rule.scope == "packet" or rule.approximate
        else "the reassembled HTTP transaction"
    )
    first = hits[0]
    evidence = {
        "suricata_sid": rule.sid,
        "rev": rule.rev,
        "action": rule.action,
        "classtype": rule.classtype,
        "reference": rule.reference,
        "rule_source": rule.source,
        "category": rule.category,
        "match_basis": basis,
        "approximate": bool(rule.approximate),
        "buffers": sorted({name for hit in hits for name in hit.get("fields", []) if name}),
        "matches": hits[:10],
        "match_count": len(hits),
        "rule": rule.raw[:1000],
    }
    entities = _entities(
        ips=[hit.get("src_ip") for hit in hits] + [hit.get("dst_ip") for hit in hits],
        hostnames=[hit.get("host") for hit in hits] + [hit.get("dns_query") for hit in hits],
        ports=[hit.get("dst_port") for hit in hits] + [hit.get("src_port") for hit in hits],
        uris=[hit.get("uri") for hit in hits],
    )
    return {
        "id": finding_id(analysis_id, rule.rule_id, [key]),
        "rule_id": rule.rule_id,
        "severity": rule.severity,
        "title": rule.msg[:300],
        "description": (
            f"Suricata-compatible rule {rule.sid} (rev {rule.rev}) from {rule.source or 'manual'} "
            f"matched traffic in this capture. The rule description is: {rule.msg}"
        )[:1000],
        "reason": _reason(rule, hits, basis),
        "evidence": evidence,
        "packet_numbers": _packet_sample(hit.get("packet") for hit in hits),
        "entities": entities,
        "recommendation": _recommendation(rule, hits),
    }


def _persist(analysis_id: str, findings: list[dict[str, Any]]) -> None:
    if not findings:
        return
    now = time.time()
    with db.get_conn() as conn:
        conn.executemany(
            """
            INSERT OR REPLACE INTO findings (
                id, analysis_id, rule_id, severity, title, description, reason,
                evidence, packet_numbers, entities, recommendation, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            [
                (
                    item["id"],
                    analysis_id,
                    item["rule_id"],
                    item["severity"],
                    item["title"],
                    item["description"],
                    item["reason"],
                    json.dumps(item["evidence"], separators=(",", ":")),
                    json.dumps(item["packet_numbers"]),
                    json.dumps(item["entities"]),
                    item["recommendation"],
                    now,
                )
                for item in findings
            ],
        )

# --------------------------------------------------------------------------
# execution
# --------------------------------------------------------------------------


def _stream(sql: str, params: Sequence[Any] = ()) -> Iterator[sqlite3.Row]:
    conn = db.connect()
    try:
        cursor = conn.execute(sql, params)
        for row in cursor:
            yield row
    finally:
        try:
            cursor.close()
        finally:
            conn.close()


PACKET_SQL = """
SELECT number, time_epoch, src_ip, dst_ip, src_port, dst_port, transport, protocol,
       frame_len, tcp_flags, ttl, ip_version, info, http_method, http_uri, http_host,
       http_status, dns_query, tls_sni
  FROM packets
 WHERE analysis_id = ?
 ORDER BY number
"""

HTTP_SQL = """
SELECT id, time_epoch, client_ip, client_port, server_ip, server_port, method, host, uri,
       full_uri, version, status_code, user_agent, referer, request_headers,
       response_headers, request_body, response_body, request_packet, response_packet
  FROM http_transactions
 WHERE analysis_id = ?
 ORDER BY time_epoch IS NULL, time_epoch, id
"""


def _buckets(rules: Sequence[CompiledRule]) -> dict[str, list[CompiledRule]]:
    buckets: dict[str, list[CompiledRule]] = {}
    for rule in rules:
        buckets.setdefault(rule.protocol, []).append(rule)
    return buckets


def _packet_candidates(buckets: dict[str, list[CompiledRule]], context: dict[str, Any]) -> list[CompiledRule]:
    """Rules worth evaluating for this packet, before the cheap filters."""
    out: list[CompiledRule] = []
    out.extend(buckets.get("any", ()))
    out.extend(buckets.get("ip", ()))
    transport = str(context.get("transport") or "").lower()
    if transport:
        out.extend(buckets.get(transport, ()))
    protocol = str(context.get("protocol") or "").upper()
    if context.get("http_uri") or context.get("http_method") or context.get("http_host") or protocol.startswith("HTTP"):
        out.extend(buckets.get("http", ()))
    if context.get("dns_query") or protocol.startswith("DNS"):
        out.extend(buckets.get("dns", ()))
    if context.get("tls_sni") or protocol.startswith("TLS"):
        out.extend(buckets.get("tls", ()))
    if int(context.get("ip_version") or 0) == 6:
        out.extend(buckets.get("ipv6", ()))
    if "ICMP" in protocol:
        out.extend(buckets.get("icmp", ()))
        out.extend(buckets.get("icmpv6", ()))
    return out


def _packet_context(row: sqlite3.Row) -> dict[str, Any]:
    return {
        "number": row["number"],
        "time_epoch": row["time_epoch"],
        "src_ip": row["src_ip"],
        "dst_ip": row["dst_ip"],
        "src_port": row["src_port"],
        "dst_port": row["dst_port"],
        "transport": row["transport"],
        "protocol": row["protocol"],
        "frame_len": row["frame_len"],
        "ttl": row["ttl"],
        "ip_version": row["ip_version"],
        "tcp_bits": _parse_flags(row["tcp_flags"]),
        "http_method": row["http_method"],
        "http_uri": row["http_uri"],
        "http_host": row["http_host"],
        "dns_query": row["dns_query"],
        "tls_sni": row["tls_sni"],
    }


def _http_context(row: sqlite3.Row) -> dict[str, Any]:
    return {
        "number": row["request_packet"],
        "packet": row["request_packet"],
        "response_packet": row["response_packet"],
        "time_epoch": row["time_epoch"],
        "src_ip": row["client_ip"],
        "dst_ip": row["server_ip"],
        "src_port": row["client_port"],
        "dst_port": row["server_port"],
        "transport": "tcp",
        "protocol": "HTTP",
        "http_method": row["method"],
        "http_uri": row["uri"],
        "http_host": row["host"],
    }


def _record(
    matches: dict[str, dict[str, list[dict[str, Any]]]],
    rule: CompiledRule,
    key: str,
    hit: dict[str, Any],
    limit: int = 10,
) -> None:
    per_rule = matches.setdefault(rule.rule_id, {})
    hits = per_rule.setdefault(key, [])
    if len(hits) < limit:
        hits.append(hit)
    else:
        per_rule[key][0]["extra"] = per_rule[key][0].get("extra", 0) + 1


def run_rules(analysis_id: str, ctx: Any = None) -> dict[str, Any]:
    """Evaluate every enabled rule against one analysed capture."""
    started = time.monotonic()
    cfg = sr.config()
    max_findings = int(cfg.get("max_findings_per_rule") or 25)
    rules, skipped = load_rules(include_unsupported=bool(cfg.get("include_unsupported")))

    stats: dict[str, Any] = {
        "rules_evaluated": len(rules),
        "rules_packet_scope": sum(1 for rule in rules if rule.scope == "packet"),
        "rules_http_scope": sum(1 for rule in rules if rule.scope == "http"),
        "skipped_pass_rules": skipped.get("pass", 0),
        "skipped_unsupported_binding": skipped.get("unsupported_binding", 0),
        "packets_scanned": 0,
        "http_scanned": 0,
        "rules_matched": 0,
        "findings": 0,
        "by_severity": {name: 0 for name in sr.SEVERITIES},
    }

    if not rules:
        stats["note"] = "no enabled, supported Suricata rules - nothing was evaluated"
        stats["seconds"] = round(time.monotonic() - started, 3)
        return stats

    packet_rules = [rule for rule in rules if rule.scope == "packet"]
    http_rules = [rule for rule in rules if rule.scope == "http"]
    packet_buckets = _buckets(packet_rules)
    http_buckets = _buckets(http_rules)

    matches: dict[str, dict[str, list[dict[str, Any]]]] = {}

    if packet_rules:
        if ctx is not None:
            ctx.set_stage("Matching Suricata rules (packets)", 0.1)
        for row in _stream(PACKET_SQL, (analysis_id,)):
            stats["packets_scanned"] += 1
            if ctx is not None and stats["packets_scanned"] % 5000 == 0:
                ctx.check_cancelled()
            context = _packet_context(row)
            buffers = packet_buffers(row)
            for rule in _packet_candidates(packet_buckets, context):
                records = evaluate_rule(rule, context, buffers)
                if records is None:
                    continue
                key = (
                    f"{context['src_ip']}:{context['src_port']}->"
                    f"{context['dst_ip']}:{context['dst_port']}"
                )
                _record(
                    matches,
                    rule,
                    key,
                    {
                        "packet": context["number"],
                        "time_epoch": context["time_epoch"],
                        "src_ip": context["src_ip"],
                        "dst_ip": context["dst_ip"],
                        "src_port": context["src_port"],
                        "dst_port": context["dst_port"],
                        "host": context.get("http_host"),
                        "uri": context.get("http_uri"),
                        "dns_query": context.get("dns_query"),
                        "where": f"{context['src_ip']}:{context['src_port']} -> "
                        f"{context['dst_ip']}:{context['dst_port']}",
                        # §evidence: the excerpt comes from the buffer that matched,
                        # never from the default "everything we can see" buffer.
                        **_evidence_fields(records),
                    },
                )

    if http_rules:
        if ctx is not None:
            ctx.set_stage("Matching Suricata rules (HTTP)", 0.6)
        for row in _stream(HTTP_SQL, (analysis_id,)):
            stats["http_scanned"] += 1
            if ctx is not None and stats["http_scanned"] % 2000 == 0:
                ctx.check_cancelled()
            context = _http_context(row)
            buffers = http_buffers(row)
            for rule in _packet_candidates(http_buckets, context):
                records = evaluate_rule(rule, context, buffers)
                if records is None:
                    continue
                key = (
                    f"{context['src_ip']}->{context['dst_ip']} "
                    f"{context.get('http_host') or ''}{context.get('http_uri') or ''}"
                ).strip()
                _record(
                    matches,
                    rule,
                    key,
                    {
                        "packet": context["number"],
                        "response_packet": context.get("response_packet"),
                        "time_epoch": context["time_epoch"],
                        "src_ip": context["src_ip"],
                        "dst_ip": context["dst_ip"],
                        "src_port": context["src_port"],
                        "dst_port": context["dst_port"],
                        "host": context.get("http_host"),
                        "uri": context.get("http_uri"),
                        "where": f"{context['src_ip']} -> {context['dst_ip']}"
                        + (f" ({context['http_host']})" if context.get("http_host") else ""),
                        # §evidence: a body rule shows body bytes. This used to
                        # prefer `http.uri`, which displayed the URI as the matched
                        # evidence for a request-body rule.
                        **_evidence_fields(records),
                    },
                )

    by_sid = {rule.rule_id: rule for rule in rules}
    findings: list[dict[str, Any]] = []
    for rule_id, per_key in matches.items():
        rule = by_sid.get(rule_id)
        if rule is None:  # pragma: no cover - defensive
            continue
        stats["rules_matched"] += 1
        for key, hits in list(per_key.items())[:max_findings]:
            if not hits:
                continue
            findings.append(_finding(rule, analysis_id, key, hits))
        if len(per_key) > max_findings:
            stats["capped_rules"] = int(stats.get("capped_rules", 0)) + 1

    db.execute(
        "DELETE FROM findings WHERE analysis_id = ? AND rule_id LIKE 'suricata:%'",
        (analysis_id,),
    )
    _persist(analysis_id, findings)
    stats["findings"] = len(findings)
    for finding in findings:
        stats["by_severity"][finding["severity"]] = (
            stats["by_severity"].get(finding["severity"], 0) + 1
        )
    stats["seconds"] = round(time.monotonic() - started, 3)
    log.info(
        "suricata: analysis %s - %s findings from %s matched rules in %.2fs",
        analysis_id,
        stats["findings"],
        stats["rules_matched"],
        stats["seconds"],
    )
    return stats


def analyze(ctx: Any, analysis_id: str, capture_path: Any = None) -> dict[str, Any]:
    """Analyzer entry point (see docs/CONTRACT.md section 4)."""
    del capture_path  # every buffer comes from the indexed tables
    return run_rules(analysis_id, ctx)


__all__ = [
    "CompiledRule",
    "HTTP_ONLY_BUFFERS",
    "analyze",
    "evaluate_rule",
    "http_buffers",
    "load_rules",
    "matched_evidence",
    "matched_regex_evidence",
    "packet_buffers",
    "run_rules",
]