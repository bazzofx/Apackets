"""Suricata rule parsing, normalisation and storage.

The application never fetches rules from the network. Rule files are either
vendored under ``backend/rules/`` (imported with :func:`seed_bundled_rules`) or
uploaded by the analyst through the API. The rule text is stored verbatim in
``suricata_rules.raw`` so it can be displayed, edited and re-exported exactly as
written.

Grammar accepted::

    action proto src_ip src_port -> dst_ip dst_port (opt; opt:val; ...)

Options are classified into three groups:

* **meta**        ``msg``, ``sid``, ``rev``, ``classtype``, ``priority`` ...
                  (stored, no effect on matching)
* **evaluable**   stored as JSON in ``suricata_rules.options`` and applied by
                  ``app.services.suricata_engine``
* **unsupported** anything the built-in matcher cannot honour faithfully
                  (``flowbits``, ``byte_test``, ``threshold``, ``pkt_data`` ...).
                  A rule carrying any of them is stored with ``supported = 0``
                  and reported as skipped - it is never half-matched, because a
                  partial match would produce a finding the rule does not
                  actually justify.
"""

from __future__ import annotations

import ipaddress
import json
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Iterator

from app.core.errors import bad_request
from app.core.logging import get_logger
from app.db import database as db

log = get_logger("apackets.suricata")

# --------------------------------------------------------------------------
# constants
# --------------------------------------------------------------------------

RULES_DIR = Path(__file__).resolve().parents[2] / "rules"

ACTIONS: frozenset[str] = frozenset(
    {"alert", "drop", "pass", "reject", "rejectsrc", "rejectdst", "rejectboth"}
)

TRANSPORT_PROTOCOLS: frozenset[str] = frozenset(
    {"tcp", "udp", "icmp", "icmpv6", "ip", "ipv6", "any"}
)
# App-layer protocols are only supported for the dissectors APackets indexes.
APP_PROTOCOLS: frozenset[str] = frozenset({"http", "dns", "tls"})
SUPPORTED_PROTOCOLS: frozenset[str] = TRANSPORT_PROTOCOLS | APP_PROTOCOLS

SEVERITIES: tuple[str, ...] = ("high", "medium", "low", "informational")

CLASSTYPE_SEVERITY: dict[str, str] = {
    "attempted-admin": "high",
    "attempted-user": "high",
    "successful-admin": "high",
    "successful-user": "high",
    "shellcode-detect": "high",
    "trojan-activity": "high",
    "malware-cnc": "high",
    "exploit-kit": "high",
    "targeted-activity": "high",
    "credential-theft": "high",
    "web-application-attack": "high",
    "attempted-recon": "medium",
    "network-scan": "medium",
    "denial-of-service": "medium",
    "policy-violation": "medium",
    "bad-unknown": "medium",
    "web-application-activity": "medium",
    "protocol-command-decode": "low",
    "not-suspicious": "low",
    "misc-activity": "low",
    "string-detect": "low",
    "unknown": "informational",
}

PRIORITY_SEVERITY: dict[int, str] = {
    1: "high",
    2: "medium",
    3: "low",
    4: "informational",
}

DEFAULT_HOME_NET: tuple[str, ...] = (
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "127.0.0.0/8",
    "169.254.0.0/16",
    "fc00::/7",
    "fe80::/10",
)

DEFAULT_PORT_VARS: dict[str, str] = {
    "HTTP_PORTS": "80",
    "HTTPS_PORTS": "443",
    "SSH_PORTS": "22",
    "DNS_PORTS": "53",
    "SMTP_PORTS": "25",
    "FTP_PORTS": "21",
    "SIP_PORTS": "5060",
    "ORACLE_PORTS": "1521",
    "SMB_PORTS": "139,445",
    "FILE_DATA_PORTS": "80,443,143,110",
    "SHELLCODE_PORTS": "!80",
}

# Sticky buffers: set the inspection buffer for every following content/pcre.
STICKY_BUFFERS: dict[str, str] = {
    "http.uri": "http.uri",
    "http.raw_uri": "http.raw_uri",
    "http.host": "http.host",
    "http.header": "http.header",
    "http.request_header": "http.request_header",
    "http.response_header": "http.response_header",
    "http.request_body": "http.request_body",
    "http.response_body": "http.response_body",
    "http.user_agent": "http.user_agent",
    "http.cookie": "http.cookie",
    "http.referer": "http.referer",
    "http.method": "http.method",
    "http.stat_code": "http.status_code",
    "http.status_code": "http.status_code",
    "http.protocol": "http.protocol",
    "dns.query": "dns.query",
    "tls.sni": "tls.sni",
}

# Buffers that address raw payload bytes we do not retain.
UNSUPPORTED_BUFFERS: dict[str, str] = {
    "pkt_data": "raw packet payload",
    "raw_data": "raw packet payload",
    "file_data": "reassembled file data",
    "tls.cert_subject": "TLS certificate subject is not indexed for matching",
    "tls.cert_issuer": "TLS certificate issuer is not indexed for matching",
    "tls.cert_serial": "TLS certificate serial is not indexed for matching",
    "dns.rdata": "DNS answer data is not indexed for matching",
    "smb.share": "SMB is not dissected",
    "krb5.msg_type": "Kerberos is not dissected",
    "http.accept": "HTTP header aggregation is partial",
    "http.accept_enc": "HTTP header aggregation is partial",
    "http.accept_lang": "HTTP header aggregation is partial",
    "http.connection": "HTTP header aggregation is partial",
    "http.content_len": "HTTP header aggregation is partial",
    "http.content_type": "HTTP header aggregation is partial",
}

# Options that change matching and that the engine implements.
_EVALUABLE = {
    "flow",
    "flags",
    "dsize",
    "content",
    "pcre",
    "ttl",
    "http.status_code",
    "http.stat_code",
}

# Options that carry no matching semantics we need to honour.
_META = {
    "msg",
    "sid",
    "rev",
    "gid",
    "classtype",
    "priority",
    "reference",
    "metadata",
    "target",
    "filestore",
    "fileextract",
    "bypass",
    "noalert",
    "tagged-packets",
    "source",
    "sameip",
    "app-layer-protocol",
}

# Legacy content modifiers -> buffer selector ("http_uri" style).
_MODIFIER_BUFFERS: dict[str, str] = {
    "http_uri": "http.uri",
    "http_raw_uri": "http.raw_uri",
    "http_host": "http.host",
    "http_method": "http.method",
    "http_user_agent": "http.user_agent",
    "http_header": "http.header",
    "http_cookie": "http.cookie",
    "http_client_body": "http.request_body",
    "http_server_body": "http.response_body",
    "http_referer": "http.referer",
    "http_content_type": "http.header",
    "http_content_len": "http.header",
    "http_connection": "http.header",
    "http_accept": "http.header",
    "http_accept_enc": "http.header",
    "http_accept_lang": "http.header",
    "http_protocol": "http.protocol",
    "http_start": "http.header",
    "dns_query": "dns.query",
    "tls_sni": "tls.sni",
}

_SIMPLE_MODIFIERS = {"nocase", "fast_pattern", "startswith", "endswith"}
_RANGE_MODIFIERS = {"depth", "offset"}
_UNSUPPORTED_MODIFIERS = {"distance", "within", "bsize", "rawbytes", "relative"}

_MAX_RAW_LENGTH = 8192
_RULE_LINE_RE = re.compile(
    r"^\s*(alert|drop|pass|reject|rejectsrc|rejectdst|rejectboth)\b", re.IGNORECASE
)
_MAX_VARIABLE_DEPTH = 8


class RuleSyntaxError(ValueError):
    """Raised when a rule cannot be parsed at all."""

# --------------------------------------------------------------------------
# parsed representation
# --------------------------------------------------------------------------


@dataclass
class ParsedRule:
    raw: str
    action: str
    protocol: str
    src_net: str
    src_port: str
    direction: str
    dst_net: str
    dst_port: str
    msg: str
    sid: int
    rev: int = 1
    classtype: str | None = None
    priority: int | None = None
    severity: str = "informational"
    reference: str | None = None
    metadata: str | None = None
    options: list[dict[str, Any]] = field(default_factory=list)
    unsupported: list[str] = field(default_factory=list)
    approximate: bool = False

    @property
    def supported(self) -> bool:
        return not self.unsupported

    def as_row(self) -> dict[str, Any]:
        return {
            "sid": self.sid,
            "rev": self.rev,
            "action": self.action,
            "protocol": self.protocol,
            "src_net": self.src_net,
            "src_port": self.src_port,
            "direction": self.direction,
            "dst_net": self.dst_net,
            "dst_port": self.dst_port,
            "msg": self.msg,
            "classtype": self.classtype,
            "priority": self.priority,
            "severity": self.severity,
            "reference": self.reference,
            "metadata": self.metadata,
            "options": json.dumps(self.options, separators=(",", ":")),
            "unsupported": json.dumps(sorted(set(self.unsupported)), separators=(",", ":")),
            "supported": 1 if self.supported else 0,
            "approximate": 1 if self.approximate else 0,
            "raw": self.raw,
        }


def severity_for(classtype: str | None, priority: int | None) -> str:
    """Map a rule onto the four APackets severities.

    ``classtype`` wins when it is known: it states what the rule detects, which
    is more informative than the numeric priority. Otherwise the Suricata
    ``priority`` is used, and informational is the fallback.
    """
    if classtype:
        key = classtype.strip().lower()
        if key in CLASSTYPE_SEVERITY:
            return CLASSTYPE_SEVERITY[key]
    if priority is not None:
        if priority in PRIORITY_SEVERITY:
            return PRIORITY_SEVERITY[priority]
        if priority >= 5:
            return "informational"
    return "informational"


# --------------------------------------------------------------------------
# tokenising helpers
# --------------------------------------------------------------------------


def split_options(body: str) -> list[str]:
    """Split an option block on ``;`` while respecting quotes and escapes."""
    parts: list[str] = []
    current: list[str] = []
    in_quotes = False
    escaped = False
    for char in body:
        if escaped:
            current.append(char)
            escaped = False
            continue
        if char == "\\":
            current.append(char)
            escaped = True
            continue
        if char == '"':
            in_quotes = not in_quotes
            current.append(char)
            continue
        if char == ";" and not in_quotes:
            parts.append("".join(current).strip())
            current = []
            continue
        current.append(char)
    tail = "".join(current).strip()
    if tail:
        parts.append(tail)
    return [part for part in parts if part]


def unquote(value: str) -> str:
    """Strip surrounding quotes and unescape backslash escapes."""
    value = value.strip()
    if len(value) >= 2 and value.startswith('"') and value.endswith('"'):
        inner = value[1:-1]
        out: list[str] = []
        escaped = False
        for char in inner:
            if escaped:
                if char in {'"', "\\", ";", ":", "|"}:
                    out.append(char)
                else:
                    out.append("\\")
                    out.append(char)
                escaped = False
                continue
            if char == "\\":
                escaped = True
                continue
            out.append(char)
        if escaped:
            out.append("\\")
        return "".join(out)
    return value


_HEX_RE = re.compile(r"\|([0-9a-fA-F\s]+)\|")


def decode_content(value: str) -> tuple[str, bytes | None]:
    """Decode a content value, honouring ``|41 42|`` hex escapes.

    Returns ``(text, raw_bytes)``; ``raw_bytes`` is ``None`` when no hex escape
    is present. ``raw_bytes`` is the content **in full and in order** — the literal
    characters *and* the escaped bytes — because it is the needle a matcher has to
    look for. Joining only the escaped part made ``content:"javascript|3A|"`` into
    ``b":"``, so the rule matched any buffer holding a colon.
    """
    if "|" not in value:
        return value, None
    binary = bytearray()
    text: list[str] = []
    position = 0
    has_binary = False
    while position < len(value):
        match = _HEX_RE.match(value, position)
        if match:
            has_binary = True
            digits = re.sub(r"\s+", "", match.group(1))
            if len(digits) % 2:
                digits = digits[:-1]
            try:
                binary.extend(bytes.fromhex(digits))
            except ValueError:  # pragma: no cover - defensive
                binary.extend(digits.encode("latin-1", "ignore"))
            position = match.end()
            continue
        char = value[position]
        # Every literal character belongs to the byte form too, wherever it sits
        # relative to the first escape.
        binary.extend(char.encode("latin-1", "ignore"))
        text.append(char)
        position += 1
    if has_binary:
        return "".join(text), bytes(binary)
    return "".join(text), None

# --------------------------------------------------------------------------
# rule parsing
# --------------------------------------------------------------------------


def parse_rule(raw: str) -> ParsedRule:
    """Parse a single Suricata rule line."""
    line = raw.strip()
    if not line:
        raise RuleSyntaxError("empty rule")
    if line.startswith("#"):
        raise RuleSyntaxError("rule is commented out")

    open_index = line.find("(")
    close_index = line.rfind(")")
    if open_index == -1 or close_index == -1 or close_index < open_index:
        raise RuleSyntaxError("missing option block: expected '(...)' at the end of the rule")

    header = line[:open_index].split()
    body = line[open_index + 1 : close_index]
    if len(header) != 7:
        raise RuleSyntaxError(
            "rule header must have 7 fields "
            f"(action proto src sport direction dst dport), got {len(header)}"
        )

    action, protocol, src_net, src_port, direction, dst_net, dst_port = header
    action = action.lower()
    if action not in ACTIONS:
        raise RuleSyntaxError(f"unknown action {action!r}")
    protocol = protocol.lower()
    if direction not in {"->", "<>"}:
        raise RuleSyntaxError(f"unknown direction {direction!r}")

    rule = ParsedRule(
        raw=line[:_MAX_RAW_LENGTH],
        action=action,
        protocol=protocol,
        src_net=src_net,
        src_port=src_port,
        direction=direction,
        dst_net=dst_net,
        dst_port=dst_port,
        msg="",
        sid=0,
    )

    if protocol not in SUPPORTED_PROTOCOLS:
        rule.unsupported.append(f"protocol {protocol!r} is not indexed")

    state = _ParseState()
    for token in split_options(body):
        _apply_option(rule, token, state)

    if not rule.msg:
        raise RuleSyntaxError("rule has no msg option")
    if rule.sid <= 0:
        raise RuleSyntaxError("rule has no valid sid option")

    _validate_bindings(rule)
    rule.severity = severity_for(rule.classtype, rule.priority)
    return rule


def _validate_bindings(rule: ParsedRule) -> None:
    """Check the address/port expressions can be evaluated at match time."""
    variables = default_variables()
    expressions = (
        ("src address", rule.src_net, parse_address_expr),
        ("dst address", rule.dst_net, parse_address_expr),
        ("src port", rule.src_port, parse_port_expr),
        ("dst port", rule.dst_port, parse_port_expr),
    )
    for label, expression, parser in expressions:
        parsed = parser(expression, variables)
        reason = parsed.unsupported_reason
        if reason:
            rule.unsupported.append(f"{label}: {reason}")


class _ParseState:
    """Sticky buffer plus the option that the next modifier applies to.

    Suricata writes buffer selection and match modifiers as *separate* options
    that describe the content before them, e.g.::

        content:"GET"; http_method; content:"/login"; http_uri; nocase;

    so the state has to remember which content option is currently open.
    """

    __slots__ = ("buffer", "last")

    def __init__(self) -> None:
        self.buffer: str | None = None
        self.last: int | None = None

    def open(self, rule: ParsedRule, option: dict[str, Any]) -> None:
        rule.options.append(option)
        self.last = len(rule.options) - 1

    def target(self, rule: ParsedRule) -> dict[str, Any] | None:
        if self.last is None or self.last >= len(rule.options):
            return None
        return rule.options[self.last]


def _apply_option(rule: ParsedRule, token: str, state: _ParseState) -> None:
    if ":" in token:
        name, value = token.split(":", 1)
        name = name.strip().lower()
        value = value.strip()
    else:
        name = token.strip().lower()
        value = ""

    if name in _META:
        _apply_meta(rule, name, value)
        return

    if name in STICKY_BUFFERS:
        # Applies to every following content/pcre option.
        state.buffer = STICKY_BUFFERS[name]
        return

    if name in UNSUPPORTED_BUFFERS:
        state.buffer = None
        state.last = None
        rule.unsupported.append(f"buffer {name} ({UNSUPPORTED_BUFFERS[name]})")
        return

    if name == "content":
        _apply_content(rule, value, state)
        return

    if name == "pcre":
        _apply_pcre(rule, value, state)
        return

    if name == "flow":
        flow: dict[str, bool] = {}
        for part in re.split(r"[,\s]+", value):
            part = part.strip()
            if part:
                flow[part] = True
        rule.options.append({"kind": "flow", "value": flow})
        return

    if name == "flags":
        rule.options.append({"kind": "flags", "value": value})
        return

    if name in {"dsize", "ttl"}:
        parsed = _parse_numeric_op(value)
        if parsed is None:
            rule.unsupported.append(f"{name}:{value}")
        else:
            rule.options.append({"kind": name, **parsed})
        return

    target = state.target(rule)

    if name in _SIMPLE_MODIFIERS:
        if target is None:
            rule.unsupported.append(name)
        else:
            target[name] = True
        return

    if name in _RANGE_MODIFIERS:
        if target is None:
            rule.unsupported.append(name)
            return
        number = _to_int(value)
        if number is None:
            rule.unsupported.append(f"{name}:{value}")
        else:
            target[name] = number
            if name == "offset" and "depth" not in target:
                target["depth"] = max(1, len(str(target.get("value") or "")))
        return

    if name in _UNSUPPORTED_MODIFIERS:
        # distance/within/bsize/rawbytes change what the pattern means
        # relative to the previous match; approximating them is not acceptable.
        rule.unsupported.append(name)
        return

    if name in _MODIFIER_BUFFERS:
        if target is None:
            rule.unsupported.append(f"buffer {name} without content")
        else:
            target["buffer"] = _MODIFIER_BUFFERS[name]
        return

    rule.unsupported.append(name)


def _apply_meta(rule: ParsedRule, name: str, value: str) -> None:
    text = unquote(value)
    if name == "msg":
        rule.msg = text
    elif name == "sid":
        try:
            rule.sid = int(text)
        except ValueError as exc:
            raise RuleSyntaxError(f"sid is not an integer: {text!r}") from exc
    elif name == "rev":
        try:
            rule.rev = int(text)
        except ValueError:
            rule.rev = 1
    elif name == "classtype":
        rule.classtype = text.lower()
    elif name == "priority":
        try:
            rule.priority = int(text)
        except ValueError:
            rule.priority = None
    elif name == "reference":
        rule.reference = text
    elif name == "metadata":
        rule.metadata = text


def _parse_numeric_op(value: str) -> dict[str, Any] | None:
    """Parse ``>10``, ``<20``, ``10``, ``10<>20`` into a comparison dict."""
    value = value.strip()
    match = re.fullmatch(r"([<>]?)=?\s*(\d+)\s*(?:<>\s*(\d+))?", value)
    if not match:
        return None
    op = match.group(1) or "="
    low = int(match.group(2))
    high = match.group(3)
    if high is not None:
        return {"op": "range", "low": low, "high": int(high)}
    if op == ">":
        return {"op": ">", "value": low}
    if op == "<":
        return {"op": "<", "value": low}
    return {"op": "=", "value": low}


def _split_inline(value: str) -> list[str]:
    """Split a content/pcre option from its inline modifiers.

    Handles both ``content:"x"; nocase`` (separate options, handled earlier) and
    ``content:"x", nocase, depth:4`` while respecting quoted commas inside the
    value itself.
    """
    parts: list[str] = []
    current: list[str] = []
    in_quotes = False
    escaped = False
    for char in value:
        if escaped:
            current.append(char)
            escaped = False
            continue
        if char == "\\":
            current.append(char)
            escaped = True
            continue
        if char == '"':
            in_quotes = not in_quotes
            current.append(char)
            continue
        if char in ";," and not in_quotes:
            parts.append("".join(current).strip())
            current = []
            continue
        current.append(char)
    tail = "".join(current).strip()
    if tail:
        parts.append(tail)
    return [part for part in parts if part]

def _apply_content(rule: ParsedRule, value: str, state: _ParseState) -> None:
    # Both spellings occur in the wild:
    #   content:"x"; nocase; depth:5;
    #   content:"x", nocase, depth 5;
    parts = _split_inline(value)
    if not parts:
        rule.unsupported.append("content(empty)")
        return

    raw_value = parts[0].strip()
    negated_value = False
    if raw_value.startswith("!"):
        negated_value = True
        raw_value = raw_value[1:].strip()

    text, binary = decode_content(unquote(raw_value))
    if text == "" and binary is None:
        rule.unsupported.append("content(empty)")
        return

    option: dict[str, Any] = {
        "kind": "content",
        "buffer": state.buffer,
        "value": text,
        "bytes": binary.hex() if binary is not None else None,
        "negated": negated_value,
    }
    state.open(rule, option)

    for modifier in parts[1:]:
        _apply_inline_modifier(rule, option, modifier)


def _apply_inline_modifier(rule: ParsedRule, option: dict[str, Any], modifier: str) -> None:
    """Apply a modifier written inside the content option itself."""
    key = modifier.strip()
    if not key:
        return
    if ":" in key:
        name, arg = key.split(":", 1)
        name = name.strip().lower()
        arg = arg.strip().strip('"')
    elif " " in key:
        name, arg = key.split(None, 1)
        name = name.strip().lower()
        arg = arg.strip().strip('"')
    else:
        name = key.lower()
        arg = ""

    if name in _SIMPLE_MODIFIERS:
        option[name] = True
    elif name in _RANGE_MODIFIERS:
        number = _to_int(arg)
        if number is None:
            rule.unsupported.append(f"{name}:{arg}")
        else:
            option[name] = number
    elif name in _MODIFIER_BUFFERS:
        option["buffer"] = _MODIFIER_BUFFERS[name]
    elif name in STICKY_BUFFERS:
        option["buffer"] = STICKY_BUFFERS[name]
    elif name in _UNSUPPORTED_MODIFIERS or name in UNSUPPORTED_BUFFERS:
        rule.unsupported.append(name)
    else:
        rule.unsupported.append(name)


def _apply_pcre(rule: ParsedRule, value: str, state: _ParseState) -> None:
    parts = _split_inline(value)
    if not parts:
        rule.unsupported.append("pcre(empty)")
        return

    raw_pattern = unquote(parts[0].strip())
    negated_value = False
    if raw_pattern.startswith("!"):
        negated_value = True
        raw_pattern = unquote(raw_pattern[1:].strip())

    if not raw_pattern.startswith("/"):
        rule.unsupported.append("pcre(no delimiter)")
        return
    end = raw_pattern.rfind("/")
    if end <= 0:
        rule.unsupported.append("pcre(unterminated)")
        return

    pattern = raw_pattern[1:end]
    flags = 0
    for flag in raw_pattern[end + 1 :]:
        if flag == "i":
            flags |= re.IGNORECASE
        elif flag == "s":
            flags |= re.DOTALL
        elif flag == "m":
            flags |= re.MULTILINE
        elif flag == "x":
            flags |= re.VERBOSE
        else:
            # PCRE-only modes cannot be reproduced faithfully by Python's engine.
            rule.unsupported.append(f"pcre-flag:{flag}")

    option: dict[str, Any] = {
        "kind": "pcre",
        "buffer": state.buffer,
        "pattern": pattern,
        "flags": int(flags),
        "negated": negated_value,
    }
    state.open(rule, option)

    for modifier in parts[1:]:
        _apply_inline_modifier(rule, option, modifier)

def _to_int(value: str) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


# --------------------------------------------------------------------------
# address / port expressions
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class AddressExpr:
    any: bool
    negated: bool
    networks: tuple[Any, ...]
    unsupported_reason: str | None = None

    def matches(self, address: str | None) -> bool:
        if self.any:
            return not self.negated
        if not address:
            return False
        try:
            ip = ipaddress.ip_address(address)
        except ValueError:
            return False
        found = False
        for net in self.networks:
            if net.version == ip.version and ip in net:
                found = True
                break
        return not found if self.negated else found


@dataclass(frozen=True)
class PortExpr:
    any: bool
    negated: bool
    low: int
    high: int
    unsupported_reason: str | None = None

    def matches(self, port: int | None) -> bool:
        if self.any:
            return not self.negated
        if port is None:
            return False
        found = self.low <= port <= self.high
        return not found if self.negated else found


def parse_address_expr(
    expression: str, variables: dict[str, str] | None = None, depth: int = 0
) -> AddressExpr:
    """Parse ``any``, ``!10.0.0.0/8``, ``[a, b]``, ``$HOME_NET`` and friends."""
    if depth > _MAX_VARIABLE_DEPTH:
        return AddressExpr(False, False, (), "variable recursion is too deep")
    variables = variables if variables is not None else default_variables()
    text = expression.strip()
    negated = False
    if text.startswith("!"):
        negated = True
        text = text[1:].strip()

    if text.startswith("$"):
        name = text[1:]
        resolved = variables.get(name)
        if not resolved:
            return AddressExpr(False, negated, (), f"variable ${name} is undefined")
        inner = parse_address_expr(resolved, variables, depth + 1)
        return AddressExpr(
            any=inner.any,
            negated=(negated != inner.negated),
            networks=inner.networks,
            unsupported_reason=inner.unsupported_reason,
        )

    if text.startswith("[") and text.endswith("]"):
        networks: list[Any] = []
        for chunk in text[1:-1].split(","):
            chunk = chunk.strip()
            if not chunk:
                continue
            item = parse_address_expr(chunk, variables, depth + 1)
            if item.unsupported_reason:
                return AddressExpr(False, negated, (), item.unsupported_reason)
            if item.any:
                return AddressExpr(True, negated, ())
            if item.negated:
                # A negated list entry cannot be represented as a single range.
                return AddressExpr(False, negated, (), "negated list entry")
            networks.extend(item.networks)
        if not networks:
            return AddressExpr(False, negated, (), "empty address list")
        return AddressExpr(False, negated, tuple(networks))

    if text.lower() == "any":
        return AddressExpr(True, negated, ())

    try:
        return AddressExpr(False, negated, (ipaddress.ip_network(text, strict=False),))
    except ValueError:
        return AddressExpr(False, negated, (), f"{text!r} is not an address or network")


def parse_port_expr(
    expression: str, variables: dict[str, str] | None = None, depth: int = 0
) -> PortExpr:
    """Parse ``any``, ``443``, ``1024:``, ``:1024``, ``[80,443]``, ``$HTTP_PORTS``."""
    if depth > _MAX_VARIABLE_DEPTH:
        return PortExpr(False, False, 0, 0, "variable recursion is too deep")
    variables = variables if variables is not None else default_variables()
    text = expression.strip()
    negated = False
    if text.startswith("!"):
        negated = True
        text = text[1:].strip()

    if text.startswith("$"):
        name = text[1:]
        resolved = variables.get(name)
        if not resolved:
            return PortExpr(False, negated, 0, 0, f"variable ${name} is undefined")
        inner = parse_port_expr(resolved, variables, depth + 1)
        return PortExpr(
            any=inner.any,
            negated=(negated != inner.negated),
            low=inner.low,
            high=inner.high,
            unsupported_reason=inner.unsupported_reason,
        )

    if text.startswith("[") and text.endswith("]"):
        low, high = 65535, -1
        for chunk in text[1:-1].split(","):
            chunk = chunk.strip()
            if not chunk:
                continue
            item = parse_port_expr(chunk, variables, depth + 1)
            if item.unsupported_reason:
                return PortExpr(False, negated, 0, 0, item.unsupported_reason)
            if item.any:
                return PortExpr(True, negated, 0, 65535)
            if item.negated:
                return PortExpr(False, negated, 0, 0, "negated list entry")
            low = min(low, item.low)
            high = max(high, item.high)
        if high < low:
            return PortExpr(False, negated, 0, 0, "empty port list")
        return PortExpr(False, negated, low, high)

    if text.lower() == "any":
        return PortExpr(True, negated, 0, 65535)

    match = re.fullmatch(r"(\d*)\s*:\s*(\d*)", text)
    if match:
        low = int(match.group(1)) if match.group(1) else 0
        high = int(match.group(2)) if match.group(2) else 65535
        if high < low:
            low, high = high, low
        return PortExpr(False, negated, low, high)

    if text.isdigit():
        value = int(text)
        return PortExpr(False, negated, value, value)

    return PortExpr(False, negated, 0, 0, f"{text!r} is not a port expression")

def default_variables() -> dict[str, str]:
    """Suricata variable defaults; ``*_SERVERS`` all collapse onto HOME_NET."""
    variables: dict[str, str] = {
        "HOME_NET": "[" + ",".join(DEFAULT_HOME_NET) + "]",
        "EXTERNAL_NET": "!$HOME_NET",
    }
    for name in (
        "HTTP_SERVERS",
        "HTTPS_SERVERS",
        "DNS_SERVERS",
        "SMTP_SERVERS",
        "SQL_SERVERS",
        "TELNET_SERVERS",
        "DC_SERVERS",
        "SSH_SERVERS",
        "SIP_SERVERS",
        "FTP_SERVERS",
        "SMB_SERVERS",
        "FILE_DATA_SERVERS",
        "SHELLCODE_SERVERS",
        "KRB5_SERVERS",
        "NFS_SERVERS",
        "RDP_SERVERS",
        "TFTP_SERVERS",
        "IKE_SERVERS",
        "DNP3_SERVERS",
        "MODBUS_SERVERS",
        "ENIP_SERVERS",
    ):
        variables[name] = "$HOME_NET"
    variables.update(DEFAULT_PORT_VARS)
    return variables


def merge_variables(overrides: dict[str, str] | None = None) -> dict[str, str]:
    variables = default_variables()
    if overrides:
        for key, value in overrides.items():
            if isinstance(value, str) and value.strip():
                variables[key] = value.strip()
    return variables


# --------------------------------------------------------------------------
# file parsing
# --------------------------------------------------------------------------


def iter_rule_lines(text: str) -> Iterator[str]:
    """Yield complete rule lines, joining backslash continuations."""
    buffer = ""
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if stripped.endswith("\\"):
            buffer += stripped[:-1]
            continue
        candidate = buffer + stripped
        buffer = ""
        if _RULE_LINE_RE.match(candidate):
            yield candidate


def parse_rule_text(text: str) -> tuple[list[ParsedRule], list[str]]:
    """Parse a whole ``.rules`` file: returns (rules, error messages)."""
    rules: list[ParsedRule] = []
    errors: list[str] = []
    seen: set[int] = set()
    for index, line in enumerate(iter_rule_lines(text), start=1):
        try:
            parsed = parse_rule(line)
        except RuleSyntaxError as exc:
            errors.append(f"line {index}: {exc}")
            continue
        if parsed.sid in seen:
            continue
        seen.add(parsed.sid)
        rules.append(parsed)
    return rules, errors


def load_bundled_files() -> list[tuple[Path, str, str]]:
    """List vendored rule files as ``(path, source, category)`` tuples."""
    if not RULES_DIR.is_dir():
        return []
    found: list[tuple[Path, str, str]] = []
    for path in sorted(RULES_DIR.rglob("*.rules")):
        relative = path.relative_to(RULES_DIR)
        source = f"bundled:{relative.parts[0]}" if relative.parts else "bundled"
        middle = relative.parts[1:-1] if len(relative.parts) > 1 else ()
        category = "/".join(middle) if middle else relative.stem
        found.append((path, source, category))
    return found

# --------------------------------------------------------------------------
# storage
# --------------------------------------------------------------------------

_UPSERT_SQL = """
INSERT INTO suricata_rules (
    sid, rev, action, protocol, src_net, src_port, direction, dst_net, dst_port,
    msg, classtype, priority, severity, reference, metadata, options,
    unsupported, supported, approximate, enabled, source, category, raw,
    created_at, updated_at
) VALUES (
    :sid, :rev, :action, :protocol, :src_net, :src_port, :direction, :dst_net, :dst_port,
    :msg, :classtype, :priority, :severity, :reference, :metadata, :options,
    :unsupported, :supported, :approximate, :enabled, :source, :category, :raw,
    :created_at, :updated_at
)
ON CONFLICT(sid) DO UPDATE SET
    rev = excluded.rev,
    action = excluded.action,
    protocol = excluded.protocol,
    src_net = excluded.src_net,
    src_port = excluded.src_port,
    direction = excluded.direction,
    dst_net = excluded.dst_net,
    dst_port = excluded.dst_port,
    msg = excluded.msg,
    classtype = excluded.classtype,
    priority = excluded.priority,
    severity = excluded.severity,
    reference = excluded.reference,
    metadata = excluded.metadata,
    options = excluded.options,
    unsupported = excluded.unsupported,
    supported = excluded.supported,
    approximate = excluded.approximate,
    source = excluded.source,
    category = excluded.category,
    raw = excluded.raw,
    updated_at = excluded.updated_at
"""


def _row_for(
    rule: ParsedRule,
    source: str,
    category: str | None,
    enabled: int,
    created_at: float | None = None,
) -> dict[str, Any]:
    now = time.time()
    row = rule.as_row()
    row.update(
        {
            "source": source,
            "category": category,
            "enabled": enabled,
            "created_at": created_at if created_at is not None else now,
            "updated_at": now,
        }
    )
    return row


def import_rules(
    rules: Iterable[ParsedRule],
    *,
    source: str,
    category: str | None = None,
    enabled: int = 1,
) -> dict[str, int]:
    """Upsert parsed rules.

    Re-importing keeps whatever enabled/disabled state the analyst chose: the
    UPSERT deliberately does not touch the ``enabled`` column of an existing row.
    """
    imported = 0
    updated = 0
    with db.get_conn() as conn:
        existing = {int(row["sid"]) for row in conn.execute("SELECT sid FROM suricata_rules")}
        for rule in rules:
            if rule.sid in existing:
                updated += 1
            else:
                imported += 1
                existing.add(rule.sid)
            conn.execute(_UPSERT_SQL, _row_for(rule, source, category, enabled))
    return {"imported": imported, "updated": updated}


def seed_bundled_rules(*, enabled: int = 1) -> dict[str, Any]:
    """Import every vendored rule file. Idempotent: SIDs are upserted."""
    files = load_bundled_files()
    if not files:
        return {
            "files": 0,
            "imported": 0,
            "updated": 0,
            "errors": ["no bundled rule files found"],
        }

    imported = 0
    updated = 0
    errors: list[str] = []
    with db.get_conn() as conn:
        existing = {int(row["sid"]) for row in conn.execute("SELECT sid FROM suricata_rules")}
        for path, source, category in files:
            try:
                text = path.read_text(encoding="utf-8", errors="replace")
            except OSError as exc:  # pragma: no cover - unreadable file
                errors.append(f"{path.name}: {exc}")
                continue
            rules, file_errors = parse_rule_text(text)
            errors.extend(f"{path.name}: {message}" for message in file_errors[:3])
            for rule in rules:
                if rule.sid in existing:
                    updated += 1
                else:
                    imported += 1
                    existing.add(rule.sid)
                conn.execute(_UPSERT_SQL, _row_for(rule, source, category, enabled))
    log.info(
        "suricata rules seeded from %s files: %s new, %s updated", len(files), imported, updated
    )
    return {
        "files": len(files),
        "imported": imported,
        "updated": updated,
        "errors": errors[:20],
    }


def get_rule(sid: int) -> dict[str, Any] | None:
    row = db.query_one("SELECT * FROM suricata_rules WHERE sid = ?", (sid,))
    return dict(row) if row else None


def save_rule(
    sid: int,
    *,
    raw: str | None = None,
    enabled: bool | None = None,
) -> dict[str, Any]:
    """Update a stored rule. Editing the text re-parses it; the SID must match."""
    current = get_rule(sid)
    if current is None:
        raise bad_request("rule_not_found", f"No Suricata rule with sid {sid}.")

    fields: dict[str, Any] = {"updated_at": time.time()}
    if enabled is not None:
        fields["enabled"] = 1 if enabled else 0

    if raw is not None:
        try:
            parsed = parse_rule(raw)
        except RuleSyntaxError as exc:
            raise bad_request("invalid_rule", str(exc), {"sid": sid}) from exc
        if parsed.sid != sid:
            raise bad_request(
                "sid_mismatch",
                f"The edited rule declares sid {parsed.sid}; a rule cannot be moved to another sid.",
                {"stored_sid": sid, "parsed_sid": parsed.sid},
            )
        row = _row_for(
            parsed,
            str(current.get("source") or "manual"),
            current.get("category"),
            int(fields.get("enabled", current.get("enabled") or 0)),
            created_at=current.get("created_at"),
        )
        row.pop("created_at")
        fields.update(row)

    # db.execute() runs the statement with positional parameters, so the
    # assignment list and the parameter list have to line up exactly.
    columns = list(fields)
    assignments = ", ".join(f"{key} = ?" for key in columns)
    params: list[Any] = [fields[key] for key in columns]
    params.append(sid)
    db.execute(f"UPDATE suricata_rules SET {assignments} WHERE sid = ?", params)
    return get_rule(sid) or current


def delete_rule(sid: int) -> bool:
    if get_rule(sid) is None:
        return False
    db.execute("DELETE FROM suricata_rules WHERE sid = ?", (sid,))
    return True


def rule_stats() -> dict[str, Any]:
    row = db.query_one(
        """
        SELECT COUNT(*)                                         AS total,
               SUM(CASE WHEN enabled = 1 THEN 1 ELSE 0 END)     AS enabled,
               SUM(CASE WHEN supported = 1 THEN 1 ELSE 0 END)   AS supported,
               SUM(CASE WHEN supported = 0 THEN 1 ELSE 0 END)   AS unsupported,
               SUM(CASE WHEN approximate = 1 THEN 1 ELSE 0 END) AS approximate
          FROM suricata_rules
        """
    )
    severities = {
        str(item["severity"]): int(item["n"])
        for item in db.query_all(
            "SELECT severity, COUNT(*) AS n FROM suricata_rules GROUP BY severity"
        )
    }
    sources = [
        {"source": str(item["source"]), "rules": int(item["n"])}
        for item in db.query_all(
            "SELECT source, COUNT(*) AS n FROM suricata_rules GROUP BY source ORDER BY n DESC"
        )
    ]
    categories = [
        {"category": str(item["category"] or ""), "rules": int(item["n"])}
        for item in db.query_all(
            "SELECT category, COUNT(*) AS n FROM suricata_rules"
            " GROUP BY category ORDER BY n DESC LIMIT 25"
        )
    ]
    return {
        "total": int(row["total"] or 0) if row else 0,
        "enabled": int(row["enabled"] or 0) if row else 0,
        "supported": int(row["supported"] or 0) if row else 0,
        "unsupported": int(row["unsupported"] or 0) if row else 0,
        "approximate": int(row["approximate"] or 0) if row else 0,
        "severities": {name: severities.get(name, 0) for name in SEVERITIES},
        "sources": sources,
        "categories": categories,
    }


# --------------------------------------------------------------------------
# matcher configuration
# --------------------------------------------------------------------------

CONFIG_KEY = "suricata_config"

DEFAULT_CONFIG: dict[str, Any] = {
    "home_net": list(DEFAULT_HOME_NET),
    "variables": {},
    "max_findings_per_rule": 25,
    "include_unsupported": False,
}


def config() -> dict[str, Any]:
    """Matcher configuration, stored in the ``settings`` table."""
    from app.core import runtime_settings

    stored = runtime_settings.load_overrides().get(CONFIG_KEY)
    if not isinstance(stored, dict):
        stored = {}
    merged: dict[str, Any] = json.loads(json.dumps(DEFAULT_CONFIG))
    merged.update({key: value for key, value in stored.items() if value is not None})
    return merged


def save_config(payload: dict[str, Any]) -> dict[str, Any]:
    from app.core import runtime_settings

    allowed = set(DEFAULT_CONFIG)
    unknown = sorted(set(payload) - allowed)
    if unknown:
        raise bad_request(
            "invalid_setting",
            f"Unknown suricata setting(s): {', '.join(unknown)}.",
            {"allowed": sorted(allowed)},
        )

    clean: dict[str, Any] = {}
    if "home_net" in payload:
        value = payload["home_net"]
        if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
            raise bad_request("invalid_setting", "home_net must be a list of CIDR strings.")
        for entry in value:
            try:
                ipaddress.ip_network(entry, strict=False)
            except ValueError as exc:
                raise bad_request(
                    "invalid_setting", f"{entry!r} is not a valid network."
                ) from exc
        clean["home_net"] = [entry.strip() for entry in value if entry.strip()]
    if "variables" in payload:
        value = payload["variables"]
        if not isinstance(value, dict) or not all(
            isinstance(key, str) and isinstance(val, str) for key, val in value.items()
        ):
            raise bad_request("invalid_setting", "variables must map name -> expression string.")
        clean["variables"] = {key.strip().upper(): val.strip() for key, val in value.items()}
    if "max_findings_per_rule" in payload:
        try:
            number = int(payload["max_findings_per_rule"])
        except (TypeError, ValueError) as exc:
            raise bad_request(
                "invalid_setting", "max_findings_per_rule must be an integer."
            ) from exc
        if not 1 <= number <= 1000:
            raise bad_request(
                "invalid_setting", "max_findings_per_rule must be between 1 and 1000."
            )
        clean["max_findings_per_rule"] = number
    if "include_unsupported" in payload:
        clean["include_unsupported"] = bool(payload["include_unsupported"])

    overrides = runtime_settings.load_overrides()
    current = config()
    current.update(clean)
    overrides[CONFIG_KEY] = current
    runtime_settings.save_overrides(overrides)
    return current


def variables_from_config(cfg: dict[str, Any] | None = None) -> dict[str, str]:
    cfg = cfg if cfg is not None else config()
    overrides: dict[str, str] = {}
    home = cfg.get("home_net") or []
    if home:
        overrides["HOME_NET"] = "[" + ",".join(home) + "]"
    extra = cfg.get("variables") or {}
    if isinstance(extra, dict):
        overrides.update({str(key): str(value) for key, value in extra.items()})
    return merge_variables(overrides)


__all__ = [
    "CONFIG_KEY",
    "RULES_DIR",
    "SEVERITIES",
    "STICKY_BUFFERS",
    "UNSUPPORTED_BUFFERS",
    "AddressExpr",
    "ParsedRule",
    "PortExpr",
    "RuleSyntaxError",
    "config",
    "default_variables",
    "delete_rule",
    "get_rule",
    "import_rules",
    "load_bundled_files",
    "merge_variables",
    "parse_address_expr",
    "parse_port_expr",
    "parse_rule",
    "parse_rule_text",
    "rule_stats",
    "save_config",
    "save_rule",
    "seed_bundled_rules",
    "severity_for",
    "variables_from_config",
]