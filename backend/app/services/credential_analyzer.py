"""Credential discovery over the rows the other analysers wrote, plus the control
channels of the four command protocols.

The normative contract is ``docs/CREDENTIALS.md``, whose §2 gives the stage two
sources and no third: the rows the other analysers already wrote, and — for FTP,
SMTP, POP3 and IMAP only — the control channel of a session those rows say
exchanged a credential, reassembled with the stream machinery this application
already uses. Nothing is invented, and a value is only ever reported where a
protocol said what the field is.

Why it is built this way:

* **The rows first, because they are free.** HTTP needs no capture access at all:
  its bodies are stored with their transactions, so the HTTP half of a scan works
  even on an installation whose uploads have been purged.
* **The control channel second, because the value is deliberately not in the
  database.** ``protocol_analyzer`` blanks a ``PASS`` argument and keeps an SMTP
  ``AUTH`` command's mechanism without the Base64 exchange that follows it
  (``docs/PROTOCOLS.md`` §1.3), and that redaction must not be undone: every
  ``/protocols`` response sends ``detail`` to the browser, so a value written
  there would be served unredacted. The reassembly happens here, for the streams
  the analyser already classified, and the value goes into ``credentials`` and
  nowhere else (§10).
* **Base64 is decoded only where a protocol says the field is Base64** (§3.1):
  HTTP Basic, and ``AUTH PLAIN`` / ``AUTH LOGIN`` / ``AUTHENTICATE``. Everywhere
  else a Base64-looking string is left alone, because decoding a token that
  nothing identified would manufacture a value the wire never carried.
* **Redaction happens before storage.** A finding's ``evidence`` line quotes the
  source field or command with the value's middle removed, so a row read straight
  out of SQLite leaks no more than the API does, and ``value_preview`` never
  equals the full value (§5).
* **Nothing is logged.** The stage logs counts and kinds; a credential value
  never enters a log line, a warning or an error message (§5). The warnings the
  stage does record name streams, protocols and caps — never values.

An optional stage never sinks an analysis: a control stream that cannot be
reassembled (capture purged, timeout, nothing to follow) is skipped and named in
the stage warning, and the HTTP half of the scan still writes its findings.

Where this module had to interpret the contract, the reasoning is on the
function or constant it concerns; the readings are listed in ``CONTRACT_NOTES``.
"""

from __future__ import annotations

import json
import re
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterator, Sequence
from urllib.parse import parse_qsl

from app.core import runtime_settings
from app.core.logging import get_logger
from app.db import database as db
from app.services import http_analyzer, protocol_analyzer, tshark
from app.services.jobs import JobContext

log = get_logger("apackets.credentials")

# --------------------------------------------------------------------------
# caps (docs/CREDENTIALS.md §9)
# --------------------------------------------------------------------------

MAX_FINDINGS = 200          # rows stored per analysis, highest confidence first
MAX_VALUE_CHARS = 512       # a stored value's length, truncated and flagged
MAX_BODY_CHARS = 262144     # characters of any one body examined
MAX_FIELDS_PER_LOCATION = 200   # fields read from one form/JSON/query
MIN_VALUE_CHARS = 3         # shorter values are ignored
PREVIEW_HEAD = 3            # §5
PREVIEW_TAIL = 2            # §5
JSON_DEPTH = 6              # how deep the JSON walker looks

# §2(b): the control channels of the four command protocols, reassembled. Small
# numbers on purpose - a mail control stream is a few hundred bytes, and the caps
# are what keep a capture with thousands of mail streams cheap.
MAX_CONTROL_STREAMS = 25    # control streams reassembled per protocol
MAX_STREAM_CHARS = 262144   # characters examined from one reassembled stream
STREAM_TIMEOUT_S = 20       # wall clock for one reassembly

#: The verbs §2(a) reads out of ``detail.commands`` to decide that a session
#: exchanged a credential, and whose control channel is therefore worth reading.
CONTROL_VERBS: frozenset[str] = frozenset(
    {"USER", "PASS", "AUTH", "LOGIN", "AUTHENTICATE"}
)

#: ``method`` of a value read out of a reassembled control channel, so a reader can
#: tell a value the analyser stored from one this stage recovered from the wire.
CONTROL_METHOD = "control_stream"

#: The verbs a value can follow in the reassembled text (§3.1's command grammar).
_SASL_MECHANISMS: frozenset[str] = frozenset({"PLAIN", "LOGIN"})

#: The IMAP commands this stage reads. A token that is not one of them, in front of
#: one that is, is the command's tag (``a2 LOGIN …``) rather than a verb.
_IMAP_COMMANDS: frozenset[str] = frozenset({"LOGIN", "AUTHENTICATE"})

#: §5's separator between the head and the tail of a redacted value.
PREVIEW_SEPARATOR = "•••"

#: How long one evidence line may be. §6 asks for "one redacted line of
#: context", and a stored JSON body can be megabytes long, so the line is cut
#: where no other constant speaks: it quotes the field and its redacted value,
#: which never needs more than this.
EVIDENCE_MAX_CHARS = 240

#: The protocols this build can read credentials from (§1). The runtime setting
#: ``credential_protocols`` selects a subset of these; an empty list means none.
PROTOCOLS: tuple[str, ...] = runtime_settings.CREDENTIAL_PROTOCOLS

#: Every ``kind`` the table can hold (§6).
KINDS: tuple[str, ...] = (
    "username",
    "password",
    "api_key",
    "bearer_token",
    "other_secret",
    "aws_access_key",
    "jwt",
    "pem_private_key",
    "github_token",
    "slack_token",
    "google_api_key",
    "stripe_key",
)

CONFIDENCE_LEVELS: tuple[str, ...] = ("high", "medium", "low")

#: Sort rank: high first. Used for MAX_FINDINGS and for the marker's counts.
_CONFIDENCE_RANK: dict[str, int] = {"high": 0, "medium": 1, "low": 2}

#: The ``stats_cache`` kind recording that this stage ran for an analysis, with
#: the counts it wrote and when. It is what lets the endpoint tell "the scan has
#: run and found nothing" apart from "the scan has never run" (§7), the same way
#: ``protocol_analyzer.MARKER_KIND`` answers ``extracted``.
MARKER_KIND = "credentials"

#: What this module knowingly had to interpret in docs/CREDENTIALS.md, in one
#: place, so a reader comparing the two does not have to reverse-engineer it:
#:
#: 1. §5's first bullet forbids the full value appearing in a list response while
#:    its parenthetical ("••• between them when the value is longer than
#:    2 x (head + tail)") prints values of ten characters or fewer verbatim. The
#:    bullet wins: :func:`preview` hides the middle whenever there is a middle to
#:    hide and, for a value too short to split, prints no character of it at all.
#: 2. §3.3 is written with markdown-escaped pipes (``ghp\\|gho``); the patterns
#:    here use the alternation the intent requires.
#: 3. §2(a) gives FTP ``detail.auth_username``; the FTP detail the analyser actually
#:    writes uses ``username``, so both names are read.
#: 4. §8 gives no default for ``order``; it is ``desc``, like every other list
#:    endpoint in this application, and the confidence sort is expressed so that
#:    ``desc`` means "highest confidence first".
#: 5. §9 says MAX_FIELDS_PER_LOCATION limits "candidate fields"; it is applied to
#:    every field read from one location, because that is what bounds the work.
#: 6. §6 does not say whether ``value_length`` counts the stored value or the wire
#:    value; ``Documentation/Credentials.md`` §6 does, so a truncated row reports
#:    512 and sets ``value_truncated`` rather than a length it cannot show.
#: 7. §2(b) gates a reassembly on "a credential-bearing verb, or an authenticated
#:    SMTP/POP3/IMAP login"; the second clause is read as the record of an
#:    authenticated login the analyser keeps in ``password_present`` and
#:    ``auth_username``, and it is applied to FTP too, whose detail records the
#:    same two facts under ``username``.
#: 8. §2(a) lists the command *verbs* as the signal that a credential was
#:    exchanged; a command argument the analyser did store (an FTP ``USER``, an
#:    identity in ``auth_username``) is still read as a value, because it is a
#:    value the row literally carries - the verbs add the control channel, they do
#:    not take away what the row already holds.
CONTRACT_NOTES: tuple[str, ...] = (
    "§5's no-full-value rule is applied to values of every length (see preview()).",
    "§3.3's escaped pipes are read as alternation.",
    "FTP username is read from detail.username as well as detail.auth_username.",
    "order defaults to desc; confidence sorts high first under desc.",
    "MAX_FIELDS_PER_LOCATION bounds every field read from one location.",
    "value_length counts the stored value, so a truncated row reports MAX_VALUE_CHARS.",
    "a session that recorded an authenticated login is read like one that recorded a verb.",
    "a value the analyser did store is still reported; the verbs add the control channel.",
)

# --------------------------------------------------------------------------
# §3.2 field names
# --------------------------------------------------------------------------

#: The §3.2 list, grouped by the kind a match yields. The grouping is this
#: module's reading: the contract fixes which *names* are credential-like, and
#: the kind column of §6 needs one answer per match.
#:
#: Two lists are merged here, and deliberately. ``http_analyzer.CREDENTIAL_KEYWORDS``
#: is the application's existing answer to "does this request look like it carries a
#: credential", and every name in it is covered below, so the two features cannot
#: disagree about a password form. The rest of §3.2's list is added because that
#: keyword list was written to *flag a request*, not to name a field: it holds
#: haystack substrings (``pass=``, ``user=``, ``authorization:``) and misses names a
#: real login uses — ``login``, ``logon``, ``account``, ``email``, ``sessionid``,
#: ``access_token``, ``client_secret`` — which this contract names explicitly.
_CREDENTIAL_KEYWORD_NAMES: frozenset[str] = frozenset(
    keyword.rstrip("=:").strip().lower().replace("-", "_")
    for keyword in http_analyzer.CREDENTIAL_KEYWORDS
)

_FIELD_KINDS: dict[str, str] = {
    # http_analyzer.CREDENTIAL_KEYWORDS, reduced to the field names it implies.
    **{name: "username" for name in ("user",)},
    **{name: "password" for name in ("pass", "passwd", "pwd", "password")},
    **{name: "api_key" for name in ("api_key", "apikey")},
    **{name: "other_secret" for name in ("secret", "token", "authorization")},
    # §3.2's wider list, and the paragraph above says why it is wider.
    "username": "username",
    "user_name": "username",
    "login": "username",
    "login_id": "username",
    "logon": "username",
    "email": "username",
    "account": "username",
    "name": "username",
    "client_secret": "api_key",
    "access_key": "api_key",
    "access_token": "other_secret",
    "auth_token": "other_secret",
    "session": "other_secret",
    "sessionid": "other_secret",
    "bearer": "bearer_token",
}

#: The §3.1 cookie markers: a cookie *name* that mentions one of these is
#: credential-like. Substring matching, unlike §3.2's exact names, because real
#: cookie names compose: ``PHPSESSID``, ``JSESSIONID``, ``csrftoken`` and
#: ``session_id`` all name a session or a token without being one of the words.
_COOKIE_MARKERS: tuple[str, ...] = ("session", "token", "auth", "jwt", "sid", "api_key")

#: A header whose name is credential-like (``X-Api-Key``, ``X-Auth-Token``): the
#: ``x-`` prefix is dropped before the §3.2 names are consulted, because that
#: prefix is the HTTP convention for a non-standard header rather than a word.
_HEADER_PREFIXES: tuple[str, ...] = ("x_",)

#: §3.4 placeholders. Exactly the documents' list: a value that is one of these
#: words is a template, not a credential, and reporting it would train a reader
#: to ignore the page.
_PLACEHOLDER_WORDS: frozenset[str] = frozenset(
    {"password", "changeme", "example", "test", "null", "undefined", "true", "false"}
)
_PLACEHOLDER_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"^x{3,}$"),        # xxx… (any run of x)
    re.compile(r"^<.*>$"),         # <...>
    re.compile(r"^\*+$"),          # ***
)

# --------------------------------------------------------------------------
# §3.3 secret shapes
# --------------------------------------------------------------------------

#: Applied only to values §3.1/§3.2 already selected, never to a whole body.
#: Order matters: the first shape that matches names the finding, so the table is
#: the contract's order.
PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("aws_access_key", re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b")),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b")),
    ("pem_private_key", re.compile(r"-----BEGIN(?: [A-Z]+)? PRIVATE KEY-----")),
    ("github_token", re.compile(r"\b(?:ghp|gho|ghu|ghs)_[A-Za-z0-9]{36}\b")),
    ("slack_token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b")),
    ("google_api_key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")),
    ("stripe_key", re.compile(r"\b(?:sk|pk)_(?:live|test)_[A-Za-z0-9]{16,}\b")),
)

_BASE64_RE = re.compile(r"^[A-Za-z0-9+/]+={0,2}$")

# --------------------------------------------------------------------------
# values and redaction
# --------------------------------------------------------------------------


def preview(value: str) -> str:
    """§5's redaction: the head and tail of a value, its middle removed.

    The contract's parenthetical prints a short value verbatim, which would put
    the full value in a list response — the thing §5's first bullet forbids. The
    bullet wins here: a value long enough to split keeps ``PREVIEW_HEAD`` and
    ``PREVIEW_TAIL`` characters, and one too short to split keeps none of them,
    so no response and no stored ``evidence`` line carries a complete value.
    """
    if not value:
        return ""
    if len(value) > PREVIEW_HEAD + PREVIEW_TAIL:
        candidate = f"{value[:PREVIEW_HEAD]}{PREVIEW_SEPARATOR}{value[-PREVIEW_TAIL:]}"
        # A value that already contains the separator at the right offsets would
        # be reproduced exactly; then nothing of it is shown.
        return candidate if candidate != value else PREVIEW_SEPARATOR
    return PREVIEW_SEPARATOR


@dataclass(frozen=True, slots=True)
class _Prepared:
    """A value that survived §3.4, with the length it had before truncation."""

    text: str
    length: int
    truncated: bool


def _measure(value: str) -> _Prepared:
    """The stored value, its stored length, and whether anything had to be cut.

    ``value_length`` is the length of what this row *stores*, not of what crossed
    the wire: a value longer than :data:`MAX_VALUE_CHARS` is stored truncated with
    ``value_truncated`` set, and the length of the part that was dropped is not a
    figure the page could show the value for
    (see ``Documentation/Credentials.md`` §6). The contract leaves the column's
    meaning open; the repository's own documentation of it decides the reading.
    """
    if len(value) > MAX_VALUE_CHARS:
        return _Prepared(value[:MAX_VALUE_CHARS], MAX_VALUE_CHARS, True)
    return _Prepared(value, len(value), False)


def normalise_name(name: str) -> str:
    """§3.2's name comparison: lower case, and ``-`` read as ``_``."""
    return name.strip().lower().replace("-", "_")


def _is_placeholder(value: str) -> bool:
    if value.lower() in _PLACEHOLDER_WORDS:
        return True
    return any(pattern.match(value) for pattern in _PLACEHOLDER_PATTERNS)


def _prepare_value(value: Any, field: str | None) -> _Prepared | None:
    """§3.4: everything a stored value has to survive to be reported."""
    if not isinstance(value, str):
        return None
    if len(value) < MIN_VALUE_CHARS:
        return None
    stripped = value.strip()
    if not stripped:
        return None
    if not any(char.isalnum() for char in stripped):   # wholly punctuation
        return None
    if _is_placeholder(stripped):
        return None
    if field is not None and normalise_name(stripped) == normalise_name(field):
        return None
    return _measure(value)


def shape_of(value: str) -> tuple[str, str] | None:
    """The first §3.3 shape in ``value``, as ``(kind, matched_text)``.

    The shape is returned rather than the whole value because the shape *is* the
    secret: reporting the surrounding prose under a kind of ``jwt`` would be a
    kind that describes text the secret is embedded in.
    """
    for kind, pattern in PATTERNS:
        match = pattern.search(value)
        if match:
            return kind, match.group(0)
    return None


def _evidence(prefix: str, redacted: str) -> str:
    """One redacted line, never longer than :data:`EVIDENCE_MAX_CHARS`."""
    line = " ".join(f"{prefix}{redacted}".split())
    return line[:EVIDENCE_MAX_CHARS]


# --------------------------------------------------------------------------
# collection
# --------------------------------------------------------------------------


@dataclass(slots=True)
class Finding:
    """One candidate on its way to ``credentials`` (§6)."""

    kind: str
    value: str
    value_length: int
    value_truncated: bool
    protocol: str
    location: str
    method: str
    confidence: str
    evidence: str
    note: str
    source_field: str | None = None
    transport: str | None = None
    stream_id: int | None = None
    direction: str | None = None
    client_ip: str | None = None
    client_port: int | None = None
    server_ip: str | None = None
    server_port: int | None = None
    packet_first: int | None = None
    packet_last: int | None = None
    order: int = 0


class _Scan:
    """Accumulates findings for one analysis, applying §3.4 and de-duplication.

    Duplicate suppression is keyed on what makes two rows the same fact: the same
    value, of the same kind, in the same location of the same stream, selected by
    the same field. Two different packets are two packets, so the packet is part
    of the key and a credential sent twice stays two findings.
    """

    def __init__(self, analysis_id: str) -> None:
        self.analysis_id = analysis_id
        self.findings: list[Finding] = []
        #: What the scan could not read, and which caps bit (§9). These become the
        #: stage's warnings and §8.2's ``limits``; they name streams, protocols and
        #: caps, never a value.
        self.notes: list[str] = []
        #: The protocols a source row actually answered for, so an empty section is
        #: never read as "the capture held nothing" (§8.1's ``protocols_scanned``).
        self.scanned: set[str] = set()
        self.control_streams = 0
        self._seen: set[tuple] = set()
        #: ``(kind, value, protocol, stream_id)`` for the command protocols. The same
        #: identity reaches this stage twice — once in the analyser's row and once on
        #: the wire it was read from — and a session with one username has one
        #: username, not two rows saying it. HTTP is not deduplicated this way: two
        #: header fields or two JSON fields with the same value are two locations.
        self._session_values: set[tuple] = set()
        #: Shape-derived values already reported for this analysis, so the
        #: whole-text pass of one location cannot repeat a labelled field's find.
        self._shape_reported: set[tuple[str, str]] = set()
        self._order = 0

    # -- adding ------------------------------------------------------------

    def add(
        self,
        *,
        value: Any,
        location: str,
        method: str,
        confidence: str,
        note: str | None,
        kind: str | None = None,
        vouched: bool = True,
        evidence_prefix: str = "",
        evidence_value: str | None = None,
        source_field: str | None = None,
        protocol: str = "http",
        transport: str | None = None,
        stream_id: int | None = None,
        direction: str | None = None,
        client_ip: str | None = None,
        client_port: int | None = None,
        server_ip: str | None = None,
        server_port: int | None = None,
        packet_first: int | None = None,
        packet_last: int | None = None,
    ) -> None:
        """Report ``value`` if it survives §3.4, as §3.1/§3.2/§3.3 say it should.

        ``vouched`` is False for a value no field name selected (a free-text body,
        or a field whose name is not credential-like). Such a value is reported
        only when a §3.3 shape matched it, and then at ``low`` confidence (§4).
        """
        prepared = _prepare_value(value, source_field)
        if prepared is None:
            return

        text = prepared.text
        length = prepared.length
        truncated = prepared.truncated

        shape = shape_of(text)
        if shape is not None:
            kind = shape[0]
            text = shape[1]
            length, truncated = len(text), False
            method = "pattern"
            if vouched:
                note = (
                    f"{note}; the kind comes from a matched {kind} shape"
                    if note
                    else f"A matched {kind} shape in a field the field name selected"
                )
            else:
                confidence = "low"
                note = f"A {kind} shape found in a value no field name vouched for"
        elif not vouched or kind is None:
            return

        if shape is not None:
            self._shape_reported.add((kind, text))

        drawn = evidence_value if evidence_value is not None else text
        evidence = _evidence(evidence_prefix, preview(drawn))

        if protocol != "http":
            session_key = (kind, text, protocol, stream_id)
            if session_key in self._session_values:
                return
            self._session_values.add(session_key)

        key = (
            kind,
            text,
            protocol,
            stream_id,
            location,
            source_field,
            direction,
            packet_first,
        )
        if key in self._seen:
            return
        self._seen.add(key)

        self.findings.append(
            Finding(
                kind=kind,
                value=text,
                value_length=length,
                value_truncated=truncated,
                protocol=protocol,
                location=location,
                method=method,
                confidence=confidence,
                evidence=evidence,
                note=note or "",
                source_field=source_field,
                transport=transport,
                stream_id=stream_id,
                direction=direction,
                client_ip=client_ip,
                client_port=client_port,
                server_ip=server_ip,
                server_port=server_port,
                packet_first=packet_first,
                packet_last=packet_last,
                order=self._order,
            )
        )
        self._order += 1

    def add_shape_only(
        self, *, value: Any, note: str | None = None, evidence_prefix: str = "", **kwargs: Any
    ) -> None:
        """§4 low: a §3.3 shape in a string no field name vouched for."""
        if isinstance(value, str):
            shape = shape_of(value)
            if shape is not None and shape in self._shape_reported:
                return
        self.add(value=value, method="pattern", confidence="low", kind=None,
                 vouched=False, note=note, evidence_prefix=evidence_prefix, **kwargs)


# --------------------------------------------------------------------------
# §3.1 parsers
# --------------------------------------------------------------------------


def _json_object(raw: Any) -> dict:
    if isinstance(raw, dict):
        return raw
    if not isinstance(raw, str) or not raw:
        return {}
    try:
        value = json.loads(raw)
    except (json.JSONDecodeError, TypeError):
        return {}
    return value if isinstance(value, dict) else {}


def _request_headers(raw: Any) -> dict[str, str]:
    """The stored request header block as ``{name: value}``.

    ``http_analyzer`` keeps the block as JSON in ``http_transactions`` today
    (``json.dumps(request.headers)``), and ``parse_header_lines`` is this
    application's parser for the ``\\x1f``-aggregated text TShark emits before that.
    Both shapes are accepted here — and the text one goes through the app's own
    parser rather than a second one, so a header name is split, unescaped and
    de-duplicated exactly as the HTTP analyser and its flagging already do.
    """
    if isinstance(raw, dict):
        return {
            str(name): str(value)
            for name, value in raw.items()
            if isinstance(name, str) and isinstance(value, str)
        }
    if not isinstance(raw, str) or not raw.strip():
        return {}
    text = raw.strip()
    if text.startswith("{"):
        try:
            parsed = json.loads(text)
        except (json.JSONDecodeError, TypeError):
            parsed = None
        if isinstance(parsed, dict):
            return {
                str(name): str(value)
                for name, value in parsed.items()
                if isinstance(name, str) and isinstance(value, str)
            }
    return http_analyzer.parse_header_lines(raw, separator=http_analyzer.HEADER_SEPARATOR)


def _decode_base64(text: str) -> str | None:
    """The application's strict Base64 decoder, as a plain ``str | None`` (§3.1).

    Base64 is decoded only where a protocol says the field is Base64 — HTTP Basic,
    ``AUTH PLAIN``, ``AUTH LOGIN`` — and when it is decoded it goes through
    :func:`protocol_analyzer.maybe_base64`, the one strict decoder in this build,
    so the credential scanner and the protocol analyser cannot disagree about
    whether a string was Base64. That decoder requires at least eight characters,
    a multiple of four, the standard alphabet, and a decode that is printable
    UTF-8 (the NUL of an ``AUTH PLAIN`` pair excepted) — which is why an exchange
    that stopped early cannot turn the next command verb into a password, and why
    a value that is not decoded is reported as the opaque string it was, or not at
    all.
    """
    decoded, looked_like_base64 = protocol_analyzer.maybe_base64(text)
    if not looked_like_base64:
        return None
    return decoded


# --------------------------------------------------------------------------
# protocol_sessions: FTP, SMTP, POP3, IMAP (§2, §3.1)
# --------------------------------------------------------------------------


def _commands(detail: dict) -> list[tuple[str, str | None]]:
    """``detail.commands`` as ``(verb, arg)`` pairs, whatever shape it has.

    The analyser writes ``[{verb, arg, count}]`` for FTP/SMTP/POP3 and
    ``[{verb, count}]`` for IMAP (§2), and it deliberately leaves ``arg`` out of a
    ``PASS`` command, so an absent argument is normal rather than an error: a
    command with no stored argument contributes no value.
    """
    entries = detail.get("commands")
    if not isinstance(entries, list):
        return []
    out: list[tuple[str, str | None]] = []
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        verb = entry.get("verb")
        if not isinstance(verb, str) or not verb.strip():
            continue
        arg = entry.get("arg")
        out.append((verb.strip().upper(), arg if isinstance(arg, str) and arg else None))
    return out


def _auth_values(
    scan: _Scan, *, protocol: str, arg: str, base: dict[str, Any], location_prefix: str
) -> None:
    """``AUTH <mechanism> <arg>``: §3.1's mechanism-specific decoding.

    ``PLAIN`` is Base64 of ``\\0user\\0pass`` (the authorisation identity may be
    empty, and is not copied). ``LOGIN`` carries a Base64 username and password in
    the command's arguments. Any other mechanism has no shape this build can
    decode, so the argument is left alone — a mechanism name with no value
    produces nothing at all, and a decode that does not have the shape the
    mechanism promises is reported as the opaque encoded value rather than
    guessed at.
    """
    mechanism, _, rest = arg.strip().partition(" ")
    mechanism = mechanism.upper()
    rest = rest.strip()

    if not rest:
        return

    if mechanism == "PLAIN":
        decoded = _decode_base64(rest)
        if decoded is not None:
            parts = decoded.split("\x00")
            if len(parts) >= 2 and parts[-1]:
                username = parts[-2]
                password = parts[-1]
                _emit_command_value(
                    scan, protocol=protocol, verb="AUTH", value=username,
                    kind="username", location=f"{location_prefix}_auth_plain",
                    method="auth_mechanism", confidence="high",
                    evidence_prefix=f"{location_prefix.upper()} AUTH PLAIN ",
                    evidence_value=rest, base=base,
                    note=f"{protocol.upper()} AUTH PLAIN, decoded from the argument",
                )
                _emit_command_value(
                    scan, protocol=protocol, verb="AUTH", value=password,
                    kind="password", location=f"{location_prefix}_auth_plain",
                    method="auth_mechanism", confidence="high",
                    evidence_prefix=f"{location_prefix.upper()} AUTH PLAIN ",
                    evidence_value=rest, base=base,
                    note=f"{protocol.upper()} AUTH PLAIN, decoded from the argument",
                )
                return
        scan.add(
            value=rest, kind="other_secret",
            location=f"{location_prefix}_auth_plain", method="auth_mechanism",
            confidence="medium", protocol=protocol, source_field="AUTH",
            evidence_prefix=f"{location_prefix.upper()} AUTH PLAIN ",
            note=(
                f"An {protocol.upper()} AUTH PLAIN argument that is not the "
                "\\0user\\0pass pair the mechanism promises; kept whole rather than guessed at"
            ),
            **base,
        )
        return

    if mechanism == "LOGIN":
        tokens = rest.split()
        if len(tokens) >= 2:
            username = _decode_base64(tokens[0])
            password = _decode_base64(tokens[1])
            if username is not None:
                _emit_command_value(
                    scan, protocol=protocol, verb="AUTH", value=username,
                    kind="username", location=f"{location_prefix}_auth_login",
                    method="auth_mechanism", confidence="high",
                    evidence_prefix=f"{location_prefix.upper()} AUTH LOGIN ",
                    evidence_value=tokens[0], base=base,
                    note=f"{protocol.upper()} AUTH LOGIN, decoded from the argument",
                )
            if password is not None:
                _emit_command_value(
                    scan, protocol=protocol, verb="AUTH", value=password,
                    kind="password", location=f"{location_prefix}_auth_login",
                    method="auth_mechanism", confidence="high",
                    evidence_prefix=f"{location_prefix.upper()} AUTH LOGIN ",
                    evidence_value=tokens[1], base=base,
                    note=f"{protocol.upper()} AUTH LOGIN, decoded from the argument",
                )
            return


def _emit_command_value(
    scan: _Scan,
    *,
    protocol: str,
    verb: str,
    value: Any,
    kind: str,
    location: str,
    method: str,
    confidence: str,
    note: str,
    base: dict[str, Any],
    evidence_prefix: str = "",
    evidence_value: str | None = None,
    source_field: str | None = None,
) -> None:
    """One value from one command, with the command itself as its evidence."""
    scan.add(
        value=value,
        kind=kind,
        location=location,
        method=method,
        confidence=confidence,
        note=note,
        protocol=protocol,
        source_field=source_field or verb,
        evidence_prefix=evidence_prefix or f"{verb} ",
        evidence_value=evidence_value,
        **base,
    )


def scan_session(scan: _Scan, row: Any) -> None:
    """One ``protocol_sessions`` row (§2), by protocol."""
    protocol = str(row["protocol"] or "").lower()
    detail = _json_object(row["detail"])
    commands = _commands(detail)

    base: dict[str, Any] = {
        "transport": row["transport"],
        "stream_id": row["stream_id"],
        # An authentication command is only ever sent by the client (§3.1).
        "direction": "client_to_server",
        "client_ip": row["client_ip"],
        "client_port": row["client_port"],
        "server_ip": row["server_ip"],
        "server_port": row["server_port"],
        "packet_first": row["first_frame"],
        "packet_last": row["last_frame"],
    }

    seen_username = False
    for verb, arg in commands:
        if arg is None:
            continue
        if verb == "USER":
            if protocol == "imap":
                continue
            _emit_command_value(
                scan, protocol=protocol, verb=verb, value=arg, kind="username",
                location=f"{protocol}_user_command", method="command_arg",
                confidence="high", base=base,
                note=f"{protocol.upper()} USER command on the control channel",
            )
            seen_username = True
        elif verb == "PASS":
            _emit_command_value(
                scan, protocol=protocol, verb=verb, value=arg, kind="password",
                location=f"{protocol}_pass_command", method="command_arg",
                confidence="high", base=base,
                note=f"{protocol.upper()} PASS command on the control channel",
            )
        elif verb == "AUTH":
            _auth_values(scan, protocol=protocol, arg=arg, base=base,
                         location_prefix=protocol)
        elif verb == "LOGIN" and protocol == "imap":
            _imap_login(scan, arg=arg, base=base)
            seen_username = True
        elif verb == "AUTHENTICATE" and protocol == "imap":
            _auth_values(scan, protocol=protocol, arg=arg, base=base,
                         location_prefix=protocol)

    # §2 lists detail.auth_username (and the FTP detail's own key username) as a
    # location of its own. It is read only as a fallback, so one identity in one
    # session is one finding rather than two rows saying the same thing.
    if not seen_username:
        for key in ("auth_username", "username"):
            value = detail.get(key)
            if isinstance(value, str) and value:
                _emit_command_value(
                    scan, protocol=protocol, verb=key.upper(), value=value,
                    kind="username", location=f"{protocol}_{key}",
                    method="command_arg", confidence="high", base=base,
                    source_field=key,
                    evidence_prefix=f"{protocol.upper()} {key}=",
                    note=(
                        f"An identity the {protocol.upper()} dissector recorded for "
                        "this session"
                    ),
                )
                break

    # ``detail.password_present`` is a boolean, and a boolean is not a value: it
    # says a password crossed the wire without carrying one, so nothing is
    # reported from it. The fact stays visible on the protocol page that owns it.


def _imap_login(scan: _Scan, *, arg: str, base: dict[str, Any]) -> None:
    """``LOGIN user pass``, in the quoting IMAP uses.

    An IMAP argument is a quoted string or an atom; a quoted string may contain
    an escaped quote. Only the quoting is removed — nothing is unescaped beyond
    the backslash the protocol defines, and a command with fewer than two
    arguments yields nothing.
    """
    tokens = _imap_tokens(arg)
    if not tokens:
        return
    if len(tokens) >= 2:
        _emit_command_value(
            scan, protocol="imap", verb="LOGIN", value=tokens[0], kind="username",
            location="imap_login_command", method="command_arg", confidence="high",
            base=base, note="IMAP LOGIN command on the control channel",
        )
        _emit_command_value(
            scan, protocol="imap", verb="LOGIN", value=tokens[-1], kind="password",
            location="imap_login_command", method="command_arg", confidence="high",
            base=base, note="IMAP LOGIN command on the control channel",
        )
        return
    _emit_command_value(
        scan, protocol="imap", verb="LOGIN", value=tokens[0], kind="username",
        location="imap_login_command", method="command_arg", confidence="high",
        base=base, note="IMAP LOGIN command on the control channel",
    )


def _imap_tokens(arg: str) -> list[str]:
    """The arguments of an IMAP command, with quoted strings read as one token."""
    tokens: list[str] = []
    current: list[str] = []
    quoted = False
    index = 0
    while index < len(arg):
        char = arg[index]
        if quoted:
            if char == "\\" and index + 1 < len(arg):
                current.append(arg[index + 1])
                index += 2
                continue
            if char == '"':
                quoted = False
                tokens.append("".join(current))
                current = []
            else:
                current.append(char)
        elif char == '"':
            quoted = True
        elif char.isspace():
            if current:
                tokens.append("".join(current))
                current = []
        else:
            current.append(char)
        index += 1
    if current:
        tokens.append("".join(current))
    return tokens


# --------------------------------------------------------------------------
# §2(b) the control channel of the four command protocols
# --------------------------------------------------------------------------
#
# The value is deliberately absent from the database: ``protocol_analyzer`` blanks
# a ``PASS`` argument and reduces an SMTP ``AUTH`` command to its mechanism. So the
# value is read back off the wire - from the *client's* side of the stream the
# analyser already classified, reassembled by TShark's own ``follow`` (the same
# call the stream viewer uses), and it is written into ``credentials`` and nowhere
# else (§10): ``protocol_sessions.detail`` goes to the browser on every
# ``/protocols`` response, and that page has no reveal control.

def _wants_control_stream(detail: dict) -> bool:
    """Whether §2(a)'s rows say this session exchanged a credential.

    A verb §2(a) names is the direct signal. The indirect one is a session that
    recorded an *authenticated login*: ``password_present`` and the identity are
    exactly what the analyser keeps instead of the value, so a session that
    authenticated with no verb left in its capped command list is still worth
    reading. Nothing else qualifies — a session whose detail says nothing about
    credentials has its control channel left alone.
    """
    if {verb for verb, _ in _commands(detail)} & CONTROL_VERBS:
        return True
    if detail.get("password_present") is True:
        return True
    return any(
        isinstance(detail.get(key), str) and detail[key]
        for key in ("auth_username", "username")
    )


def _client_direction(follow: tshark.FollowStream, row: Any) -> int | None:
    """Which of TShark's two nodes is this session's client, as direction 0 or 1.

    ``follow`` numbers the endpoints itself, and its numbering is not the client's:
    an SMTP session's first packet is the server's greeting. So the mapping is made
    by matching the endpoint the protocol analyser recorded as the client — the
    same way ``stream_analyzer`` decides which node a row's client is. When the
    two do not line up, nothing is read from the stream rather than guessing which
    side is which.
    """
    ip = row["client_ip"]
    port = row["client_port"]
    if not ip or port is None:
        return None
    endpoint = f"{ip}:{port}"
    if follow.node0 == endpoint:
        return 0
    if follow.node1 == endpoint:
        return 1
    return None


def _reassemble_control(
    capture_path: Path,
    row: Any,
    *,
    cancel_event: threading.Event | None = None,
) -> tuple[str | None, str | None, bool]:
    """``(client_text, reason_it_is_missing, truncated)`` for one control stream.

    One reassembly, capped by :data:`STREAM_TIMEOUT_S` and cancelled with the job.
    Every failure mode is returned rather than raised: a control stream is one
    optional fact among many, and the stage exists to report what it could read,
    not to fail an analysis because a capture was purged or a stream could not be
    followed.
    """
    stream_id = row["stream_id"]
    if stream_id is None:
        return None, "the session carries no stream id", False

    transport = row["transport"]
    if transport and transport != "tcp":
        return None, f"TShark reassembles TCP streams, and this one is {transport}", False

    try:
        follow = tshark.follow_stream(
            capture_path,
            int(stream_id),
            "ascii",
            timeout=STREAM_TIMEOUT_S,
            cancel_event=cancel_event,
        )
    except tshark.TsharkTimeout:
        return None, f"reassembly exceeded the {STREAM_TIMEOUT_S}s budget", False
    except tshark.TsharkError as exc:
        return None, f"TShark could not reassemble it ({exc})", False

    if not follow.found or not follow.chunks:
        return None, "TShark reassembled no content for it", False

    direction = _client_direction(follow, row)
    if direction is None:
        return None, "the client's side of the stream could not be identified", False

    text = "".join(chunk.data or "" for chunk in follow.chunks if chunk.direction == direction)
    truncated = len(text) > MAX_STREAM_CHARS
    return text[:MAX_STREAM_CHARS], None, truncated


def _control_base(row: Any) -> dict[str, Any]:
    """The columns every finding from one session shares (as ``scan_session``)."""
    return {
        "transport": row["transport"],
        "stream_id": row["stream_id"],
        "direction": "client_to_server",
        "client_ip": row["client_ip"],
        "client_port": row["client_port"],
        "server_ip": row["server_ip"],
        "server_port": row["server_port"],
        "packet_first": row["first_frame"],
        "packet_last": row["last_frame"],
    }


def _control_command(protocol: str, line: str) -> tuple[str, str, str]:
    """One client line as ``(verb, argument, tag)``, or ``("", "", "")``.

    The four protocols share a shape — a verb, then its argument — and IMAP adds a
    leading tag (``a2 LOGIN …``). The tag is recognised as *not a verb* rather than
    by its shape, because "the first token is whatever it is" cannot tell a tag
    from a command; the argument keeps its own text (quoting included) so each
    verb's parser can decide what its arguments are.
    """
    text = line.strip()
    if not text:
        return "", "", ""

    head, _, remainder = text.partition(" ")
    verb = head.upper()
    tag = ""
    if protocol == "imap" and verb not in _IMAP_COMMANDS:
        tag = head
        head, _, remainder = remainder.strip().partition(" ")
        verb = head.upper()
    return verb, remainder.strip(), tag


def _looks_like_a_sasl_token(line: str) -> bool:
    """A single Base64 token, which is how a SASL continuation line arrives."""
    text = line.strip()
    if not text or " " in text or len(text) < 4:
        return False
    return bool(_BASE64_RE.match(text))


def scan_control_stream(
    scan: _Scan, *, protocol: str, row: Any, text: str, truncated: bool
) -> None:
    """Read the authentication lines out of one reassembled control channel.

    Only the client's side is passed in, because a credential is always sent by
    the client and the server's side is full of Base64 challenges that look like
    credentials and are not. A SASL exchange is followed as the state machine the
    mechanisms are: ``AUTH LOGIN`` is answered by a Base64 username and then a
    Base64 password, and ``AUTH PLAIN`` without an inline argument by the single
    Base64 ``\\0user\\0pass`` token — the exchange ``protocol_analyzer`` records as
    ``password_present`` and nothing more.
    """
    base = _control_base(row)
    if truncated:
        scan.notes.append(
            f"Stream {row['stream_id']} ({protocol}) is longer than MAX_STREAM_CHARS = "
            f"{MAX_STREAM_CHARS} characters; only its first {MAX_STREAM_CHARS} were read."
        )

    #: ``("PLAIN"|"LOGIN", step)`` while a mechanism is awaiting its next token.
    state: tuple[str, int] | None = None

    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line:
            continue

        if state is not None:
            mechanism, step = state
            if _looks_like_a_sasl_token(line):
                decoded = _decode_base64(line)
                if decoded is not None:
                    state = None
                    if mechanism == "PLAIN":
                        _emit_plain_values(
                            scan, protocol=protocol, base=base, decoded=decoded, encoded=line
                        )
                    else:
                        _emit_control_value(
                            scan, protocol=protocol, value=decoded,
                            kind="username" if step == 1 else "password",
                            location=f"{protocol}_auth_login", base=base,
                            evidence_prefix="AUTH LOGIN ", evidence_value=line,
                            source_field="AUTH",
                            note=(
                                f"{protocol.upper()} AUTH LOGIN, decoded from the exchange "
                                "that follows the command"
                            ),
                        )
                        if step == 1:
                            state = (mechanism, 2)
                    continue
            # Not a continuation after all: read the line as a command.
            state = None

        verb, arg, tag = _control_command(protocol, line)
        if not verb:
            continue

        if verb == "USER" and arg and protocol != "imap":
            _emit_control_value(
                scan, protocol=protocol, value=arg, kind="username",
                location=f"{protocol}_user_command", base=base,
                evidence_prefix="USER ", source_field="USER",
                note=f"{protocol.upper()} USER command, read from the control channel",
            )
        elif verb == "PASS" and arg:
            _emit_control_value(
                scan, protocol=protocol, value=arg, kind="password",
                location=f"{protocol}_pass_command", base=base,
                evidence_prefix="PASS ", source_field="PASS",
                note=(
                    f"{protocol.upper()} PASS command, read from the control channel "
                    "because the analyser records only that a password was present"
                ),
            )
        elif verb in {"AUTH", "AUTHENTICATE"} and arg:
            state = _scan_sasl_command(
                scan, protocol=protocol, base=base, arg=arg, tag=tag
            )
        elif verb == "LOGIN" and protocol == "imap" and arg:
            _scan_imap_login_line(scan, base=base, arg=arg)


def _scan_sasl_command(
    scan: _Scan, *, protocol: str, base: dict[str, Any], arg: str, tag: str
) -> tuple[str, int] | None:
    """``AUTH``/``AUTHENTICATE <mechanism> [<token>]``; returns the pending state."""
    mechanism, _, rest = arg.strip().partition(" ")
    mechanism = mechanism.upper()
    rest = rest.strip()
    prefix = "AUTHENTICATE" if tag else "AUTH"

    if mechanism not in _SASL_MECHANISMS:
        # CRAM-MD5, NTLM and every other mechanism has a shape this build does not
        # decode: nothing is reported rather than a hash reported as a password.
        return None

    if mechanism == "PLAIN":
        if not rest:
            return ("PLAIN", 1)
        decoded = _decode_base64(rest)
        if decoded is not None:
            _emit_plain_values(
                scan, protocol=protocol, base=base, decoded=decoded, encoded=rest
            )
            return None
        _emit_control_value(
            scan, protocol=protocol, value=rest, kind="other_secret",
            location=f"{protocol}_auth_plain", base=base,
            evidence_prefix=f"{prefix} PLAIN ", source_field=prefix,
            confidence="medium",
            note=(
                f"An {protocol.upper()} AUTH PLAIN argument that is not the "
                "\\0user\\0pass pair the mechanism promises; kept whole rather than "
                "guessed at"
            ),
        )
        return None

    # mechanism == "LOGIN"
    tokens = rest.split()
    if not tokens:
        return ("LOGIN", 1)
    username = _decode_base64(tokens[0])
    if username is None:
        return None
    _emit_control_value(
        scan, protocol=protocol, value=username, kind="username",
        location=f"{protocol}_auth_login", base=base,
        evidence_prefix=f"{prefix} LOGIN ", evidence_value=tokens[0],
        source_field=prefix,
        note=f"{protocol.upper()} AUTH LOGIN, decoded from the command's argument",
    )
    if len(tokens) < 2:
        return ("LOGIN", 2)
    password = _decode_base64(tokens[1])
    if password is None:
        return None
    _emit_control_value(
        scan, protocol=protocol, value=password, kind="password",
        location=f"{protocol}_auth_login", base=base,
        evidence_prefix=f"{prefix} LOGIN ", evidence_value=tokens[1],
        source_field=prefix,
        note=f"{protocol.upper()} AUTH LOGIN, decoded from the command's argument",
    )
    return None


def _emit_plain_values(
    scan: _Scan, *, protocol: str, base: dict[str, Any], decoded: str, encoded: str
) -> None:
    """The two halves of a decoded ``\\0user\\0pass``, or one opaque value."""
    parts = decoded.split("\x00")
    if len(parts) >= 2 and parts[-1]:
        for value, kind in ((parts[-2], "username"), (parts[-1], "password")):
            _emit_control_value(
                scan, protocol=protocol, value=value, kind=kind,
                location=f"{protocol}_auth_plain", base=base,
                evidence_prefix="AUTH PLAIN ", evidence_value=encoded,
                source_field="AUTH",
                note=f"{protocol.upper()} AUTH PLAIN, decoded from the exchange",
            )
        return
    _emit_control_value(
        scan, protocol=protocol, value=encoded, kind="other_secret",
        location=f"{protocol}_auth_plain", base=base,
        evidence_prefix="AUTH PLAIN ", source_field="AUTH", confidence="medium",
        note=(
            f"An {protocol.upper()} AUTH PLAIN value that is not the \\0user\\0pass "
            "pair the mechanism promises; kept whole rather than guessed at"
        ),
    )


def _scan_imap_login_line(scan: _Scan, *, base: dict[str, Any], arg: str) -> None:
    tokens = _imap_tokens(arg)
    if not tokens:
        return
    _emit_control_value(
        scan, protocol="imap", value=tokens[0], kind="username",
        location="imap_login_command", base=base, evidence_prefix="LOGIN ",
        source_field="LOGIN",
        note="IMAP LOGIN command, read from the control channel",
    )
    if len(tokens) >= 2:
        _emit_control_value(
            scan, protocol="imap", value=tokens[-1], kind="password",
            location="imap_login_command", base=base, evidence_prefix="LOGIN ",
            source_field="LOGIN",
            note="IMAP LOGIN command, read from the control channel",
        )


def _emit_control_value(
    scan: _Scan,
    *,
    protocol: str,
    value: Any,
    kind: str,
    location: str,
    base: dict[str, Any],
    evidence_prefix: str,
    note: str,
    source_field: str,
    confidence: str = "high",
    evidence_value: str | None = None,
) -> None:
    """One value read out of a reassembled control channel.

    An authentication command is a protocol-confirmed location, so its value is
    ``high`` (§4) — except where the value is not what the mechanism promised, and
    is kept whole as an opaque secret: that is the same "we could not read it, here
    is the string" case as a malformed Basic header, and it scores the same way.
    """
    scan.add(
        value=value,
        kind=kind,
        protocol=protocol,
        location=location,
        method=CONTROL_METHOD,
        confidence=confidence,
        note=note,
        source_field=source_field,
        evidence_prefix=evidence_prefix,
        evidence_value=evidence_value,
        **base,
    )


def control_candidates(
    scan: _Scan, protocol: str, rows: Sequence[Any]
) -> list[Any]:
    """The sessions of one protocol whose control channel §2(b) is worth reading.

    Lowest stream id first, and at most :data:`MAX_CONTROL_STREAMS` of them per
    protocol. What the cap cut is returned to the caller as a note, never dropped
    silently (§9, §10).
    """
    wanted: list[Any] = []
    streamless = 0
    for row in rows:
        if row["stream_id"] is None:
            streamless += 1
            continue
        if _wants_control_stream(_json_object(row["detail"])):
            wanted.append(row)

    wanted.sort(key=lambda item: (int(item["stream_id"]), int(item["id"])))
    if len(wanted) > MAX_CONTROL_STREAMS:
        dropped = len(wanted) - MAX_CONTROL_STREAMS
        wanted = wanted[:MAX_CONTROL_STREAMS]
        scan.notes.append(
            f"{dropped} {protocol} control stream(s) were not read: MAX_CONTROL_STREAMS = "
            f"{MAX_CONTROL_STREAMS} streams are reassembled per protocol, lowest stream id first."
        )
    if streamless:
        scan.notes.append(
            f"{streamless} {protocol} session(s) carry no stream id, so their control "
            "channel could not be read."
        )
    return wanted


def scan_control_channels(
    scan: _Scan,
    *,
    protocols: Sequence[str],
    rows: Sequence[Any],
    capture_path: Path,
    cancel_event: threading.Event | None = None,
) -> int:
    """§2(b) for every protocol in the selection; returns the streams reassembled.

    Only sessions the analyser already classified as one of the four command
    protocols are considered — the rows are already filtered to them — and only the
    client's side of each is read. An HTTP stream never reaches this function:
    HTTP bodies are stored with their transactions, so reassembling one here would
    be a second capture pass for data the stage already has (§2).
    """
    reassembled = 0
    selected = [name for name in protocols if name != "http"]
    for protocol in selected:
        group = [row for row in rows if str(row["protocol"] or "").lower() == protocol]
        for row in control_candidates(scan, protocol, group):
            text, reason, truncated = _reassemble_control(
                capture_path, row, cancel_event=cancel_event
            )
            if text is None:
                scan.notes.append(
                    f"Stream {row['stream_id']} ({protocol}) was not read: {reason}."
                )
                continue
            reassembled += 1
            scan_control_stream(
                scan, protocol=protocol, row=row, text=text, truncated=truncated
            )
    return reassembled


# --------------------------------------------------------------------------
# http_transactions: headers, query and body (§2, §3.1)
# --------------------------------------------------------------------------

#: Body content types this build reads as text. Anything else — an image, a gzip,
#: an octet stream — is a preview the HTTP analyser rendered for a reader, not
#: the bytes that crossed the wire, so it is not scanned as text (§1).
_TEXT_TYPES: frozenset[str] = frozenset(
    {"application/xml", "application/javascript", "application/x-ndjson", "application/ld+json"}
)


def _body_reader(content_type: str | None) -> str:
    """``form``, ``json``, ``text`` or ``skip`` for one body (§3.1, §1)."""
    kind = (content_type or "").split(";")[0].strip().lower()
    if not kind:
        return "text"
    if kind == "application/x-www-form-urlencoded":
        return "form"
    if kind == "application/json" or kind.endswith("+json"):
        return "json"
    if kind.startswith("text/") or kind in _TEXT_TYPES:
        return "text"
    return "skip"


def _request_content_type(headers: Any) -> str | None:
    """The *request's* own ``Content-Type``, or ``None`` when it sent none.

    ``http_transactions.content_type`` describes the **response**, so it can never
    say how to read a request body: a browser POST of a form to an endpoint that
    answers ``application/json`` has a form body and a JSON content type. Keeping
    the two apart is what stops a body from being read as prose (§3.1).
    """
    if not isinstance(headers, dict):
        return None
    for name, value in headers.items():
        if not isinstance(name, str) or not isinstance(value, str):
            continue
        if normalise_name(name) == "content_type":
            return value
    return None


def _form_shape(text: str) -> bool:
    """True when a body has the structure of ``name=value`` pairs, not prose.

    Only the shape is judged, so this is a fallback for a body whose request sent
    no usable content type — never a replacement for a declared one. A form body
    is a single line and every ``&``-separated chunk carries its own ``=``; that
    is strict enough to leave multi-line prose (``password: hunter2``) and
    sentences (``the user=admin logged in``) to the text reader.
    """
    sample = text.strip()
    if not sample or sample[0] in "{[":
        return False
    if "\n" in sample or "\r" in sample:
        return False
    if "=" not in sample:
        return False
    chunks = [chunk for chunk in sample.split("&") if chunk]
    if not chunks or any("=" not in chunk for chunk in chunks):
        return False
    for name, _ in _form_pairs(sample):
        name = name.strip()
        if name and len(name) <= 64 and not any(char.isspace() for char in name):
            return True
    return False


def scan_http(scan: _Scan, row: Any) -> None:
    """One ``http_transactions`` row: request headers, query and request body."""
    base: dict[str, Any] = {
        "transport": "tcp",
        "stream_id": row["stream_id"],
        "direction": "client_to_server",
        "client_ip": row["client_ip"],
        "client_port": row["client_port"],
        "server_ip": row["server_ip"],
        "server_port": row["server_port"],
        "packet_first": row["request_packet"],
        "packet_last": row["request_packet"],
    }

    headers = _json_object(row["request_headers"])
    # The stored object is in wire order, which is what makes the same capture
    # produce the same rows.
    for name, value in headers.items():
        if not isinstance(name, str) or not isinstance(value, str):
            continue
        _scan_header(scan, name=name, value=value, base=base)

    _scan_query(scan, row=row, base=base)
    _scan_body(scan, row=row, headers=headers, base=base)


def _scan_header(scan: _Scan, *, name: str, value: str, base: dict[str, Any]) -> None:
    normalised = normalise_name(name)
    if normalised in {"authorization", "proxy_authorization"}:
        _scan_authorization(scan, name=name, value=value, base=base)
        return
    if normalised == "cookie":
        _scan_cookie(scan, value=value, base=base)
        return

    field = normalised
    for prefix in _HEADER_PREFIXES:
        if field.startswith(prefix) and field not in _FIELD_KINDS:
            field = field[len(prefix):]
            break
    kind = _FIELD_KINDS.get(field)
    if kind is None:
        # A header name that is not credential-like may still carry a secret this
        # build can recognise by shape alone (§4 low).
        scan.add_shape_only(
            value=value, protocol="http", location="request_header",
            source_field=name, evidence_prefix=f"{name}: ", **base,
        )
        return

    # A credential-like request header is a structured, protocol-confirmed
    # location: the value is what the client put in a header that names itself as
    # a credential, which §4's high rule covers for the Authorization header and
    # for a named field, and which is not free text.
    scan.add(
        value=value, kind=kind, protocol="http", location="request_header",
        method="header_field", confidence="high", source_field=name,
        evidence_prefix=f"{name}: ",
        note=f"An HTTP request header named as a credential ({name})",
        **base,
    )


def _scan_authorization(scan: _Scan, *, name: str, value: str, base: dict[str, Any]) -> None:
    """§3.1's Authorization parser: Basic, Bearer, or another scheme."""
    scheme, _, rest = value.strip().partition(" ")
    scheme = scheme.strip()
    rest = rest.strip()
    lowered = scheme.lower()

    if not scheme or not rest:
        # "Authorization: Basic" with nothing after it names no value at all.
        return

    if lowered == "basic":
        decoded = _decode_base64(rest)
        if decoded is None or ":" not in decoded:
            scan.add(
                value=rest, kind="other_secret", protocol="http",
                location="authorization_basic", method="basic_decode",
                confidence="medium", source_field=name,
                evidence_prefix=f"{name}: {scheme} ",
                note=(
                    "A Basic authorization header that is not valid Base64 "
                    "credentials; the encoded value is kept whole rather than "
                    "guessed at"
                ),
                **base,
            )
            return
        username, _, password = decoded.partition(":")
        scan.add(
            value=username, kind="username", protocol="http",
            location="authorization_basic", method="basic_decode",
            confidence="high", source_field=name,
            evidence_prefix=f"{name}: {scheme} ", evidence_value=rest,
            note="HTTP Basic credentials, decoded from the request header",
            **base,
        )
        scan.add(
            value=password, kind="password", protocol="http",
            location="authorization_basic", method="basic_decode",
            confidence="high", source_field=name,
            evidence_prefix=f"{name}: {scheme} ", evidence_value=rest,
            note="HTTP Basic credentials, decoded from the request header",
            **base,
        )
        return

    if lowered == "bearer":
        scan.add(
            value=rest, kind="bearer_token", protocol="http",
            location="authorization_bearer", method="bearer_header",
            confidence="high", source_field=name,
            evidence_prefix=f"{name}: {scheme} ",
            note="An HTTP bearer token, taken from the Authorization header",
            **base,
        )
        return

    scan.add(
        value=rest, kind="other_secret", protocol="http",
        location="authorization_scheme", method="authorization_scheme",
        confidence="high", source_field=name,
        evidence_prefix=f"{name}: {scheme} ",
        note=(
            f"An Authorization scheme this build does not decode (scheme "
            f"'{scheme}'); the value is reported as an opaque secret"
        ),
        **base,
    )


def _scan_cookie(scan: _Scan, *, value: str, base: dict[str, Any]) -> None:
    """§3.1's cookie parser: only a credential-like cookie *name* is a finding."""
    for name, cookie in _cookie_pairs(value):
        normalised = normalise_name(name)
        if not any(marker in normalised for marker in _COOKIE_MARKERS):
            continue
        kind = _FIELD_KINDS.get(normalised, "other_secret")
        scan.add(
            value=cookie, kind=kind, protocol="http", location="cookie_header",
            method="cookie_field", confidence="medium", source_field=name,
            evidence_prefix=f"Cookie: {name}=",
            note=(
                "A cookie whose name is credential-like; a cookie value is not "
                "decoded, so it is reported as the opaque string it was"
            ),
            **base,
        )


def _cookie_pairs(header: str) -> Iterator[tuple[str, str]]:
    """``k=v; k2=v2``, in order, tolerating the malformed tail of a real header."""
    for part in header.split(";"):
        piece = part.strip()
        if not piece:
            continue
        name, sep, cookie = piece.partition("=")
        if not sep:
            continue
        name = name.strip()
        cookie = cookie.strip()
        if len(cookie) >= 2 and cookie[0] == '"' and cookie[-1] == '"':
            cookie = cookie[1:-1]
        if name:
            yield name, cookie


def _scan_query(scan: _Scan, *, row: Any, base: dict[str, Any]) -> None:
    """The URL query string, parsed as form-urlencoded (§3.1).

    The query is everything after the request target's first ``?``: a request
    target never carries a fragment, so no other parsing can improve on that, and
    ``full_uri`` is preferred because it is the form that keeps the query when a
    dissector also recorded the path alone.
    """
    query = ""
    for column in ("full_uri", "uri"):
        raw = row[column]
        if isinstance(raw, str) and "?" in raw:
            query = raw.partition("?")[2]
            break
    if not query:
        return

    prefix = f"{row['method'] or 'GET'} " if row["method"] else ""
    for index, (name, value) in enumerate(_form_pairs(query)):
        if index >= MAX_FIELDS_PER_LOCATION:
            break
        kind = _FIELD_KINDS.get(normalise_name(name))
        if kind is not None:
            scan.add(
                value=value, kind=kind, protocol="http", location="url_query",
                method="query_field", confidence="medium", source_field=name,
                evidence_prefix=f"{prefix}{name}=",
                note=(
                    "A credential-like field name in the URL query string, which "
                    "is not a structured credential location"
                ),
                **base,
            )
        else:
            scan.add_shape_only(
                value=value, protocol="http", location="url_query",
                source_field=name, evidence_prefix=f"{prefix}{name}=", **base,
            )


def _form_pairs(text: str) -> list[tuple[str, str]]:
    """``parse_qsl`` without its failure modes: bad pairs are dropped, not raised.

    Both ``&`` and ``;`` separate pairs. ``parse_qsl`` cannot do that itself: its
    ``separator`` argument is a *literal* string in this Python (3.12.6), so
    ``separator="&;"`` matches nothing and the whole body came back as one field
    whose value swallowed the next one. ``;`` is therefore rewritten to ``&``
    first — a literal ``;`` inside a value is percent-encoded as ``%3B`` by the
    urlencoded spec, so this cannot cut a value in half.
    """
    pairs: list[tuple[str, str]] = []
    for chunk in text.replace(";", "&").split("&"):
        if not chunk:
            continue
        try:
            found = parse_qsl(chunk, keep_blank_values=True, strict_parsing=False)
        except ValueError:  # pragma: no cover - parse_qsl is tolerant by request
            continue
        pairs.extend((str(name), str(value)) for name, value in found)
    return pairs


def _scan_body(
    scan: _Scan, *, row: Any, headers: Any, base: dict[str, Any]
) -> None:
    """The request body, read as a form, as JSON, or as free text (§3.1)."""
    body = row["request_body"]
    if not isinstance(body, str) or not body:
        return

    # The request's own header decides (§3.1). The row's `content_type` column is
    # the response's, and using it read a form POST whose endpoint answered JSON
    # as prose, which produced one medium finding whose whole value was
    # `admin&password=secret123` instead of the two fields the server received.
    declared = _request_content_type(headers)
    reader = _body_reader(declared) if declared else "unknown"
    if reader == "skip":
        return

    text = body[:MAX_BODY_CHARS]
    if reader == "form":
        # A declaration is believed, with one exception: a body that parses as a
        # JSON document is one, whatever it was labelled, because the parse is
        # proof of what it is. Reading it as a form would find nothing at all.
        stripped = text.lstrip()
        if stripped.startswith(("{", "[")) and _scan_json(scan, text=text, base=base):
            return
        _scan_form(scan, text=text, base=base)
        return
    if reader == "json":
        if _scan_json(scan, text=text, base=base):
            return
        # Declared JSON but not JSON: fall back to the body's own shape.
        if _form_shape(text):
            _scan_form(scan, text=text, base=base)
            return
        _scan_text(scan, text=text, base=base)
        return

    # No content type recorded: the shape decides, and a JSON document is parsed
    # rather than read as prose because the parse is proof of what it is.
    stripped = text.lstrip()
    if stripped.startswith(("{", "[")) and _scan_json(scan, text=text, base=base):
        return
    if _form_shape(text):
        _scan_form(scan, text=text, base=base)
        return
    _scan_text(scan, text=text, base=base)


def _scan_form(scan: _Scan, *, text: str, base: dict[str, Any]) -> None:
    for index, (name, value) in enumerate(_form_pairs(text)):
        if index >= MAX_FIELDS_PER_LOCATION:
            break
        # A form value ends at the pair separator, and quotes around it are
        # transport, not content.
        value = value.strip()
        if len(value) >= 2 and value[0] == '"' and value[-1] == '"':
            value = value[1:-1]
        kind = _FIELD_KINDS.get(normalise_name(name))
        if kind is not None:
            scan.add(
                value=value, kind=kind, protocol="http", location="form_body",
                method="form_field", confidence="high", source_field=name,
                evidence_prefix=f"form body {name}=",
                note="A credential-like field name in a form body",
                **base,
            )
        else:
            scan.add_shape_only(
                value=value, protocol="http", location="form_body",
                source_field=name, evidence_prefix=f"form body {name}=", **base,
            )


def _scan_json(scan: _Scan, *, text: str, base: dict[str, Any]) -> bool:
    """Walk a JSON body to :data:`JSON_DEPTH`; ``False`` when it is not JSON."""
    try:
        document = json.loads(text)
    except (json.JSONDecodeError, ValueError):
        return False

    for index, (path, name, value) in enumerate(_json_fields(document)):
        if index >= MAX_FIELDS_PER_LOCATION:
            break
        if not isinstance(value, (str, int, float, bool)):
            continue
        rendered = value if isinstance(value, str) else json.dumps(value)
        kind = _FIELD_KINDS.get(normalise_name(name))
        evidence_prefix = f"json body {path}="
        if kind is not None:
            scan.add(
                value=rendered, kind=kind, protocol="http", location="json_body",
                method="json_field", confidence="high", source_field=name,
                evidence_prefix=evidence_prefix,
                note="A credential-like field name in a JSON body",
                **base,
            )
        else:
            scan.add_shape_only(
                value=rendered, protocol="http", location="json_body",
                source_field=name, evidence_prefix=evidence_prefix, **base,
            )
    return True


def _json_fields(
    node: Any, *, depth: int = 1, path: str = ""
) -> Iterator[tuple[str, str, Any]]:
    """Every leaf of a decoded document, as ``(path, key, value)``.

    Containers are entered while the depth is below :data:`JSON_DEPTH`, so the
    keys of a container at that depth are read and the containers inside it are
    not — a credential seven objects deep is out of reach by the contract's own
    cap rather than by accident. Every leaf is yielded, keyed by name or by list
    index, because the cap counts fields read rather than only the ones reported.
    """
    if isinstance(node, dict):
        items: Iterator[tuple[Any, Any]] = iter(node.items())
    elif isinstance(node, list):
        items = iter(enumerate(node))
    else:
        return

    for key, value in items:
        name = key if isinstance(key, str) else str(key)
        child = f"{path}.{name}" if path else name
        if isinstance(value, (dict, list)):
            if depth < JSON_DEPTH:
                yield from _json_fields(value, depth=depth + 1, path=child)
            continue
        yield child, name, value


def _scan_text(scan: _Scan, *, text: str, base: dict[str, Any]) -> None:
    """A free-text body: labels if it has any, then shapes that no name vouched for.

    The label reader is deliberately conservative — a line's leading token before
    an ``=`` or a ``:``, with quoting removed — because §1.3's rule that nothing is
    invented matters more here than recall.
    """
    for name, value in _text_fields(text):
        kind = _FIELD_KINDS.get(normalise_name(name))
        evidence_prefix = f"body text {name}="
        if kind is not None:
            scan.add(
                value=value, kind=kind, protocol="http", location="body_text",
                method="text_field", confidence="medium", source_field=name,
                evidence_prefix=evidence_prefix,
                note="A credential-like label in a free-text request body",
                **base,
            )
        else:
            scan.add_shape_only(
                value=value, protocol="http", location="body_text",
                source_field=name, evidence_prefix=evidence_prefix, **base,
            )

    # §10: a secret pasted into an unlabelled body is reported at low confidence.
    scan.add_shape_only(
        value=text, protocol="http", location="body_text",
        evidence_prefix="body text ",
        note="A shape found in a request body that no field name vouched for",
        **base,
    )


def _text_fields(text: str) -> Iterator[tuple[str, str]]:
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        index = min(
            [position for position in (line.find("="), line.find(":")) if position > 0]
            or [-1]
        )
        if index <= 0:
            continue
        name = line[:index].strip().strip('"\'{[,')
        value = line[index + 1:].strip()
        # A value ends at the next pair separator, so a one-line
        # `user=a&pass=b` read as text still yields two fields rather than one
        # value made of the whole tail.
        value = _terminate(value)
        value = value.rstrip(",")
        if len(value) >= 2 and value[0] == '"' and value[-1] == '"':
            value = value[1:-1]
        if not name or len(name) > 64 or any(char.isspace() for char in name):
            continue
        yield name, value


def _terminate(value: str) -> str:
    """Cut a label's value at the first pair separator (``&`` or ``;``)."""
    end = len(value)
    for separator in ("&", ";"):
        position = value.find(separator)
        if position != -1:
            end = min(end, position)
    return value[:end].strip()


# --------------------------------------------------------------------------
# reading and writing
# --------------------------------------------------------------------------

_SELECT_HTTP = "SELECT * FROM http_transactions WHERE analysis_id = ? ORDER BY id"
_SELECT_SESSION = (
    "SELECT * FROM protocol_sessions WHERE analysis_id = ? ORDER BY id"
)

INSERT_SQL = """
INSERT INTO credentials (
    analysis_id, kind, value, value_preview, value_length, value_truncated,
    protocol, transport, stream_id, direction, location, source_field, method,
    confidence, client_ip, client_port, server_ip, server_port,
    packet_first, packet_last, evidence, note, created_at
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
"""


@dataclass(slots=True)
class ScanResult:
    """What one pass over a capture's rows (and control channels) produced.

    ``notes`` is the honest half: the caps that bit and the streams that could not
    be read. It becomes the stage's warnings and §8.2's ``limits``, and it never
    carries a value — only streams, protocols and caps.
    """

    findings: list[Finding]
    notes: list[str]
    scanned: list[str]
    control_streams: int


def collect(
    analysis_id: str,
    protocols: Sequence[str],
    *,
    capture_path: Path | None = None,
    cancel_event: threading.Event | None = None,
) -> ScanResult:
    """Every finding §2's two sources support, in discovery order.

    Only the protocols the caller selected are read, and only the tables §2 names:
    an empty selection reads nothing at all, which is what "none" means rather than
    "everything". With no ``capture_path`` the stage keeps to the stored rows — the
    HTTP half of the scan needs nothing else — and the four command protocols keep
    whatever the analyser stored. With one, §2(b) additionally reassembles the
    control channel of the sessions those rows say exchanged a credential.
    """
    scan = _Scan(analysis_id)
    selected = set(protocols)

    if "http" in selected:
        rows = db.query_all(_SELECT_HTTP, (analysis_id,))
        for row in rows:
            scan_http(scan, row)
        if rows:
            scan.scanned.add("http")
        log.debug("credential scan read %d HTTP transaction(s) of %s", len(rows), analysis_id)

    command_protocols = [name for name in PROTOCOLS if name != "http" and name in selected]
    sessions: list[Any] = []
    if command_protocols:
        placeholders = ", ".join("?" for _ in command_protocols)
        sessions = db.query_all(
            f"{_SELECT_SESSION.split(' ORDER BY')[0]} AND protocol IN ({placeholders})"
            " ORDER BY id",
            (analysis_id, *command_protocols),
        )
        for row in sessions:
            scan.scanned.add(str(row["protocol"] or "").lower())
            scan_session(scan, row)

    if capture_path is not None and command_protocols:
        scan.control_streams = scan_control_channels(
            scan,
            protocols=command_protocols,
            rows=sessions,
            capture_path=Path(capture_path),
            cancel_event=cancel_event,
        )

    return ScanResult(
        findings=scan.findings,
        notes=list(scan.notes),
        scanned=sorted(scan.scanned, key=PROTOCOLS.index),
        control_streams=scan.control_streams,
    )


def rank(findings: Sequence[Finding]) -> list[Finding]:
    """§9's MAX_FINDINGS: highest confidence first, on a deterministic order.

    The sort is total, so the same rows always produce the same stored order, and
    the discovery order breaks any remaining tie.
    """
    ordered = sorted(
        findings,
        key=lambda finding: (
            _CONFIDENCE_RANK.get(finding.confidence, len(CONFIDENCE_LEVELS)),
            finding.protocol,
            -1 if finding.stream_id is None else finding.stream_id,
            finding.location,
            finding.source_field or "",
            finding.method,
            finding.kind,
            finding.value,
            finding.order,
        ),
    )
    return ordered[:MAX_FINDINGS]


def _count_by(findings: Sequence[Finding], attribute: str) -> dict[str, int]:
    counts: dict[str, int] = {}
    for finding in findings:
        key = getattr(finding, attribute)
        counts[str(key)] = counts.get(str(key), 0) + 1
    return counts


def _persist(analysis_id: str, findings: Sequence[Finding]) -> None:
    now = time.time()
    rows = [
        (
            analysis_id,
            finding.kind,
            finding.value,
            preview(finding.value),
            finding.value_length,
            1 if finding.value_truncated else 0,
            finding.protocol,
            finding.transport,
            finding.stream_id,
            finding.direction,
            finding.location,
            finding.source_field,
            finding.method,
            finding.confidence,
            finding.client_ip,
            finding.client_port,
            finding.server_ip,
            finding.server_port,
            finding.packet_first,
            finding.packet_last,
            finding.evidence,
            finding.note,
            now,
        )
        for finding in findings
    ]
    with db.get_conn() as conn:
        if rows:
            conn.executemany(INSERT_SQL, rows)


def write_marker(analysis_id: str, payload: dict) -> None:
    """Record that this stage ran, with the counts it wrote."""
    with db.get_conn() as conn:
        conn.execute(
            """
            INSERT OR REPLACE INTO stats_cache (analysis_id, kind, json, created_at)
            VALUES (?, ?, ?, ?)
            """,
            (
                analysis_id,
                MARKER_KIND,
                json.dumps(payload, separators=(",", ":")),
                time.time(),
            ),
        )


def stage_marker(analysis_id: str) -> dict | None:
    """The record this stage wrote for an analysis, or ``None`` when it never ran."""
    row = db.query_one(
        "SELECT json, created_at FROM stats_cache WHERE analysis_id = ? AND kind = ?",
        (analysis_id, MARKER_KIND),
    )
    if row is None:
        return None
    try:
        payload = json.loads(row["json"])
    except (json.JSONDecodeError, TypeError):
        payload = {}
    return {"created_at": row["created_at"], **(payload if isinstance(payload, dict) else {})}


def scan_state(analysis_id: str) -> dict:
    """§7's ``scan`` block: the setting as it is now, and what the last run wrote.

    The two are deliberately separate: turning the scan off does not delete what
    it found, so the block has to be able to report the settings that would apply
    *if* it ran again next to the run that produced the rows on screen.
    ``stage_ran`` is what tells a *never scanned* analysis from a scanned one that
    found nothing, and ``rows``/``rows_written_at`` are the rows actually stored -
    which a later run with the scan off leaves exactly where the earlier one put
    them.
    """
    config = runtime_settings.credential_config()
    marker = stage_marker(analysis_id)
    counts = db.query_one(
        "SELECT COUNT(*) AS n, MAX(created_at) AS written_at,"
        " MIN(created_at) AS first_at FROM credentials WHERE analysis_id = ?",
        (analysis_id,),
    )
    return {
        "enabled": bool(config["credential_scan_enabled"]),
        "protocols": list(config["credential_protocols"]),
        "protocols_scanned": list(marker.get("protocols_scanned", [])) if marker else [],
        "scanned_at": marker.get("scanned_at") if marker else None,
        "stage_ran": marker is not None,
        "rows_written_at": counts["written_at"] if counts else None,
        "findings": int(marker.get("findings", 0)) if marker else 0,
        "seconds": marker.get("seconds") if marker else None,
        # Live-API extras: what MAX_FINDINGS cut (§8.1's ``capped``), what the
        # stage matched before the cap, what is actually stored now, and the kind
        # histogram the page's tiles are drawn from.
        "capped": bool(marker.get("capped", False)) if marker else False,
        "matched": int(marker.get("matched", 0)) if marker else 0,
        "rows": int(counts["n"]) if counts else 0,
        "by_kind": dict(marker.get("by_kind", {})) if marker else {},
        "control_streams": int(marker.get("control_streams", 0)) if marker else 0,
    }


def limits_in_words(marker: dict | None = None) -> list[str]:
    """§8.2's ``limits``: the caps that applied to this scan, in words.

    The constants first, so the page can state what this build observes without
    inventing a number, and then the run's own notes — the caps that actually bit
    and the streams that could not be read — because "at most 25 per protocol" and
    "25 of 41 were read" are different statements.
    """
    lines = [
        f"At most {MAX_FINDINGS} findings are stored for one analysis, highest confidence first.",
        f"At most {MAX_CONTROL_STREAMS} control streams are reassembled per protocol, "
        "lowest stream id first.",
        f"At most {MAX_STREAM_CHARS} characters are examined from one reassembled control stream.",
        f"One control stream is given {STREAM_TIMEOUT_S} seconds to reassemble before it is skipped.",
        f"HTTP bodies are read from the stored previews, at most {MAX_BODY_CHARS} characters each.",
        f"At most {MAX_FIELDS_PER_LOCATION} fields are read from one form, JSON document or query.",
        f"A value longer than {MAX_VALUE_CHARS} characters is stored truncated, with "
        "value_truncated set.",
    ]
    if marker:
        lines.extend(str(note) for note in marker.get("unread", []))
    return lines


def scan_limits(analysis_id: str) -> list[str]:
    """``limits_in_words`` for the last run recorded for one analysis."""
    return limits_in_words(stage_marker(analysis_id))


# --------------------------------------------------------------------------
# the stage
# --------------------------------------------------------------------------


def analyze(ctx: JobContext, analysis_id: str, capture_path: Path | None = None) -> dict:
    """Scan one analysis's rows — and, for the four command protocols, its control channels.

    ``capture_path`` is the capture §2(b) reassembles control streams from. The
    HTTP half of the scan never touches it: HTTP bodies are stored with their
    transactions, so a purged capture costs the command protocols their channel
    and nothing else. Every failure to read one is recorded in ``warnings`` and
    never raised, because an optional stage that could sink an analysis would be
    worse than a partial answer (the pipeline's own rule).

    When the runtime setting ``credential_scan_enabled`` is false the stage writes
    nothing at all — not even disturbing the rows it wrote last time, because §7
    says turning the scan off does not delete what it found — and returns a warning
    naming the setting for the pipeline to record.
    """
    started = time.monotonic()
    ctx.set_stage("Scanning for credentials")

    config = runtime_settings.credential_config()
    if not config["credential_scan_enabled"]:
        log.info("credential scan skipped for %s: credential_scan_enabled is false", analysis_id)
        return {
            "enabled": False,
            "skipped": True,
            "findings": 0,
            "matched": 0,
            "capped": False,
            "protocols": list(config["credential_protocols"]),
            "warnings": [
                "The credential scan is disabled by the setting "
                "credential_scan_enabled; no credential rows were written."
            ],
        }

    protocols = list(config["credential_protocols"])
    with db.get_conn() as conn:
        conn.execute("DELETE FROM credentials WHERE analysis_id = ?", (analysis_id,))
        conn.execute(
            "DELETE FROM stats_cache WHERE analysis_id = ? AND kind = ?",
            (analysis_id, MARKER_KIND),
        )

    ctx.check_cancelled()
    scan = collect(
        analysis_id,
        protocols,
        capture_path=capture_path,
        cancel_event=getattr(ctx, "cancel_event", None),
    )
    ctx.check_cancelled()

    findings = rank(scan.findings)
    capped = len(scan.findings) > MAX_FINDINGS
    warnings = list(scan.notes)
    if capped:
        warnings.append(
            f"{len(scan.findings)} findings were matched and MAX_FINDINGS = {MAX_FINDINGS} "
            "were stored, highest confidence first; the rest were not kept."
        )
    _persist(analysis_id, findings)

    seconds = round(time.monotonic() - started, 3)
    by_kind = {kind: count for kind, count in _count_by(findings, "kind").items() if count}
    by_confidence = {
        level: count for level, count in _count_by(findings, "confidence").items() if count
    }
    by_protocol = {name: count for name, count in _count_by(findings, "protocol").items() if count}
    result = {
        "enabled": True,
        "skipped": False,
        "findings": len(findings),
        "matched": len(scan.findings),
        "capped": capped,
        "by_kind": by_kind,
        "by_confidence": by_confidence,
        "by_protocol": by_protocol,
        "protocols": protocols,
        "protocols_scanned": scan.scanned,
        "control_streams": scan.control_streams,
        "seconds": seconds,
        "warnings": warnings,
    }
    write_marker(
        analysis_id,
        {
            "findings": len(findings),
            "matched": len(scan.findings),
            "capped": capped,
            "by_kind": by_kind,
            "by_confidence": by_confidence,
            "by_protocol": by_protocol,
            "protocols": protocols,
            "protocols_scanned": scan.scanned,
            "control_streams": scan.control_streams,
            "unread": warnings,
            "seconds": seconds,
            "scanned_at": time.time(),
        },
    )
    # Counts and kinds only: a credential value never reaches a log line (§5).
    kinds = ", ".join(f"{kind}={count}" for kind, count in sorted(by_kind.items())) or "none"
    log.info(
        "credential scan for %s wrote %d finding(s) from %d control stream(s) in %.2fs (%s)",
        analysis_id,
        len(findings),
        scan.control_streams,
        seconds,
        kinds,
    )
    for note in warnings:
        log.info("credential scan for %s: %s", analysis_id, note)
    return result


__all__ = [
    "CONFIDENCE_LEVELS",
    "CONTRACT_NOTES",
    "CONTROL_METHOD",
    "CONTROL_VERBS",
    "EVIDENCE_MAX_CHARS",
    "Finding",
    "JSON_DEPTH",
    "KINDS",
    "MARKER_KIND",
    "MAX_BODY_CHARS",
    "MAX_CONTROL_STREAMS",
    "MAX_FIELDS_PER_LOCATION",
    "MAX_FINDINGS",
    "MAX_STREAM_CHARS",
    "MAX_VALUE_CHARS",
    "MIN_VALUE_CHARS",
    "PATTERNS",
    "PREVIEW_HEAD",
    "PREVIEW_SEPARATOR",
    "PREVIEW_TAIL",
    "PROTOCOLS",
    "STREAM_TIMEOUT_S",
    "ScanResult",
    "analyze",
    "collect",
    "control_candidates",
    "limits_in_words",
    "normalise_name",
    "preview",
    "rank",
    "scan_control_channels",
    "scan_control_stream",
    "scan_http",
    "scan_limits",
    "scan_session",
    "scan_state",
    "shape_of",
    "stage_marker",
    "write_marker",
]
