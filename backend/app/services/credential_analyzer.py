"""Credential discovery over the rows the other analysers already wrote.

The normative contract is ``docs/CREDENTIALS.md``. This module implements it
without a capture pass of its own: it reads ``http_transactions`` and
``protocol_sessions``, decides which of their fields are credential-bearing,
and never invents a value that no stored row carried.

Why it is built this way:

* **No new capture pass.** Every value comes from a field the HTTP or protocol
  analyser already decoded and stored, so the stage costs two SELECTs instead of
  a TShark pass, and a capture the other stages could not read yields nothing
  here either rather than a different, half-decoded answer.
* **Base64 is decoded only where a protocol says the field is Base64** (§3.1):
  HTTP Basic, and ``AUTH PLAIN`` / ``AUTH LOGIN``. Everywhere else a
  Base64-looking string is left alone, because decoding a token that nothing
  identified would manufacture a value the wire never carried.
* **Redaction happens before storage.** A finding's ``evidence`` line quotes the
  source field with the value's middle removed, so a row read straight out of
  SQLite leaks no more than the API does, and ``value_preview`` never equals the
  full value (§5).
* **Nothing is logged.** The stage logs counts and kinds; a credential value
  never enters a log line, a warning or an error message (§5).

Two limits of the stored rows are worth stating where they can be read (§3.1's
"only what the analysers capped"):

* ``protocol_analyzer`` blanks the argument of an FTP/POP3 ``PASS`` command and
  keeps only the mechanism name of an SMTP/POP3 ``AUTH`` command, and IMAP
  commands carry no argument at all. This scanner reads whatever is stored and
  reports nothing where nothing was stored: an upstream redaction is a fact of
  this build, not evidence that no credential crossed the wire.
* Bodies are read from the stored previews, so a credential the HTTP analyser
  did not keep in its preview cannot be found here.

Where this module had to interpret the contract, the reasoning is on the
function or constant it concerns; the disagreements are listed in the module's
``CONTRACT_NOTES``.
"""

from __future__ import annotations

import base64
import binascii
import json
import re
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterator, Sequence
from urllib.parse import parse_qsl

from app.core import runtime_settings
from app.core.logging import get_logger
from app.db import database as db
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
#: 3. §2 gives FTP ``detail.auth_username``; the FTP detail the analyser actually
#:    writes uses ``username``, so both names are read.
#: 4. §8 does not say what ``order`` defaults to. It is ``desc``, like every other
#:    list endpoint in this application, and the confidence sort is expressed so
#:    that ``desc`` means "highest confidence first".
#: 5. §9 says MAX_FIELDS_PER_LOCATION limits "candidate fields"; it is applied to
#:    every field read from one location, because that is what bounds the work.
#: 6. §6 does not say whether ``value_length`` counts the stored value or the wire
#:    value; ``Documentation/Credentials.md`` §6 does, so a truncated row reports
#:    512 and sets ``value_truncated`` rather than a length it cannot show.
CONTRACT_NOTES: tuple[str, ...] = (
    "§5's no-full-value rule is applied to values of every length (see preview()).",
    "§3.3's escaped pipes are read as alternation.",
    "FTP username is read from detail.username as well as detail.auth_username.",
    "order defaults to desc; confidence sorts high first under desc.",
    "MAX_FIELDS_PER_LOCATION bounds every field read from one location.",
    "value_length counts the stored value, so a truncated row reports MAX_VALUE_CHARS.",
)

# --------------------------------------------------------------------------
# §3.2 field names
# --------------------------------------------------------------------------

#: The §3.2 list, grouped by the kind a match yields. The grouping is this
#: module's reading: the contract fixes which *names* are credential-like, and
#: the kind column of §6 needs one answer per match.
_FIELD_KINDS: dict[str, str] = {
    "user": "username",
    "username": "username",
    "user_name": "username",
    "login": "username",
    "login_id": "username",
    "logon": "username",
    "email": "username",
    "account": "username",
    "name": "username",
    "pass": "password",
    "passwd": "password",
    "password": "password",
    "pwd": "password",
    "secret": "other_secret",
    "client_secret": "api_key",
    "api_key": "api_key",
    "apikey": "api_key",
    "access_key": "api_key",
    "access_token": "other_secret",
    "auth_token": "other_secret",
    "token": "other_secret",
    "session": "other_secret",
    "sessionid": "other_secret",
    "bearer": "bearer_token",
    "authorization": "other_secret",
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
        self._seen: set[tuple] = set()
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


def _decode_base64(text: str) -> str | None:
    """Strict Base64, in the one place a protocol says the field is Base64 (§3.1).

    Padding is tolerated because RFC 4648 allows it to be omitted and captures
    routinely show it missing. Nothing else is: an alphabet character outside the
    standard set, or bytes that are not UTF-8 text, mean this is not the encoding
    the protocol said it was, and a value that is not decoded is reported as the
    opaque string it was.
    """
    candidate = text.strip()
    if not candidate or len(candidate) < 4 or not _BASE64_RE.match(candidate):
        return None
    padded = candidate + "=" * (-len(candidate) % 4)
    try:
        raw = base64.b64decode(padded, validate=True)
    except (binascii.Error, ValueError):
        return None
    try:
        decoded = raw.decode("utf-8")
    except UnicodeDecodeError:
        return None
    if not decoded:
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
    _scan_body(scan, row=row, base=base)


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
    """``parse_qsl`` without its failure modes: bad pairs are dropped, not raised."""
    try:
        pairs = parse_qsl(text, keep_blank_values=True, strict_parsing=False)
    except ValueError:  # pragma: no cover - parse_qsl is tolerant by request
        return []
    return [(str(name), str(value)) for name, value in pairs]


def _scan_body(scan: _Scan, *, row: Any, base: dict[str, Any]) -> None:
    """The request body, read as a form, as JSON, or as free text (§3.1)."""
    body = row["request_body"]
    if not isinstance(body, str) or not body:
        return
    reader = _body_reader(row["content_type"])
    if reader == "skip":
        return

    text = body[:MAX_BODY_CHARS]
    if reader == "form":
        _scan_form(scan, text=text, base=base)
        return
    if reader == "json":
        if _scan_json(scan, text=text, base=base):
            return
        _scan_text(scan, text=text, base=base)
        return

    # A body the analyser kept as text: a JSON document whose content type was
    # never recorded is still parsed as JSON rather than as prose, because the
    # parse is proof of what it is and reading it as text would lose every field.
    stripped = text.lstrip()
    if stripped.startswith(("{", "[")) and _scan_json(scan, text=text, base=base):
        return
    _scan_text(scan, text=text, base=base)


def _scan_form(scan: _Scan, *, text: str, base: dict[str, Any]) -> None:
    for index, (name, value) in enumerate(_form_pairs(text)):
        if index >= MAX_FIELDS_PER_LOCATION:
            break
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
        value = value.rstrip(",")
        if len(value) >= 2 and value[0] == '"' and value[-1] == '"':
            value = value[1:-1]
        if not name or len(name) > 64 or any(char.isspace() for char in name):
            continue
        yield name, value


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


def collect(analysis_id: str, protocols: Sequence[str]) -> list[Finding]:
    """Every finding the stored rows support, in discovery order.

    Only the protocols the caller selected are read, and only the two tables §2
    names: an empty selection reads nothing at all, which is what "none" means
    rather than "everything".
    """
    scan = _Scan(analysis_id)
    selected = set(protocols)

    if "http" in selected:
        for row in db.query_all(_SELECT_HTTP, (analysis_id,)):
            scan_http(scan, row)
        log.debug("credential scan read the HTTP transactions of %s", analysis_id)

    command_protocols = [name for name in PROTOCOLS if name != "http" and name in selected]
    if command_protocols:
        placeholders = ", ".join("?" for _ in command_protocols)
        rows = db.query_all(
            f"{_SELECT_SESSION.split(' ORDER BY')[0]} AND protocol IN ({placeholders})"
            " ORDER BY id",
            (analysis_id, *command_protocols),
        )
        for row in rows:
            scan_session(scan, row)

    return scan.findings


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
        "scanned_at": marker.get("scanned_at") if marker else None,
        "stage_ran": marker is not None,
        "protocols_scanned": list(marker.get("protocols", [])) if marker else [],
        "findings": int(marker.get("findings", 0)) if marker else 0,
        "by_kind": dict(marker.get("by_kind", {})) if marker else {},
        "seconds": marker.get("seconds") if marker else None,
        "try_count": marker.get("try_count") if marker else None,
        "rows": int(counts["n"]) if counts else 0,
        "rows_written_at": counts["written_at"] if counts else None,
    }


# --------------------------------------------------------------------------
# the stage
# --------------------------------------------------------------------------


def analyze(ctx: JobContext, analysis_id: str, capture_path: Path | None = None) -> dict:
    """Scan the rows already stored for ``analysis_id`` and persist the findings.

    ``capture_path`` is accepted so this stage has the signature every other
    stage has, and is deliberately never opened: the contract forbids a second
    capture pass (§2), so the only inputs are ``http_transactions`` and
    ``protocol_sessions``.

    When the runtime setting ``credential_scan_enabled`` is false the stage writes
    nothing at all — not even the rows it wrote last time, because §7 says turning
    the scan off does not delete what it found — and returns a ``warning`` naming
    the setting for the pipeline to record.
    """
    del capture_path  # no capture pass: see the docstring and docs/CREDENTIALS.md §2
    started = time.monotonic()
    ctx.set_stage("Scanning for credentials")

    config = runtime_settings.credential_config()
    if not config["credential_scan_enabled"]:
        log.info("credential scan skipped for %s: credential_scan_enabled is false", analysis_id)
        return {
            "enabled": False,
            "skipped": True,
            "findings": 0,
            "protocols": list(config["credential_protocols"]),
            "warning": (
                "The credential scan is disabled by the setting "
                "credential_scan_enabled; no credential rows were written."
            ),
        }

    protocols = list(config["credential_protocols"])
    with db.get_conn() as conn:
        conn.execute("DELETE FROM credentials WHERE analysis_id = ?", (analysis_id,))
        conn.execute(
            "DELETE FROM stats_cache WHERE analysis_id = ? AND kind = ?",
            (analysis_id, MARKER_KIND),
        )

    ctx.check_cancelled()
    findings = rank(collect(analysis_id, protocols))
    ctx.check_cancelled()
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
        "by_kind": by_kind,
        "by_confidence": by_confidence,
        "by_protocol": by_protocol,
        "protocols": protocols,
        "seconds": seconds,
    }
    write_marker(
        analysis_id,
        {
            "findings": len(findings),
            "by_kind": by_kind,
            "by_confidence": by_confidence,
            "by_protocol": by_protocol,
            "protocols": protocols,
            "seconds": seconds,
            "scanned_at": time.time(),
        },
    )
    # Counts and kinds only: a credential value never reaches a log line (§5).
    kinds = ", ".join(f"{kind}={count}" for kind, count in sorted(by_kind.items())) or "none"
    log.info(
        "credential scan for %s wrote %d finding(s) in %.2fs (%s)",
        analysis_id,
        len(findings),
        seconds,
        kinds,
    )
    return result


__all__ = [
    "CONFIDENCE_LEVELS",
    "CONTRACT_NOTES",
    "EVIDENCE_MAX_CHARS",
    "Finding",
    "JSON_DEPTH",
    "KINDS",
    "MARKER_KIND",
    "MAX_BODY_CHARS",
    "MAX_FIELDS_PER_LOCATION",
    "MAX_FINDINGS",
    "MAX_VALUE_CHARS",
    "MIN_VALUE_CHARS",
    "PATTERNS",
    "PREVIEW_HEAD",
    "PREVIEW_SEPARATOR",
    "PREVIEW_TAIL",
    "PROTOCOLS",
    "analyze",
    "collect",
    "normalise_name",
    "preview",
    "rank",
    "scan_http",
    "scan_session",
    "scan_state",
    "shape_of",
    "stage_marker",
    "write_marker",
]
