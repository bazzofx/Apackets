r"""Protocol session metadata for nine protocols in five families.

Normative contract: ``docs/PROTOCOLS.md``. This module is its §1-§4 and §6:

* **One row per stream** in which a protocol appeared, never merged across streams.
* **Five TShark passes**, one per family, each asking for every field the family
  needs plus the per-frame framing fields, so sessions, times and both directions'
  volumes are computed from real frames rather than estimated.
* **Roles by §1.2**, with the rule that applied recorded in ``note``.
* **``detail`` holds only keys the dissector produced** - a value that did not cross
  the wire is absent, never approximated. Payloads and password *values* are never
  copied: a password is recorded as ``password_present: true``.
* **``flags`` is a JSON array of ``code`` or ``"code: detail"`` strings**, most
  serious first, capped at :data:`FLAG_CAP`.

Measurements are deliberately literal:

* ``packets`` / ``bytes`` count the frames TShark attributed to this protocol in
  this stream (the frames the pass matched), split by the direction the roles gave.
* The field names below were verified against the installed TShark build
  (``tshark -G fields``); a name that does not exist there is not used.
* TShark's ``-T fields`` writer escapes backslashes, so every value is un-escaped
  once on the way in. Verified against this build: ``-T fields`` prints
  ``smb2.tree`` as ``\\\\robotainment-DC\\IPC$`` where the field's real value, as
  ``-T json`` shows it, is ``\\robotainment-DC\Shared``.
* The port table of §1.2 is the source for two things: which endpoint is the server
  (rule 1) and whether the server port is unusual. Its alternates are accepted, because
  standard submission or implicit-TLS traffic is not unusual, and a tool that says it is
  is a tool that cries wolf.
* ``smtp.auth.username`` is the *encoded* AUTH data in this build: TShark 4.6.8
  exposes no base64-decode preference for SMTP (``-o smtp.decode_data:TRUE`` is
  rejected as an unknown preference), so the base64 is decoded here when - and only
  when - it decodes cleanly to printable text, and the row's ``note`` says so.
* SMB2/SMB1 command and dialect numbers are named from this build's own value
  tables (``tshark -G values``); anything outside those tables keeps the value the
  dissector printed, in hex, rather than a guessed label.
"""

from __future__ import annotations

import base64
import json
import re
import sqlite3
import time
from collections import OrderedDict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, Iterator, Sequence

from app.core.logging import get_logger
from app.db import database as db
from app.services import tshark
from app.services.jobs import JobContext

log = get_logger("apackets.protocols")

# --------------------------------------------------------------------------
# caps (docs/PROTOCOLS.md §6)
# --------------------------------------------------------------------------

SESSION_CAP = 2000          # session rows read for one API request
LIST_CAP = 50               # entries in any detail list
COMMAND_CAP = 25            # distinct commands kept per session
FLAG_CAP = 10               # flags kept per session
COUNT_CAP = 200             # distinct codes/statuses kept in a count map
LARGE_TRANSFER_BYTES = 10 * 1024 * 1024
MANY_COMMANDS = 40
LONG_SESSION_SECONDS = 3600

#: The ``stats_cache`` kind that records this stage having run for an analysis, with the
#: counts it wrote. It is what makes ``extracted`` answerable (docs/PROTOCOLS.md §5.1):
#: the record's presence means the capture has been read for these protocols, so zero
#: rows really does mean zero sessions - and its absence means "not read yet", whatever
#: the analysis's timestamps say.
MARKER_KIND = "protocol_sessions"

# --------------------------------------------------------------------------
# families, protocols, ports
# --------------------------------------------------------------------------

FAMILIES: dict[str, tuple[str, ...]] = {
    "email": ("smtp", "pop3", "imap"),
    "ssh": ("ssh",),
    "ftp": ("ftp",),
    "voip": ("sip", "rtp", "rtcp"),
    "smb": ("smb",),
}

PROTOCOLS: tuple[str, ...] = tuple(p for family in FAMILIES.values() for p in family)

PROTOCOL_FAMILY: dict[str, str] = {
    protocol: family for family, protocols in FAMILIES.items() for protocol in protocols
}

# §1.2's port table, verbatim: the ports that make an endpoint the server of a session.
# It is deliberately wider than the single registered port, because the well-known
# alternates carry the same protocol (587/465 submission, 995/993 implicit TLS, 20 the
# FTP data channel, 5061 SIP over TLS, 139 NetBIOS session service). RTP/RTCP have none:
# they take the role of the SIP session that produced them.
SERVER_PORTS: dict[str, frozenset[int]] = {
    "smtp": frozenset({25, 587, 465}),
    "pop3": frozenset({110, 995}),
    "imap": frozenset({143, 993}),
    "ssh": frozenset({22}),
    "ftp": frozenset({21, 20}),
    "sip": frozenset({5060, 5061}),
    "smb": frozenset({445, 139}),
}

# §4 scopes `no_encryption_upgrade` to the ports that carry the protocol in the clear and
# expect an *optional* upgrade: 25 and 587 for SMTP, 110 POP3, 143 IMAP, 21 FTP. 587 is
# submission - the port modern mail actually uses - and a session there that never
# upgraded is readable, so leaving it out would under-report cleartext mail on the most
# common mail port. The implicit-TLS ports (465, 995, 993) are deliberately absent: a
# session there is TLS from its first byte and is not dissected as this protocol at all.
UPGRADE_EXPECTING_PORTS: frozenset[int] = frozenset({25, 587, 110, 143, 21})

# The page each protocol belongs to, used for the detail route's links.
PAGE_BY_FAMILY: dict[str, str] = {
    "email": "/email",
    "ssh": "/ssh",
    "ftp": "/ftp",
    "voip": "/voip",
    "smb": "/smb",
}

# --------------------------------------------------------------------------
# TShark fields (all verified present in this build with `tshark -G fields`)
# --------------------------------------------------------------------------

FRAMING_FIELDS: tuple[str, ...] = (
    "frame.number",
    "frame.time_epoch",
    "frame.len",
    "frame.protocols",
    "ip.src",
    "ipv6.src",
    "ip.dst",
    "ipv6.dst",
    "tcp.srcport",
    "tcp.dstport",
    "udp.srcport",
    "udp.dstport",
    "tcp.stream",
    "udp.stream",
)

SSH_FIELDS: tuple[str, ...] = (
    "ssh.protocol",
    "ssh.message_code",
    "ssh.kex_algorithms",
    "ssh.server_host_key_algorithms",
    "ssh.encryption_algorithms_client_to_server",
    "ssh.encryption_algorithms_server_to_client",
    "ssh.mac_algorithms_client_to_server",
)

_FRAMING_NAMES = frozenset(FRAMING_FIELDS)


@dataclass(frozen=True)
class FamilySpec:
    """One TShark pass: what to match, and which protocol each match belongs to."""

    name: str
    display_filter: str
    protocols: tuple[str, ...]
    tokens: dict[str, str]          # frame.protocols token -> protocol
    fields: tuple[str, ...]


FAMILY_SPECS: dict[str, FamilySpec] = {
    "email": FamilySpec(
        name="email",
        display_filter="smtp or pop or imap",
        protocols=FAMILIES["email"],
        tokens={"smtp": "smtp", "pop": "pop3", "imap": "imap"},
        fields=(
            "smtp.req.command",
            "smtp.req.parameter",
            "smtp.response.code",
            "smtp.rsp.parameter",
            "smtp.auth.username",
            "smtp.auth.password",
            "smtp.eom",
            "pop.request.command",
            "pop.request.parameter",
            "pop.response.indicator",
            "pop.response.description",
            "imap.request.command",
            "imap.request_tag",
            "imap.response.status",
            "imap.request.folder",
            "imap.request.username",
            "imap.request.password",
            "imap.request.command.uid",
            "imap.tag",
        ),
    ),
    "ssh": FamilySpec(
        name="ssh",
        display_filter="ssh",
        protocols=FAMILIES["ssh"],
        tokens={"ssh": "ssh"},
        fields=SSH_FIELDS,
    ),
    "ftp": FamilySpec(
        name="ftp",
        display_filter="ftp",
        protocols=FAMILIES["ftp"],
        tokens={"ftp": "ftp"},
        fields=(
            "ftp.request.command",
            "ftp.request.arg",
            "ftp.response.code",
            "ftp.response.arg",
            "ftp.passive.ip",
            "ftp.passive.port",
            "ftp.epsv.port",
            "ftp.eprt.ip",
            "ftp.eprt.port",
            "ftp.active.cip",
            "ftp.active.port",
            "ftp.current-working-directory",
        ),
    ),
    "voip": FamilySpec(
        name="voip",
        display_filter="sip or rtp or rtcp",
        protocols=FAMILIES["voip"],
        tokens={"sip": "sip", "rtp": "rtp", "rtcp": "rtcp"},
        fields=(
            "sip.Method",
            "sip.Status-Code",
            "sip.Call-ID",
            "sip.User-Agent",
            "sip.r-uri.host",
            "sip.r-uri.user",
            "sip.from.user",
            "sip.to.user",
            "rtp.ssrc",
            "rtp.p_type",
            "rtp.seq",
            "rtcp.pt",
            "rtcp.senderssrc",
            "rtcp.ssrc.identifier",
        ),
    ),
    "smb": FamilySpec(
        name="smb",
        display_filter="smb or smb2",
        protocols=FAMILIES["smb"],
        tokens={"smb": "smb", "smb2": "smb"},
        fields=(
            "smb.cmd",
            "smb.nt_status",
            "smb.flags.response",
            "smb.flags2.sec_sig_required",
            "smb2.cmd",
            "smb2.flags.response",
            "smb2.dialect",
            "smb2.tree",
            "smb2.filename",
            "smb2.nt_status",
            "smb2.host",
            "smb2.acct",
            "smb2.sec_mode",
            "smb2.sec_mode.sign_required",
            "smb2.ses_flags.encrypt",
            "smb2.ses_flags.guest",
            "smb2.ses_flags.null",
            "smb2.capabilities.encryption",
        ),
    ),
}

# Separator/aggregator per row. Neither may be a character ``str.splitlines`` or the
# line reader would treat as a break; the unit separator and end-of-medium are not.
FIELD_SEPARATOR = "\x1f"
AGGREGATOR = "\x19"

BATCH_SIZE = 500
CANCEL_EVERY = 2000

# --------------------------------------------------------------------------
# value tables, read from this build's own `tshark -G values` output
# --------------------------------------------------------------------------

# smb2.cmd: the dissector's value strings, upper-cased with spaces to underscores so
# the keys are the names docs/PROTOCOLS.md §3.8 lists (NEGOTIATE, SESSION_SETUP, ...).
SMB2_COMMANDS: dict[int, str] = {
    0: "NEGOTIATE",
    1: "SESSION_SETUP",
    2: "LOGOFF",
    3: "TREE_CONNECT",
    4: "TREE_DISCONNECT",
    5: "CREATE",
    6: "CLOSE",
    7: "FLUSH",
    8: "READ",
    9: "WRITE",
    10: "LOCK",
    11: "IOCTL",
    12: "CANCEL",
    13: "KEEPALIVE",
    14: "FIND",
    15: "NOTIFY",
    16: "GETINFO",
    17: "SETINFO",
    18: "BREAK",
    19: "SERVER_NOTIFICATION",
}

# smb.cmd (SMB1). Only the names this build publishes are listed; a command outside
# the table keeps the value the dissector printed.
SMB1_COMMANDS: dict[int, str] = {
    0x00: "CREATE_DIRECTORY",
    0x01: "DELETE_DIRECTORY",
    0x02: "OPEN",
    0x03: "CREATE",
    0x04: "CLOSE",
    0x05: "FLUSH",
    0x06: "DELETE",
    0x07: "RENAME",
    0x08: "QUERY_INFORMATION",
    0x09: "SET_INFORMATION",
    0x0A: "READ",
    0x0B: "WRITE",
    0x0C: "LOCK_BYTE_RANGE",
    0x0D: "UNLOCK_BYTE_RANGE",
    0x0E: "CREATE_TEMP",
    0x0F: "CREATE_NEW",
    0x10: "CHECK_DIRECTORY",
    0x11: "PROCESS_EXIT",
    0x12: "SEEK",
    0x13: "LOCK_AND_READ",
    0x14: "WRITE_AND_UNLOCK",
    0x1A: "READ_RAW",
    0x1B: "READ_MPX",
    0x1C: "READ_MPX_SECONDARY",
    0x1D: "WRITE_RAW",
    0x1E: "WRITE_MPX",
    0x1F: "WRITE_MPX_SECONDARY",
    0x20: "WRITE_COMPLETE",
    0x21: "QUERY_SERVER",
    0x22: "SET_INFORMATION2",
    0x23: "QUERY_INFORMATION2",
    0x24: "LOCKING_ANDX",
    0x25: "TRANS",
    0x26: "TRANS_SECONDARY",
    0x27: "IOCTL",
    0x28: "IOCTL_SECONDARY",
    0x29: "COPY",
    0x2A: "MOVE",
    0x2B: "ECHO",
    0x2C: "WRITE_AND_CLOSE",
    0x2D: "OPEN_ANDX",
    0x2E: "READ_ANDX",
    0x2F: "WRITE_ANDX",
    0x30: "NEW_FILE_SIZE",
    0x31: "CLOSE_AND_TREE_DISCONNECT",
    0x32: "TRANS2",
    0x33: "TRANS2_SECONDARY",
    0x34: "FIND_CLOSE2",
    0x35: "FIND_NOTIFY_CLOSE",
    0x70: "TREE_CONNECT",
    0x71: "TREE_DISCONNECT",
    0x72: "NEGOTIATE",
    0x73: "SESSION_SETUP_ANDX",
    0x74: "LOGOFF_ANDX",
    0x75: "TREE_CONNECT_ANDX",
    0x80: "QUERY_INFORMATION_DISK",
    0x81: "SEARCH",
    0x82: "FIND",
    0x83: "FIND_UNIQUE",
    0x84: "FIND_CLOSE",
    0xA0: "NT_TRANS",
    0xA1: "NT_TRANS_SECONDARY",
    0xA2: "NT_CREATE_ANDX",
    0xA4: "NT_CANCEL",
    0xA5: "NT_RENAME",
    0xC0: "OPEN_PRINT_FILE",
    0xC1: "WRITE_PRINT_FILE",
    0xC2: "CLOSE_PRINT_FILE",
    0xC3: "GET_PRINT_QUEUE",
    0xD0: "SEND_SINGLE_BLOCK_MESSAGE",
    0xD1: "SEND_BROADCAST_MESSAGE",
    0xD2: "FORWARD_USER_NAME",
    0xD3: "CANCEL_FORWARD",
    0xD4: "GET_MACHINE_NAME",
}

# smb2.dialect: names verbatim from this build's value table.
SMB_DIALECTS: dict[int, str] = {
    0x0202: "SMB 2.0.2",
    0x0210: "SMB 2.1",
    0x02FF: "SMB2 wildcard",
    0x0222: "SMB 2.2.2 (deprecated; should be 3.0)",
    0x0224: "SMB 2.2.4 (deprecated; should be 3.0)",
    0x0300: "SMB 3.0",
    0x0302: "SMB 3.0.2",
    0x0310: "SMB 3.1.0 (deprecated; should be 3.1.1)",
    0x0311: "SMB 3.1.1",
}

# The SMB1 dialect name this contract mandates when a session negotiated SMB1.
SMB1_DIALECT = "SMB 1"

# The most common NT status codes, names verbatim from this build's value table for
# smb.nt_status/smb2.nt_status. A code outside the table keeps the hex the dissector
# printed.
NT_STATUS: dict[int, str] = {
    0x00000000: "STATUS_SUCCESS",
    0x00000103: "STATUS_PENDING",
    0x00000104: "STATUS_REPARSE",
    0x40000000: "STATUS_OBJECT_NAME_EXISTS",
    0x80000005: "STATUS_BUFFER_OVERFLOW",
    0x8000001A: "STATUS_NO_MORE_ENTRIES",
    0xC0000001: "STATUS_UNSUCCESSFUL",
    0xC0000002: "STATUS_NOT_IMPLEMENTED",
    0xC0000008: "STATUS_INVALID_HANDLE",
    0xC000000D: "STATUS_INVALID_PARAMETER",
    0xC000000F: "STATUS_NO_SUCH_FILE",
    0xC0000010: "STATUS_INVALID_DEVICE_REQUEST",
    0xC0000011: "STATUS_END_OF_FILE",
    0xC0000016: "STATUS_MORE_PROCESSING_REQUIRED",
    0xC0000022: "STATUS_ACCESS_DENIED",
    0xC0000023: "STATUS_BUFFER_TOO_SMALL",
    0xC0000033: "STATUS_OBJECT_NAME_INVALID",
    0xC0000034: "STATUS_OBJECT_NAME_NOT_FOUND",
    0xC0000035: "STATUS_OBJECT_NAME_COLLISION",
    0xC0000039: "STATUS_OBJECT_PATH_INVALID",
    0xC000003A: "STATUS_OBJECT_PATH_NOT_FOUND",
    0xC0000043: "STATUS_SHARING_VIOLATION",
    0xC0000054: "STATUS_FILE_LOCK_CONFLICT",
    0xC0000056: "STATUS_DELETE_PENDING",
    0xC0000061: "STATUS_PRIVILEGE_NOT_HELD",
    0xC000006A: "STATUS_WRONG_PASSWORD",
    0xC000006D: "STATUS_LOGON_FAILURE",
    0xC000006E: "STATUS_ACCOUNT_RESTRICTION",
    0xC000006F: "STATUS_INVALID_LOGON_HOURS",
    0xC0000071: "STATUS_PASSWORD_EXPIRED",
    0xC0000072: "STATUS_ACCOUNT_DISABLED",
    0xC000007F: "STATUS_DISK_FULL",
    0xC000009A: "STATUS_INSUFFICIENT_RESOURCES",
    0xC00000AC: "STATUS_PIPE_NOT_AVAILABLE",
    0xC00000B5: "STATUS_IO_TIMEOUT",
    0xC00000BA: "STATUS_FILE_IS_A_DIRECTORY",
    0xC00000BB: "STATUS_NOT_SUPPORTED",
    0xC00000C9: "STATUS_NETWORK_NAME_DELETED",
    0xC00000CE: "STATUS_TOO_MANY_SESSIONS",
    0xC00000E2: "STATUS_OPLOCK_NOT_GRANTED",
    0xC0000103: "STATUS_NOT_A_DIRECTORY",
    0xC0000128: "STATUS_FILE_CLOSED",
    0xC000015B: "STATUS_LOGON_TYPE_NOT_GRANTED",
    0xC0000185: "STATUS_IO_DEVICE_ERROR",
    0xC000018B: "STATUS_NO_TRUST_SAM_ACCOUNT",
    0xC000018C: "STATUS_TRUSTED_DOMAIN_FAILURE",
    0xC0000202: "STATUS_NO_USER_SESSION_KEY",
    0xC0000203: "STATUS_USER_SESSION_DELETED",
    0xC0000225: "STATUS_NOT_FOUND",
    0xC00000CC: "STATUS_BAD_NETWORK_NAME",
    0xC0000064: "STATUS_NO_SUCH_USER",
    0xC0000234: "STATUS_ACCOUNT_LOCKED_OUT",
    0xC000035C: "STATUS_NETWORK_SESSION_EXPIRED",
}

# Anonymous-style identities, per §4's anonymous_login (ftp, smb).
ANONYMOUS_IDENTITIES = frozenset({"anonymous", "ftp", "guest", "anonymous user"})

# A response code/status/indicator that means "this authentication was rejected".
AUTH_FAILURE_CODES: dict[str, tuple[str, ...]] = {
    "smtp": ("535",),
    "pop3": ("-ERR",),
    "imap": ("NO",),
    "ftp": ("530",),
}

CLEARTEXT_PROTOCOLS = frozenset({"smtp", "pop3", "imap", "ftp"})
COMMAND_PROTOCOLS = frozenset({"smtp", "pop3", "imap", "ftp"})

# §4 list order: the most serious first. The cap keeps the head of this list.
FLAG_ORDER: tuple[str, ...] = (
    "cleartext_credentials",
    "cleartext_username",
    "auth_failures",
    "anonymous_login",
    "no_encryption_upgrade",
    "legacy_dialect",
    "signing_not_required",
    "media_without_signalling",
    "unusual_port",
    "large_transfer",
    "many_commands",
    "long_session",
)

_B64_RE = re.compile(r"^[A-Za-z0-9+/]+={0,2}$")


# --------------------------------------------------------------------------
# frames
# --------------------------------------------------------------------------

def _unescape(value: str) -> str:
    """Undo TShark's ``-T fields`` backslash escaping.

    The writer doubles every backslash, so replacing each pair left to right
    recovers the field value exactly (see the module docstring for the evidence).
    """
    if "\\" not in value:
        return value
    return value.replace("\\\\", "\\")


def _parts_of(value: str | None) -> tuple[str, ...]:
    if not value:
        return ()
    return tuple(_unescape(part) for part in value.split(AGGREGATOR) if part)


def _int_or_none(value: str | None) -> int | None:
    if value is None or not value.strip():
        return None
    text = value.strip()
    try:
        return int(text, 0)
    except ValueError:
        try:
            return int(float(text))
        except ValueError:
            return None


def _float_or_none(value: str | None) -> float | None:
    if value is None or not value.strip():
        return None
    try:
        return float(value.strip())
    except ValueError:
        return None


@dataclass
class Frame:
    """One TShark row: the framing facts plus the family's own field values."""

    protocol: str
    number: int
    time: float | None
    length: int
    stream: int | None
    transport: str | None
    src_ip: str | None
    src_port: int | None
    dst_ip: str | None
    dst_port: int | None
    values: dict[str, tuple[str, ...]] = field(default_factory=dict)
    #: ``frame.protocols`` split into its dissector tokens, outermost first.
    tokens: tuple[str, ...] = ()

    def parts(self, key: str) -> tuple[str, ...]:
        return self.values.get(key, ())

    def value(self, key: str) -> str | None:
        for part in self.parts(key):
            if part:
                return part
        return None

    def has(self, key: str) -> bool:
        return bool(self.value(key))

    def flags_true(self, key: str) -> bool:
        """True when a boolean-ish dissector field printed ``True``/``1``."""
        value = self.value(key)
        return value is not None and value.lower() in {"true", "1"}

    @property
    def src(self) -> "Endpoint":
        return Endpoint(self.src_ip, self.src_port)

    @property
    def dst(self) -> "Endpoint":
        return Endpoint(self.dst_ip, self.dst_port)


def _build_frame(fields: list[str], names: Sequence[str]) -> Frame | None:
    if len(fields) < len(names):
        fields = [*fields, *([""] * (len(names) - len(fields)))]
    cells = dict(zip(names, fields))

    number = _int_or_none(cells.get("frame.number"))
    if number is None:
        return None

    protocols = _parts_of(cells.get("frame.protocols"))
    tokens = tuple(
        token
        for chain in protocols
        for token in chain.split(":")
        if token
    )

    stream_tcp = _int_or_none(cells.get("tcp.stream"))
    stream_udp = _int_or_none(cells.get("udp.stream"))
    if stream_tcp is not None:
        stream, transport = stream_tcp, "tcp"
    elif stream_udp is not None:
        stream, transport = stream_udp, "udp"
    elif "tcp" in tokens or "tcp.segments" in tokens:
        stream, transport = None, "tcp"
    elif "udp" in tokens:
        stream, transport = None, "udp"
    else:
        stream, transport = None, None

    src_port = _int_or_none(cells.get("tcp.srcport"))
    dst_port = _int_or_none(cells.get("tcp.dstport"))
    if src_port is None:
        src_port = _int_or_none(cells.get("udp.srcport"))
    if dst_port is None:
        dst_port = _int_or_none(cells.get("udp.dstport"))

    return Frame(
        protocol="",  # attributed by the caller
        number=number,
        time=_float_or_none(cells.get("frame.time_epoch")),
        length=_int_or_none(cells.get("frame.len")) or 0,
        stream=stream,
        transport=transport,
        src_ip=cells.get("ip.src") or cells.get("ipv6.src") or None,
        src_port=src_port,
        dst_ip=cells.get("ip.dst") or cells.get("ipv6.dst") or None,
        dst_port=dst_port,
        values={
            name: _parts_of(cells.get(name))
            for name in names
            if name not in _FRAMING_NAMES
        },
        tokens=tokens,
    )


def _protocol_from_tokens(tokens: Sequence[str], spec: FamilySpec) -> str | None:
    """The family protocol this frame carries, from the innermost dissector out."""
    for token in reversed(tuple(tokens)):
        protocol = spec.tokens.get(token)
        if protocol is not None:
            return protocol
    return None


def collect_frames(capture_path: Path, spec: FamilySpec, ctx: JobContext) -> list[Frame]:
    """Stream one family's frames, in capture order."""
    names = [*FRAMING_FIELDS, *spec.fields]
    frames: list[Frame] = []
    scanned = 0
    for row in tshark.stream_fields(
        capture_path,
        names,
        display_filter=spec.display_filter,
        occurrence="a",
        aggregator=AGGREGATOR,
        separator=FIELD_SEPARATOR,
        cancel_event=ctx.cancel_event,
    ):
        scanned += 1
        try:
            frame = _build_frame(row, names)
        except Exception as exc:  # a malformed row must never abort the analysis
            log.debug("skipping malformed %s row: %s", spec.name, exc)
            frame = None
        if frame is not None:
            frames.append(frame)
        if scanned % CANCEL_EVERY == 0:
            ctx.check_cancelled()
            ctx.set_stage(f"Analyzing {spec.name} sessions ({scanned:,} frames)")
    return frames


# --------------------------------------------------------------------------
# sessions
# --------------------------------------------------------------------------

@dataclass(frozen=True)
class Endpoint:
    ip: str | None
    port: int | None

    def key(self) -> tuple[str, int]:
        return (self.ip or "", self.port or 0)

    def label(self) -> str:
        if self.ip is None:
            return "unknown"
        return f"{self.ip}:{self.port}" if self.port is not None else self.ip


@dataclass
class Facts:
    """Measurements a row's flags rest on. Never stored in ``detail``."""

    commands: int = 0
    username: str | None = None
    password: bool = False
    auth_failures: int = 0
    tls_upgrade: bool = False
    anonymous: bool = False
    legacy_dialect: bool = False
    signing_required: bool | None = None
    notes: list[str] = field(default_factory=list)


@dataclass
class Session:
    protocol: str
    stream_id: int | None = None
    transport: str | None = None
    client: Endpoint = Endpoint(None, None)
    server: Endpoint = Endpoint(None, None)
    first_frame: int | None = None
    last_frame: int | None = None
    start_time: float | None = None
    end_time: float | None = None
    duration: float | None = None
    packets: int = 0
    bytes: int = 0
    client_packets: int = 0
    client_bytes: int = 0
    server_packets: int = 0
    server_bytes: int = 0
    detail: dict = field(default_factory=dict)
    flags: list[str] = field(default_factory=list)
    note: str | None = None
    facts: Facts = field(default_factory=Facts)
    frames: list[Frame] = field(default_factory=list)

    @property
    def family(self) -> str:
        return PROTOCOL_FAMILY.get(self.protocol, "")

    @property
    def server_port(self) -> int | None:
        """The port the service ran on - the row's ``server_port`` column."""
        return self.server.port

    @property
    def client_port(self) -> int | None:
        return self.client.port


COLUMNS: tuple[str, ...] = (
    "analysis_id",
    "protocol",
    "stream_id",
    "transport",
    "client_ip",
    "client_port",
    "server_ip",
    "server_port",
    "first_frame",
    "last_frame",
    "start_time",
    "end_time",
    "duration",
    "packets",
    "bytes",
    "client_packets",
    "client_bytes",
    "server_packets",
    "server_bytes",
    "detail",
    "flags",
    "note",
    "created_at",
)

INSERT_SQL = (
    f"INSERT INTO protocol_sessions ({', '.join(COLUMNS)}) "
    f"VALUES ({', '.join('?' for _ in COLUMNS)})"
)


def to_sql_row(analysis_id: str, session: Session, now: float | None = None) -> tuple:
    return (
        analysis_id,
        session.protocol,
        session.stream_id,
        session.transport,
        session.client.ip,
        session.client.port,
        session.server.ip,
        session.server.port,
        session.first_frame,
        session.last_frame,
        session.start_time,
        session.end_time,
        session.duration,
        session.packets,
        session.bytes,
        session.client_packets,
        session.client_bytes,
        session.server_packets,
        session.server_bytes,
        json.dumps(session.detail, separators=(",", ":")),
        json.dumps(session.flags, separators=(",", ":")),
        session.note,
        time.time() if now is None else now,
    )


def build_sessions(
    frames: list[Frame],
    spec: FamilySpec,
    *,
    sip_roles: Sequence[tuple[Endpoint, Endpoint, str]] | None = None,
) -> tuple[list[Session], dict]:
    """Group one family's frames into sessions and fill every shared column.

    ``sip_roles`` carries the roles of the SIP sessions already settled in this same
    pass, so an RTP/RTCP row can inherit them (§1.2 rule 1).
    """
    attributed: dict[tuple[str | None, int | None], str] = {}
    for frame in frames:
        protocol = _protocol_from_tokens(frame.tokens, spec)
        if protocol is None:
            continue
        frame.protocol = protocol
        key = (frame.transport, frame.stream)
        if frame.stream is not None:
            attributed.setdefault(key, protocol)

    groups: OrderedDict[tuple, list[Frame]] = OrderedDict()
    unattributed = 0
    for frame in frames:
        protocol = frame.protocol or attributed.get((frame.transport, frame.stream))
        if protocol is None:
            unattributed += 1
            continue
        frame.protocol = protocol
        if frame.stream is not None:
            key: tuple = (protocol, "stream", frame.stream)
        else:
            # §1.2's fallback identity: the two endpoints, order-independent, because
            # the roles are not known until the group is complete.
            endpoints = tuple(
                sorted({frame.src.label(), frame.dst.label()})
            )
            key = (protocol, "endpoints", endpoints)
        groups.setdefault(key, []).append(frame)

    sessions: list[Session] = []
    for (protocol, _, _), group in groups.items():
        group.sort(key=lambda item: item.number)
        session = Session(protocol=protocol)
        session.frames = group
        session.stream_id = group[0].stream if group[0].stream is not None else None
        session.transport = next((f.transport for f in group if f.transport), None)
        _fill_summary(session, group)
        _assign_roles(session, group, sip_roles or ())
        session.detail, session.facts = _detail_for(session, group)
        if session.facts.notes:
            session.note = "; ".join([session.note or "", *session.facts.notes]).strip("; ")
        sessions.append(session)

    sessions.sort(key=lambda item: (item.start_time or 0.0, item.protocol, item.stream_id or 0))
    stats = {
        "frames": len(frames),
        "frames_unattributed": unattributed,
        "sessions": len(sessions),
    }
    return sessions, stats


def _fill_summary(session: Session, group: list[Frame]) -> None:
    session.first_frame = group[0].number
    session.last_frame = group[-1].number
    times = [frame.time for frame in group if frame.time is not None]
    session.start_time = min(times) if times else None
    session.end_time = max(times) if times else None
    if session.start_time is not None and session.end_time is not None:
        session.duration = round(session.end_time - session.start_time, 6)
    session.packets = len(group)
    session.bytes = sum(frame.length for frame in group)


def _endpoint_counts(group: Iterable[Frame]) -> OrderedDict[Endpoint, int]:
    counts: OrderedDict[Endpoint, int] = OrderedDict()
    for frame in group:
        for endpoint in (frame.src, frame.dst):
            if endpoint.ip is None:
                continue
            counts[endpoint] = counts.get(endpoint, 0) + 1
    return counts


def _counterpart(counts: OrderedDict[Endpoint, int], endpoint: Endpoint) -> Endpoint | None:
    """The busiest endpoint on the other side of ``endpoint``."""
    candidates = [
        (count, other)
        for other, count in counts.items()
        if other != endpoint and other.ip != endpoint.ip
    ]
    if not candidates:
        return None
    candidates.sort(key=lambda item: (-item[0], item[1].key()))
    return candidates[0][1]


def _greeting(protocol: str, frame: Frame) -> str | None:
    """The server-role message §1.2 rule 2 names for this protocol."""
    if protocol == "smtp" and "220" in frame.parts("smtp.response.code"):
        return "the 220 banner"
    if protocol == "ftp" and "220" in frame.parts("ftp.response.code"):
        return "the 220 banner"
    if protocol == "pop3":
        if any(part.upper().startswith("+OK") for part in frame.parts("pop.response.indicator")):
            return "the +OK greeting"
    if protocol == "imap":
        statuses = {part.upper() for part in frame.parts("imap.response.status")}
        tag = frame.value("imap.tag")
        if "OK" in statuses and (tag is None or tag.strip() in {"*", ""}):
            return "the * OK greeting"
    # No SSH case: both endpoints send an identification string and the client sends its
    # own first, so "the first SSH-2.0-... string" would name the client as the server. Off
    # §1.2's port table an SSH session therefore falls to rule 3, whose answer - the sender
    # of the session's first frame, i.e. the connecting side - is the client. `detail`
    # still records both banners, chosen by the settled roles.
    if protocol == "sip" and frame.has("sip.Status-Code"):
        return "the SIP status line"
    return None


def _assign_roles(
    session: Session,
    group: list[Frame],
    sip_roles: Sequence[tuple[Endpoint, Endpoint, str]] = (),
) -> None:
    """§1.2 in order, with the rule that applied recorded in ``note``."""
    protocol = session.protocol
    counts = _endpoint_counts(group)
    notes: list[str] = []

    # RTP/RTCP: no registered port, so they inherit the SIP session's roles.
    if protocol in {"rtp", "rtcp"} and sip_roles:
        adopted = _adopt_sip_roles(counts, sip_roles)
        if adopted is not None:
            client, server, label = adopted
            session.client, session.server = client, server
            session.note = (
                f"roles taken from the SIP session {label} that carried this media "
                "(RTP/RTCP have no registered port)"
            )
            _apply_volumes(session, group)
            return

    ports = SERVER_PORTS.get(protocol)
    if ports:
        servers = [endpoint for endpoint in counts if endpoint.port in ports]
        if len(servers) == 1:
            server = servers[0]
            client = _counterpart(counts, server)
            session.client = client or Endpoint(None, None)
            session.server = server
            notes.append(f"server on the well-known port {server.port} (rule 1)")
            if client is None:
                notes.append("the peer was not captured, so the client is unknown")
            session.note = "; ".join(notes)
            _apply_volumes(session, group)
            return

    for frame in group:
        greeting = _greeting(protocol, frame)
        if greeting is not None:
            server = frame.src
            client = _counterpart(counts, server)
            session.client = client or Endpoint(None, None)
            session.server = server
            notes.append(f"server is the sender of {greeting} (rule 2)")
            if client is None:
                notes.append("the peer was not captured, so the client is unknown")
            session.note = "; ".join(notes)
            _apply_volumes(session, group)
            return

    first = group[0]
    client = first.src
    server = _counterpart(counts, client)
    session.client = client
    session.server = server or Endpoint(None, None)
    notes.append(
        "client is the sender of the session's first frame "
        "(rule 3: no registered port and no server-role message seen)"
    )
    if server is None:
        notes.append("the peer was not captured, so the server is unknown")
    session.note = "; ".join(notes)
    _apply_volumes(session, group)


def _apply_volumes(session: Session, group: list[Frame]) -> None:
    client, server = session.client, session.server
    for frame in group:
        side = _side(frame, client, server)
        if side == "client":
            session.client_packets += 1
            session.client_bytes += frame.length
        elif side == "server":
            session.server_packets += 1
            session.server_bytes += frame.length


def _side(frame: Frame, client: Endpoint, server: Endpoint) -> str | None:
    if client.ip is not None and frame.src_ip == client.ip and (
        client.port is None or frame.src_port == client.port
    ):
        return "client"
    if server.ip is not None and frame.src_ip == server.ip and (
        server.port is None or frame.src_port == server.port
    ):
        return "server"
    return None


def sip_role_index(sessions: Sequence[Session]) -> list[tuple[Endpoint, Endpoint, str]]:
    """The settled roles of the SIP rows in a pass, for RTP/RTCP to inherit."""
    index: list[tuple[Endpoint, Endpoint, str]] = []
    for session in sessions:
        if session.protocol != "sip":
            continue
        if session.client.ip is None or session.server.ip is None:
            continue
        index.append(
            (
                session.client,
                session.server,
                f"{session.client.label()} - {session.server.label()}",
            )
        )
    return index


def _adopt_sip_roles(
    counts: OrderedDict[Endpoint, int], sip: list[tuple[Endpoint, Endpoint, str]]
) -> tuple[Endpoint, Endpoint, str] | None:
    for sip_client, sip_server, label in sip:
        client = _endpoint_with_ip(counts, sip_client.ip)
        server = _endpoint_with_ip(counts, sip_server.ip)
        if client is not None and server is not None and client != server:
            return client, server, label
    return None


def _endpoint_with_ip(counts: OrderedDict[Endpoint, int], ip: str | None) -> Endpoint | None:
    if ip is None:
        return None
    matches = [endpoint for endpoint in counts if endpoint.ip == ip]
    if not matches:
        return None
    matches.sort(key=lambda endpoint: (-counts[endpoint], endpoint.key()))
    return matches[0]


# --------------------------------------------------------------------------
# ``detail``: only what the dissector produced
# --------------------------------------------------------------------------

def _dedupe(values: Iterable[str]) -> list[str]:
    seen: OrderedDict[str, None] = OrderedDict()
    for value in values:
        text = value.strip()
        if text and text not in seen:
            seen[text] = None
    return list(seen)


def _put_list(detail: dict, key: str, values: Iterable[str]) -> None:
    unique = _dedupe(values)
    if not unique:
        return
    if len(unique) > LIST_CAP:
        detail[key] = unique[:LIST_CAP]
        detail[f"{key}_truncated"] = True
    else:
        detail[key] = unique


def _put_counts(detail: dict, key: str, values: Iterable[str]) -> dict[str, int]:
    counts: OrderedDict[str, int] = OrderedDict()
    for value in values:
        text = value.strip()
        if not text:
            continue
        counts[text] = counts.get(text, 0) + 1
    if not counts:
        return {}
    if len(counts) > COUNT_CAP:
        detail[key] = dict(list(counts.items())[:COUNT_CAP])
        detail[f"{key}_truncated"] = True
    else:
        detail[key] = dict(counts)
    return dict(counts)


def _all_values(frames: Iterable[Frame], key: str) -> Iterator[str]:
    for frame in frames:
        yield from frame.parts(key)


def _first_value(frames: Iterable[Frame], key: str) -> str | None:
    for frame in frames:
        value = frame.value(key)
        if value:
            return value
    return None


def _command_pairs(
    frames: Iterable[Frame],
    key: str,
    arg_key: str | None,
    *,
    redact: frozenset[str] = frozenset(),
    mechanism_only: frozenset[str] = frozenset(),
) -> list[tuple[str, str | None]]:
    """Every command occurrence as ``(VERB, arg)``, in wire order.

    Upper-casing the verb is the only normalisation: the dissector prints EHLO and
    mail/rcpt for the same command in different messages, and §3.1 lists the verbs in
    upper case.

    Two argument kinds are deliberately not copied, because §1.3 forbids credential
    values: ``redact`` names the verbs whose argument *is* a password (POP3/FTP
    ``PASS``) and ``mechanism_only`` names verbs whose argument carries encoded
    credentials (SMTP ``AUTH``, which keeps the mechanism name alone).
    """
    pairs: list[tuple[str, str | None]] = []
    for frame in frames:
        verbs = frame.parts(key)
        if not verbs:
            continue
        args = frame.parts(arg_key) if arg_key else ()
        for index, verb in enumerate(verbs):
            text = verb.strip().upper()
            if not text:
                continue
            arg = args[index] if index < len(args) else (args[0] if len(args) == 1 else None)
            arg = arg.strip() if arg else None
            if text in redact:
                arg = None
            elif text in mechanism_only and arg:
                arg = arg.split()[0].upper()
            pairs.append((text, arg))
    return pairs


def _put_commands(detail: dict, pairs: Sequence[tuple[str, str | None]]) -> None:
    """``[{verb, arg, count}]``, deduplicated on (verb, arg) and capped."""
    counts: OrderedDict[tuple[str, str | None], int] = OrderedDict()
    for verb, arg in pairs:
        counts[(verb, arg)] = counts.get((verb, arg), 0) + 1
    entries: list[dict] = []
    for (verb, arg), count in counts.items():
        entry: dict = {"verb": verb}
        if arg:
            entry["arg"] = arg
        entry["count"] = count
        entries.append(entry)
    if not entries:
        return
    if len(entries) > COMMAND_CAP:
        detail["commands"] = entries[:COMMAND_CAP]
        detail["commands_truncated"] = True
    else:
        detail["commands"] = entries


def _put_verbs(detail: dict, pairs: Sequence[tuple[str, str | None]]) -> None:
    """``[{verb, count}]``: IMAP commands carry no argument of their own."""
    counts: OrderedDict[str, int] = OrderedDict()
    for verb, _ in pairs:
        counts[verb] = counts.get(verb, 0) + 1
    entries = [{"verb": verb, "count": count} for verb, count in counts.items()]
    if not entries:
        return
    if len(entries) > COMMAND_CAP:
        detail["commands"] = entries[:COMMAND_CAP]
        detail["commands_truncated"] = True
    else:
        detail["commands"] = entries


def _address(arg: str | None, prefix: str) -> str | None:
    """``FROM:<a@b>`` -> ``a@b``. The argument is the dissector's, only unwrapped."""
    if not arg:
        return None
    text = arg.strip()
    head = f"{prefix}:"
    if text.upper().startswith(head):
        text = text[len(head) :].strip()
    text = text.strip("<>").strip()
    return text or None


def _maybe_base64(value: str | None) -> tuple[str | None, bool]:
    """Decode a base64 AUTH value when it decodes cleanly; report what happened."""
    if not value:
        return None, False
    text = value.strip()
    if len(text) < 8 or len(text) % 4 or not _B64_RE.match(text):
        return text, False
    try:
        raw = base64.b64decode(text, validate=True)
    except Exception:  # noqa: BLE001 - not base64 after all
        return text, False
    try:
        decoded = raw.decode("utf-8")
    except UnicodeDecodeError:
        return text, False
    printable = sum(1 for char in decoded if char.isprintable() or char == "\x00")
    if not decoded or printable < len(decoded):
        return text, False
    return decoded, True


def _detail_for(session: Session, group: list[Frame]) -> tuple[dict, Facts]:
    protocol = session.protocol
    if protocol == "smtp":
        return _smtp_detail(group)
    if protocol == "pop3":
        return _pop3_detail(group)
    if protocol == "imap":
        return _imap_detail(group)
    if protocol == "ssh":
        return _ssh_detail(group, session)
    if protocol == "ftp":
        return _ftp_detail(group)
    if protocol == "sip":
        return _sip_detail(group)
    if protocol in {"rtp", "rtcp"}:
        return _rtp_detail(protocol, group)
    if protocol == "smb":
        return _smb_detail(group)
    return {}, Facts()  # pragma: no cover - every protocol above is handled


def _smtp_detail(group: list[Frame]) -> tuple[dict, Facts]:
    detail: dict = {}
    facts = Facts()
    pairs = _command_pairs(
        group, "smtp.req.command", "smtp.req.parameter", mechanism_only=frozenset({"AUTH"})
    )
    facts.commands = len(pairs)
    _put_commands(detail, pairs)
    codes = _put_counts(detail, "response_codes", _all_values(group, "smtp.response.code"))

    helo = next((arg for verb, arg in pairs if verb in {"EHLO", "HELO"} and arg), None)
    if helo:
        detail["helo"] = helo
    _put_list(detail, "mail_from", (_address(arg, "FROM") or "" for verb, arg in pairs if verb == "MAIL"))
    _put_list(detail, "rcpt_to", (_address(arg, "TO") or "" for verb, arg in pairs if verb == "RCPT"))

    mechanisms: list[str] = []
    for verb, arg in pairs:
        if verb == "AUTH" and arg:
            mechanisms.append(arg.split()[0].upper())
    for part in _all_values(group, "smtp.rsp.parameter"):
        for line in part.splitlines() or [part]:
            text = line.strip()
            upper = text.upper()
            if upper.startswith("AUTH "):
                mechanisms.extend(token.upper() for token in text.split()[1:])
    _put_list(detail, "auth_mechanisms", mechanisms)

    username, decoded = _maybe_base64(_first_value(group, "smtp.auth.username"))
    password = bool(_first_value(group, "smtp.auth.password"))
    if username and "\x00" in username:
        # AUTH PLAIN: base64 of "\0user\0password".
        chunks = username.split("\x00")
        if len(chunks) > 1 and chunks[1]:
            username = chunks[1]
        if len(chunks) > 2 and chunks[2]:
            password = True
    if username:
        detail["auth_username"] = username
        facts.username = username
    if password:
        detail["password_present"] = True
        facts.password = True
    if decoded:
        facts.notes.append("the SMTP AUTH identity was base64 on the wire and is recorded decoded")

    data_blocks = sum(1 for frame in group if frame.has("smtp.eom"))
    if data_blocks:
        detail["data_blocks"] = data_blocks

    facts.auth_failures = sum(count for code, count in codes.items() if code in AUTH_FAILURE_CODES["smtp"])
    facts.tls_upgrade = any(verb == "STARTTLS" for verb, _ in pairs)
    return detail, facts


def _pop3_detail(group: list[Frame]) -> tuple[dict, Facts]:
    detail: dict = {}
    facts = Facts()
    pairs = _command_pairs(
        group, "pop.request.command", "pop.request.parameter", redact=frozenset({"PASS"})
    )
    facts.commands = len(pairs)
    _put_commands(detail, pairs)
    indicators = _put_counts(
        detail,
        "response_indicators",
        (part.upper() for part in _all_values(group, "pop.response.indicator")),
    )

    username = next((arg for verb, arg in pairs if verb == "USER" and arg), None)
    if username:
        detail["username"] = username
        facts.username = username
    if any(verb == "PASS" for verb, _ in pairs):
        detail["password_present"] = True
        facts.password = True

    retrieved = sum(1 for verb, _ in pairs if verb == "RETR")
    if retrieved:
        detail["retrieved"] = retrieved
    deleted = sum(1 for verb, _ in pairs if verb == "DELE")
    if deleted:
        detail["deleted"] = deleted

    # STAT / LIST report the mailbox size; the response description is where the
    # dissector puts it, and only a bare LIST (no argument) reports a count.
    message_count = None
    pending: tuple[str, str | None] | None = None
    for frame in group:
        command = frame.value("pop.request.command")
        if command:
            pending = (command.strip().upper(), frame.value("pop.request.parameter"))
            continue
        description = frame.value("pop.response.description")
        if not description or pending is None:
            continue
        verb, arg = pending
        if verb == "STAT" or (verb == "LIST" and not arg):
            match = re.search(r"\d+", description)
            if match:
                message_count = int(match.group(0))
                break
    if message_count is not None:
        detail["message_count"] = message_count

    facts.auth_failures = indicators.get("-ERR", 0)
    facts.tls_upgrade = any(verb == "STLS" for verb, _ in pairs)
    return detail, facts


def _imap_detail(group: list[Frame]) -> tuple[dict, Facts]:
    detail: dict = {}
    facts = Facts()
    pairs = _command_pairs(group, "imap.request.command", None)
    facts.commands = len(pairs)
    _put_verbs(detail, pairs)
    statuses = _put_counts(
        detail,
        "statuses",
        (part.upper() for part in _all_values(group, "imap.response.status")),
    )

    username = _first_value(group, "imap.request.username")
    if username:
        detail["username"] = username
        facts.username = username
    if _first_value(group, "imap.request.password"):
        detail["password_present"] = True
        facts.password = True
    _put_list(
        detail,
        "folders",
        (_unquote(value) for value in _all_values(group, "imap.request.folder")),
    )

    uid_commands = sum(
        1
        for frame in group
        for verb in frame.parts("imap.request.command")
        if verb.strip().upper() == "UID" and frame.flags_true("imap.request.command.uid")
    )
    fetches = (
        sum(
            1
            for frame in group
            for verb in frame.parts("imap.request.command")
            if verb.strip().upper() == "FETCH"
        )
        + uid_commands
    )
    if fetches:
        detail["fetches"] = fetches

    facts.auth_failures = statuses.get("NO", 0)
    facts.tls_upgrade = any(verb == "STARTTLS" for verb, _ in pairs)
    return detail, facts


def _unquote(value: str) -> str:
    """A mailbox name is the content of the quoted string the dissector printed."""
    text = value.strip()
    if len(text) > 1 and text.startswith('"') and text.endswith('"'):
        return text[1:-1]
    return text


def _split_algorithms(value: str | None) -> list[str]:
    if not value:
        return []
    return [part.strip() for part in value.split(",") if part.strip()]


def _ssh_detail(group: list[Frame], session: Session) -> tuple[dict, Facts]:
    detail: dict = {}
    facts = Facts()

    client_banner = _first_value(
        (frame for frame in group if _side(frame, session.client, session.server) != "server"),
        "ssh.protocol",
    )
    server_banner = _first_value(
        (frame for frame in group if _side(frame, session.client, session.server) == "server"),
        "ssh.protocol",
    )
    if client_banner is None and server_banner is None:
        # No direction to go on: the first identification string is the client's.
        banners = _dedupe(_all_values(group, "ssh.protocol"))
        client_banner = banners[0] if banners else None
        server_banner = banners[1] if len(banners) > 1 else None
    if client_banner:
        detail["client_banner"] = client_banner
    if server_banner:
        detail["server_banner"] = server_banner

    for key, field_name in (
        ("kex_algorithms", "ssh.kex_algorithms"),
        ("server_host_key_algorithms", "ssh.server_host_key_algorithms"),
        ("encryption_client_to_server", "ssh.encryption_algorithms_client_to_server"),
        ("encryption_server_to_client", "ssh.encryption_algorithms_server_to_client"),
        ("mac_client_to_server", "ssh.mac_algorithms_client_to_server"),
    ):
        _put_list(detail, key, _split_algorithms(_first_value(group, field_name)))

    _put_counts(detail, "messages", _all_values(group, "ssh.message_code"))
    return detail, facts


def _ftp_detail(group: list[Frame]) -> tuple[dict, Facts]:
    detail: dict = {}
    facts = Facts()
    pairs = _command_pairs(
        group, "ftp.request.command", "ftp.request.arg", redact=frozenset({"PASS"})
    )
    facts.commands = len(pairs)
    _put_commands(detail, pairs)
    codes = _put_counts(detail, "response_codes", _all_values(group, "ftp.response.code"))

    username = next((arg for verb, arg in pairs if verb == "USER" and arg), None)
    if username:
        detail["username"] = username
        facts.username = username
    if any(verb == "PASS" for verb, _ in pairs):
        detail["password_present"] = True
        facts.password = True

    paths = [arg for verb, arg in pairs if verb in {"CWD", "XCWD"} and arg]
    paths.extend(_all_values(group, "ftp.current-working-directory"))
    _put_list(detail, "paths", paths)

    _put_list(
        detail,
        "files_requested",
        (arg for verb, arg in pairs if verb in {"RETR", "STOR", "APPE", "DELE", "STOU"} and arg),
    )

    # A data connection is announced by the dissector publishing one of these
    # endpoints: PASV/EPSV responses, EPRT/PORT requests and their replies.
    data_setups = sum(
        1
        for frame in group
        if any(
            frame.has(key)
            for key in (
                "ftp.passive.port",
                "ftp.epsv.port",
                "ftp.eprt.port",
                "ftp.active.port",
                "ftp.active.cip",
            )
        )
    )
    if data_setups:
        detail["data_streams"] = data_setups

    if username and username.strip().lower() in ANONYMOUS_IDENTITIES:
        facts.anonymous = True
    facts.auth_failures = sum(count for code, count in codes.items() if code in AUTH_FAILURE_CODES["ftp"])
    facts.tls_upgrade = any(
        verb == "AUTH" and (arg or "").strip().upper() in {"TLS", "SSL", "TLS-C", "TLS-P"}
        for verb, arg in pairs
    )
    return detail, facts


def _sip_detail(group: list[Frame]) -> tuple[dict, Facts]:
    detail: dict = {}
    facts = Facts()
    _put_counts(detail, "methods", (part.upper() for part in _all_values(group, "sip.Method")))
    _put_counts(detail, "status_codes", _all_values(group, "sip.Status-Code"))
    _put_list(detail, "call_ids", _all_values(group, "sip.Call-ID"))
    _put_list(detail, "from_users", _all_values(group, "sip.from.user"))
    _put_list(detail, "to_users", _all_values(group, "sip.to.user"))

    uris: list[str] = []
    for frame in group:
        user = frame.value("sip.r-uri.user")
        host = frame.value("sip.r-uri.host")
        if user and host:
            uris.append(f"{user}@{host}")
        elif host:
            uris.append(host)
        elif user:
            uris.append(user)
    _put_list(detail, "request_uris", uris)
    _put_list(detail, "user_agents", _all_values(group, "sip.User-Agent"))
    return detail, facts


def _rtp_detail(protocol: str, group: list[Frame]) -> tuple[dict, Facts]:
    detail: dict = {}
    facts = Facts()
    if protocol == "rtp":
        ssrc = _first_value(group, "rtp.ssrc")
        if ssrc:
            detail["ssrc"] = ssrc
        _put_counts(detail, "payload_types", _all_values(group, "rtp.p_type"))
        sequences = [
            number
            for number in (_int_or_none(part) for part in _all_values(group, "rtp.seq"))
            if number is not None
        ]
        if len(sequences) > 1:
            # Gaps between consecutive sequence numbers of this stream, modulo the
            # 16-bit space. A backward jump is treated as a reordered or duplicated
            # packet and ignored rather than counted as 65 000 lost packets, and the
            # result is only what this capture shows - not jitter, and not the
            # sender's own loss counter.
            lost = 0
            for previous, current in zip(sequences, sequences[1:]):
                gap = (current - previous) % 65536
                if 1 < gap < 32768:
                    lost += gap - 1
            detail["packets_lost"] = lost
    else:
        ssrc = _first_value(group, "rtcp.senderssrc") or _first_value(group, "rtcp.ssrc.identifier")
        if ssrc:
            detail["ssrc"] = ssrc
        _put_counts(detail, "rtcp_packet_types", _all_values(group, "rtcp.pt"))
    return detail, facts


def _smb_command_name(frame: Frame) -> str | None:
    value = frame.value("smb2.cmd")
    if value is not None:
        number = _int_or_none(value)
        if number is not None and number in SMB2_COMMANDS:
            return SMB2_COMMANDS[number]
        return value
    value = frame.value("smb.cmd")
    if value is not None:
        number = _int_or_none(value)
        if number is not None and number in SMB1_COMMANDS:
            return SMB1_COMMANDS[number]
        return value
    return None


def _smb_detail(group: list[Frame]) -> tuple[dict, Facts]:
    detail: dict = {}
    facts = Facts()

    commands: OrderedDict[str, int] = OrderedDict()
    for frame in group:
        name = _smb_command_name(frame)
        if name:
            commands[name] = commands.get(name, 0) + 1
    if commands:
        if len(commands) > COMMAND_CAP:
            detail["commands"] = dict(list(commands.items())[:COMMAND_CAP])
            detail["commands_truncated"] = True
        else:
            detail["commands"] = dict(commands)

    def is_response(frame: Frame) -> bool:
        return frame.flags_true("smb2.flags.response") or frame.flags_true("smb.flags.response")

    smb2_frames = [frame for frame in group if frame.has("smb2.cmd") or frame.has("smb2.dialect")]
    response_dialects: list[str] = []
    for frame in group:
        if not is_response(frame):
            continue
        for raw in frame.parts("smb2.dialect"):
            number = _int_or_none(raw)
            if number in SMB_DIALECTS:
                response_dialects.append(SMB_DIALECTS[number])
            elif raw:
                response_dialects.append(raw)
    if response_dialects:
        _put_list(detail, "dialects", response_dialects)
    elif group and not smb2_frames:
        # No SMB2 frame anywhere in the stream: this session is SMB1, which §3.8
        # records as "SMB 1". The flag needs an actual negotiation: the SMB dissector
        # also claims the odd NetBIOS datagram, and a lone command is not a dialect.
        detail["dialects"] = [SMB1_DIALECT]
        facts.legacy_dialect = "NEGOTIATE" in commands

    _put_list(detail, "trees", _all_values(group, "smb2.tree"))
    _put_list(detail, "filenames", _all_values(group, "smb2.filename"))

    statuses: OrderedDict[str, int] = OrderedDict()
    for raw in (*_all_values(group, "smb2.nt_status"), *_all_values(group, "smb.nt_status")):
        number = _int_or_none(raw)
        name = NT_STATUS.get(number) if number is not None else None
        key = name or raw
        statuses[key] = statuses.get(key, 0) + 1
    if statuses:
        if len(statuses) > COUNT_CAP:
            detail["statuses"] = dict(list(statuses.items())[:COUNT_CAP])
            detail["statuses_truncated"] = True
        else:
            detail["statuses"] = dict(statuses)

    def negotiate_frames(frame: Frame) -> bool:
        return is_response(frame) and _smb_command_name(frame) == "NEGOTIATE"

    sign_values = [
        frame.flags_true("smb2.sec_mode.sign_required")
        for frame in group
        if negotiate_frames(frame) and frame.has("smb2.sec_mode.sign_required")
    ]
    if not sign_values:
        sign_values = [
            frame.flags_true("smb.flags2.sec_sig_required")
            for frame in group
            if is_response(frame) and frame.has("smb.flags2.sec_sig_required")
        ]
    if sign_values:
        facts.signing_required = any(sign_values)
        detail["signing_required"] = facts.signing_required

    encryption = [
        frame.flags_true("smb2.capabilities.encryption")
        for frame in group
        if negotiate_frames(frame) and frame.has("smb2.capabilities.encryption")
    ]
    if encryption:
        detail["encryption_capable"] = any(encryption)

    server = _first_value(group, "smb2.host")
    if server:
        detail["server"] = server

    account = (_first_value(group, "smb2.acct") or "").strip()
    guest = any(frame.flags_true("smb2.ses_flags.guest") for frame in group)
    null_session = any(frame.flags_true("smb2.ses_flags.null") for frame in group)
    if guest or null_session or account.lower() in ANONYMOUS_IDENTITIES:
        facts.anonymous = True
    return detail, facts


# --------------------------------------------------------------------------
# flags (§4)
# --------------------------------------------------------------------------

def compute_flags(
    session: Session,
    sip_sessions: Sequence[Session] = (),
) -> list[str]:
    """Investigative leads, most serious first, capped at :data:`FLAG_CAP`."""
    found: dict[str, str] = {}
    facts = session.facts
    protocol = session.protocol

    if protocol in CLEARTEXT_PROTOCOLS:
        if facts.password:
            found["cleartext_credentials"] = (
                f"a password for {facts.username} crossed the wire in the clear"
                if facts.username
                else "a password crossed the wire in the clear"
            )
        elif facts.username:
            found["cleartext_username"] = f"{facts.username} was sent without a password"
        if facts.auth_failures:
            codes = "/".join(AUTH_FAILURE_CODES.get(protocol, ()))
            found["auth_failures"] = (
                f"{facts.auth_failures} rejected authentication(s) ({codes})"
            )
        # §4: only on a port whose session expects an upgrade, and the detail names the
        # port the session actually used - never a port it did not.
        if not facts.tls_upgrade and session.server_port in UPGRADE_EXPECTING_PORTS:
            found["no_encryption_upgrade"] = (
                "no STARTTLS/STLS/AUTH TLS exchange was seen "
                f"on port {session.server_port}"
            )

    if protocol in {"ftp", "smb"} and facts.anonymous:
        identity = facts.username or "an anonymous-style identity"
        found["anonymous_login"] = f"{identity} was used"

    if protocol == "smb":
        if facts.legacy_dialect:
            found["legacy_dialect"] = "SMB 1 was negotiated"
        if facts.signing_required is False:
            found["signing_not_required"] = "the negotiate response did not require signing"

    if protocol in {"rtp", "rtcp"} and not _media_is_signalled(session, sip_sessions):
        found["media_without_signalling"] = (
            "no SIP session between these addresses named this media"
        )

    ports = SERVER_PORTS.get(protocol)
    if ports and session.server.port is not None and session.server.port not in ports:
        accepted = ", ".join(str(port) for port in sorted(ports))
        found["unusual_port"] = (
            f"the server port {session.server.port} is none of this protocol's ports "
            f"({accepted})"
        )

    if session.bytes > LARGE_TRANSFER_BYTES:
        found["large_transfer"] = f"{session.bytes} bytes"
    if protocol in COMMAND_PROTOCOLS and facts.commands > MANY_COMMANDS:
        found["many_commands"] = f"{facts.commands} commands"
    if session.duration is not None and session.duration > LONG_SESSION_SECONDS:
        found["long_session"] = f"{round(session.duration)} seconds"

    flags = [f"{code}: {found[code]}" for code in FLAG_ORDER if code in found]
    return flags[:FLAG_CAP]


def _media_is_signalled(session: Session, sip_sessions: Sequence[Session]) -> bool:
    if session.client.ip is None and session.server.ip is None:
        return False
    addresses = {session.client.ip, session.server.ip}
    for sip in sip_sessions:
        if sip.protocol != "sip":
            continue
        if addresses & {sip.client.ip, sip.server.ip}:
            return True
    return False


def apply_flags(sessions: list[Session]) -> None:
    """Compute every session's flags once the family's SIP rows exist."""
    sip_sessions = [session for session in sessions if session.protocol == "sip"]
    for session in sessions:
        session.flags = compute_flags(session, sip_sessions)


# --------------------------------------------------------------------------
# persistence and entry point
# --------------------------------------------------------------------------

def analyze_family(
    capture_path: Path, spec: FamilySpec, ctx: JobContext
) -> tuple[list[Session], dict]:
    """Run one family's pass and build its rows (no database writes)."""
    frames = collect_frames(capture_path, spec, ctx)
    sessions: list[Session] = []

    # Roles are settled per group; SIP settles first so RTP/RTCP can inherit them.
    if spec.name == "voip":
        sessions, stats = _build_voip_sessions(frames, spec)
    else:
        sessions, stats = build_sessions(frames, spec)

    apply_flags(sessions)
    return sessions, stats


def _build_voip_sessions(frames: list[Frame], spec: FamilySpec) -> tuple[list[Session], dict]:
    """Build SIP first, then RTP/RTCP with the SIP roles already settled."""
    sip_frames: list[Frame] = []
    media_frames: list[Frame] = []
    rest: list[Frame] = []
    for frame in frames:
        protocol = _protocol_from_tokens(frame.tokens, spec)
        if protocol == "sip":
            sip_frames.append(frame)
        elif protocol in {"rtp", "rtcp"}:
            media_frames.append(frame)
        else:
            rest.append(frame)

    sessions: list[Session] = []
    stats = {"frames": len(frames), "frames_unattributed": 0, "sessions": 0}
    sip_roles: list[tuple[Endpoint, Endpoint, str]] = []

    if sip_frames:
        sip_sessions, sip_stats = build_sessions(sip_frames, spec)
        sip_roles = sip_role_index(sip_sessions)
        sessions.extend(sip_sessions)
        stats["frames_unattributed"] += sip_stats["frames_unattributed"]

    for subset in (media_frames, rest):
        if not subset:
            continue
        subset_sessions, subset_stats = build_sessions(subset, spec, sip_roles=sip_roles)
        sessions.extend(subset_sessions)
        stats["frames_unattributed"] += subset_stats["frames_unattributed"]

    sessions.sort(key=lambda item: (item.start_time or 0.0, item.protocol, item.stream_id or 0))
    stats["sessions"] = len(sessions)
    return sessions, stats


def analyze(ctx: JobContext, analysis_id: str, capture_path: Path) -> dict:
    """Extract and persist every protocol session in ``capture_path``.

    The rows go to ``protocol_sessions``, which is cleared for the analysis and
    rewritten, so a rescan is idempotent. The one other write is the :data:`MARKER_KIND`
    record in ``stats_cache`` that says this stage ran and what it found; it is cleared
    before the rows are rewritten so it can never outlive them.
    """
    started = time.monotonic()
    ctx.set_stage("Analysing protocol sessions")

    with db.get_conn() as conn:
        conn.execute("DELETE FROM protocol_sessions WHERE analysis_id = ?", (analysis_id,))
        conn.execute(
            "DELETE FROM stats_cache WHERE analysis_id = ? AND kind = ?",
            (analysis_id, MARKER_KIND),
        )

    sessions: list[Session] = []
    family_stats: dict[str, dict] = {}
    for spec in FAMILY_SPECS.values():
        ctx.check_cancelled()
        ctx.set_stage(f"Analysing {spec.name} protocol sessions")
        family_sessions, stats = analyze_family(capture_path, spec, ctx)
        family_stats[spec.name] = stats
        sessions.extend(family_sessions)
        log.debug("%s family produced %s session(s)", spec.name, len(family_sessions))

    ctx.check_cancelled()
    _persist(analysis_id, sessions)

    seconds = round(time.monotonic() - started, 2)
    summary = _counters(analysis_id)
    result = {
        **summary,
        "families": {
            name: {
                "sessions": stats["sessions"],
                "frames": stats["frames"],
                "frames_unattributed": stats["frames_unattributed"],
            }
            for name, stats in family_stats.items()
        },
        "seconds": seconds,
    }
    _write_marker(analysis_id, result)
    log.info("protocol analysis for %s: %s in %.1fs", analysis_id, summary, seconds)
    return result


def _write_marker(analysis_id: str, result: dict) -> None:
    """Record that this stage ran, with the counts it wrote (§5.1's ``extracted``)."""
    payload = {
        "sessions": result["protocol_sessions"],
        "flagged": result["protocol_flagged"],
        "bytes": result["protocol_bytes"],
        "by_protocol": result["protocols"],
        "families": result["families"],
        "seconds": result["seconds"],
        "extracted_at": time.time(),
    }
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


def stage_ran(analysis_id: str) -> bool:
    """True when this analysis has been through the protocol stage (§5.1)."""
    return stage_marker(analysis_id) is not None


def _persist(analysis_id: str, sessions: Sequence[Session]) -> None:
    conn: sqlite3.Connection = db.connect()
    now = time.time()
    try:
        conn.execute("BEGIN")
        buffer: list[tuple] = []
        for session in sessions:
            buffer.append(to_sql_row(analysis_id, session, now))
            if len(buffer) >= BATCH_SIZE:
                conn.executemany(INSERT_SQL, buffer)
                buffer.clear()
                conn.commit()
                conn.execute("BEGIN")
        if buffer:
            conn.executemany(INSERT_SQL, buffer)
            buffer.clear()
        conn.commit()
    finally:
        conn.close()


def _counters(analysis_id: str) -> dict:
    row = db.query_one(
        """
        SELECT COUNT(*) AS n,
               SUM(CASE WHEN flags IS NOT NULL AND flags <> '[]' THEN 1 ELSE 0 END) AS flagged,
               SUM(bytes) AS bytes
          FROM protocol_sessions
         WHERE analysis_id = ?
        """,
        (analysis_id,),
    )
    data = dict(row) if row else {}
    protocols = {
        item["protocol"]: int(item["n"])
        for item in db.query_all(
            """
            SELECT protocol, COUNT(*) AS n
              FROM protocol_sessions
             WHERE analysis_id = ?
             GROUP BY protocol
             ORDER BY protocol ASC
            """,
            (analysis_id,),
        )
    }
    return {
        "protocol_sessions": int(data.get("n") or 0),
        "protocol_flagged": int(data.get("flagged") or 0),
        "protocol_bytes": int(data.get("bytes") or 0),
        "protocols": protocols,
    }


__all__ = [
    "AGGREGATOR",
    "COLUMNS",
    "COMMAND_CAP",
    "COUNT_CAP",
    "FAMILIES",
    "FAMILY_SPECS",
    "FIELD_SEPARATOR",
    "FLAG_CAP",
    "FLAG_ORDER",
    "LARGE_TRANSFER_BYTES",
    "LIST_CAP",
    "LONG_SESSION_SECONDS",
    "MANY_COMMANDS",
    "MARKER_KIND",
    "PAGE_BY_FAMILY",
    "PROTOCOLS",
    "PROTOCOL_FAMILY",
    "SERVER_PORTS",
    "SESSION_CAP",
    "UPGRADE_EXPECTING_PORTS",
    "Endpoint",
    "Facts",
    "Frame",
    "Session",
    "analyze",
    "analyze_family",
    "apply_flags",
    "build_sessions",
    "collect_frames",
    "compute_flags",
    "sip_role_index",
    "stage_marker",
    "stage_ran",
    "to_sql_row",
]
