"""Controlled TShark process execution.

All packet dissection is delegated to TShark. This module is the only place in
the application that spawns a subprocess, and it does so with:

* ``shell=False`` and an explicit argument vector (never a command string),
* a hard wall-clock timeout,
* cooperative cancellation,
* no name resolution (``-n``) so analysis never touches the network.

Nothing here ever loads a whole capture into memory: callers consume
:func:`stream_fields` row by row.
"""

from __future__ import annotations

import os
import re
import shutil
import struct
import subprocess
import threading
import time
from collections.abc import Iterator, Sequence
from dataclasses import dataclass, field
from pathlib import Path

from app.core.config import REPO_ROOT, settings
from app.core.logging import get_logger

log = get_logger("shadowpackets.tshark")

# Windows: do not flash a console window for every dissection run.
_CREATE_NO_WINDOW = 0x08000000
_FLAGS = _CREATE_NO_WINDOW if os.name == "nt" else 0

# Directories searched when the binary is not on PATH.
_WINDOWS_HINTS = [
    Path(r"C:\Program Files\Wireshark"),
    Path(r"C:\Program Files (x86)\Wireshark"),
]

_binary_cache: dict[str, str | None] = {}
_canary_lock = threading.Lock()


class TsharkError(RuntimeError):
    """Raised when TShark exits with a code the caller did not allow."""

    def __init__(self, message: str, result: TsharkResult | None = None) -> None:
        super().__init__(message)
        self.result = result


class TsharkTimeout(TsharkError):
    """Raised when a dissection run exceeds its wall-clock budget."""


class JobCancelled(RuntimeError):
    """Raised inside a worker when the job has been cancelled."""


@dataclass
class TsharkResult:
    args: list[str]
    returncode: int
    stdout: str
    stderr: str
    duration: float
    timed_out: bool = False
    cancelled: bool = False


@dataclass
class StreamChunk:
    direction: int  # 0 = node0 -> node1, 1 = node1 -> node0
    byte_len: int
    data: str
    hex: str


@dataclass
class FollowStream:
    node0: str | None = None
    node1: str | None = None
    chunks: list[StreamChunk] = field(default_factory=list)
    raw: str = ""
    found: bool = False


# --------------------------------------------------------------------------
# binary resolution
# --------------------------------------------------------------------------

def resolve_binary(name: str = "tshark") -> str | None:
    """Locate ``tshark``/``capinfos``: config → PATH → known install dirs."""
    if name in _binary_cache:
        return _binary_cache[name]

    candidates: list[str] = []
    if name == "tshark":
        configured = settings.tshark_path
    elif name == "capinfos":
        configured = settings.capinfos_path
    else:
        configured = None
    if configured and configured not in {"tshark", "capinfos"}:
        candidates.append(configured)

    found = shutil.which(name)
    if found:
        candidates.append(found)

    for directory in _WINDOWS_HINTS:
        if directory.is_dir():
            candidates.append(str(directory / f"{name}.exe"))
            candidates.append(str(directory / name))

    linux_hints = [Path("/usr/bin"), Path("/usr/local/bin")]
    for directory in linux_hints:
        candidates.append(str(directory / name))

    resolved: str | None = None
    for candidate in candidates:
        try:
            if candidate and Path(candidate).is_file():
                resolved = candidate
                break
        except OSError:
            continue

    _binary_cache[name] = resolved
    if resolved:
        log.debug("resolved %s -> %s", name, resolved)
    else:
        log.warning("%s not found; packet analysis will fail", name)
    return resolved


def _reset_binary_cache() -> None:
    """Testing hook."""
    _binary_cache.clear()


def install_dirs() -> list[Path]:
    """The directories a Wireshark install is looked for in.

    Public because the other Wireshark binary this application can start (the
    GUI, in :mod:`app.services.wireshark`) ships in the same directory: one list
    of hints means the two can never disagree about where Wireshark lives.
    """
    return list(_WINDOWS_HINTS)


def version() -> dict:
    """TShark availability + version, safe to call when TShark is absent."""
    binary = resolve_binary("tshark")
    if not binary:
        return {"available": False, "path": None, "version": None, "error": "tshark not found"}
    try:
        result = run(["--version"], timeout=20, allow_exit_codes=(0, 1))
    except Exception as exc:  # pragma: no cover - defensive
        return {"available": False, "path": binary, "version": None, "error": str(exc)}
    first = (result.stdout or result.stderr).splitlines()
    text = first[0].strip() if first else ""
    # "TShark (Wireshark) 4.6.8 (v4.6.8-0-ge677bf052328)."
    parsed = None
    for token in text.replace("(", " ").replace(")", " ").split():
        if token and token[0].isdigit() and token.count(".") >= 2:
            parsed = token.rstrip(".")
            break
    return {
        "available": result.returncode == 0 or bool(parsed),
        "path": binary,
        "version": parsed,
        "banner": text,
        "error": None,
    }


# --------------------------------------------------------------------------
# execution primitives
# --------------------------------------------------------------------------

def _guard(argv: Sequence[str]) -> None:
    for arg in argv:
        if "\x00" in arg:
            raise ValueError("NUL byte in TShark argument")


def _kill(proc: subprocess.Popen) -> None:
    try:
        proc.kill()
    except Exception:  # pragma: no cover - already gone
        pass


def run(
    args: Sequence[str],
    *,
    timeout: float | None = None,
    cancel_event: threading.Event | None = None,
    allow_exit_codes: tuple[int, ...] = (0,),
    binary: str = "tshark",
) -> TsharkResult:
    """Run one TShark command to completion.

    Raises :class:`TsharkTimeout` on timeout, :class:`JobCancelled` on
    cancellation, and :class:`TsharkError` for a disallowed exit code.
    """
    exe = resolve_binary(binary)
    if not exe:
        raise TsharkError(f"{binary} executable not found on this system")

    argv = [exe, *args]
    _guard(argv)
    budget = float(timeout if timeout is not None else settings.tshark_timeout_s)
    log.debug("exec %s", " ".join(argv[:8]))

    started = time.monotonic()
    proc = subprocess.Popen(  # noqa: S603 - explicit argv, shell=False
        argv,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        stdin=subprocess.DEVNULL,
        text=True,
        encoding="utf-8",
        errors="replace",
        shell=False,
        creationflags=_FLAGS,
    )

    deadline = started + budget
    timed_out = False
    cancelled = False
    out = err = ""

    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            # Deadline reached. Report a timeout only if the process was still
            # running; something that finished just inside the budget is fine.
            if proc.poll() is None:
                _kill(proc)
                timed_out = True
            out, err = proc.communicate()
            break
        try:
            # Poll in short slices so the deadline is honoured to within a few
            # milliseconds rather than rounded up to the poll interval.
            out, err = proc.communicate(timeout=min(0.25, remaining))
            break
        except subprocess.TimeoutExpired:
            if cancel_event is not None and cancel_event.is_set():
                _kill(proc)
                out, err = proc.communicate()
                cancelled = True
                break

    duration = time.monotonic() - started
    result = TsharkResult(
        args=argv,
        returncode=proc.returncode if proc.returncode is not None else -1,
        stdout=out or "",
        stderr=err or "",
        duration=duration,
        timed_out=timed_out,
        cancelled=cancelled,
    )

    if cancelled:
        raise JobCancelled(f"cancelled: {binary} {' '.join(args[:4])}")
    if timed_out:
        raise TsharkTimeout(f"{binary} exceeded {budget:.0f}s budget", result)
    if result.returncode not in allow_exit_codes:
        raise TsharkError(
            f"{binary} exited {result.returncode}: {_short(result.stderr)}", result
        )
    return result


def _short(text: str, limit: int = 300) -> str:
    text = " ".join((text or "").split())
    return text if len(text) <= limit else text[: limit - 1] + "…"


def run_bytes(
    args: Sequence[str],
    *,
    timeout: float | None = None,
    cancel_event: threading.Event | None = None,
    allow_exit_codes: tuple[int, ...] = (0,),
    binary: str = "tshark",
) -> tuple[bytes, str, int]:
    """Run TShark capturing **raw bytes** of stdout.

    Used where byte fidelity matters (stream reassembly, hex dumps): text mode
    would translate CRLF and corrupt payload reconstruction.
    """
    exe = resolve_binary(binary)
    if not exe:
        raise TsharkError(f"{binary} executable not found on this system")

    argv = [exe, *args]
    _guard(argv)
    budget = float(timeout if timeout is not None else settings.tshark_timeout_s)

    started = time.monotonic()
    proc = subprocess.Popen(  # noqa: S603 - explicit argv, shell=False
        argv,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        stdin=subprocess.DEVNULL,
        shell=False,
        creationflags=_FLAGS,
    )

    deadline = started + budget
    timed_out = False
    cancelled = False
    out_b = b""
    err_b = b""

    while True:
        try:
            out_b, err_b = proc.communicate(timeout=0.25)
            break
        except subprocess.TimeoutExpired:
            if cancel_event is not None and cancel_event.is_set():
                _kill(proc)
                out_b, err_b = proc.communicate()
                cancelled = True
                break
            if time.monotonic() > deadline:
                _kill(proc)
                out_b, err_b = proc.communicate()
                timed_out = True
                break

    stderr_text = (err_b or b"").decode("utf-8", "replace")
    code = proc.returncode if proc.returncode is not None else -1

    if cancelled:
        raise JobCancelled("cancelled")
    if timed_out:
        raise TsharkTimeout(f"{binary} exceeded {budget:.0f}s budget")
    if code not in allow_exit_codes:
        raise TsharkError(f"{binary} exited {code}: {_short(stderr_text)}")
    return out_b or b"", stderr_text, code


# --------------------------------------------------------------------------
# display-filter validation
# --------------------------------------------------------------------------

def canary_capture() -> Path:
    """A valid, empty pcap used only to compile display filters.

    Validating a filter needs a readable capture, not any actual packets — a
    display filter compiles independently of file contents.
    """
    path = settings.data_dir / ".filter-canary.pcap"
    with _canary_lock:
        if not path.exists():
            settings.ensure_dirs()
            header = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
            path.write_bytes(header)
    return path


_INVALID_MARKERS = (
    "is not a valid protocol or protocol field",
    "unexpected end of filter expression",
    "was unexpected",
    "syntax error",
    "isn't a valid",
    "not a valid",
)


def validate_filter(expr: str | None) -> tuple[bool, str | None]:
    """Return ``(True, None)`` for a valid display filter.

    A valid filter that matches nothing still returns ``True`` — the caller must
    distinguish that from an invalid filter itself.
    """
    if expr is None or not expr.strip():
        return True, None

    try:
        result = run(
            ["-r", str(canary_capture()), "-n", "-Y", expr, "-T", "fields", "-e", "frame.number"],
            timeout=30,
            allow_exit_codes=(0, 1, 2, 4, 255),
        )
    except TsharkError as exc:
        return False, _short(str(exc))
    except (TsharkTimeout, OSError) as exc:
        return False, f"could not validate filter: {exc}"

    if result.returncode == 0:
        return True, None

    reason = _short(result.stderr) or f"tshark rejected the filter (exit {result.returncode})"
    return False, reason


# --------------------------------------------------------------------------
# streaming field extraction
# --------------------------------------------------------------------------

def stream_fields(
    path: str | Path,
    fields: Sequence[str],
    *,
    display_filter: str | None = None,
    extra_args: Sequence[str] | None = None,
    occurrence: str = "f",
    aggregator: str | None = None,
    separator: str = "\t",
    timeout: float | None = None,
    cancel_event: threading.Event | None = None,
) -> Iterator[list[str]]:
    """Yield one ``list[str]`` per packet, streaming TShark's stdout.

    The caller must consume the generator fully or ``break`` out of it; closing
    the generator terminates the process.
    """
    exe = resolve_binary("tshark")
    if not exe:
        raise TsharkError("tshark executable not found on this system")

    args: list[str] = [
        "-r",
        str(path),
        "-n",
        "-T",
        "fields",
        "-E",
        f"separator={separator}",
        "-E",
        f"occurrence={occurrence}",
    ]
    if aggregator:
        args += ["-E", f"aggregator={aggregator}"]
    for field_name in fields:
        args += ["-e", field_name]
    if display_filter and display_filter.strip():
        args += ["-Y", display_filter]
    if extra_args:
        args += list(extra_args)

    argv = [exe, *args]
    _guard(argv)
    budget = float(timeout if timeout is not None else settings.tshark_timeout_s)
    deadline = time.monotonic() + budget

    proc = subprocess.Popen(  # noqa: S603 - explicit argv, shell=False
        argv,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        stdin=subprocess.DEVNULL,
        text=True,
        encoding="utf-8",
        errors="replace",
        shell=False,
        creationflags=_FLAGS,
    )

    state = {"timed_out": False, "cancelled": False}
    stop = threading.Event()

    def _watchdog() -> None:
        while not stop.is_set():
            if cancel_event is not None and cancel_event.is_set():
                state["cancelled"] = True
                _kill(proc)
                return
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                state["timed_out"] = True
                _kill(proc)
                return
            # Sleep in short slices so a tight deadline is honoured promptly.
            stop.wait(min(0.25, remaining))

    watcher = threading.Thread(target=_watchdog, name="tshark-watchdog", daemon=True)
    watcher.start()

    completed = False
    try:
        assert proc.stdout is not None
        for line in proc.stdout:
            line = line.rstrip("\r\n")
            if line == "":
                continue
            yield line.split(separator)
        completed = True
    finally:
        stop.set()
        if proc.poll() is None:
            _kill(proc)
        try:
            proc.wait(timeout=5)
        except Exception:  # pragma: no cover
            pass
        stderr_text = ""
        if proc.stderr is not None:
            try:
                stderr_text = proc.stderr.read() or ""
            except Exception:  # pragma: no cover
                stderr_text = ""
            finally:
                proc.stderr.close()
        if proc.stdout is not None:
            proc.stdout.close()

        if state["cancelled"]:
            raise JobCancelled("packet extraction cancelled")
        if state["timed_out"]:
            raise TsharkTimeout(f"packet extraction exceeded {budget:.0f}s budget")
        # Only surface a process failure when the stream ran to completion; an
        # early ``break`` intentionally kills TShark and is not an error.
        if completed:
            code = proc.returncode
            if code not in (0, None) and stderr_text.strip():
                raise TsharkError(f"tshark exited {code}: {_short(stderr_text)}")


def matching_frame_numbers(
    path: str | Path,
    display_filter: str,
    *,
    limit: int = 200_000,
    cancel_event: threading.Event | None = None,
    timeout: float | None = None,
) -> list[int]:
    """Frame numbers matching a display filter, in capture order."""
    numbers: list[int] = []
    for row in stream_fields(
        path,
        ["frame.number"],
        display_filter=display_filter,
        cancel_event=cancel_event,
        timeout=timeout,
    ):
        if row and row[0].strip():
            try:
                numbers.append(int(row[0]))
            except ValueError:
                continue
            if len(numbers) >= limit:
                break
    return numbers


def first_matching_frame(
    path: str | Path,
    display_filter: str,
    *,
    after: int | None = None,
    before: int | None = None,
    timeout: float | None = None,
) -> int | None:
    """First frame matching ``display_filter`` after/before a packet number.

    For ``after`` the scan stops as soon as a match appears. For ``before`` all
    matches must be seen to know which is closest, so the last one wins.
    """
    if after is not None:
        expr = f"({display_filter}) && frame.number > {int(after)}"
        for row in stream_fields(path, ["frame.number"], display_filter=expr, timeout=timeout):
            if row and row[0].strip():
                try:
                    return int(row[0])
                except ValueError:
                    continue
        return None

    if before is not None:
        expr = f"({display_filter}) && frame.number < {int(before)}"
        closest: int | None = None
        for row in stream_fields(path, ["frame.number"], display_filter=expr, timeout=timeout):
            if row and row[0].strip():
                try:
                    number = int(row[0])
                except ValueError:
                    continue
                # Rows arrive in capture order, so the last one seen is closest.
                if number < int(before):
                    closest = number
        return closest

    for row in stream_fields(path, ["frame.number"], display_filter=display_filter, timeout=timeout):
        if row and row[0].strip():
            try:
                return int(row[0])
            except ValueError:
                continue
    return None


# --------------------------------------------------------------------------
# packet detail
# --------------------------------------------------------------------------

def _clean_layers(node: object) -> object:
    """Drop the synthetic ``*_tree`` containers TShark emits in JSON output.

    Their children are folded into the parent because they carry the resolved
    names (address OUI lookups and similar) that are worth showing.
    """
    if isinstance(node, dict):
        out: dict[str, object] = {}
        for key, value in node.items():
            if isinstance(value, dict) and key.endswith("_tree"):
                merged = _clean_layers(value)
                if isinstance(merged, dict):
                    for sub_key, sub_value in merged.items():
                        out.setdefault(sub_key, sub_value)
                continue
            if key.endswith("_raw"):
                continue
            out[key] = _clean_layers(value)
        return out
    if isinstance(node, list):
        return [_clean_layers(item) for item in node]
    return node


def packet_json(
    path: str | Path,
    packet_number: int,
    *,
    timeout: float | None = None,
    cancel_event: threading.Event | None = None,
) -> dict:
    """Nested protocol layers for one packet, from ``tshark -T json``."""
    import json

    expr = f"frame.number == {int(packet_number)}"
    result = run(
        ["-r", str(path), "-n", "-Y", expr, "-T", "json"],
        timeout=timeout,
        cancel_event=cancel_event,
    )
    text = result.stdout.strip()
    if not text:
        return {}
    try:
        payload = json.loads(text)
    except json.JSONDecodeError as exc:
        log.warning("could not parse packet json: %s", exc)
        return {}
    if not isinstance(payload, list) or not payload:
        return {}
    source = payload[0].get("_source") or {}
    layers = source.get("layers") or {}
    cleaned = _clean_layers(layers)
    return cleaned if isinstance(cleaned, dict) else {}


_HEX_BYTE = set("0123456789abcdefABCDEF")
_OFFSET_RE = re.compile(r"^([0-9a-fA-F]+)\s+")


def _ascii_of(hex_clean: str) -> str:
    """Wireshark-style ASCII column: printable bytes, other bytes as '.'."""
    try:
        data = bytes.fromhex(hex_clean)
    except ValueError:
        return ""
    return "".join(chr(b) if 32 <= b < 127 else "." for b in data)


def parse_hexdump(text: str) -> tuple[list[dict], str]:
    """Parse classic tshark ``-x`` output into rows plus the raw hex string.

    TShark's layout is ``offset  hex bytes  ascii`` with variable padding, so the
    hex bytes are read token by token (at most 16 per row) and the ASCII column
    is rendered from the bytes rather than parsed from the padded text.

    Returns ``(rows, raw_hex)`` where each row is
    ``{"offset": int, "hex": str, "ascii": str, "bytes": int}``.
    """
    rows: list[dict] = []
    hex_parts: list[str] = []

    for line in text.splitlines():
        line = line.rstrip("\r\n")
        if not line:
            continue
        match = _OFFSET_RE.match(line)
        if not match:
            continue
        try:
            offset = int(match.group(1), 16)
        except ValueError:
            continue

        tokens: list[str] = []
        for token in line[match.end() :].split():
            if len(token) == 2 and all(ch in _HEX_BYTE for ch in token):
                tokens.append(token)
                if len(tokens) == 16:
                    break
            else:
                break
        if not tokens:
            continue

        hex_clean = "".join(token.lower() for token in tokens)
        hex_parts.append(hex_clean)
        rows.append(
            {
                "offset": offset,
                "hex": " ".join(tokens),
                "ascii": _ascii_of(hex_clean),
                "bytes": len(tokens),
            }
        )

    return rows, "".join(hex_parts)


def packet_hexdump(
    path: str | Path,
    packet_number: int,
    *,
    timeout: float | None = None,
    cancel_event: threading.Event | None = None,
) -> tuple[list[dict], str]:
    """Hex + ASCII dump for one packet."""
    expr = f"frame.number == {int(packet_number)}"
    result = run(
        ["-r", str(path), "-n", "-Y", expr, "-x"],
        timeout=timeout,
        cancel_event=cancel_event,
    )
    return parse_hexdump(result.stdout)


def render_ascii(raw_hex: str, limit: int = 8192) -> tuple[str, bool]:
    """Printable rendering of captured bytes, truncated for transport."""
    try:
        data = bytes.fromhex(raw_hex)
    except ValueError:
        return "", False
    truncated = len(data) > limit
    window = data[:limit]
    text = "".join(chr(b) if 32 <= b < 127 or b in (9, 10, 13) else "." for b in window)
    return text, truncated


# --------------------------------------------------------------------------
# statistics and stream helpers
# --------------------------------------------------------------------------

def run_z(path: str | Path, statistic: str, *, timeout: float | None = None) -> str:
    """Run a ``-z`` statistic and return stdout."""
    result = run(
        ["-r", str(path), "-n", "-q", "-z", statistic],
        timeout=timeout,
    )
    return result.stdout


def undo_windows_lf_expansion(data: bytes) -> bytes:
    """Invert the C runtime's LF -> CRLF text-mode expansion.

    TShark writes its output through the Windows CRT, which inserts a CR before
    every LF byte it emits. That silently corrupts reconstructed payloads: a
    capture byte sequence of ``\\r\\n`` arrives as ``\\r\\r\\n``, and a lone
    ``\\x0a`` inside binary data arrives as ``\\r\\n``.

    The transformation is a pure insertion, so replacing every ``\\r\\n`` with
    ``\\n`` (left to right, non-overlapping) recovers the original bytes exactly.
    Verified against a known payload in ``tests/test_tshark_runner.py``.

    On POSIX platforms no expansion happens and this is a no-op.
    """
    if os.name != "nt":
        return data
    return data.replace(b"\r\n", b"\n")


def follow_raw_block(
    path: str | Path,
    stream_id: int,
    *,
    timeout: float | None = None,
    cancel_event: threading.Event | None = None,
) -> bytes:
    """The ``follow,tcp,raw`` block for one stream, with LF expansion undone.

    ``raw`` is the only byte-exact follow mode:

    * ``ascii`` replaces non-printable bytes with ``.`` — lossy for binary payloads,
    * ``hex`` emits an offsets + ASCII dump that has to be re-parsed,
    * ``raw`` emits the payload as continuous lowercase hex, one line per
      direction run, with a leading TAB marking node 1 -> node 0.
    """
    data, _, _ = run_bytes(
        ["-r", str(path), "-n", "-q", "-z", f"follow,tcp,raw,{int(stream_id)}"],
        timeout=timeout,
        cancel_event=cancel_event,
        allow_exit_codes=(0, 1),
    )
    return undo_windows_lf_expansion(data)


def follow_stream_data(
    stream_id: int,
    path: str | Path,
    mode: str = "raw",
    *,
    normalize_newlines: bool = True,
) -> bytes:
    """Raw bytes of a ``-z follow`` block (raw mode by default)."""
    data, _, _ = run_bytes(
        ["-r", str(path), "-n", "-q", "-z", f"follow,tcp,{mode},{int(stream_id)}"],
        allow_exit_codes=(0, 1),
    )
    return undo_windows_lf_expansion(data) if normalize_newlines else data


def follow_stream(
    path: str | Path,
    stream_id: int,
    mode: str = "ascii",
    *,
    timeout: float | None = None,
    cancel_event: threading.Event | None = None,
) -> FollowStream:
    """Reassembled TCP stream via TShark's ``follow``.

    TShark performs the reassembly (sequence numbers, retransmissions,
    out-of-order segments, direction). This function only reshapes its output.

    The authoritative bytes always come from raw mode; ``mode`` selects how the
    returned chunks are *rendered*, so ``ascii`` never loses binary data.
    """
    mode = mode if mode in {"ascii", "hex", "raw"} else "ascii"
    data = follow_raw_block(path, stream_id, timeout=timeout, cancel_event=cancel_event)
    return parse_follow_raw(data, mode)


def _next_line(data: bytes, pos: int) -> tuple[bytes, int]:
    newline = data.find(b"\n", pos)
    if newline == -1:
        return data[pos:], len(data)
    return data[pos:newline], newline + 1


def _node_is_valid(text: str | None) -> bool:
    """True when a follow ``Node N:`` line names a real endpoint.

    For a stream that does not exist TShark still prints ``Node 0: :0`` with an
    empty host, so the placeholder must not be mistaken for a real stream.
    """
    if not text:
        return False
    host, _, port = text.rpartition(":")
    if not host.strip():
        return False
    port_text = port.strip()
    return port_text.isdigit() and int(port_text) > 0


def parse_follow_raw(data: bytes, mode: str = "ascii") -> FollowStream:
    """Parse a ``follow,tcp,raw`` block into direction-tagged byte chunks.

    Structure::

        ================
        Follow: tcp,raw
        Filter: tcp.stream eq 0
        Node 0: <ip>:<port>
        Node 1: <ip>:<port>
        <hex of node0 -> node1 data>
        \\t<hex of node1 -> node0 data>
        ================
    """
    stream = FollowStream()
    if not data:
        return stream

    stream.raw = data.decode("utf-8", "replace")

    segments: list[tuple[int, str]] = []  # (direction, hex)
    pos = 0
    total = len(data)
    in_body = False

    while pos < total:
        line, pos = _next_line(data, pos)

        if line.startswith(b"Node 0:"):
            stream.node0 = line[len(b"Node 0:") :].strip().decode("utf-8", "replace")
            in_body = True
            continue
        if line.startswith(b"Node 1:"):
            stream.node1 = line[len(b"Node 1:") :].strip().decode("utf-8", "replace")
            in_body = True
            continue
        if not in_body:
            continue

        stripped = line.strip()
        if not stripped or set(stripped) == {ord("=")}:
            continue

        direction = 1 if line.startswith(b"\t") else 0
        decoded = stripped.decode("ascii", "replace")
        if len(decoded) % 2 or any(ch not in _HEX_BYTE for ch in decoded):
            # Not a payload line (unexpected format); ignore rather than corrupt.
            continue

        if segments and segments[-1][0] == direction:
            # A single direction's data may wrap across several lines.
            segments[-1] = (direction, segments[-1][1] + decoded)
        else:
            segments.append((direction, decoded))

    stream.found = _node_is_valid(stream.node0) or _node_is_valid(stream.node1)

    for direction, hex_text in segments:
        try:
            payload = bytes.fromhex(hex_text)
        except ValueError:
            continue
        if not payload:
            continue
        stream.chunks.append(_build_chunk(payload, direction, mode))

    return stream


def _build_chunk(payload: bytes, direction: int, mode: str) -> StreamChunk:
    """Render one direction's reassembled bytes in the requested representation."""
    hex_text = payload.hex()

    if mode == "hex":
        return StreamChunk(direction=direction, byte_len=len(payload), data=hex_text, hex=hex_text)

    if mode == "raw":
        text = "".join(
            chr(byte) if 32 <= byte < 127 or byte in (9, 10, 13) else "." for byte in payload
        )
        return StreamChunk(direction=direction, byte_len=len(payload), data=text, hex=hex_text)

    return StreamChunk(
        direction=direction,
        byte_len=len(payload),
        data=payload.decode("utf-8", "replace"),
        hex=hex_text,
    )


def export_objects(
    path: str | Path,
    destination: Path,
    *,
    protocol: str = "http",
    timeout: float | None = None,
) -> str:
    """Run ``--export-objects`` into ``destination``. Returns stdout."""
    destination.mkdir(parents=True, exist_ok=True)
    result = run(
        ["-r", str(path), "-n", "--export-objects", f"{protocol},{destination}"],
        timeout=timeout,
        allow_exit_codes=(0, 1, 2),
    )
    return result.stdout


def capture_metadata(path: str | Path, *, timeout: float | None = None) -> dict[str, str]:
    """Capture-level metadata from ``capinfos -M -T``.

    ``-T`` emits a header row followed by a single value row, both
    tab separated, so the two rows are zipped into a mapping. Header names are
    normalised to snake_case keys such as ``number_of_packets``.

    Returns an empty mapping for a file capinfos cannot read; callers that need a
    hard failure should use :func:`version` or :func:`stream_fields` instead.
    """
    exe = resolve_binary("capinfos")
    if not exe:
        return {}
    try:
        result = run(
            ["-M", "-T", str(path)],
            binary="capinfos",
            timeout=timeout,
            allow_exit_codes=(0, 1, 2),
        )
    except TsharkError:
        # Unreadable or truncated capture: no metadata rather than an exception.
        return {}
    lines = [line for line in (result.stdout or "").splitlines() if line.strip("\t \r\n")]
    if len(lines) < 2:
        return {}

    headers = [h.strip() for h in lines[0].split("\t")]
    values = lines[1].split("\t")

    meta: dict[str, str] = {}
    for index, header in enumerate(headers):
        if not header:
            continue
        value = values[index].strip() if index < len(values) else ""
        if value in {"", "n/a"}:
            continue
        key = re.sub(r"[^a-z0-9]+", "_", header.lower()).strip("_")
        meta[key] = value
    return meta


__all__ = [
    "FollowStream",
    "JobCancelled",
    "StreamChunk",
    "TsharkError",
    "TsharkResult",
    "TsharkTimeout",
    "REPO_ROOT",
    "canary_capture",
    "capture_metadata",
    "export_objects",
    "first_matching_frame",
    "follow_raw_block",
    "follow_stream",
    "follow_stream_data",
    "matching_frame_numbers",
    "packet_hexdump",
    "packet_json",
    "parse_follow_raw",
    "parse_hexdump",
    "render_ascii",
    "resolve_binary",
    "run",
    "run_bytes",
    "run_z",
    "stream_fields",
    "undo_windows_lf_expansion",
    "validate_filter",
    "version",
]
