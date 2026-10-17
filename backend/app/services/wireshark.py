"""Open a capture in the Wireshark GUI, filtered to what the operator asked for.

This is the **only** module that starts a program other than the dissection
tools, and it is deliberately the narrowest possible door onto it:

* the caller passes *structured* facts — an address, and optionally a transport
  and stream id — never a filter string. The display filter is composed here, so
  no client input can reach a command line as syntax;
* the argument vector is explicit and ``shell=False``, so there is no shell to
  inject into even if it could;
* the process is started **detached** and never waited on: Wireshark is a GUI
  that outlives the request, and a request thread must not sit on it;
* the capture path comes from the analysis row, never from the request.

Wireshark's stream numbering is TShark's — ``tcp.stream`` is the same number
this application stores as ``conversations.stream_id`` — so ``tcp.stream == N``
selects exactly the conversation the operator was looking at. UDP has no stream
field of that kind, so a UDP conversation is filtered by the address and its
port pair instead, and the menu says which filter was used.

Nothing here is required for the application to work. When Wireshark is not
installed, :func:`availability` reports it and the UI does not offer the action.
"""

from __future__ import annotations

import ipaddress
import os
import shutil
import subprocess
import threading
from pathlib import Path

from app.core.config import settings
from app.core.logging import get_logger
from app.services import tshark

log = get_logger("apackets.wireshark")

#: The longest display filter this module will compose. A guard against a
#: pathological address finding its way in, not a limit anyone will meet.
FILTER_MAX_CHARS = 200

#: Transports a stream id can be trusted for. ``udp.stream`` exists in Wireshark
#: but is not the number stored in ``conversations.stream_id``, so a UDP
#: conversation is never filtered by stream.
STREAM_TRANSPORTS = ("tcp",)

_binary_cache: dict[str, str | None] = {}
_version_cache: list[str | None] = []


class WiresharkError(RuntimeError):
    """Raised when the action cannot be carried out, with the reason."""


def _reset_binary_cache() -> None:
    """Testing hook."""
    _binary_cache.clear()
    _version_cache.clear()


def _binary_name() -> str:
    return "wireshark.exe" if os.name == "nt" else "wireshark"


def _real_path(candidate: str) -> str | None:
    """The candidate as it actually exists on disk, or ``None``.

    Windows would accept ``…\\wireshark.exe`` for a file named ``Wireshark.exe``,
    but the path reported to the operator (and stored in ``args``) should be the
    real one, so the directory is read rather than trusted.
    """
    path = Path(candidate)
    try:
        if path.is_file():
            parent = path.parent
            if parent.is_dir():
                wanted = path.name.lower()
                for entry in parent.iterdir():
                    if entry.name.lower() == wanted:
                        return str(entry)
            return str(path)
    except OSError:
        return None
    return None


def resolve_binary() -> str | None:
    """Locate the Wireshark GUI: config → PATH → next to TShark → known dirs.

    TShark and Wireshark ship together, so the directory TShark was found in is
    the strongest hint available on Windows, where Wireshark is not on ``PATH``.
    """
    cached = "wireshark" in _binary_cache
    if cached:
        return _binary_cache["wireshark"]

    candidates: list[str] = []
    configured = settings.wireshark_path
    if configured and configured not in {"wireshark", _binary_name()}:
        candidates.append(configured)

    found = shutil.which("wireshark")
    if found:
        candidates.append(found)

    # Next to the TShark this application already uses.
    tshark_binary = tshark.resolve_binary("tshark")
    if tshark_binary:
        candidates.append(str(Path(tshark_binary).with_name(_binary_name())))

    for directory in tshark.install_dirs():
        if directory.is_dir():
            candidates.append(str(directory / _binary_name()))
            candidates.append(str(directory / "wireshark"))

    for directory in (Path("/usr/bin"), Path("/usr/local/bin"), Path("/Applications/Wireshark.app/Contents/MacOS")):
        candidates.append(str(directory / "wireshark"))

    resolved: str | None = None
    for candidate in candidates:
        if not candidate:
            continue
        real = _real_path(candidate)
        if real:
            resolved = real
            break

    _binary_cache["wireshark"] = resolved
    if resolved:
        log.debug("resolved wireshark -> %s", resolved)
    else:
        log.info("the Wireshark GUI was not found; the packet pivot stays hidden")
    return resolved


def _version() -> str | None:
    """Wireshark's version, read once per process from the dissection tool.

    The two ship together, so TShark's banner *is* Wireshark's version, and the
    GUI binary has no version flag that does not open a window. The answer is
    memoised: availability is asked for on every page load, and a subprocess per
    page load to learn a number that cannot change is not worth it.
    """
    if _version_cache:
        return _version_cache[0]
    version = tshark.version().get("version")
    _version_cache.append(version)
    return version


def availability() -> dict:
    """Whether the packet pivot can be offered at all, and where it would open.

    No GUI is started to answer this: the executable is only checked for.
    """
    binary = resolve_binary()
    if not binary:
        return {
            "available": False,
            "path": None,
            "version": _version(),
            "error": "the Wireshark GUI was not found",
        }
    return {"available": True, "path": binary, "version": _version(), "error": None}


def _address(value: str) -> str:
    """A canonical address, or :class:`WiresharkError` — never a filter fragment.

    An IPv4-mapped IPv6 address (``::ffff:8.8.8.8``) is unwrapped to the IPv4
    address it is, the same reading the rest of this application gives it: a
    filter on the mapped form would match nothing in a capture of ordinary IPv4
    frames.
    """
    try:
        parsed = ipaddress.ip_address(value.strip())
    except ValueError as exc:
        raise WiresharkError(f"'{value}' is not an IP address") from exc
    mapped = getattr(parsed, "ipv4_mapped", None)
    return str(mapped if mapped is not None else parsed)


def build_filter(
    ip: str,
    *,
    peer: str | None = None,
    transport: str | None = None,
    stream_id: int | None = None,
    port: int | None = None,
) -> str:
    """The display filter for one address, one direction, or one conversation.

    Three shapes, in order of how much the caller knows:

    * an address alone selects every frame it appears in — ``ip.addr == A``;
    * with a peer it becomes a *direction*: ``ip.src == A && ip.dst == B``. This is
      what a conversation gives, and it is the honest filter for one: the analyst
      right-clicked the side they were looking at, and the reply traffic belongs to
      the same exchange;
    * the conversation narrows it further: ``tcp.stream == N`` for TCP, because that
      number is the one this application stored, and a port for anything else.

    The returned string contains only characters produced here — canonical
    addresses, a validated transport and integers.
    """
    address = _address(ip)
    if peer is not None:
        # A direction, not the address: the endpoint the analyst acted on is the
        # source and the other end is the destination, so the window opens on the
        # side of the exchange they were reading. It is deliberately one way - a
        # display filter is editable in Wireshark, and `|| ip.src == B && ip.dst ==
        # A` is the analyst's own decision to make, not one this endpoint takes for
        # them. Both addresses are canonicalised, so nothing arrives as it was typed.
        parts = [f"ip.src == {address} && ip.dst == {_address(peer)}"]
    else:
        parts = [f"ip.addr == {address}"]

    if stream_id is not None:
        if not isinstance(stream_id, int) or stream_id < 0:
            raise WiresharkError(f"'{stream_id}' is not a stream id")
        if transport in STREAM_TRANSPORTS:
            # Both terms: the stream is the conversation, the address keeps the
            # filter honest about whose frames are meant.
            parts.append(f"tcp.stream == {stream_id}")
        elif port is not None:
            if not isinstance(port, int) or not 0 <= port <= 65535:
                raise WiresharkError(f"'{port}' is not a port number")
            parts.append(f"port == {port}")

    display = " && ".join(parts)
    if len(display) > FILTER_MAX_CHARS:  # pragma: no cover - defensive
        raise WiresharkError("the composed filter is longer than this build allows")
    return display


def _argv(binary: str, capture: Path, display_filter: str, *, read_filter: bool) -> list[str]:
    """The argument vector, built here and nowhere else.

    Two options make the window land *on* the packets rather than merely load the
    file:

    * ``-Y <filter>`` starts with the display filter applied, so the packet list
      shows this conversation and nothing else;
    * ``-J <filter>`` jumps the selection to the first packet matching it, which
      for this filter is the conversation's first frame. Wireshark's manual:
      "jump to the packet matching the filter … If no exact match is found the
      first packet after that is selected." ``-j`` would select the packet
      *before* a missing match instead, which is not what an analyst wants.

    ``-R`` applies a *read* filter and is faster on a large capture, but it is
    only honoured with ``-2`` (two-pass), and two passes mean Wireshark is busy
    before it shows anything. ``read_filter=True`` is kept for callers that would
    rather wait.
    """
    argv = [binary, "-r", str(capture)]
    if read_filter:
        argv += ["-2", "-R", display_filter]
    else:
        argv += ["-Y", display_filter, "-J", display_filter]
    return argv


def open_capture(
    capture: Path,
    ip: str,
    *,
    peer: str | None = None,
    transport: str | None = None,
    stream_id: int | None = None,
    port: int | None = None,
    read_filter: bool = False,
) -> dict:
    """Start Wireshark on *capture*, filtered, and return what was started.

    Raises :class:`WiresharkError` with a reason a reader can act on when the
    GUI is missing or the capture is not on disk. The process is detached: this
    returns as soon as it has been started, and its exit status is nobody's
    business but the operator's.
    """
    binary = resolve_binary()
    if not binary:
        raise WiresharkError(
            "the Wireshark GUI was not found; install Wireshark, or set APACKETS_WIRESHARK_PATH"
        )
    if not capture.is_file():
        raise WiresharkError("the capture is no longer on disk, so there is nothing to open")

    display_filter = build_filter(
        ip, peer=peer, transport=transport, stream_id=stream_id, port=port
    )
    argv = _argv(binary, capture, display_filter, read_filter=read_filter)

    # DETACHED_PROCESS keeps the GUI alive after the request that started it, and
    # CREATE_NEW_PROCESS_GROUP keeps a Ctrl-C in the server's console from
    # reaching it. Both are Windows concepts; elsewhere start_new_session does
    # the same job.
    kwargs: dict = {"shell": False, "close_fds": True, "stdin": subprocess.DEVNULL}
    if os.name == "nt":
        kwargs["creationflags"] = 0x00000008 | 0x00000200  # DETACHED_PROCESS | NEW_PROCESS_GROUP
        kwargs["stdout"] = subprocess.DEVNULL
        kwargs["stderr"] = subprocess.DEVNULL
    else:
        kwargs["start_new_session"] = True
        kwargs["stdout"] = subprocess.DEVNULL
        kwargs["stderr"] = subprocess.DEVNULL

    try:
        process = subprocess.Popen(argv, **kwargs)  # noqa: S603 - explicit argv, shell=False
    except OSError as exc:
        raise WiresharkError(f"Wireshark could not be started: {exc}") from exc

    log.info("opened %s in Wireshark (pid %s) with filter %r", capture.name, process.pid, display_filter)

    # The child is not waited on, so it must not be reported as a zombie to the
    # runtime: a thread that reaps it in the background is the standard remedy.
    #
    # Note for anyone reading the returned ``pid``: on Windows the executable
    # re-execs itself, so the process started here is a launcher that exits while
    # the window it spawned keeps running. "That pid is gone" therefore says
    # nothing about whether a window opened — the launcher exits *because* the GUI
    # came up. The pid is reported for the log's sake, not as a handle on the GUI.
    def _reap() -> None:
        try:
            process.wait(timeout=3600)
        except Exception:  # noqa: BLE001 - reaping is best effort
            pass

    threading.Thread(target=_reap, name="wireshark-reap", daemon=True).start()

    return {
        "launched": True,
        "executable": binary,
        "filter": display_filter,
        "args": argv,
        "pid": process.pid,
        "capture": str(capture),
        "read_filter": read_filter,
    }
