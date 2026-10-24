"""TCP stream reassembly, search and export for the stream viewer.

Stream bytes always come from TShark's own ``follow`` reassembly via
:func:`app.services.tshark.follow_stream` — sequence handling, retransmissions and
out-of-order segments are TShark's problem, never ours. This module only reshapes
that output for the API and applies transport-size caps so a response can never
carry an unbounded payload.
"""

from __future__ import annotations

import csv
import io
from pathlib import Path

from app.core.errors import ApiError, bad_request, not_found
from app.core.logging import get_logger
from app.db import database as db
from app.services import storage, tshark

log = get_logger("shadowpackets.streams")

MODES = ("ascii", "hex", "raw")
EXPORT_FORMATS = ("txt", "hex", "csv", "raw")

# Cap on the per-direction text/hex summary (in source bytes).
MAX_SUMMARY_BYTES = 2 * 1024 * 1024
# Cap on a single chunk preview, in characters.
PREVIEW_CHARS = 2000
# Cap on how many chunks are returned inline; the total is always reported.
MAX_CHUNKS = 500
MAX_SEARCH_MATCHES = 500
CONTEXT_CHARS = 80


# --------------------------------------------------------------------------
# lookups
# --------------------------------------------------------------------------

def _analysis_row(analysis_id: str) -> dict:
    storage.validate_analysis_id(analysis_id)
    row = db.query_one("SELECT * FROM analyses WHERE id = ?", (analysis_id,))
    if row is None:
        raise not_found("analysis_not_found", f"No analysis with id {analysis_id}.")
    return dict(row)


def _capture_path(analysis_id: str) -> Path:
    row = _analysis_row(analysis_id)
    stored = row.get("stored_path")
    if not stored:
        raise ApiError(
            410,
            "capture_missing",
            "The stored capture file is no longer available; re-upload the file.",
            {"path": None},
        )
    path = Path(stored)
    if not path.is_file():
        raise ApiError(
            410,
            "capture_missing",
            "The stored capture file is no longer available; re-upload the file.",
            {"path": str(path)},
        )
    return path


def _stream_row(analysis_id: str, stream_id: int) -> dict:
    """One ``streams`` row. TCP is preferred when an id exists for both transports.

    ``streams`` is keyed by ``(analysis_id, transport, stream_id)`` while the API
    path carries only the numeric id, so TCP (the only transport TShark can
    reassemble) wins when the two namespaces collide.
    """
    rows = db.query_all(
        """
        SELECT * FROM streams
         WHERE analysis_id = ? AND stream_id = ?
         ORDER BY CASE transport WHEN 'tcp' THEN 0 ELSE 1 END
        """,
        (analysis_id, stream_id),
    )
    if not rows:
        raise not_found(
            "stream_not_found",
            f"Stream {stream_id} is not present in this analysis.",
            stream_id=stream_id,
        )
    return dict(rows[0])


def _check_mode(mode: str) -> str:
    if mode not in MODES:
        raise bad_request(
            "invalid_mode",
            f"Unsupported stream mode '{mode}'.",
            allowed=list(MODES),
        )
    return mode


def _reassemble(
    analysis_id: str,
    stream_id: int,
    mode: str,
) -> tuple[dict, tshark.FollowStream]:
    """Reassembled stream data for one ``(analysis_id, stream_id)``."""
    mode = _check_mode(mode)
    row = _stream_row(analysis_id, stream_id)
    path = _capture_path(analysis_id)

    if row.get("transport") == "tcp":
        try:
            follow = tshark.follow_stream(path, stream_id, mode)
        except tshark.TsharkTimeout as exc:
            raise ApiError(
                504,
                "tshark_timeout",
                "Reassembling the stream exceeded the TShark time budget.",
                {"stream_id": stream_id},
            ) from exc
        except tshark.TsharkError as exc:
            raise ApiError(
                500,
                "stream_read_failed",
                "TShark could not reassemble this stream.",
                {"stream_id": stream_id, "reason": str(exc)},
            ) from exc
    else:
        # TShark's ``follow`` only reassembles TCP; a UDP "stream" has no
        # ordered reassembly to report, so the follow block stays empty rather
        # than being synthesised from packet payloads.
        log.debug("stream %s is %s; no TCP reassembly available", stream_id, row.get("transport"))
        follow = tshark.FollowStream()

    return row, follow


# --------------------------------------------------------------------------
# rendering helpers
# --------------------------------------------------------------------------

def _chunk_bytes(chunk: tshark.StreamChunk) -> bytes:
    try:
        return bytes.fromhex(chunk.hex or "")
    except ValueError:  # pragma: no cover - TShark always emits hex
        return b""


def _render(raw: bytes, mode: str) -> str:
    if mode == "hex":
        return raw.hex()
    if mode == "raw":
        return "".join(
            chr(byte) if 32 <= byte < 127 or byte in (9, 10, 13) else "." for byte in raw
        )
    return raw.decode("utf-8", "replace")


def _direction_bytes(follow: tshark.FollowStream) -> dict[int, int]:
    totals = {0: 0, 1: 0}
    for chunk in follow.chunks:
        totals[chunk.direction] = totals.get(chunk.direction, 0) + chunk.byte_len
    return totals


def _direction_summary(
    follow: tshark.FollowStream,
    direction: int,
    mode: str,
) -> tuple[dict, bool]:
    """Capped text/hex rendering of one direction's reassembled bytes."""
    window = bytearray()
    total = 0
    for chunk in follow.chunks:
        if chunk.direction != direction:
            continue
        data = _chunk_bytes(chunk)
        total += len(data)
        remaining = MAX_SUMMARY_BYTES - len(window)
        if remaining > 0:
            window += data[:remaining]

    truncated = total > len(window)
    return (
        {
            "direction": direction,
            "bytes": total,
            "text": _render(bytes(window), mode),
            "hex": bytes(window).hex(),
            "truncated": truncated,
        },
        truncated,
    )


def _chunk_items(follow: tshark.FollowStream) -> tuple[list[dict], bool]:
    items: list[dict] = []
    for index, chunk in enumerate(follow.chunks):
        if index >= MAX_CHUNKS:
            break
        items.append(
            {
                "index": index,
                "direction": chunk.direction,
                "byte_len": chunk.byte_len,
                "text_preview": (chunk.data or "")[:PREVIEW_CHARS],
                "hex_preview": (chunk.hex or "")[:PREVIEW_CHARS],
            }
        )
    return items, len(follow.chunks) > len(items)


def _node_of(row: dict, follow: tshark.FollowStream) -> str | None:
    """Which TShark node matches the client recorded in the ``streams`` row."""
    client_ip = row.get("client_ip")
    client_port = row.get("client_port")
    if not client_ip or client_port is None:
        return None
    expected = f"{client_ip}:{client_port}"
    if follow.node0 == expected:
        return "node0"
    if follow.node1 == expected:
        return "node1"
    return None


def _endpoint(row: dict, prefix: str) -> str | None:
    ip = row.get(f"{prefix}_ip")
    port = row.get(f"{prefix}_port")
    if not ip or port is None:
        return None
    return f"{ip}:{port}"


# --------------------------------------------------------------------------
# public API
# --------------------------------------------------------------------------

def get_stream(analysis_id: str, stream_id: int, mode: str = "ascii") -> dict:
    """``{"stream": row|null, "follow": {...}}`` for the stream viewer."""
    row, follow = _reassemble(analysis_id, stream_id, mode)

    client_to_server, truncated_c2s = _direction_summary(follow, 0, mode)
    server_to_client, truncated_s2c = _direction_summary(follow, 1, mode)
    chunks, chunks_truncated = _chunk_items(follow)

    return {
        "stream": row,
        "follow": {
            "stream_id": row.get("stream_id"),
            "transport": row.get("transport"),
            "node0": follow.node0,
            "node1": follow.node1,
            "client_endpoint": _endpoint(row, "client"),
            "server_endpoint": _endpoint(row, "server"),
            "client_node": _node_of(row, follow),
            "client_to_server": client_to_server,
            "server_to_client": server_to_client,
            "chunks": chunks,
            "chunk_count": len(follow.chunks),
            "chunks_truncated": chunks_truncated,
            "truncated": truncated_c2s or truncated_s2c or chunks_truncated,
        },
    }


def search_stream(
    analysis_id: str,
    stream_id: int,
    query: str,
    mode: str = "ascii",
) -> dict:
    """Case-insensitive search over the reassembled bytes.

    Offsets are byte offsets inside the reassembled stream of the reported
    direction. ``mode`` controls how the surrounding context is rendered.
    """
    mode = _check_mode(mode)
    needle = (query or "").encode("utf-8")
    if not needle:
        raise bad_request("invalid_query", "A search query is required.")

    row, follow = _reassemble(analysis_id, stream_id, mode)

    buffers: dict[int, bytearray] = {0: bytearray(), 1: bytearray()}
    for chunk in follow.chunks:
        buffers.setdefault(chunk.direction, bytearray()).extend(_chunk_bytes(chunk))

    lowered = needle.lower()
    items: list[dict] = []
    truncated = False

    for direction in sorted(buffers):
        data = bytes(buffers[direction])
        haystack = data.lower()
        position = 0
        while True:
            found = haystack.find(lowered, position)
            if found < 0:
                break
            if len(items) >= MAX_SEARCH_MATCHES:
                truncated = True
                break
            start = max(0, found - CONTEXT_CHARS)
            end = min(len(data), found + len(needle) + CONTEXT_CHARS)
            items.append(
                {
                    "direction": direction,
                    "offset": found,
                    "context": _render(data[start:end], mode),
                }
            )
            position = found + len(lowered)
        if truncated:
            break

    return {
        "stream": row,
        "query": query,
        "mode": mode,
        "count": len(items),
        "truncated": truncated,
        "items": items,
    }


def export_stream(
    analysis_id: str,
    stream_id: int,
    mode: str = "ascii",
    fmt: str = "txt",
) -> tuple[bytes, str, str]:
    """``(payload, filename, media_type)`` for a stream download."""
    mode = _check_mode(mode)
    if fmt not in EXPORT_FORMATS:
        raise bad_request(
            "invalid_format",
            f"Unsupported export format '{fmt}'.",
            allowed=list(EXPORT_FORMATS),
        )

    row, follow = _reassemble(analysis_id, stream_id, mode)
    transport = row.get("transport") or "stream"
    stem = f"stream-{transport}-{int(stream_id)}"

    if fmt == "raw":
        # Byte-exact payload in capture order, independent of the display mode.
        payload = b"".join(_chunk_bytes(chunk) for chunk in follow.chunks)
        return payload, storage.safe_filename(f"{stem}.bin"), "application/octet-stream"

    if fmt == "csv":
        buffer = io.StringIO()
        writer = csv.writer(buffer, lineterminator="\n")
        writer.writerow(["index", "direction", "byte_len", "hex"])
        for index, chunk in enumerate(follow.chunks):
            writer.writerow([index, chunk.direction, chunk.byte_len, chunk.hex or ""])
        return (
            buffer.getvalue().encode("utf-8"),
            storage.safe_filename(f"{stem}.csv"),
            "text/csv; charset=utf-8",
        )

    if fmt == "hex":
        text = "".join(chunk.hex or "" for chunk in follow.chunks)
        return (
            text.encode("ascii"),
            storage.safe_filename(f"{stem}.hex.txt"),
            "text/plain; charset=utf-8",
        )

    # txt: the reassembled payload rendered in the requested mode, capture order.
    text = "".join(chunk.data or "" for chunk in follow.chunks)
    return (
        text.encode("utf-8"),
        storage.safe_filename(f"{stem}.txt"),
        "text/plain; charset=utf-8",
    )


__all__ = [
    "EXPORT_FORMATS",
    "MAX_SUMMARY_BYTES",
    "MODES",
    "export_stream",
    "get_stream",
    "search_stream",
]
