"""Upload validation and capture-level metadata.

Two responsibilities:

* refuse files that are not real captures (extension, magic bytes, TShark),
* report what the capture is (format, encapsulation, size, duration, hashes).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

from app.core.config import settings
from app.core.errors import ApiError
from app.core.logging import get_logger
from app.services import storage, tshark

log = get_logger("apackets.capture")

_PARSE_ERROR_MARKERS = (
    "isn't a capture file",
    "is not a capture file",
    "unknown file format",
    "the file isn't a capture file",
    "truncated",
    "unexpected end of file",
)


@dataclass
class CaptureInfo:
    path: Path
    file_type: str | None = None
    encapsulation: str | None = None
    file_size: int = 0
    packet_count: int | None = None
    data_size: int | None = None
    duration: float | None = None
    sha256: str | None = None
    sha1: str | None = None
    warnings: list[str] = field(default_factory=list)
    raw: dict[str, str] = field(default_factory=dict)


def _to_float(value: str | None) -> float | None:
    if value is None:
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _to_int(value: str | None) -> int | None:
    if value is None:
        return None
    try:
        return int(float(value))
    except (TypeError, ValueError):
        return None


def validate_extension(filename: str) -> str:
    suffix = Path(filename or "").suffix.lower()
    if suffix not in settings.allowed_extensions:
        raise ApiError(
            415,
            "unsupported_file_type",
            f"Unsupported file extension '{suffix or '(none)'}'.",
            {"allowed": settings.allowed_extensions},
        )
    return suffix


def inspect(path: Path, *, original_filename: str | None = None) -> CaptureInfo:
    """Validate a stored upload and extract its metadata.

    Raises :class:`ApiError` when the file cannot be treated as a capture.
    """
    if not path.exists() or not path.is_file():
        raise ApiError(404, "upload_missing", "Stored upload could not be found.")

    size = path.stat().st_size
    if size == 0:
        raise ApiError(400, "empty_file", "The uploaded file is empty.")
    if size > settings.max_upload_bytes:
        raise ApiError(
            413,
            "file_too_large",
            f"File exceeds the {settings.max_upload_mb} MB upload limit.",
            {"size": size, "limit": settings.max_upload_bytes},
        )

    info = CaptureInfo(path=path, file_size=size)

    if original_filename:
        validate_extension(original_filename)

    with open(path, "rb") as handle:
        magic = handle.read(4)
    sniffed = storage.sniff_capture_format(path, magic)
    if sniffed is None:
        raise ApiError(
            415,
            "unsupported_file_type",
            "File is not a PCAP or PCAPNG capture (unrecognised magic bytes).",
            {"first_bytes": magic.hex()},
        )
    info.file_type = sniffed

    # TShark must be able to read it before we commit to an analysis.
    if not tshark.resolve_binary("capinfos"):
        raise ApiError(503, "tshark_unavailable", "TShark/capinfos is not available on this host.")

    try:
        meta = tshark.capture_metadata(path)
    except tshark.TsharkTimeout as exc:
        raise ApiError(504, "metadata_timeout", f"Reading capture metadata timed out: {exc}") from exc
    except tshark.TsharkError as exc:
        raise ApiError(
            400,
            "invalid_capture",
            "TShark could not read this file as a capture.",
            {"reason": str(exc)},
        ) from exc

    if not meta:
        raise ApiError(400, "invalid_capture", "TShark produced no capture metadata.")

    info.raw = meta
    info.file_type = meta.get("file_type") or info.file_type
    info.encapsulation = meta.get("file_encapsulation")
    info.packet_count = _to_int(meta.get("number_of_packets"))
    info.data_size = _to_int(meta.get("data_size_bytes"))
    info.duration = _to_float(meta.get("capture_duration_seconds"))
    info.sha256 = meta.get("sha256")
    info.sha1 = meta.get("sha1")

    declared_size = _to_int(meta.get("file_size_bytes"))
    if declared_size is not None and declared_size < size:
        info.warnings.append(
            f"capinfos reports {declared_size} bytes but the file is {size} bytes; "
            "the capture may be truncated."
        )

    if info.packet_count is None:
        raise ApiError(
            400,
            "invalid_capture",
            "TShark could not determine the packet count; the file may be truncated.",
        )

    if info.packet_count == 0:
        info.warnings.append("The capture contains no packets.")

    log.info(
        "capture %s: %s %s packets=%s duration=%s",
        original_filename or path.name,
        info.file_type,
        info.encapsulation,
        info.packet_count,
        info.duration,
    )
    return info


def summary_text(info: CaptureInfo) -> str:
    parts = [f"{info.file_type or 'capture'}/{info.encapsulation or 'unknown'}"]
    if info.packet_count is not None:
        parts.append(f"{info.packet_count} packets")
    if info.file_size:
        parts.append(f"{info.file_size} bytes")
    if info.duration is not None:
        parts.append(f"{info.duration:.3f}s")
    return ", ".join(parts)


def looks_like_parse_error(text: str) -> bool:
    lowered = (text or "").lower()
    return any(marker in lowered for marker in _PARSE_ERROR_MARKERS) or bool(
        re.search(r"malformed|invalid.*packet", lowered)
    )
