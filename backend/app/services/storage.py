"""Filesystem layout and safe path handling.

Every filesystem operation that involves a user-supplied or capture-supplied
name goes through :func:`safe_filename` / :func:`ensure_within`, so a crafted
upload name or a filename found inside a capture can never escape the analysis
directory.
"""

from __future__ import annotations

import hashlib
import re
import shutil
import unicodedata
import uuid
from pathlib import Path

from app.core.config import settings
from app.core.errors import bad_request
from app.core.logging import get_logger

log = get_logger("apackets.storage")

ANALYSIS_ID_RE = re.compile(r"^[0-9a-f]{32}$")

_UNSAFE_CHARS = re.compile(r"[^A-Za-z0-9._ -]")
_WINDOWS_RESERVED = {
    "CON", "PRN", "AUX", "NUL",
    *(f"COM{i}" for i in range(1, 10)),
    *(f"LPT{i}" for i in range(1, 10)),
}


def new_analysis_id() -> str:
    return uuid.uuid4().hex


def validate_analysis_id(analysis_id: str) -> str:
    if not isinstance(analysis_id, str) or not ANALYSIS_ID_RE.match(analysis_id):
        raise bad_request(
            "invalid_analysis_id",
            "Analysis identifier must be a 32 character hexadecimal string.",
        )
    return analysis_id


def safe_filename(name: str, *, fallback: str = "unnamed", max_length: int = 180) -> str:
    """Reduce any string to a single, harmless path component."""
    if not name:
        return fallback

    # Strip any directory component from both separator conventions.
    candidate = str(name).replace("\\", "/").split("/")[-1]
    candidate = unicodedata.normalize("NFKD", candidate)

    # Drop control characters outright.
    candidate = "".join(ch for ch in candidate if ch.isprintable())

    candidate = _UNSAFE_CHARS.sub("_", candidate).strip(" .")

    # Never allow traversal artefacts or hidden-file prefixes.
    while candidate.startswith("."):
        candidate = candidate[1:]
    candidate = candidate.replace("..", "_")

    if not candidate:
        return fallback

    stem = candidate.split(".")[0].upper()
    if stem in _WINDOWS_RESERVED:
        candidate = f"_{candidate}"

    if len(candidate) > max_length:
        suffix = Path(candidate).suffix[:20]
        candidate = candidate[: max_length - len(suffix)] + suffix

    return candidate or fallback


def ensure_within(base: Path, candidate: Path) -> Path:
    """Resolve ``candidate`` and assert it stays inside ``base``."""
    base_resolved = base.resolve()
    candidate_resolved = Path(candidate).resolve()
    if candidate_resolved != base_resolved and base_resolved not in candidate_resolved.parents:
        from app.core.errors import ApiError

        raise ApiError(
            403,
            "path_traversal",
            "Resolved path escapes the permitted directory.",
            {"base": str(base_resolved)},
        )
    return candidate_resolved


# --- layout ----------------------------------------------------------------

def analysis_dir(analysis_id: str) -> Path:
    validate_analysis_id(analysis_id)
    return settings.analyses_dir / analysis_id


def analysis_objects_dir(analysis_id: str) -> Path:
    return analysis_dir(analysis_id) / "objects"


def upload_path(analysis_id: str, original_filename: str) -> Path:
    """Stable, server-side upload path. Never derived from user input alone."""
    validate_analysis_id(analysis_id)
    safe = safe_filename(original_filename, fallback="capture.pcap")
    suffix = Path(safe).suffix.lower() or ".pcap"
    return settings.uploads_dir / f"{analysis_id}{suffix}"


def ensure_analysis_dirs(analysis_id: str) -> Path:
    directory = analysis_dir(analysis_id)
    (directory / "objects").mkdir(parents=True, exist_ok=True)
    settings.uploads_dir.mkdir(parents=True, exist_ok=True)
    return directory


# --- hashing and sizing ----------------------------------------------------

def sha256_file(path: Path, chunk_size: int = 1 << 20) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for block in iter(lambda: handle.read(chunk_size), b""):
            digest.update(block)
    return digest.hexdigest()


def hash_file(path: Path) -> dict[str, str]:
    md5 = hashlib.md5()  # noqa: S324 - forensic identifier, not security
    sha1 = hashlib.sha1()  # noqa: S324 - forensic identifier, not security
    sha256 = hashlib.sha256()
    with open(path, "rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            md5.update(block)
            sha1.update(block)
            sha256.update(block)
    return {
        "md5": md5.hexdigest(),
        "sha1": sha1.hexdigest(),
        "sha256": sha256.hexdigest(),
    }


def dir_size(path: Path) -> int:
    total = 0
    if not path.exists():
        return 0
    for item in path.rglob("*"):
        try:
            if item.is_file():
                total += item.stat().st_size
        except OSError:
            continue
    return total


# --- capture format sniffing ----------------------------------------------

PCAP_MAGIC = {
    b"\xd4\xc3\xb2\xa1": "pcap",
    b"\xa1\xb2\xc3\xd4": "pcap",
    b"\x4d\x3c\xb2\xa1": "pcap",
    b"\xa1\xb2\x3c\x4d": "pcap",
    b"\x0a\x0d\x0d\x0a": "pcapng",
}


def sniff_capture_format(path: Path, first_bytes: bytes | None = None) -> str | None:
    """Return ``'pcap'``, ``'pcapng'`` or ``None`` from the file's magic bytes."""
    if first_bytes is None:
        try:
            with open(path, "rb") as handle:
                first_bytes = handle.read(4)
        except OSError:
            return None
    for magic, kind in PCAP_MAGIC.items():
        if first_bytes.startswith(magic):
            return kind
    return None


# --- deletion --------------------------------------------------------------

def delete_analysis(analysis_id: str) -> None:
    """Remove every on-disk artefact for one analysis.

    The analysis id is validated first, so ``shutil.rmtree`` can never be aimed
    at an arbitrary path.
    """
    validate_analysis_id(analysis_id)

    directory = analysis_dir(analysis_id)
    if directory.exists():
        ensure_within(settings.analyses_dir, directory)
        shutil.rmtree(directory, ignore_errors=True)
        log.info("removed analysis directory %s", directory)

    for candidate in settings.uploads_dir.glob(f"{analysis_id}.*"):
        try:
            if candidate.is_file():
                ensure_within(settings.uploads_dir, candidate)
                candidate.unlink()
                log.info("removed upload %s", candidate)
        except OSError as exc:  # pragma: no cover - best effort cleanup
            log.warning("could not remove %s: %s", candidate, exc)
