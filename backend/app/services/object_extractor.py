"""HTTP object extraction.

TShark performs the actual extraction (``--export-objects http,<dir>``); this
module is responsible for everything that happens *after* a hostile capture has
produced files on disk:

* Extraction happens into a **staging directory inside the analysis directory**,
  never into a shared or user-visible location.
* Every extracted filename is treated as untrusted. The name is only ever used
  for display (``filename`` / ``original_filename``); the file on disk is renamed
  to a server-generated uuid4 whose value is the only thing the API accepts.
  ``storage.safe_filename`` and ``storage.ensure_within`` are applied to the
  final path, so a crafted name cannot escape the objects directory.
* Symlinks are never followed, oversized objects are refused and recorded as
  ``status='failed'`` rather than stored, and nothing is ever executed.
* ``stored_path`` is always relative to the analysis directory and always under
  ``objects/``.

Objects are correlated back to the capture through ``http_transactions``: the
filename TShark derives from a URI is reproduced from the indexed ``uri``
column, and the extracted size is compared with the body size the transaction
reports. When those two signals agree the object is tied to a stream, an
endpoint pair and the frames that carried it; when they do not, the object is
recorded with the uncertainty spelled out in ``note`` and no invented values.
"""

from __future__ import annotations

import json
import os
import shutil
import sqlite3
import time
import uuid
from collections.abc import Iterator
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from app.core.config import settings
from app.core.errors import ApiError
from app.core.logging import get_logger
from app.db import database as db
from app.services import storage, tshark

log = get_logger("apackets.objects")

STAGING_DIRNAME = "objects_staging"

# --------------------------------------------------------------------------
# small helpers
# --------------------------------------------------------------------------

def _as_int(value: Any) -> int | None:
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return int(value)
    text = str(value).strip()
    if not text:
        return None
    try:
        return int(text, 16) if text.lower().startswith("0x") else int(float(text))
    except ValueError:
        return None


def _as_text(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _parse_headers(raw: Any) -> dict[str, str]:
    """Header JSON from ``http_transactions`` as a lowercase-keyed mapping."""
    if not raw:
        return {}
    try:
        parsed = json.loads(raw) if isinstance(raw, str) else raw
    except (TypeError, ValueError):
        return {}
    if not isinstance(parsed, dict):
        return {}
    return {str(key).strip().lower(): str(value) for key, value in parsed.items()}


# --------------------------------------------------------------------------
# staging / directory safety
# --------------------------------------------------------------------------

def _reset_directory(target: Path, base: Path) -> Path:
    """Empty a directory that is proven to live inside ``base``."""
    resolved = storage.ensure_within(base, target)
    if resolved.exists():
        if resolved.is_symlink():
            resolved.unlink()
        elif resolved.is_dir():
            shutil.rmtree(resolved)
        else:
            resolved.unlink()
    resolved.mkdir(parents=True, exist_ok=True)
    return resolved


def _clear_directory(directory: Path, base: Path) -> None:
    """Remove every child of an existing directory without following symlinks."""
    resolved = storage.ensure_within(base, directory)
    if not resolved.exists() or not resolved.is_dir():
        return
    for entry in os.scandir(resolved):
        try:
            if entry.is_symlink() or entry.is_file(follow_symlinks=False):
                os.unlink(entry.path)
            elif entry.is_dir(follow_symlinks=False):
                shutil.rmtree(entry.path)
        except OSError as exc:  # best effort: a locked file must not abort extraction
            log.warning("could not remove %s: %s", entry.path, exc)


def _iter_files(root: Path) -> Iterator[Path]:
    """Every regular file under ``root``, following no symlinks whatsoever."""
    stack: list[Path] = [root]
    while stack:
        current = stack.pop()
        try:
            entries = sorted(os.scandir(current), key=lambda entry: entry.name)
        except OSError as exc:
            log.warning("could not list %s: %s", current, exc)
            continue
        for entry in entries:
            try:
                if entry.is_symlink():
                    log.warning("skipping symlink produced by object export: %s", entry.path)
                    continue
                if entry.is_dir(follow_symlinks=False):
                    stack.append(Path(entry.path))
                    continue
                if entry.is_file(follow_symlinks=False):
                    yield Path(entry.path)
            except OSError as exc:  # pragma: no cover - defensive
                log.warning("could not stat %s: %s", entry.path, exc)


# --------------------------------------------------------------------------
# correlation against the indexed HTTP transactions
# --------------------------------------------------------------------------

def tshark_object_name(uri: str) -> str:
    """Reproduce the filename TShark's ``--export-objects`` derives from a URI.

    Verified against TShark 4.6.8: the path is reduced to its last segment and a
    query string is appended with ``?`` escaped as ``%3f`` — ``/a/b.txt?x=1``
    becomes ``b.txt%3fx=1`` and ``/`` becomes ``%3fx=1``.
    """
    target = uri
    if "://" in target:
        split = urlsplit(target)
        target = f"{split.path}?{split.query}" if split.query else split.path
    path, _, query = target.partition("?")
    path = path.replace("\\", "/")
    basename = path.rsplit("/", 1)[-1]
    name = basename + ("%3f" + query if query else "")
    return name.lower()


def _normalise_exported_name(name: str) -> str:
    """Strip TShark's ``(1)``/``(2)`` duplicate suffix and normalise case."""
    text = (name or "").strip()
    while text.endswith(")"):
        head, _, tail = text[:-1].rpartition("(")
        if head and tail.isdigit():
            text = head
            continue
        break
    return text.lower()


def _load_transactions(analysis_id: str) -> list[dict[str, Any]]:
    try:
        rows = db.query_all(
            """
            SELECT id, stream_id, request_packet, response_packet, time_epoch,
                   client_ip, client_port, server_ip, server_port, method, host, uri,
                   full_uri, status_code, content_type, request_len, response_len,
                   request_headers, response_headers, request_body_size,
                   response_body_size, response_body_truncated
            FROM http_transactions WHERE analysis_id = ?
            ORDER BY COALESCE(time_epoch, 0), id
            """,
            (analysis_id,),
        )
    except sqlite3.Error as exc:
        log.warning("could not read http_transactions for %s: %s", analysis_id, exc)
        return []

    candidates: list[dict[str, Any]] = []
    for row in rows:
        uri = _as_text(row["uri"])
        if not uri:
            continue
        request_headers = _parse_headers(row["request_headers"])
        response_headers = _parse_headers(row["response_headers"])
        request_size = _as_int(row["request_body_size"])
        if request_size is None:
            request_size = _as_int(request_headers.get("content-length"))
        response_size = _as_int(row["response_body_size"])
        if response_size is None:
            response_size = _as_int(response_headers.get("content-length"))
        candidates.append(
            {
                "transaction_id": _as_int(row["id"]),
                "stream_id": _as_int(row["stream_id"]),
                "request_packet": _as_int(row["request_packet"]),
                "response_packet": _as_int(row["response_packet"]),
                "time_epoch": row["time_epoch"],
                "client_ip": _as_text(row["client_ip"]),
                "client_port": _as_int(row["client_port"]),
                "server_ip": _as_text(row["server_ip"]),
                "server_port": _as_int(row["server_port"]),
                "method": _as_text(row["method"]),
                "host": _as_text(row["host"]),
                "uri": uri,
                "status_code": _as_int(row["status_code"]),
                "content_type": _as_text(row["content_type"]),
                "request_content_type": _as_text(request_headers.get("content-type")),
                "request_size": request_size,
                "response_size": response_size,
                "response_body_truncated": _as_int(row["response_body_truncated"]),
                "object_name": tshark_object_name(uri),
                "object_name_fuzzy": storage.safe_filename(
                    tshark_object_name(uri), fallback=""
                ).lower(),
            }
        )
    return candidates


def _frames_for(
    analysis_id: str,
    *,
    stream_id: int | None,
    src_ip: str | None,
    lower: int | None,
    upper: int | None,
    limit: int = 50,
) -> tuple[list[int], bool]:
    """Frames carrying payload in one direction of a stream.

    Returns ``(frame_numbers, bounded)``; ``bounded`` is False when the
    transaction did not record a starting frame, meaning the frames are the
    earliest payload frames of that stream and direction rather than a proven
    window.
    """
    if stream_id is None:
        return [], False

    clauses = ["analysis_id = ?", "tcp_stream = ?", "tcp_len > 0", "number >= ?"]
    params: list[Any] = [analysis_id, stream_id, lower if lower else 1]
    bounded = lower is not None
    if src_ip:
        clauses.append("src_ip = ?")
        params.append(src_ip)
    if upper is not None:
        clauses.append("number <= ?")
        params.append(upper)
    params.append(limit)

    sql = (
        f"SELECT number FROM packets WHERE {' AND '.join(clauses)} "
        "ORDER BY number LIMIT ?"
    )
    try:
        rows = db.query_all(sql, tuple(params))
    except sqlite3.Error as exc:
        log.warning("could not read frames for stream %s: %s", stream_id, exc)
        return [], bounded
    return [int(row["number"]) for row in rows], bounded


def _correlate(
    analysis_id: str,
    *,
    original_filename: str,
    size: int,
    candidates: list[dict[str, Any]],
) -> dict[str, Any]:
    """Tie one extracted file back to the transaction it came from.

    A filename that resolves to a URI identifies a *transaction*; the body size
    then identifies whether the file is that transaction's request body or its
    response body. When either signal is missing the corresponding field is left
    empty and ``note`` says exactly which signal was unavailable.
    """
    result: dict[str, Any] = {
        "transaction": None,
        "kind": "unknown",
        "stream_id": None,
        "src_ip": None,
        "dst_ip": None,
        "src_port": None,
        "dst_port": None,
        "content_type": None,
        "packet_numbers": [],
        "note": None,
        "expected_size": None,
    }
    if not candidates:
        result["note"] = (
            "No HTTP transaction was indexed for this analysis, so the object could not be "
            "correlated to a stream or frame range."
        )
        return result

    normalised = _normalise_exported_name(original_filename)
    fuzzy = storage.safe_filename(original_filename, fallback="").lower()
    matches = [item for item in candidates if item["object_name"] == normalised]
    if not matches and fuzzy:
        matches = [item for item in candidates if item["object_name_fuzzy"] == fuzzy]
    if not matches:
        result["note"] = (
            f"No indexed HTTP transaction reported a URI that resolves to the exported name "
            f"'{original_filename}', so the object could not be tied to a stream or frame range."
        )
        return result

    if len(matches) > 1:
        # TShark names a second object for the same URI ``name(1)``, so several
        # transactions can share a name. The recorded body size breaks the tie.
        by_size = [
            item
            for item in matches
            if (item["response_size"] is not None and size == item["response_size"])
            or (item["request_size"] is not None and size == item["request_size"])
        ]
        if len(by_size) != 1:
            result["note"] = (
                f"{len(matches)} indexed HTTP transactions match the exported name "
                f"'{original_filename}' and none of them reports a body of {size} bytes, so no "
                "stream, endpoints or frames are asserted for this object."
            )
            return result
        matches = by_size

    transaction = matches[0]
    result["transaction"] = transaction
    result["stream_id"] = transaction["stream_id"]

    response_size = transaction["response_size"]
    request_size = transaction["request_size"]
    matches_response = response_size is not None and size == response_size
    matches_request = request_size is not None and size == request_size

    if matches_response and matches_request:
        result["note"] = (
            f"Both the request body and the response body recorded for "
            f"{transaction['uri']} are {size} bytes, so the direction of this object could not be "
            "determined from the capture."
        )
        return result

    if matches_response:
        kind = "response"
    elif matches_request:
        kind = "request"
    else:
        result["note"] = (
            f"'{transaction['uri']}' is the closest indexed HTTP transaction, but the extracted "
            f"size ({size} bytes) matches neither its recorded request body ({request_size}) nor "
            f"its recorded response body ({response_size}), so the direction of this object is not "
            "asserted."
        )
        return result

    result["kind"] = kind
    if kind == "response":
        result["src_ip"] = transaction["server_ip"]
        result["src_port"] = transaction["server_port"]
        result["dst_ip"] = transaction["client_ip"]
        result["dst_port"] = transaction["client_port"]
        result["content_type"] = transaction["content_type"]
        result["expected_size"] = response_size
    else:
        result["src_ip"] = transaction["client_ip"]
        result["src_port"] = transaction["client_port"]
        result["dst_ip"] = transaction["server_ip"]
        result["dst_port"] = transaction["server_port"]
        result["content_type"] = transaction["request_content_type"]
        result["expected_size"] = request_size

    frames, bounded = _frames_for(
        analysis_id,
        stream_id=transaction["stream_id"],
        src_ip=result["src_ip"],
        lower=transaction["request_packet"],
        upper=transaction["response_packet"] if kind == "response" else None,
        limit=50,
    )
    result["packet_numbers"] = frames

    notes: list[str] = []
    if not frames:
        notes.append(
            "The frames that carried the body could not be listed from the packet index "
            "(the stream or its payload frames are absent from the capture)."
        )
    elif kind == "request":
        notes.append(
            "The frames listed are the payload frames this client sent from the request frame "
            "onwards (capped at 50), which is the range that carried the request body."
        )
    elif not bounded:
        notes.append(
            "The transaction did not record a request frame, so the listed frames are the "
            "earliest payload frames of that stream in that direction rather than an exact window."
        )
    result["note"] = " ".join(notes) or None
    return result


# --------------------------------------------------------------------------
# extraction
# --------------------------------------------------------------------------

def _supports_export_objects() -> bool | None:
    """Ask TShark whether this build advertises ``--export-objects``.

    Only consulted when an export produced no files even though the index proves
    HTTP bodies exist, so it never produces noise on a capture without HTTP.
    """
    try:
        result = tshark.run(["--help"], timeout=20, allow_exit_codes=(0, 1, 2))
    except Exception as exc:  # pragma: no cover - defensive
        log.debug("tshark --help failed: %s", exc)
        return None
    text = f"{result.stdout or ''}{result.stderr or ''}"
    if "export-objects" in text:
        return True
    return False if text.strip() else None


def _export_warning(exc: BaseException) -> str:
    message = " ".join(str(exc).split())
    lowered = message.lower()
    unsupported = any(
        marker in lowered
        for marker in ("unknown option", "invalid option", "unrecognized option", "export-objects")
    )
    if unsupported:
        return (
            "This TShark build rejected --export-objects, so no HTTP objects were extracted "
            f"({message[:200]}). Analysis continues without extracted objects."
        )
    return (
        f"HTTP object export failed and no objects were extracted ({message[:200]}). "
        "Analysis continues without extracted objects."
    )


def _suffix_of(filename: str) -> str:
    """A short, sanitised extension taken from an untrusted name."""
    name = storage.safe_filename(filename, fallback="object")
    suffix = Path(name).suffix
    if not suffix or len(suffix) > 20:
        return ""
    return suffix


def _transaction_body_count(analysis_id: str) -> int:
    try:
        row = db.query_one(
            """
            SELECT COUNT(*) AS n FROM http_transactions
            WHERE analysis_id = ?
              AND (COALESCE(response_body_size, 0) > 0 OR COALESCE(request_body_size, 0) > 0
                   OR COALESCE(response_len, 0) > 0 OR COALESCE(request_len, 0) > 0)
            """,
            (analysis_id,),
        )
    except sqlite3.Error:
        return 0
    return int(row["n"]) if row else 0


INSERT_SQL = """
    INSERT OR REPLACE INTO objects
        (id, analysis_id, filename, original_filename, stored_path, protocol, content_type,
         size, sha256, sha1, md5, src_ip, dst_ip, src_port, dst_port, stream_id,
         packet_numbers, status, note, created_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
"""


def analyze(ctx: Any, analysis_id: str, capture_path: Path) -> dict:
    """Extract HTTP objects into the analysis ``objects/`` directory."""
    started = time.monotonic()
    # Validates the id before any filesystem work happens.
    analysis = storage.analysis_dir(analysis_id)
    objects_dir = storage.analysis_objects_dir(analysis_id)
    staging = analysis / STAGING_DIRNAME

    stats: dict[str, Any] = {
        "objects": 0,
        "extracted": 0,
        "complete": 0,
        "partial": 0,
        "failed": 0,
        "bytes": 0,
        "skipped_oversize": 0,
        "uncorrelated": 0,
        "warning": None,
        "seconds": 0.0,
    }

    limit_bytes = int(settings.max_object_bytes)
    _reset_directory(staging, analysis)
    objects_dir.mkdir(parents=True, exist_ok=True)

    if ctx is not None:
        ctx.check_cancelled()  # JobCancelled must propagate
        try:
            ctx.set_stage("Exporting HTTP objects")
        except Exception:  # pragma: no cover
            log.debug("could not publish object-export stage")

    try:
        tshark.export_objects(capture_path, staging, protocol="http")
    except tshark.JobCancelled:
        raise
    except (tshark.TsharkError, tshark.TsharkTimeout, OSError) as exc:
        warning = _export_warning(exc)
        log.warning("object export failed for %s: %s", analysis_id, exc)
        stats["warning"] = warning
        stats["seconds"] = round(time.monotonic() - started, 3)
        # Leave the previous run's rows alone and drop the temporary directory.
        try:
            _clear_directory(staging, analysis)
            shutil.rmtree(staging, ignore_errors=True)
        except Exception:  # pragma: no cover - best effort
            log.debug("could not clean staging directory %s", staging)
        return stats

    files = list(_iter_files(staging))
    if not files:
        expected = _transaction_body_count(analysis_id)
        if expected:
            support = _supports_export_objects()
            hint = (
                " tshark --help on this build does not list --export-objects."
                if support is False
                else ""
            )
            stats["warning"] = (
                f"TShark exported no objects although the index records {expected} HTTP "
                f"transaction(s) with a body.{hint}"
            )
            log.warning("no objects exported for %s (%s transactions with bodies)", analysis_id, expected)
        else:
            log.info("no HTTP objects to extract for %s", analysis_id)
        _clear_directory(staging, analysis)
        shutil.rmtree(staging, ignore_errors=True)
        stats["seconds"] = round(time.monotonic() - started, 3)
        return stats

    candidates = _load_transactions(analysis_id)
    created_at = time.time()

    # Only now that extraction produced files do we drop the previous run's rows.
    with db.get_conn() as conn:
        conn.execute("DELETE FROM objects WHERE analysis_id = ?", (analysis_id,))
    _clear_directory(objects_dir, analysis)

    rows: list[tuple] = []
    for index, staged in enumerate(files):
        if ctx is not None:
            ctx.check_cancelled()
            if index % 10 == 0:
                try:
                    ctx.set_stage(f"Storing extracted objects ({index + 1} of {len(files)})")
                except Exception:  # pragma: no cover
                    pass

        original_name = staged.name
        try:
            size = staged.stat().st_size
        except OSError as exc:
            log.warning("could not stat staged object %s: %s", staged, exc)
            continue

        object_id = uuid.uuid4().hex
        display_name = storage.safe_filename(original_name, fallback="object", max_length=160)

        if size > limit_bytes:
            # Refuse to store it. The row records why, with the real size.
            stats["skipped_oversize"] += 1
            stats["failed"] += 1
            try:
                staged.unlink()
            except OSError as exc:  # pragma: no cover - best effort
                log.warning("could not remove oversized staged object %s: %s", staged, exc)
            rows.append(
                (
                    object_id, analysis_id, display_name, original_name,
                    f"objects/{object_id}", "http", None, size, None, None, None,
                    None, None, None, None, None, "[]", "failed",
                    f"Object exceeds the {limit_bytes} byte storage limit "
                    f"(max_object_bytes); the extracted file ({size} bytes) was discarded instead "
                    "of being stored, so no hashes are recorded for it. Raise "
                    "max_object_bytes in Settings if this object has to be retained.",
                    created_at,
                )
            )
            log.info("refused oversized object %s (%d bytes)", original_name, size)
            continue

        disk_name = f"{object_id}{_suffix_of(display_name)}"
        try:
            destination = storage.ensure_within(objects_dir, objects_dir / disk_name)
        except ApiError:
            # ensure_within raises for a path that escapes; a uuid plus a
            # sanitised suffix can never legitimately do that.
            log.error("refusing object %s: resolved path escaped the objects directory", original_name)
            continue

        try:
            if destination.exists():
                destination.unlink()
            shutil.move(str(staged), str(destination))
        except OSError as exc:
            log.warning("could not move %s into place: %s", staged, exc)
            stats["failed"] += 1
            rows.append(
                (
                    object_id, analysis_id, display_name, original_name,
                    f"objects/{object_id}", "http", None, size, None, None, None,
                    None, None, None, None, None, "[]", "failed",
                    f"The extracted file could not be moved into the objects directory "
                    f"({type(exc).__name__}); no hashes are recorded.",
                    created_at,
                )
            )
            continue

        stored_size = destination.stat().st_size
        digests = storage.hash_file(destination)

        correlation = _correlate(
            analysis_id,
            original_filename=original_name,
            size=stored_size,
            candidates=candidates,
        )
        expected = correlation["expected_size"]
        notes: list[str] = []
        status = "complete"

        if correlation["kind"] not in {"response", "request"} or expected is None:
            notes.append(
                "Completeness could not be verified against the capture because this object could "
                "not be matched to a recorded HTTP body size."
            )
        elif stored_size < expected:
            status = "partial"
            notes.append(
                f"TShark exported {stored_size} bytes but the HTTP transaction reports {expected} "
                f"bytes for the {correlation['kind']} body; the object appears truncated "
                "(a capture snap length, a gap in the TCP stream, or chunked transfer encoding "
                "can all cause this)."
            )
        elif stored_size > expected:
            notes.append(
                f"The exported file is {stored_size} bytes while the transaction reports {expected} "
                f"bytes for the {correlation['kind']} body; the export may include framing or "
                "additional data."
            )
        if correlation["note"]:
            notes.append(correlation["note"])
        if correlation["transaction"] is None:
            stats["uncorrelated"] += 1

        rows.append(
            (
                object_id,
                analysis_id,
                display_name,
                original_name,
                f"objects/{disk_name}",
                "http",
                correlation["content_type"],
                stored_size,
                digests["sha256"],
                digests["sha1"],
                digests["md5"],
                correlation["src_ip"],
                correlation["dst_ip"],
                correlation["src_port"],
                correlation["dst_port"],
                correlation["stream_id"],
                json.dumps(correlation["packet_numbers"], separators=(",", ":")),
                status,
                " ".join(notes) or None,
                created_at,
            )
        )
        stats[status] = stats.get(status, 0) + 1
        stats["bytes"] += stored_size

    if rows:
        with db.get_conn() as conn:
            conn.executemany(INSERT_SQL, rows)

    stats["objects"] = len(rows)
    stats["extracted"] = stats["complete"] + stats["partial"]
    stats["seconds"] = round(time.monotonic() - started, 3)

    try:
        shutil.rmtree(staging, ignore_errors=True)
    except OSError:  # pragma: no cover - best effort
        pass

    log.info(
        "extracted %d HTTP object(s) for %s (%d complete, %d partial, %d failed, %d bytes) in %.2fs",
        stats["objects"],
        analysis_id,
        stats["complete"],
        stats["partial"],
        stats["failed"],
        stats["bytes"],
        stats["seconds"],
    )
    return stats


# --------------------------------------------------------------------------
# API support
# --------------------------------------------------------------------------

def object_path(analysis_id: str, object_id: str) -> Path:
    """Absolute path of one stored object, with traversal protection.

    Raises ``404 object_not_found`` when the row does not belong to the analysis,
    and ``403 path_traversal`` when the recorded ``stored_path`` resolves outside
    the analysis ``objects/`` directory.
    """
    # Raises 400 invalid_analysis_id for a malformed id.
    analysis = storage.analysis_dir(analysis_id)
    objects_dir = storage.analysis_objects_dir(analysis_id)

    row = db.query_one(
        "SELECT id, analysis_id, stored_path FROM objects WHERE id = ? AND analysis_id = ?",
        (object_id, analysis_id),
    )
    if row is None:
        raise ApiError(
            404,
            "object_not_found",
            "No extracted object with that identifier exists for this analysis.",
            {"object_id": object_id, "analysis_id": analysis_id},
        )

    stored = _as_text(row["stored_path"])
    if not stored:
        raise ApiError(
            404,
            "object_not_found",
            "The object row has no stored path recorded.",
            {"object_id": object_id},
        )

    # The stored path is relative to the analysis directory and must stay inside
    # objects/: ensure_within raises 403 path_traversal otherwise.
    candidate = analysis / stored
    return storage.ensure_within(objects_dir, candidate)


__all__ = [
    "STAGING_DIRNAME",
    "analyze",
    "object_path",
    "tshark_object_name",
]
