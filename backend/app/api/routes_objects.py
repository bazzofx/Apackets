"""Extracted-object API.

* ``GET  /api/analyses/{id}/objects``                     — paginated envelope
* ``GET  /api/analyses/{id}/objects/{object_id}/export``  — attachment download
* ``POST /api/analyses/{id}/objects/extract``             — re-run extraction

Security notes that this router depends on and must not weaken:

* ``object_id`` is the **only** handle the API accepts. It is a server-generated
  uuid4, so a capture-derived filename can never become a path or URL.
* The stored path is resolved and checked against the analysis ``objects/``
  directory on every request (:func:`app.services.object_extractor.object_path`),
  which raises ``403 path_traversal`` for anything that escapes — including a row
  whose ``stored_path`` was tampered with.
* Downloads always carry ``Content-Disposition: attachment``,
  ``X-Content-Type-Options: nosniff`` and an allow-listed ``Content-Type``; when
  the recorded type is not on the allow list the response falls back to
  ``application/octet-stream`` and the observed type is reported in
  ``X-Object-Content-Type`` instead of being handed to the browser.
"""

from __future__ import annotations

from pathlib import Path

from fastapi import APIRouter, Depends, Query
from fastapi.responses import FileResponse

from app.api import deps
from app.core.errors import ApiError, bad_request
from app.core.logging import get_logger
from app.db import database as db
from app.services import detection_engine, object_extractor, storage

log = get_logger("shadowpackets.api.objects")

router = APIRouter(prefix="/api/analyses", tags=["objects"])

_SORT_COLUMNS: dict[str, str] = {
    "filename": "filename",
    "size": "size",
    "created_at": "created_at",
    "status": "status",
    "content_type": "content_type",
}

# Only these types are ever sent as Content-Type. Everything else is served as
# application/octet-stream with the real type in X-Object-Content-Type.
SAFE_CONTENT_TYPES: frozenset[str] = frozenset(
    {
        "application/gzip",
        "application/json",
        "application/octet-stream",
        "application/pdf",
        "application/rtf",
        "application/vnd.ms-excel",
        "application/x-7z-compressed",
        "application/x-tar",
        "application/xml",
        "application/zip",
        "audio/mpeg",
        "font/otf",
        "font/ttf",
        "image/bmp",
        "image/gif",
        "image/jpeg",
        "image/png",
        "image/tiff",
        "image/vnd.microsoft.icon",
        "image/webp",
        "image/x-icon",
        "text/css",
        "text/csv",
        "text/html",
        "text/javascript",
        "text/plain",
        "text/xml",
        "video/mp4",
    }
)


def _escape_like(term: str) -> str:
    """Neutralise LIKE wildcards so a search term is matched literally."""
    return term.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def _order_clause(sort: str | None, order: str | None) -> str:
    """ORDER BY clause from allow-listed columns only.

    See ``routes_findings._order_clause``: the shared ``deps`` sort helpers
    currently raise ``TypeError`` on their error path because they pass a
    positional details dict to ``errors.bad_request``. The narrow fallback keeps
    the documented ``400 invalid_sort`` behaviour until that is fixed.
    """
    try:
        column = deps.resolve_sort(sort, _SORT_COLUMNS, "filename")
        direction = deps.resolve_order(order, "asc")
    except ApiError:
        raise
    except TypeError:
        key = (sort or "").strip().lstrip("-")
        if key not in _SORT_COLUMNS:
            raise bad_request(
                "invalid_sort",
                f"Cannot sort by '{sort}'.",
                allowed=sorted(_SORT_COLUMNS),
            ) from None
        value = (order or "asc").strip().lower()
        if value not in {"asc", "desc"}:
            raise bad_request(
                "invalid_order",
                "Order must be 'asc' or 'desc'.",
                order=order,
            ) from None
        column, direction = _SORT_COLUMNS[key], value.upper()
    return f"{column} {direction}, id ASC"


def _header_safe(value: str, limit: int = 200) -> str:
    """Make a capture-derived string safe to place in a response header."""
    cleaned = "".join(ch if 32 <= ord(ch) < 127 else " " for ch in value)
    return " ".join(cleaned.split())[:limit]


def _parse_array(raw: str | None) -> list:
    parsed = deps.json_or(raw, [])
    return parsed if isinstance(parsed, list) else []


def _serialise(row) -> dict:
    data = dict(row)
    data["packet_numbers"] = [
        int(number) for number in _parse_array(data.get("packet_numbers")) if isinstance(number, int)
    ]
    data["export_url"] = f"/api/analyses/{data['analysis_id']}/objects/{data['id']}/export"
    return data


def _content_type(row) -> tuple[str, str | None]:
    """(safe Content-Type for the response, observed type for the diagnostics header)."""
    observed = _header_safe(str(row["content_type"] or ""))
    if not observed:
        return "application/octet-stream", None
    media_type = observed.split(";", 1)[0].strip().lower()
    if media_type in SAFE_CONTENT_TYPES:
        return media_type, observed
    return "application/octet-stream", observed



#: Raster image types the browser may be asked to draw inline.
#:
#: SVG is deliberately absent: an SVG is a document that can carry script, and this
#: application never executes or renders capture content as active content. Everything
#: here is a bitmap a browser decodes and draws, nothing more.
INLINE_IMAGE_TYPES: frozenset[str] = frozenset(
    {
        "image/avif",
        "image/bmp",
        "image/gif",
        "image/jpeg",
        "image/png",
        "image/tiff",
        "image/vnd.microsoft.icon",
        "image/webp",
        "image/x-icon",
    }
)

#: Filename suffix -> media type, used when the capture recorded no usable type. Many
#: carved bodies arrive as `application/octet-stream` (or with no type at all) even when
#: the bytes are an image, and the suffix is the only evidence there is.
_IMAGE_SUFFIXES: dict[str, str] = {
    ".avif": "image/avif",
    ".bmp": "image/bmp",
    ".gif": "image/gif",
    ".ico": "image/vnd.microsoft.icon",
    ".jpeg": "image/jpeg",
    ".jpg": "image/jpeg",
    ".png": "image/png",
    ".tif": "image/tiff",
    ".tiff": "image/tiff",
    ".webp": "image/webp",
}


def _image_media_type(row) -> str | None:
    """The image type this object can honestly be served as, or None.

    The recorded content type wins; the filename suffix is the fallback, because a
    carved body frequently records `application/octet-stream` while the name says what
    it actually is. A browser that receives the wrong raster type simply fails to draw
    it - there is no execution path in a PNG, a GIF or an icon.
    """
    media_type, _ = _content_type(row)
    if media_type in INLINE_IMAGE_TYPES:
        return media_type
    suffix = Path(str(row["filename"] or "")).suffix.lower()
    return _IMAGE_SUFFIXES.get(suffix)

@router.get("/{analysis_id}/objects")
def list_objects(
    analysis_id: str,
    pager: deps.Pagination = Depends(deps.pagination),
    sort: str | None = Query(None, description="filename | size | created_at | status"),
    order: str | None = Query(None, description="asc | desc"),
    status: str | None = Query(None, description="complete | partial | failed"),
    search: str | None = Query(None, description="Substring of the displayed filename"),
    content_type: str | None = Query(
        None,
        description=("Family prefix, e.g. 'image'. 'image' also matches image file names whose "
                     "recorded type is missing or generic, which is how carved bodies arrive."),
    ),
) -> dict:
    """Paginated extracted objects for one analysis."""
    deps.get_ready_analysis(analysis_id)

    where = ["analysis_id = ?"]
    params: list[object] = [analysis_id]
    if status and status.strip():
        where.append("status = ?")
        params.append(status.strip())
    if search and search.strip():
        term = f"%{_escape_like(search.strip())}%"
        where.append("(filename LIKE ? ESCAPE '\\' OR original_filename LIKE ? ESCAPE '\\')")
        params.extend([term, term])
    if content_type and content_type.strip():
        family = content_type.strip().lower().split(";", 1)[0].strip().rstrip("/")
        if family == "image":
            # An image is an image whether or not the capture recorded a type for it.
            suffix_clause = " OR ".join("lower(filename) LIKE ?" for _ in _IMAGE_SUFFIXES)
            where.append(
                "(COALESCE(lower(content_type), '') LIKE ? OR " + suffix_clause + ")"
            )
            params.append("image/%")
            params.extend(f"%{suffix}" for suffix in _IMAGE_SUFFIXES)
            # An SVG is not drawn anywhere in this application - it is a document that can
            # carry script - so it is not offered to a gallery either. It stays visible on
            # Files and Objects, where every carved file is listed by name.
            where.append("COALESCE(lower(content_type), '') NOT LIKE ?")
            params.append("image/svg%")
        else:
            where.append("COALESCE(lower(content_type), '') LIKE ?")
            params.append(f"{family}/%")

    clause = " AND ".join(where)
    order_sql = _order_clause(sort, order)

    total_row = db.query_one(f"SELECT COUNT(*) AS n FROM objects WHERE {clause}", tuple(params))
    total = int(total_row["n"]) if total_row else 0

    rows = db.query_all(
        f"""
        SELECT id, analysis_id, filename, original_filename, stored_path, protocol,
               content_type, size, sha256, sha1, md5, src_ip, dst_ip, src_port,
               dst_port, stream_id, packet_numbers, status, note, created_at
        FROM objects WHERE {clause}
        ORDER BY {order_sql}
        LIMIT ? OFFSET ?
        """,
        tuple([*params, pager.limit, pager.offset]),
    )

    envelope = pager.envelope([_serialise(row) for row in rows], total)
    summary = db.query_one(
        """
        SELECT COUNT(*) AS total, COALESCE(SUM(size), 0) AS bytes,
               SUM(CASE WHEN status = 'complete' THEN 1 ELSE 0 END) AS complete,
               SUM(CASE WHEN status = 'partial' THEN 1 ELSE 0 END) AS partial,
               SUM(CASE WHEN status = 'failed' THEN 1 ELSE 0 END) AS failed
        FROM objects WHERE analysis_id = ?
        """,
        (analysis_id,),
    )
    if summary is not None:
        envelope["totals"] = {
            "objects": int(summary["total"] or 0),
            "bytes": int(summary["bytes"] or 0),
            "complete": int(summary["complete"] or 0),
            "partial": int(summary["partial"] or 0),
            "failed": int(summary["failed"] or 0),
        }
    return envelope


@router.get("/{analysis_id}/objects/{object_id}/export")
def export_object(
    analysis_id: str,
    object_id: str,
    inline: bool = Query(
        False,
        description=("Serve a raster image inline, so a gallery can draw it. Anything that "
                     "is not a raster image is still an attachment, whatever this says."),
    ),
) -> FileResponse:
    """Download one extracted object, as an attachment unless it is a raster image asked for inline."""
    deps.get_ready_analysis(analysis_id)

    row = db.query_one(
        """
        SELECT id, analysis_id, filename, content_type, stored_path, status
        FROM objects WHERE id = ? AND analysis_id = ?
        """,
        (object_id, analysis_id),
    )
    if row is None:
        raise ApiError(
            404,
            "object_not_found",
            f"No extracted object with id {object_id} in this analysis.",
            {"object_id": object_id, "analysis_id": analysis_id},
        )

    # Raises 403 path_traversal when the recorded path escapes objects/.
    path: Path = object_extractor.object_path(analysis_id, object_id)

    if not path.is_file() or path.is_symlink():
        raise ApiError(
            410,
            "object_missing",
            "The object row exists but its file is no longer present on disk.",
            {"object_id": object_id, "status": row["status"]},
        )

    # The download name is the sanitised name only; the file on disk is named
    # after the server-generated id.
    filename = storage.safe_filename(str(row["filename"] or path.name), fallback="object.bin")
    filename = _header_safe(filename, limit=160) or "object.bin"
    media_type, observed = _content_type(row)

    # Inline is a privilege, not a request: only a raster image type may be drawn in the
    # page, and the type is decided here rather than trusted from the query string.
    image_type = _image_media_type(row) if inline else None
    if image_type is not None:
        media_type = image_type

    headers = {
        "Content-Disposition": (
            f'inline; filename="{filename}"' if image_type is not None else f'attachment; filename="{filename}"'
        ),
        "X-Content-Type-Options": "nosniff",
        # A gallery re-reads the same handful of images on every visit; an attachment is
        # a one-off download and stays uncached.
        "Cache-Control": "private, max-age=3600" if image_type is not None else "no-store",
    }
    if observed:
        headers["X-Object-Content-Type"] = observed

    log.info("exporting object %s (%s) for analysis %s", object_id, filename, analysis_id)
    return FileResponse(
        path=str(path),
        media_type=media_type,
        filename=filename,
        headers=headers,
    )


@router.post("/{analysis_id}/objects/extract")
def extract_objects(analysis_id: str) -> dict:
    """Re-run HTTP object extraction for this analysis."""
    row = deps.get_ready_analysis(analysis_id)
    capture = deps.capture_path(row)

    ctx = detection_engine.InlineJobContext(analysis_id=analysis_id)
    stats = object_extractor.analyze(ctx, analysis_id, capture)

    log.info("extraction for %s stored %s object(s)", analysis_id, stats.get("extracted"))
    return {
        "ok": True,
        "extracted": int(stats.get("extracted") or 0),
        "objects": int(stats.get("objects") or 0),
        "by_status": {
            "complete": int(stats.get("complete") or 0),
            "partial": int(stats.get("partial") or 0),
            "failed": int(stats.get("failed") or 0),
        },
        "bytes": int(stats.get("bytes") or 0),
        "warning": stats.get("warning"),
        "seconds": stats.get("seconds"),
    }
