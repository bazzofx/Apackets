"""The images gallery's two backend facts: which objects count as images, and which of
them may be served inline.

The second is a security boundary, not a preference: an extracted object is data from an
untrusted capture, so the export route decides the media type itself and only ever draws a
raster image in the page. These tests pin that down."""

from __future__ import annotations

import time
from pathlib import Path

from app.core.config import settings
from app.db import database as db
from app.services import storage

ANALYSIS_ID = "0" * 31 + "1"

#: The smallest valid PNG: 1x1, transparent. Real bytes, so a browser could draw it.
PNG_BYTES = bytes.fromhex(
    "89504e470d0a1a0a0000000d49484452000000010000000108060000001f15c489"
    "0000000a49444154789c6360000002000100ffff03000006000557bfabd40000000049454e44ae426082"
)


def _analysis() -> None:
    now = time.time()
    with db.get_conn() as conn:
        conn.execute(
            """
            INSERT OR REPLACE INTO analyses (
                id, original_filename, stored_path, file_size, file_type, status,
                progress, stage, packet_count, created_at, updated_at
            ) VALUES (?, 'capture.pcap', 'x.pcap', 0, 'pcap', 'completed', 100, 'completed', 10, ?, ?)
            """,
            (ANALYSIS_ID, now, now),
        )


def _object(object_id: str, filename: str, content_type: str | None, payload: bytes) -> None:
    """One stored object: the row, and real bytes on disk where the route looks for them."""
    objects_dir = storage.analysis_objects_dir(ANALYSIS_ID)
    objects_dir.mkdir(parents=True, exist_ok=True)
    suffix = Path(filename).suffix or ".bin"
    relative = "objects/" + object_id + suffix
    (storage.analysis_dir(ANALYSIS_ID) / relative).write_bytes(payload)
    with db.get_conn() as conn:
        conn.execute(
            """
            INSERT OR REPLACE INTO objects (
                id, analysis_id, filename, original_filename, stored_path, protocol,
                content_type, size, sha256, sha1, md5, src_ip, dst_ip, src_port, dst_port,
                stream_id, packet_numbers, status, note, created_at
            ) VALUES (?, ?, ?, ?, ?, 'http', ?, ?, NULL, NULL, NULL, '10.0.0.1', '10.0.0.2',
                      51000, 80, 1, '[]', 'complete', NULL, ?)
            """,
            (object_id, ANALYSIS_ID, filename, filename, relative, content_type, len(payload), time.time()),
        )


def _seed() -> None:
    _analysis()
    _object("png1", "photo.png", "image/png", PNG_BYTES)
    # A carved body whose type was never recorded, only its name says what it is.
    _object("png2", "screenshot.PNG", None, PNG_BYTES)
    _object("txt1", "notes.txt", "text/plain", b"hello")
    # An SVG is a document that can carry script: it must never be drawn inline.
    _object("svg1", "logo.svg", "image/svg+xml", b"<svg xmlns='http://www.w3.org/2000/svg'/>")


def test_only_images_are_listed_by_the_image_filter(client) -> None:  # noqa: ARG001
    _seed()
    body = client.get(f"/api/analyses/{ANALYSIS_ID}/objects?content_type=image").json()
    names = sorted(item["filename"] for item in body["items"])
    # The screenshot has no recorded type at all; it is still an image, by its name.
    assert names == ["photo.png", "screenshot.PNG"]
    assert body["total"] == 2


def test_a_png_is_served_inline_when_asked(client) -> None:  # noqa: ARG001
    _seed()
    response = client.get(f"/api/analyses/{ANALYSIS_ID}/objects/png1/export?inline=1")
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("image/png")
    assert response.headers["content-disposition"].startswith("inline")
    assert response.headers["x-content-type-options"] == "nosniff"


def test_a_name_is_enough_to_draw_a_body_with_no_recorded_type(client) -> None:  # noqa: ARG001
    _seed()
    response = client.get(f"/api/analyses/{ANALYSIS_ID}/objects/png2/export?inline=1")
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("image/png")
    assert response.headers["content-disposition"].startswith("inline")


def test_inline_is_a_privilege_and_never_a_way_to_render_a_document(client) -> None:  # noqa: ARG001
    _seed()
    # A text file asked for inline is still an attachment...
    text = client.get(f"/api/analyses/{ANALYSIS_ID}/objects/txt1/export?inline=1")
    assert text.headers["content-disposition"].startswith("attachment")
    assert not text.headers["content-type"].startswith("image/")
    # ...and an SVG never is: it is a document, and this application does not render
    # capture content as active content.
    svg = client.get(f"/api/analyses/{ANALYSIS_ID}/objects/svg1/export?inline=1")
    assert svg.headers["content-disposition"].startswith("attachment")


def test_the_default_export_is_unchanged(client) -> None:  # noqa: ARG001
    _seed()
    response = client.get(f"/api/analyses/{ANALYSIS_ID}/objects/png1/export")
    assert response.status_code == 200
    assert response.headers["content-disposition"].startswith("attachment")
    assert response.content == PNG_BYTES
