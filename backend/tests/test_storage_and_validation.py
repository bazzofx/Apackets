"""Storage layout, path-traversal protection and upload validation."""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from app.core.config import settings
from app.core.errors import ApiError
from app.services import capture_parser, storage


# --------------------------------------------------------------------------
# safe_filename
# --------------------------------------------------------------------------

@pytest.mark.parametrize(
    "hostile",
    [
        "../../etc/passwd",
        "..\\..\\windows\\system32\\config",
        "/absolute/path/evil.pcap",
        "C:\\Windows\\System32\\evil.pcap",
        "....//....//evil.pcap",
        "..%2f..%2fevil.pcap",
        "a/b/c/../../d.pcap",
    ],
)
def test_safe_filename_strips_directories_and_traversal(hostile):
    result = storage.safe_filename(hostile)
    assert "/" not in result
    assert "\\" not in result
    assert ".." not in result
    assert not result.startswith(".")
    assert result


def test_safe_filename_removes_control_characters():
    result = storage.safe_filename("bad\x00name\x1b[31m.pcap")
    assert "\x00" not in result
    assert "\x1b" not in result


def test_safe_filename_guards_windows_reserved_names():
    for reserved in ("CON.pcap", "PRN", "aux.txt", "COM1.pcap", "LPT9.cap"):
        result = storage.safe_filename(reserved)
        stem = result.split(".")[0].upper()
        assert stem not in storage._WINDOWS_RESERVED


def test_safe_filename_falls_back_for_empty_input():
    assert storage.safe_filename("") == "unnamed"
    assert storage.safe_filename("///") == "unnamed"
    assert storage.safe_filename("...") == "unnamed"


def test_safe_filename_truncates_absurdly_long_names():
    result = storage.safe_filename("a" * 5000 + ".pcap")
    assert len(result) <= 180


def test_safe_filename_keeps_a_sane_name_intact():
    assert storage.safe_filename("capture-2024.pcapng") == "capture-2024.pcapng"


# --------------------------------------------------------------------------
# ensure_within
# --------------------------------------------------------------------------

def test_ensure_within_allows_a_child_path(scratch_dir: Path):
    base = scratch_dir / "base"
    base.mkdir(exist_ok=True)
    child = base / "inside.txt"
    child.write_text("x")
    assert storage.ensure_within(base, child) == child.resolve()


@pytest.mark.parametrize(
    "escape", ["../outside.txt", "../../etc/passwd", "a/../../outside.txt"]
)
def test_ensure_within_rejects_escapes(scratch_dir: Path, escape: str):
    base = scratch_dir / "base"
    base.mkdir(exist_ok=True)
    with pytest.raises(ApiError) as excinfo:
        storage.ensure_within(base, base / escape)
    assert excinfo.value.status_code == 403
    assert excinfo.value.code == "path_traversal"


# --------------------------------------------------------------------------
# analysis identifiers and layout
# --------------------------------------------------------------------------

def test_new_analysis_id_is_hex32_and_unique():
    ids = {storage.new_analysis_id() for _ in range(50)}
    assert len(ids) == 50
    for value in ids:
        assert len(value) == 32
        assert all(ch in "0123456789abcdef" for ch in value)


@pytest.mark.parametrize(
    "bad", ["", "abc", "../../etc", "A" * 32, "z" * 32, "0" * 31, "0" * 33, None]
)
def test_validate_analysis_id_rejects_malformed(bad):
    with pytest.raises(ApiError):
        storage.validate_analysis_id(bad)  # type: ignore[arg-type]


def test_upload_path_is_derived_from_the_id_not_the_filename():
    analysis_id = storage.new_analysis_id()
    hostile = storage.upload_path(analysis_id, "../../../evil.pcap")
    benign = storage.upload_path(analysis_id, "innocent.pcap")

    # Same directory, id-based stem, extension preserved.
    assert hostile.parent == benign.parent == settings.uploads_dir
    assert hostile.name == f"{analysis_id}.pcap"
    assert benign.name == f"{analysis_id}.pcap"


def test_upload_path_forces_a_capture_extension():
    analysis_id = storage.new_analysis_id()
    assert storage.upload_path(analysis_id, "no-extension").suffix == ".pcap"
    assert storage.upload_path(analysis_id, "x.pcapng").suffix == ".pcapng"


def test_ensure_analysis_dirs_creates_objects_subdirectory():
    analysis_id = storage.new_analysis_id()
    directory = storage.ensure_analysis_dirs(analysis_id)
    assert (directory / "objects").is_dir()
    assert directory == settings.analyses_dir / analysis_id


# --------------------------------------------------------------------------
# hashing and format sniffing
# --------------------------------------------------------------------------

def test_hash_file_returns_real_digests(scratch_dir: Path):
    payload = b"shadowpackets" * 1000
    target = scratch_dir / "hashme.bin"
    target.write_bytes(payload)

    import hashlib

    digests = storage.hash_file(target)
    assert digests["sha256"] == hashlib.sha256(payload).hexdigest()
    assert digests["sha1"] == hashlib.sha1(payload).hexdigest()
    assert digests["md5"] == hashlib.md5(payload).hexdigest()


def test_sha256_file_matches_hashlib(scratch_dir: Path):
    import hashlib

    payload = bytes(range(256)) * 512  # larger than the 1 MiB read chunk? no, but mixed
    target = scratch_dir / "chunked.bin"
    target.write_bytes(payload)
    assert storage.sha256_file(target) == hashlib.sha256(payload).hexdigest()


@pytest.mark.parametrize(
    "magic,expected",
    [
        (b"\xd4\xc3\xb2\xa1", "pcap"),
        (b"\xa1\xb2\xc3\xd4", "pcap"),
        (b"\x4d\x3c\xb2\xa1", "pcap"),
        (b"\x0a\x0d\x0d\x0a", "pcapng"),
    ],
)
def test_sniff_capture_format(scratch_dir: Path, magic: bytes, expected: str):
    target = scratch_dir / f"magic-{magic.hex()}.bin"
    target.write_bytes(magic + b"\x00" * 60)
    assert storage.sniff_capture_format(target) == expected


def test_sniff_capture_format_rejects_other_files(scratch_dir: Path):
    target = scratch_dir / "notacapture.bin"
    target.write_bytes(b"PK\x03\x04 this is a zip")
    assert storage.sniff_capture_format(target) is None


def test_dir_size_sums_files(scratch_dir: Path):
    directory = scratch_dir / "sized"
    directory.mkdir(exist_ok=True)
    (directory / "a.bin").write_bytes(b"x" * 100)
    (directory / "b.bin").write_bytes(b"y" * 250)
    (directory / "sub").mkdir(exist_ok=True)
    (directory / "sub" / "c.bin").write_bytes(b"z" * 50)
    assert storage.dir_size(directory) == 400


# --------------------------------------------------------------------------
# deletion
# --------------------------------------------------------------------------

def test_delete_analysis_removes_directory_and_upload():
    analysis_id = storage.new_analysis_id()
    storage.ensure_analysis_dirs(analysis_id)
    (storage.analysis_objects_dir(analysis_id) / "obj.bin").write_bytes(b"payload")
    upload = storage.upload_path(analysis_id, "x.pcap")
    upload.write_bytes(b"capture")

    storage.delete_analysis(analysis_id)

    assert not storage.analysis_dir(analysis_id).exists()
    assert not upload.exists()


def test_delete_analysis_refuses_a_traversal_id():
    with pytest.raises(ApiError):
        storage.delete_analysis("../../important")


def test_delete_analysis_is_idempotent_for_missing_ids():
    storage.delete_analysis(storage.new_analysis_id())  # must not raise


# --------------------------------------------------------------------------
# capture validation (capture_parser.inspect)
# --------------------------------------------------------------------------

def test_inspect_accepts_a_real_capture(http_capture: Path):
    import generators

    info = capture_parser.inspect(http_capture, original_filename="http.pcap")
    assert info.file_type == "pcap"
    assert info.encapsulation == "ether"
    assert info.packet_count == generators.expected("http")["packets"]
    assert info.sha256 and len(info.sha256) == 64
    assert info.file_size == http_capture.stat().st_size


def test_inspect_rejects_an_empty_file(scratch_dir: Path):
    target = scratch_dir / "empty.pcap"
    target.write_bytes(b"")
    with pytest.raises(ApiError) as excinfo:
        capture_parser.inspect(target, original_filename="empty.pcap")
    assert excinfo.value.status_code == 400
    assert excinfo.value.code == "empty_file"


def test_inspect_rejects_a_non_capture(scratch_dir: Path):
    target = scratch_dir / "notacapture.pcap"
    target.write_bytes(b"this is plainly not a pcap file at all")
    with pytest.raises(ApiError) as excinfo:
        capture_parser.inspect(target, original_filename="notacapture.pcap")
    assert excinfo.value.status_code == 415
    assert excinfo.value.code == "unsupported_file_type"


def test_inspect_accepts_an_empty_but_valid_capture(empty_capture: Path):
    """A capture with zero packets is valid; it just has no data."""
    info = capture_parser.inspect(empty_capture, original_filename="empty.pcap")
    assert info.packet_count == 0
    assert info.warnings, "an empty capture should warn about having no packets"


def test_inspect_handles_a_malformed_capture(malformed_capture: Path):
    """A capture with a corrupt record after valid packets must not crash.

    ``capinfos`` counts packet *records* in the file, so a record whose payload is
    garbage is still counted; what matters is that the valid packets are not lost
    and that nothing raises.
    """
    import generators

    expectations = generators.expected("malformed")

    try:
        info = capture_parser.inspect(malformed_capture, original_filename="malformed.pcap")
    except ApiError as exc:
        # Rejecting it outright is also acceptable, as long as it is orderly.
        assert exc.status_code in {400, 415}
        assert exc.code in {"invalid_capture", "unsupported_file_type"}
        return

    assert info.packet_count is not None
    assert info.packet_count >= expectations["valid_packets"], (
        "the valid packets must not be lost when a later record is corrupt"
    )


def test_inspect_reports_truncated_capture(truncated_capture: Path):
    """A capture cut off mid-packet exposes fewer packets than it declares."""
    import generators

    expectations = generators.expected("truncated")
    try:
        info = capture_parser.inspect(truncated_capture, original_filename="truncated.pcap")
    except ApiError as exc:
        assert exc.status_code in {400, 415}
        return

    assert info.packet_count is not None
    assert info.packet_count < expectations["full_packets"]
    assert info.packet_count == expectations["readable_packets"]


def test_inspect_rejects_a_bad_extension(scratch_dir: Path, http_capture: Path):
    target = scratch_dir / "renamed.txt"
    shutil.copy(http_capture, target)
    with pytest.raises(ApiError) as excinfo:
        capture_parser.inspect(target, original_filename="renamed.txt")
    assert excinfo.value.status_code == 415


def test_validate_extension_is_case_insensitive():
    assert capture_parser.validate_extension("CAP.PCAP") == ".pcap"
    assert capture_parser.validate_extension("x.PcapNg") == ".pcapng"
    with pytest.raises(ApiError):
        capture_parser.validate_extension("x.txt")


def test_inspect_missing_file_is_404(scratch_dir: Path):
    with pytest.raises(ApiError) as excinfo:
        capture_parser.inspect(scratch_dir / "does-not-exist.pcap")
    assert excinfo.value.status_code == 404


def test_summary_text_is_human_readable(http_capture: Path):
    info = capture_parser.inspect(http_capture, original_filename="http.pcap")
    text = capture_parser.summary_text(info)
    assert "packets" in text
    assert "ether" in text
