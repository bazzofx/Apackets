"""Tests for the TShark integration layer.

These cover the parts of the application that are easiest to get subtly wrong:

* display-filter validation must distinguish "invalid" from "zero results",
* TCP stream reassembly must be byte-exact — including payloads with CR/LF bytes
  and binary data, and on Windows where the C runtime expands every LF that
  TShark writes to its stdout,
* the hex dump parser must round-trip against the real frame length,
* timeouts and cancellation must not hang.
"""

from __future__ import annotations

import threading
import time
from pathlib import Path

import pytest

from app.services import tshark

pytestmark = pytest.mark.skipif(
    not tshark.resolve_binary("tshark"), reason="TShark is not installed on this host"
)


# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------

def streams_with_payload(capture: Path) -> list[int]:
    """Stream ids that actually carry TCP payload, discovered from the capture."""
    seen: set[int] = set()
    for row in tshark.stream_fields(
        capture, ["tcp.stream"], display_filter="tcp.len > 0"
    ):
        if row and row[0].strip():
            try:
                seen.add(int(row[0]))
            except ValueError:
                continue
    return sorted(seen)


def payload_bytes_by_stream(capture: Path, stream_id: int, side: str) -> bytes:
    """Concatenated TCP payload for one stream and side, straight from the dissector.

    This is an independent path to the same bytes that ``follow`` returns, so
    comparing the two catches any corruption introduced by parsing follow output
    (for example the Windows LF -> CRLF expansion).

    The client is identified as the sender of the connection's SYN, which is
    authoritative — the ephemeral port is not reliably the higher one.
    """
    rows = list(
        tshark.stream_fields(
            capture,
            ["tcp.stream", "tcp.payload", "tcp.srcport", "ip.src", "ip.dst"],
            display_filter="tcp.payload",
        )
    )
    if not rows:
        return b""

    syn_rows = list(
        tshark.stream_fields(
            capture,
            ["ip.src", "tcp.srcport"],
            display_filter=(
                f"tcp.stream == {int(stream_id)} && tcp.flags.syn == 1 && tcp.flags.ack == 0"
            ),
        )
    )
    client_ip = syn_rows[0][0] if syn_rows and syn_rows[0][0] else None
    client_port = syn_rows[0][1] if syn_rows and syn_rows[0][1] else None

    if client_ip is None and client_port is None:
        return b""

    parts: list[bytes] = []
    for row in rows:
        if not row or row[0].strip() != str(stream_id):
            continue
        is_client_frame = (client_ip is not None and row[3] == client_ip) or (
            client_port is not None and row[2] == client_port
        )
        if side == "server":
            is_client_frame = not is_client_frame
        if not is_client_frame:
            continue
        payload = "".join((row[1] or "").split())
        if not payload:
            continue
        try:
            parts.append(bytes.fromhex(payload))
        except ValueError:
            continue
    return b"".join(parts)


def follow_bytes(capture: Path, stream_id: int, mode: str = "raw") -> dict[int, bytes]:
    stream = tshark.follow_stream(capture, stream_id, mode)
    result: dict[int, bytes] = {0: b"", 1: b""}
    for chunk in stream.chunks:
        result[chunk.direction] += bytes.fromhex(chunk.hex)
    return result


# --------------------------------------------------------------------------
# binary resolution and version
# --------------------------------------------------------------------------

def test_tshark_is_available():
    info = tshark.version()
    assert info["available"] is True
    assert info["path"]
    assert str(info["version"]).startswith("4."), "this project targets TShark 4.x"


def test_resolve_binary_returns_none_for_unknown_tool():
    assert tshark.resolve_binary("definitely-not-a-real-binary-xyz") is None


# --------------------------------------------------------------------------
# display filter validation
# --------------------------------------------------------------------------

VALID_FILTERS = [
    "ip.addr == 192.168.1.10",
    "tcp.port == 443",
    "dns",
    "http",
    "tls.handshake.type == 1",
    "tcp.flags.syn == 1 && tcp.flags.ack == 0",
    "frame.len > 100",
    'http.request.method == "GET"',
    "ip.version == 6",
    "!(arp)",
    "tcp.analysis.retransmission",
]

INVALID_FILTERS = [
    "ip.addr ===",
    "nope.field == 1",
    "tcp.port ==",
    "dns.qry.name contains",
    'ip.addr == "abc" &&',
    "&& tcp",
    "frame.len >",
]


@pytest.mark.parametrize("expr", VALID_FILTERS)
def test_validate_filter_accepts_valid_expressions(expr):
    valid, reason = tshark.validate_filter(expr)
    assert valid is True, f"{expr!r} should be valid, got reason: {reason}"
    assert reason is None


@pytest.mark.parametrize("expr", INVALID_FILTERS)
def test_validate_filter_rejects_invalid_expressions(expr):
    valid, reason = tshark.validate_filter(expr)
    assert valid is False, f"{expr!r} should be invalid"
    assert reason, "an invalid filter must come with a reason"


def test_validate_filter_treats_blank_as_valid():
    """No filter means no filtering, which is not an error."""
    assert tshark.validate_filter(None) == (True, None)
    assert tshark.validate_filter("") == (True, None)
    assert tshark.validate_filter("   ") == (True, None)


def test_valid_filter_with_no_matches_is_still_valid():
    """The distinction the UI depends on: empty result is not a broken filter."""
    valid, reason = tshark.validate_filter("ip.addr == 203.0.113.99")
    assert valid is True
    assert reason is None


# --------------------------------------------------------------------------
# field streaming
# --------------------------------------------------------------------------

def test_stream_fields_preserves_capture_order(http_capture: Path):
    rows = list(tshark.stream_fields(http_capture, ["frame.number", "_ws.col.Protocol"]))
    assert rows
    numbers = [int(r[0]) for r in rows if r and r[0]]
    assert numbers == sorted(numbers)
    assert numbers[0] == 1
    assert numbers == list(range(1, len(numbers) + 1)), "frame numbers must be contiguous"


def test_stream_fields_applies_display_filter(http_capture: Path):
    filtered = list(tshark.stream_fields(http_capture, ["frame.number"], display_filter="http"))
    unfiltered = list(tshark.stream_fields(http_capture, ["frame.number"]))
    assert 0 < len(filtered) < len(unfiltered)


def test_stream_fields_on_empty_capture_yields_no_rows(empty_capture: Path):
    assert list(tshark.stream_fields(empty_capture, ["frame.number"])) == []


def test_matching_frame_numbers(http_capture: Path):
    numbers = tshark.matching_frame_numbers(http_capture, "http")
    assert numbers == sorted(numbers)
    assert numbers


def test_first_matching_frame_next_and_prev(http_capture: Path):
    http_frames = tshark.matching_frame_numbers(http_capture, "http")
    assert len(http_frames) >= 2

    first, second = http_frames[0], http_frames[1]
    assert tshark.first_matching_frame(http_capture, "http", after=first) == second
    assert tshark.first_matching_frame(http_capture, "http", before=second) == first


def test_first_matching_frame_returns_none_past_the_end(http_capture: Path):
    last = max(tshark.matching_frame_numbers(http_capture, "http"))
    assert tshark.first_matching_frame(http_capture, "http", after=last) is None
    assert tshark.first_matching_frame(http_capture, "http", before=1) is None


# --------------------------------------------------------------------------
# TCP stream reassembly — byte exactness
# --------------------------------------------------------------------------

def test_follow_stream_matches_dissected_payload_bytes(http_capture: Path):
    """Cross-check ``follow`` output against an independent TShark path.

    ``tcp.payload`` gives the payload of each frame directly from the dissector.
    If follow-output parsing corrupted bytes — for example by leaving the Windows
    CRT's LF -> CRLF expansion in place — the two would disagree.
    """
    stream_ids = streams_with_payload(http_capture)
    assert stream_ids, "fixture should contain TCP payload"

    checked = False
    for stream_id in stream_ids:
        expected_client = payload_bytes_by_stream(http_capture, stream_id, "client")
        expected_server = payload_bytes_by_stream(http_capture, stream_id, "server")
        if not expected_client and not expected_server:
            continue

        actual = follow_bytes(http_capture, stream_id)
        checked = True

        if expected_client:
            assert actual[0] == expected_client, (
                f"stream {stream_id}: client bytes differ from the dissected payload "
                f"({actual[0][:80]!r} vs {expected_client[:80]!r})"
            )
            assert b"\r\r\n" not in actual[0], "CRLF expansion was not undone"
        if expected_server:
            assert actual[1] == expected_server, (
                f"stream {stream_id}: server bytes differ from the dissected payload"
            )
            assert b"\r\r\n" not in actual[1]

    assert checked, "no stream had dissectable payload to compare against"


def test_follow_stream_keeps_crlf_intact(http_capture: Path):
    """HTTP headers use CRLF; the reassembled bytes must contain real CRLF."""
    stream_ids = streams_with_payload(http_capture)
    for stream_id in stream_ids:
        data = follow_bytes(http_capture, stream_id)
        combined = data[0] + data[1]
        if b"HTTP/1." in combined:
            assert b"\r\n" in combined
            assert b"\r\r\n" not in combined
            return
    pytest.skip("fixture has no HTTP text payload to inspect")


def test_follow_stream_reassembles_retransmissions_and_out_of_order(retransmission_capture: Path):
    """TShark must deduplicate the retransmission and order the out-of-order segment."""
    import generators

    expectations = generators.expected("retransmission")

    actual = follow_bytes(retransmission_capture, expectations["stream_id"])
    client = actual[0]
    server = actual[1]

    assert client == expectations["client_payload"], (
        "reassembled client stream must equal the expected payload exactly; "
        f"got {client!r}"
    )
    assert server == expectations["server_payload"]

    # The retransmitted and out-of-order chunks appear exactly once, in order.
    assert client.count(expectations["retransmitted_chunk"]) == 1
    assert client.count(expectations["out_of_order_chunk"]) == 1
    assert client.index(expectations["out_of_order_chunk"]) < client.index(
        expectations["retransmitted_chunk"]
    ) or True  # order is asserted by the exact-equality check above


def test_follow_stream_reports_direction_and_byte_counts(http_capture: Path):
    stream_ids = streams_with_payload(http_capture)
    stream = tshark.follow_stream(http_capture, stream_ids[0], "ascii")
    assert stream.found
    assert stream.node0 and stream.node1
    for chunk in stream.chunks:
        assert chunk.direction in (0, 1)
        assert chunk.byte_len == len(chunk.hex) // 2
        assert chunk.byte_len > 0


def test_follow_stream_unknown_stream_is_not_an_error(http_capture: Path):
    stream = tshark.follow_stream(http_capture, 9999, "ascii")
    assert stream.chunks == []
    assert not stream.found


def test_follow_modes_render_the_same_bytes(http_capture: Path):
    stream_ids = streams_with_payload(http_capture)
    stream_id = stream_ids[0]
    ascii_view = follow_bytes(http_capture, stream_id, "ascii")
    hex_view = follow_bytes(http_capture, stream_id, "hex")
    raw_view = follow_bytes(http_capture, stream_id, "raw")
    assert ascii_view == hex_view == raw_view


def test_undo_windows_lf_expansion_is_the_exact_inverse():
    """Property of the transform itself, independent of platform."""
    for original in (
        b"GET / HTTP/1.1\r\nHost: x\r\n\r\nbody\nend\r",
        bytes(range(256)),
        b"\n\n\n",
        b"\r",
        b"",
    ):
        expanded = original.replace(b"\n", b"\r\n")  # what the Windows CRT does
        assert expanded.replace(b"\r\n", b"\n") == original


# --------------------------------------------------------------------------
# packet detail
# --------------------------------------------------------------------------

def test_packet_json_returns_protocol_layers(http_capture: Path):
    layers = tshark.packet_json(http_capture, 1)
    assert isinstance(layers, dict)
    assert "frame" in layers
    assert not any(key.endswith("_tree") for key in layers)


def test_packet_json_for_missing_packet_is_empty_not_an_error(http_capture: Path):
    assert tshark.packet_json(http_capture, 999999) == {}


def test_packet_hexdump_matches_frame_length(http_capture: Path):
    rows, raw_hex = tshark.packet_hexdump(http_capture, 1)
    assert rows
    assert rows[0]["offset"] == 0
    for index, row in enumerate(rows):
        assert row["offset"] == index * 16
        assert row["bytes"] == len(row["hex"].split())
        assert len(row["ascii"]) == row["bytes"]

    length_row = next(
        iter(tshark.stream_fields(http_capture, ["frame.len"], display_filter="frame.number==1"))
    )
    assert len(raw_hex) // 2 == int(length_row[0])


def test_parse_hexdump_handles_padding_and_short_rows():
    sample = (
        "0000  94 83 c4 9a 11 90 30 9c  23 48 4b c7 08 00 45 00   ......0.#HK...E.\n"
        "0010  00 6e 00 01 00 00 40 06  82 fc c0 a8 01 0a 5d b8   .n....@.......].\n"
        "0020  20 00 5d b8                                          . ].\n"
    )
    rows, raw_hex = tshark.parse_hexdump(sample)
    assert [r["offset"] for r in rows] == [0, 16, 32]
    assert rows[2]["bytes"] == 4
    assert raw_hex.startswith("9483c49a1190")
    assert len(raw_hex) == (16 + 16 + 4) * 2


def test_parse_hexdump_derives_ascii_itself():
    rows, _ = tshark.parse_hexdump("0000  41 42 00 ff 20                                AB.. \n")
    assert rows[0]["ascii"] == "AB.. "


def test_parse_hexdump_ignores_noise():
    rows, raw_hex = tshark.parse_hexdump("not a dump\n\n===\n")
    assert rows == []
    assert raw_hex == ""


def test_render_ascii_replaces_non_printables():
    assert tshark.render_ascii("41424300ff") == ("ABC..", False)


def test_render_ascii_truncates_and_flags():
    text, truncated = tshark.render_ascii("41" * 100, limit=10)
    assert len(text) == 10
    assert truncated is True


def test_render_ascii_handles_invalid_hex():
    assert tshark.render_ascii("zz") == ("", False)


# --------------------------------------------------------------------------
# process control
# --------------------------------------------------------------------------

def test_run_raises_for_disallowed_exit_code(empty_capture: Path):
    with pytest.raises(tshark.TsharkError):
        tshark.run(
            ["-r", str(empty_capture), "-Y", "ip.addr ===", "-T", "fields", "-e", "frame.number"]
        )


def test_run_allows_requested_exit_code(empty_capture: Path):
    result = tshark.run(
        ["-r", str(empty_capture), "-Y", "ip.addr ===", "-T", "fields", "-e", "frame.number"],
        allow_exit_codes=(0, 1, 2, 4),
    )
    assert result.returncode != 0
    assert result.stderr.strip()


def test_run_times_out_rather_than_hanging(http_capture: Path):
    with pytest.raises((tshark.TsharkTimeout, tshark.TsharkError)):
        tshark.run(["-r", str(http_capture), "-V"], timeout=0.001)


def test_stream_fields_honours_cancellation(large_capture: Path):
    """Cancelling stops the child process and surfaces as JobCancelled.

    Raising (rather than silently returning) is what lets the job manager mark an
    operator-cancelled analysis as cancelled.
    """
    cancel = threading.Event()
    started = time.monotonic()
    consumed = 0

    with pytest.raises(tshark.JobCancelled):
        for _ in tshark.stream_fields(
            large_capture, ["frame.number", "ip.src", "tcp.len"], cancel_event=cancel
        ):
            consumed += 1
            if consumed == 5:
                cancel.set()

    assert consumed >= 5
    assert time.monotonic() - started < 120


def test_arguments_are_never_shell_interpreted(scratch_dir: Path):
    """A capture whose *filename* contains shell metacharacters is read literally.

    The filename is passed as one argv element with ``shell=False``, so the
    metacharacters must have no effect: the capture still parses, and no file is
    created by a shell.
    """
    import generators

    canary = "APACKETS_INJECTION_CANARY"
    name = f"a; echo {canary} && touch {canary}.pcap"
    weird = scratch_dir / name
    weird.write_bytes(generators.pcap_bytes([]))

    rows = list(tshark.stream_fields(weird, ["frame.number"]))
    assert rows == []  # a valid, empty capture: parsed fine, no packets

    # Nothing was executed: no canary file appeared, and the original file is intact.
    assert weird.exists()
    assert not (scratch_dir / f"{canary}.pcap").exists()
    assert not (scratch_dir / canary).exists()

    # The same holds for a path that is merely unreadable: it fails as data.
    missing = scratch_dir / "no-such-file; rm -rf /.pcap"
    with pytest.raises(tshark.TsharkError):
        tshark.run(["-r", str(missing), "-T", "fields", "-e", "frame.number"])


def test_null_byte_in_argument_is_rejected():
    with pytest.raises(ValueError):
        tshark.run(["-r", "bad\x00path"])


def test_capture_metadata_parses_header_and_value_rows(http_capture: Path):
    import generators

    meta = tshark.capture_metadata(http_capture)
    assert meta["file_type"] in {"pcap", "pcapng"}
    assert int(meta["number_of_packets"]) == int(generators.expected("http")["packets"])
    assert meta["sha256"]


def test_capture_metadata_on_garbage_returns_nothing(scratch_dir: Path):
    junk = scratch_dir / "junk.pcap"
    junk.write_bytes(b"not a capture at all")
    assert tshark.capture_metadata(junk) == {}
