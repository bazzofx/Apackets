"""The baseline network: one global reference capture, compared against every analysis.

The rules here are the ones that make claims about *another* capture, so the tests are
about the claims as much as the matching: novelty is only reported when the two captures
demonstrably belong to the same network, and a capture that shares nothing with the
baseline says so instead of reporting a whole foreign network as new.
"""

from __future__ import annotations

import time

import pytest

from app.db import database as db
from app.services import baseline, detection_engine

BASELINE_ID = "b" * 32
CAPTURE_ID = "c" * 32
FOREIGN_ID = "f" * 32


def _analysis(analysis_id: str, filename: str, packets: int = 10, status: str = "completed") -> None:
    now = time.time()
    with db.get_conn() as conn:
        conn.execute(
            """
            INSERT OR REPLACE INTO analyses (
                id, original_filename, stored_path, file_size, file_type, status,
                progress, stage, packet_count, created_at, updated_at
            ) VALUES (?, ?, 'x.pcap', 0, 'pcap', ?, 100, ?, ?, ?, ?)
            """,
            (analysis_id, filename, status, status, packets, now, now),
        )


def _packets(analysis_id: str, rows: list[tuple[str, str, int, int, int]]) -> None:
    """Insert (src, dst, sport, dport, flags) rows as indexed packets."""
    with db.get_conn() as conn:
        for index, (src, dst, sport, dport, flags) in enumerate(rows, start=1):
            conn.execute(
                """
                INSERT OR REPLACE INTO packets (
                    analysis_id, number, src_ip, dst_ip, src_port, dst_port, transport,
                    tcp_flags_raw, protocol, frame_len, info
                ) VALUES (?, ?, ?, ?, ?, ?, 'tcp', ?, 'TCP', 60, 'test')
                """,
                (analysis_id, index, src, dst, sport, dport, str(flags)),
            )


def _baseline_setup(*, enabled: bool = True) -> None:
    """A baseline holding one local host and one external destination."""
    _analysis(BASELINE_ID, "baseline.pcapng", packets=6)
    _packets(
        BASELINE_ID,
        [
            ("192.168.8.229", "93.184.216.34", 51000, 443, 2),
            ("93.184.216.34", "192.168.8.229", 443, 51000, 18),
            ("192.168.8.229", "93.184.216.34", 51000, 443, 24),
        ],
    )
    baseline.save_config({"analysis_id": BASELINE_ID, "enabled": enabled, "label": "test-net"})


def test_status_is_empty_by_default(client) -> None:  # noqa: ARG001
    body = client.get("/api/baseline").json()
    assert body["configured"] is False
    assert body["active"] is False
    assert body["baseline"] is None


def test_a_baseline_must_be_a_completed_capture(client) -> None:  # noqa: ARG001
    _analysis("p" * 32, "pending.pcap", status="processing")
    assert client.put("/api/baseline", json={"analysis_id": "p" * 32}).status_code == 400

    _analysis("e" * 32, "empty.pcap", packets=0)
    assert client.put("/api/baseline", json={"analysis_id": "e" * 32}).status_code == 400

    assert client.put("/api/baseline", json={"analysis_id": "9" * 32}).status_code == 400


def test_choosing_a_baseline_reports_what_it_holds(client) -> None:  # noqa: ARG001
    _baseline_setup()
    body = client.get("/api/baseline").json()
    assert body["configured"] is True
    assert body["active"] is True
    assert body["baseline"]["analysis_id"] == BASELINE_ID
    assert body["counts"]["hosts"] == 2


def test_a_new_private_address_is_reported(client) -> None:  # noqa: ARG001
    _baseline_setup()
    _analysis(CAPTURE_ID, "after.pcap")
    _packets(
        CAPTURE_ID,
        [
            ("192.168.8.229", "93.184.216.34", 51000, 443, 2),
            ("192.168.8.178", "93.184.216.34", 52000, 443, 2),
        ],
    )

    items = baseline.rule_items("new_host", CAPTURE_ID, {})
    assert [item["title"] for item in items] == [
        "New address 192.168.8.178 is not in the baseline network"
    ]
    reason = items[0]["reason"]
    # The finding carries the reference it was measured against.
    assert "test-net" in reason
    assert "shares 2 of its 3" in reason
    assert items[0]["evidence"]["baseline"]["analysis_id"] == BASELINE_ID
    assert items[0]["packet_numbers"] == [2]


def test_a_new_external_destination_is_reported_but_multicast_is_not(client) -> None:  # noqa: ARG001
    _baseline_setup()
    _analysis(CAPTURE_ID, "after.pcap")
    _packets(
        CAPTURE_ID,
        [
            ("192.168.8.229", "93.184.216.34", 51000, 443, 2),
            ("192.168.8.229", "1.1.1.1", 51001, 443, 2),
            # A multicast group and a documentation address are not destinations
            # anyone chose to reach: neither may be reported as new reach.
            ("192.168.8.229", "239.255.255.250", 51002, 1900, 2),
            ("192.168.8.229", "203.0.113.9", 51003, 443, 2),
        ],
    )

    items = baseline.rule_items("new_destination", CAPTURE_ID, {})
    assert len(items) == 1
    assert items[0]["evidence"]["sample"] == ["1.1.1.1"]


def test_a_capture_from_another_network_suppresses_novelty(client) -> None:  # noqa: ARG001
    _baseline_setup()
    _analysis(FOREIGN_ID, "foreign.pcap")
    _packets(
        FOREIGN_ID,
        [
            ("10.101.10.191", "8.8.8.8", 40000, 53, 2),
            ("10.101.10.192", "8.8.8.8", 40001, 53, 2),
        ],
    )

    summary = client.get("/api/analyses/" + FOREIGN_ID + "/baseline").json()
    assert summary["active"] is True
    assert summary["comparable"] is False
    assert summary["overlap"]["shared_private_hosts"] == 0

    # Every novelty rule stays silent...
    for kind in ("new_host", "new_destination", "new_service", "new_dns", "new_sni", "new_ja3"):
        assert baseline.rule_items(kind, FOREIGN_ID, {}) == []
    # ...and exactly one finding says why.
    overlap_items = baseline.rule_items("no_overlap", FOREIGN_ID, {})
    assert len(overlap_items) == 1
    assert "different network" in overlap_items[0]["reason"]


def test_baseline_mode_off_reports_nothing(client) -> None:  # noqa: ARG001
    _baseline_setup(enabled=False)
    _analysis(CAPTURE_ID, "after.pcap")
    _packets(CAPTURE_ID, [("192.168.8.178", "203.0.113.9", 52000, 443, 2)])

    assert client.get("/api/baseline").json()["active"] is False
    for kind in ("new_host", "new_destination", "no_overlap"):
        assert baseline.rule_items(kind, CAPTURE_ID, {}) == []
    assert baseline.compare(CAPTURE_ID)["reason"] == "baseline mode is off"


def test_the_baseline_is_not_compared_with_itself(client) -> None:  # noqa: ARG001
    _baseline_setup()
    assert baseline.compare(BASELINE_ID)["active"] is False
    assert baseline.rule_items("new_host", BASELINE_ID, {}) == []


def test_clearing_the_baseline_turns_the_mode_off(client) -> None:  # noqa: ARG001
    _baseline_setup()
    body = client.delete("/api/baseline").json()
    assert body["configured"] is False
    assert body["enabled"] is False


def test_a_deleted_baseline_capture_is_reported(client) -> None:  # noqa: ARG001
    _baseline_setup()
    with db.get_conn() as conn:
        conn.execute("DELETE FROM analyses WHERE id = ?", (BASELINE_ID,))
    body = client.get("/api/baseline").json()
    assert body["configured"] is False
    assert "deleted" in body["reason"]


def test_the_baseline_rules_are_in_the_catalogue(client) -> None:  # noqa: ARG001
    ids = {item["rule_id"] for item in client.get("/api/detection/rules").json()["items"]}
    assert {
        "baseline_new_host",
        "baseline_new_destination",
        "baseline_new_service",
        "baseline_new_dns",
        "baseline_new_sni",
        "baseline_new_ja3",
        "baseline_no_overlap",
    } <= ids
    # They are switchable like any other rule.
    assert detection_engine.RULES["baseline_new_host"].severity == "high"
