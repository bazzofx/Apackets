"""Tests for the alert -> conversation linkage used by the flow highlight layer.

These are deliberately independent of *which* Suricata rules fire on a fixture:
the linkage is the thing under test, so findings are inserted with frame numbers
that point at known conversations in a generated capture. That keeps the test
deterministic and offline — no rule corpus is seeded and no external capture is
read.

The endpoint's ``source`` defaults to ``all`` (imported Suricata rules **and** the
built-in detection engine), because the Findings page shows both and an overlay
that disagreed with it would be misleading. Tests that insert synthetic
``suricata:`` rows and assert exact counts therefore use :func:`suricata_alerts`
to ask for that source explicitly.
"""

from __future__ import annotations

import json
import time

import pytest

import generators


def insert_finding(
    analysis_id: str,
    *,
    finding_id: str,
    rule_id: str = "suricata:9999999",
    severity: str = "high",
    title: str = "Synthetic alert",
    packet_numbers: list[int] | None = None,
    entities: dict | None = None,
) -> None:
    from app.db import database as db

    with db.get_conn() as conn:
        conn.execute(
            """
            INSERT OR REPLACE INTO findings
                (id, analysis_id, rule_id, severity, title, description, reason,
                 evidence, packet_numbers, entities, recommendation, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                finding_id,
                analysis_id,
                rule_id,
                severity,
                title,
                "Synthetic description",
                "Synthetic reason",
                json.dumps({"synthetic": True}),
                json.dumps(packet_numbers or []),
                json.dumps(entities or {"ips": [], "hostnames": [], "ports": [], "uris": []}),
                "Synthetic recommendation",
                time.time(),
            ),
        )


def suricata_alerts(client, analysis_id: str, **params) -> dict:
    """The alert map restricted to the imported Suricata rules.

    Isolates the synthetic rows these tests insert from the fixture's own built-in
    findings, so exact counts stay meaningful.
    """
    params.setdefault("source", "suricata")
    response = client.get(f"/api/analyses/{analysis_id}/alerts/conversations", params=params)
    assert response.status_code == 200, response.text
    return response.json()


def all_alerts(client, analysis_id: str, **params) -> dict:
    """The alert map across both sources (the endpoint's default)."""
    params.setdefault("source", "all")
    response = client.get(f"/api/analyses/{analysis_id}/alerts/conversations", params=params)
    assert response.status_code == 200, response.text
    return response.json()


def conversation_keys(client, analysis_id: str) -> set[str]:
    """The keys the flow actually draws: transport:stream_id per conversation."""
    body = client.get(
        f"/api/analyses/{analysis_id}/conversations", params={"page_size": 1000}
    ).json()
    return {
        f"{row['transport']}:{row['stream_id']}"
        for row in body["items"]
        if row.get("stream_id") is not None
    }


def first_packet_of_a_stream(client, analysis_id: str) -> tuple[int, str]:
    """A frame number and the conversation key it belongs to, taken from real data."""
    body = client.get(
        f"/api/analyses/{analysis_id}/packets", params={"page_size": 100}
    ).json()
    for row in body["items"]:
        if row.get("tcp_stream") is not None and row.get("transport") == "tcp":
            return int(row["number"]), f"tcp:{row['tcp_stream']}"
        if row.get("udp_stream") is not None and row.get("transport") == "udp":
            return int(row["number"]), f"udp:{row['udp_stream']}"
    pytest.skip("fixture has no packet carrying a stream id")


# --------------------------------------------------------------------------
# linkage
# --------------------------------------------------------------------------

def test_alert_is_linked_to_the_conversation_its_frames_belong_to(
    client, run_analysis, http_capture
):
    """The core promise: a finding's frames decide the conversation."""
    analysis_id, _ = run_analysis(http_capture)
    drawable = conversation_keys(client, analysis_id)
    assert drawable, "the fixture must produce conversations with stream ids"

    frame, expected_key = first_packet_of_a_stream(client, analysis_id)
    assert expected_key in drawable

    insert_finding(
        analysis_id,
        finding_id="suricata:9999999:test-linked",
        severity="high",
        packet_numbers=[frame],
    )

    body = suricata_alerts(client, analysis_id)

    assert body["counts"]["high"] == 1
    assert body["linked_conversations"] == 1
    assert body["unlinked_findings"] == 0

    assert set(body["by_conversation"]) == {expected_key}, body["by_conversation"]
    entry = body["by_conversation"][expected_key]
    assert entry["severity"] == "high"
    assert entry["rules"] == ["suricata:9999999"]
    assert entry["finding_ids"] == ["suricata:9999999:test-linked"]

    # The decisive invariant: everything returned is something the flow draws.
    assert set(body["by_conversation"]) <= drawable

    alert = body["alerts"][0]
    assert alert["linked_by"] == "packets"
    assert alert["conversations"] == [expected_key]
    assert alert["packet_numbers"] == [frame]


def test_severity_is_the_most_urgent_of_the_linked_alerts(
    client, run_analysis, http_capture
):
    analysis_id, _ = run_analysis(http_capture)
    frame, key = first_packet_of_a_stream(client, analysis_id)

    insert_finding(
        analysis_id, finding_id="suricata:1:medium", severity="medium", packet_numbers=[frame]
    )
    body = suricata_alerts(client, analysis_id)
    assert body["by_conversation"][key]["severity"] == "medium"

    insert_finding(
        analysis_id, finding_id="suricata:1:high", severity="high", packet_numbers=[frame]
    )
    body = suricata_alerts(client, analysis_id)
    entry = body["by_conversation"][key]
    assert entry["severity"] == "high", "high must win over medium for the same conversation"
    assert len(entry["finding_ids"]) == 2, "both findings stay attached"
    assert body["counts"] == {"informational": 0, "low": 0, "medium": 1, "high": 1}


def test_unlinkable_findings_are_reported_not_guessed(client, run_analysis, http_capture):
    """A finding whose frames are not in the index must not invent a conversation."""
    analysis_id, _ = run_analysis(http_capture)
    real_frame, _ = first_packet_of_a_stream(client, analysis_id)

    insert_finding(
        analysis_id,
        finding_id="suricata:2:orphan",
        severity="high",
        packet_numbers=[999999],  # a frame that does not exist
    )
    insert_finding(
        analysis_id,
        finding_id="suricata:3:no-frames",
        severity="medium",
        packet_numbers=[],
    )

    body = suricata_alerts(client, analysis_id)
    assert body["linked_conversations"] == 0
    assert body["by_conversation"] == {}
    assert body["unlinked_findings"] == 2
    assert all(alert["linked_by"] == "none" for alert in body["alerts"])
    assert body["note"]

    # And the same endpoint still links a finding that does have real frames.
    insert_finding(
        analysis_id,
        finding_id="suricata:4:linked",
        severity="medium",
        packet_numbers=[real_frame],
    )
    body = suricata_alerts(client, analysis_id)
    assert body["linked_conversations"] == 1
    assert body["unlinked_findings"] == 2


def test_by_ip_covers_both_ends_of_the_flagged_conversation(
    client, run_analysis, http_capture
):
    analysis_id, _ = run_analysis(http_capture)
    frame, key = first_packet_of_a_stream(client, analysis_id)
    insert_finding(
        analysis_id, finding_id="suricata:5:ip", severity="high", packet_numbers=[frame]
    )

    body = suricata_alerts(client, analysis_id)
    assert body["by_ip"], "a flagged conversation must implicate its endpoints"

    conversations = client.get(
        f"/api/analyses/{analysis_id}/conversations", params={"page_size": 1000}
    ).json()["items"]
    row = next(
        (c for c in conversations if f"{c['transport']}:{c['stream_id']}" == key), None
    )
    assert row is not None
    assert row["ip_a"] in body["by_ip"]
    assert row["ip_b"] in body["by_ip"]
    for ip in (row["ip_a"], row["ip_b"]):
        assert body["by_ip"][ip]["severity"] == "high"
        assert key in body["by_ip"][ip]["conversations"]


# --------------------------------------------------------------------------
# filtering, validation and coexistence
# --------------------------------------------------------------------------

def test_min_severity_filters_and_is_validated(client, run_analysis, http_capture):
    analysis_id, _ = run_analysis(http_capture)
    frame, _ = first_packet_of_a_stream(client, analysis_id)

    insert_finding(
        analysis_id, finding_id="suricata:6:medium", severity="medium", packet_numbers=[frame]
    )
    insert_finding(
        analysis_id, finding_id="suricata:7:low", severity="low", packet_numbers=[frame]
    )
    insert_finding(
        analysis_id, finding_id="suricata:8:info", severity="informational", packet_numbers=[frame]
    )

    medium_up = suricata_alerts(client, analysis_id)
    assert medium_up["counts"]["medium"] == 1
    assert medium_up["counts"]["low"] == 0, "low is below the default threshold"
    assert medium_up["all_counts"]["low"] == 1, "but still reported in all_counts"
    assert medium_up["all_counts"]["informational"] == 1

    high_only = suricata_alerts(client, analysis_id, min_severity="high")
    assert high_only["alerts"] == []
    assert high_only["by_conversation"] == {}

    everything = suricata_alerts(client, analysis_id, min_severity="informational")
    assert len(everything["alerts"]) == 3

    bad = client.get(
        f"/api/analyses/{analysis_id}/alerts/conversations", params={"min_severity": "urgent"}
    )
    assert bad.status_code == 400
    assert bad.json()["error"]["code"] == "invalid_min_severity"

    bad_source = client.get(
        f"/api/analyses/{analysis_id}/alerts/conversations", params={"source": "elsewhere"}
    )
    assert bad_source.status_code == 422


def test_default_source_includes_builtin_findings_not_just_suricata(
    client, run_analysis, http_capture
):
    """The default must agree with the Findings page.

    Regression guard for a capture whose medium alerts all come from the built-in
    engine: `source=suricata` reported zero medium while Findings showed two, which
    is exactly the disagreement this default exists to prevent.
    """
    analysis_id, _ = run_analysis(http_capture)
    frame, _ = first_packet_of_a_stream(client, analysis_id)

    insert_finding(
        analysis_id,
        finding_id="dns_nxdomain_burst:builtin-medium",
        rule_id="dns_nxdomain_burst",
        severity="medium",
        title="6 NXDOMAIN responses",
        packet_numbers=[frame],
    )

    # No `source` param at all: the default.
    default_body = client.get(
        f"/api/analyses/{analysis_id}/alerts/conversations"
    ).json()
    assert default_body["source"] == "all"
    assert default_body["counts"]["medium"] >= 1, (
        "a built-in medium finding must be counted by default"
    )
    assert any(
        alert["rule_id"] == "dns_nxdomain_burst" for alert in default_body["alerts"]
    )
    assert default_body["linked_conversations"] >= 1

    # And the narrow view still exists for callers that want it.
    narrow = suricata_alerts(client, analysis_id)
    assert all(alert["rule_id"].startswith("suricata:") for alert in narrow["alerts"])
    assert narrow["counts"]["medium"] == 0


def test_source_filter_separates_suricata_from_builtin_findings(
    client, run_analysis, http_capture
):
    analysis_id, _ = run_analysis(http_capture)
    frame, _ = first_packet_of_a_stream(client, analysis_id)

    insert_finding(
        analysis_id,
        finding_id="suricata:9:suricata",
        rule_id="suricata:50300004",
        severity="high",
        packet_numbers=[frame],
    )
    insert_finding(
        analysis_id,
        finding_id="http_suspicious_path:builtin",
        rule_id="http_suspicious_path",
        severity="medium",
        packet_numbers=[frame],
    )

    suricata_only = suricata_alerts(client, analysis_id)
    assert [a["rule_id"] for a in suricata_only["alerts"]] == ["suricata:50300004"]

    both = all_alerts(client, analysis_id)
    rules = {a["rule_id"] for a in both["alerts"]}
    # The fixture's own built-in findings also appear here, so assert containment
    # rather than an exact set.
    assert "suricata:50300004" in rules
    assert "http_suspicious_path" in rules
    assert len(both["alerts"]) > len(suricata_only["alerts"])


def test_alert_conversations_requires_a_known_analysis(client):
    response = client.get(f"/api/analyses/{'a' * 32}/alerts/conversations")
    assert response.status_code == 404
    assert response.json()["error"]["code"] == "analysis_not_found"

    malformed = client.get("/api/analyses/not-an-id/alerts/conversations")
    assert malformed.status_code == 400


def test_existing_findings_routes_still_work(client, run_analysis, http_capture):
    """The new route must not shadow the parameterised findings routes."""
    analysis_id, _ = run_analysis(http_capture)
    frame, _ = first_packet_of_a_stream(client, analysis_id)
    insert_finding(
        analysis_id, finding_id="suricata:10:coexist", severity="high", packet_numbers=[frame]
    )

    listing = client.get(f"/api/analyses/{analysis_id}/findings")
    assert listing.status_code == 200
    assert listing.json()["total"] >= 1

    rules = client.get(f"/api/analyses/{analysis_id}/findings/rules")
    assert rules.status_code == 200

    detail = client.get(f"/api/analyses/{analysis_id}/findings/suricata:10:coexist")
    assert detail.status_code == 200
    assert detail.json()["severity"] == "high"

    context = client.get(
        f"/api/analyses/{analysis_id}/findings/suricata:10:coexist/context"
    )
    assert context.status_code == 200


def test_empty_capture_returns_an_honest_empty_result(client, run_analysis, empty_capture):
    analysis_id, _ = run_analysis(empty_capture)
    body = client.get(f"/api/analyses/{analysis_id}/alerts/conversations").json()

    assert body["alerts"] == []
    assert body["by_conversation"] == {}
    assert body["by_ip"] == {}
    assert body["linked_conversations"] == 0
    assert body["note"], "the linkage caveat is always returned"
