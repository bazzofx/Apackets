"""The finding-context endpoint behind the Findings workbench.

The endpoint fans one finding out into the packets that triggered it, the
conversations and reassembled streams they belong to, the application-layer
records, the transferred files and the related findings. These tests drive a real
generated capture through the real API, so the correlation is exercised against
data TShark actually produced.

Each test that needs an analysed capture uploads once; the assertions for caps,
objects, the Suricata rule block and the 404s all reuse that one analysis.
"""

from __future__ import annotations

import pytest


def _findings(client, analysis_id: str) -> list[dict]:
    payload = client.get(f"/api/analyses/{analysis_id}/findings?page_size=200").json()
    return payload.get("items") or []


def _stream_keys(packets: list[dict]) -> set[tuple[str, int]]:
    """``(transport, stream_id)`` for whatever the packets recorded."""
    keys: set[tuple[str, int]] = set()
    for packet in packets:
        transport = str(packet.get("transport") or "").lower()
        stream_id = packet.get("tcp_stream") if transport == "tcp" else packet.get("udp_stream")
        if stream_id is None:
            stream_id = packet.get("tcp_stream")
            transport = "tcp" if stream_id is not None else transport
        if stream_id is None:
            stream_id = packet.get("udp_stream")
            transport = "udp" if stream_id is not None else transport
        if stream_id is not None:
            keys.add((transport or "tcp", int(stream_id)))
    return keys


def _pick_with_context(client, analysis_id: str, *, want_tcp: bool = True):
    """The busiest finding, preferably one whose packets are TCP.

    Returns ``(finding, context)`` or ``(None, None)``.
    """
    candidates = sorted(
        _findings(client, analysis_id),
        key=lambda item: -len(item.get("packet_numbers") or []),
    )
    for finding in candidates[:6]:
        if len(finding.get("packet_numbers") or []) < 2:
            break
        response = client.get(f"/api/analyses/{analysis_id}/findings/{finding['id']}/context")
        if response.status_code != 200:
            continue
        payload = response.json()
        if not want_tcp:
            return finding, payload
        tcp_keys = {key for key in _stream_keys(payload["packets"]) if key[0] == "tcp"}
        if tcp_keys:
            return finding, payload
    return None, None


def test_context_returns_packets_conversations_and_matching_packet_numbers(
    client, run_analysis, combined_capture
) -> None:
    analysis_id, detail = run_analysis(combined_capture)
    assert detail["status"] == "completed", detail

    finding, payload = _pick_with_context(client, analysis_id, want_tcp=True)
    if finding is None:
        pytest.skip("the generated capture produced no TCP finding with several packets")

    # 1. the finding itself, in the same shape as the detail route
    assert payload["finding"]["id"] == finding["id"]
    assert payload["finding"]["rule_id"] == finding["rule_id"]
    assert payload["analysis"]["original_filename"] == combined_capture.name

    # 2. the packets that triggered it, and only those
    packets = payload["packets"]
    assert packets, "the context must return the packets that triggered the finding"
    returned = [item["number"] for item in packets]
    declared = finding["packet_numbers"]
    assert set(returned) <= set(declared)
    if not payload["truncated"]["packets"]:
        assert returned == declared
    assert all(item["alerting"] is True for item in packets)
    assert all(item["frame_len"] for item in packets)

    # 3. the conversation(s) those packets belong to
    conversations = payload["conversations"]
    assert conversations, "the alerting packets belong to captured conversations"
    conversation_keys = {
        (str(conversation["transport"]).lower(), int(conversation["stream_id"]))
        for conversation in conversations
    }
    assert _stream_keys(packets) & conversation_keys
    for conversation in conversations:
        assert conversation["packets_total"] >= 1
        assert conversation["endpoint_a"] and conversation["endpoint_b"]

    # 4. the reassembled stream content
    streams = payload["streams"]
    assert streams
    assert streams[0]["stream"] is not None
    with_follow = [block for block in streams if block.get("follow")]
    assert with_follow, "at least one TCP stream must come back with its follow content"
    follow = with_follow[0]["follow"]
    assert follow.get("node0") and follow.get("node1")
    assert isinstance((follow.get("client_to_server") or {}).get("bytes"), int)
    assert isinstance((follow.get("chunks") or []), list)

    # 5. the peer cards
    endpoints = payload["endpoints"]
    assert endpoints
    assert {endpoint["direction"] for endpoint in endpoints} <= {"source", "destination"}
    assert all(isinstance(endpoint["ports"], list) and endpoint["ports"] for endpoint in endpoints)
    assert all("ip" in endpoint for endpoint in endpoints)

    # 6. caps are always reported, and counts agree with the payload
    assert payload["limits"]["packets"] == 50
    assert set(payload["truncated"]) >= {"packets", "streams", "http", "objects"}
    assert payload["counts"]["packets"] == len(packets)
    assert payload["counts"]["conversations"] == len(conversations)

    # 7. an explicit smaller cap is honoured and flagged
    limited = client.get(
        f"/api/analyses/{analysis_id}/findings/{finding['id']}/context",
        params={"packets_limit": 2, "include_follow": "false"},
    ).json()
    assert limited["limits"]["packets"] == 2
    assert limited["truncated"]["packets"] is True
    assert len(limited["packets"]) == 2
    assert all(block["follow"] is None for block in limited["streams"])

    # 8. unknown finding -> documented 404 envelope
    missing = client.get(f"/api/analyses/{analysis_id}/findings/nope/context")
    assert missing.status_code == 404
    body = missing.json()
    assert body["error"]["code"] == "finding_not_found"
    assert body["error"]["details"]["finding_id"] == "nope"
    assert body["error"]["details"]["analysis_id"] == analysis_id

    # 9. the pre-existing detail route is untouched
    original = client.get(f"/api/analyses/{analysis_id}/findings/{finding['id']}")
    assert original.status_code == 200, original.text
    assert set(original.json()) >= {
        "id",
        "analysis_id",
        "rule_id",
        "severity",
        "title",
        "description",
        "reason",
        "evidence",
        "packet_numbers",
        "entities",
        "recommendation",
        "created_at",
    }


def test_context_includes_the_suricata_rule_and_inferred_files(
    client, run_analysis, combined_capture
) -> None:
    analysis_id, _detail = run_analysis(combined_capture)

    rule = (
        'alert http any any -> any any (msg:"context test rule"; http.uri; '
        'content:"/"; sid:9001001; rev:1;)'
    )
    created = client.post("/api/suricata/rules", json={"raw": rule})
    assert created.status_code == 201, created.text

    run = client.post(f"/api/analyses/{analysis_id}/suricata/run")
    assert run.status_code == 200, run.text
    assert run.json()["findings"] >= 1

    suricata_findings = [
        item for item in _findings(client, analysis_id) if item["rule_id"] == "suricata:9001001"
    ]
    assert suricata_findings, "the seeded rule must produce a finding"
    payload = client.get(
        f"/api/analyses/{analysis_id}/findings/{suricata_findings[0]['id']}/context"
    ).json()

    assert payload["packets"], "a suricata finding carries the packets it matched"
    assert payload["rule"] is not None
    assert payload["rule"]["sid"] == 9001001
    assert payload["rule"]["rev"] == 1
    assert payload["rule"]["source"] == "manual"
    assert "http.uri" in [option.get("buffer") for option in payload["rule"]["options"]]

    # Extracted files: exact match where the pipeline correlated them, otherwise
    # an explicitly labelled inference from the request URI.
    for item in _findings(client, analysis_id):
        objects = client.get(
            f"/api/analyses/{analysis_id}/findings/{item['id']}/context"
        ).json()["objects"]
        if not objects:
            continue
        assert all(entry.get("match") in {"stream", "packet", "inferred-uri"} for entry in objects)
        assert all(entry.get("filename") for entry in objects)
        assert all(entry.get("id") for entry in objects)
        return
    pytest.skip("no finding in this capture carried extracted objects")


def test_context_unknown_analysis_returns_404_envelope(client) -> None:
    response = client.get(f"/api/analyses/{'0' * 32}/findings/whatever/context")
    assert response.status_code == 404
    assert response.json()["error"]["code"] == "analysis_not_found"