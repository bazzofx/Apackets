"""The built-in detection-rule API: view and tune the heuristics from the UI.

These rules are code, so the only thing the interface may change is the
configuration the code reads. The tests below pin the properties that matter for
that claim: the API describes exactly the knobs the engine defines, a rejected
value is rejected with the reason, a partial update cannot silently reset a
neighbouring threshold, and a finding carries the rule that produced it so the
interface can offer the editor instead of a blank page.
"""

from __future__ import annotations

import json
import time

import pytest

from app.db import database as db
from app.services import detection_engine


def _item(client, rule_id: str) -> dict:
    response = client.get("/api/detection/rules/" + rule_id)
    assert response.status_code == 200, response.text
    return response.json()


# --------------------------------------------------------------------------
# listing
# --------------------------------------------------------------------------

def test_every_built_in_rule_is_listed_with_its_configuration(client) -> None:
    response = client.get("/api/detection/rules")
    assert response.status_code == 200, response.text
    body = response.json()

    assert body["total"] == len(detection_engine.RULES)
    assert body["enabled"] == len(detection_engine.RULES)
    assert set(body["severities"]) == set(detection_engine.SEVERITIES)
    assert sum(body["severities"].values()) == body["total"]

    by_id = {item["rule_id"]: item for item in body["items"]}
    assert set(by_id) == set(detection_engine.RULE_ORDER)

    nxdomain = by_id["dns_nxdomain_burst"]
    assert nxdomain["severity"] == "medium"
    assert nxdomain["enabled"] is True
    assert nxdomain["thresholds"] == {"min_nxdomain": 5}
    assert nxdomain["defaults"] == {"min_nxdomain": 5}
    # The sentence the interface shows is rendered from the effective thresholds.
    assert nxdomain["threshold"] == "5 or more NXDOMAIN responses for one client"


def test_severity_filter_data_includes_the_medium_rules(client) -> None:
    body = client.get("/api/detection/rules").json()
    medium = [item["rule_id"] for item in body["items"] if item["severity"] == "medium"]
    assert "dns_nxdomain_burst" in medium
    assert "outbound_volume" in medium
    assert body["severities"]["medium"] == len(medium)


def test_list_for_an_unknown_analysis_is_404(client) -> None:
    assert client.get("/api/detection/rules?analysis_id=" + "0" * 32).status_code == 404


# --------------------------------------------------------------------------
# updating
# --------------------------------------------------------------------------

def test_tuning_a_threshold_rerenders_the_threshold_sentence(client) -> None:
    response = client.put(
        "/api/detection/rules/dns_nxdomain_burst", json={"thresholds": {"min_nxdomain": 9}}
    )
    assert response.status_code == 200, response.text
    item = response.json()
    assert item["thresholds"]["min_nxdomain"] == 9
    assert item["threshold"] == "9 or more NXDOMAIN responses for one client"
    # Persisted, not just echoed.
    assert _item(client, "dns_nxdomain_burst")["thresholds"] == {"min_nxdomain": 9}


def test_a_partial_update_does_not_reset_a_neighbouring_threshold(client) -> None:
    client.put("/api/detection/rules/outbound_volume", json={"thresholds": {"max_mb": 12}})
    client.put("/api/detection/rules/outbound_volume", json={"enabled": False})

    item = _item(client, "outbound_volume")
    assert item["enabled"] is False
    # max_bytes survives the second, unrelated update.
    assert item["thresholds"]["max_bytes"] == 12 * 1024 * 1024
    assert item["thresholds"]["max_mb"] == 12


def test_disable_then_enable(client) -> None:
    assert client.put(
        "/api/detection/rules/rare_destination_port", json={"enabled": False}
    ).json()["enabled"] is False
    assert client.put(
        "/api/detection/rules/rare_destination_port", json={"enabled": True}
    ).json()["enabled"] is True


def test_reset_restores_the_documented_defaults(client) -> None:
    client.put("/api/detection/rules/outbound_volume", json={"thresholds": {"max_mb": 1}})
    client.put("/api/detection/rules/outbound_volume", json={"enabled": False})

    item = client.put("/api/detection/rules/outbound_volume", json={"reset": True}).json()
    assert item["enabled"] is True
    assert item["thresholds"]["max_mb"] == item["defaults"]["max_mb"]
    assert item["thresholds"]["max_bytes"] == item["defaults"]["max_bytes"]


def test_max_mb_is_stored_as_bytes(client) -> None:
    item = client.put(
        "/api/detection/rules/outbound_volume", json={"thresholds": {"max_mb": 3}}
    ).json()
    assert item["thresholds"]["max_bytes"] == 3 * 1024 * 1024
    assert item["threshold"] == (
        "3 MB sent by one host, or 10x the median sender volume with at least 2 senders"
    )


def test_common_ports_accepts_a_list_and_null(client) -> None:
    ports = client.put(
        "/api/detection/rules/rare_destination_port",
        json={"thresholds": {"common_ports": [80, 443, 8443]}},
    )
    assert ports.status_code == 200, ports.text
    assert ports.json()["thresholds"]["common_ports"] == [80, 443, 8443]

    cleared = client.put(
        "/api/detection/rules/rare_destination_port", json={"thresholds": {"common_ports": None}}
    )
    assert cleared.json()["thresholds"]["common_ports"] is None


# --------------------------------------------------------------------------
# refusals
# --------------------------------------------------------------------------

def test_unknown_rule_is_404_with_the_known_ids(client) -> None:
    response = client.put("/api/detection/rules/not_a_rule", json={"enabled": True})
    assert response.status_code == 404
    error = response.json()["error"]
    assert error["code"] == "rule_not_found"
    assert "dns_nxdomain_burst" in error["details"]["allowed"]


def test_unknown_threshold_is_422_naming_the_real_ones(client) -> None:
    response = client.put(
        "/api/detection/rules/dns_nxdomain_burst", json={"thresholds": {"min_nx_domains": 3}}
    )
    assert response.status_code == 422
    error = response.json()["error"]
    assert error["code"] == "validation_error"
    assert error["details"]["keys"] == ["min_nxdomain"]


@pytest.mark.parametrize("value", [0, -3, "abc", None])
def test_a_threshold_that_is_not_positive_is_refused(client, value) -> None:
    response = client.put(
        "/api/detection/rules/dns_nxdomain_burst", json={"thresholds": {"min_nxdomain": value}}
    )
    assert response.status_code == 422, response.text
    # Nothing was written.
    assert _item(client, "dns_nxdomain_burst")["thresholds"] == {"min_nxdomain": 5}


def test_enabled_cannot_be_smuggled_into_thresholds(client) -> None:
    response = client.put(
        "/api/detection/rules/dns_nxdomain_burst", json={"thresholds": {"enabled": False}}
    )
    assert response.status_code == 400
    assert response.json()["error"]["code"] == "invalid_rule_update"
    assert _item(client, "dns_nxdomain_burst")["enabled"] is True


def test_a_reset_cannot_be_combined_with_other_fields(client) -> None:
    response = client.put(
        "/api/detection/rules/dns_nxdomain_burst",
        json={"reset": True, "thresholds": {"min_nxdomain": 2}},
    )
    assert response.status_code == 400
    assert response.json()["error"]["code"] == "invalid_rule_update"


def test_an_empty_update_is_rejected(client) -> None:
    response = client.put("/api/detection/rules/dns_nxdomain_burst", json={})
    assert response.status_code == 400
    assert response.json()["error"]["code"] == "no_changes"


def test_a_bad_port_in_the_common_ports_list_is_refused(client) -> None:
    response = client.put(
        "/api/detection/rules/rare_destination_port",
        json={"thresholds": {"common_ports": [80, 70000]}},
    )
    assert response.status_code == 422
    assert "not a port" in response.json()["error"]["message"]


# --------------------------------------------------------------------------
# the finding -> rule link
# --------------------------------------------------------------------------

ANALYSIS_ID = "d" * 32


def _seed_finding(rule_id: str) -> str:
    """One completed analysis with a single finding, and nothing else."""
    now = time.time()
    finding_id = rule_id + ":0f1e2d3c4b5a"
    with db.get_conn() as conn:
        conn.execute(
            """
            INSERT OR REPLACE INTO analyses (
                id, original_filename, stored_path, file_size, file_type, status,
                progress, stage, packet_count, created_at, updated_at
            ) VALUES (?, 'seed.pcap', 'seed.pcap', 0, 'pcap', 'completed', 100,
                      'completed', 0, ?, ?)
            """,
            (ANALYSIS_ID, now, now),
        )
        conn.execute(
            """
            INSERT OR REPLACE INTO findings (
                id, analysis_id, rule_id, severity, title, description, reason,
                evidence, packet_numbers, entities, recommendation, created_at
            ) VALUES (?, ?, ?, 'medium', 'title', 'description', 'reason',
                      '{}', '[]', '{}', 'recommendation', ?)
            """,
            (finding_id, ANALYSIS_ID, rule_id, now),
        )
    return finding_id


def test_a_built_in_finding_reports_the_rule_that_produced_it(client) -> None:
    finding_id = _seed_finding("dns_nxdomain_burst")
    response = client.get(
        "/api/analyses/" + ANALYSIS_ID + "/findings/" + finding_id + "/context"
    )
    assert response.status_code == 200, response.text
    context = response.json()

    # A Suricata rule is not reported for a built-in finding, and vice versa.
    assert context["rule"] is None
    rule = context["detection_rule"]
    assert rule["rule_id"] == "dns_nxdomain_burst"
    assert rule["severity"] == "medium"
    assert rule["enabled"] is True
    assert rule["threshold"] == "5 or more NXDOMAIN responses for one client"
    assert rule["thresholds"] == {"min_nxdomain": 5}
    assert rule["defaults"] == {"min_nxdomain": 5}


def test_the_context_shows_a_tuned_threshold(client) -> None:
    finding_id = _seed_finding("dns_nxdomain_burst")
    client.put(
        "/api/detection/rules/dns_nxdomain_burst", json={"thresholds": {"min_nxdomain": 12}}
    )
    context = client.get(
        "/api/analyses/" + ANALYSIS_ID + "/findings/" + finding_id + "/context"
    ).json()
    assert context["detection_rule"]["thresholds"] == {"min_nxdomain": 12}
    assert context["detection_rule"]["threshold"].startswith("12 ")


def test_a_disabled_rule_is_reported_as_disabled(client) -> None:
    finding_id = _seed_finding("outbound_volume")
    client.put("/api/detection/rules/outbound_volume", json={"enabled": False})
    context = client.get(
        "/api/analyses/" + ANALYSIS_ID + "/findings/" + finding_id + "/context"
    ).json()
    # The finding stays (it is evidence of what happened); the rule behind it says
    # it will not run again.
    assert context["detection_rule"]["enabled"] is False


def test_a_suricata_finding_gets_no_built_in_rule(client) -> None:
    finding_id = _seed_finding("suricata:50200003")
    context = client.get(
        "/api/analyses/" + ANALYSIS_ID + "/findings/" + finding_id + "/context"
    ).json()
    assert context["detection_rule"] is None
