"""Suricata rule parsing, storage and matching.

These tests cover the parts that are easy to get subtly wrong: attaching a
buffer to the right content option (Suricata writes ``content:"x"; http_uri;
nocase;`` as separate options that describe the content *before* them),
expanding rule variables, keeping enable/disable state across a re-import, and
refusing to half-match a rule whose options cannot be honoured.
"""

from __future__ import annotations

import pytest

from app.services import suricata_engine, suricata_rules as sr

# Sticky-buffer spelling: the buffer selects the content that follows it.
STICKY_RULE = (
    'alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"sticky buffer test"; '
    'flow:established,to_server; http.uri; content:"/admin"; nocase; '
    "classtype:web-application-attack; sid:9000001; rev:2;)"
)

LEGACY_RULE = (
    'alert http any any -> any any (msg:"legacy modifier test"; '
    'content:"/login"; http_uri; content:"POST"; http_method; sid:9000002; rev:1;)'
)

UNSUPPORTED_RULE = (
    'alert tcp any any -> any any (msg:"needs flowbits"; content:"abc"; pkt_data; '
    "flowbits:set,already_seen; sid:9000003; rev:1;)"
)

DNS_RULE = (
    'alert dns any any -> any any (msg:"dns name test"; dns.query; '
    'content:"evil.example"; nocase; classtype:bad-unknown; sid:9000004; rev:1;)'
)


# --------------------------------------------------------------------------
# parsing
# --------------------------------------------------------------------------


def test_parse_rule_reads_header_and_meta() -> None:
    rule = sr.parse_rule(STICKY_RULE)
    assert rule.sid == 9000001
    assert rule.rev == 2
    assert rule.action == "alert"
    assert rule.protocol == "http"
    assert rule.src_net == "$HOME_NET"
    assert rule.dst_net == "$EXTERNAL_NET"
    assert rule.direction == "->"
    assert rule.classtype == "web-application-attack"
    assert rule.severity == "high"
    assert rule.supported is True


def test_sticky_buffer_and_legacy_modifier_attach_to_their_content() -> None:
    sticky = sr.parse_rule(STICKY_RULE)
    content = [opt for opt in sticky.options if opt["kind"] == "content"]
    assert len(content) == 1
    assert content[0]["buffer"] == "http.uri"
    assert content[0]["value"] == "/admin"
    assert content[0]["nocase"] is True

    legacy = sr.parse_rule(LEGACY_RULE)
    legacy_content = [opt for opt in legacy.options if opt["kind"] == "content"]
    assert [opt["buffer"] for opt in legacy_content] == ["http.uri", "http.method"]
    assert [opt["value"] for opt in legacy_content] == ["/login", "POST"]


def test_home_net_and_external_net_variables_expand() -> None:
    rule = sr.parse_rule(STICKY_RULE)
    assert rule.supported is True, rule.unsupported

    variables = sr.default_variables()
    home = sr.parse_address_expr("$HOME_NET", variables)
    external = sr.parse_address_expr("$EXTERNAL_NET", variables)
    assert home.matches("10.1.2.3") is True
    assert home.matches("8.8.8.8") is False
    assert external.matches("8.8.8.8") is True
    assert external.matches("10.1.2.3") is False


def test_unsupported_options_flag_the_rule_without_dropping_it() -> None:
    rule = sr.parse_rule(UNSUPPORTED_RULE)
    assert rule.supported is False
    assert rule.msg == "needs flowbits"
    reasons = " ".join(rule.unsupported)
    assert "flowbits" in reasons
    assert "pkt_data" in reasons


def test_rule_without_msg_or_sid_is_rejected() -> None:
    with pytest.raises(sr.RuleSyntaxError):
        sr.parse_rule('alert tcp any any -> any any (content:"x"; sid:1;)')
    with pytest.raises(sr.RuleSyntaxError):
        sr.parse_rule('alert tcp any any -> any any (msg:"no sid"; content:"x";)')


def test_severity_prefers_classtype_then_priority() -> None:
    assert sr.severity_for("web-application-attack", 4) == "high"
    assert sr.severity_for(None, 2) == "medium"
    assert sr.severity_for(None, 9) == "informational"
    assert sr.severity_for(None, None) == "informational"


def test_rule_text_file_parsing_reports_errors() -> None:
    text = "\n".join(
        [
            "# a comment",
            "",
            LEGACY_RULE,
            'alert tcp any any -> any any (msg:"broken"; sid:notanumber;)',
        ]
    )
    rules, errors = sr.parse_rule_text(text)
    assert [rule.sid for rule in rules] == [9000002]
    assert len(errors) == 1


# --------------------------------------------------------------------------
# storage
# --------------------------------------------------------------------------


def test_import_is_idempotent_and_preserves_disabled_state(fresh_db) -> None:  # noqa: ARG001
    parsed = [sr.parse_rule(STICKY_RULE), sr.parse_rule(LEGACY_RULE)]
    first = sr.import_rules(parsed, source="test")
    assert first == {"imported": 2, "updated": 0}

    sr.save_rule(9000001, enabled=False)
    assert sr.get_rule(9000001)["enabled"] == 0

    second = sr.import_rules(parsed, source="test")
    assert second == {"imported": 0, "updated": 2}
    # Re-importing must not re-enable a rule the analyst turned off.
    assert sr.get_rule(9000001)["enabled"] == 0
    assert sr.get_rule(9000002)["enabled"] == 1


def test_save_rule_edits_text_and_toggles_enabled(fresh_db) -> None:  # noqa: ARG001
    sr.import_rules([sr.parse_rule(LEGACY_RULE)], source="test")

    toggled = sr.save_rule(9000002, enabled=False)
    assert toggled["enabled"] == 0

    edited_text = LEGACY_RULE.replace("legacy modifier test", "renamed rule")
    edited = sr.save_rule(9000002, raw=edited_text, enabled=True)
    assert edited["msg"] == "renamed rule"
    assert edited["enabled"] == 1


def test_save_rule_refuses_to_move_a_rule_to_another_sid(fresh_db) -> None:  # noqa: ARG001
    from app.core.errors import ApiError

    sr.import_rules([sr.parse_rule(LEGACY_RULE)], source="test")
    with pytest.raises(ApiError) as excinfo:
        sr.save_rule(9000002, raw=STICKY_RULE)
    assert excinfo.value.code == "sid_mismatch"


def test_delete_rule(fresh_db) -> None:  # noqa: ARG001
    sr.import_rules([sr.parse_rule(LEGACY_RULE)], source="test")
    assert sr.delete_rule(9000002) is True
    assert sr.get_rule(9000002) is None
    assert sr.delete_rule(9000002) is False


def test_rule_stats_count_severities_and_support(fresh_db) -> None:  # noqa: ARG001
    sr.import_rules([sr.parse_rule(STICKY_RULE), sr.parse_rule(UNSUPPORTED_RULE)], source="test")
    stats = sr.rule_stats()
    assert stats["total"] == 2
    assert stats["enabled"] == 2
    assert stats["supported"] == 1
    assert stats["unsupported"] == 1

# --------------------------------------------------------------------------
# matching
# --------------------------------------------------------------------------


def _context(**overrides):
    context = {
        "number": 1,
        "time_epoch": 1_700_000_000.0,
        "src_ip": "10.0.0.5",
        "dst_ip": "93.184.216.34",
        "src_port": 51000,
        "dst_port": 80,
        "transport": "tcp",
        "protocol": "HTTP",
        "frame_len": 400,
        "ttl": 64,
        "ip_version": 4,
        "tcp_bits": 0x18,  # PSH + ACK: an established data packet
        "http_method": "GET",
        "http_uri": "/admin/login.php",
        "http_host": "example.com",
        "dns_query": None,
        "tls_sni": None,
    }
    context.update(overrides)
    return context


def test_engine_matches_the_http_uri_buffer(fresh_db) -> None:  # noqa: ARG001
    sr.import_rules([sr.parse_rule(STICKY_RULE)], source="test")
    rules, _ = suricata_engine.load_rules()
    assert len(rules) == 1

    buffers = {"http.uri": "/admin/login.php", "": "GET /admin/login.php"}
    matched = suricata_engine.evaluate_rule(rules[0], _context(), buffers)
    assert matched is not None
    assert "http.uri" in matched

    # A different URI must not match...
    assert suricata_engine.evaluate_rule(rules[0], _context(), {"http.uri": "/index.html"}) is None
    # ...and neither must a peer outside $HOME_NET.
    assert (
        suricata_engine.evaluate_rule(
            rules[0], _context(src_ip="8.8.8.8"), {"http.uri": "/admin/login.php"}
        )
        is None
    )


def test_engine_skips_rules_it_cannot_evaluate(fresh_db) -> None:  # noqa: ARG001
    sr.import_rules([sr.parse_rule(STICKY_RULE), sr.parse_rule(UNSUPPORTED_RULE)], source="test")
    rules, _ = suricata_engine.load_rules()
    assert [rule.sid for rule in rules] == [9000001]


def test_engine_matches_dns_query_buffer(fresh_db) -> None:  # noqa: ARG001
    sr.import_rules([sr.parse_rule(DNS_RULE)], source="test")
    rules, _ = suricata_engine.load_rules()
    context = _context(transport="udp", protocol="DNS", dst_port=53, dns_query="a.evil.example")
    buffers = {"dns.query": "a.evil.example", "": "Standard query a.evil.example"}
    assert suricata_engine.evaluate_rule(rules[0], context, buffers) is not None
    assert (
        suricata_engine.evaluate_rule(
            rules[0], context, {"dns.query": "www.example.org", "": "Standard query"}
        )
        is None
    )


# --------------------------------------------------------------------------
# API
# --------------------------------------------------------------------------


def test_api_rule_crud(client) -> None:
    stats = client.get("/api/suricata/rules/stats")
    assert stats.status_code == 200
    assert stats.json()["total"] == 0

    created = client.post("/api/suricata/rules", json={"raw": STICKY_RULE})
    assert created.status_code == 201, created.text
    assert created.json()["sid"] == 9000001

    listed = client.get("/api/suricata/rules?severity=high")
    assert listed.status_code == 200
    assert listed.json()["total"] == 1

    disabled = client.put("/api/suricata/rules/9000001", json={"enabled": False})
    assert disabled.status_code == 200
    assert disabled.json()["enabled"] is False

    bad_edit = client.put("/api/suricata/rules/9000001", json={"raw": LEGACY_RULE})
    assert bad_edit.status_code == 400
    assert bad_edit.json()["error"]["code"] == "sid_mismatch"

    duplicate = client.post("/api/suricata/rules", json={"raw": STICKY_RULE})
    assert duplicate.status_code == 400
    assert duplicate.json()["error"]["code"] == "rule_exists"

    removed = client.delete("/api/suricata/rules/9000001")
    assert removed.status_code == 200
    assert removed.json()["ok"] is True
    assert client.get("/api/suricata/rules/9000001").status_code == 404


def test_api_imports_a_rule_file(client) -> None:
    body = "\n".join([STICKY_RULE, DNS_RULE, "# comment"])
    response = client.post(
        "/api/suricata/rules/import",
        files={"file": ("analyst.rules", body.encode("utf-8"), "text/plain")},
    )
    assert response.status_code == 200, response.text
    payload = response.json()
    assert payload["imported"] == 2
    assert payload["files"][0]["file"] == "analyst.rules"

    rejected = client.post(
        "/api/suricata/rules/import",
        files={"file": ("rules.exe", b"not a rule file", "application/octet-stream")},
    )
    assert rejected.status_code == 200
    assert rejected.json()["imported"] == 0
    assert rejected.json()["errors"]


def test_api_runs_rules_against_a_capture(client, run_analysis, http_capture) -> None:
    client.post("/api/suricata/rules", json={"raw": STICKY_RULE})
    analysis_id, detail = run_analysis(http_capture)
    assert detail["status"] == "completed"

    # The stage already ran inside the pipeline; the endpoint re-runs it on demand.
    response = client.post(f"/api/analyses/{analysis_id}/suricata/run")
    assert response.status_code == 200, response.text
    payload = response.json()
    assert payload["rules_evaluated"] >= 1
    assert payload["findings"] >= 0

    alerts = client.get(f"/api/analyses/{analysis_id}/suricata/alerts")
    assert alerts.status_code == 200
    assert alerts.json()["total"] == payload["findings"]

    unknown = client.post("/api/analyses/" + "0" * 32 + "/suricata/run")
    assert unknown.status_code == 404