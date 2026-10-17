"""Suricata rule parsing, storage and matching.

These tests cover the parts that are easy to get subtly wrong: attaching a
buffer to the right content option (Suricata writes ``content:"x"; http_uri;
nocase;`` as separate options that describe the content *before* them),
expanding rule variables, keeping enable/disable state across a re-import, and
refusing to half-match a rule whose options cannot be honoured.
"""

from __future__ import annotations

import json
import time

import pytest

from app.db import database as db
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
    assert [record["buffer"] for record in matched] == ["http.uri"]
    assert matched[0]["matched_text"] == "/admin"
    assert matched[0]["offset"] == 0

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
# evidence: the bytes that satisfied the condition, from their own buffer
# --------------------------------------------------------------------------

# The real rule, verbatim from
# backend/rules/daffainfo/http/web-attacks/cross-site-scripting.rules. Its
# required inspection buffer is the HTTP client request body (`http_client_body`,
# which the engine resolves to `http.request_body`), not the URI and not a header.
XSS_BODY_RULE = (
    'alert http any any -> any any (msg:"Possible XSS attack, js protocol in '
    'request body"; content:"javascript|3A|"; nocase; http_client_body; '
    "classtype:web-application-attack; sid:50100017; rev:1;)"
)

URI_ONLY_REQUEST = {
    "uri": "/search?q=javascript:alert(1)",
    "full_uri": "http://example.test/search?q=javascript:alert(1)",
    "method": "POST",
    "host": "example.test",
    "request_headers": '{"Host": "example.test", "X-Debug": "javascript:alert(1)"}',
    "request_body": "q=hello+world&page=2",
}


def _http_row(**overrides):
    """One `http_transactions` row, as `http_buffers` reads it."""
    row = {
        "id": 1,
        "time_epoch": 1_700_000_000.0,
        "client_ip": "10.0.0.5",
        "client_port": 51000,
        "server_ip": "93.184.216.34",
        "server_port": 80,
        "method": "POST",
        "host": "example.test",
        "uri": "/submit",
        "full_uri": "http://example.test/submit",
        "version": "HTTP/1.1",
        "status_code": 200,
        "user_agent": "Mozilla/5.0",
        "referer": None,
        "request_headers": '{"Host": "example.test"}',
        "response_headers": '{"Content-Type": "text/html"}',
        "request_body": None,
        "response_body": None,
        "request_packet": 10,
        "response_packet": 12,
    }
    row.update(overrides)
    return row


def _xss_rule(fresh_db):  # noqa: ARG001 - fresh_db empties the tables first
    sr.import_rules([sr.parse_rule(XSS_BODY_RULE)], source="test")
    rules, _ = suricata_engine.load_rules()
    assert [rule.sid for rule in rules] == [50100017]
    return rules[0]


def test_a_uri_cannot_satisfy_a_request_body_rule(fresh_db) -> None:  # noqa: ARG001
    """The regression: URI and header carry `javascript:`, the body does not.

    SID 50100017 inspects `http_client_body`, so nothing in the request line or
    the headers can satisfy it. A finding here would be evidence taken from a
    buffer the rule never named.
    """
    rule = _xss_rule(fresh_db)
    buffers = suricata_engine.http_buffers(_http_row(**URI_ONLY_REQUEST))

    # The trap is present in the buffers the rule must not use...
    assert "javascript:" in buffers["http.uri"]
    assert "javascript:" in buffers["http.request_header"]
    assert "javascript:" in buffers[""]
    assert "javascript:" not in buffers["http.request_body"]

    assert suricata_engine.evaluate_rule(rule, _context(), buffers) is None


def test_a_header_cannot_satisfy_a_request_body_rule(fresh_db) -> None:  # noqa: ARG001
    rule = _xss_rule(fresh_db)
    buffers = suricata_engine.http_buffers(
        _http_row(request_headers='{"X-Debug": "javascript:alert(1)"}', request_body=None)
    )
    assert "http.request_body" not in buffers
    assert suricata_engine.evaluate_rule(rule, _context(), buffers) is None


def test_a_body_match_records_the_body_buffer_its_bytes_and_its_offset(fresh_db) -> None:  # noqa: ARG001
    """The positive case: the body carries `javascript:`, so the body is evidence."""
    rule = _xss_rule(fresh_db)
    body = "comment=ok&redirect=javascript:alert(document.cookie)&x=1"
    buffers = suricata_engine.http_buffers(
        _http_row(uri="/submit?q=clean", full_uri="http://example.test/submit?q=clean", request_body=body)
    )

    records = suricata_engine.evaluate_rule(rule, _context(), buffers)
    assert records is not None
    record = records[0]

    assert record["buffer"] == "http.request_body"
    assert record["encoding"] == "hex"          # the rule writes `|3A|`
    assert record["matched"] == b"javascript:"
    assert record["matched_text"] == "javascript:"
    assert record["matched_hex"] == "6a6176617363726970743a"
    assert record["offset"] == body.encode().index(b"javascript:")
    assert "evidence_error" not in record

    # The displayed excerpt is the body around the match, and the URI is nowhere
    # in it - the field that used to be shown for this rule.
    assert "redirect=" in record["excerpt"]
    assert "/submit" not in record["excerpt"]


def test_the_matched_bytes_are_the_buffers_own_bytes_not_the_rule_text(fresh_db) -> None:  # noqa: ARG001
    """`nocase` matches in either case; the evidence keeps the buffer's spelling."""
    rule = _xss_rule(fresh_db)
    body = "x=<a href='JaVaScRiPt:alert(1)'>go</a>"
    buffers = suricata_engine.http_buffers(_http_row(request_body=body))

    record = suricata_engine.evaluate_rule(rule, _context(), buffers)[0]
    assert record["matched"] == b"JaVaScRiPt:"
    assert record["matched_text"] == "JaVaScRiPt:"
    assert record["matched_hex"] == b"JaVaScRiPt:".hex()
    # The rule wrote `javascript|3A|`; the evidence is what the buffer holds.
    assert record["matched"] != b"javascript:"


def test_a_hit_carries_its_buffer_bytes_and_offset_for_the_interface(fresh_db) -> None:  # noqa: ARG001
    """The hit the findings table stores: one record, self-describing."""
    rule = _xss_rule(fresh_db)
    body = "next=javascript:alert(1)"
    buffers = suricata_engine.http_buffers(_http_row(request_body=body))
    records = suricata_engine.evaluate_rule(rule, _context(), buffers)

    hit = {"packet": 10, **suricata_engine._evidence_fields(records)}
    assert hit["fields"] == ["http.request_body"]
    assert hit["buffer"] == "http.request_body"
    assert hit["offset"] == body.index("javascript:")
    assert hit["matched"] == "javascript:"
    assert hit["matched_hex"] == "6a6176617363726970743a"
    assert hit["excerpt"] == body
    assert hit["conditions"][0]["buffer"] == "http.request_body"
    # JSON is how the finding is stored, so every field has to survive it.
    assert json.loads(json.dumps(hit))["matched"] == "javascript:"


def test_api_evidence_for_a_body_rule_comes_from_the_body(client) -> None:
    """End to end: what the interface shows is the body the rule inspected."""
    client.post("/api/suricata/rules", json={"raw": XSS_BODY_RULE})
    analysis_id = "5" * 32
    now = time.time()
    with db.get_conn() as conn:
        conn.execute(
            """
            INSERT OR REPLACE INTO analyses (
                id, original_filename, stored_path, file_size, file_type, status,
                progress, stage, packet_count, created_at, updated_at
            ) VALUES (?, 'xss.pcap', 'xss.pcap', 0, 'pcap', 'completed', 100,
                      'completed', 0, ?, ?)
            """,
            (analysis_id, now, now),
        )
        # Row 1: the URI and a header carry the payload; the body does not.
        conn.execute(
            """
            INSERT INTO http_transactions (
                analysis_id, time_epoch, stream_id, client_ip, client_port,
                server_ip, server_port, method, host, uri, full_uri, content_type,
                request_headers, request_body, request_packet, response_packet
            ) VALUES (?, ?, 1, '10.0.0.5', 51000, '93.184.216.34', 80, 'POST',
                      'example.test', ?, ?, 'text/html', ?, ?, 10, 12)
            """,
            (
                analysis_id, now, URI_ONLY_REQUEST["uri"], URI_ONLY_REQUEST["full_uri"],
                URI_ONLY_REQUEST["request_headers"], URI_ONLY_REQUEST["request_body"],
            ),
        )
        # Row 2: the same payload inside the request body.
        conn.execute(
            """
            INSERT INTO http_transactions (
                analysis_id, time_epoch, stream_id, client_ip, client_port,
                server_ip, server_port, method, host, uri, full_uri, content_type,
                request_headers, request_body, request_packet, response_packet
            ) VALUES (?, ?, 2, '10.0.0.5', 51001, '93.184.216.34', 80, 'POST',
                      'example.test', '/submit?q=clean', 'http://example.test/submit?q=clean',
                      'text/html', '{"Host": "example.test"}', ?, 20, 22)
            """,
            (analysis_id, now, "comment=javascript:alert(1)"),
        )

    run = client.post(f"/api/analyses/{analysis_id}/suricata/run")
    assert run.status_code == 200, run.text

    alerts = client.get(f"/api/analyses/{analysis_id}/suricata/alerts")
    assert alerts.status_code == 200, alerts.text
    items = alerts.json()["items"]
    # Only the body row matched: the URI-only request produced no finding at all.
    assert [item["evidence"]["suricata_sid"] for item in items] == [50100017]

    evidence = items[0]["evidence"]
    match = evidence["matches"][0]
    assert evidence["buffers"] == ["http.request_body"]
    assert match["fields"] == ["http.request_body"]
    assert match["buffer"] == "http.request_body"
    assert match["matched"] == "javascript:"
    assert match["offset"] == len(b"comment=")
    assert match["excerpt"].startswith("comment=javascript:")
    assert "q=javascript" not in match["excerpt"]
    assert match["packet"] == 20


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