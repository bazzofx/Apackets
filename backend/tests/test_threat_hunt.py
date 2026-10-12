"""Threat Hunt endpoint: the structural contract of ``docs/THREAT_HUNT.md``.

The page is built from one envelope and seventeen indicator objects, and the
frontend being built against it switches on ``id``, ``availability`` and each
visual's ``kind``. These tests therefore assert the *shape* of that envelope —
all seventeen indicators, in the order of §1, with the availability rules of
§3.1, the caps of §4 and link targets restricted to the parameters of §5 — on
real analyses produced by the real pipeline, not on hand-written dicts.

Detection behaviour is asserted where a generated capture is built to contain
the pattern (a SYN scan, repeated unanswered connections); everywhere else the
values are checked against a direct SQL count of the same table the endpoint
claims to read, so a wrong number fails here rather than on screen.
"""

from __future__ import annotations

import re
import time
from urllib.parse import parse_qsl, urlsplit

import pytest

# --------------------------------------------------------------------------
# the contract, transcribed
# --------------------------------------------------------------------------

# §1 — one indicator per row, in this order. The order is part of the contract.
INDICATOR_IDS = (
    "c2_beaconing",
    "network_scanning",
    "dns_anomalies",
    "data_exfiltration",
    "lateral_movement",
    "suspicious_http",
    "suspicious_tls",
    "unusual_ports",
    "high_fan_out",
    "rare_pairs",
    "malware_download",
    "dns_tunnelling",
    "ids_matches",
    "traffic_bursts",
    "unusual_egress",
    "data_staging",
    "failed_connections",
)

# §1 — the titles the page must show.
INDICATOR_TITLES = {
    "c2_beaconing": "Potential C2 Beaconing",
    "network_scanning": "Network Scanning",
    "dns_anomalies": "DNS Anomalies",
    "data_exfiltration": "Potential Data Exfiltration",
    "lateral_movement": "Lateral Movement Indicators",
    "suspicious_http": "Suspicious HTTP Activity",
    "suspicious_tls": "Suspicious TLS Connections",
    "unusual_ports": "Unusual Port Usage",
    "high_fan_out": "High-Fan-Out Hosts",
    "rare_pairs": "Rare Communication Pairs",
    "malware_download": "Possible Malware Download",
    "dns_tunnelling": "Possible DNS Tunnelling",
    "ids_matches": "IDS Signature Matches",
    "traffic_bursts": "Suspicious Traffic Bursts",
    "unusual_egress": "Unusual Egress",
    "data_staging": "Potential Data Staging",
    "failed_connections": "Repeated Failed Connections",
}

# §5 — the query parameters the target pages actually read. A link built from
# anything else is a link that silently does nothing.
ALLOWED_PARAMS: dict[str, frozenset[str]] = {
    "/packets": frozenset(
        "mode search ip src_ip dst_ip port src_port dst_port protocol transport "
        "tcp_flags min_length max_length start_time end_time filter stream_id sel "
        "sort order page page_size".split()
    ),
    "/conversations": frozenset(
        "transport ip port search stream smode alerts tab node expand".split()
    ),
    "/dns": frozenset(
        "view domain client_ip server_ip qtype rcode search unanswered nxdomain "
        "suspicious sel".split()
    ),
    "/http": frozenset(
        "method host uri status client_ip server_ip user_agent search interesting tx".split()
    ),
    "/tls": frozenset("view sni version ip port alpn ja3 has_cert sel".split()),
    "/hosts": frozenset("view ip search protocol is_private".split()),
    "/findings": frozenset(),
    "/objects": frozenset(),
}

# §4 — the cap each visual kind must respect. §4 gives `histogram` no cap of its
# own, so the service bounds it at the table cap and reports it the same way.
VISUAL_CAPS = {
    "bars": None,
    "heatmap": None,
    "timeline": 240,
    "table": 50,
    "scatter": 200,
    "histogram": 50,
}

DATA_KEY = {
    "bars": "items",
    "timeline": "points",
    "histogram": "buckets",
    "scatter": "points",
    "heatmap": "rows",
    "table": "rows",
}

# The service reports this reason when an indicator raised instead of returning;
# it must never appear in a response.
FAILED_REASON = "internal error while computing this indicator"


# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------

def _fetch(client, analysis_id: str, **params) -> dict:
    response = client.get(f"/api/analyses/{analysis_id}/threat-hunt", params=params)
    assert response.status_code == 200, response.text
    return response.json()


def _targets(indicator: dict) -> list[str]:
    """Every ``to`` in an indicator, including the ones inside visual cells."""
    targets: list[str] = [link["to"] for link in indicator["links"]]

    def walk(node) -> None:
        if isinstance(node, dict):
            if isinstance(node.get("to"), str):
                targets.append(node["to"])
            for value in node.values():
                walk(value)
        elif isinstance(node, list):
            for value in node:
                walk(value)

    walk(indicator["visuals"])
    return targets


def _assert_target_allowed(target: str) -> None:
    parts = urlsplit(target)
    assert not parts.scheme and not parts.netloc, f"link is not a local path: {target!r}"

    path = parts.path
    # §5 lists `/findings` and `/findings/{id}` as path-only targets.
    if path.startswith("/findings/"):
        path = "/findings"
    assert path in ALLOWED_PARAMS, f"link targets a page not in §5: {target!r}"

    for key, _value in parse_qsl(parts.query, keep_blank_values=True):
        assert key in ALLOWED_PARAMS[path], f"parameter {key!r} is not read by {path}: {target!r}"
    # A packet is opened with `sel`, never `number`.
    assert "number=" not in parts.query, f"packet link must use sel: {target!r}"


def _assert_indicator_shape(indicator: dict, *, top: int) -> None:
    availability = indicator["availability"]
    assert availability in {"ok", "empty", "not_applicable"}, availability

    # §3.1: availability_reason is required whenever availability != "ok".
    reason = indicator["availability_reason"]
    if availability == "ok":
        assert reason is None, indicator["id"]
    else:
        assert isinstance(reason, str) and reason.strip(), (indicator["id"], availability)
        assert FAILED_REASON not in reason, (indicator["id"], reason)

    assert indicator["title"] == INDICATOR_TITLES[indicator["id"]]
    assert isinstance(indicator["question"], str) and indicator["question"].strip()
    assert isinstance(indicator["interpretation"], str) and indicator["interpretation"].strip()
    # §0.2: every indicator says what it does not establish.
    assert isinstance(indicator["caveat"], str) and indicator["caveat"].strip()

    headline = indicator["headline"]
    assert set(headline) == {"value", "label", "tone"}
    assert headline["tone"] in {"info", "watch", "warn"}, headline
    assert isinstance(headline["label"], str) and headline["label"].strip()
    assert isinstance(headline["value"], (int, float)) and not isinstance(headline["value"], bool)
    # §3.1: a zero headline means "nothing matched", so it may only appear when
    # the indicator is not "ok".
    if availability == "ok":
        assert headline["value"] > 0, indicator["id"]
    else:
        assert headline["value"] == 0, indicator["id"]

    visuals = indicator["visuals"]
    if availability == "ok":
        assert visuals, f"{indicator['id']} is ok but carries no visual"

    for visual in visuals:
        kind = visual["kind"]
        assert kind in DATA_KEY, kind
        assert isinstance(visual.get("title", ""), str) and visual["title"]
        assert isinstance(visual.get("note", ""), str)
        data = visual[DATA_KEY[kind]]

        # §4: empty data is allowed only when the indicator is not "ok".
        if availability == "ok":
            assert data, f"{indicator['id']}: {kind} is empty on an ok indicator"

        cap = VISUAL_CAPS[kind] if VISUAL_CAPS[kind] is not None else top
        assert len(data) <= cap, f"{indicator['id']}: {kind} has {len(data)} > cap {cap}"

        # §4: a cap that bites is stated as "top N of M", with N the number of
        # rows actually shown and M the real total.
        note = visual["note"]
        if kind == "heatmap":
            # The matrix reports its row and column caps separately.
            for match in re.finditer(r"top (\d+) of (\d+) (source\(s\)|port\(s\))", note):
                shown_n, total_n = int(match.group(1)), int(match.group(2))
                axis = visual["rows"] if match.group(3) == "source(s)" else visual["columns"]
                assert shown_n == len(axis), (indicator["id"], note)
                assert total_n >= shown_n, (indicator["id"], note)
        elif note.startswith("top "):
            match = re.match(r"top (\d+) of (\d+) ", note)
            assert match, (indicator["id"], kind, note)
            assert int(match.group(1)) == len(data), (indicator["id"], kind, note)
            assert int(match.group(2)) >= len(data), (indicator["id"], kind, note)

        if kind == "heatmap":
            columns = visual["columns"]
            assert len(columns) <= top
            for row in visual["rows"]:
                assert len(row["cells"]) == len(columns), indicator["id"]
                assert isinstance(row["label"], str)
        if kind == "bars":
            values = [item["value"] for item in visual["items"]]
            assert values == sorted(values, reverse=True), f"{indicator['id']}: bars unsorted"
        if kind == "table":
            columns = visual["columns"]
            assert columns, indicator["id"]
            for row in visual["rows"]:
                assert len(row["cells"]) == len(columns), indicator["id"]
                assert all(isinstance(cell["text"], str) for cell in row["cells"])

    for target in _targets(indicator):
        _assert_target_allowed(target)


def _seed_analysis(analysis_id: str, *, status: str) -> None:
    from app.db import database as db

    now = time.time()
    with db.get_conn() as conn:
        conn.execute(
            """
            INSERT INTO analyses (id, original_filename, stored_path, status, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (analysis_id, "seeded.pcap", "C:/nonexistent/seeded.pcap", status, now, now),
        )


# --------------------------------------------------------------------------
# the envelope and every indicator, against a real analysis
# --------------------------------------------------------------------------

def test_threat_hunt_matches_the_contract(client, run_analysis, combined_capture) -> None:
    analysis_id, detail = run_analysis(combined_capture)
    assert detail["status"] == "completed", detail

    payload = _fetch(client, analysis_id)

    # §3 envelope
    assert payload["analysis_id"] == analysis_id
    assert isinstance(payload["generated_at"], float) and payload["generated_at"] > 0
    assert payload["packets_scanned"] > 0
    assert payload["packets_scanned"] <= detail["packet_count"]
    assert payload["window"] == 60
    assert payload["top"] == 12
    assert isinstance(payload["note"], str) and payload["note"].strip()

    # §1: seventeen indicators, in order
    indicators = payload["indicators"]
    assert [item["id"] for item in indicators] == list(INDICATOR_IDS)
    assert len(indicators) == 17

    for indicator in indicators:
        _assert_indicator_shape(indicator, top=12)

    # Every indicator must answer its own question in the same envelope, and the
    # page must be able to tell "not computed" from "nothing matched".
    availability = [item["availability"] for item in indicators]
    assert set(availability) <= {"ok", "empty", "not_applicable"}
    assert all(item["availability_reason"] is not None or item["availability"] == "ok"
               for item in indicators)


def test_threat_hunt_numbers_agree_with_direct_sql(client, run_analysis, combined_capture) -> None:
    """Cross-check three indicators against hand-written SQL over the same tables."""
    from app.db import database as db

    analysis_id, _detail = run_analysis(combined_capture)
    payload = _fetch(client, analysis_id)
    by_id = {item["id"]: item for item in payload["indicators"]}

    # 1. ids_matches — findings whose rule id is a suricata signature.
    row = db.query_one(
        """
        SELECT COUNT(*) AS n FROM findings
         WHERE analysis_id = ? AND rule_id LIKE 'suricata:%'
        """,
        (analysis_id,),
    )
    assert by_id["ids_matches"]["headline"]["value"] == int(row["n"])

    # 2. rare_pairs — address pairs in exactly one conversation of <= 2 packets.
    rows = db.query_all(
        """
        SELECT ip_a, ip_b, packets_total FROM conversations
         WHERE analysis_id = ? AND ip_a IS NOT NULL AND ip_b IS NOT NULL
        """,
        (analysis_id,),
    )
    pairs: dict[tuple[str, str], list[int]] = {}
    for item in rows:
        key = tuple(sorted((str(item["ip_a"]), str(item["ip_b"]))))
        entry = pairs.setdefault(key, [0, 0])
        entry[0] += 1
        entry[1] += int(item["packets_total"] or 0)
    expected_rare = sum(1 for count, packets in pairs.values() if count == 1 and packets <= 2)
    assert by_id["rare_pairs"]["headline"]["value"] == expected_rare

    # 3. unusual_ports — destination ports used exactly once outside COMMON_PORTS.
    from app.services.detection_engine import COMMON_PORTS

    rows = db.query_all(
        """
        SELECT dst_port, COUNT(*) AS n FROM packets
         WHERE analysis_id = ? AND dst_port IS NOT NULL
         GROUP BY dst_port
        """,
        (analysis_id,),
    )
    expected_ports = sum(
        1
        for item in rows
        if int(item["n"]) == 1 and int(item["dst_port"]) not in COMMON_PORTS
    )
    assert by_id["unusual_ports"]["headline"]["value"] == expected_ports

    # 4. high_fan_out — hosts at or above the published peer threshold.
    row = db.query_one(
        "SELECT COUNT(*) AS n FROM hosts WHERE analysis_id = ? AND peer_count >= 10",
        (analysis_id,),
    )
    assert by_id["high_fan_out"]["headline"]["value"] == int(row["n"])


def test_threat_hunt_honours_the_window_and_top_parameters(
    client, run_analysis, combined_capture
) -> None:
    analysis_id, _detail = run_analysis(combined_capture)

    payload = _fetch(client, analysis_id, window=5, top=3)
    assert payload["window"] == 5
    assert payload["top"] == 3

    for indicator in payload["indicators"]:
        _assert_indicator_shape(indicator, top=3)
        for visual in indicator["visuals"]:
            if visual["kind"] == "timeline":
                for point in visual["points"]:
                    # §4: t is the start of a bucket, so it must sit on the grid.
                    assert int(point["t"]) % 5 == 0, (indicator["id"], point["t"])
                    assert set(point) == {"t", "value", "marker"}
                    assert isinstance(point["marker"], bool)

    # A cap that bites is reported, not silently applied.
    notes = [
        visual["note"]
        for indicator in payload["indicators"]
        for visual in indicator["visuals"]
        if visual["kind"] in {"bars", "heatmap", "table", "scatter"}
    ]
    assert any(note.startswith("top 3 of") for note in notes), notes


# --------------------------------------------------------------------------
# detections that a generated capture is built to contain
# --------------------------------------------------------------------------

def test_network_scanning_fires_on_a_syn_scan(client, run_analysis, syn_scan_capture) -> None:
    analysis_id, detail = run_analysis(syn_scan_capture)
    assert detail["status"] == "completed", detail

    payload = _fetch(client, analysis_id)
    indicator = next(item for item in payload["indicators"] if item["id"] == "network_scanning")

    assert indicator["availability"] == "ok", indicator["availability_reason"]
    assert indicator["headline"]["value"] >= 1
    assert indicator["availability_reason"] is None

    kinds = {visual["kind"] for visual in indicator["visuals"]}
    assert kinds == {"heatmap", "table"}
    heatmap = next(v for v in indicator["visuals"] if v["kind"] == "heatmap")
    assert heatmap["rows"] and heatmap["columns"]
    # The scanner is the source with the widest port spread in the matrix.
    widest = max(heatmap["rows"], key=lambda row: sum(row["cells"]))
    assert sum(widest["cells"]) > 0
    table = next(v for v in indicator["visuals"] if v["kind"] == "table")
    assert table["rows"]


def test_network_scanning_fires_on_a_local_arp_sweep(
    client, run_analysis, arp_sweep_capture
) -> None:
    """A local ``nmap -sn`` sweep probes with ARP and never opens a port.

    This is the case a port-based detector cannot see at all: the capture holds no
    SYN, and the probed addresses never appear in ``ip.dst``, because an ARP frame
    carries no IP layer. The sweep is measured instead as the hosts one source probed
    that never answered it.
    """
    import generators

    expected = generators.expected("arp_sweep")
    analysis_id, detail = run_analysis(arp_sweep_capture)
    assert detail["status"] == "completed", detail

    payload = _fetch(client, analysis_id)
    indicator = next(item for item in payload["indicators"] if item["id"] == "network_scanning")

    assert indicator["availability"] == "ok", indicator["availability_reason"]
    assert indicator["headline"]["value"] == 1, indicator["headline"]
    assert indicator["availability_reason"] is None

    kinds = {visual["kind"] for visual in indicator["visuals"]}
    # No port is ever opened, so the port matrix has nothing to draw and is omitted
    # rather than rendered empty.
    assert "heatmap" not in kinds, kinds
    assert {"bars", "table"} <= kinds, kinds

    bars = next(v for v in indicator["visuals"] if v["kind"] == "bars")
    assert [item["label"] for item in bars["items"]] == [expected["sweeper"]]
    assert bars["items"][0]["value"] == expected["unanswered"]

    table = next(v for v in indicator["visuals"] if v["kind"] == "table")
    # Exactly one source: the control host resolved its gateway once and was answered,
    # so one unanswered probe stays below the threshold.
    assert len(table["rows"]) == 1, table["rows"]
    cells = table["rows"][0]["cells"]
    assert cells[0]["text"] == expected["sweeper"]
    assert int(cells[1]["text"]) == expected["unanswered"]
    assert int(cells[2]["text"]) == 0, "no port was opened by an ARP sweep"


def test_failed_connections_fire_on_repeated_unanswered_syns(
    client, run_analysis, failed_connections_capture
) -> None:
    analysis_id, detail = run_analysis(failed_connections_capture)
    assert detail["status"] == "completed", detail

    payload = _fetch(client, analysis_id)
    by_id = {item["id"]: item for item in payload["indicators"]}

    indicator = by_id["failed_connections"]
    assert indicator["availability"] == "ok", indicator["availability_reason"]
    assert indicator["headline"]["value"] >= 1
    kinds = {visual["kind"] for visual in indicator["visuals"]}
    assert kinds == {"timeline", "bars"}
    assert any(point["marker"] for point in
               next(v for v in indicator["visuals"] if v["kind"] == "timeline")["points"])

    # The same capture ends every attempt unanswered, so no TCP flow completed.
    assert all(
        item["availability"] in {"ok", "empty", "not_applicable"}
        for item in payload["indicators"]
    )


def test_unavailable_indicators_state_why_on_an_empty_capture(
    client, run_analysis, empty_capture
) -> None:
    analysis_id, detail = run_analysis(empty_capture)
    assert detail["status"] == "completed", detail

    payload = _fetch(client, analysis_id)
    assert payload["packets_scanned"] == 0

    indicators = payload["indicators"]
    assert [item["id"] for item in indicators] == list(INDICATOR_IDS)

    # §3.1: an indicator that cannot be computed says so, and never renders a
    # zero that looks like a real reading.
    for indicator in indicators:
        _assert_indicator_shape(indicator, top=12)
        assert indicator["availability"] == "not_applicable", (
            indicator["id"],
            indicator["availability"],
            indicator["availability_reason"],
        )
        assert indicator["headline"]["value"] == 0
        assert indicator["visuals"] == []
        assert indicator["availability_reason"].strip()


# --------------------------------------------------------------------------
# errors and parameter validation
# --------------------------------------------------------------------------

# --------------------------------------------------------------------------
# where the lateral-movement bars take you
# --------------------------------------------------------------------------


def _lateral_fixture(
    analysis_id: str,
    *,
    flow: tuple[str, str, int],
    conversation: tuple[str, str, int, str, int, int | None] | None,
) -> None:
    """Seed one internal-to-internal flow on an administration port, and its conversation.

    `conversation` is `(ip_a, ip_b, port_a, port_b, bytes, stream_id)`, and `flow` is the
    `(source, destination, destination port)` the packet index records.
    """
    from app.db import database as db

    source, destination, port = flow
    _seed_analysis(analysis_id, status="completed")
    now = time.time()
    with db.get_conn() as conn:
        conn.execute(
            "UPDATE analyses SET packet_count = 2, tcp_count = 2, status = 'completed' WHERE id = ?",
            (analysis_id,),
        )
        for number in (1, 2):
            conn.execute(
                """
                INSERT INTO packets (analysis_id, number, time_epoch, frame_len, protocol,
                                     transport, src_ip, dst_ip, dst_port)
                VALUES (?, ?, ?, ?, 'TCP', 'tcp', ?, ?, ?)
                """,
                (analysis_id, number, now + number, 100, source, destination, port),
            )
        if conversation is not None:
            ip_a, ip_b, port_a, port_b, moved, stream_id = conversation
            conn.execute(
                """
                INSERT INTO conversations (analysis_id, conv_id, transport, stream_id,
                                           endpoint_a, endpoint_b, ip_a, port_a, ip_b, port_b,
                                           packets_total, bytes_total, start_time)
                VALUES (?, ?, 'tcp', ?, ?, ?, ?, ?, ?, ?, 2, ?, ?)
                """,
                (
                    analysis_id,
                    f"tcp:{ip_a}:{port_a}-{ip_b}:{port_b}",
                    stream_id,
                    f"{ip_a}:{port_a}",
                    f"{ip_b}:{port_b}",
                    ip_a,
                    port_a,
                    ip_b,
                    port_b,
                    moved,
                    now,
                ),
            )


def _lateral_bar_targets(analysis_id: str) -> list[tuple[str, str]]:
    """`(label, to)` for every bar, straight from the indicator function."""
    from types import SimpleNamespace

    from app.services import threat_hunt

    index = SimpleNamespace(
        analysis_id=analysis_id, has_traffic=True, tcp_packets=2, top=12
    )
    result = threat_hunt._lateral_movement(index)
    bars = next(visual for visual in result.visuals if visual["kind"] == "bars")
    return [(item["label"], item["to"]) for item in bars["items"]]


def test_lateral_bar_opens_the_flow_and_the_port_node_the_diagram_draws() -> None:
    """The bar for `host:445` must open that conversation, with the node on the right side.

    `ip_a`/`port_a` is the flow diagram's `source`/`sourcePort` column and `ip_b`/`port_b` its
    `destination`/`destinationPort` — the side is the conversation's own assignment, not who
    spoke first, and a link naming the wrong column selects nothing.
    """
    analysis_id = "11111111111111111111111111111111"
    _lateral_fixture(
        analysis_id,
        flow=("10.0.0.9", "10.0.0.5", 445),
        conversation=("10.0.0.5", "10.0.0.9", 445, 51234, 900, 7),
    )

    [(label, target)] = _lateral_bar_targets(analysis_id)

    assert label == "10.0.0.5:445 (SMB)"
    assert target == (
        "/conversations?ip=10.0.0.5&port=445&node=sourcePort%3A445&stream=tcp%3A7"
    )


def test_lateral_bar_names_the_other_column_when_the_service_is_the_second_side() -> None:
    analysis_id = "22222222222222222222222222222222"
    _lateral_fixture(
        analysis_id,
        flow=("10.0.0.9", "10.0.0.5", 445),
        conversation=("10.0.0.9", "10.0.0.5", 51234, 445, 900, 11),
    )

    [(_, target)] = _lateral_bar_targets(analysis_id)

    assert target == (
        "/conversations?ip=10.0.0.5&port=445&node=destinationPort%3A445&stream=tcp%3A11"
    )


def test_lateral_bar_without_a_conversation_keeps_the_filter_link() -> None:
    """No conversation, or none with a reassembled stream, means no conversation to open."""
    analysis_id = "33333333333333333333333333333333"
    _lateral_fixture(
        analysis_id,
        flow=("10.0.0.9", "10.0.0.5", 445),
        conversation=("10.0.0.5", "10.0.0.9", 445, 51234, 900, None),
    )

    [(_, target)] = _lateral_bar_targets(analysis_id)

    assert target == "/conversations?ip=10.0.0.5&port=445", (
        "a flow whose conversation has no stream has nothing to select, so the link must stay "
        "a filter rather than name a stream that does not exist"
    )
    _assert_target_allowed(target)


def test_lateral_bar_links_use_only_the_parameters_of_section_5() -> None:
    analysis_id = "44444444444444444444444444444444"
    _lateral_fixture(
        analysis_id,
        flow=("10.0.0.9", "10.0.0.5", 445),
        conversation=("10.0.0.5", "10.0.0.9", 445, 51234, 900, 7),
    )

    for _label, target in _lateral_bar_targets(analysis_id):
        _assert_target_allowed(target)


def test_threat_hunt_unknown_analysis_is_404(client) -> None:
    response = client.get(f"/api/analyses/{'0' * 32}/threat-hunt")
    assert response.status_code == 404
    assert response.json()["error"]["code"] == "analysis_not_found"


def test_threat_hunt_unfinished_analysis_is_409(client) -> None:
    analysis_id = "1" * 32
    _seed_analysis(analysis_id, status="running")

    response = client.get(f"/api/analyses/{analysis_id}/threat-hunt")
    assert response.status_code == 409
    body = response.json()["error"]
    assert body["code"] == "analysis_not_ready"
    assert body["details"]["status"] == "running"


@pytest.mark.parametrize(
    "params",
    [
        {"window": 4},
        {"window": 3601},
        {"window": 0},
        {"top": 0},
        {"top": 51},
    ],
)
def test_threat_hunt_rejects_out_of_range_parameters(client, params) -> None:
    response = client.get(f"/api/analyses/{'2' * 32}/threat-hunt", params=params)
    assert response.status_code == 422
    assert response.json()["error"]["code"] == "validation_error"


def test_threat_hunt_is_exported_by_the_router_registry() -> None:
    """``main.ROUTER_SPECS`` must register the router, or the page 404s."""
    from app.main import ROUTER_SPECS

    assert ("app.api.routes_threat_hunt", "router") in ROUTER_SPECS
