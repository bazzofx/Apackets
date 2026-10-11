"""Entity profile endpoints: the contract of ``docs/ENTITY_PROFILE.md``.

The Investigate page is built from one search response and one profile response
per entity, and the frontend switches on ``availability`` and on each visual's
``kind``. These tests therefore assert the *shape* of both envelopes — the
question sets of §4.1/§4.2/§4.3 in order, the availability rules of §3, the caps
of §3 and link targets restricted to the parameters of §5 — on analyses produced
by the real pipeline, not on hand-written dicts.

Where a figure can be checked against the table the endpoint claims to read, it
is: the numbers below are compared with a direct SQL count over the same index,
so a wrong value fails here rather than on screen. The questions a capture
*cannot* answer are asserted as ``not_applicable`` with a reason, because that
distinction is the reason the vocabulary exists.
"""

from __future__ import annotations

import re
import time
from urllib.parse import parse_qsl, quote, urlsplit

import pytest

# --------------------------------------------------------------------------
# the contract, transcribed
# --------------------------------------------------------------------------

# §4.1 — the questions asked of an address, in contract order.
IP_QUESTIONS = (
    "volume_by_direction",
    "activity_over_time",
    "connections",
    "peer_fanout",
    "ports_offered",
    "ports_contacted",
    "protocol_mix",
    "domains_resolved",
    "domains_contacted",
    "dns_health",
    "http_activity",
    "clear_text_credentials",
    "files",
    "tls_fingerprints",
    "fingerprint_peers",
    "findings",
)

# §4.2 — the questions asked of a name.
DOMAIN_QUESTIONS = (
    "clients",
    "answers",
    "rcodes",
    "activity_over_time",
    "tls_sessions",
    "http_transactions",
    "files",
    "findings",
)

# §4.3 — the questions asked of a URL.
URL_QUESTIONS = (
    "clients",
    "status_codes",
    "methods",
    "activity_over_time",
    "request_shape",
    "files",
    "findings",
)

QUESTIONS = {"ip": IP_QUESTIONS, "domain": DOMAIN_QUESTIONS, "url": URL_QUESTIONS}

# §3 — the cap each visual kind must respect.
VISUAL_CAPS = {
    "bars": 12,
    "timeline": 240,
    "histogram": 50,
    "scatter": 200,
    "heatmap": 15,
    "table": 50,
}

DATA_KEY = {
    "bars": "items",
    "timeline": "points",
    "histogram": "buckets",
    "scatter": "points",
    "heatmap": "rows",
    "table": "rows",
}

# §5 — the query parameters the target pages actually read. This is the full
# table of `docs/THREAT_HUNT.md` §5, which `docs/ENTITY_PROFILE.md` §5 defers to;
# `/objects?search=` is the one addition `docs/ENTITY_PROFILE.md` §5 names and
# `app/api/routes_objects.py` really reads.
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
    "/objects": frozenset({"search"}),
    # `docs/ENTITY_PROFILE.md` §5 fixes the finding link as
    # `/findings/<id>?tab=overview`, which the page reads; the id is encoded
    # because it contains a colon.
    "/findings": frozenset({"tab"}),
}

# Response codes the services report when a question raised instead of returning;
# it must never appear in a response.
FAILED_REASON = "internal error while computing this question"


# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------


def _search(client, analysis_id: str, q: str, **params) -> dict:
    response = client.get(f"/api/analyses/{analysis_id}/profile", params={"q": q, **params})
    assert response.status_code == 200, response.text
    return response.json()


def _profile(client, analysis_id: str, kind: str, entity: str) -> dict:
    response = client.get(
        f"/api/analyses/{analysis_id}/profile/{kind}/{quote(entity, safe='')}"
    )
    assert response.status_code == 200, response.text
    return response.json()


def _by_id(payload: dict) -> dict[str, dict]:
    return {question["id"]: question for question in payload["questions"]}


def _count(sql: str, params: tuple = ()) -> int:
    from app.db import database as db

    row = db.query_one(sql, params)
    return int(row["n"]) if row else 0


def _name_references(analysis_id: str, name: str) -> int:
    """§2: a domain match counts its rows across DNS, HTTP hosts and TLS SNI."""
    return _count(
        """
        SELECT (
                 (SELECT COUNT(*) FROM dns_queries
                   WHERE analysis_id = ? AND query_name = ? COLLATE NOCASE)
               + (SELECT COUNT(*) FROM http_transactions
                   WHERE analysis_id = ? AND host = ? COLLATE NOCASE)
               + (SELECT COUNT(*) FROM tls_sessions
                   WHERE analysis_id = ? AND sni = ? COLLATE NOCASE)
               ) AS n
        """,
        (analysis_id, name, analysis_id, name, analysis_id, name),
    )


def _targets(question: dict) -> list[str]:
    """Every ``to`` in a question, including the ones inside visual cells."""
    targets: list[str] = [link["to"] for link in question["links"]]

    def walk(node) -> None:
        if isinstance(node, dict):
            if isinstance(node.get("to"), str):
                targets.append(node["to"])
            for value in node.values():
                walk(value)
        elif isinstance(node, list):
            for value in node:
                walk(value)

    walk(question["visuals"])
    return targets


def _assert_target_allowed(target: str) -> None:
    parts = urlsplit(target)
    assert not parts.scheme and not parts.netloc, f"link is not a local path: {target!r}"

    path = parts.path
    # §5 lists `/findings/{id}` as a path-only target.
    if path.startswith("/findings/"):
        path = "/findings"
    assert path in ALLOWED_PARAMS, f"link targets a page not in §5: {target!r}"

    for key, _value in parse_qsl(parts.query, keep_blank_values=True):
        assert key in ALLOWED_PARAMS[path], f"parameter {key!r} is not read by {path}: {target!r}"
    assert "number=" not in parts.query, f"packet link must use sel: {target!r}"


def _assert_question_shape(question: dict) -> None:
    availability = question["availability"]
    assert availability in {"ok", "empty", "not_applicable"}, availability

    # §3: the reason is required whenever availability is not "ok".
    reason = question["availability_reason"]
    if availability == "ok":
        assert reason is None, question["id"]
    else:
        assert isinstance(reason, str) and reason.strip(), (question["id"], availability)
        assert FAILED_REASON not in reason, (question["id"], reason)

    for field in ("title", "question", "interpretation", "caveat"):
        assert isinstance(question[field], str) and question[field].strip(), (
            question["id"],
            field,
        )

    headline = question["headline"]
    assert set(headline) == {"value", "label", "tone"}
    assert headline["tone"] in {"info", "watch", "warn"}, headline
    assert isinstance(headline["label"], str) and headline["label"].strip()
    assert isinstance(headline["value"], (int, float)) and not isinstance(headline["value"], bool)
    # §3: a zero headline means "nothing matched", so it may only appear when the
    # question is not "ok".
    if availability == "ok":
        assert headline["value"] > 0, question["id"]
    else:
        assert headline["value"] == 0, question["id"]

    visuals = question["visuals"]
    if availability == "ok":
        assert visuals, f"{question['id']} is ok but carries no visual"
    if availability == "not_applicable":
        assert visuals == [], question["id"]
        assert question["links"] == [], question["id"]

    for visual in visuals:
        kind = visual["kind"]
        assert kind in DATA_KEY, kind
        assert isinstance(visual.get("title", ""), str)
        assert isinstance(visual.get("note", ""), str)
        data = visual[DATA_KEY[kind]]

        # §3: empty data is allowed only when the question is not "ok".
        if availability == "ok":
            assert data, f"{question['id']}: {kind} is empty on an ok question"

        if kind == "heatmap":
            # The matrix reports its row and column caps separately.
            columns = visual["columns"]
            assert len(columns) <= VISUAL_CAPS["heatmap"], question["id"]
            for match in re.finditer(r"showing (\d+) of (\d+) (peer\(s\)|port\(s\))", visual["note"]):
                shown_n, total_n = int(match.group(1)), int(match.group(2))
                axis = visual["rows"] if match.group(3) == "peer(s)" else visual["columns"]
                assert shown_n == len(axis), (question["id"], visual["note"])
                assert total_n >= shown_n, (question["id"], visual["note"])
            for row in visual["rows"]:
                assert len(row["cells"]) == len(columns), question["id"]
                assert isinstance(row["label"], str)
        else:
            cap = VISUAL_CAPS[kind]
            assert len(data) <= cap, f"{question['id']}: {kind} has {len(data)} > cap {cap}"
            if visual["note"].startswith("showing "):
                match = re.match(r"showing (\d+) of (\d+) ", visual["note"])
                assert match, (question["id"], kind, visual["note"])
                assert int(match.group(1)) == len(data), (question["id"], kind, visual["note"])
                assert int(match.group(2)) >= len(data), (question["id"], kind, visual["note"])

        if kind == "bars":
            values = [item["value"] for item in visual["items"]]
            assert values == sorted(values, reverse=True), f"{question['id']}: bars unsorted"
        if kind == "table":
            columns = visual["columns"]
            assert columns, question["id"]
            for row in visual["rows"]:
                assert len(row["cells"]) == len(columns), question["id"]
                assert all(isinstance(cell["text"], str) for cell in row["cells"])
        if kind == "scatter":
            for point in visual["points"]:
                assert isinstance(point["x"], (int, float))
                assert isinstance(point["y"], (int, float))
                assert isinstance(point["label"], str)
        if kind == "timeline":
            for point in visual["points"]:
                assert set(point) == {"t", "value", "marker"}
                assert int(point["t"]) % 60 == 0, point
                assert isinstance(point["marker"], bool)

    for target in _targets(question):
        _assert_target_allowed(target)


def _assert_profile_shape(payload: dict, *, kind: str, entity: str) -> None:
    assert payload["kind"] == kind
    assert payload["entity"] == entity
    assert isinstance(payload["generated_at"], float) and payload["generated_at"] > 0

    summary = payload["summary"]
    assert set(summary) == {
        "label",
        "scope",
        "mac",
        "hostnames",
        "first_seen",
        "last_seen",
        "packets",
        "bytes",
        "note",
    }
    assert isinstance(summary["label"], str) and summary["label"]
    assert isinstance(summary["hostnames"], list)
    # §2 annotates `mac` and `first_seen` as nullable but shows `packets`/`bytes`
    # as plain numbers, so those two are always numbers — the frontend renders
    # them as counts.
    assert isinstance(summary["packets"], int), summary["packets"]
    assert isinstance(summary["bytes"], int), summary["bytes"]
    assert summary["note"] is None or isinstance(summary["note"], str)

    questions = payload["questions"]
    assert [item["id"] for item in questions] == list(QUESTIONS[kind])
    for question in questions:
        _assert_question_shape(question)

    # §3: every question of this kind appears in the map, so a reader can tell
    # "nothing was capped" from "this question was not computed", and a cap that
    # bit is reported truthfully.
    assert set(payload["truncated"]) == set(QUESTIONS[kind])
    for question in questions:
        for visual in question["visuals"]:
            if visual["note"].startswith("showing "):
                assert payload["truncated"][question["id"]] is True, question["id"]


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
# §2 — search
# --------------------------------------------------------------------------


def test_search_resolves_every_kind_of_entity(client, run_analysis, combined_capture) -> None:
    """One query finds addresses, names and URLs, and each match is actionable."""
    analysis_id, detail = run_analysis(combined_capture)
    assert detail["status"] == "completed", detail

    # An address: `hosts.ip`, with the conversation count as its hint and count.
    payload = _search(client, analysis_id, "10.0.0.10")
    assert payload["analysis_id"] == analysis_id
    assert payload["query"] == "10.0.0.10"
    assert payload["truncated"] is False

    match = next(item for item in payload["matches"] if item["kind"] == "ip")
    assert match["entity"] == "10.0.0.10"
    assert match["label"] == "10.0.0.10"
    assert match["to"] == "/investigate?kind=ip&entity=10.0.0.10"
    assert match["hint"].startswith("private address")
    assert match["count"] == _count(
        "SELECT COUNT(*) AS n FROM conversations "
        "WHERE analysis_id = ? AND (ip_a = ? OR ip_b = ?)",
        (analysis_id, "10.0.0.10", "10.0.0.10"),
    )

    # A name: the union of DNS names, HTTP hosts and TLS SNI. `www.example.com` is
    # an HTTP host, `txt.example.com` is only ever a DNS query and
    # `secure.example.com` is only ever a TLS SNI, so all three tables are
    # reachable through one search and their counts are summed.
    for name in ("www.example.com", "txt.example.com", "secure.example.com"):
        matches = {
            item["entity"]: item
            for item in _search(client, analysis_id, name)["matches"]
            if item["kind"] == "domain"
        }
        assert name in matches, sorted(matches)
        assert matches[name]["count"] == _name_references(analysis_id, name), name
        assert matches[name]["hint"] == f"{matches[name]['count']} name reference(s) in this capture"

    # A URL: `http_transactions.uri`.
    urls = {
        item["entity"]
        for item in _search(client, analysis_id, "/index.html")["matches"]
        if item["kind"] == "url"
    }
    assert urls == {"/index.html"}

    # Every match resolves to a profile the page can render, and the capture really
    # holds the layers those questions read.
    address = _by_id(_profile(client, analysis_id, "ip", "10.0.0.10"))
    assert address["http_activity"]["availability"] == "ok"
    assert address["domains_resolved"]["availability"] == "ok"
    assert address["tls_fingerprints"]["availability"] == "ok"


def test_search_returns_nothing_for_a_query_that_matches_nothing(
    client, run_analysis, combined_capture
) -> None:
    analysis_id, _detail = run_analysis(combined_capture)

    payload = _search(client, analysis_id, "no-such-entity-in-this-capture-zzz")
    assert payload["matches"] == []
    assert payload["truncated"] is False
    assert payload["query"] == "no-such-entity-in-this-capture-zzz"


def test_search_restricts_the_kinds_by_the_shape_of_the_query(
    client, run_analysis, combined_capture
) -> None:
    """§2: an address-shaped query returns addresses only; `/…` returns URLs only."""
    analysis_id, _detail = run_analysis(combined_capture)

    address_shaped = _search(client, analysis_id, "10.0.0.1")
    assert address_shaped["matches"], "the combined capture holds 10.0.0.10 and 10.0.0.11"
    assert {item["kind"] for item in address_shaped["matches"]} == {"ip"}

    url_shaped = _search(client, analysis_id, "/index.html")
    assert url_shaped["matches"]
    assert {item["kind"] for item in url_shaped["matches"]} == {"url"}

    # A plain query searches all three kinds: `index.html` is a URL substring with
    # no leading slash, and `10.0.0.` is an address substring that is not itself
    # address-shaped, so neither query takes the shortcut above.
    plain_url = _search(client, analysis_id, "index.html")
    assert {item["entity"] for item in plain_url["matches"] if item["kind"] == "url"} == {
        "/index.html"
    }
    plain_ip = _search(client, analysis_id, "10.0.0.")
    assert {item["entity"] for item in plain_ip["matches"] if item["kind"] == "ip"} >= {
        "10.0.0.10",
        "10.0.0.20",
    }
    assert any(item["kind"] == "domain" for item in _search(client, analysis_id, "example")["matches"])


def test_search_caps_the_matches_and_says_so(client, run_analysis, combined_capture) -> None:
    from app.services import entity_profile

    analysis_id, _detail = run_analysis(combined_capture)

    payload = _search(client, analysis_id, "example.com", limit=1)
    assert len(payload["matches"]) == 1
    assert payload["truncated"] is True

    full = _search(client, analysis_id, "example.com", limit=entity_profile.MAX_MATCH_LIMIT)
    assert len(full["matches"]) > 1
    # Ordering: most evidence first, so the reader sees the busiest entity first.
    counts = [item["count"] for item in full["matches"]]
    assert counts == sorted(counts, reverse=True)

    for item in full["matches"]:
        parts = urlsplit(item["to"])
        assert parts.path == "/investigate"
        params = dict(parse_qsl(parts.query))
        assert set(params) == {"kind", "entity"}
        assert params["kind"] == item["kind"]
        assert params["entity"] == item["entity"]


# --------------------------------------------------------------------------
# §4.1 — the address profile, against a real analysis
# --------------------------------------------------------------------------


def test_ip_profile_answers_what_the_capture_can_answer(
    client, run_analysis, combined_capture
) -> None:
    """Every figure that should be `ok` is `ok`, and it agrees with direct SQL."""
    analysis_id, detail = run_analysis(combined_capture)
    assert detail["status"] == "completed", detail

    ip = "10.0.0.10"
    payload = _profile(client, analysis_id, "ip", ip)
    _assert_profile_shape(payload, kind="ip", entity=ip)

    summary = payload["summary"]
    assert summary["scope"] == "private"
    assert summary["mac"] == "02:00:00:00:00:0a"
    assert summary["packets"] == _count(
        "SELECT COUNT(*) AS n FROM packets WHERE analysis_id = ? AND (src_ip = ? OR dst_ip = ?)",
        (analysis_id, ip, ip),
    )
    assert summary["first_seen"] <= summary["last_seen"]

    questions = _by_id(payload)

    # volume_by_direction — the hosts totals the contract names.
    assert questions["volume_by_direction"]["availability"] == "ok"
    assert questions["volume_by_direction"]["headline"]["value"] == _count(
        "SELECT bytes_sent + bytes_received AS n FROM hosts WHERE analysis_id = ? AND ip = ?",
        (analysis_id, ip),
    )

    # connections and peer_fanout — `conversations`.
    assert questions["connections"]["headline"]["value"] == _count(
        "SELECT COUNT(*) AS n FROM conversations "
        "WHERE analysis_id = ? AND (ip_a = ? OR ip_b = ?)",
        (analysis_id, ip, ip),
    )
    assert questions["peer_fanout"]["headline"]["value"] == _count(
        """
        SELECT COUNT(DISTINCT CASE WHEN ip_a = ? THEN ip_b ELSE ip_a END) AS n
          FROM conversations WHERE analysis_id = ? AND (ip_a = ? OR ip_b = ?)
        """,
        (ip, analysis_id, ip, ip),
    )

    # protocol_mix — `packets.protocol`.
    assert questions["protocol_mix"]["headline"]["value"] == _count(
        "SELECT COUNT(DISTINCT protocol) AS n FROM packets "
        "WHERE analysis_id = ? AND (src_ip = ? OR dst_ip = ?) AND protocol IS NOT NULL",
        (analysis_id, ip, ip),
    )

    # domains_resolved — `dns_queries` where it is the client.
    assert questions["domains_resolved"]["availability"] == "ok"
    assert questions["domains_resolved"]["headline"]["value"] == _count(
        "SELECT COUNT(DISTINCT query_name) AS n FROM dns_queries "
        "WHERE analysis_id = ? AND client_ip = ? AND query_name IS NOT NULL",
        (analysis_id, ip),
    )

    # dns_health — unanswered is a real measurement, and a capture where every
    # query was answered reports `empty` with the measure rather than an ok zero.
    unanswered = _count(
        "SELECT COUNT(*) AS n FROM dns_queries "
        "WHERE analysis_id = ? AND client_ip = ? AND response_packet IS NULL",
        (analysis_id, ip),
    )
    if unanswered:
        assert questions["dns_health"]["availability"] == "ok"
        assert questions["dns_health"]["headline"]["value"] == unanswered
    else:
        assert questions["dns_health"]["availability"] == "empty"
        assert "0 left unanswered" in questions["dns_health"]["availability_reason"]

    # http_activity / clear_text_credentials — `http_transactions`.
    assert questions["http_activity"]["headline"]["value"] == _count(
        "SELECT COUNT(*) AS n FROM http_transactions "
        "WHERE analysis_id = ? AND (client_ip = ? OR server_ip = ?)",
        (analysis_id, ip, ip),
    )
    credentials = _count(
        "SELECT COUNT(*) AS n FROM http_transactions "
        "WHERE analysis_id = ? AND (client_ip = ? OR server_ip = ?) "
        "AND flags LIKE '%cleartext_credentials%'",
        (analysis_id, ip, ip),
    )
    assert questions["clear_text_credentials"]["headline"]["value"] == credentials

    # domains_contacted — `tls_sessions` endpoints.
    assert questions["domains_contacted"]["headline"]["value"] == _count(
        "SELECT COUNT(DISTINCT sni) AS n FROM tls_sessions "
        "WHERE analysis_id = ? AND (client_ip = ? OR server_ip = ?) AND sni IS NOT NULL",
        (analysis_id, ip, ip),
    )

    # ports_contacted — the destination ports of the conversations it initiated.
    assert questions["ports_contacted"]["headline"]["value"] == _count(
        "SELECT COUNT(DISTINCT port_b) AS n FROM conversations "
        "WHERE analysis_id = ? AND ip_a = ? AND port_b IS NOT NULL",
        (analysis_id, ip),
    )

    # ports_offered is the mirror image. A workstation that initiated every flow it
    # was in is `empty` here, with the measured reason, rather than `ok` with 0.
    offered = _count(
        "SELECT COUNT(DISTINCT port_b) AS n FROM conversations "
        "WHERE analysis_id = ? AND ip_b = ? AND port_b IS NOT NULL",
        (analysis_id, ip),
    )
    if offered:
        assert questions["ports_offered"]["availability"] == "ok"
        assert questions["ports_offered"]["headline"]["value"] == offered
    else:
        assert questions["ports_offered"]["availability"] == "empty"
        assert "initiator in all" in questions["ports_offered"]["availability_reason"]


def test_ip_profile_marks_what_a_capture_cannot_answer(client, run_analysis, udp_capture) -> None:
    """A UDP-only capture cannot answer the DNS, HTTP or TLS questions.

    §3: those questions are ``not_applicable`` with a reason naming the table, not
    an ``ok`` zero that would read as "this host did none of that".
    """
    analysis_id, detail = run_analysis(udp_capture)
    assert detail["status"] == "completed", detail

    from app.db import database as db

    for table in ("dns_queries", "http_transactions", "tls_sessions", "objects"):
        row = db.query_one(f"SELECT COUNT(*) AS n FROM {table} WHERE analysis_id = ?", (analysis_id,))
        assert int(row["n"]) == 0, table

    payload = _profile(client, analysis_id, "ip", "10.0.0.10")
    _assert_profile_shape(payload, kind="ip", entity="10.0.0.10")
    questions = _by_id(payload)

    # What plain UDP can answer is answered.
    for question_id in (
        "volume_by_direction",
        "activity_over_time",
        "connections",
        "peer_fanout",
        "ports_contacted",
        "protocol_mix",
    ):
        assert questions[question_id]["availability"] == "ok", (
            question_id,
            questions[question_id]["availability_reason"],
        )

    # 10.0.0.10 is also the destination of one datagram, so it was seen accepting
    # traffic on a port.
    assert questions["ports_offered"]["availability"] == "ok"
    assert questions["ports_offered"]["headline"]["value"] == 1

    expected_reason = {
        "domains_resolved": "no DNS queries",
        "dns_health": "no DNS queries",
        "domains_contacted": "no TLS sessions",
        "tls_fingerprints": "no TLS sessions",
        "fingerprint_peers": "no TLS sessions",
        "http_activity": "no HTTP transactions",
        "clear_text_credentials": "no HTTP transactions",
        "files": "no extracted objects",
    }
    for question_id, phrase in expected_reason.items():
        question = questions[question_id]
        assert question["availability"] == "not_applicable", (
            question_id,
            question["availability"],
            question["availability_reason"],
        )
        assert phrase in question["availability_reason"], (
            question_id,
            question["availability_reason"],
        )
        assert question["visuals"] == []

    # Detections ran over this capture, so the findings question is computable:
    # either a rule names this address, or the question answers `empty` with the
    # number of findings it looked through — never `not_applicable`.
    findings = questions["findings"]
    assert findings["availability"] in {"ok", "empty"}, findings["availability_reason"]
    if findings["availability"] == "empty":
        assert "finding(s) in this capture" in findings["availability_reason"]
    else:
        assert findings["headline"]["value"] > 0


def test_profile_distinguishes_a_missing_layer_from_a_missing_entity(
    client, run_analysis, udp_capture
) -> None:
    """The same address, one layer it exists in and one it does not.

    `10.0.0.10` appears in this capture, so a question about a layer the capture
    *does* hold is answerable and honest; a capture-wide empty table is not.
    """
    analysis_id, _detail = run_analysis(udp_capture)

    questions = _by_id(_profile(client, analysis_id, "ip", "10.0.0.10"))
    # The capture holds no DNS rows at all, so the reason names the layer.
    assert questions["domains_resolved"]["availability"] == "not_applicable"
    assert "no DNS queries" in questions["domains_resolved"]["availability_reason"]

    # A connector address that the capture really holds in every layer it has.
    other = _by_id(_profile(client, analysis_id, "ip", "10.0.0.30"))
    assert other["connections"]["availability"] == "ok"
    assert other["ports_offered"]["availability"] == "ok"


def test_domain_and_url_profiles_answer_their_own_questions(
    client, run_analysis, combined_capture
) -> None:
    analysis_id, _detail = run_analysis(combined_capture)

    domain = "www.example.com"
    payload = _profile(client, analysis_id, "domain", domain)
    _assert_profile_shape(payload, kind="domain", entity=domain)
    questions = _by_id(payload)

    # A name is not an address, so the summary says which fields do not apply
    # instead of showing a zero that looks measured.
    assert payload["summary"]["scope"] is None
    assert payload["summary"]["mac"] is None
    assert payload["summary"]["hostnames"] == []
    assert payload["summary"]["note"] and "a name, not an address" in payload["summary"]["note"]

    clients = _count(
        "SELECT COUNT(DISTINCT client_ip) AS n FROM dns_queries "
        "WHERE analysis_id = ? AND query_name = ?",
        (analysis_id, domain),
    )
    if clients:
        assert questions["clients"]["availability"] == "ok"
        assert questions["clients"]["headline"]["value"] == clients
    else:
        # No DNS row names it, so the question says the capture holds no evidence
        # rather than reporting that nobody asked.
        assert questions["clients"]["availability"] == "not_applicable"
        assert "no DNS row" in questions["clients"]["availability_reason"]

    requests = _count(
        "SELECT COUNT(*) AS n FROM http_transactions WHERE analysis_id = ? AND host = ?",
        (analysis_id, domain),
    )
    assert requests > 0
    assert questions["http_transactions"]["availability"] == "ok"
    assert questions["http_transactions"]["headline"]["value"] == requests

    # `secure.example.com` is a TLS SNI but never a DNS query in this capture, so
    # the TLS question is `ok` and the DNS-only one is `not_applicable`.
    tls_only = _by_id(_profile(client, analysis_id, "domain", "secure.example.com"))
    assert tls_only["tls_sessions"]["availability"] == "ok"
    assert tls_only["clients"]["availability"] == "not_applicable"
    assert "no DNS row" in tls_only["clients"]["availability_reason"]

    uri = "/login"
    url_payload = _profile(client, analysis_id, "url", uri)
    _assert_profile_shape(url_payload, kind="url", entity=uri)
    url_questions = _by_id(url_payload)
    assert url_questions["methods"]["availability"] == "ok"
    assert url_questions["status_codes"]["availability"] == "ok"
    methods = url_questions["methods"]["visuals"][0]["items"]
    assert [item["label"] for item in methods] == ["POST"]

    # §2: a URL's label is what to show; the entity is what to pass back.
    match = next(
        item for item in _search(client, analysis_id, "/login")["matches"] if item["kind"] == "url"
    )
    assert match["entity"] == "/login"
    assert match["label"] == "www.example.com/login"


# --------------------------------------------------------------------------
# §2 — an unknown entity explains itself
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("kind", "entity"),
    [
        ("ip", "203.0.113.99"),
        ("domain", "not-in-this-capture.example"),
        ("url", "/no-such-path-anywhere"),
    ],
)
def test_unknown_entity_is_200_with_every_question_not_applicable(
    client, run_analysis, udp_capture, kind, entity
) -> None:
    analysis_id, _detail = run_analysis(udp_capture)

    response = client.get(f"/api/analyses/{analysis_id}/profile/{kind}/{quote(entity, safe='')}")
    assert response.status_code == 200, response.text
    payload = response.json()

    assert payload["entity"] == entity
    assert [item["id"] for item in payload["questions"]] == list(QUESTIONS[kind])
    for question in payload["questions"]:
        assert question["availability"] == "not_applicable", question["id"]
        assert question["availability_reason"].strip()
        assert "no row that names" in question["availability_reason"], question["id"]
        assert question["visuals"] == []
        assert question["links"] == []
        assert question["headline"]["value"] == 0
    assert set(payload["truncated"]) == set(QUESTIONS[kind])
    assert not any(payload["truncated"].values())

    # The summary says the same thing in one line rather than leaving the reader
    # to guess why the totals are zero.
    assert payload["summary"]["packets"] == 0
    assert payload["summary"]["bytes"] == 0
    assert payload["summary"]["mac"] is None
    assert "no row that names" in payload["summary"]["note"]
    assert "zero totals" in payload["summary"]["note"]


def test_unknown_entity_is_not_confused_with_an_empty_capture(
    client, run_analysis, empty_capture
) -> None:
    """A capture with no frames answers nothing either, and says why."""
    analysis_id, detail = run_analysis(empty_capture)
    assert detail["status"] == "completed", detail

    payload = _profile(client, analysis_id, "ip", "10.0.0.10")
    _assert_profile_shape(payload, kind="ip", entity="10.0.0.10")
    assert all(question["availability"] == "not_applicable" for question in payload["questions"])
    assert payload["summary"]["packets"] == 0


# --------------------------------------------------------------------------
# §6 — attribution, and the caps
# --------------------------------------------------------------------------


def test_files_are_attributed_only_through_a_stream_or_a_frame(
    client, run_analysis, http_object_capture
) -> None:
    """The extracted object is tied to both addresses by its conversation."""
    import generators

    expected = generators.expected("http_object")
    analysis_id, _detail = run_analysis(http_object_capture)

    payload = _profile(client, analysis_id, "ip", "10.0.0.10")
    _assert_profile_shape(payload, kind="ip", entity="10.0.0.10")

    question = _by_id(payload)["files"]
    assert question["availability"] == "ok", question["availability_reason"]

    table = question["visuals"][0]
    assert table["kind"] == "table"
    names = [row["cells"][0]["text"] for row in table["rows"]]
    hashes = [row["cells"][2]["text"] for row in table["rows"]]
    assert any(name.endswith(".bin") for name in names), names
    assert expected["sha256"] in hashes, (names, hashes)
    # §6: an object is tied by its stream or by its recorded frames, and the row
    # says which one it was.
    assert {row["cells"][3]["text"] for row in table["rows"]} <= {"stream", "frame"}
    assert "stream" in {row["cells"][3]["text"] for row in table["rows"]}

    # The other end of the same conversation is attributed the same object.
    server = _by_id(_profile(client, analysis_id, "ip", "10.0.0.20"))["files"]
    assert server["availability"] == "ok"
    assert server["headline"]["value"] == question["headline"]["value"]


def test_caps_bite_and_are_reported(client, run_analysis, dns_capture) -> None:
    """120 distinct names for one client, 50 rows of table, cap stated in the note."""
    from app.services import entity_profile

    analysis_id, _detail = run_analysis(dns_capture)
    total = _count(
        "SELECT COUNT(DISTINCT query_name) AS n FROM dns_queries "
        "WHERE analysis_id = ? AND client_ip = ?",
        (analysis_id, "10.0.0.77"),
    )
    assert total > entity_profile.PROFILE_CAP, total

    payload = _profile(client, analysis_id, "ip", "10.0.0.77")
    _assert_profile_shape(payload, kind="ip", entity="10.0.0.77")

    question = _by_id(payload)["domains_resolved"]
    assert question["availability"] == "ok"
    assert question["headline"]["value"] == total
    table = question["visuals"][0]
    assert len(table["rows"]) == entity_profile.PROFILE_CAP
    assert table["note"] == f"showing {entity_profile.PROFILE_CAP} of {total} name(s)"
    assert payload["truncated"]["domains_resolved"] is True
    assert payload["truncated"]["volume_by_direction"] is False


def test_bars_and_heatmap_caps_bite_on_a_port_scan(client, run_analysis, syn_scan_capture) -> None:
    """One scanner reaching 41 ports: 12 bars, 15 heatmap columns."""
    import generators
    from app.services import entity_profile

    expected = generators.expected("syn_scan")
    analysis_id, _detail = run_analysis(syn_scan_capture)

    ports = _count(
        "SELECT COUNT(DISTINCT port_b) AS n FROM conversations "
        "WHERE analysis_id = ? AND ip_a = ? AND port_b IS NOT NULL",
        (analysis_id, expected["scanner"]),
    )
    assert ports > entity_profile.BARS_CAP, ports

    payload = _profile(client, analysis_id, "ip", expected["scanner"])
    _assert_profile_shape(payload, kind="ip", entity=expected["scanner"])
    questions = _by_id(payload)

    bars = questions["ports_contacted"]["visuals"][0]
    assert bars["kind"] == "bars"
    assert len(bars["items"]) == entity_profile.BARS_CAP
    assert bars["note"] == f"showing {entity_profile.BARS_CAP} of {ports} port(s)"
    assert payload["truncated"]["ports_contacted"] is True
    # The visual is real data, not a decoration: the scan's ports are in it.
    assert any("common port" in item["label"] for item in bars["items"])

    heatmap = questions["connections"]["visuals"][0]
    assert heatmap["kind"] == "heatmap"
    assert len(heatmap["columns"]) == entity_profile.HEATMAP_CAP
    assert len(heatmap["rows"]) == 1, "the scanner talked to one host"
    assert all(len(row["cells"]) == len(heatmap["columns"]) for row in heatmap["rows"])
    assert f"showing {entity_profile.HEATMAP_CAP} of {ports} port(s)" in heatmap["note"]
    assert payload["truncated"]["connections"] is True


def test_ports_offered_are_the_ports_the_address_was_contacted_on(
    client, run_analysis, syn_scan_capture
) -> None:
    """The scanned host's answer is the scanner's target list, port for port.

    ``ports_offered`` is the mirror of ``ports_contacted``: the port a
    conversation is aimed at is ``port_b``, so the responder's offered ports and
    the initiator's contacted ports cannot disagree.
    """
    import generators

    expected = generators.expected("syn_scan")
    analysis_id, _detail = run_analysis(syn_scan_capture)

    scanner_ip = expected["scanner"]
    target_ip = expected["target"]
    expected_ports = sorted({*expected["ports"], expected["completed_handshake_port"]})

    served = _by_id(_profile(client, analysis_id, "ip", target_ip))
    assert served["ports_offered"]["availability"] == "ok"
    assert served["ports_offered"]["headline"]["value"] == len(expected_ports)
    offered = served["ports_offered"]["visuals"][0]
    labels = [item["label"].split(" ", 1)[0] for item in offered["items"]]
    assert set(labels) <= {str(port) for port in expected_ports}, labels
    assert offered["note"].startswith("showing "), offered["note"]

    # The scanner reached out on exactly that list, and was never the responder.
    scanned = _by_id(_profile(client, analysis_id, "ip", scanner_ip))
    assert scanned["ports_contacted"]["headline"]["value"] == len(expected_ports)
    assert scanned["ports_offered"]["availability"] == "empty"
    assert "initiator in all" in scanned["ports_offered"]["availability_reason"]


# --------------------------------------------------------------------------
# errors and parameter validation
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "params",
    [
        {},
        {"q": ""},
        {"q": "x" * 201},
        {"q": "a", "limit": 0},
        {"q": "a", "limit": 101},
    ],
)
def test_search_rejects_invalid_parameters(client, run_analysis, combined_capture, params) -> None:
    analysis_id, _detail = run_analysis(combined_capture)

    response = client.get(f"/api/analyses/{analysis_id}/profile", params=params)
    assert response.status_code == 422, response.text
    assert response.json()["error"]["code"] in {"validation_error", "invalid_query"}


def test_search_rejects_a_query_that_is_only_spaces(client, run_analysis, combined_capture) -> None:
    analysis_id, _detail = run_analysis(combined_capture)

    response = client.get(f"/api/analyses/{analysis_id}/profile", params={"q": "   "})
    assert response.status_code == 422, response.text
    assert response.json()["error"]["code"] == "invalid_query"


def test_profile_rejects_an_unknown_kind(client, run_analysis, combined_capture) -> None:
    analysis_id, _detail = run_analysis(combined_capture)

    response = client.get(f"/api/analyses/{analysis_id}/profile/hostname/10.0.0.10")
    assert response.status_code == 422, response.text
    assert response.json()["error"]["code"] == "validation_error"


def test_profile_accepts_a_url_entity_that_contains_slashes(
    client, run_analysis, combined_capture
) -> None:
    """A request URI contains `/`, so it must survive the trip through the client.

    §2 says `{entity}` is URL-encoded by the caller, which is the only way a URI
    with a leading slash can be sent at all — an HTTP client resolves a literal
    `../` in a path before it goes out on the wire.
    """
    analysis_id, _detail = run_analysis(combined_capture)

    uri = "/../../etc/passwd"
    response = client.get(f"/api/analyses/{analysis_id}/profile/url/{quote(uri, safe='')}")
    assert response.status_code == 200, response.text
    payload = response.json()
    assert payload["entity"] == uri
    assert _by_id(payload)["methods"]["availability"] == "ok"


def test_profile_unknown_analysis_is_404(client) -> None:
    for path in (
        f"/api/analyses/{'0' * 32}/profile?q=1.1.1.1",
        f"/api/analyses/{'0' * 32}/profile/ip/1.1.1.1",
    ):
        response = client.get(path)
        assert response.status_code == 404, response.text
        assert response.json()["error"]["code"] == "analysis_not_found"


def test_profile_unfinished_analysis_is_409(client) -> None:
    analysis_id = "3" * 32
    _seed_analysis(analysis_id, status="running")

    for path in (
        f"/api/analyses/{analysis_id}/profile?q=1.1.1.1",
        f"/api/analyses/{analysis_id}/profile/ip/1.1.1.1",
    ):
        response = client.get(path)
        assert response.status_code == 409, response.text
        assert response.json()["error"]["code"] == "analysis_not_ready"


def test_profile_is_exported_by_the_router_registry() -> None:
    """``main.ROUTER_SPECS`` must register the router, or the page 404s."""
    from app.main import ROUTER_SPECS

    assert ("app.api.routes_profile", "router") in ROUTER_SPECS
