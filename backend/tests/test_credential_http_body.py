"""How an HTTP request body is read (§3.1): the request's own type, then its shape.

The defect these tests exist for: `http_transactions.content_type` is the
**response's** type, and the scanner used it to choose a reader for the
**request** body. A browser POST of a form to an endpoint that answers JSON —
the most ordinary login on the web — was therefore read as prose, and the finding
it produced was one medium row whose value was the entire string
``admin&password=secret123`` instead of the two high-confidence fields the server
actually received. A body is proof of nothing until it is read correctly.

These tests drive `scan_http` directly with synthetic rows, so they assert what the
body reader does and nothing about the rest of the pipeline.
"""

from __future__ import annotations

import json
from typing import Any

from app.services import credential_analyzer as ca

ANALYSIS_ID = "00112233445566778899aabbccddeeff"
FORM = "application/x-www-form-urlencoded"


def row(
    *,
    body: str,
    request_headers: dict[str, str] | None = None,
    content_type: str | None = "application/json",
) -> dict[str, Any]:
    """One `http_transactions` row; `content_type` defaults to the response's JSON."""
    return {
        "id": 1,
        "stream_id": 0,
        "client_ip": "10.0.0.5",
        "client_port": 51000,
        "server_ip": "93.184.216.34",
        "server_port": 80,
        "request_packet": 10,
        "request_headers": json.dumps(request_headers or {}),
        "content_type": content_type,
        "request_body": body,
        "full_uri": "/login",
        "uri": "/login",
        "method": "POST",
    }


def scan(**kwargs: Any) -> list[ca.Finding]:
    state = ca._Scan(ANALYSIS_ID)
    ca.scan_http(state, row(**kwargs))
    return state.findings


def fields(findings: list[ca.Finding]) -> list[tuple[str, str]]:
    return sorted((finding.kind, finding.value) for finding in findings)


def test_the_requests_type_decides_not_the_responses() -> None:
    """The reported defect: form request, JSON response, two fields recovered."""
    findings = scan(
        body="username=admin&password=secret123",
        request_headers={"Content-Type": FORM},
        content_type="application/json",
    )
    assert fields(findings) == [("password", "secret123"), ("username", "admin")]
    for finding in findings:
        assert finding.location == "form_body"
        assert finding.method == "form_field"
        assert finding.confidence == "high"
    # The old reading produced one row carrying the pair separator.
    assert not [finding for finding in findings if "&" in finding.value]


def test_the_response_type_cannot_change_the_reading() -> None:
    """Whatever the server answered, one request body reads the same way."""
    body = "username=admin&password=secret123"
    headers = {"Content-Type": FORM}
    readings = {
        tuple(fields(scan(body=body, request_headers=headers, content_type=response_type)))
        for response_type in (None, "application/json", "text/html", "image/png")
    }
    assert readings == {(("password", "secret123"), ("username", "admin"))}


def test_shape_is_the_fallback_when_no_type_was_recorded() -> None:
    findings = scan(body="username=admin&password=secret123", request_headers={})
    assert fields(findings) == [("password", "secret123"), ("username", "admin")]
    assert {finding.location for finding in findings} == {"form_body"}


def test_a_single_pair_is_a_form_even_with_no_separator() -> None:
    findings = scan(body="password=secret123", request_headers={})
    assert fields(findings) == [("password", "secret123")]
    assert findings[0].confidence == "high"


def test_semicolons_separate_pairs_too() -> None:
    """`;` was the earlier separator, and `parse_qsl` no longer splits on it."""
    findings = scan(body="username=admin;password=secret123", request_headers={})
    assert fields(findings) == [("password", "secret123"), ("username", "admin")]


def test_values_are_decoded_and_unquoted() -> None:
    findings = scan(
        body='username=alice%40example.com&password="secret+123"',
        request_headers={"Content-Type": FORM},
    )
    assert fields(findings) == [
        ("password", "secret 123"),
        ("username", "alice@example.com"),
    ]


def test_prose_with_an_equals_sign_is_not_a_form() -> None:
    """Nothing is invented: a sentence is not a pair, and yields no finding."""
    assert scan(body="the user=admin logged in", request_headers={}) == []


def test_a_multiline_labelled_body_is_still_read_as_text() -> None:
    findings = scan(
        body="username: alice\npassword: hunter2",
        request_headers={"Content-Type": "text/plain"},
    )
    assert fields(findings) == [("password", "hunter2"), ("username", "alice")]
    for finding in findings:
        assert finding.location == "body_text"
        assert finding.confidence == "medium"


def test_a_json_body_is_parsed_as_json() -> None:
    findings = scan(
        body='{"username": "alice", "password": "hunter2"}',
        request_headers={"Content-Type": "application/json"},
    )
    assert fields(findings) == [("password", "hunter2"), ("username", "alice")]
    assert {finding.location for finding in findings} == {"json_body"}
    assert {finding.confidence for finding in findings} == {"high"}


def test_json_is_parsed_even_when_its_type_was_never_recorded() -> None:
    findings = scan(body='{"username": "alice", "password": "hunter2"}', request_headers={})
    assert fields(findings) == [("password", "hunter2"), ("username", "alice")]


def test_a_body_labelled_a_form_but_provably_json_is_parsed_as_json() -> None:
    findings = scan(
        body='{"username": "alice", "password": "hunter2"}',
        request_headers={"Content-Type": FORM},
    )
    assert fields(findings) == [("password", "hunter2"), ("username", "alice")]


def test_an_empty_or_absent_body_produces_nothing() -> None:
    assert scan(body="", request_headers={"Content-Type": FORM}) == []
    assert ca.scan_http(ca._Scan(ANALYSIS_ID), row(body=None, request_headers={})) is None


def test_a_body_whose_type_says_skip_is_not_read() -> None:
    """§1: a binary request body is out of scope, not guessed at."""
    findings = scan(
        body="username=admin&password=secret123",
        request_headers={"Content-Type": "image/png"},
    )
    assert findings == []


def test_pair_chunks_survive_a_body_with_a_trailing_separator() -> None:
    findings = scan(body="username=admin&password=secret123&", request_headers={})
    assert fields(findings) == [("password", "secret123"), ("username", "admin")]
