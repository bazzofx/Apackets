"""Credential discovery tests: extraction, scoring, redaction, caps and the API.

Rows are written straight into ``http_transactions`` and ``protocol_sessions`` with
``db.get_conn()``, exactly as the HTTP and protocol analysers would have written
them, and the scanner is then run over those rows. Nothing here uploads a capture
except the two pipeline tests, so an assertion about a finding is an assertion about
the scanner's reading of a stored row rather than about a dissector.

The expected values are always strings a fixture put in a row. No test asserts a
value the scanner could only have guessed, which is the point of the contract: a
credential is recoverable only because a dissector already decoded the field.
"""

from __future__ import annotations

import base64
import json
import logging
import threading
import time
from pathlib import Path

import pytest

import protocol_captures as capture_builders
from app.core import runtime_settings
from app.core.config import settings
from app.db import database as db
from app.services import credential_analyzer as ca
from app.services import protocol_analyzer, tshark

ANALYSIS_ID = "a1b2c3d4e5f60718293a4b5c6d7e8f90"
OTHER_ID = "0011223344556677889900aabbccddee"
MISSING_ID = "0123456789abcdef0123456789abcdef"
CAPTURE_FILE = "credential-fixture.pcap"

# The tables the scan may touch: its own, and the stats_cache record that says the
# stage ran (the marker pattern the protocol stage already uses).
TOUCHED = {"credentials", "stats_cache"}

ALL_TABLES = (
    "analyses", "jobs", "packets", "conversations", "streams", "http_transactions",
    "dns_queries", "tls_sessions", "protocol_sessions", "hosts", "findings",
    "objects", "stats_cache", "indicators", "settings", "suricata_rules",
    "ip_lookups", "credentials",
)

# §3.3 shapes, as literals a fixture can put in a field.
AKIA = "AKIAIOSFODNN7EXAMPLE"
ASIA = "ASIAIOSFODNN7EXAMPLE"
GITHUB = "ghp_" + "A" * 36
SLACK = "xoxb-1234567890-abcdefghij"
GOOGLE = "AIza" + "B" * 35
STRIPE = "sk_live_" + "c" * 24
JWT = (
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
    ".eyJzdWIiOiIxMjM0NTY3ODkwIn0"
    ".SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
)
PEM = "-----BEGIN RSA PRIVATE KEY-----"

# The values the seeded fixture puts in its rows, so the redaction tests can look
# for them by name instead of by literal.
SEED_SECRETS = ("Example123", "Hunter2Hunter2", "alice", "bob", "carol", "abcdef123456")


def b64(text: str) -> str:
    return base64.b64encode(text.encode("utf-8")).decode("ascii")


def akia(index: int) -> str:
    """A distinct, shape-valid AWS key: ``AKIA`` plus sixteen digits."""
    return f"AKIA{index:016d}"


class StubContext:
    """The minimum a JobContext has to offer the scanner (and the protocol analyser)."""

    def __init__(self) -> None:
        self.stages: list[str] = []
        self.cancel_event = threading.Event()

    def set_stage(self, stage: str, progress: float | None = None) -> None:
        self.stages.append(stage)

    def check_cancelled(self) -> None:
        return None


# --------------------------------------------------------------------------
# fixtures
# --------------------------------------------------------------------------

@pytest.fixture()
def insert_http(fresh_db):  # noqa: ARG001 - fresh_db empties the tables first
    """Insert one ``http_transactions`` row and return its id."""

    def _insert(*, analysis_id: str = ANALYSIS_ID, stream_id: int = 7,
                request_packet: int = 1450, **overrides) -> int:
        values: dict[str, object] = {
            "analysis_id": analysis_id,
            "stream_id": stream_id,
            "request_packet": request_packet,
            "client_ip": "192.168.1.10",
            "client_port": 51000,
            "server_ip": "192.168.1.20",
            "server_port": 80,
            "method": "POST",
            "host": "example.test",
            "uri": "/login",
            "full_uri": "http://example.test/login",
            "content_type": None,
            "request_headers": None,
            "request_body": None,
        }
        values.update(overrides)
        columns = ", ".join(values)
        marks = ", ".join("?" for _ in values)
        with db.get_conn() as conn:
            cursor = conn.execute(
                f"INSERT INTO http_transactions ({columns}) VALUES ({marks})",
                tuple(values.values()),
            )
            return int(cursor.lastrowid or 0)

    return _insert


@pytest.fixture()
def insert_session(fresh_db):  # noqa: ARG001
    """Insert one ``protocol_sessions`` row and return its id."""

    def _insert(protocol: str, detail: dict | None = None, *,
                analysis_id: str = ANALYSIS_ID, stream_id: int = 3,
                first_frame: int = 11, last_frame: int = 19,
                **overrides) -> int:
        values: dict[str, object] = {
            "analysis_id": analysis_id,
            "protocol": protocol,
            "stream_id": stream_id,
            "transport": "tcp",
            "client_ip": "10.0.0.1",
            "client_port": 40000,
            "server_ip": "10.0.0.2",
            "server_port": {"ftp": 21, "smtp": 25, "pop3": 110, "imap": 143}.get(protocol, 0),
            "first_frame": first_frame,
            "last_frame": last_frame,
            "start_time": 100.0,
            "end_time": 101.0,
            "packets": 10,
            "bytes": 1000,
            "detail": json.dumps(detail or {}),
            "flags": "[]",
            "created_at": time.time(),
        }
        values.update(overrides)
        columns = ", ".join(values)
        marks = ", ".join("?" for _ in values)
        with db.get_conn() as conn:
            cursor = conn.execute(
                f"INSERT INTO protocol_sessions ({columns}) VALUES ({marks})",
                tuple(values.values()),
            )
            return int(cursor.lastrowid or 0)

    return _insert


@pytest.fixture()
def run_scan(fresh_db):  # noqa: ARG001
    """Run the scanner over the stored rows, and return what it wrote.

    ``protocols`` rewrites the setting first, so a test can restrict the scan
    without reaching into the module's constants.
    """

    def _run(*, analysis_id: str = ANALYSIS_ID, protocols: list[str] | None = None,
             capture: Path | None = None):
        if protocols is not None:
            runtime_settings.save_credential_config({"credential_protocols": protocols})
        stats = ca.analyze(StubContext(), analysis_id, capture)
        rows = db.query_all(
            "SELECT * FROM credentials WHERE analysis_id = ? ORDER BY id", (analysis_id,)
        )
        return [dict(row) for row in rows], stats

    return _run


@pytest.fixture()
def analysis(fresh_db):  # noqa: ARG001
    """A completed analysis whose capture really exists, for the route gates."""

    def _make(*, status: str = "completed", capture: bool = True,
              analysis_id: str = ANALYSIS_ID) -> dict:
        now = time.time()
        path = settings.uploads_dir / CAPTURE_FILE
        path.parent.mkdir(parents=True, exist_ok=True)
        if capture:
            path.write_bytes(b"\xd4\xc3\xb2\xa1fixture-not-a-real-capture")
        elif path.is_file():
            path.unlink()
        with db.get_conn() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO analyses (
                    id, original_filename, stored_path, file_size, file_type, status,
                    progress, stage, packet_count, created_at, updated_at
                ) VALUES (?, 'fixture.pcap', ?, 0, 'pcap', ?, 100, ?, 0, ?, ?)
                """,
                (analysis_id, str(path), status, status, now, now),
            )
        return {"id": analysis_id, "stored_path": str(path)}

    return _make


@pytest.fixture(scope="session")
def control_captures(scratch_dir: Path) -> dict[str, Path]:
    """Two real captures (§2b tests), built once for this module.

    ``ftp`` and ``email`` are the builders ``tests/test_protocol_captures.py``
    already uses: the FTP one authenticates with ``USER``/``PASS`` and the email one
    holds SMTP ``AUTH LOGIN``, POP3 ``USER``/``PASS`` and IMAP ``LOGIN``, so the
    control-channel half of the contract is exercised against what TShark and the
    protocol analyser actually produce rather than against a shape a test invented.
    """
    directory = scratch_dir / "credential-captures"
    directory.mkdir(parents=True, exist_ok=True)
    return {
        "ftp": capture_builders.ftp_capture(directory),
        "email": capture_builders.email_capture(directory),
    }


@pytest.fixture()
def analyser_sessions(fresh_db, control_captures):  # noqa: ARG001
    """Run the real protocol analyser over a real capture and return its rows.

    This is what makes the §2(b) tests honest: the rows are the analyser's own, so
    the test can assert that the password is *not* in them and still recover it
    from the control channel.
    """

    def _run(name: str = "ftp") -> list[dict]:
        protocol_analyzer.analyze(StubContext(), ANALYSIS_ID, control_captures[name])
        rows = db.query_all(
            "SELECT * FROM protocol_sessions WHERE analysis_id = ? ORDER BY id",
            (ANALYSIS_ID,),
        )
        return [dict(row) for row in rows]

    return _run


@pytest.fixture()
def fake_reassembly(monkeypatch):
    """Answer ``tshark.follow_stream`` from a handler, and record what was asked.

    The reassembly is TShark's, and a test of the *scanner* should not depend on a
    capture the scanner did not build; the real-capture tests above cover the call
    itself, and these cover every branch of reading its answer.
    """

    def _install(handler):
        calls: list[int] = []

        def _follow(path, stream_id, mode="ascii", **kwargs):  # noqa: ARG001
            calls.append(int(stream_id))
            answer = handler(int(stream_id))
            if isinstance(answer, Exception):
                raise answer
            return answer

        monkeypatch.setattr(tshark, "follow_stream", _follow)
        return calls

    return _install


def follow_stream_fixture(
    *, client: str, server: str, client_lines: list[str], server_lines: list[str] | None = None
) -> tshark.FollowStream:
    """A ``FollowStream`` shaped exactly as ``tshark.parse_follow_raw`` returns one."""
    stream = tshark.FollowStream()
    stream.node0 = client
    stream.node1 = server
    stream.found = True
    for direction, lines in ((0, client_lines), (1, server_lines or [])):
        if not lines:
            continue
        text = "".join(f"{line}\r\n" for line in lines)
        stream.chunks.append(
            tshark.StreamChunk(
                direction=direction, byte_len=len(text), data=text, hex=text.encode().hex()
            )
        )
    return stream


@pytest.fixture()
def seeded(analysis, insert_http, insert_session, run_scan):
    """A small representative capture, with a finding at each confidence.

    Five streams and seven findings: HTTP Basic, a form body, an FTP ``USER``, a
    credential-like URL query field and an unlabelled token in a free-text body, so
    the list, summary and filter routes have something of each kind to be wrong
    about. The analysis row is real because every read route gates on it.
    """
    analysis()
    insert_http(
        stream_id=30,
        request_headers=json.dumps({"Authorization": f"Basic {b64('alice:Example123')}"}),
    )
    insert_http(
        stream_id=31,
        method="POST",
        content_type="application/x-www-form-urlencoded",
        request_body="user=bob&password=Hunter2Hunter2",
    )
    insert_session(
        "ftp", {"commands": [{"verb": "USER", "arg": "carol", "count": 1}]}, stream_id=32
    )
    insert_http(
        stream_id=33,
        method="GET",
        uri="/login?api_key=abcdef123456",
        full_uri="http://example.test/login?api_key=abcdef123456",
    )
    insert_http(
        stream_id=34,
        method="POST",
        content_type="text/plain",
        request_body=f"here is a token {GITHUB} in the clear",
    )
    rows, _ = run_scan()
    return rows


# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------

def _find(rows, *, kind=None, location=None, value=None, protocol=None, confidence=None,
          method=None):
    out = []
    for row in rows:
        if kind is not None and row["kind"] != kind:
            continue
        if location is not None and row["location"] != location:
            continue
        if value is not None and row["value"] != value:
            continue
        if protocol is not None and row["protocol"] != protocol:
            continue
        if confidence is not None and row["confidence"] != confidence:
            continue
        if method is not None and row["method"] != method:
            continue
        out.append(row)
    return out


def _one(rows, **criteria):
    found = _find(rows, **criteria)
    assert len(found) == 1, f"expected one row for {criteria}, got {len(found)}: {found}"
    return found[0]


def _values(rows) -> list[str]:
    return [row["value"] for row in rows]


def _table_counts() -> dict[str, int]:
    counts = {}
    for table in ALL_TABLES:
        row = db.query_one(f"SELECT COUNT(*) AS n FROM {table}")
        counts[table] = int(row["n"]) if row else 0
    return counts


def _await_job(job_id: str, timeout: float = 60.0) -> str:
    deadline = time.monotonic() + timeout
    status = "queued"
    while time.monotonic() < deadline:
        row = db.query_one("SELECT status FROM jobs WHERE id = ?", (job_id,))
        status = row["status"] if row else "missing"
        if status in {"completed", "failed", "cancelled"}:
            return status
        time.sleep(0.05)
    return status


# ==========================================================================
# 1. storage
# ==========================================================================

def test_credentials_table_has_every_contract_column(fresh_db):  # noqa: ARG001
    columns = [row["name"] for row in db.query_all("PRAGMA table_info(credentials)")]
    assert columns == [
        "id", "analysis_id", "kind", "value", "value_preview", "value_length",
        "value_truncated", "protocol", "transport", "stream_id", "direction",
        "location", "source_field", "method", "confidence", "client_ip",
        "client_port", "server_ip", "server_port", "packet_first", "packet_last",
        "evidence", "note", "created_at",
    ]


def test_credentials_table_has_both_contract_indexes(fresh_db):  # noqa: ARG001
    names = {
        row["name"]
        for row in db.query_all(
            "SELECT name FROM sqlite_master WHERE type = 'index' AND tbl_name = 'credentials'"
        )
    }
    assert {"idx_credentials_analysis", "idx_credentials_stream"} <= names


def test_a_stored_row_carries_the_columns_the_endpoint_serves(insert_http, run_scan):
    insert_http(
        stream_id=41,
        request_headers=json.dumps({"Authorization": f"Basic {b64('alice:Example123')}"}),
    )
    rows, _ = run_scan()
    row = _one(rows, kind="password", value="Example123")
    assert row["protocol"] == "http"
    assert row["transport"] == "tcp"
    assert row["stream_id"] == 41
    assert row["direction"] == "client_to_server"
    assert row["location"] == "authorization_basic"
    assert row["source_field"] == "Authorization"
    assert row["method"] == "basic_decode"
    assert row["confidence"] == "high"
    assert row["client_ip"] == "192.168.1.10"
    assert row["server_port"] == 80
    assert row["packet_first"] == 1450
    assert row["packet_last"] == 1450
    assert row["value_length"] == len("Example123")
    assert row["value_truncated"] == 0
    assert row["note"]


def test_the_stage_writes_nothing_but_its_own_table_and_marker(insert_http, run_scan):
    insert_http(request_headers=json.dumps({"Authorization": f"Basic {b64('alice:Example123')}"}))
    before = _table_counts()
    run_scan()
    after = _table_counts()
    changed = {name for name in ALL_TABLES if before[name] != after[name]}
    assert changed <= TOUCHED, changed
    assert changed == {"credentials", "stats_cache"}
    marker = ca.stage_marker(ANALYSIS_ID)
    assert marker is not None and marker["findings"] == 2


def test_the_http_half_needs_no_capture_pass(insert_http, run_scan, monkeypatch):
    """HTTP is read from the stored rows: no TShark call at all for that half (§2a)."""
    def _forbidden(*args, **kwargs):  # pragma: no cover - only reached on failure
        raise AssertionError("the HTTP half of the scan must not invoke TShark")

    for name in ("run", "run_bytes", "run_z", "stream_fields", "follow_stream", "packet_json"):
        monkeypatch.setattr(tshark, name, _forbidden)

    insert_http(request_headers=json.dumps({"Authorization": f"Basic {b64('alice:Example123')}"}))
    rows, stats = run_scan()
    assert stats["findings"] == 2
    assert stats["control_streams"] == 0
    assert len(rows) == 2


def test_a_missing_capture_costs_only_the_control_channels(insert_http, insert_session, run_scan):
    """§2(b) needs the capture; the rows half does not, so a purged upload still scans."""
    insert_http(request_headers=json.dumps({"Authorization": f"Basic {b64('alice:Example123')}"}))
    insert_session("ftp", {"commands": [{"verb": "PASS", "count": 1}]})
    rows, stats = run_scan(capture=Path("N:/does/not/exist/capture.pcap"))
    assert stats["findings"] == 2
    assert stats["control_streams"] == 0
    assert any("was not read" in warning for warning in stats["warnings"])


def test_only_rows_of_the_named_analysis_are_read(insert_http, run_scan):
    insert_http(
        analysis_id=OTHER_ID,
        request_headers=json.dumps({"Authorization": f"Basic {b64('mallory:Other123')}"}),
    )
    rows, stats = run_scan()
    assert stats["findings"] == 0
    assert rows == []


# ==========================================================================
# 2. HTTP Basic (§3.1)
# ==========================================================================

def test_basic_authorization_is_decoded_into_username_and_password(insert_http, run_scan):
    insert_http(request_headers=json.dumps({"Authorization": f"Basic {b64('alice:Example123')}"}))
    rows, _ = run_scan()
    assert _one(rows, kind="username")["value"] == "alice"
    password = _one(rows, kind="password")
    assert password["value"] == "Example123"
    assert password["confidence"] == "high"
    assert password["method"] == "basic_decode"
    assert password["source_field"] == "Authorization"


def test_basic_evidence_quotes_the_header_redacted(insert_http, run_scan):
    encoded = b64("alice:Example123")
    insert_http(request_headers=json.dumps({"Authorization": f"Basic {encoded}"}))
    rows, _ = run_scan()
    password = _one(rows, kind="password")
    assert password["evidence"] == f"Authorization: Basic {ca.preview(encoded)}"
    assert encoded not in password["evidence"]


def test_basic_splits_on_the_first_colon_only(insert_http, run_scan):
    insert_http(request_headers=json.dumps({"Authorization": f"Basic {b64('alice:a:b:c')}"}))
    rows, _ = run_scan()
    assert _one(rows, kind="username")["value"] == "alice"
    assert _one(rows, kind="password")["value"] == "a:b:c"


def test_basic_with_invalid_base64_is_one_medium_opaque_value(insert_http, run_scan):
    insert_http(request_headers=json.dumps({"Authorization": "Basic not*base64*at*all"}))
    rows, _ = run_scan()
    assert len(rows) == 1
    row = rows[0]
    assert row["kind"] == "other_secret"
    assert row["value"] == "not*base64*at*all"
    assert row["confidence"] == "medium"
    assert row["location"] == "authorization_basic"


def test_basic_without_a_colon_is_one_medium_opaque_value(insert_http, run_scan):
    encoded = b64("aliceisnotapassword")
    insert_http(request_headers=json.dumps({"Authorization": f"Basic {encoded}"}))
    rows, _ = run_scan()
    assert len(rows) == 1
    assert rows[0]["kind"] == "other_secret"
    assert rows[0]["value"] == encoded
    assert rows[0]["confidence"] == "medium"


def test_a_non_basic_scheme_is_reported_naming_the_scheme(insert_http, run_scan):
    insert_http(
        request_headers=json.dumps({"Authorization": "Digest username=alice, nonce=abc123"})
    )
    rows, _ = run_scan()
    row = _one(rows, kind="other_secret")
    assert row["value"] == "username=alice, nonce=abc123"
    assert row["confidence"] == "high"
    assert row["location"] == "authorization_scheme"
    assert "Digest" in row["note"]


def test_a_bearer_token_is_a_bearer_token(insert_http, run_scan):
    insert_http(request_headers=json.dumps({"Authorization": "Bearer abcdef123456ghijkl"}))
    rows, _ = run_scan()
    row = _one(rows, kind="bearer_token")
    assert row["value"] == "abcdef123456ghijkl"
    assert row["confidence"] == "high"
    assert row["method"] == "bearer_header"


def test_an_authorization_header_with_no_value_reports_nothing(insert_http, run_scan):
    insert_http(request_headers=json.dumps({"Authorization": "Bearer"}))
    rows, stats = run_scan()
    assert rows == []
    assert stats["findings"] == 0


def test_an_empty_basic_payload_reports_nothing(insert_http, run_scan):
    insert_http(request_headers=json.dumps({"Authorization": "Basic"}))
    rows, _ = run_scan()
    assert rows == []


# ==========================================================================
# 3. headers and cookies (§3.1, §3.2)
# ==========================================================================

def test_a_credential_like_request_header_is_reported(insert_http, run_scan):
    insert_http(request_headers=json.dumps({"X-Api-Key": "abcdef123456"}))
    rows, _ = run_scan()
    row = _one(rows, kind="api_key")
    assert row["value"] == "abcdef123456"
    assert row["confidence"] == "high"
    assert row["source_field"] == "X-Api-Key"
    assert row["location"] == "request_header"


def test_an_ordinary_request_header_is_not_reported(insert_http, run_scan):
    insert_http(
        request_headers=json.dumps(
            {"Accept": "text/html", "User-Agent": "curl/8.0", "X-Request-Id": "abc123"}
        )
    )
    rows, _ = run_scan()
    assert rows == []


def test_a_credential_like_cookie_is_medium_confidence(insert_http, run_scan):
    insert_http(request_headers=json.dumps({"Cookie": "theme=dark; session_id=9f8e7d6c5b4a"}))
    rows, _ = run_scan()
    row = _one(rows, kind="other_secret")
    assert row["value"] == "9f8e7d6c5b4a"
    assert row["confidence"] == "medium"
    assert row["location"] == "cookie_header"
    assert row["source_field"] == "session_id"
    assert row["method"] == "cookie_field"


def test_ordinary_cookies_are_ignored(insert_http, run_scan):
    insert_http(request_headers=json.dumps({"Cookie": "theme=dark; lang=en; _ga=GA1.2.3.4"}))
    rows, _ = run_scan()
    assert rows == []


def test_a_cookie_named_for_a_token_keeps_the_tokens_kind(insert_http, run_scan):
    insert_http(request_headers=json.dumps({"Cookie": "access_token=abcdef123456"}))
    rows, _ = run_scan()
    row = _one(rows)
    assert row["kind"] == "other_secret"
    assert row["source_field"] == "access_token"


# ==========================================================================
# 4. query, form and JSON bodies (§3.1)
# ==========================================================================

def test_a_url_query_field_is_medium_confidence(insert_http, run_scan):
    insert_http(
        method="GET",
        uri="/login?user=alice&password=Example123",
        full_uri="http://example.test/login?user=alice&password=Example123",
    )
    rows, _ = run_scan()
    assert _one(rows, kind="username")["confidence"] == "medium"
    password = _one(rows, kind="password")
    assert password["confidence"] == "medium"
    assert password["location"] == "url_query"
    assert password["source_field"] == "password"


def test_a_url_query_value_is_percent_decoded(insert_http, run_scan):
    insert_http(
        method="GET",
        uri="/login?password=Ex%40mple%2B123",
        full_uri="http://example.test/login?password=Ex%40mple%2B123",
    )
    rows, _ = run_scan()
    assert _one(rows, kind="password")["value"] == "Ex@mple+123"


def test_a_form_body_field_is_high_confidence(insert_http, run_scan):
    insert_http(
        content_type="application/x-www-form-urlencoded",
        request_body="username=alice&password=Example123&submit=Sign+in",
    )
    rows, _ = run_scan()
    assert _one(rows, kind="username")["confidence"] == "high"
    password = _one(rows, kind="password")
    assert password["location"] == "form_body"
    assert password["method"] == "form_field"
    # "Sign in" is not credential-like, so no finding is invented for it.
    assert _find(rows, value="Sign in") == []


def test_a_json_body_field_is_high_confidence(insert_http, run_scan):
    insert_http(
        content_type="application/json",
        request_body=json.dumps({"username": "alice", "password": "Example123"}),
    )
    rows, _ = run_scan()
    assert _one(rows, kind="username")["confidence"] == "high"
    password = _one(rows, kind="password")
    assert password["location"] == "json_body"
    assert password["method"] == "json_field"
    assert "password" in password["evidence"]


def test_a_nested_json_field_is_found(insert_http, run_scan):
    insert_http(
        content_type="application/json",
        request_body=json.dumps({"auth": {"user": {"password": "Example123"}}}),
    )
    rows, _ = run_scan()
    password = _one(rows, kind="password")
    assert password["value"] == "Example123"
    assert "auth.user.password" in password["evidence"]


def test_the_json_walker_stops_at_the_depth_cap(insert_http, run_scan):
    def nested(depth: int, value: str) -> str:
        node: dict = {"password": value}
        for _ in range(depth):
            node = {"wrap": node}
        return json.dumps(node)

    insert_http(stream_id=61, content_type="application/json",
                request_body=nested(5, "read-at-depth-six"))
    insert_http(stream_id=62, content_type="application/json",
                request_body=nested(6, "past-the-depth-cap"))
    rows, _ = run_scan()
    assert _find(rows, value="read-at-depth-six")
    assert _find(rows, value="past-the-depth-cap") == []


def test_a_json_value_of_the_wrong_type_is_not_invented(insert_http, run_scan):
    insert_http(
        content_type="application/json",
        request_body=json.dumps(
            {"password": None, "token": ["a", "b"], "secret": {"nested": "abc"}}
        ),
    )
    rows, _ = run_scan()
    assert rows == []


def test_a_json_boolean_is_a_placeholder_and_a_number_is_a_value(insert_http, run_scan):
    insert_http(
        content_type="application/json",
        request_body=json.dumps({"password": True, "token": 987654321}),
    )
    rows, _ = run_scan()
    assert len(rows) == 1
    assert rows[0]["kind"] == "other_secret"
    assert rows[0]["value"] == "987654321"


def test_a_json_body_without_a_content_type_is_still_parsed_as_json(insert_http, run_scan):
    insert_http(content_type=None, request_body=json.dumps({"password": "Example123"}))
    rows, _ = run_scan()
    assert _one(rows, kind="password")["value"] == "Example123"


def test_a_non_textual_body_is_not_scanned(insert_http, run_scan):
    insert_http(content_type="image/png", request_body="password=Example123&token=abcdef")
    rows, _ = run_scan()
    assert rows == []


def test_a_free_text_label_is_medium_and_an_unlabelled_shape_is_low(insert_http, run_scan):
    insert_http(
        content_type="text/plain",
        request_body=f"password=Example123\nnote {AKIA} pasted here\n",
    )
    rows, _ = run_scan()
    labelled = _one(rows, kind="password")
    assert labelled["confidence"] == "medium"
    assert labelled["location"] == "body_text"
    shaped = _one(rows, kind="aws_access_key")
    assert shaped["confidence"] == "low"
    assert shaped["value"] == AKIA


def test_a_body_beyond_max_body_chars_is_not_examined(insert_http, run_scan):
    insert_http(
        stream_id=71,
        content_type="application/x-www-form-urlencoded",
        request_body="password=" + "a" * 20,
    )
    insert_http(
        stream_id=72,
        content_type="application/x-www-form-urlencoded",
        request_body="x" * (ca.MAX_BODY_CHARS + 10) + "&password=BeyondTheCap1",
    )
    rows, _ = run_scan()
    assert _values(rows) == ["a" * 20]


# ==========================================================================
# 5. command protocols (§2, §3.1)
# ==========================================================================

def test_ftp_user_command_yields_a_username(insert_session, run_scan):
    insert_session("ftp", {"commands": [{"verb": "USER", "arg": "carol", "count": 1}]})
    rows, _ = run_scan()
    row = _one(rows, kind="username")
    assert row["value"] == "carol"
    assert row["protocol"] == "ftp"
    assert row["location"] == "ftp_user_command"
    assert row["confidence"] == "high"
    assert row["transport"] == "tcp"
    assert row["direction"] == "client_to_server"
    assert row["packet_first"] == 11 and row["packet_last"] == 19


def test_ftp_pass_command_yields_a_password(insert_session, run_scan):
    insert_session("ftp", {"commands": [{"verb": "PASS", "arg": "S3cretFtp", "count": 1}]})
    rows, _ = run_scan()
    row = _one(rows, kind="password")
    assert row["value"] == "S3cretFtp"
    assert row["location"] == "ftp_pass_command"


def test_a_redacted_pass_argument_reports_nothing(insert_session, run_scan):
    """The analyser blanks a PASS argument; a count is not a value (§3.1, §5)."""
    insert_session(
        "ftp",
        {
            "commands": [
                {"verb": "USER", "arg": "carol", "count": 1},
                {"verb": "PASS", "count": 1},
            ],
            "password_present": True,
        },
    )
    rows, _ = run_scan()
    assert _values(rows) == ["carol"]


def test_ftp_username_detail_is_read_as_a_fallback(insert_session, run_scan):
    insert_session("ftp", {"username": "dave", "password_present": True})
    rows, _ = run_scan()
    row = _one(rows, kind="username")
    assert row["value"] == "dave"
    assert row["location"] == "ftp_username"


def test_smtp_auth_plain_is_decoded(insert_session, run_scan):
    payload = b64("\0alice\0Example123")
    insert_session("smtp", {"commands": [{"verb": "AUTH", "arg": f"PLAIN {payload}", "count": 1}]})
    rows, _ = run_scan()
    assert _one(rows, kind="username")["value"] == "alice"
    password = _one(rows, kind="password")
    assert password["value"] == "Example123"
    assert password["location"] == "smtp_auth_plain"
    assert password["confidence"] == "high"
    assert payload not in password["evidence"]


def test_smtp_auth_plain_that_is_not_a_credential_pair_is_opaque(insert_session, run_scan):
    payload = b64("alice-only-name")
    insert_session("smtp", {"commands": [{"verb": "AUTH", "arg": f"PLAIN {payload}", "count": 1}]})
    rows, _ = run_scan()
    row = _one(rows, kind="other_secret")
    assert row["value"] == payload
    assert row["confidence"] == "medium"


def test_smtp_auth_login_decodes_both_arguments(insert_session, run_scan):
    insert_session(
        "smtp",
        {
            "commands": [
                {"verb": "AUTH", "arg": f"LOGIN {b64('alice')} {b64('Example123')}", "count": 1}
            ]
        },
    )
    rows, _ = run_scan()
    assert _one(rows, kind="username")["value"] == "alice"
    password = _one(rows, kind="password")
    assert password["value"] == "Example123"
    assert password["location"] == "smtp_auth_login"


def test_smtp_user_and_pass_commands(insert_session, run_scan):
    insert_session(
        "smtp",
        {
            "commands": [
                {"verb": "USER", "arg": "alice", "count": 1},
                {"verb": "PASS", "arg": "Example123", "count": 1},
            ]
        },
    )
    rows, _ = run_scan()
    assert _one(rows, kind="username")["location"] == "smtp_user_command"
    assert _one(rows, kind="password")["location"] == "smtp_pass_command"


def test_smtp_auth_username_detail_is_a_fallback(insert_session, run_scan):
    insert_session(
        "smtp",
        {"auth_username": "alice", "password_present": True, "auth_mechanisms": ["PLAIN"]},
    )
    rows, _ = run_scan()
    row = _one(rows, kind="username")
    assert row["value"] == "alice"
    assert row["location"] == "smtp_auth_username"


def test_a_password_present_boolean_yields_no_value(insert_session, run_scan):
    insert_session("smtp", {"auth_username": "alice", "password_present": True})
    insert_session("pop3", {"username": "bob", "password_present": True}, stream_id=4)
    insert_session("imap", {"username": "carol", "password_present": True}, stream_id=5)
    rows, _ = run_scan()
    assert sorted(_values(rows)) == ["alice", "bob", "carol"]
    assert _find(rows, kind="password") == []


def test_pop3_user_and_pass_commands(insert_session, run_scan):
    insert_session(
        "pop3",
        {
            "commands": [
                {"verb": "USER", "arg": "alice", "count": 1},
                {"verb": "PASS", "arg": "Example123", "count": 1},
            ]
        },
    )
    rows, _ = run_scan()
    assert _one(rows, kind="username")["location"] == "pop3_user_command"
    row = _one(rows, kind="password")
    assert row["value"] == "Example123"
    assert row["location"] == "pop3_pass_command"


def test_pop3_auth_plain(insert_session, run_scan):
    payload = b64("\0alice\0Example123")
    insert_session("pop3", {"commands": [{"verb": "AUTH", "arg": f"PLAIN {payload}", "count": 1}]})
    rows, _ = run_scan()
    assert _one(rows, kind="password")["location"] == "pop3_auth_plain"


def test_imap_login_command_yields_username_and_password(insert_session, run_scan):
    insert_session(
        "imap", {"commands": [{"verb": "LOGIN", "arg": '"alice" "Example123"', "count": 1}]}
    )
    rows, _ = run_scan()
    assert _one(rows, kind="username")["value"] == "alice"
    password = _one(rows, kind="password")
    assert password["value"] == "Example123"
    assert password["location"] == "imap_login_command"


def test_imap_login_with_an_escaped_quote(insert_session, run_scan):
    # IMAP escapes a quote inside a quoted string with a backslash.
    insert_session(
        "imap", {"commands": [{"verb": "LOGIN", "arg": '"al\\"ice" "Example123"', "count": 1}]}
    )
    rows, _ = run_scan()
    assert _one(rows, kind="username")["value"] == 'al"ice'


def test_imap_commands_without_arguments_yield_only_the_username_detail(insert_session, run_scan):
    """The IMAP detail stores verbs without arguments, so only its identity is readable."""
    insert_session(
        "imap",
        {
            "commands": [{"verb": "LOGIN", "count": 1}, {"verb": "SELECT", "count": 2}],
            "username": "alice",
            "password_present": True,
        },
    )
    rows, _ = run_scan()
    assert _values(rows) == ["alice"]
    assert _one(rows, kind="username")["location"] == "imap_username"


def test_a_protocol_that_was_not_classified_is_not_read(insert_session, run_scan):
    insert_session("ssh", {"commands": [{"verb": "USER", "arg": "alice", "count": 1}]})
    insert_session("smb", {"username": "alice", "password_present": True}, stream_id=6)
    rows, stats = run_scan()
    assert rows == []
    assert stats["findings"] == 0


# ==========================================================================
# 6. secret shapes (§3.3)
# ==========================================================================

@pytest.mark.parametrize(
    ("value", "kind"),
    [
        (AKIA, "aws_access_key"),
        (ASIA, "aws_access_key"),
        (JWT, "jwt"),
        (PEM, "pem_private_key"),
        (GITHUB, "github_token"),
        (SLACK, "slack_token"),
        (GOOGLE, "google_api_key"),
        (STRIPE, "stripe_key"),
    ],
)
def test_each_shape_is_matched_inside_a_selected_value(insert_http, run_scan, value, kind):
    insert_http(content_type="application/json", request_body=json.dumps({"password": value}))
    rows, _ = run_scan()
    row = _one(rows, kind=kind)
    assert row["value"] == value
    assert row["confidence"] == "high"
    assert row["method"] == "pattern"
    assert row["location"] == "json_body"
    assert row["source_field"] == "password"


def test_a_shape_inside_a_query_value_keeps_the_query_confidence(insert_http, run_scan):
    insert_http(
        method="GET",
        uri=f"/hook?access_token={JWT}",
        full_uri=f"http://example.test/hook?access_token={JWT}",
    )
    rows, _ = run_scan()
    assert _one(rows, kind="jwt")["confidence"] == "medium"


def test_a_shape_in_a_value_no_name_vouched_for_is_low(insert_http, run_scan):
    insert_http(
        method="GET",
        uri=f"/hook?ref={GITHUB}",
        full_uri=f"http://example.test/hook?ref={GITHUB}",
    )
    rows, _ = run_scan()
    row = _one(rows, kind="github_token")
    assert row["confidence"] == "low"
    assert row["source_field"] == "ref"


def test_only_the_matched_shape_is_stored_from_a_longer_value(insert_http, run_scan):
    insert_http(
        content_type="application/json",
        request_body=json.dumps({"token": f"prefix {SLACK} suffix"}),
    )
    rows, _ = run_scan()
    row = _one(rows, kind="slack_token")
    assert row["value"] == SLACK
    assert "suffix" not in row["value"]


def test_no_shape_is_reported_from_a_body_that_is_not_scanned(insert_http, run_scan):
    insert_http(content_type="application/octet-stream", request_body=f"github {GITHUB}")
    rows, _ = run_scan()
    assert rows == []


def test_a_base64_looking_value_with_no_context_is_not_decoded(insert_http, run_scan):
    """§3.1: Base64 is decoded only where a protocol says the field is Base64."""
    insert_http(
        content_type="application/json",
        request_body=json.dumps({"blob": b64("alice:Example123")}),
    )
    rows, _ = run_scan()
    assert rows == []


# ==========================================================================
# 7. value filtering (§3.4)
# ==========================================================================

def test_a_value_shorter_than_the_minimum_is_ignored(insert_http, run_scan):
    insert_http(content_type="application/json", request_body=json.dumps({"password": "ab"}))
    rows, _ = run_scan()
    assert rows == []


@pytest.mark.parametrize(
    "placeholder",
    [
        "password", "changeme", "example", "test", "xxxxxx", "<TOKEN>", "***", "null",
        "undefined", "true", "false",
    ],
)
def test_placeholder_values_are_discarded(insert_http, run_scan, placeholder):
    insert_http(content_type="application/json", request_body=json.dumps({"password": placeholder}))
    rows, _ = run_scan()
    assert rows == []


def test_a_punctuation_only_value_is_discarded(insert_http, run_scan):
    insert_http(content_type="application/json", request_body=json.dumps({"password": ":-:-:"}))
    rows, _ = run_scan()
    assert rows == []


def test_an_overlong_value_is_truncated_and_flagged(insert_http, run_scan):
    overlong = "A1" * (ca.MAX_VALUE_CHARS + 40)
    insert_http(content_type="application/json", request_body=json.dumps({"password": overlong}))
    rows, _ = run_scan()
    row = _one(rows, kind="password")
    # value_length counts what the row stores (Documentation/Credentials.md §6).
    assert len(row["value"]) == ca.MAX_VALUE_CHARS
    assert row["value_length"] == ca.MAX_VALUE_CHARS
    assert row["value_truncated"] == 1
    assert row["value_preview"] == ca.preview(overlong[: ca.MAX_VALUE_CHARS])


def test_a_value_identical_to_its_field_name_is_discarded(insert_http, run_scan):
    insert_http(content_type="application/json", request_body=json.dumps({"password": "password1"}))
    insert_http(
        stream_id=81, content_type="application/json", request_body=json.dumps({"api_key": "api_key"})
    )
    rows, _ = run_scan()
    assert _find(rows, value="api_key") == []
    assert _values(rows) == ["password1"]


# ==========================================================================
# 8. redaction and reveal (§5)
# ==========================================================================

def test_preview_keeps_a_head_and_a_tail_and_nothing_between(insert_http, run_scan):
    insert_http(content_type="application/json", request_body=json.dumps({"password": "Example123"}))
    rows, _ = run_scan()
    row = _one(rows, kind="password")
    assert row["value_preview"] == "Exa•••23"


def test_preview_never_reproduces_the_value():
    for length in range(1, 40):
        value = ("abcdefghij" * 4)[:length]
        assert ca.preview(value) != value, value
    # Even a value that already contains the separator is not reproduced.
    assert ca.preview("abc•••ef") == ca.PREVIEW_SEPARATOR
    assert ca.preview("") == ""


def test_evidence_is_redacted_before_it_is_stored(insert_http, run_scan):
    insert_http(content_type="application/json", request_body=json.dumps({"password": "Example123"}))
    rows, _ = run_scan()
    row = _one(rows, kind="password")
    assert "Example123" not in row["evidence"]
    assert ca.preview("Example123") in row["evidence"]


def test_the_log_lines_carry_no_value(insert_http, run_scan, caplog):
    secret = "Example123NotLogged"
    insert_http(request_headers=json.dumps({"Authorization": f"Basic {b64(f'alice:{secret}')}"}))
    insert_http(
        stream_id=91,
        content_type="application/json",
        request_body=json.dumps({"password": secret}),
    )
    with caplog.at_level(logging.DEBUG, logger="apackets.credentials"):
        rows, _ = run_scan()
    assert rows, "the fixture must produce findings for this test to mean anything"
    assert secret not in caplog.text
    assert b64(f"alice:{secret}") not in caplog.text
    assert "password=" in caplog.text


# ==========================================================================
# 9. the toggle and the protocol selection (§7)
# ==========================================================================

def test_a_disabled_scan_writes_nothing_and_names_the_setting(insert_http):
    insert_http(request_headers=json.dumps({"Authorization": f"Basic {b64('alice:Example123')}"}))
    runtime_settings.save_credential_config({"credential_scan_enabled": False})
    before = _table_counts()

    stats = ca.analyze(StubContext(), ANALYSIS_ID, None)

    assert stats["enabled"] is False
    assert stats["skipped"] is True
    assert stats["findings"] == 0
    assert any("credential_scan_enabled" in w for w in stats["warnings"])
    assert _table_counts() == before
    assert ca.stage_marker(ANALYSIS_ID) is None


def test_a_disabled_scan_leaves_earlier_findings_alone(insert_http, run_scan):
    insert_http(request_headers=json.dumps({"Authorization": f"Basic {b64('alice:Example123')}"}))
    rows, _ = run_scan()
    assert len(rows) == 2

    runtime_settings.save_credential_config({"credential_scan_enabled": False})
    stats = ca.analyze(StubContext(), ANALYSIS_ID, None)

    assert stats["skipped"] is True
    kept = db.query_all("SELECT * FROM credentials WHERE analysis_id = ?", (ANALYSIS_ID,))
    assert len(kept) == 2
    # The marker still describes the run that wrote them (§7).
    assert ca.stage_marker(ANALYSIS_ID)["findings"] == 2


def test_the_protocol_selection_restricts_the_scan(insert_http, insert_session, run_scan):
    insert_http(request_headers=json.dumps({"Authorization": f"Basic {b64('alice:Example123')}"}))
    insert_session("ftp", {"commands": [{"verb": "USER", "arg": "carol", "count": 1}]})

    rows, stats = run_scan(protocols=["ftp"])
    assert stats["protocols"] == ["ftp"]
    assert _values(rows) == ["carol"]

    rows, _ = run_scan(protocols=["http"])
    assert sorted(_values(rows)) == ["Example123", "alice"]


def test_an_empty_protocol_list_scans_nothing(insert_http, insert_session, run_scan):
    insert_http(request_headers=json.dumps({"Authorization": f"Basic {b64('alice:Example123')}"}))
    insert_session("ftp", {"commands": [{"verb": "USER", "arg": "carol", "count": 1}]})
    rows, stats = run_scan(protocols=[])
    assert stats["findings"] == 0
    assert rows == []
    # The stage still ran, so the marker exists and says what it scanned.
    assert ca.stage_marker(ANALYSIS_ID)["protocols"] == []


def test_the_pipeline_band_table_still_sums_to_one_hundred():
    from app.services import pipeline

    assert sum(span for _, span in pipeline.BANDS.values()) == pytest.approx(100.0)
    assert set(pipeline.BANDS) == {
        "metadata", "packets", "conversations", "http", "dns", "tls", "protocols",
        "hosts", "objects", "credentials", "detection", "suricata", "finalise",
    }
    assert pipeline.BANDS["objects"][0] < pipeline.BANDS["credentials"][0]
    assert pipeline.BANDS["credentials"][0] < pipeline.BANDS["detection"][0]
    assert pipeline.BANDS["detection"][0] < pipeline.BANDS["suricata"][0]


def test_the_pipeline_runs_credentials_after_objects_and_before_detection(
    client, run_analysis, empty_capture, monkeypatch
):
    """The stage's place in the pipeline, asserted by recording what ran."""
    order: list[str] = []
    _patch_stages(monkeypatch, order)

    analysis_id, detail = run_analysis(empty_capture)
    assert detail["status"] == "completed"
    assert order.index("objects") < order.index("credentials") < order.index("detection")


def test_the_pipeline_records_the_declined_scan_as_a_warning(
    client, run_analysis, empty_capture, monkeypatch
):
    """With the setting off the analysis completes and says why nothing was written."""
    from app.services import pipeline

    order: list[str] = []
    _patch_stages(monkeypatch, order, skip="credentials")
    runtime_settings.save_credential_config({"credential_scan_enabled": False})

    analysis_id, detail = run_analysis(empty_capture)

    assert detail["status"] == "completed"
    assert "objects" in order and "detection" in order
    warnings = pipeline.load_warnings(analysis_id)
    assert any("credential_scan_enabled" in warning for warning in warnings), warnings
    assert db.query_all("SELECT * FROM credentials WHERE analysis_id = ?", (analysis_id,)) == []


def _patch_stages(monkeypatch, order: list[str], *, skip: str | None = None) -> None:
    """Replace every optional stage with a recorder, so ordering is what is tested."""
    import importlib

    stages = {
        "conversations": "conversation_analyzer",
        "http": "http_analyzer",
        "dns": "dns_analyzer",
        "tls": "tls_analyzer",
        "protocols": "protocol_analyzer",
        "hosts": "host_analyzer",
        "objects": "object_extractor",
        "credentials": "credential_analyzer",
        "detection": "detection_engine",
        "suricata": "suricata_engine",
    }
    for stage, module_name in stages.items():
        if stage == skip:
            continue
        module = importlib.import_module(f"app.services.{module_name}")

        def recorder(ctx, analysis_id, capture_path, _stage=stage):  # noqa: ARG001
            order.append(_stage)
            return {"recorded": _stage, "findings": 0}

        monkeypatch.setattr(module, "analyze", recorder)


# ==========================================================================
# 10. caps (§9)
# ==========================================================================

def test_max_findings_keeps_the_highest_confidence_first(insert_http, run_scan):
    insert_http(
        stream_id=101,
        content_type="application/x-www-form-urlencoded",
        request_body="&".join(f"password=value-{index:03d}" for index in range(199)),
    )
    for index in range(10):
        insert_http(
            stream_id=102 + index,
            content_type="text/plain",
            request_body=f"unlabelled token {akia(index)} in the clear",
        )
    rows, stats = run_scan()
    assert stats["findings"] == ca.MAX_FINDINGS
    assert len(rows) == ca.MAX_FINDINGS
    confidences = [row["confidence"] for row in rows]
    assert confidences[:199] == ["high"] * 199
    assert confidences[199:] == ["low"]
    assert _find(rows, value="value-000") and _find(rows, value="value-198")
    assert _find(rows, value="value-199") == []


def test_max_fields_per_location(insert_http, run_scan):
    insert_http(
        content_type="application/x-www-form-urlencoded",
        request_body="&".join(f"password=value-{index:03d}" for index in range(250)),
    )
    rows, stats = run_scan()
    assert ca.MAX_FIELDS_PER_LOCATION == 200
    assert stats["findings"] == 200
    assert _find(rows, value="value-199")
    assert _find(rows, value="value-200") == []


def test_the_contract_caps_have_their_documented_values():
    assert ca.MAX_FINDINGS == 200
    assert ca.MAX_VALUE_CHARS == 512
    assert ca.MAX_BODY_CHARS == 262144
    assert ca.MAX_FIELDS_PER_LOCATION == 200
    assert ca.MIN_VALUE_CHARS == 3
    assert (ca.PREVIEW_HEAD, ca.PREVIEW_TAIL) == (3, 2)
    assert ca.JSON_DEPTH == 6


# ==========================================================================
# 11. determinism
# ==========================================================================

def test_the_same_rows_produce_the_same_rows_twice(insert_http, insert_session, run_scan):
    insert_http(
        stream_id=111,
        request_headers=json.dumps(
            {
                "Authorization": f"Basic {b64('alice:Example123')}",
                "Cookie": "session_id=9f8e7d6c5b4a",
            }
        ),
        content_type="application/json",
        request_body=json.dumps({"user": "alice", "password": "Example123", "token": GITHUB}),
    )
    insert_session(
        "ftp",
        {
            "commands": [
                {"verb": "USER", "arg": "carol", "count": 1},
                {"verb": "PASS", "arg": "S3cretFtp", "count": 1},
            ]
        },
    )
    insert_session(
        "smtp",
        {"commands": [{"verb": "AUTH", "arg": f"PLAIN {b64(chr(0) + 'bob' + chr(0) + 'Example123')}", "count": 1}]},
        stream_id=4,
    )

    columns = [row["name"] for row in db.query_all("PRAGMA table_info(credentials)")]
    stable = [name for name in columns if name not in {"id", "created_at"}]

    first, _ = run_scan()
    second, _ = run_scan()

    def shape(rows):
        return [tuple(row[name] for name in stable) for row in rows]

    assert shape(first) == shape(second)
    assert len(first) > 4


def test_two_analyses_do_not_see_each_others_rows(insert_http, run_scan):
    insert_http(
        analysis_id=ANALYSIS_ID,
        request_headers=json.dumps({"Authorization": f"Basic {b64('alice:Example123')}"}),
    )
    insert_http(
        analysis_id=OTHER_ID,
        request_headers=json.dumps({"Authorization": f"Basic {b64('mallory:Other123')}"}),
    )

    rows, _ = run_scan(analysis_id=ANALYSIS_ID)
    assert sorted(_values(rows)) == ["Example123", "alice"]
    other, _ = run_scan(analysis_id=OTHER_ID)
    assert sorted(_values(other)) == ["Other123", "mallory"]


# ==========================================================================
# 12. the endpoints (§8)
# ==========================================================================

ITEM_FIELDS = (
    "id", "kind", "value_preview", "value_length", "value_truncated", "protocol",
    "transport", "stream_id", "direction", "location", "source_field", "method",
    "confidence", "client_ip", "client_port", "server_ip", "server_port",
    "packet_first", "packet_last", "evidence", "note", "created_at",
)


def test_list_serves_the_seeded_rows(client, seeded):
    body = client.get(f"/api/analyses/{ANALYSIS_ID}/credentials").json()
    assert body["total"] == 7
    assert body["page"] == 1
    assert body["page_size"] == 50
    assert body["reveal"] is False
    assert len(body["items"]) == 7
    assert body["note"]
    assert set(body["scan"]) >= {"enabled", "protocols", "scanned_at"}


def test_list_items_carry_the_contract_fields(client, seeded):
    item = client.get(f"/api/analyses/{ANALYSIS_ID}/credentials").json()["items"][0]
    for field in ITEM_FIELDS:
        assert field in item, field
    assert "value" not in item
    assert "analysis_id" not in item
    assert item["value_truncated"] is False
    assert item["value_preview"]


def test_list_never_serves_a_full_value(client, seeded):
    response = client.get(f"/api/analyses/{ANALYSIS_ID}/credentials")
    assert response.status_code == 200
    for secret in SEED_SECRETS:
        assert secret not in response.text, secret
    assert "•••" in response.text


def test_reveal_serves_the_full_value(client, seeded):
    body = client.get(f"/api/analyses/{ANALYSIS_ID}/credentials?reveal=1").json()
    assert body["reveal"] is True
    served = {item.get("value") for item in body["items"]}
    assert {"Example123", "Hunter2Hunter2", "alice", "bob", "carol"} <= served
    assert all("value" in item for item in body["items"])


def test_list_filters_by_kind(client, seeded):
    body = client.get(f"/api/analyses/{ANALYSIS_ID}/credentials?kind=password").json()
    assert body["total"] == 2
    assert {item["kind"] for item in body["items"]} == {"password"}


def test_list_filters_by_protocol(client, seeded):
    body = client.get(f"/api/analyses/{ANALYSIS_ID}/credentials?protocol=ftp").json()
    assert body["total"] == 1
    assert body["items"][0]["protocol"] == "ftp"


def test_list_filters_by_confidence(client, seeded):
    for level, expected in (("high", 5), ("medium", 1), ("low", 1)):
        body = client.get(f"/api/analyses/{ANALYSIS_ID}/credentials?confidence={level}").json()
        assert body["total"] == expected, level
        assert {item["confidence"] for item in body["items"]} == {level}


def test_list_filters_by_stream_id(client, seeded):
    body = client.get(f"/api/analyses/{ANALYSIS_ID}/credentials?stream_id=31").json()
    assert body["total"] == 2
    assert {item["stream_id"] for item in body["items"]} == {31}


def test_list_filters_combine(client, seeded):
    body = client.get(
        f"/api/analyses/{ANALYSIS_ID}/credentials?kind=password&protocol=http&confidence=high"
    ).json()
    assert body["total"] == 2


def test_list_rejects_an_unknown_kind(client, seeded):
    response = client.get(f"/api/analyses/{ANALYSIS_ID}/credentials?kind=ssh_key")
    assert response.status_code == 422
    assert response.json()["error"]["code"] == "validation_error"
    assert "password" in response.json()["error"]["details"]["allowed"]


def test_list_rejects_an_unknown_protocol(client, seeded):
    response = client.get(f"/api/analyses/{ANALYSIS_ID}/credentials?protocol=ssh")
    assert response.status_code == 422
    assert "http" in response.json()["error"]["details"]["allowed"]


def test_list_rejects_an_unknown_confidence(client, seeded):
    response = client.get(f"/api/analyses/{ANALYSIS_ID}/credentials?confidence=certain")
    assert response.status_code == 422


def test_list_rejects_an_unknown_sort(client, seeded):
    response = client.get(f"/api/analyses/{ANALYSIS_ID}/credentials?sort=value")
    assert response.status_code == 400
    assert response.json()["error"]["code"] == "invalid_sort"
    assert "confidence" in response.json()["error"]["details"]["allowed"]


def test_list_rejects_an_unknown_order(client, seeded):
    response = client.get(f"/api/analyses/{ANALYSIS_ID}/credentials?order=sideways")
    assert response.status_code == 400
    assert response.json()["error"]["code"] == "invalid_order"


def test_list_sorts_by_confidence_highest_first_by_default(client, seeded):
    body = client.get(f"/api/analyses/{ANALYSIS_ID}/credentials").json()
    assert body["items"][0]["confidence"] == "high"
    assert body["items"][-1]["confidence"] == "low"
    ascending = client.get(f"/api/analyses/{ANALYSIS_ID}/credentials?order=asc").json()
    assert ascending["items"][0]["confidence"] == "low"


def test_list_sorts_by_kind_and_by_created_at(client, seeded):
    by_kind = client.get(f"/api/analyses/{ANALYSIS_ID}/credentials?sort=kind&order=asc").json()
    kinds = [item["kind"] for item in by_kind["items"]]
    assert kinds == sorted(kinds)

    by_time = client.get(
        f"/api/analyses/{ANALYSIS_ID}/credentials?sort=created_at&order=desc"
    ).json()
    times = [item["created_at"] for item in by_time["items"]]
    assert times == sorted(times, reverse=True)
    assert len(by_time["items"]) == 7


def test_list_paginates(client, seeded):
    first = client.get(f"/api/analyses/{ANALYSIS_ID}/credentials?page=1&page_size=3").json()
    second = client.get(f"/api/analyses/{ANALYSIS_ID}/credentials?page=2&page_size=3").json()
    third = client.get(f"/api/analyses/{ANALYSIS_ID}/credentials?page=3&page_size=3").json()
    assert first["total"] == second["total"] == third["total"] == 7
    assert [len(page["items"]) for page in (first, second, third)] == [3, 3, 1]
    seen = [item["id"] for page in (first, second, third) for item in page["items"]]
    assert len(set(seen)) == 7


def test_list_counts_block_describes_the_whole_filter(client, seeded):
    counts = client.get(
        f"/api/analyses/{ANALYSIS_ID}/credentials?confidence=high"
    ).json()["counts"]
    assert counts["total"] == 5
    assert counts["by_confidence"]["high"] == 5
    assert counts["by_confidence"]["medium"] == 0
    assert counts["by_kind"]["password"] == 2
    assert set(counts["by_kind"]) == set(ca.KINDS)


def test_the_scan_block_reports_the_setting_and_the_last_run(client, seeded):
    scan = client.get(f"/api/analyses/{ANALYSIS_ID}/credentials").json()["scan"]
    assert scan["enabled"] is True
    assert scan["protocols"] == list(runtime_settings.CREDENTIAL_PROTOCOLS)
    assert scan["protocols_scanned"] == ["http", "ftp"]
    assert scan["stage_ran"] is True
    assert scan["scanned_at"] is not None
    assert scan["rows"] == 7
    assert scan["rows_written_at"] is not None
    assert scan["findings"] == 7
    assert scan["seconds"] is not None
    assert scan["capped"] is False
    assert scan["matched"] == 7


def test_the_scan_block_still_reports_rows_when_the_setting_is_off(client, seeded):
    runtime_settings.save_credential_config({"credential_scan_enabled": False})
    body = client.get(f"/api/analyses/{ANALYSIS_ID}/credentials").json()
    assert body["scan"]["enabled"] is False
    assert body["scan"]["rows"] == 7


def test_a_capped_scan_says_so_in_the_envelope(client, analysis, insert_http, run_scan):
    """§8.1's ``capped``: MAX_FINDINGS stopped the stage storing everything it matched."""
    analysis()
    insert_http(
        stream_id=401,
        content_type="application/x-www-form-urlencoded",
        request_body="&".join(f"password=value-{index:03d}" for index in range(199)),
    )
    for index in range(10):
        insert_http(
            stream_id=402 + index,
            content_type="text/plain",
            request_body=f"unlabelled token {akia(index)} in the clear",
        )
    run_scan()
    body = client.get(f"/api/analyses/{ANALYSIS_ID}/credentials").json()
    assert body["capped"] is True
    assert body["scan"]["capped"] is True
    assert body["scan"]["matched"] == 209
    assert body["scan"]["rows"] == body["total"] == ca.MAX_FINDINGS


def test_an_uncapped_scan_says_so(client, seeded):
    body = client.get(f"/api/analyses/{ANALYSIS_ID}/credentials").json()
    assert body["capped"] is False
    assert body["scan"]["matched"] == body["scan"]["findings"]


def test_summary_carries_no_values_at_all(client, seeded):
    response = client.get(f"/api/analyses/{ANALYSIS_ID}/credentials/summary")
    assert response.status_code == 200
    # Not the values, and not even a preview: §8.2 sends counts only.
    assert "•••" not in response.text
    for fragment in (*SEED_SECRETS, "value_preview", "evidence"):
        assert fragment not in response.text, fragment
    assert response.json()["total"] == 7


def test_summary_counts_kinds_protocols_and_confidences(client, seeded):
    body = client.get(f"/api/analyses/{ANALYSIS_ID}/credentials/summary").json()
    assert set(body["by_kind"]) == set(ca.KINDS)
    assert set(body["by_protocol"]) == set(ca.PROTOCOLS)
    assert body["by_protocol"]["http"] == 6
    assert body["by_protocol"]["ftp"] == 1
    assert body["by_confidence"]["high"] == 5
    assert body["by_confidence"]["low"] == 1
    assert body["high_confidence"] == 5
    # §8.2: ``streams`` is the per-(protocol, stream) breakdown and ``stream_count``
    # the number of those pairs.
    assert body["stream_count"] == 5
    assert {entry["stream_id"] for entry in body["streams"]} == {30, 31, 32, 33, 34}
    assert sum(entry["findings"] for entry in body["streams"]) == 7
    assert all(set(entry) == {"stream_id", "protocol", "findings"} for entry in body["streams"])
    assert body["scan"]["rows"] == 7


def test_the_summary_limits_state_the_caps_that_applied(client, seeded):
    """§8.2's ``limits``: the caps in words, plus what this run could not read."""
    limits = client.get(f"/api/analyses/{ANALYSIS_ID}/credentials/summary").json()["limits"]
    assert limits
    text = " ".join(limits)
    for constant in (
        str(ca.MAX_FINDINGS),
        str(ca.MAX_CONTROL_STREAMS),
        str(ca.MAX_STREAM_CHARS),
        str(ca.STREAM_TIMEOUT_S),
        str(ca.MAX_BODY_CHARS),
    ):
        assert constant in text, constant
    assert any("control stream" in line for line in limits)
    assert all("•••" not in line for line in limits)


def test_the_summary_limits_name_the_caps_that_actually_bit(
    client, analysis, insert_session, fake_reassembly, run_scan
):
    analysis()
    for index in range(30):
        insert_session(
            "ftp",
            {"commands": [{"verb": "PASS", "count": 1}], "password_present": True},
            stream_id=100 + index,
        )
    fake_reassembly(
        lambda stream_id: tshark.TsharkTimeout("slow")
        if stream_id == 100
        else follow_stream_fixture(
            client="10.0.0.1:40000",
            server="10.0.0.2:21",
            client_lines=[f"PASS value-{stream_id}"],
        )
    )
    run_scan(capture=Path(CAPTURE_FILE))
    limits = client.get(f"/api/analyses/{ANALYSIS_ID}/credentials/summary").json()["limits"]
    assert any("MAX_CONTROL_STREAMS" in line for line in limits)
    assert any("Stream 100 (ftp) was not read" in line and "20s" in line for line in limits)
    # A limit is stated in words, never with a value in it.
    assert all("value-" not in line for line in limits)


def test_summary_is_empty_for_an_analysis_with_no_rows(client, analysis):
    analysis()
    body = client.get(f"/api/analyses/{ANALYSIS_ID}/credentials/summary").json()
    assert body["total"] == 0
    assert body["scan"]["stage_ran"] is False
    assert body["scan"]["scanned_at"] is None
    assert body["streams"] == []
    assert body["stream_count"] == 0
    assert body["by_kind"]["password"] == 0
    # The caps are still stated, because they are what a scan would apply.
    assert body["limits"]


def test_the_read_routes_404_for_an_unknown_analysis(client):
    for path in ("/credentials", "/credentials/summary"):
        response = client.get(f"/api/analyses/{MISSING_ID}{path}")
        assert response.status_code == 404, path
        assert response.json()["error"]["code"] == "analysis_not_found"


def test_the_read_routes_409_while_the_analysis_is_not_ready(client, analysis):
    analysis(status="processing")
    for path in ("/credentials", "/credentials/summary"):
        response = client.get(f"/api/analyses/{ANALYSIS_ID}{path}")
        assert response.status_code == 409, path
        assert response.json()["error"]["code"] == "analysis_not_ready"


def test_the_scan_route_404_and_409_match_the_other_routes(client, analysis):
    response = client.post(f"/api/analyses/{MISSING_ID}/credentials/scan")
    assert response.status_code == 404
    assert response.json()["error"]["code"] == "analysis_not_found"

    analysis(status="processing")
    response = client.post(f"/api/analyses/{ANALYSIS_ID}/credentials/scan")
    assert response.status_code == 409
    assert response.json()["error"]["code"] == "analysis_not_ready"


def test_the_scan_route_410_when_the_capture_is_gone(client, analysis):
    analysis(capture=False)
    response = client.post(f"/api/analyses/{ANALYSIS_ID}/credentials/scan")
    assert response.status_code == 410
    assert response.json()["error"]["code"] == "capture_missing"


def test_the_scan_route_is_refused_while_the_setting_is_off(client, analysis):
    analysis()
    runtime_settings.save_credential_config({"credential_scan_enabled": False})
    response = client.post(f"/api/analyses/{ANALYSIS_ID}/credentials/scan")
    assert response.status_code == 409
    error = response.json()["error"]
    assert error["code"] == "credential_scan_disabled"
    assert "credential_scan_enabled" in error["message"]
    assert error["details"]["setting"] == "credential_scan_enabled"


def test_the_scan_route_queues_a_job_that_completes(client, analysis, insert_http):
    analysis()
    insert_http(request_headers=json.dumps({"Authorization": f"Basic {b64('alice:Example123')}"}))
    response = client.post(f"/api/analyses/{ANALYSIS_ID}/credentials/scan")
    assert response.status_code == 202
    body = response.json()
    assert body["kind"] == "credential_scan"
    assert body["status"] == "queued"
    assert body["analysis_id"] == ANALYSIS_ID

    assert _await_job(body["job_id"]) == "completed"

    items = client.get(f"/api/analyses/{ANALYSIS_ID}/credentials").json()["items"]
    assert len(items) == 2
    assert ca.stage_marker(ANALYSIS_ID)["findings"] == 2


# ==========================================================================
# 13. settings (§7)
# ==========================================================================

def test_settings_expose_the_credential_values(client):
    body = client.get("/api/settings").json()
    assert body["credential_scan_enabled"] is True
    assert body["credential_protocols"] == list(runtime_settings.CREDENTIAL_PROTOCOLS)
    assert body["credential_protocols_available"] == list(runtime_settings.CREDENTIAL_PROTOCOLS)


def test_settings_accept_the_credential_values(client):
    response = client.put(
        "/api/settings",
        json={"credential_scan_enabled": False, "credential_protocols": ["smtp", "pop3"]},
    )
    assert response.status_code == 200
    body = response.json()
    assert set(body["changed"]) >= {"credential_scan_enabled", "credential_protocols"}
    assert body["settings"]["credential_scan_enabled"] is False
    # The stored order is the contract's own order (http, ftp, smtp, pop3, imap).
    assert body["settings"]["credential_protocols"] == ["smtp", "pop3"]

    stored = db.query_one("SELECT value FROM settings WHERE key = ?", ("credential_config",))
    assert stored is not None
    assert json.loads(stored["value"])["credential_scan_enabled"] is False
    assert runtime_settings.credential_protocols() == ["smtp", "pop3"]


def test_settings_accept_an_empty_protocol_list(client):
    response = client.put("/api/settings", json={"credential_protocols": []})
    assert response.status_code == 200
    assert response.json()["settings"]["credential_protocols"] == []
    assert runtime_settings.credential_protocols() == []


def test_settings_reject_an_unknown_protocol_with_the_existing_error_shape(client):
    response = client.put("/api/settings", json={"credential_protocols": ["http", "telnet"]})
    assert response.status_code == 422
    error = response.json()["error"]
    assert error["code"] == "validation_error"
    assert "telnet" in error["message"]
    assert error["details"]["allowed"] == list(runtime_settings.CREDENTIAL_PROTOCOLS)
    # A rejected request writes nothing at all.
    assert db.query_one("SELECT value FROM settings WHERE key = ?", ("credential_config",)) is None


def test_settings_reject_a_badly_typed_protocol_list(client):
    response = client.put("/api/settings", json={"credential_protocols": "http"})
    assert response.status_code == 422
    assert response.json()["error"]["code"] == "validation_error"


def test_settings_do_not_disturb_the_other_overrides(client):
    assert client.put("/api/settings", json={"max_upload_mb": 123}).status_code == 200
    assert client.put("/api/settings", json={"credential_scan_enabled": False}).status_code == 200
    assert client.get("/api/settings").json()["max_upload_mb"] == 123
    assert runtime_settings.load_overrides()["max_upload_mb"] == 123
    assert runtime_settings.credential_scan_enabled() is False


def test_the_settings_page_can_turn_the_scan_back_on(client, analysis, insert_http):
    analysis()
    insert_http(request_headers=json.dumps({"Authorization": f"Basic {b64('alice:Example123')}"}))
    client.put("/api/settings", json={"credential_scan_enabled": False})
    assert client.post(f"/api/analyses/{ANALYSIS_ID}/credentials/scan").status_code == 409

    client.put("/api/settings", json={"credential_scan_enabled": True})
    response = client.post(f"/api/analyses/{ANALYSIS_ID}/credentials/scan")
    assert response.status_code == 202
    assert _await_job(response.json()["job_id"]) == "completed"


# ==========================================================================
# 14. the capability listing
# ==========================================================================

def test_capabilities_report_the_credentials_router(client):
    assert client.get("/api/capabilities").json()["features"]["credentials"] is True


# ==========================================================================
# 15. the control channel (§2b) — against the real captures
# ==========================================================================

def _details(rows: list[dict], protocol: str) -> dict:
    row = _one(rows, protocol=protocol)
    return json.loads(row["detail"])


def test_the_analysers_rows_hold_the_login_but_not_the_password(analyser_sessions):
    """The premise §2b rests on: the value is deliberately absent from the database."""
    rows = analyser_sessions("ftp")
    detail = _details(rows, "ftp")
    verbs = {entry["verb"]: entry for entry in detail["commands"]}

    assert "PASS" in verbs, "the analyser records the verb"
    assert "arg" not in verbs["PASS"], "and deliberately not its argument"
    assert detail.get("password_present") is True
    assert "guest@example.com" not in json.dumps(detail)


def test_ftp_pass_is_recovered_from_the_control_channel(
    analyser_sessions, control_captures, run_scan
):
    analyser_sessions("ftp")            # the analyser's own rows, nothing else
    rows, stats = run_scan(capture=control_captures["ftp"])

    password = _one(rows, kind="password", value="guest@example.com")
    assert password["confidence"] == "high"
    assert password["method"] == ca.CONTROL_METHOD
    assert password["location"] == "ftp_pass_command"
    assert password["protocol"] == "ftp"
    assert password["source_field"] == "PASS"
    assert password["direction"] == "client_to_server"
    assert password["value_preview"] == ca.preview("guest@example.com")
    assert "guest@example.com" not in password["evidence"]
    assert stats["control_streams"] == 1

    # The USER the analyser already stored is still reported, once, from the row.
    username = _one(rows, kind="username", value="anonymous")
    assert username["method"] == "command_arg"


def test_smtp_auth_login_exchange_is_read_from_the_control_channel(
    analyser_sessions, control_captures, run_scan
):
    """SMTP keeps the mechanism; the Base64 that answers it is only on the wire."""
    sessions = analyser_sessions("email")
    smtp = _details(sessions, "smtp")
    assert smtp.get("password_present") is True
    assert "s3cr3t" not in json.dumps(smtp)

    rows, stats = run_scan(capture=control_captures["email"])

    password = _one(rows, kind="password", value="s3cr3t")
    assert password["protocol"] == "smtp"
    assert password["location"] == "smtp_auth_login"
    assert password["confidence"] == "high"
    assert password["method"] == ca.CONTROL_METHOD
    assert b64("s3cr3t") not in password["evidence"]
    assert _one(rows, kind="username", value="alice")
    assert stats["control_streams"] == 3


def test_pop3_and_imap_logins_are_read_from_the_control_channel(
    analyser_sessions, control_captures, run_scan
):
    analyser_sessions("email")
    rows, _ = run_scan(capture=control_captures["email"])

    assert _one(rows, kind="username", value="dave")["protocol"] == "pop3"
    pop3 = _one(rows, kind="password", value="hunter2")
    assert pop3["location"] == "pop3_pass_command"
    assert pop3["method"] == ca.CONTROL_METHOD

    imap = _one(rows, kind="password", value="p@ss w0rd")
    assert imap["protocol"] == "imap"
    assert imap["location"] == "imap_login_command"
    assert imap["confidence"] == "high"
    assert _one(rows, kind="username", value="erin")["protocol"] == "imap"


# --------------------------------------------------------------------------
# the same reading, exercised on every branch of the exchange
# --------------------------------------------------------------------------

def _ftp_password_session(insert_session, *, stream_id: int = 3, port: int = 21) -> None:
    insert_session(
        "ftp",
        {"commands": [{"verb": "USER", "arg": "carol", "count": 1}, {"verb": "PASS", "count": 1}],
         "username": "carol", "password_present": True},
        stream_id=stream_id,
        server_port=port,
    )


def test_auth_plain_with_an_inline_token_is_decoded_from_the_channel(
    insert_session, fake_reassembly, run_scan
):
    _ftp_password_session(insert_session)
    insert_session(
        "smtp",
        {"commands": [{"verb": "AUTH", "arg": "PLAIN", "count": 1}]},
        stream_id=4,
        server_port=25,
    )
    fake_reassembly(
        lambda stream_id: follow_stream_fixture(
            client="10.0.0.1:40000",
            server="10.0.0.2:25",
            client_lines=[f"AUTH PLAIN {b64(chr(0) + 'bob' + chr(0) + 'Example123')}"],
        )
        if stream_id == 4
        else follow_stream_fixture(
            client="10.0.0.1:40000", server="10.0.0.2:21", client_lines=["PASS S3cretFtp"]
        )
    )
    rows, _ = run_scan(capture=Path(CAPTURE_FILE))

    assert _one(rows, kind="username", value="bob")["location"] == "smtp_auth_plain"
    password = _one(rows, kind="password", value="Example123")
    assert password["location"] == "smtp_auth_plain"
    assert password["confidence"] == "high"


def test_auth_plain_without_an_inline_token_waits_for_the_next_line(
    insert_session, fake_reassembly, run_scan
):
    """``AUTH PLAIN`` alone is answered by the Base64 blob on the next client line."""
    insert_session(
        "smtp", {"commands": [{"verb": "AUTH", "arg": "PLAIN", "count": 1}]}, stream_id=4
    )
    fake_reassembly(
        lambda stream_id: follow_stream_fixture(
            client="10.0.0.1:40000",
            server="10.0.0.2:25",
            client_lines=["AUTH PLAIN", b64("\0bob\0Example123")],
            server_lines=["334 "],
        )
    )
    rows, _ = run_scan(capture=Path(CAPTURE_FILE))
    assert _one(rows, kind="username", value="bob")
    assert _one(rows, kind="password", value="Example123")


def test_auth_login_without_an_inline_token_waits_for_both_lines(
    insert_session, fake_reassembly, run_scan
):
    insert_session(
        "smtp", {"commands": [{"verb": "AUTH", "arg": "LOGIN", "count": 1}]}, stream_id=4
    )
    fake_reassembly(
        lambda stream_id: follow_stream_fixture(
            client="10.0.0.1:40000",
            server="10.0.0.2:25",
            client_lines=["AUTH LOGIN", b64("alice"), b64("Example123")],
            server_lines=["334 VXNlcm5hbWU6", "334 UGFzc3dvcmQ6"],
        )
    )
    rows, _ = run_scan(capture=Path(CAPTURE_FILE))
    assert _one(rows, kind="username", value="alice")["location"] == "smtp_auth_login"
    assert _one(rows, kind="password", value="Example123")["location"] == "smtp_auth_login"


def test_auth_plain_that_is_not_a_credential_pair_is_medium_from_the_channel(
    insert_session, fake_reassembly, run_scan
):
    insert_session(
        "smtp", {"commands": [{"verb": "AUTH", "arg": "PLAIN", "count": 1}]}, stream_id=4
    )
    fake_reassembly(
        lambda stream_id: follow_stream_fixture(
            client="10.0.0.1:40000",
            server="10.0.0.2:25",
            client_lines=[f"AUTH PLAIN {b64('only-one-field')}"],
        )
    )
    rows, _ = run_scan(capture=Path(CAPTURE_FILE))
    row = _one(rows, kind="other_secret")
    assert row["value"] == b64("only-one-field")
    assert row["confidence"] == "medium"


def test_a_mechanism_this_build_does_not_decode_reports_nothing(
    insert_session, fake_reassembly, run_scan
):
    """CRAM-MD5's answer is a hash, not a password: nothing is reported for it."""
    insert_session(
        "smtp", {"commands": [{"verb": "AUTH", "arg": "CRAM-MD5", "count": 1}]}, stream_id=4
    )
    fake_reassembly(
        lambda stream_id: follow_stream_fixture(
            client="10.0.0.1:40000",
            server="10.0.0.2:25",
            client_lines=["AUTH CRAM-MD5", "YWxpY2UgYjNjNmQ1ZjY="],
            server_lines=["334 PDEyMzQ1Njc4OTA+"],
        )
    )
    rows, _ = run_scan(capture=Path(CAPTURE_FILE))
    assert rows == []


def test_the_servers_side_of_the_channel_is_never_read(
    insert_session, fake_reassembly, run_scan
):
    """A server line is a challenge or a banner, never the client's credential."""
    _ftp_password_session(insert_session)
    fake_reassembly(
        lambda stream_id: follow_stream_fixture(
            client="10.0.0.1:40000",
            server="10.0.0.2:21",
            client_lines=["USER carol", "PASS S3cretFtp"],
            server_lines=["331 Password required", "PASS server-side-deception"],
        )
    )
    rows, _ = run_scan(capture=Path(CAPTURE_FILE))
    assert sorted(_values(rows)) == ["S3cretFtp", "carol"]
    assert _find(rows, value="server-side-deception") == []


def test_a_stream_whose_client_side_cannot_be_identified_is_named(
    insert_session, fake_reassembly, run_scan
):
    _ftp_password_session(insert_session)
    fake_reassembly(
        lambda stream_id: follow_stream_fixture(
            client="192.0.2.9:1",
            server="192.0.2.9:2",
            client_lines=["PASS S3cretFtp"],
        )
    )
    rows, stats = run_scan(capture=Path(CAPTURE_FILE))
    assert _find(rows, kind="password") == []
    assert any("client's side" in warning for warning in stats["warnings"])


def test_a_stream_the_reassembly_did_not_find_is_named(
    insert_session, fake_reassembly, run_scan
):
    _ftp_password_session(insert_session)
    fake_reassembly(lambda stream_id: tshark.FollowStream())
    rows, stats = run_scan(capture=Path(CAPTURE_FILE))
    assert _find(rows, kind="password") == []
    assert any("reassembled no content" in warning for warning in stats["warnings"])


def test_a_udp_session_is_not_reassembled(insert_session, fake_reassembly, run_scan):
    _ftp_password_session(insert_session)
    db.execute(
        "UPDATE protocol_sessions SET transport = 'udp' WHERE analysis_id = ?", (ANALYSIS_ID,)
    )
    calls = fake_reassembly(lambda stream_id: follow_stream_fixture(
        client="10.0.0.1:40000", server="10.0.0.2:21", client_lines=["PASS S3cretFtp"]
    ))
    rows, stats = run_scan(capture=Path(CAPTURE_FILE))
    assert calls == []
    assert _find(rows, kind="password") == []
    assert any("TCP streams" in warning for warning in stats["warnings"])


# --------------------------------------------------------------------------
# what §2b must not do
# --------------------------------------------------------------------------

def test_a_session_with_no_credential_verb_is_not_reassembled(
    insert_session, fake_reassembly, run_scan
):
    insert_session(
        "ftp",
        {"commands": [{"verb": "CWD", "arg": "/pub", "count": 1},
                      {"verb": "RETR", "arg": "report.pdf", "count": 1}]},
        stream_id=7,
    )
    calls = fake_reassembly(
        lambda stream_id: follow_stream_fixture(
            client="10.0.0.1:40000",
            server="10.0.0.2:21",
            client_lines=["PASS S3cretFtp"],
        )
    )
    rows, stats = run_scan(capture=Path(CAPTURE_FILE))
    assert calls == []
    assert rows == []
    assert stats["control_streams"] == 0


def test_an_authenticated_login_without_a_verb_is_still_reassembled(
    insert_session, fake_reassembly, run_scan
):
    """``password_present``/``auth_username`` are the analyser's record of a login."""
    insert_session("smtp", {"auth_username": "alice", "password_present": True}, stream_id=9)
    calls = fake_reassembly(
        lambda stream_id: follow_stream_fixture(
            client="10.0.0.1:40000", server="10.0.0.2:25", client_lines=["PASS S3cretFtp"]
        )
    )
    rows, stats = run_scan(capture=Path(CAPTURE_FILE))
    assert calls == [9]
    assert stats["control_streams"] == 1
    assert _one(rows, kind="password", value="S3cretFtp")


def test_http_streams_are_never_reassembled(insert_http, insert_session, fake_reassembly,
                                            run_scan):
    """HTTP has its bodies stored, so §2b leaves its streams alone."""
    insert_http(stream_id=1,
                request_headers=json.dumps({"Authorization": f"Basic {b64('alice:Example123')}"}))
    _ftp_password_session(insert_session, stream_id=2)
    calls = fake_reassembly(
        lambda stream_id: follow_stream_fixture(
            client="10.0.0.1:40000", server="10.0.0.2:21", client_lines=["PASS S3cretFtp"]
        )
    )
    rows, _ = run_scan(capture=Path(CAPTURE_FILE))
    assert calls == [2], "the HTTP row's stream 1 must not be followed"
    assert _one(rows, kind="password", value="Example123")
    assert _one(rows, kind="password", value="S3cretFtp")


def test_a_protocol_outside_the_selection_is_not_reassembled(
    insert_session, fake_reassembly, run_scan
):
    _ftp_password_session(insert_session)
    calls = fake_reassembly(
        lambda stream_id: follow_stream_fixture(
            client="10.0.0.1:40000", server="10.0.0.2:21", client_lines=["PASS S3cretFtp"]
        )
    )
    rows, _ = run_scan(protocols=["http"], capture=Path(CAPTURE_FILE))
    assert calls == []
    assert rows == []


def test_no_value_is_written_into_protocol_sessions_detail(
    analyser_sessions, control_captures, run_scan
):
    """§10: ``credentials`` is the only table that holds a value."""
    analyser_sessions("ftp")
    before = {
        row["id"]: row["detail"]
        for row in db.query_all(
            "SELECT id, detail FROM protocol_sessions WHERE analysis_id = ?", (ANALYSIS_ID,)
        )
    }

    rows, _ = run_scan(capture=control_captures["ftp"])
    assert _find(rows, value="guest@example.com"), "the fixture must recover the password"

    after = {
        row["id"]: row["detail"]
        for row in db.query_all(
            "SELECT id, detail FROM protocol_sessions WHERE analysis_id = ?", (ANALYSIS_ID,)
        )
    }
    assert after == before, "the stage must not touch protocol_sessions"
    for detail in after.values():
        assert "guest@example.com" not in detail
        assert "password_present" in detail or "commands" in detail

    # And the value it did store is the redacted-by-default one every other row is.
    stored = db.query_all("SELECT * FROM credentials WHERE analysis_id = ?", (ANALYSIS_ID,))
    assert any(row["value"] == "guest@example.com" for row in stored)
    assert all(row["value_preview"] != row["value"] for row in stored)


# --------------------------------------------------------------------------
# the caps of §9
# --------------------------------------------------------------------------

def test_the_control_stream_cap_is_honoured(insert_session, fake_reassembly, run_scan):
    for index in range(30):
        _ftp_password_session(insert_session, stream_id=500 + index)
    calls = fake_reassembly(
        lambda stream_id: follow_stream_fixture(
            client="10.0.0.1:40000",
            server="10.0.0.2:21",
            client_lines=[f"PASS value-{stream_id}"],
        )
    )
    rows, stats = run_scan(capture=Path(CAPTURE_FILE))

    assert ca.MAX_CONTROL_STREAMS == 25
    assert len(calls) == 25
    assert calls == sorted(calls), "lowest stream id first"
    assert calls == [500 + index for index in range(25)]
    assert stats["control_streams"] == 25
    assert _find(rows, value="value-500") and _find(rows, value="value-524")
    assert _find(rows, value="value-525") == []
    assert any("MAX_CONTROL_STREAMS" in warning for warning in stats["warnings"])


def test_the_stream_character_cap_is_honoured(insert_session, fake_reassembly, run_scan):
    _ftp_password_session(insert_session)
    filler = "220 " + "x" * (ca.MAX_STREAM_CHARS + 10)
    fake_reassembly(
        lambda stream_id: follow_stream_fixture(
            client="10.0.0.1:40000",
            server="10.0.0.2:21",
            client_lines=[filler, "PASS BeyondTheCap1"],
        )
    )
    rows, stats = run_scan(capture=Path(CAPTURE_FILE))
    assert _find(rows, value="BeyondTheCap1") == []
    assert any("MAX_STREAM_CHARS" in warning for warning in stats["warnings"])


def test_a_timeout_is_tolerated_and_the_http_half_still_completes(
    insert_http, insert_session, fake_reassembly, run_scan
):
    insert_http(request_headers=json.dumps({"Authorization": f"Basic {b64('alice:Example123')}"}))
    _ftp_password_session(insert_session)
    insert_session("smtp", {"auth_username": "bob", "password_present": True}, stream_id=4)
    fake_reassembly(
        lambda stream_id: tshark.TsharkTimeout("one stream took too long")
        if stream_id == 3
        else follow_stream_fixture(
            client="10.0.0.1:40000", server="10.0.0.2:25", client_lines=["PASS SmtpOnly123"]
        )
    )
    rows, stats = run_scan(capture=Path(CAPTURE_FILE))

    # The HTTP half is complete, the readable stream was read, the timeout was named.
    assert _one(rows, kind="password", value="Example123")
    assert _one(rows, kind="password", value="SmtpOnly123")
    assert stats["control_streams"] == 1
    assert any(
        "Stream 3 (ftp) was not read" in warning and "20s" in warning
        for warning in stats["warnings"]
    )


def test_a_failed_reassembly_is_tolerated_and_the_http_half_still_completes(
    insert_http, insert_session, fake_reassembly, run_scan
):
    insert_http(request_headers=json.dumps({"Authorization": f"Basic {b64('alice:Example123')}"}))
    _ftp_password_session(insert_session)
    fake_reassembly(lambda stream_id: tshark.TsharkError("no such stream"))
    rows, stats = run_scan(capture=Path(CAPTURE_FILE))

    # The two HTTP findings and the identity the analyser stored are all present;
    # nothing was invented for the stream that could not be read.
    assert stats["findings"] == 3
    assert stats["control_streams"] == 0
    assert sorted(_values(rows)) == ["Example123", "alice", "carol"]
    assert any("TShark could not reassemble it" in warning for warning in stats["warnings"])


def test_the_control_channel_is_read_the_same_way_twice(insert_session, fake_reassembly,
                                                        run_scan):
    _ftp_password_session(insert_session)

    def handler(stream_id):
        return follow_stream_fixture(
            client="10.0.0.1:40000",
            server="10.0.0.2:21",
            client_lines=["USER carol", "PASS S3cretFtp"],
            server_lines=["331 Password required"],
        )

    fake_reassembly(handler)
    columns = [row["name"] for row in db.query_all("PRAGMA table_info(credentials)")]
    stable = [name for name in columns if name not in {"id", "created_at"}]

    first, _ = run_scan(capture=Path(CAPTURE_FILE))
    second, _ = run_scan(capture=Path(CAPTURE_FILE))

    def shape(rows):
        return [tuple(row[name] for name in stable) for row in rows]

    assert shape(first) == shape(second)
    assert sorted(_values(first)) == ["S3cretFtp", "carol"]


def test_protocols_scanned_reports_only_what_had_rows(client, analysis, insert_http,
                                                      insert_session, run_scan):
    analysis()
    insert_http(request_headers=json.dumps({"Authorization": f"Basic {b64('alice:Example123')}"}))
    insert_session("smtp", {"auth_username": "alice", "password_present": True}, stream_id=9)
    run_scan(capture=None)
    scan = client.get(f"/api/analyses/{ANALYSIS_ID}/credentials").json()["scan"]
    assert scan["protocols_scanned"] == ["http", "smtp"]
    assert scan["protocols"] == list(runtime_settings.CREDENTIAL_PROTOCOLS)
    assert scan["control_streams"] == 0


# --------------------------------------------------------------------------
# the capture the contract was amended against
# --------------------------------------------------------------------------

REAL_LAB09 = (
    Path(__file__).resolve().parents[2] / "data" / "uploads" / "9e2ef6a921304dc9ac0c739133682641.pcap"
)


@pytest.mark.skipif(
    not REAL_LAB09.is_file(), reason="the lab-09 capture is not present on this machine"
)
def test_the_lab_capture_yields_smtp_passwords_the_rows_do_not_hold(run_scan):
    """The real capture, where the row says ``password_present`` and the wire says the value.

    This is the case the contract's §2(b) exists for: seven SMTP sessions that
    authenticated with ``AUTH LOGIN``, whose stored detail holds the mechanism, the
    identity and the boolean - and no password. The scan reads the seven control
    channels and stores seven passwords, and every one of them is still absent from
    the row it was read next to.
    """
    protocol_analyzer.analyze(StubContext(), ANALYSIS_ID, REAL_LAB09)
    sessions = db.query_all(
        "SELECT * FROM protocol_sessions WHERE analysis_id = ? AND protocol = 'smtp'",
        (ANALYSIS_ID,),
    )
    assert sessions, "the lab capture holds SMTP sessions"
    for row in sessions:
        detail = json.loads(row["detail"])
        assert detail.get("password_present") is True
        assert detail.get("auth_username")

    rows, stats = run_scan(capture=REAL_LAB09)

    recovered = _find(rows, kind="password", protocol="smtp", method=ca.CONTROL_METHOD)
    assert len(recovered) == len(sessions) == stats["control_streams"]
    assert {row["confidence"] for row in recovered} == {"high"}
    assert {row["location"] for row in recovered} == {"smtp_auth_login"}

    stored = db.query_all(
        "SELECT detail FROM protocol_sessions WHERE analysis_id = ?", (ANALYSIS_ID,)
    )
    for row in recovered:
        assert row["value_preview"] != row["value"]
        assert all(row["value"] not in record["detail"] for record in stored)
