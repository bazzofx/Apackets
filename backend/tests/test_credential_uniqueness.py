"""The unique view: one row per distinct value, not one per occurrence.

`docs/CREDENTIALS.md` §8.1 serves one row per distinct `(kind, value)` by default,
because a credential is the value and the streams are where it was seen. The lab
capture this feature was built against authenticates seven times with one username
and one password, and seven identical rows is not seven credentials.

These tests insert rows directly, so they say nothing about how a value was found —
only about how the stored occurrences are presented. They live in their own module
because the feature's other tests are a large file with its own fixtures, and a
presentation change is easier to read on its own.
"""

from __future__ import annotations

import json
import time

import pytest

from app.core.config import settings
from app.db import database as db

ANALYSIS_ID = "a1b2c3d4e5f60718293a4b5c6d7e8f90"


@pytest.fixture()
def analysis(fresh_db):  # noqa: ARG001 - fresh_db empties the tables first
    """A completed analysis whose retained capture exists, for the route gate."""

    def _make(*, analysis_id: str = ANALYSIS_ID, status: str = "completed") -> str:
        now = time.time()
        path = settings.uploads_dir / f"{analysis_id}.pcap"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b"\xd4\xc3\xb2\xa1fixture-not-a-real-capture")
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
        return analysis_id

    return _make


@pytest.fixture()
def credential(fresh_db):  # noqa: ARG001
    """Insert one stored occurrence and return its id."""

    def _insert(
        *,
        analysis_id: str = ANALYSIS_ID,
        kind: str = "username",
        value: str = "alice",
        protocol: str = "smtp",
        stream_id: int = 16,
        location: str = "smtp_auth_login",
        method: str = "auth_mechanism",
        confidence: str = "high",
        packet_first: int = 100,
        packet_last: int = 100,
        created_at: float | None = None,
    ) -> int:
        preview = value if len(value) <= 5 else f"{value[:3]}\u2022\u2022\u2022{value[-2:]}"
        with db.get_conn() as conn:
            cursor = conn.execute(
                """
                INSERT INTO credentials (
                    analysis_id, kind, value, value_preview, value_length, value_truncated,
                    protocol, transport, stream_id, direction, location, source_field, method,
                    confidence, client_ip, client_port, server_ip, server_port,
                    packet_first, packet_last, evidence, note, created_at
                ) VALUES (?, ?, ?, ?, ?, 0, ?, 'tcp', ?, 'client_to_server', ?, 'AUTH', ?, ?,
                          '10.4.10.132', 49206, '23.229.162.69', 587, ?, ?, ?, NULL, ?)
                """,
                (
                    analysis_id, kind, value, preview, len(value), protocol, stream_id,
                    location, method, confidence, packet_first, packet_last,
                    f"{protocol.upper()} {location} {preview}", created_at or time.time(),
                ),
            )
            return int(cursor.lastrowid or 0)

    return _insert


def _listing(client, analysis_id: str, query: str = "") -> dict:
    response = client.get(f"/api/analyses/{analysis_id}/credentials{query}")
    assert response.status_code == 200, response.text
    return response.json()


# --------------------------------------------------------------------------
# one row per value
# --------------------------------------------------------------------------

def test_seven_occurrences_of_one_credential_are_one_row(client, analysis, credential):
    """The lab capture's shape: the same username and password in seven streams."""
    analysis_id = analysis()
    for stream in (16, 21, 24, 27, 29, 35, 37):
        credential(analysis_id=analysis_id, kind="username", value="sales.del@test.invalid",
                   stream_id=stream, location="smtp_auth_login")
        credential(analysis_id=analysis_id, kind="password", value="Sales@23",
                   stream_id=stream, location="smtp_auth_login")

    body = _listing(client, analysis_id)
    assert body["total"] == 2, "one username and one password, not fourteen rows"
    assert body["unique"] is True
    assert {item["kind"] for item in body["items"]} == {"username", "password"}
    assert all(item["occurrences"] == 7 for item in body["items"]), body["items"]
    assert all(item["stream_ids"] == [16, 21, 24, 27, 29, 35, 37] for item in body["items"])
    assert body["counts"]["total"] == 2
    assert body["counts"]["by_kind"]["username"] == 1
    assert body["counts"]["by_kind"]["password"] == 1
    assert body["counts"]["occurrences"] == 14, "the fourteen stored rows are still reported"


def test_the_same_value_under_two_kinds_is_two_credentials(client, analysis, credential):
    """A value is a credential in its role: `admin` as a username and as a password differ."""
    analysis_id = analysis()
    credential(analysis_id=analysis_id, kind="username", value="admin")
    credential(analysis_id=analysis_id, kind="password", value="admin")
    body = _listing(client, analysis_id)
    assert body["total"] == 2
    assert {item["kind"] for item in body["items"]} == {"username", "password"}


def test_unique_zero_shows_every_occurrence(client, analysis, credential):
    analysis_id = analysis()
    for stream in (16, 21, 24):
        credential(analysis_id=analysis_id, stream_id=stream, value="alice")
    body = _listing(client, analysis_id, "?unique=0")
    assert body["unique"] is False
    assert body["total"] == 3
    assert all("occurrences" not in item for item in body["items"]), "the occurrence view lists rows"
    assert sorted(item["stream_id"] for item in body["items"]) == [16, 21, 24]
    # §8.1's default is `order=desc`, so the occurrence view is newest-first; asking
    # for `asc` is what returns the three in the order they happened.
    ascending = _listing(client, analysis_id, "?unique=0&order=asc")
    assert [item["stream_id"] for item in ascending["items"]] == [16, 21, 24]


def test_the_row_shown_is_the_earliest_occurrence(client, analysis, credential):
    """The value, preview and method shown belong to a real row, not to a mixture."""
    analysis_id = analysis()
    first = credential(analysis_id=analysis_id, value="alice", stream_id=16,
                       location="smtp_auth_login", method="auth_mechanism", packet_first=100)
    credential(analysis_id=analysis_id, value="alice", stream_id=21,
               location="smtp_auth_username", method="command_arg", packet_first=900)

    item = _listing(client, analysis_id)["items"][0]
    assert item["id"] == first
    assert item["stream_id"] == 16, "the row is the earliest occurrence"
    assert item["location"] == "smtp_auth_login"
    assert item["method"] == "auth_mechanism"
    assert item["packet_first"] == 100
    assert item["stream_ids"] == [16, 21]
    assert item["locations"] == ["smtp_auth_login", "smtp_auth_username"]
    assert item["occurrences"] == 2


def test_an_occurrence_spanning_protocols_names_both(client, analysis, credential):
    analysis_id = analysis()
    credential(analysis_id=analysis_id, value="shared", protocol="smtp", stream_id=4)
    credential(analysis_id=analysis_id, value="shared", protocol="ftp", stream_id=9)
    item = _listing(client, analysis_id)["items"][0]
    assert item["protocols"] == ["ftp", "smtp"], "both protocols are reported, in a stable order"
    assert item["occurrences"] == 2
    assert item["protocol"] in {"ftp", "smtp"}, "the representative row still names one"


def test_a_value_seen_once_reports_one_occurrence(client, analysis, credential):
    analysis_id = analysis()
    credential(analysis_id=analysis_id, value="once")
    item = _listing(client, analysis_id)["items"][0]
    assert item["occurrences"] == 1
    assert item["stream_ids"] == [16]


# --------------------------------------------------------------------------
# filters, sorting and paging over groups
# --------------------------------------------------------------------------

def test_a_filter_still_selects_the_rows_before_grouping(client, analysis, credential):
    """`kind=password` groups only the passwords, and its counts describe that selection."""
    analysis_id = analysis()
    credential(analysis_id=analysis_id, kind="username", value="alice")
    credential(analysis_id=analysis_id, kind="password", value="secret")
    credential(analysis_id=analysis_id, kind="password", value="secret", stream_id=21)
    body = _listing(client, analysis_id, "?kind=password")
    assert body["total"] == 1
    assert body["items"][0]["value_preview"].startswith("sec")
    assert body["items"][0]["occurrences"] == 2
    assert body["counts"]["by_kind"]["password"] == 1
    assert body["counts"]["by_kind"]["username"] == 0


def test_the_stream_filter_narrows_to_that_stream(client, analysis, credential):
    analysis_id = analysis()
    credential(analysis_id=analysis_id, value="alice", stream_id=16)
    credential(analysis_id=analysis_id, value="alice", stream_id=21)
    body = _listing(client, analysis_id, "?stream_id=21")
    assert body["total"] == 1
    assert body["items"][0]["stream_id"] == 21
    assert body["items"][0]["occurrences"] == 1


def test_paging_counts_groups_not_occurrences(client, analysis, credential):
    analysis_id = analysis()
    for index in range(5):
        credential(analysis_id=analysis_id, value=f"user{index}", stream_id=index + 1)
    first = _listing(client, analysis_id, "?page=1&page_size=2")
    second = _listing(client, analysis_id, "?page=2&page_size=2")
    assert first["total"] == 5 and second["total"] == 5
    assert len(first["items"]) == 2 and len(second["items"]) == 2
    assert not {item["value_preview"] for item in first["items"]} & {
        item["value_preview"] for item in second["items"]
    }, "pages do not repeat a group"


def test_sorting_by_confidence_orders_the_groups(client, analysis, credential):
    analysis_id = analysis()
    credential(analysis_id=analysis_id, value="lowone", confidence="low")
    credential(analysis_id=analysis_id, value="highone", confidence="high")
    credential(analysis_id=analysis_id, value="midone", confidence="medium")
    ordered = [item["confidence"] for item in _listing(client, analysis_id, "?sort=confidence")["items"]]
    assert ordered == ["high", "medium", "low"], ordered
    ascending = [
        item["confidence"]
        for item in _listing(client, analysis_id, "?sort=confidence&order=asc")["items"]
    ]
    assert ascending == ["low", "medium", "high"], ascending


def test_a_group_whose_occurrences_differ_takes_the_highest_for_ordering(client, analysis, credential):
    """A group is ordered by its best evidence, and still shows its earliest row."""
    analysis_id = analysis()
    credential(analysis_id=analysis_id, value="mixed", confidence="low", stream_id=16)
    credential(analysis_id=analysis_id, value="mixed", confidence="high", stream_id=17)
    credential(analysis_id=analysis_id, value="other", confidence="medium", stream_id=18)
    items = _listing(client, analysis_id, "?sort=confidence")["items"]
    assert [item["value_preview"][:3] for item in items] == ["mix", "oth"], items
    assert items[0]["confidence"] == "low", "the row shown is still the earliest occurrence"


# --------------------------------------------------------------------------
# the summary agrees with the listing
# --------------------------------------------------------------------------

def test_the_summary_counts_distinct_values_and_reports_occurrences(
    client, analysis, credential
):
    analysis_id = analysis()
    for stream in (16, 21, 24):
        credential(analysis_id=analysis_id, kind="username", value="sales.del@test.invalid",
                   stream_id=stream)
        credential(analysis_id=analysis_id, kind="password", value="Sales@23", stream_id=stream)
    response = client.get(f"/api/analyses/{analysis_id}/credentials/summary")
    assert response.status_code == 200, response.text
    summary = response.json()
    assert summary["total"] == 2, "the tiles count credentials, not rows"
    assert summary["occurrences"] == 6, "and the six stored rows are still reported"
    assert summary["by_kind"]["username"] == 1
    assert summary["by_kind"]["password"] == 1
    assert summary["by_confidence"]["high"] == 2
    assert summary["stream_count"] == 3, "three streams carried them"
    assert all(group["findings"] == 2 for group in summary["streams"]), summary["streams"]


def test_the_summary_carries_no_value_anywhere(client, analysis, credential):
    analysis_id = analysis()
    credential(analysis_id=analysis_id, value="Sales@23", kind="password")
    summary = client.get(f"/api/analyses/{analysis_id}/credentials/summary").json()

    leaks: list[str] = []

    def walk(node, path="$"):
        if isinstance(node, dict):
            for key, value in node.items():
                if key == "value":
                    leaks.append(path)
                walk(value, f"{path}.{key}")
        elif isinstance(node, list):
            for index, value in enumerate(node):
                walk(value, f"{path}[{index}]")

    walk(summary)
    assert leaks == [], leaks
    assert "Sales@23" not in json.dumps(summary)


# --------------------------------------------------------------------------
# redaction still governs the grouped view
# --------------------------------------------------------------------------

def test_a_grouped_row_is_redacted_unless_reveal_is_asked_for(client, analysis, credential):
    analysis_id = analysis()
    credential(analysis_id=analysis_id, value="Sales@23", kind="password", stream_id=16)
    credential(analysis_id=analysis_id, value="Sales@23", kind="password", stream_id=21)

    plain = _listing(client, analysis_id)
    assert "Sales@23" not in json.dumps(plain), "the grouped view redacts like the flat one"
    assert plain["items"][0]["value_preview"] != "Sales@23"

    revealed = _listing(client, analysis_id, "?reveal=1")
    assert revealed["items"][0]["value"] == "Sales@23"
    assert revealed["items"][0]["occurrences"] == 2


def test_the_scan_block_travels_with_the_grouped_view(client, analysis):
    analysis_id = analysis()
    body = _listing(client, analysis_id)
    assert body["total"] == 0
    assert "scan" in body and body["scan"]["enabled"] in {True, False}
    assert body["capped"] in {True, False}
