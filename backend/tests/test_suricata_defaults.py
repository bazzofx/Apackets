"""Rule defaults: marking a rule that is not at its default, and restoring it.

Two rule families live in this application and both need the same two answers: *is
this rule still what shipped?* and *can I put it back?*. For the imported Suricata
rules "what shipped" is the vendored .rules tree, so restoring re-reads that file;
a rule that was uploaded or hand-written has no such file, and the API says so
instead of inventing a default.
"""

from __future__ import annotations

import json
import time

import pytest

from app.db import database as db
from app.services import suricata_rules as sr


@pytest.fixture()
def seeded(fresh_db):  # noqa: ARG001 - fresh_db empties suricata_rules first
    """The vendored rule set, imported the way the seed route imports it."""
    result = sr.seed_bundled_rules()
    assert result["files"] > 0
    return result


def _rule(client, sid: int) -> dict:
    response = client.get(f"/api/suricata/rules/{sid}")
    assert response.status_code == 200, response.text
    return response.json()


def test_a_seeded_rule_is_at_its_default(client, seeded) -> None:  # noqa: ARG001
    rule = _rule(client, 50200005)
    assert rule["modified"] is False
    assert rule["restorable"] is True
    assert rule["differs"] == []
    assert client.get("/api/suricata/rules/stats").json()["modified"] == 0


def test_editing_a_rule_marks_it_modified_and_restore_puts_it_back(client, seeded) -> None:  # noqa: ARG001
    original = _rule(client, 50200005)
    edited_text = original["raw"].replace("Attempt to access /proc*", "Attempt to access /proc* (edited)")
    client.put("/api/suricata/rules/50200005", json={"raw": edited_text})

    edited = _rule(client, 50200005)
    assert edited["modified"] is True
    assert "text" in edited["differs"]
    assert client.get("/api/suricata/rules/stats").json()["modified"] == 1

    restored = client.post("/api/suricata/rules/50200005/restore")
    assert restored.status_code == 200, restored.text
    body = restored.json()
    assert body["modified"] is False
    assert body["differs"] == []
    assert body["raw"] == original["raw"]
    assert body["msg"] == original["msg"]
    assert client.get("/api/suricata/rules/stats").json()["modified"] == 0


def test_a_disabled_rule_is_modified_and_restore_reenables_it(client, seeded) -> None:  # noqa: ARG001
    client.put("/api/suricata/rules/22014001", json={"enabled": False})
    off = _rule(client, 22014001)
    assert off["modified"] is True
    assert off["differs"] == ["disabled"]

    back = client.post("/api/suricata/rules/22014001/restore").json()
    assert back["enabled"] is True
    assert back["modified"] is False


def test_a_rule_from_a_newer_revision_is_modified(client, seeded) -> None:  # noqa: ARG001
    rule = _rule(client, 50200003)
    bumped = rule["raw"].replace("rev:2;", "rev:9;")
    assert bumped != rule["raw"]
    client.put("/api/suricata/rules/50200003", json={"raw": bumped})
    # Changing the rev changes the text too, so both are reported.
    assert "revision" in _rule(client, 50200003)["differs"]


def test_an_uploaded_rule_has_no_default_to_restore(client, seeded) -> None:  # noqa: ARG001
    created = client.post(
        "/api/suricata/rules",
        json={"raw": 'alert tcp any any -> any any (msg:"hand written"; content:"abc"; sid:9900200; rev:1;)'},
    )
    assert created.status_code == 201, created.text
    rule = created.json()
    # It is at *its* state and there is nothing to go back to.
    assert rule["modified"] is False
    assert rule["restorable"] is False

    response = client.post("/api/suricata/rules/9900200/restore")
    assert response.status_code == 404
    assert response.json()["error"]["code"] == "no_bundled_default"


def test_restoring_an_unknown_sid_is_404(client, seeded) -> None:  # noqa: ARG001
    response = client.post("/api/suricata/rules/12345678/restore")
    assert response.status_code == 404
    assert response.json()["error"]["code"] == "rule_not_found"


def test_restore_of_a_local_layer_rule_returns_the_local_override(client, seeded) -> None:  # noqa: ARG001
    """The 17 locally corrected rules restore to backend/rules/local/, not upstream.

    This is the point of writing corrections as same-SID overrides: "the default"
    for sid 50200005 is the corrected rule, so restoring must not resurrect the
    boundary-less pattern the audit replaced.
    """
    original = _rule(client, 50200005)
    client.put("/api/suricata/rules/50200005", json={"enabled": False})
    restored = client.post("/api/suricata/rules/50200005/restore").json()
    assert restored["raw"] == original["raw"]
    assert restored["source"] == "bundled:local"
    assert "(?![\\w.~-])" in restored["raw"]


def test_the_rule_list_carries_the_same_flags(client, seeded) -> None:  # noqa: ARG001
    client.put("/api/suricata/rules/50200005", json={"enabled": False})
    listed = client.get("/api/suricata/rules?search=50200005&page_size=10").json()["items"]
    by_sid = {item["sid"]: item for item in listed}
    assert by_sid[50200005]["modified"] is True
    assert by_sid[50200005]["restorable"] is True
