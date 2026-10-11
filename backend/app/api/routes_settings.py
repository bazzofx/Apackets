"""Application settings and analyst-supplied indicators.

Settings are stored in the ``settings`` table as JSON so they survive restarts
without a config-file rewrite. Only a documented allow-list of keys is mutable.
"""

from __future__ import annotations

import time

from fastapi import APIRouter

from app import __version__
from app.core import runtime_settings
from app.core.config import settings
from app.core.errors import bad_request, not_found
from app.core.logging import get_logger
from app.db import database as db
from app.schemas import IndicatorCreate, SettingsUpdate
from app.services import tshark

log = get_logger("apackets.api.settings")

router = APIRouter(prefix="/api", tags=["settings"])

INDICATOR_TYPES = {"ip", "domain", "port", "ja3", "ja4", "ua", "sha256"}


def effective_settings() -> dict:
    body = runtime_settings.effective()
    body.update(
        {
            "version": __version__,
            "tshark": tshark.version(),
            "local_only": settings.host in {"127.0.0.1", "localhost", "::1"},
            "telemetry": False,
        }
    )
    return body


@router.get("/settings")
def get_settings_endpoint() -> dict:
    return effective_settings()


@router.put("/settings")
def update_settings(body: SettingsUpdate) -> dict:
    overrides = runtime_settings.load_overrides()
    changed: list[str] = []

    for key, (low, high) in runtime_settings.INT_BOUNDS.items():
        value = getattr(body, key, None)
        if value is None:
            continue
        if not isinstance(value, int) or isinstance(value, bool):
            raise bad_request("invalid_setting", f"{key} must be an integer.")
        if not (low <= value <= high):
            raise bad_request(
                "invalid_setting",
                f"{key} must be between {low} and {high}.",
                {"key": key, "value": value},
            )
        overrides[key] = int(value)
        changed.append(key)

    if body.retain_uploads is not None:
        overrides["retain_uploads"] = bool(body.retain_uploads)
        changed.append("retain_uploads")

    if not changed:
        raise bad_request(
            "no_changes",
            "No mutable settings were supplied.",
            {"mutable": sorted([*runtime_settings.INT_BOUNDS, "retain_uploads"])},
        )

    runtime_settings.save_overrides(overrides)
    log.info("settings updated: %s", ", ".join(changed))
    return {"ok": True, "changed": changed, "settings": effective_settings()}


# --------------------------------------------------------------------------
# indicators (input for detection rule 10)
# --------------------------------------------------------------------------

@router.get("/indicators")
def list_indicators(analysis_id: str | None = None) -> dict:
    if analysis_id:
        rows = db.query_all(
            """
            SELECT * FROM indicators WHERE analysis_id = ? OR analysis_id IS NULL
             ORDER BY created_at DESC
            """,
            (analysis_id,),
        )
    else:
        rows = db.query_all("SELECT * FROM indicators ORDER BY created_at DESC")
    return {"items": [dict(r) for r in rows]}


@router.post("/indicators", status_code=201)
def create_indicator(body: IndicatorCreate) -> dict:
    indicator_type = body.type.strip().lower()
    if indicator_type not in INDICATOR_TYPES:
        raise bad_request(
            "invalid_indicator_type",
            f"Unsupported indicator type '{body.type}'.",
            {"allowed": sorted(INDICATOR_TYPES)},
        )
    value = body.value.strip()
    if not value:
        raise bad_request("invalid_indicator_value", "An indicator value is required.")

    if indicator_type == "port":
        try:
            port = int(value)
        except ValueError as exc:
            raise bad_request("invalid_indicator_value", "A port indicator must be numeric.") from exc
        if not (0 <= port <= 65535):
            raise bad_request("invalid_indicator_value", "Port must be between 0 and 65535.")

    now = time.time()
    with db.get_conn() as conn:
        cursor = conn.execute(
            """
            INSERT INTO indicators (analysis_id, type, value, note, created_at)
            VALUES (?, ?, ?, ?, ?)
            """,
            (body.analysis_id, indicator_type, value, body.note, now),
        )
        new_id = cursor.lastrowid

    row = db.query_one("SELECT * FROM indicators WHERE id = ?", (new_id,))
    return dict(row) if row else {}


@router.delete("/indicators/{indicator_id}")
def delete_indicator(indicator_id: int) -> dict:
    row = db.query_one("SELECT id FROM indicators WHERE id = ?", (indicator_id,))
    if row is None:
        raise not_found("indicator_not_found", f"No indicator with id {indicator_id}.")
    with db.get_conn() as conn:
        conn.execute("DELETE FROM indicators WHERE id = ?", (indicator_id,))
    return {"ok": True, "id": indicator_id}
