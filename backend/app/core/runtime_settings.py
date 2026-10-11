"""Runtime-overridable settings.

Static configuration lives in :mod:`app.core.config` and comes from the
environment. A small documented set of values is also editable from the UI and
persisted in the ``settings`` table; both the API and the processing pipeline
read them through this module so a change takes effect without a restart.
"""

from __future__ import annotations

import json
import time

from app.core.config import settings
from app.core.logging import get_logger
from app.db import database as db

log = get_logger("apackets.runtime_settings")

OVERRIDES_KEY = "app_settings"

# key -> (python type, minimum, maximum)
INT_BOUNDS: dict[str, tuple[int, int]] = {
    "max_upload_mb": (1, 10240),
    "max_object_bytes": (1024, 2 * 1024 * 1024 * 1024),
    "body_preview_bytes": (1024, 8 * 1024 * 1024),
    "tshark_timeout_s": (10, 7200),
}

_cache: dict | None = None


def load_overrides(*, use_cache: bool = True) -> dict:
    global _cache
    if use_cache and _cache is not None:
        return dict(_cache)

    try:
        row = db.query_one("SELECT value FROM settings WHERE key = ?", (OVERRIDES_KEY,))
    except Exception:  # noqa: BLE001 - the DB may not exist yet
        return {}

    values: dict = {}
    if row is not None:
        try:
            parsed = json.loads(row["value"])
            if isinstance(parsed, dict):
                values = parsed
        except (json.JSONDecodeError, TypeError):
            log.warning("ignoring malformed settings overrides")

    _cache = values
    return dict(values)


def save_overrides(values: dict) -> None:
    global _cache
    with db.get_conn() as conn:
        conn.execute(
            "INSERT OR REPLACE INTO settings (key, value, updated_at) VALUES (?, ?, ?)",
            (OVERRIDES_KEY, json.dumps(values), time.time()),
        )
    _cache = dict(values)


def clear_cache() -> None:
    """Testing hook."""
    global _cache
    _cache = None


def _int_value(key: str, default: int) -> int:
    overrides = load_overrides()
    raw = overrides.get(key, default)
    try:
        value = int(raw)
    except (TypeError, ValueError):
        return default
    low, high = INT_BOUNDS.get(key, (0, 2**63))
    return max(low, min(high, value))


def max_upload_mb() -> int:
    return _int_value("max_upload_mb", settings.max_upload_mb)


def max_upload_bytes() -> int:
    return max_upload_mb() * 1024 * 1024


def max_object_bytes() -> int:
    return _int_value("max_object_bytes", settings.max_object_bytes)


def body_preview_bytes() -> int:
    return _int_value("body_preview_bytes", settings.body_preview_bytes)


def tshark_timeout_s() -> int:
    return _int_value("tshark_timeout_s", settings.tshark_timeout_s)


def retain_uploads() -> bool:
    overrides = load_overrides()
    value = overrides.get("retain_uploads", settings.retain_uploads)
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in {"1", "true", "yes", "on"}


def effective() -> dict:
    """The full effective settings view shown on the Settings page."""
    return {
        "data_dir": str(settings.data_dir),
        "uploads_dir": str(settings.uploads_dir),
        "analyses_dir": str(settings.analyses_dir),
        "db_path": str(settings.db_path),
        "max_upload_mb": max_upload_mb(),
        "max_object_bytes": max_object_bytes(),
        "body_preview_bytes": body_preview_bytes(),
        "tshark_timeout_s": tshark_timeout_s(),
        "retain_uploads": retain_uploads(),
        "allowed_extensions": list(settings.allowed_extensions),
        "host": settings.host,
        "port": settings.port,
        "worker_threads": settings.worker_threads,
        "max_export_rows": settings.max_export_rows,
    }
