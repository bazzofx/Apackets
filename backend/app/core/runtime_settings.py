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

log = get_logger("shadowpackets.runtime_settings")

OVERRIDES_KEY = "app_settings"

#: The credential scanner's own settings row (docs/CREDENTIALS.md §7). It is a
#: second key rather than part of ``app_settings`` because turning the scan off
#: must not be able to disturb the values stored beside it, and because the
#: detection configuration already set the precedent of one documented key per
#: feature area.
CREDENTIAL_CONFIG_KEY = "credential_config"

#: The protocols this build can read credentials from. The scanner reads the rows
#: the HTTP and protocol analysers wrote, so this list is the contract's §1 scope
#: and nothing wider: an empty selection means "scan nothing", never "no
#: restriction".
CREDENTIAL_PROTOCOLS: tuple[str, ...] = ("http", "ftp", "smtp", "pop3", "imap")

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


# --------------------------------------------------------------------------
# credential scanner (docs/CREDENTIALS.md §7)
# --------------------------------------------------------------------------

def default_credential_config() -> dict:
    """The documented defaults: scanning on, every readable protocol selected."""
    return {
        "credential_scan_enabled": True,
        "credential_protocols": list(CREDENTIAL_PROTOCOLS),
    }


def _as_bool(value: object, default: bool) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() in {"1", "true", "yes", "on"}
    return default


def _as_protocols(value: object) -> list[str]:
    """The stored list reduced to known protocols, in the contract's own order.

    An unknown name is dropped with a warning rather than kept: the scanner can
    only read the protocols it has code for, and silently ignoring the name at
    scan time would make the setting's echo on the Settings page a lie.
    """
    if not isinstance(value, list):
        if value is not None:
            log.warning("credential_config.credential_protocols must be a list; using defaults")
        return list(CREDENTIAL_PROTOCOLS)
    known = {name.strip().lower() for name in value if isinstance(name, str)}
    for name in sorted(known - set(CREDENTIAL_PROTOCOLS)):
        log.warning("ignoring unknown credential protocol %r", name)
    return [name for name in CREDENTIAL_PROTOCOLS if name in known]


def load_credential_config() -> dict:
    """The documented defaults merged with the ``credential_config`` row.

    Reading is defensive on purpose: a malformed row (a hand-edited database, an
    older build) falls back to the defaults with a warning instead of failing a
    pipeline stage or a settings request.
    """
    defaults = default_credential_config()
    try:
        row = db.query_one("SELECT value FROM settings WHERE key = ?", (CREDENTIAL_CONFIG_KEY,))
    except Exception:  # noqa: BLE001 - the DB may not exist yet
        return defaults

    if row is None or not row["value"]:
        return defaults

    try:
        stored = json.loads(row["value"])
    except (json.JSONDecodeError, TypeError):
        log.warning("credential_config is not valid JSON; using defaults")
        return defaults
    if not isinstance(stored, dict):
        log.warning("credential_config must be a JSON object; using defaults")
        return defaults

    return {
        "credential_scan_enabled": _as_bool(
            stored.get("credential_scan_enabled"), defaults["credential_scan_enabled"]
        ),
        "credential_protocols": _as_protocols(stored.get("credential_protocols")),
    }


def save_credential_config(config: dict) -> dict:
    """Merge ``config`` over the currently effective values, persist, and return them.

    Merging over the *effective* configuration rather than over the defaults is
    what the detection configuration does: a partial update cannot silently reset
    the other key.
    """
    effective = load_credential_config()
    if isinstance(config, dict):
        if "credential_scan_enabled" in config:
            effective["credential_scan_enabled"] = _as_bool(
                config["credential_scan_enabled"], effective["credential_scan_enabled"]
            )
        if "credential_protocols" in config:
            effective["credential_protocols"] = _as_protocols(config["credential_protocols"])

    with db.get_conn() as conn:
        conn.execute(
            """
            INSERT INTO settings (key, value, updated_at) VALUES (?, ?, ?)
            ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at
            """,
            (CREDENTIAL_CONFIG_KEY, json.dumps(effective), time.time()),
        )
    log.info(
        "credential scan settings saved: enabled=%s, %d protocol(s)",
        effective["credential_scan_enabled"],
        len(effective["credential_protocols"]),
    )
    return load_credential_config()


def credential_config() -> dict:
    """The credential settings as they are right now."""
    return load_credential_config()


def credential_scan_enabled() -> bool:
    return bool(load_credential_config()["credential_scan_enabled"])


def credential_protocols() -> list[str]:
    return list(load_credential_config()["credential_protocols"])


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
        "credential_scan_enabled": credential_scan_enabled(),
        "credential_protocols": credential_protocols(),
        "credential_protocols_available": list(CREDENTIAL_PROTOCOLS),
        "allowed_extensions": list(settings.allowed_extensions),
        "host": settings.host,
        "port": settings.port,
        "worker_threads": settings.worker_threads,
        "max_export_rows": settings.max_export_rows,
    }
