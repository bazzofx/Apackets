"""Application settings.

Every value is overridable through the environment with the ``SHADOWPACKETS_`` prefix
or through a ``.env`` file at the repository root (see ``.env.example``).
"""

from __future__ import annotations

import os
from functools import lru_cache
from pathlib import Path

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

# backend/app/core/config.py -> repository root
REPO_ROOT = Path(__file__).resolve().parents[3]

# The application was renamed, and its environment prefix with it. A deployment
# that still exports the old names is read once, here, so a rename cannot silently
# change a setting back to its default. Both the process environment and the
# dotenv file are honoured; the new name always wins when both are set.
_LEGACY_PREFIX = "APACKETS_"
_ENV_PREFIX = "SHADOWPACKETS_"


def _adopt_legacy_environment() -> None:
    """Copy old-prefixed settings to their new names, once, at import."""
    for name, value in list(os.environ.items()):
        if name.upper().startswith(_LEGACY_PREFIX):
            os.environ.setdefault(_ENV_PREFIX + name[len(_LEGACY_PREFIX) :], value)
    dotenv = REPO_ROOT / ".env"
    if not dotenv.exists():
        return
    try:
        lines = dotenv.read_text(encoding="utf-8").splitlines()
    except OSError:  # pragma: no cover - an unreadable dotenv is not fatal
        return
    for line in lines:
        entry = line.strip()
        if not entry or entry.startswith("#") or "=" not in entry:
            continue
        name, _, value = entry.partition("=")
        name = name.strip()
        if name.upper().startswith(_LEGACY_PREFIX):
            os.environ.setdefault(
                _ENV_PREFIX + name[len(_LEGACY_PREFIX) :],
                value.strip().strip('"').strip("'"),
            )


_adopt_legacy_environment()


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="SHADOWPACKETS_",
        env_file=str(REPO_ROOT / ".env"),
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=False,
    )

    # --- storage -----------------------------------------------------------
    data_dir: Path = Field(default=REPO_ROOT / "data")

    # --- uploads -----------------------------------------------------------
    max_upload_mb: int = 512
    allowed_extensions: list[str] = [".pcap", ".pcapng", ".cap"]

    # --- packet processing -------------------------------------------------
    tshark_path: str = "tshark"
    capinfos_path: str = "capinfos"
    # The Wireshark GUI, used only by the "Pivot to Wireshark" action: it opens
    # this capture, filtered, in a window on the operator's own desktop.
    wireshark_path: str = "wireshark"
    tshark_timeout_s: int = 300
    # 0 == index every packet
    max_packet_rows: int = 0
    worker_threads: int = 2

    # --- objects / previews ------------------------------------------------
    max_object_bytes: int = 50 * 1024 * 1024
    body_preview_bytes: int = 256 * 1024
    # hard cap on rows emitted by a single CSV export
    max_export_rows: int = 200_000

    # --- retention ---------------------------------------------------------
    retain_uploads: bool = True

    # --- detection ---------------------------------------------------------
    # Choosing a baseline rewrites the baseline findings of every analysis in the
    # background; the test suite switches that off so a sweep cannot write while a
    # test is asserting.
    baseline_auto_recalc: bool = True
    # Import the vendored Suricata rules on startup when the rule store is empty.
    # Existing rules are never overwritten; the test suite disables this so a
    # fresh database stays empty unless a test seeds it explicitly.
    suricata_auto_seed: bool = True

    # --- server ------------------------------------------------------------
    host: str = "127.0.0.1"
    port: int = 8000
    # The URL a browser should use for this deployment. Optional, because a
    # direct uvicorn run is reachable at host:port; Compose sets it to the
    # published host port so the startup log names the URL the operator opens.
    public_url: str | None = None
    cors_origins: list[str] = [
        "http://127.0.0.1:5173",
        "http://localhost:5173",
        "http://127.0.0.1:4173",
    ]
    log_level: str = "INFO"

    @field_validator("cors_origins", "allowed_extensions", mode="before")
    @classmethod
    def _split_csv(cls, value: object) -> object:
        """Allow ``SHADOWPACKETS_CORS_ORIGINS=a,b`` as well as JSON lists."""
        if isinstance(value, str):
            stripped = value.strip()
            if stripped.startswith("["):
                return value
            return [item.strip() for item in stripped.split(",") if item.strip()]
        return value

    @field_validator("data_dir", mode="after")
    @classmethod
    def _absolute(cls, value: Path) -> Path:
        return value if value.is_absolute() else (REPO_ROOT / value).resolve()

    # --- derived paths -----------------------------------------------------
    @property
    def uploads_dir(self) -> Path:
        return self.data_dir / "uploads"

    @property
    def analyses_dir(self) -> Path:
        return self.data_dir / "analyses"

    @property
    def exports_dir(self) -> Path:
        return self.data_dir / "exports"

    @property
    def geoip_dir(self) -> Path:
        """The DB-IP Lite dataset, created on the first successful refresh
        (``docs/GEOGRAPHY.md`` §4) - deliberately not part of ``ensure_dirs``."""
        return self.data_dir / "geoip"

    @property
    def db_path(self) -> Path:
        return self.data_dir / "shadowpackets.db"

    @property
    def max_upload_bytes(self) -> int:
        return self.max_upload_mb * 1024 * 1024

    def ensure_dirs(self) -> None:
        for path in (self.data_dir, self.uploads_dir, self.analyses_dir, self.exports_dir):
            path.mkdir(parents=True, exist_ok=True)


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
