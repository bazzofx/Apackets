"""Application settings.

Every value is overridable through the environment with the ``APACKETS_`` prefix
or through a ``.env`` file at the repository root (see ``.env.example``).
"""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

# backend/app/core/config.py -> repository root
REPO_ROOT = Path(__file__).resolve().parents[3]


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="APACKETS_",
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

    # --- server ------------------------------------------------------------
    host: str = "127.0.0.1"
    port: int = 8000
    cors_origins: list[str] = [
        "http://127.0.0.1:5173",
        "http://localhost:5173",
        "http://127.0.0.1:4173",
    ]
    log_level: str = "INFO"

    @field_validator("cors_origins", "allowed_extensions", mode="before")
    @classmethod
    def _split_csv(cls, value: object) -> object:
        """Allow ``APACKETS_CORS_ORIGINS=a,b`` as well as JSON lists."""
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
        return self.data_dir / "apackets.db"

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
