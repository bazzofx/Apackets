"""Request payload models shared by the API routers."""

from __future__ import annotations

from pydantic import BaseModel, Field


class FilterRequest(BaseModel):
    """Body of ``POST /api/analyses/{id}/filter``."""

    filter: str = Field(default="", description="Wireshark display filter expression")
    page: int = Field(default=1, ge=1)
    page_size: int = Field(default=50, ge=1, le=1000)


class SettingsUpdate(BaseModel):
    """Body of ``PUT /api/settings``. Only these keys are mutable at runtime."""

    max_upload_mb: int | None = None
    max_object_bytes: int | None = None
    body_preview_bytes: int | None = None
    tshark_timeout_s: int | None = None
    retain_uploads: bool | None = None


class IndicatorCreate(BaseModel):
    """Body of ``POST /api/indicators`` — analyst-supplied detection input."""

    type: str = Field(..., description="One of: ip, domain, port, ja3, ja4, ua, sha256")
    value: str = Field(..., min_length=1, max_length=512)
    note: str | None = Field(default=None, max_length=512)
    analysis_id: str | None = None


class WiresharkRequest(BaseModel):
    """Body of ``POST /api/analyses/{id}/wireshark`` — the packet pivot.

    Structured on purpose: the client names an address and, at most, which of
    its conversations is meant. It never sends a display filter, so no request
    can reach the Wireshark command line as filter syntax.
    """

    ip: str = Field(..., min_length=1, max_length=64, description="The address to open on")
    transport: str | None = Field(default=None, max_length=16, description="e.g. tcp")
    stream_id: int | None = Field(default=None, ge=0, description="The conversation's stream id")
    port: int | None = Field(default=None, ge=0, le=65535, description="Used when no stream applies")
