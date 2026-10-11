"""Shared FastAPI dependencies.

Owned by the core; every router uses these helpers so that analysis lookup,
readiness gating and pagination behave identically across the API.
"""

from __future__ import annotations

import math
import sqlite3
from dataclasses import dataclass
from pathlib import Path

from fastapi import Query

from app.core.errors import ApiError, bad_request, not_found
from app.db import database as db
from app.services import storage

MAX_PAGE_SIZE = 1000


@dataclass(frozen=True)
class Pagination:
    page: int
    page_size: int

    @property
    def offset(self) -> int:
        return (self.page - 1) * self.page_size

    @property
    def limit(self) -> int:
        return self.page_size

    def envelope(self, items: list, total: int) -> dict:
        return {
            "items": items,
            "total": total,
            "page": self.page,
            "page_size": self.page_size,
            "pages": max(1, math.ceil(total / self.page_size)) if total else 0,
        }


def pagination(
    page: int = Query(1, ge=1, description="1-based page number"),
    page_size: int = Query(100, ge=1, le=MAX_PAGE_SIZE, description="Rows per page"),
) -> Pagination:
    return Pagination(page=page, page_size=page_size)


def check_analysis_id(analysis_id: str) -> str:
    """Validate the id shape before it ever touches the filesystem."""
    return storage.validate_analysis_id(analysis_id)


def get_analysis(analysis_id: str) -> sqlite3.Row:
    """Fetch an analysis row or raise 404."""
    check_analysis_id(analysis_id)
    row = db.query_one("SELECT * FROM analyses WHERE id = ?", (analysis_id,))
    if row is None:
        raise not_found("analysis_not_found", f"No analysis with id {analysis_id}.")
    return row


def get_ready_analysis(analysis_id: str) -> sqlite3.Row:
    """Fetch an analysis that has finished processing, or raise 404/409."""
    row = get_analysis(analysis_id)
    status = row["status"]
    if status != "completed":
        raise ApiError(
            409,
            "analysis_not_ready",
            f"Analysis is '{status}'; data is available once processing completes.",
            {"status": status, "stage": row["stage"], "progress": row["progress"]},
        )
    return row


def capture_path(row: sqlite3.Row) -> Path:
    """Absolute path of the retained capture for an analysis row."""
    path = Path(row["stored_path"])
    if not path.is_file():
        raise ApiError(
            410,
            "capture_missing",
            "The stored capture file is no longer available; re-upload the file.",
            {"path": str(path)},
        )
    return path


def analysis_ready_row(analysis_id: str) -> sqlite3.Row:
    """Convenience for routes: ready analysis plus a guaranteed capture."""
    row = get_ready_analysis(analysis_id)
    capture_path(row)
    return row


def resolve_sort(sort: str | None, allowed: dict[str, str], default: str) -> str:
    """Map a client-supplied sort key onto an allow-listed SQL expression.

    Never interpolate the raw value: only values present in ``allowed`` are used.
    """
    if not sort:
        return default
    key = sort.strip()
    if key.startswith("-"):
        key = key[1:]
    if key not in allowed:
        raise bad_request(
            "invalid_sort",
            f"Cannot sort by '{sort}'.",
            {"allowed": sorted(allowed)},
        )
    return allowed[key]


def resolve_order(order: str | None, default: str = "desc") -> str:
    value = (order or default).strip().lower()
    if value not in {"asc", "desc"}:
        raise bad_request("invalid_order", "Order must be 'asc' or 'desc'.", {"order": order})
    return value.upper()


def json_or(raw: str | None, fallback: object) -> object:
    """Parse a JSON text column defensively; capture data may be malformed."""
    import json

    if raw is None or raw == "":
        return fallback
    try:
        return json.loads(raw)
    except (json.JSONDecodeError, TypeError):
        return fallback
