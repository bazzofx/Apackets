"""TLS endpoints: session list, single session and fingerprint aggregation.

Only what TShark dissected or fingerprinted is served; nothing is inferred. TLS
payloads are never decrypted, so the certificate columns are NULL whenever the
handshake did not carry a readable certificate (TLS 1.3 encrypts it).
"""

from __future__ import annotations

import sqlite3
from typing import Any

from fastapi import APIRouter, Depends, Query

from app.core.errors import not_found
from app.core.logging import get_logger
from app.db import database as db
from app.api.routes_http import sort_expression, sort_order
from app.api.deps import (
    Pagination,
    analysis_ready_row,
    json_or,
    pagination,
)

log = get_logger("apackets.api.tls")

router = APIRouter(prefix="/api/analyses/{analysis_id}", tags=["tls"])

SORTABLE = {
    "time_epoch": "time_epoch",
    "sni": "sni",
    "version": "version",
    "server_port": "server_port",
    "cipher_suite": "cipher_suite",
    "stream_id": "stream_id",
}

DEFAULT_SORT = "time_epoch"

# Any of these being non-null means a certificate was actually decoded.
CERT_COLUMNS = (
    "cert_serial",
    "cert_subject",
    "cert_issuer",
    "cert_not_before",
    "cert_not_after",
)


def _serialise(row: sqlite3.Row) -> dict[str, Any]:
    """Row -> JSON-safe dict; JSON columns are parsed, NULL stays None."""
    data = dict(row)
    data["flags"] = json_or(data.get("flags"), [])
    return data


def _escapable(value: str) -> str:
    """Escape LIKE wildcards so a literal ``%`` does not widen a search."""
    return value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def _like(value: str) -> str:
    return f"%{_escapable(value.strip())}%"


@router.get("/tls")
def list_tls_sessions(
    analysis_id: str,
    page: Pagination = Depends(pagination),
    sni: str | None = Query(None, description="Substring match on the SNI"),
    version: str | None = Query(None, description="Exact version, e.g. 'TLS 1.2'"),
    ip: str | None = Query(None, description="Client or server IP"),
    port: str | None = Query(None, description="Client or server port"),
    alpn: str | None = Query(None, description="Substring match on the ALPN list"),
    ja3: str | None = Query(None, description="Exact JA3, JA3S or JA4 fingerprint"),
    has_cert: bool | None = Query(None, description="Only sessions with a certificate"),
    sort: str | None = Query(None),
    order: str | None = Query(None),
) -> dict:
    analysis_ready_row(analysis_id)

    where: list[str] = ["analysis_id = ?"]
    params: list[Any] = [analysis_id]

    if sni:
        where.append("sni LIKE ? ESCAPE '\\'")
        params.append(_like(sni))
    if version:
        where.append("version = ?")
        params.append(version.strip())
    if ip:
        where.append("(client_ip = ? OR server_ip = ?)")
        params.extend([ip.strip(), ip.strip()])
    if port:
        try:
            port_value = int(port, 0)
        except ValueError:
            where.append("0 = 1")  # not a port number: match nothing
        else:
            where.append("(client_port = ? OR server_port = ?)")
            params.extend([port_value, port_value])
    if alpn:
        where.append("alpn LIKE ? ESCAPE '\\'")
        params.append(_like(alpn))
    if ja3:
        where.append("(ja3 = ? OR ja3s = ? OR ja4 = ?)")
        value = ja3.strip()
        params.extend([value, value, value])
    if has_cert is not None:
        present = " OR ".join(f"{column} IS NOT NULL" for column in CERT_COLUMNS)
        where.append(f"({present})" if has_cert else f"NOT ({present})")

    clause = " AND ".join(where)
    total_row = db.query_one(f"SELECT COUNT(*) AS n FROM tls_sessions WHERE {clause}", params)
    total = int(total_row["n"]) if total_row else 0

    sort_sql = sort_expression(sort, SORTABLE, DEFAULT_SORT)
    order_sql = sort_order(order, "asc")
    rows = db.query_all(
        f"SELECT * FROM tls_sessions WHERE {clause} "
        f"ORDER BY {sort_sql} {order_sql}, id {order_sql} LIMIT ? OFFSET ?",
        [*params, page.limit, page.offset],
    )

    return {
        **page.envelope([_serialise(row) for row in rows], total),
        "snis": _distinct("sni", analysis_id),
        "versions": _distinct("version", analysis_id),
    }


@router.get("/tls/fingerprints")
def tls_fingerprints(
    analysis_id: str,
    fingerprint_type: str | None = Query(
        None, alias="type", description="ja3, ja3s or ja4"
    ),
) -> dict:
    """Fingerprint aggregation computed from the stored session rows."""
    analysis_ready_row(analysis_id)

    wanted = [
        ("ja3", "ja3"),
        ("ja3s", "ja3s"),
        ("ja4", "ja4"),
    ]
    if fingerprint_type:
        requested = fingerprint_type.strip().lower()
        wanted = [item for item in wanted if item[0] == requested]

    items: list[dict] = []
    for label, column in wanted:
        rows = db.query_all(
            f"""
            SELECT {column} AS fingerprint,
                   COUNT(*)                        AS sessions,
                   GROUP_CONCAT(DISTINCT sni)      AS snis,
                   GROUP_CONCAT(DISTINCT client_ip) AS clients
            FROM tls_sessions
            WHERE analysis_id = ? AND {column} IS NOT NULL AND {column} <> ''
            GROUP BY {column}
            ORDER BY sessions DESC, fingerprint ASC
            """,
            (analysis_id,),
        )
        for row in rows:
            items.append(
                {
                    "fingerprint": row["fingerprint"],
                    "type": label,
                    "sessions": int(row["sessions"]),
                    "snis": _split_joined(row["snis"]),
                    "clients": _split_joined(row["clients"]),
                }
            )

    items.sort(key=lambda item: (-item["sessions"], str(item["fingerprint"])))
    return {"items": items, "total": len(items)}


@router.get("/tls/{session_id}")
def tls_session_detail(analysis_id: str, session_id: int) -> dict:
    """One stored TLS session."""
    analysis_ready_row(analysis_id)
    row = db.query_one(
        "SELECT * FROM tls_sessions WHERE analysis_id = ? AND id = ?",
        (analysis_id, session_id),
    )
    if row is None:
        raise not_found("tls_session_not_found", f"No TLS session {session_id} in this analysis.")
    return _serialise(row)


def _split_joined(value: str | None) -> list[str]:
    if not value:
        return []
    out: list[str] = []
    for part in value.split(","):
        part = part.strip()
        if part and part not in out:
            out.append(part)
    return out


def _distinct(column: str, analysis_id: str) -> list[str]:
    """Distinct non-null values of a fixed column, for filter dropdowns."""
    if column not in {"sni", "version"}:
        raise ValueError("unexpected column")
    rows = db.query_all(
        f"SELECT DISTINCT {column} AS v FROM tls_sessions "
        f"WHERE analysis_id = ? AND {column} IS NOT NULL AND {column} <> '' ORDER BY v ASC",
        (analysis_id,),
    )
    return [row["v"] for row in rows]
