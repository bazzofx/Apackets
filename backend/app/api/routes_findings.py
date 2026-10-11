"""Findings API.

* ``GET  /api/analyses/{id}/findings``            — paginated findings + counts
* ``GET  /api/analyses/{id}/findings/rules``      — rule catalogue with hit counts
* ``GET  /api/analyses/{id}/findings/{finding_id}`` — one finding, JSON columns parsed
* ``POST /api/analyses/{id}/findings/rescan``     — re-run the detection engine

Ordering is deliberate rather than alphabetical: findings sort high → medium →
low → informational through an explicit ``CASE`` expression, because the string
ordering of those labels (``high`` < ``informational`` < ``low`` < ``medium``)
would put the least urgent rows first.
"""

from __future__ import annotations

from pathlib import Path

from fastapi import APIRouter, Depends, Query

from app.api import deps
from app.core.errors import ApiError, bad_request
from app.core.logging import get_logger
from app.db import database as db
from app.services import detection_engine

log = get_logger("apackets.api.findings")

router = APIRouter(prefix="/api/analyses", tags=["findings"])

# Severity is an ordered vocabulary, so the rank is spelled out explicitly.
_SEVERITY_RANK_SQL = (
    "CASE severity "
    "WHEN 'high' THEN 0 "
    "WHEN 'medium' THEN 1 "
    "WHEN 'low' THEN 2 "
    "WHEN 'informational' THEN 3 "
    "ELSE 4 END"
)

# Sort allow-list: client input only ever selects one of these expressions.
# The contract fixes this list at severity, rule_id and title.
_SORT_COLUMNS: dict[str, str] = {
    "severity": _SEVERITY_RANK_SQL,
    "rule_id": "rule_id",
    "title": "title",
}

_JSON_ARRAY_FIELDS = ("packet_numbers",)
_JSON_OBJECT_FIELDS = ("evidence", "entities")


def _escape_like(term: str) -> str:
    """Neutralise LIKE wildcards so a search term is matched literally."""
    return term.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def _order_clause(sort: str | None, order: str | None) -> str:
    """ORDER BY clause from allow-listed columns only.

    ``deps.resolve_sort`` / ``deps.resolve_order`` are the shared helpers, but on
    this revision they build their error with a positional details dict, which
    ``errors.bad_request(code, message, **details)`` cannot accept — so an
    invalid sort raises ``TypeError`` (HTTP 500) instead of the documented
    ``400 invalid_sort``. The narrow fallback below preserves the documented
    contract; it can be deleted once ``deps.py`` passes ``details`` by keyword.
    """
    if not sort:
        # Documented default: severity high -> informational, then rule id, then id.
        return f"{_SEVERITY_RANK_SQL} ASC, rule_id ASC, id ASC"
    try:
        column = deps.resolve_sort(sort, _SORT_COLUMNS, "rule_id")
        direction = deps.resolve_order(order, "asc")
    except ApiError:
        raise
    except TypeError:
        key = sort.strip().lstrip("-")
        if key not in _SORT_COLUMNS:
            raise bad_request(
                "invalid_sort",
                f"Cannot sort by '{sort}'.",
                allowed=sorted(_SORT_COLUMNS),
            ) from None
        value = (order or "asc").strip().lower()
        if value not in {"asc", "desc"}:
            raise bad_request(
                "invalid_order",
                "Order must be 'asc' or 'desc'.",
                order=order,
            ) from None
        column, direction = _SORT_COLUMNS[key], value.upper()
    return f"{column} {direction}, id ASC"


def _serialise(row) -> dict:
    """A finding row with its JSON text columns parsed into real structures."""
    data = dict(row)
    for field in _JSON_ARRAY_FIELDS:
        parsed = deps.json_or(data.get(field), [])
        data[field] = parsed if isinstance(parsed, list) else []
    for field in _JSON_OBJECT_FIELDS:
        parsed = deps.json_or(data.get(field), {})
        data[field] = parsed if isinstance(parsed, dict) else {}

    entities = data.get("entities") or {}
    data["entities"] = {
        "ips": list(entities.get("ips") or []),
        "hostnames": list(entities.get("hostnames") or []),
        "ports": list(entities.get("ports") or []),
        "uris": list(entities.get("uris") or []),
    }
    data["packet_numbers"] = sorted(
        {int(number) for number in data["packet_numbers"] if isinstance(number, (int, float))}
    )
    return data


def _counts(analysis_id: str) -> dict[str, int]:
    counts = {name: 0 for name in detection_engine.SEVERITIES}
    rows = db.query_all(
        "SELECT severity, COUNT(*) AS n FROM findings WHERE analysis_id = ? GROUP BY severity",
        (analysis_id,),
    )
    for row in rows:
        counts[str(row["severity"])] = int(row["n"])
    return counts


@router.get("/{analysis_id}/findings")
def list_findings(
    analysis_id: str,
    pager: deps.Pagination = Depends(deps.pagination),
    sort: str | None = Query(None, description="severity | rule_id | title"),
    order: str | None = Query(None, description="asc | desc"),
    severity: str | None = Query(None),
    rule_id: str | None = Query(None),
    search: str | None = Query(None, description="Substring of title, reason or rule id"),
) -> dict:
    """Paginated findings for one analysis, with severity counts for the whole set."""
    deps.get_ready_analysis(analysis_id)

    where = ["analysis_id = ?"]
    params: list[object] = [analysis_id]

    if severity and severity.strip():
        where.append("severity = ?")
        params.append(severity.strip())
    if rule_id and rule_id.strip():
        where.append("rule_id = ?")
        params.append(rule_id.strip())
    if search and search.strip():
        term = f"%{_escape_like(search.strip())}%"
        where.append(
            "(title LIKE ? ESCAPE '\\' OR reason LIKE ? ESCAPE '\\' "
            "OR description LIKE ? ESCAPE '\\' OR rule_id LIKE ? ESCAPE '\\')"
        )
        params.extend([term, term, term, term])

    clause = " AND ".join(where)
    order_sql = _order_clause(sort, order)

    total_row = db.query_one(f"SELECT COUNT(*) AS n FROM findings WHERE {clause}", tuple(params))
    total = int(total_row["n"]) if total_row else 0

    rows = db.query_all(
        f"""
        SELECT id, analysis_id, rule_id, severity, title, description, reason,
               evidence, packet_numbers, entities, recommendation, created_at
        FROM findings WHERE {clause}
        ORDER BY {order_sql}
        LIMIT ? OFFSET ?
        """,
        tuple([*params, pager.limit, pager.offset]),
    )

    envelope = pager.envelope([_serialise(row) for row in rows], total)
    envelope["counts"] = _counts(analysis_id)
    return envelope


@router.get("/{analysis_id}/findings/rules")
def list_rules(analysis_id: str) -> dict:
    """Every rule in the catalogue with its hit count for this analysis."""
    deps.get_ready_analysis(analysis_id)
    return {"items": detection_engine.list_rules(analysis_id)}


@router.get("/{analysis_id}/findings/{finding_id}")
def get_finding(analysis_id: str, finding_id: str) -> dict:
    """One finding with ``evidence``, ``packet_numbers`` and ``entities`` parsed."""
    deps.get_ready_analysis(analysis_id)
    row = db.query_one(
        """
        SELECT id, analysis_id, rule_id, severity, title, description, reason,
               evidence, packet_numbers, entities, recommendation, created_at
        FROM findings WHERE id = ? AND analysis_id = ?
        """,
        (finding_id, analysis_id),
    )
    if row is None:
        raise ApiError(
            404,
            "finding_not_found",
            f"No finding with id {finding_id} in this analysis.",
            {"finding_id": finding_id, "analysis_id": analysis_id},
        )
    return _serialise(row)


@router.post("/{analysis_id}/findings/rescan")
def rescan_findings(analysis_id: str) -> dict:
    """Re-run the detection engine.

    The rules read the indexed tables, so this is fast enough to run inside the
    request. Findings are cleared and rewritten with deterministic ids, which
    makes repeated runs idempotent. The retained capture is only referenced so
    the result can report whether it is still on disk; it is never re-dissected,
    so a rescan still works when ``retain_uploads`` has purged the upload.
    """
    row = deps.get_ready_analysis(analysis_id)
    capture = Path(row["stored_path"])

    ctx = detection_engine.InlineJobContext(analysis_id=analysis_id)
    stats = detection_engine.analyze(ctx, analysis_id, capture)
    log.info(
        "rescan for %s produced %s finding(s)",
        analysis_id,
        stats.get("findings"),
    )
    return {
        "ok": True,
        "findings": int(stats.get("findings") or 0),
        "by_severity": stats.get("by_severity") or {},
        "rules_run": int(stats.get("rules_run") or 0),
        "rule_errors": stats.get("rule_errors") or {},
        "seconds": stats.get("seconds"),
    }
