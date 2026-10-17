"""Suricata rule management API.

Rules are stored in ``suricata_rules`` and evaluated by
``app.services.suricata_engine``. Nothing here talks to the network: rules come
from the vendored ``backend/rules/`` tree or from analyst uploads.

Endpoints
---------
GET    /api/suricata/rules                     list (filters + pagination)
GET    /api/suricata/rules/stats               counts by severity/source/category
GET    /api/suricata/rules/{sid}               one rule, parsed
POST   /api/suricata/rules                     create one rule from text
PUT    /api/suricata/rules/{sid}               edit text and/or enable/disable
DELETE /api/suricata/rules/{sid}               remove
POST   /api/suricata/rules/{sid}/restore       put a rule back to its vendored default
POST   /api/suricata/rules/import              upload one or more .rules files
POST   /api/suricata/rules/seed                import the vendored rule sets
GET    /api/suricata/config                    matcher configuration
PUT    /api/suricata/config                    update matcher configuration
GET    /api/analyses/{id}/suricata/alerts      Suricata findings for an analysis
POST   /api/analyses/{id}/suricata/run         re-evaluate rules for an analysis
"""

from __future__ import annotations

import json
from typing import Any

from fastapi import APIRouter, Depends, File, Query, UploadFile

from app.api.deps import Pagination, get_analysis, pagination, resolve_order, resolve_sort
from app.core.errors import bad_request, not_found
from app.core.logging import get_logger
from app.db import database as db
from app.services import suricata_engine, suricata_rules as sr

log = get_logger("apackets.api.suricata")

router = APIRouter(prefix="/api", tags=["suricata"])

MAX_RULE_FILE_BYTES = 16 * 1024 * 1024
MAX_UPLOAD_FILES = 25

SORTABLE: dict[str, str] = {
    "sid": "sid",
    "msg": "msg",
    "action": "action",
    "protocol": "protocol",
    "category": "category",
    "source": "source",
    "rev": "rev",
    "updated_at": "updated_at",
    "severity": (
        "CASE severity WHEN 'high' THEN 0 WHEN 'medium' THEN 1"
        " WHEN 'low' THEN 2 ELSE 3 END"
    ),
}


def _rule_dict(row: dict[str, Any] | Any, hits: int | None = None) -> dict[str, Any]:
    data = dict(row)
    for key in ("options", "unsupported"):
        raw = data.get(key)
        try:
            parsed = json.loads(raw) if isinstance(raw, str) else (raw or [])
        except (TypeError, ValueError):
            parsed = []
        data[key] = parsed
    for key in ("enabled", "supported", "approximate"):
        data[key] = bool(data.get(key))
    # Whether this rule still runs the definition the vendored tree carries, and
    # what moved if it does not, so the interface can mark a rule that is not at
    # its default and offer the restore action only where one exists.
    data.update(sr.describe_deviation(row))
    if hits is not None:
        data["hits"] = hits
    return data


# --------------------------------------------------------------------------
# read
# --------------------------------------------------------------------------


@router.get("/suricata/rules/stats")
def suricata_rule_stats() -> dict:
    """Counts used by the rules panel header."""
    return sr.rule_stats()


@router.get("/suricata/rules")
def list_suricata_rules(
    page: Pagination = Depends(pagination),
    enabled: bool | None = Query(None, description="only enabled/disabled rules"),
    supported: bool | None = Query(None, description="only rules the matcher can evaluate"),
    severity: str | None = Query(None, description="high|medium|low|informational"),
    protocol: str | None = Query(None),
    source: str | None = Query(None, description="e.g. bundled:daffainfo"),
    category: str | None = Query(None),
    action: str | None = Query(None),
    search: str | None = Query(None, description="substring of msg, sid or raw text"),
    analysis_id: str | None = Query(
        None, description="include per-analysis hit counts for this analysis"
    ),
    sort: str | None = Query(None),
    order: str | None = Query(None),
) -> dict:
    where: list[str] = ["1=1"]
    params: list[Any] = []

    if enabled is not None:
        where.append("enabled = ?")
        params.append(1 if enabled else 0)
    if supported is not None:
        where.append("supported = ?")
        params.append(1 if supported else 0)
    if severity:
        if severity not in sr.SEVERITIES:
            raise bad_request(
                "invalid_severity",
                f"Unknown severity {severity!r}.",
                {"allowed": list(sr.SEVERITIES)},
            )
        where.append("severity = ?")
        params.append(severity)
    if protocol:
        where.append("LOWER(protocol) = ?")
        params.append(protocol.strip().lower())
    if source:
        where.append("source = ?")
        params.append(source)
    if category:
        where.append("category LIKE ?")
        params.append(f"%{category}%")
    if action:
        where.append("LOWER(action) = ?")
        params.append(action.strip().lower())
    if search:
        needle = f"%{search.strip()}%"
        where.append("(msg LIKE ? OR raw LIKE ? OR CAST(sid AS TEXT) LIKE ?)")
        params.extend([needle, needle, f"%{search.strip()}%"])

    clause = " AND ".join(where)
    total_row = db.query_one(f"SELECT COUNT(*) AS n FROM suricata_rules WHERE {clause}", params)
    total = int(total_row["n"]) if total_row else 0

    sort_column = resolve_sort(sort, SORTABLE, "sid")
    direction = resolve_order(order, "asc")

    hits_select = "NULL AS hits"
    hit_params: list[Any] = []
    if analysis_id:
        get_analysis(analysis_id)  # 404 for unknown ids before touching findings
        hits_select = (
            "(SELECT COUNT(*) FROM findings f WHERE f.analysis_id = ?"
            " AND f.rule_id = 'suricata:' || CAST(suricata_rules.sid AS TEXT)) AS hits"
        )
        hit_params.append(analysis_id)

    rows = db.query_all(
        f"SELECT suricata_rules.*, {hits_select} FROM suricata_rules"
        f" WHERE {clause} ORDER BY {sort_column} {direction} LIMIT ? OFFSET ?",
        [*hit_params, *params, page.limit, page.offset],
    )
    items = [
        _rule_dict(row, hits=int(row["hits"]) if row["hits"] is not None else None) for row in rows
    ]
    return page.envelope(items, total)


@router.get("/suricata/config")
def get_suricata_config() -> dict:
    """Matcher configuration: HOME_NET, variable overrides and finding caps."""
    config = sr.config()
    return {
        **config,
        "variables_default": sr.default_variables(),
        "bundled_rules_dir": str(sr.RULES_DIR),
        "bundled_files": len(sr.load_bundled_files()),
        "engine": {
            "engine": "apackets-native-matcher",
            "suricata_binary": None,
            "note": (
                "Rules are matched against TShark-extracted fields. The Suricata binary is "
                "not required and is not used."
            ),
        },
    }


@router.get("/suricata/rules/{sid}")
def get_suricata_rule(sid: int) -> dict:
    row = sr.get_rule(sid)
    if row is None:
        raise not_found("rule_not_found", f"No Suricata rule with sid {sid}.")
    return _rule_dict(row)


# --------------------------------------------------------------------------
# write
# --------------------------------------------------------------------------


@router.post("/suricata/rules", status_code=201)
def create_suricata_rule(payload: dict) -> dict:
    """Create a rule from a single signature line."""
    raw = str(payload.get("raw") or "").strip()
    if not raw:
        raise bad_request("invalid_rule", "Provide the rule text in the 'raw' field.")
    try:
        parsed = sr.parse_rule(raw)
    except sr.RuleSyntaxError as exc:
        raise bad_request("invalid_rule", str(exc)) from exc

    if sr.get_rule(parsed.sid) is not None:
        raise bad_request(
            "rule_exists",
            f"A rule with sid {parsed.sid} already exists; edit it instead.",
            {"sid": parsed.sid},
        )
    enabled = 1 if payload.get("enabled", True) else 0
    sr.import_rules([parsed], source=str(payload.get("source") or "manual"), enabled=enabled)
    return _rule_dict(sr.get_rule(parsed.sid) or {})


@router.put("/suricata/rules/{sid}")
def update_suricata_rule(sid: int, payload: dict) -> dict:
    """Edit the rule text and/or enable/disable it."""
    raw = payload.get("raw")
    enabled = payload.get("enabled")
    if raw is None and enabled is None:
        raise bad_request(
            "nothing_to_update", "Provide 'raw' (rule text) and/or 'enabled'."
        )
    if raw is not None and not isinstance(raw, str):
        raise bad_request("invalid_rule", "'raw' must be the rule text as a string.")
    if enabled is not None and not isinstance(enabled, bool):
        raise bad_request("invalid_setting", "'enabled' must be true or false.")
    updated = sr.save_rule(sid, raw=raw, enabled=enabled)
    return _rule_dict(updated)


@router.delete("/suricata/rules/{sid}")
def delete_suricata_rule(sid: int) -> dict:
    if not sr.delete_rule(sid):
        raise not_found("rule_not_found", f"No Suricata rule with sid {sid}.")
    return {"ok": True, "sid": sid}


@router.post("/suricata/rules/seed")
def seed_suricata_rules(
    enabled: bool = Query(True, description="enable rules that are imported for the first time"),
) -> dict:
    """Import the rule sets vendored under ``backend/rules/``."""
    result = sr.seed_bundled_rules(enabled=1 if enabled else 0)
    return {"ok": True, **result, "stats": sr.rule_stats()}


@router.post("/suricata/rules/import")
async def import_suricata_rules(
    file: list[UploadFile] = File(..., description="one or more .rules files"),
    enabled: bool = Query(True, description="enable newly imported rules"),
) -> dict:
    """Import uploaded ``.rules`` files (Suricata or Emerging Threats format)."""
    if not file:
        raise bad_request("no_files", "Attach at least one .rules file.")
    if len(file) > MAX_UPLOAD_FILES:
        raise bad_request(
            "too_many_files",
            f"Import at most {MAX_UPLOAD_FILES} files per request (got {len(file)}).",
        )

    imported = 0
    updated = 0
    skipped = 0
    errors: list[str] = []
    files_report: list[dict[str, Any]] = []

    for upload in file:
        name = upload.filename or "upload.rules"
        if not name.lower().endswith((".rules", ".txt", ".rule")):
            errors.append(f"{name}: expected a .rules file")
            files_report.append({"file": name, "imported": 0, "updated": 0, "errors": 1})
            continue
        blob = await upload.read()
        if len(blob) > MAX_RULE_FILE_BYTES:
            errors.append(f"{name}: larger than {MAX_RULE_FILE_BYTES // (1024 * 1024)} MiB")
            files_report.append({"file": name, "imported": 0, "updated": 0, "errors": 1})
            continue
        text = blob.decode("utf-8", errors="replace")
        rules, file_errors = sr.parse_rule_text(text)
        for message in file_errors[:5]:
            errors.append(f"{name}: {message}")
        if not rules:
            skipped += 1
            files_report.append(
                {"file": name, "imported": 0, "updated": 0, "errors": len(file_errors)}
            )
            continue
        result = sr.import_rules(
            rules,
            source=f"upload:{name}",
            category=None,
            enabled=1 if enabled else 0,
        )
        imported += result["imported"]
        updated += result["updated"]
        files_report.append(
            {
                "file": name,
                "imported": result["imported"],
                "updated": result["updated"],
                "errors": len(file_errors),
            }
        )

    log.info("suricata import: %s new, %s updated, %s with errors", imported, updated, len(errors))
    return {
        "ok": True,
        "files": files_report,
        "imported": imported,
        "updated": updated,
        "skipped_files": skipped,
        "errors": errors[:20],
        "stats": sr.rule_stats(),
    }


@router.put("/suricata/config")
def update_suricata_config(payload: dict) -> dict:
    """Update HOME_NET / variable overrides / finding cap."""
    return sr.save_config(payload)


# --------------------------------------------------------------------------
# per-analysis
# --------------------------------------------------------------------------


@router.get("/analyses/{analysis_id}/suricata/alerts")
def list_suricata_alerts(
    analysis_id: str,
    page: Pagination = Depends(pagination),
    severity: str | None = Query(None),
    search: str | None = Query(None),
) -> dict:
    """Suricata findings for one analysis (also visible through /findings)."""
    get_analysis(analysis_id)
    where = ["analysis_id = ?", "rule_id LIKE 'suricata:%'"]
    params: list[Any] = [analysis_id]
    if severity:
        where.append("severity = ?")
        params.append(severity)
    if search:
        needle = f"%{search.strip()}%"
        where.append("(title LIKE ? OR reason LIKE ?)")
        params.extend([needle, needle])
    clause = " AND ".join(where)

    total_row = db.query_one(f"SELECT COUNT(*) AS n FROM findings WHERE {clause}", params)
    total = int(total_row["n"]) if total_row else 0
    rows = db.query_all(
        f"""
        SELECT id, rule_id, severity, title, description, reason, evidence,
               packet_numbers, entities, recommendation, created_at
          FROM findings
         WHERE {clause}
         ORDER BY CASE severity WHEN 'high' THEN 0 WHEN 'medium' THEN 1
                  WHEN 'low' THEN 2 ELSE 3 END, rule_id
         LIMIT ? OFFSET ?
        """,
        [*params, page.limit, page.offset],
    )
    items: list[dict[str, Any]] = []
    for row in rows:
        item = dict(row)
        for key in ("evidence", "packet_numbers", "entities"):
            try:
                item[key] = json.loads(item[key]) if item[key] else None
            except (TypeError, ValueError):
                item[key] = None
        items.append(item)
    return page.envelope(items, total)


@router.post("/analyses/{analysis_id}/suricata/run")
def run_suricata_rules(analysis_id: str) -> dict:
    """Evaluate the enabled rules against an already-analysed capture."""
    row = get_analysis(analysis_id)
    if row["status"] != "completed":
        raise bad_request(
            "analysis_not_ready",
            f"Analysis is '{row['status']}'; Suricata rules can run once it completes.",
            {"status": row["status"]},
        )
    stats = suricata_engine.run_rules(analysis_id)
    return {"ok": True, "analysis_id": analysis_id, **stats}
