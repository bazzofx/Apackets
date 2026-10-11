"""Analysis pipeline orchestration.

Runs the stages of a full analysis inside a worker job, reporting progress and
honouring cancellation. Optional stages (HTTP, DNS, TLS, hosts, objects,
detection) degrade gracefully: if one fails, the analysis still completes and the
failure is recorded, because losing a whole capture's metadata over one optional
dissector would be worse than a partial result.
"""

from __future__ import annotations

import importlib
import json
import re
import time
from pathlib import Path

from app.core.config import settings
from app.core.logging import get_logger
from app.db import database as db
from app.services import capture_parser, packet_indexer, storage, tshark
from app.services.jobs import JobContext

log = get_logger("apackets.pipeline")

# Progress bands per stage: (stage_label, start_percent, span_percent)
BANDS: dict[str, tuple[float, float]] = {
    "metadata": (0.0, 5.0),
    "packets": (5.0, 45.0),
    "conversations": (50.0, 8.0),
    "http": (58.0, 10.0),
    "dns": (68.0, 8.0),
    "tls": (76.0, 7.0),
    "hosts": (83.0, 7.0),
    "objects": (90.0, 5.0),
    "detection": (95.0, 4.0),
    "finalise": (99.0, 1.0),
}


def _band(stage: str) -> tuple[float, float]:
    return BANDS.get(stage, (95.0, 1.0))


def run_analysis(ctx: JobContext, analysis_id: str, capture_path: Path) -> None:
    """Worker entry point: process one capture end to end."""
    started = time.monotonic()
    results: dict[str, object] = {}
    warnings: list[str] = []

    def progress(stage: str):
        """Return a setter that maps a 0..1 fraction onto the stage's band."""
        start, span = _band(stage)
        ctx.set_stage(f"{stage}: starting", start)

        def setter(message: str, fraction: float | None = None) -> None:
            if fraction is None:
                ctx.set_stage(message, start)
            else:
                clamped = max(0.0, min(1.0, fraction))
                ctx.set_stage(message, start + span * clamped)

        return setter

    # ---------------------------------------------------------------- metadata
    ctx.check_cancelled()
    set_progress = progress("metadata")
    set_progress("Validating capture", 0.1)

    info = capture_parser.inspect(capture_path)
    results["capture"] = {
        "file_type": info.file_type,
        "encapsulation": info.encapsulation,
        "packet_count": info.packet_count,
        "file_size": info.file_size,
        "duration": info.duration,
    }
    warnings.extend(info.warnings)

    with db.get_conn() as conn:
        conn.execute(
            """
            UPDATE analyses
               SET file_type = ?, encapsulation = ?, file_size = ?,
                   file_sha256 = COALESCE(?, file_sha256),
                   packet_count = ?, updated_at = ?
             WHERE id = ?
            """,
            (
                info.file_type,
                info.encapsulation,
                info.file_size,
                info.sha256,
                info.packet_count or 0,
                time.time(),
                analysis_id,
            ),
        )
    set_progress("Capture validated", 1.0)

    # ----------------------------------------------------------------- packets
    ctx.check_cancelled()
    set_progress = progress("packets")
    base, span = BANDS["packets"]
    set_progress("Indexing packets", 0.0)
    aggregates = packet_indexer.index_packets(
        ctx,
        analysis_id,
        capture_path,
        expected_packets=info.packet_count,
        progress_base=base,
        progress_span=span,
    )
    results["packets"] = aggregates

    total_packets = int(aggregates.get("packets", 0) or 0)
    if total_packets == 0 and (info.packet_count or 0) > 0:
        warnings.append("No packets could be indexed even though the capture reports packets.")
    if int(aggregates.get("packets_skipped", 0) or 0) > 0:
        warnings.append(
            f"{aggregates['packets_skipped']} packet(s) were skipped because TShark "
            "did not report a frame number."
        )

    # Persist capture-level aggregates derived from the real frames.
    with db.get_conn() as conn:
        conn.execute(
            """
            UPDATE analyses
               SET packet_count = ?, bytes_total = ?, capture_start = ?, capture_end = ?,
                   duration = ?, src_ip_count = ?, dst_ip_count = ?, tcp_count = ?,
                   udp_count = ?, dns_count = ?, http_count = ?, tls_count = ?,
                   updated_at = ?
             WHERE id = ?
            """,
            (
                aggregates.get("packets") or 0,
                aggregates.get("bytes_total") or 0,
                aggregates.get("start_time"),
                aggregates.get("end_time"),
                aggregates.get("duration"),
                aggregates.get("src_ips") or 0,
                aggregates.get("dst_ips") or 0,
                aggregates.get("tcp_packets") or 0,
                aggregates.get("udp_packets") or 0,
                aggregates.get("dns_packets") or 0,
                aggregates.get("http_packets") or 0,
                aggregates.get("tls_packets") or 0,
                time.time(),
                analysis_id,
            ),
        )

    # ------------------------------------------------- optional analysis stages
    optional_stages = [
        ("conversations", "conversation_analyzer", "Analysing conversations"),
        ("http", "http_analyzer", "Analysing HTTP"),
        ("dns", "dns_analyzer", "Analysing DNS"),
        ("tls", "tls_analyzer", "Analysing TLS"),
        ("hosts", "host_analyzer", "Building host statistics"),
        ("objects", "object_extractor", "Extracting objects"),
        ("detection", "detection_engine", "Running detection rules"),
    ]

    for stage, module_name, label in optional_stages:
        ctx.check_cancelled()
        set_progress = progress(stage)
        set_progress(label, 0.0)
        try:
            module = importlib.import_module(f"app.services.{module_name}")
        except ImportError as exc:  # pragma: no cover - stage not shipped yet
            log.warning("stage %s unavailable: %s", stage, exc)
            warnings.append(f"The {stage} stage is not available in this build.")
            continue

        analyze = getattr(module, "analyze", None)
        if analyze is None:  # pragma: no cover - defensive
            warnings.append(f"The {stage} stage exposes no analyze() entry point.")
            continue

        stage_started = time.monotonic()
        try:
            outcome = analyze(ctx, analysis_id, capture_path)
            results[stage] = outcome
            log.info(
                "stage %s completed in %.2fs: %s",
                stage,
                time.monotonic() - stage_started,
                outcome,
            )
        except Exception as exc:  # noqa: BLE001 - one stage must not sink the job
            log.exception("stage %s failed", stage)
            warnings.append(f"The {stage} stage failed: {type(exc).__name__}: {exc}")
            results[stage] = {"error": f"{type(exc).__name__}: {exc}"}
        set_progress(label, 1.0)

    # ---------------------------------------------------------------- finalise
    ctx.check_cancelled()
    set_progress = progress("finalise")
    set_progress("Finalising", 0.0)

    _cache_protocol_hierarchy(analysis_id, capture_path)
    _store_warnings(analysis_id, warnings)
    _refresh_counts(analysis_id)

    set_progress("Complete", 1.0)
    log.info(
        "analysis %s finished in %.1fs (%s packets)",
        analysis_id,
        time.monotonic() - started,
        total_packets,
    )


# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------

_PHS_RE = re.compile(
    r"^(?P<indent>\s*)(?P<name>[\w.\-()]+)\s+frames:(?P<frames>\d+)\s+bytes:(?P<bytes>\d+)\s*$"
)


def parse_protocol_hierarchy(text: str) -> list[dict]:
    """Parse tshark's ``-z io,phs`` output into a flat depth-annotated list."""
    entries: list[dict] = []
    for line in text.splitlines():
        match = _PHS_RE.match(line.rstrip())
        if not match:
            continue
        entries.append(
            {
                "protocol": match.group("name"),
                "frames": int(match.group("frames")),
                "bytes": int(match.group("bytes")),
                # Two spaces of indentation per level in tshark's output.
                "depth": len(match.group("indent")) // 2,
            }
        )
    return entries


def _cache_protocol_hierarchy(analysis_id: str, capture_path: Path) -> None:
    try:
        text = tshark.run_z(capture_path, "io,phs")
        entries = parse_protocol_hierarchy(text)
    except Exception as exc:  # noqa: BLE001
        log.warning("could not compute protocol hierarchy: %s", exc)
        return
    if not entries:
        return
    with db.get_conn() as conn:
        conn.execute(
            """
            INSERT OR REPLACE INTO stats_cache (analysis_id, kind, json, created_at)
            VALUES (?, 'protocol_hierarchy', ?, ?)
            """,
            (analysis_id, json.dumps(entries), time.time()),
        )


def _store_warnings(analysis_id: str, warnings: list[str]) -> None:
    if not warnings:
        return
    # De-duplicate while preserving order.
    seen: set[str] = set()
    unique = [w for w in warnings if not (w in seen or seen.add(w))]
    with db.get_conn() as conn:
        conn.execute(
            """
            INSERT OR REPLACE INTO stats_cache (analysis_id, kind, json, created_at)
            VALUES (?, 'warnings', ?, ?)
            """,
            (analysis_id, json.dumps(unique), time.time()),
        )


def load_warnings(analysis_id: str) -> list[str]:
    row = db.query_one(
        "SELECT json FROM stats_cache WHERE analysis_id = ? AND kind = 'warnings'",
        (analysis_id,),
    )
    if row is None:
        return []
    try:
        value = json.loads(row["json"])
        return [str(item) for item in value] if isinstance(value, list) else []
    except (json.JSONDecodeError, TypeError):
        return []


def load_protocol_hierarchy(analysis_id: str) -> list[dict]:
    row = db.query_one(
        "SELECT json FROM stats_cache WHERE analysis_id = ? AND kind = 'protocol_hierarchy'",
        (analysis_id,),
    )
    if row is None:
        return []
    try:
        value = json.loads(row["json"])
        return value if isinstance(value, list) else []
    except (json.JSONDecodeError, TypeError):
        return []


def _refresh_counts(analysis_id: str) -> None:
    """Refresh the per-protocol counters shown on the dashboard cards."""
    def count(table: str, where: str = "1=1") -> int:
        row = db.query_one(
            f"SELECT COUNT(*) AS n FROM {table} WHERE analysis_id = ? AND {where}",
            (analysis_id,),
        )
        return int(row["n"]) if row else 0

    dns_total = count("dns_queries")
    http_total = count("http_transactions", "method IS NOT NULL")
    tls_total = count("tls_sessions")

    with db.get_conn() as conn:
        conn.execute(
            """
            UPDATE analyses SET dns_count = ?, http_count = ?, tls_count = ?, updated_at = ?
             WHERE id = ?
            """,
            (dns_total, http_total, tls_total, time.time(), analysis_id),
        )


def process_new_analysis(ctx: JobContext, analysis_id: str) -> None:
    """Entry point used by the upload route: resolve the stored capture, then run."""
    row = db.query_one("SELECT stored_path FROM analyses WHERE id = ?", (analysis_id,))
    if row is None:
        raise RuntimeError(f"analysis {analysis_id} disappeared before processing")
    capture_path = Path(row["stored_path"])
    if not capture_path.is_file():
        raise FileNotFoundError(f"stored capture missing: {capture_path}")
    run_analysis(ctx, analysis_id, capture_path)


def analysis_disk_usage(analysis_id: str) -> int:
    total = storage.dir_size(storage.analysis_dir(analysis_id))
    for candidate in settings.uploads_dir.glob(f"{analysis_id}.*"):
        try:
            total += candidate.stat().st_size
        except OSError:
            continue
    return total
