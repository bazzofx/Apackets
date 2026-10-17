"""Analysis lifecycle: upload, list, inspect, summary, cancel, delete."""

from __future__ import annotations

import json
import threading
import time
from collections import OrderedDict
from pathlib import Path

from fastapi import APIRouter, Depends, File, Query, UploadFile

from app import __version__
from app.core import runtime_settings
from app.core.config import settings
from app.core.errors import ApiError, bad_request
from app.core.logging import get_logger
from app.db import database as db
from app.api.deps import Pagination, get_analysis, pagination
from app.services import capture_parser, pipeline, storage, tshark
from app.services.host_analyzer import address_scope
from app.services.jobs import jobs

log = get_logger("apackets.api.analyses")

router = APIRouter(prefix="/api", tags=["analyses"])

UPLOAD_CHUNK = 1 << 20  # 1 MiB

# Well-known service names for the Top Ports panel (IANA registry, not capture data).
KNOWN_PORTS: dict[int, str] = {
    20: "ftp-data", 21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "domain",
    67: "dhcp", 68: "dhcp", 69: "tftp", 80: "http", 110: "pop3", 123: "ntp",
    135: "msrpc", 137: "netbios-ns", 138: "netbios-dgm", 139: "netbios-ssn",
    143: "imap", 161: "snmp", 162: "snmp-trap", 389: "ldap", 443: "https",
    445: "microsoft-ds", 465: "smtps", 514: "syslog", 587: "submission",
    636: "ldaps", 993: "imaps", 995: "pop3s", 1080: "socks", 1194: "openvpn",
    1433: "ms-sql-s", 1521: "oracle", 1723: "pptp", 2049: "nfs", 3128: "squid",
    3306: "mysql", 3389: "rdp", 5060: "sip", 5222: "xmpp-client", 5353: "mdns",
    5432: "postgresql", 5900: "vnc", 5985: "winrm-http", 5986: "winrm-https",
    6379: "redis", 8080: "http-alt", 8443: "https-alt", 8888: "http-alt",
    9200: "elasticsearch", 11211: "memcached", 27017: "mongodb",
}

MAX_SERIES_BUCKETS = 240

# Per-domain byte attribution is derived from DNS answers plus observed
# conversations, so it is a real measurement with real caveats. The caveats are
# returned with the data and shown in the UI: this is attribution, not proof of
# who a name "belongs" to.
TOP_DOMAINS_NOTE = (
    "Domain totals are attributed from the IP addresses this capture observed in DNS "
    "answers, then summed from the conversations with those addresses. Directions are "
    "measured from the conversation, not guessed: 'received' is data that arrived from "
    "the domain's addresses and 'sent' is data sent to them. Names that never appeared "
    "in a captured answer are absent, CNAME chains are not followed, and a shared or "
    "CDN address can legitimately carry several names."
)


# --------------------------------------------------------------------------
# serialisation helpers
# --------------------------------------------------------------------------

def _analysis_dict(row) -> dict:
    data = dict(row)
    try:
        data["disk_usage"] = pipeline.analysis_disk_usage(row["id"])
    except ApiError:
        # A row whose id predates validation must not make the whole list 400.
        data["disk_usage"] = None
    data["upload_retained"] = bool(settings.retain_uploads)
    return data


def _latest_job(analysis_id: str) -> dict | None:
    row = db.query_one(
        "SELECT * FROM jobs WHERE analysis_id = ? ORDER BY created_at DESC LIMIT 1",
        (analysis_id,),
    )
    return dict(row) if row else None


# --------------------------------------------------------------------------
# upload
# --------------------------------------------------------------------------

@router.post("/analyses", status_code=202)
async def upload_analysis(file: UploadFile = File(...)) -> dict:
    """Accept a capture, validate it, and queue background processing."""
    if file.filename is None or not file.filename.strip():
        raise bad_request("missing_filename", "An uploaded file must have a filename.")

    # Reject by extension before writing anything to disk.
    capture_parser.validate_extension(file.filename)

    analysis_id = storage.new_analysis_id()
    settings.ensure_dirs()
    stored = storage.upload_path(analysis_id, file.filename)

    limit_bytes = runtime_settings.max_upload_bytes()
    limit_mb = runtime_settings.max_upload_mb()

    size = 0
    try:
        with open(stored, "wb") as handle:
            while True:
                chunk = await file.read(UPLOAD_CHUNK)
                if not chunk:
                    break
                size += len(chunk)
                if size > limit_bytes:
                    raise ApiError(
                        413,
                        "file_too_large",
                        f"File exceeds the {limit_mb} MB upload limit.",
                        {"limit_bytes": limit_bytes},
                    )
                handle.write(chunk)
    except ApiError:
        _discard(stored)
        raise
    except OSError as exc:
        _discard(stored)
        raise ApiError(500, "upload_failed", f"Could not store the upload: {exc}") from exc
    finally:
        await file.close()

    if size == 0:
        _discard(stored)
        raise ApiError(400, "empty_file", "The uploaded file is empty.")

    # TShark must be able to read it before we commit to an analysis.
    try:
        info = capture_parser.inspect(stored, original_filename=file.filename)
    except ApiError:
        _discard(stored)
        raise
    except Exception as exc:  # noqa: BLE001
        _discard(stored)
        raise ApiError(
            400, "invalid_capture", f"Could not read the file as a capture: {exc}"
        ) from exc

    now = time.time()
    safe_name = storage.safe_filename(file.filename, fallback="capture.pcap")
    storage.ensure_analysis_dirs(analysis_id)

    with db.get_conn() as conn:
        conn.execute(
            """
            INSERT INTO analyses (
                id, original_filename, stored_path, file_size, file_sha256, file_type,
                encapsulation, status, progress, stage, packet_count, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, 'pending', 0, 'queued', ?, ?, ?)
            """,
            (
                analysis_id,
                safe_name,
                str(stored),
                size,
                info.sha256 or storage.sha256_file(stored),
                info.file_type,
                info.encapsulation,
                info.packet_count or 0,
                now,
                now,
            ),
        )

    jobs.submit(analysis_id, lambda ctx: pipeline.process_new_analysis(ctx, analysis_id))

    row = db.query_one("SELECT * FROM analyses WHERE id = ?", (analysis_id,))
    body = _analysis_dict(row)
    body["job"] = _latest_job(analysis_id)
    log.info("accepted upload %s (%s bytes) as analysis %s", safe_name, size, analysis_id)
    return body


def _discard(path: Path) -> None:
    try:
        if path.exists():
            path.unlink()
    except OSError as exc:  # pragma: no cover
        log.warning("could not remove partial upload %s: %s", path, exc)


# --------------------------------------------------------------------------
# listing and detail
# --------------------------------------------------------------------------

@router.get("/analyses")
def list_analyses(page: Pagination = Depends(pagination)) -> dict:
    total_row = db.query_one("SELECT COUNT(*) AS n FROM analyses")
    total = int(total_row["n"]) if total_row else 0

    rows = db.query_all(
        """
        SELECT a.*,
               (SELECT j.status FROM jobs j WHERE j.analysis_id = a.id
                 ORDER BY j.created_at DESC LIMIT 1) AS job_status
          FROM analyses a
         ORDER BY a.created_at DESC
         LIMIT ? OFFSET ?
        """,
        (page.limit, page.offset),
    )
    return page.envelope([_analysis_dict(r) for r in rows], total)


@router.get("/analyses/{analysis_id}")
def get_analysis_detail(analysis_id: str) -> dict:
    row = get_analysis(analysis_id)
    body = _analysis_dict(row)
    body["job"] = _latest_job(analysis_id)
    body["warnings"] = pipeline.load_warnings(analysis_id)
    return body


@router.get("/analyses/{analysis_id}/jobs")
def list_jobs(analysis_id: str) -> dict:
    get_analysis(analysis_id)
    rows = db.query_all(
        "SELECT * FROM jobs WHERE analysis_id = ? ORDER BY created_at DESC",
        (analysis_id,),
    )
    return {"items": [dict(r) for r in rows]}


@router.get("/analyses/{analysis_id}/summary")
def analysis_summary(
    analysis_id: str,
    domain_limit: int = Query(5, ge=1, le=50, description="How many top domains to return"),
) -> dict:
    row = get_analysis(analysis_id)
    return build_summary(row, domain_limit=domain_limit)


# --------------------------------------------------------------------------
# lifecycle actions
# --------------------------------------------------------------------------

@router.post("/analyses/{analysis_id}/cancel")
def cancel_analysis(analysis_id: str) -> dict:
    row = get_analysis(analysis_id)
    if row["status"] not in {"pending", "processing"}:
        raise ApiError(
            409,
            "not_cancellable",
            f"Analysis is '{row['status']}' and cannot be cancelled.",
            {"status": row["status"]},
        )
    requested = jobs.cancel_for_analysis(analysis_id)
    if not requested:
        # The job is not in this process's registry (e.g. it already ended).
        with db.get_conn() as conn:
            conn.execute(
                "UPDATE jobs SET cancel_requested = 1 WHERE analysis_id = ? AND status = 'running'",
                (analysis_id,),
            )
    return {"ok": True, "id": analysis_id, "cancel_requested": True}


@router.delete("/analyses/{analysis_id}")
def delete_analysis(
    analysis_id: str,
    confirm: bool = Query(False, description="Must be true to delete"),
) -> dict:
    get_analysis(analysis_id)
    if not confirm:
        raise bad_request(
            "confirmation_required",
            "Deleting an analysis removes its capture and all derived data; pass confirm=true.",
        )

    jobs.cancel_for_analysis(analysis_id)
    # Give an in-flight worker a moment to notice the cancellation flag.
    deadline = time.monotonic() + 5.0
    while time.monotonic() < deadline:
        active = db.query_one(
            "SELECT COUNT(*) AS n FROM jobs WHERE analysis_id = ? AND status = 'running'",
            (analysis_id,),
        )
        if not active or int(active["n"]) == 0:
            break
        time.sleep(0.2)

    with db.get_conn() as conn:
        for table in (
            "packets", "conversations", "streams", "http_transactions", "dns_queries",
            "tls_sessions", "hosts", "findings", "objects", "stats_cache", "jobs",
            "indicators", "credentials",
        ):
            conn.execute(f"DELETE FROM {table} WHERE analysis_id = ?", (analysis_id,))
        conn.execute("DELETE FROM analyses WHERE id = ?", (analysis_id,))

    storage.delete_analysis(analysis_id)
    log.info("deleted analysis %s", analysis_id)
    return {"ok": True, "id": analysis_id}


# --------------------------------------------------------------------------
# summary construction
# --------------------------------------------------------------------------

def build_summary(row, *, domain_limit: int = 5) -> dict:
    analysis_id = row["id"]

    aggregate = _aggregates(analysis_id, row, domain_limit)
    # The one figure in `totals` that is not an aggregate over the capture: findings are
    # rewritten whenever the rules are re-run, so they are counted live and are not part
    # of the cached bundle (see `_aggregates`).
    totals = dict(aggregate["totals"])
    totals["findings"] = _scalar(
        "SELECT COUNT(*) FROM findings WHERE analysis_id = ?", (analysis_id,)
    )
    notes = _notes(row, totals)

    return {
        "analysis": {**_analysis_dict(row), "job_status": _job_status(analysis_id)},
        "totals": totals,
        "protocol_distribution": aggregate["protocol_distribution"],
        "traffic_series": aggregate["traffic_series"],
        "series_interval": aggregate["series_interval"],
        "top_talkers": aggregate["top_talkers"],
        "top_ports": aggregate["top_ports"],
        "top_conversations": aggregate["top_conversations"],
        "top_domains": aggregate["top_domains"],
        "top_domains_note": TOP_DOMAINS_NOTE,
        "traffic_extremes": aggregate["traffic_extremes"],
        "findings_summary": _findings_summary(analysis_id),
        "protocol_hierarchy": pipeline.load_protocol_hierarchy(analysis_id),
        "severity_counts": _severity_counts(analysis_id),
        "notes": notes,
    }


#: The parts of a summary that cannot change once a capture is indexed.
#:
#: `packets`, `conversations`, `dns_queries`, `http_transactions`, `tls_sessions` and
#: `hosts` are written by the pipeline (which always creates a new analysis id) and by
#: `POST /protocols/rescan` (which calls :func:`clear_summary_cache`). Everything else
#: in the payload - findings, severity counts, job status, the analysis row itself - is
#: computed live on every request, because those are the values a rescan, a rule run or
#: a background sweep can change, and each costs well under a millisecond.
#:
#: Measured on a 163 584-frame capture, the cached aggregate takes 0.8 s to build and
#: about 15 ms to serve; without it every visit to the Dashboard paid the 0.8 s.
_AGGREGATE_CACHE: "OrderedDict[str, dict]" = OrderedDict()
_AGGREGATE_CACHE_LIMIT = 8
_aggregate_lock = threading.Lock()


def clear_summary_cache(analysis_id: str | None = None) -> None:
    """Forget the cached aggregates of one analysis, or of all of them."""
    with _aggregate_lock:
        if analysis_id is None:
            _AGGREGATE_CACHE.clear()
        else:
            _AGGREGATE_CACHE.pop(analysis_id, None)


def _aggregates(analysis_id: str, row, domain_limit: int) -> dict:
    """The summary's immutable half, memoised per analysis and domain limit."""
    key = f"{analysis_id}:{domain_limit}"
    with _aggregate_lock:
        cached = _AGGREGATE_CACHE.get(key)
        if cached is not None:
            _AGGREGATE_CACHE.move_to_end(key)
            return cached

    interval, series = _traffic_series(analysis_id, row)
    value = {
        "totals": _totals(row),
        "protocol_distribution": _protocol_distribution(analysis_id),
        "traffic_series": series,
        "series_interval": interval,
        "top_talkers": _top_talkers(analysis_id),
        "top_ports": _top_ports(analysis_id),
        "top_conversations": _top_conversations(analysis_id),
        "top_domains": _top_domains(analysis_id, limit=domain_limit),
        "traffic_extremes": _traffic_extremes(analysis_id),
    }
    with _aggregate_lock:
        _AGGREGATE_CACHE[key] = value
        _AGGREGATE_CACHE.move_to_end(key)
        while len(_AGGREGATE_CACHE) > _AGGREGATE_CACHE_LIMIT:
            _AGGREGATE_CACHE.popitem(last=False)
    return value


def _job_status(analysis_id: str) -> str | None:
    row = db.query_one(
        "SELECT status FROM jobs WHERE analysis_id = ? ORDER BY created_at DESC LIMIT 1",
        (analysis_id,),
    )
    return row["status"] if row else None


def _scalar(sql: str, params: tuple) -> int:
    row = db.query_one(sql, params)
    if row is None:
        return 0
    value = row[0]
    return int(value) if value is not None else 0


def _totals(row) -> dict:
    analysis_id = row["id"]

    packets = _scalar("SELECT COUNT(*) FROM packets WHERE analysis_id = ?", (analysis_id,))
    bytes_total = _scalar(
        "SELECT COALESCE(SUM(frame_len), 0) FROM packets WHERE analysis_id = ?", (analysis_id,)
    )
    unique_src = _scalar(
        "SELECT COUNT(DISTINCT src_ip) FROM packets WHERE analysis_id = ? AND src_ip IS NOT NULL",
        (analysis_id,),
    )
    unique_dst = _scalar(
        "SELECT COUNT(DISTINCT dst_ip) FROM packets WHERE analysis_id = ? AND dst_ip IS NOT NULL",
        (analysis_id,),
    )
    tcp = _scalar(
        "SELECT COUNT(*) FROM packets WHERE analysis_id = ? AND transport = 'tcp'", (analysis_id,)
    )
    udp = _scalar(
        "SELECT COUNT(*) FROM packets WHERE analysis_id = ? AND transport = 'udp'", (analysis_id,)
    )

    dns_queries = _scalar(
        "SELECT COUNT(*) FROM dns_queries WHERE analysis_id = ?", (analysis_id,)
    )
    http_requests = _scalar(
        "SELECT COUNT(*) FROM http_transactions WHERE analysis_id = ? AND method IS NOT NULL",
        (analysis_id,),
    )
    tls_connections = _scalar(
        "SELECT COUNT(*) FROM tls_sessions WHERE analysis_id = ?", (analysis_id,)
    )
    conversations = _scalar(
        "SELECT COUNT(*) FROM conversations WHERE analysis_id = ?", (analysis_id,)
    )
    hosts = _scalar("SELECT COUNT(*) FROM hosts WHERE analysis_id = ?", (analysis_id,))
    findings = _scalar("SELECT COUNT(*) FROM findings WHERE analysis_id = ?", (analysis_id,))

    start = row["capture_start"]
    end = row["capture_end"]
    duration = row["duration"]
    if duration is None and start is not None and end is not None:
        duration = float(end) - float(start)

    return {
        "packets": packets,
        "bytes": bytes_total,
        "duration": duration,
        "unique_src_ips": unique_src,
        "unique_dst_ips": unique_dst,
        "tcp_packets": tcp,
        "udp_packets": udp,
        "dns_queries": dns_queries,
        "http_requests": http_requests,
        "tls_connections": tls_connections,
        "conversations": conversations,
        "hosts": hosts,
        "findings": findings,
        "start_time": start,
        "end_time": end,
    }


def _protocol_distribution(analysis_id: str, limit: int = 15) -> list[dict]:
    rows = db.query_all(
        """
        SELECT COALESCE(protocol, 'Unknown') AS protocol,
               COUNT(*) AS packets,
               COALESCE(SUM(frame_len), 0) AS bytes
          FROM packets
         WHERE analysis_id = ?
         GROUP BY protocol
         ORDER BY packets DESC
         LIMIT ?
        """,
        (analysis_id, limit),
    )
    return [dict(r) for r in rows]


def _traffic_series(analysis_id: str, row) -> tuple[float, list[dict]]:
    """Packets and bytes per interval, with empty intervals filled with zeros."""
    start = row["capture_start"]
    end = row["capture_end"]
    if start is None or end is None:
        return 1.0, []

    span = max(0.0, float(end) - float(start))
    buckets = max(1, min(MAX_SERIES_BUCKETS, int(span) + 1 if span >= 1 else 1))
    interval = span / buckets if buckets > 1 and span > 0 else max(span, 0.001)

    rows = db.query_all(
        """
        SELECT CAST((time_epoch - ?) / ? AS INTEGER) AS bucket,
               COUNT(*) AS packets,
               COALESCE(SUM(frame_len), 0) AS bytes
          FROM packets
         WHERE analysis_id = ? AND time_epoch IS NOT NULL
         GROUP BY bucket
         ORDER BY bucket
        """,
        (start, interval, analysis_id),
    )

    observed = {int(r["bucket"]): r for r in rows if r["bucket"] is not None}
    series: list[dict] = []
    for index in range(buckets):
        entry = observed.get(index)
        series.append(
            {
                "t": float(start) + index * interval,
                "packets": int(entry["packets"]) if entry else 0,
                "bytes": int(entry["bytes"]) if entry else 0,
            }
        )
    return round(interval, 6), series


def _top_talkers(analysis_id: str, limit: int = 10) -> list[dict]:
    rows = db.query_all(
        """
        SELECT ip, direction, SUM(packets) AS packets, SUM(bytes) AS bytes
          FROM (
            SELECT src_ip AS ip, 'source' AS direction, 1 AS packets, frame_len AS bytes
              FROM packets WHERE analysis_id = ? AND src_ip IS NOT NULL
            UNION ALL
            SELECT dst_ip AS ip, 'destination' AS direction, 1 AS packets, frame_len AS bytes
              FROM packets WHERE analysis_id = ? AND dst_ip IS NOT NULL
          )
         GROUP BY ip, direction
         ORDER BY bytes DESC
         LIMIT ?
        """,
        (analysis_id, analysis_id, limit),
    )
    return [dict(r) for r in rows]


def _top_ports(analysis_id: str, limit: int = 15) -> list[dict]:
    rows = db.query_all(
        """
        SELECT dst_port AS port,
               COALESCE(transport, 'other') AS protocol,
               COUNT(*) AS packets,
               COALESCE(SUM(frame_len), 0) AS bytes
          FROM packets
         WHERE analysis_id = ? AND dst_port IS NOT NULL
         GROUP BY dst_port, transport
         ORDER BY packets DESC
         LIMIT ?
        """,
        (analysis_id, limit),
    )
    items = []
    for row in rows:
        item = dict(row)
        item["service"] = KNOWN_PORTS.get(int(item["port"]))
        items.append(item)
    return items


def _top_conversations(analysis_id: str, limit: int = 10) -> list[dict]:
    rows = db.query_all(
        """
        SELECT conv_id, endpoint_a, endpoint_b, transport, ip_a, ip_b,
               packets_total, bytes_total, duration, state, protocols
          FROM conversations
         WHERE analysis_id = ?
         ORDER BY bytes_total DESC
         LIMIT ?
        """,
        (analysis_id, limit),
    )
    return [dict(r) for r in rows]


def _traffic_extremes(analysis_id: str) -> dict:
    """The single busiest sender and busiest receiver, with real host context."""
    def host(column: str) -> dict | None:
        row = db.query_one(
            f"""
            SELECT ip, mac, bytes_sent, bytes_received, packets_sent, packets_received,
                   dns_names, is_private, ip_version
              FROM hosts
             WHERE analysis_id = ? AND {column} > 0
             ORDER BY {column} DESC, ip ASC
             LIMIT 1
            """,
            (analysis_id,),
        )
        if row is None:
            return None
        data = dict(row)
        names = data.pop("dns_names", None)
        parsed: list[str] = []
        if isinstance(names, str) and names:
            try:
                value = json.loads(names)
                if isinstance(value, list):
                    parsed = [str(item) for item in value][:5]
            except (json.JSONDecodeError, TypeError):
                parsed = []
        return {
            "ip": data["ip"],
            "mac": data.get("mac"),
            "bytes": int(data.get("bytes_sent") if column == "bytes_sent" else data.get("bytes_received") or 0),
            "packets": int(
                data.get("packets_sent") if column == "bytes_sent" else data.get("packets_received") or 0
            ),
            "bytes_sent": int(data.get("bytes_sent") or 0),
            "bytes_received": int(data.get("bytes_received") or 0),
            "is_private": data.get("is_private"),
            "scope": address_scope(data["ip"]),
            "ip_version": data.get("ip_version"),
            "hostnames": parsed,
        }

    return {"max_sender": host("bytes_sent"), "max_receiver": host("bytes_received")}


def _top_domains(analysis_id: str, limit: int = 5) -> list[dict]:
    """Top domains by total bytes, with direction taken from the conversation.

    Attribution path: DNS answer addresses observed in this capture →
    conversations involving those addresses → the resolved direction of each
    conversation. A domain whose addresses were never seen in an answer does not
    appear, and that is stated in ``top_domains_note``.
    """
    # 1. domain -> address set, from answers actually observed in the capture.
    domain_ips: dict[str, set[str]] = {}
    for row in db.query_all(
        """
        SELECT query_name, answer_ips
          FROM dns_queries
         WHERE analysis_id = ? AND answer_ips IS NOT NULL AND answer_ips <> ''
        """,
        (analysis_id,),
    ):
        name = _normalise_domain(row["query_name"])
        if not name:
            continue
        addresses = {
            part.strip() for part in str(row["answer_ips"]).split(",") if part.strip()
        }
        if addresses:
            domain_ips.setdefault(name, set()).update(addresses)

    if not domain_ips:
        return []

    # 2. Conversations, so each direction is measured rather than assumed.
    conversations = db.query_all(
        """
        SELECT ip_a, ip_b, bytes_a_to_b, bytes_b_to_a,
               packets_a_to_b, packets_b_to_a
          FROM conversations
         WHERE analysis_id = ?
        """,
        (analysis_id,),
    )

    totals: dict[str, dict] = {}
    for name, addresses in domain_ips.items():
        sent = received = packets = 0
        clients: set[str] = set()
        matched: set[str] = set()

        for conv in conversations:
            ip_a, ip_b = conv["ip_a"], conv["ip_b"]
            a_is_domain = ip_a in addresses
            b_is_domain = ip_b in addresses
            if a_is_domain == b_is_domain:
                # Neither endpoint, or both (an address-to-itself conversation).
                continue

            if a_is_domain:
                received += int(conv["bytes_a_to_b"] or 0)
                sent += int(conv["bytes_b_to_a"] or 0)
                clients.add(ip_b)
                matched.add(ip_a)
            else:
                received += int(conv["bytes_b_to_a"] or 0)
                sent += int(conv["bytes_a_to_b"] or 0)
                clients.add(ip_a)
                matched.add(ip_b)

            packets += int(conv["packets_a_to_b"] or 0) + int(conv["packets_b_to_a"] or 0)

        total = sent + received
        if total <= 0:
            # A name that resolved but exchanged no observed traffic is noise here.
            continue

        totals[name] = {
            "domain": name,
            "ips": sorted(matched) or sorted(addresses),
            "address_count": len(matched) or len(addresses),
            "clients": sorted(clients)[:10],
            "client_count": len(clients),
            "bytes_sent": sent,
            "bytes_received": received,
            "bytes_total": total,
            "packets": packets,
        }

    ranked = sorted(
        totals.values(),
        key=lambda item: (-item["bytes_total"], item["domain"]),
    )
    return ranked[: max(1, limit)]


def _normalise_domain(value: object) -> str:
    """Lower-case, strip the root dot; reject anything that is not a plausible name."""
    if not isinstance(value, str):
        return ""
    name = value.strip().strip(".").lower()
    if not name or len(name) > 253 or "." not in name:
        return ""
    return name


def _findings_summary(analysis_id: str, limit: int = 10) -> list[dict]:
    rows = db.query_all(
        """
        SELECT id, rule_id, severity, title,
               CASE severity
                 WHEN 'high' THEN 0 WHEN 'medium' THEN 1
                 WHEN 'low' THEN 2 ELSE 3 END AS rank
          FROM findings
         WHERE analysis_id = ?
         ORDER BY rank, rule_id
         LIMIT ?
        """,
        (analysis_id, limit),
    )
    return [{k: v for k, v in dict(r).items() if k != "rank"} for r in rows]


def _severity_counts(analysis_id: str) -> dict:
    counts = {"high": 0, "medium": 0, "low": 0, "informational": 0}
    rows = db.query_all(
        "SELECT severity, COUNT(*) AS n FROM findings WHERE analysis_id = ? GROUP BY severity",
        (analysis_id,),
    )
    for row in rows:
        key = str(row["severity"]).lower()
        if key in counts:
            counts[key] = int(row["n"])
    return counts


def _notes(row, totals: dict) -> list[str]:
    """Real, verifiable caveats about what this analysis can and cannot show."""
    notes: list[str] = []
    analysis_id = row["id"]

    if totals["tls_connections"]:
        notes.append(
            "TLS sessions are reported from handshake metadata only. Payloads are not "
            "decrypted, so HTTP paths, headers and bodies inside HTTPS are not available "
            "unless decryption keys are supplied."
        )
    if row["file_type"] == "pcapng" and totals["packets"] == 0:
        notes.append("The capture reports no packets, so no statistics could be derived.")

    row_http = db.query_one(
        """
        SELECT COUNT(*) AS n FROM http_transactions
         WHERE analysis_id = ? AND host IS NOT NULL
           AND host GLOB '[0-9]*.[0-9]*.[0-9]*.[0-9]*'
        """,
        (analysis_id,),
    )
    if row_http and int(row_http["n"]) > 0:
        notes.append(
            f"{int(row_http['n'])} HTTP request(s) used a literal IP address as the Host "
            "header. That is common for appliances and APIs but also hides the hostname."
        )

    if totals["packets"] and not totals["conversations"]:
        notes.append("No transport conversations could be reconstructed from this capture.")

    warnings = pipeline.load_warnings(analysis_id)
    notes.extend(warnings)
    return notes


# --------------------------------------------------------------------------
# health
# --------------------------------------------------------------------------

@router.get("/health", tags=["meta"])
def health() -> dict:
    tshark_info = tshark.version()
    return {
        "status": "ok" if tshark_info.get("available") else "degraded",
        "version": __version__,
        "tshark": tshark_info,
        "data_dir": str(settings.data_dir),
        "local_only": settings.host in {"127.0.0.1", "localhost", "::1"},
    }
