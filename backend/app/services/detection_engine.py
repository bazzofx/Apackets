"""Rule-based detection engine.

Ten independent rules read the **already indexed** tables (``packets``,
``dns_queries``, ``http_transactions``, ``hosts``, ``conversations``,
``indicators``) rather than re-dissecting the capture. Findings are cheap to
produce, re-runnable, and always derived from rows that earlier pipeline stages
extracted from the original bytes.

Design rules that this module follows strictly:

* **Every rule is explainable.** ``reason`` always states the observed numbers
  *and* the threshold that was crossed. A finding is a lead for an analyst, so
  the language is investigative ("consistent with", "worth reviewing") and never
  a verdict ("is malware", "attack confirmed").
* **Every rule tolerates an empty table.** Zero rows means zero findings, never
  an error, and a rule that raises is logged and skipped rather than failing the
  whole pipeline.
* **Findings are idempotent.** ``id`` is
  ``f"{rule_id}:{sha1(canonical_key)[:12]}"`` where the canonical key includes
  the analysis id, so re-running produces byte-identical ids and
  ``INSERT OR REPLACE`` keeps the table stable.
* **No fabricated numbers.** Everything in ``evidence``, ``packet_numbers`` and
  ``entities`` comes from a persisted row; values that cannot be determined stay
  absent.

Thresholds live in the ``settings`` table under the key ``detection_config``
(see :func:`default_config`, :func:`load_config`, :func:`save_config`).
"""

from __future__ import annotations

import hashlib
import json
import re
import sqlite3
import statistics
import time
from collections import Counter, deque
from collections.abc import Callable, Iterator, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, unquote, urlsplit

from app.core.logging import get_logger
from app.db import database as db

log = get_logger("apackets.detection")

# --------------------------------------------------------------------------
# constants
# --------------------------------------------------------------------------

SEVERITIES: tuple[str, ...] = ("high", "medium", "low", "informational")
SEVERITY_RANK: dict[str, int] = {name: index for index, name in enumerate(SEVERITIES)}

CONFIG_KEY = "detection_config"

MAX_FINDINGS_PER_RULE = 60
MAX_PACKET_NUMBERS = 50
MAX_ENTITY_VALUES = 25

# TCP flag bits (tcp.flags) and the letters used by tcp.flags.str.
TCP_FIN = 0x01
TCP_SYN = 0x02
TCP_RST = 0x04
TCP_PSH = 0x08
TCP_ACK = 0x10

# A destination port outside this list that appears exactly once in a capture is
# weak evidence on its own, which is why the rule is informational.
COMMON_PORTS: frozenset[int] = frozenset(
    {
        20, 21, 22, 23, 25, 53, 67, 68, 69, 80, 110, 111, 123, 135, 137, 138, 139,
        143, 161, 162, 179, 389, 443, 445, 464, 465, 500, 514, 515, 520, 587, 623,
        631, 636, 853, 873, 902, 989, 990, 993, 995, 1080, 1194, 1433, 1434, 1521,
        1701, 1723, 1883, 1900, 2049, 2082, 2083, 2222, 2375, 2376, 2427, 3128, 3260,
        3306, 3389, 3478, 4505, 4506, 5000, 5060, 5061, 5222, 5228, 5229, 5230, 5269,
        5353, 5432, 5672, 5900, 5938, 5985, 5986, 6379, 6443, 7001, 7002, 8000, 8008,
        8080, 8081, 8088, 8123, 8443, 8500, 8883, 8888, 9000, 9042, 9090, 9092, 9100,
        9200, 9300, 9418, 9999, 10000, 11211, 15672, 25565, 27017, 27018, 32400, 49152,
        49153, 51820,
    }
)

# Patterns for http_suspicious_path. Each entry is
# (compiled regex, human label, category). Matching happens against both the raw
# URI and its percent-decoded form, so encoded traversal is caught too.
SUSPICIOUS_PATTERNS: tuple[tuple[re.Pattern[str], str, str], ...] = (
    (re.compile(r"\.\./|\.\.\\"), "'../' traversal sequence", "path traversal"),
    (re.compile(r"\.\.%2f|%2e%2e"), "'%2e%2e' encoded traversal", "path traversal"),
    (re.compile(r"/etc/passwd"), "'/etc/passwd'", "sensitive file access"),
    (re.compile(r"/etc/shadow"), "'/etc/shadow'", "sensitive file access"),
    (re.compile(r"/proc/self/environ"), "'/proc/self/environ'", "sensitive file access"),
    (re.compile(r"win\.ini|boot\.ini"), "Windows system file", "sensitive file access"),
    (re.compile(r"/\.git/|/\.svn/|/\.hg/"), "exposed VCS metadata directory", "exposed metadata"),
    (re.compile(r"/\.env\b|/\.aws/|/\.ssh/"), "exposed credential file", "exposed metadata"),
    (re.compile(r"id_rsa|\.pem\b|\.pfx\b"), "private key material", "exposed metadata"),
    (re.compile(r"/phpmyadmin|/pma/|/adminer\.php"), "database admin console", "admin interface"),
    (re.compile(r"wp-login\.php|wp-config\.php|xmlrpc\.php"), "WordPress target", "admin interface"),
    (re.compile(r"/cgi-bin/"), "'/cgi-bin/' CGI path", "legacy CGI"),
    (re.compile(r"shell\.php|/shell\b|c99\.php|r57\.php|webshell"), "web shell name", "web shell"),
    (re.compile(r"\bcmd=|;cat\s|\|\s*id\b|/bin/(?:sh|bash)\b"), "command execution parameter", "command injection"),
    (re.compile(r"exec=|system\(|passthru\(|eval\(|base64_decode\("), "code execution keyword", "command injection"),
    (re.compile(r"union\s+(?:all\s+)?select\b"), "'UNION SELECT' keyword", "SQL injection"),
    (re.compile(r"'\s*or\s+'?1'?\s*=\s*'?1"), "boolean SQL injection fragment", "SQL injection"),
    (re.compile(r"<script|onerror=|javascript:"), "script payload in request path", "cross-site scripting"),
    (re.compile(r"%00"), "'%00' null byte", "filter bypass"),
)

# Field names that should not travel over plaintext HTTP.
SENSITIVE_FIELDS: tuple[str, ...] = (
    "password", "passwd", "pass", "pwd", "passwort",
    "secret", "client_secret", "secret_key", "private_key", "api_secret",
    "token", "access_token", "auth_token", "refresh_token", "id_token", "csrf_token",
    "api_key", "apikey", "api-key", "subscription_key",
    "credential", "credentials", "user_password", "login_password",
    "session_id", "sessionid", "jsessionid", "phpsessid", "asp.net_sessionid",
    "aws_access_key_id", "aws_secret_access_key", "authorization",
)

DEFAULT_MAX_BYTES = 50 * 1024 * 1024

# Phrases that turn a lead into a verdict. Their presence is a bug in the rule
# copy, so it is reported loudly (and never crashes the analysis).
_VERDICT_PHRASES: tuple[str, ...] = (
    "is malware", "are malware", "attack confirmed", "is a hacker", "hacker",
    "definitely malicious", "proves that", "is compromised", "has been compromised",
    "infected host", "100% malicious",
)


# --------------------------------------------------------------------------
# generic helpers
# --------------------------------------------------------------------------

def _stream(sql: str, params: Sequence[Any] = ()) -> Iterator[sqlite3.Row]:
    """Iterate rows from a query without materialising the whole result set.

    Used for tables that can hold millions of rows (``packets``): it keeps the
    memory footprint proportional to the current grouping key, not the capture.
    """
    conn = db.connect()
    try:
        cursor = conn.execute(sql, tuple(params))
        try:
            for row in cursor:
                yield row
        finally:
            cursor.close()
    finally:
        conn.close()


def _rows(sql: str, params: Sequence[Any] = ()) -> list[dict[str, Any]]:
    """Fetch a bounded result set as plain dicts."""
    try:
        return [dict(row) for row in db.query_all(sql, params)]
    except sqlite3.Error as exc:  # missing table / column on an older database
        log.warning("query failed (%s): %s", exc, " ".join(sql.split())[:120])
        return []


def _as_int(value: Any) -> int | None:
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return int(value)
    text = str(value).strip()
    if not text:
        return None
    try:
        return int(text, 16) if text.lower().startswith("0x") else int(float(text))
    except ValueError:
        return None


def _as_float(value: Any) -> float | None:
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return float(value)
    try:
        return float(str(value).strip())
    except ValueError:
        return None


def _as_text(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def parse_tcp_flags(raw: Any, flags_text: str | None = None) -> int | None:
    """Best-effort TCP flag bits from ``tcp_flags_raw`` or ``tcp_flags``.

    ``tcp_flags_raw`` holds ``tcp.flags``, which TShark prints as ``0x0002``;
    depending on how the indexer stored it the column may hold a hex string, a
    decimal string, an int, or nothing at all. When it is unusable the display
    string from ``tcp.flags.str`` (for example ``··········S·``) is used instead,
    because flag letters are unambiguous.
    """
    bits = _as_int(raw)
    if bits is not None:
        return bits

    text = flags_text or ""
    if not text:
        return None

    found = 0
    if "F" in text:
        found |= TCP_FIN
    if "S" in text:
        found |= TCP_SYN
    if "R" in text:
        found |= TCP_RST
    if "P" in text:
        found |= TCP_PSH
    if "A" in text:
        found |= TCP_ACK
    return found if found else None


def _is_syn_only(flags: int | None) -> bool:
    return flags is not None and bool(flags & TCP_SYN) and not bool(flags & TCP_ACK)


def _is_syn_ack(flags: int | None) -> bool:
    return flags is not None and bool(flags & TCP_SYN) and bool(flags & TCP_ACK)


def _is_rst(flags: int | None) -> bool:
    return flags is not None and bool(flags & TCP_RST)


def _cap(values: Sequence[Any], limit: int) -> list[Any]:
    """Ordered, de-duplicated, capped list; ``None`` and blanks are dropped."""
    out: list[Any] = []
    seen: set[Any] = set()
    for value in values:
        if value is None:
            continue
        if isinstance(value, str):
            value = value.strip()
            if not value:
                continue
        if isinstance(value, list):
            # entities are JSON arrays; never nest a list inside one
            continue
        if value in seen:
            continue
        seen.add(value)
        out.append(value)
        if len(out) >= limit:
            break
    return out


def _entities(
    *,
    ips: Sequence[Any] = (),
    hostnames: Sequence[Any] = (),
    ports: Sequence[Any] = (),
    uris: Sequence[Any] = (),
) -> dict[str, list[Any]]:
    clean_ports: list[int] = []
    for value in ports:
        port = _as_int(value)
        if port is not None and 0 <= port <= 65535:
            clean_ports.append(port)
    return {
        "ips": _cap(ips, MAX_ENTITY_VALUES),
        "hostnames": _cap(hostnames, MAX_ENTITY_VALUES),
        "ports": _cap(clean_ports, MAX_ENTITY_VALUES),
        "uris": _cap(uris, MAX_ENTITY_VALUES),
    }


def _packets(numbers: Iterable[Any]) -> list[int]:
    """Real frame numbers only, earliest first, capped at 50."""
    collected: list[int] = []
    for value in numbers:
        number = _as_int(value)
        if number is not None and number > 0:
            collected.append(number)
    return sorted(set(collected))[:MAX_PACKET_NUMBERS]


def _mb(value: int | float) -> float:
    return float(value) / (1024 * 1024)


def _json(value: Any) -> str:
    return json.dumps(value, separators=(",", ":"), ensure_ascii=False, default=str)


def _safe_label(value: Any, limit: int = 200) -> str:
    """Capture-derived text rendered inside prose: single line, no controls."""
    text = "" if value is None else str(value)
    text = "".join(ch if ch.isprintable() else " " for ch in text)
    text = " ".join(text.split())
    return text[:limit]


def _check_language(text: str, where: str) -> None:
    lowered = text.lower()
    for phrase in _VERDICT_PHRASES:
        if phrase in lowered:
            log.warning("verdict language %r found in %s copy", phrase, where)


# --------------------------------------------------------------------------
# finding construction
# --------------------------------------------------------------------------

@dataclass
class RuleSpec:
    """Static definition of one rule plus its configurable thresholds."""

    rule_id: str
    title: str
    severity: str
    description: str
    threshold: str  # ``str.format`` template rendered from the effective config
    defaults: dict[str, Any]
    run: Callable[[str, dict[str, Any]], list[dict[str, Any]]]
    notes: str = ""

    def threshold_text(self, params: dict[str, Any]) -> str:
        try:
            return self.threshold.format(**params)
        except (KeyError, IndexError, ValueError):  # pragma: no cover - defensive
            return self.threshold


@dataclass
class InlineJobContext:
    """A ``JobContext``-compatible no-op context for synchronous (in-request) runs.

    The API re-runs detection or extraction inside a request. Writing progress
    through :class:`app.services.jobs.JobContext` would touch ``jobs`` and
    ``analyses.progress`` for a job that does not exist, so this variant records
    the stage locally and never writes to the database.
    """

    analysis_id: str
    job_id: str = "inline"
    stage: str | None = field(default=None, init=False)

    def check_cancelled(self) -> None:  # noqa: D102 - matches JobContext
        return None

    @property
    def cancel_event(self) -> Any:  # noqa: D102 - matches JobContext
        import threading

        return threading.Event()

    @property
    def is_cancelled(self) -> bool:  # noqa: D102 - matches JobContext
        return False

    def set_stage(self, stage: str, progress: float | None = None) -> None:  # noqa: D102
        self.stage = stage


def _finding(
    *,
    title: str,
    key: Sequence[Any],
    reason: str,
    evidence: dict[str, Any],
    packet_numbers: Iterable[Any],
    entities: dict[str, list[Any]],
    recommendation: str,
) -> dict[str, Any]:
    """Intermediate finding: severity/rule/id are attached by :func:`_finalise`."""
    return {
        "title": title,
        "key": list(key),
        "reason": reason,
        "evidence": evidence,
        "packet_numbers": _packets(packet_numbers),
        "entities": entities,
        "recommendation": recommendation,
    }


def finding_id(analysis_id: str, rule_id: str, key: Sequence[Any]) -> str:
    canonical = _json([analysis_id, rule_id, list(key)])
    digest = hashlib.sha1(canonical.encode("utf-8")).hexdigest()[:12]
    return f"{rule_id}:{digest}"


def _finalise(spec: RuleSpec, analysis_id: str, item: dict[str, Any]) -> dict[str, Any]:
    severity = spec.severity
    if severity not in SEVERITIES:  # pragma: no cover - registry is static
        raise ValueError(f"rule {spec.rule_id} declares unknown severity {severity!r}")

    _check_language(
        " ".join(
            (
                str(item.get("title") or spec.title),
                spec.description,
                str(item["reason"]),
                str(item["recommendation"]),
            )
        ),
        spec.rule_id,
    )

    return {
        "id": finding_id(analysis_id, spec.rule_id, item["key"]),
        "rule_id": spec.rule_id,
        "severity": severity,
        "title": str(item.get("title") or spec.title)[:300],
        "description": spec.description,
        "reason": str(item["reason"]),
        "evidence": item.get("evidence") or {},
        "packet_numbers": item.get("packet_numbers") or [],
        "entities": item.get("entities") or _entities(),
        "recommendation": str(item["recommendation"]),
    }


# ==========================================================================
# rule 1 - tcp_syn_scan
# ==========================================================================

def _best_scan_window(
    packets: Sequence[dict[str, Any]], window_s: float
) -> tuple[list[int], list[dict[str, Any]], float] | None:
    """Widest fan-out of distinct destination ports inside any ``window_s`` gap."""
    queue: deque[dict[str, Any]] = deque()
    counts: Counter[int] = Counter()
    best: tuple[list[int], list[dict[str, Any]], float] | None = None
    best_distinct = 0

    for packet in packets:
        queue.append(packet)
        counts[packet["dst_port"]] += 1

        while queue and (packet["time_epoch"] - queue[0]["time_epoch"]) > window_s:
            dropped = queue.popleft()
            counts[dropped["dst_port"]] -= 1
            if counts[dropped["dst_port"]] <= 0:
                del counts[dropped["dst_port"]]

        if len(counts) > best_distinct:
            best_distinct = len(counts)
            best = (
                sorted(counts),
                list(queue),
                float(packet["time_epoch"]) - float(queue[0]["time_epoch"]),
            )
    return best


def _rule_tcp_syn_scan(analysis_id: str, params: dict[str, Any]) -> list[dict[str, Any]]:
    max_ports = int(params["max_ports"])
    window_s = float(params["window_s"])
    syn_ratio = float(params["syn_ratio"])

    sql = """
        SELECT number, time_epoch, src_ip, dst_ip, dst_port, tcp_flags_raw, tcp_flags
        FROM packets
        WHERE analysis_id = ? AND transport = 'tcp' AND src_ip IS NOT NULL
              AND dst_port IS NOT NULL AND time_epoch IS NOT NULL
        ORDER BY src_ip, time_epoch, number
    """

    findings: list[dict[str, Any]] = []
    current_src: str | None = None
    group: list[dict[str, Any]] = []

    def flush() -> None:
        nonlocal group, current_src
        if not group or current_src is None or len(group) < max_ports:
            group = []
            return

        group.sort(key=lambda item: item["time_epoch"])
        best = _best_scan_window(group, window_s)
        source = current_src
        group = []
        if best is None:
            return

        ports, window, duration = best
        if len(ports) < max_ports:
            return

        syn_only = sum(1 for item in window if _is_syn_only(item["flags"]))
        ratio = syn_only / len(window) if window else 0.0
        if ratio < syn_ratio:
            return

        port_counts = Counter(item["dst_port"] for item in window)
        targets = _cap([item["dst_ip"] for item in window], MAX_ENTITY_VALUES)
        first_time = float(window[0]["time_epoch"])
        last_time = float(window[-1]["time_epoch"])

        findings.append(
            _finding(
                title=f"Possible TCP SYN scan from {source} ({len(ports)} ports in {duration:.1f} s)",
                key=[source],
                reason=(
                    f"Source {source} contacted {len(ports)} distinct destination ports across "
                    f"{len(targets)} destination address(es) within {duration:.1f} s "
                    f"(threshold: {max_ports} ports in {window_s:g} s); "
                    f"{syn_only} of {len(window)} frames in that window had SYN set with ACK clear "
                    f"({ratio:.0%}, threshold: >= {syn_ratio:.0%}). "
                    f"The window ran from epoch {first_time:.3f} to {last_time:.3f}."
                ),
                evidence={
                    "source_ip": source,
                    "distinct_destination_ports": len(ports),
                    "distinct_destination_ips": len(targets),
                    "destination_ips": targets,
                    "ports": [
                        {"port": port, "frames": port_counts[port]}
                        for port in sorted(port_counts)[:40]
                    ],
                    "window_seconds": round(duration, 3),
                    "window_start_epoch": first_time,
                    "window_end_epoch": last_time,
                    "frames_in_window": len(window),
                    "syn_only_frames": syn_only,
                    "syn_only_ratio": round(ratio, 4),
                    "thresholds": {
                        "max_ports": max_ports,
                        "window_s": window_s,
                        "syn_ratio": syn_ratio,
                    },
                },
                packet_numbers=[item["number"] for item in window],
                entities=_entities(
                    ips=[source, *targets],
                    ports=ports,
                    hostnames=[],
                    uris=[],
                ),
                recommendation=(
                    f"Confirm whether {source} is authorised to perform service discovery in this "
                    "network, then review the responding ports on "
                    f"{targets[0] if targets else 'the destination'} in the Conversations view. "
                    "A single scan from an inventory or monitoring system has the same signature as "
                    "reconnaissance, so check the host's ownership record and recent change history "
                    "before escalating."
                ),
            )
        )

    for row in _stream(sql, (analysis_id,)):
        src = row["src_ip"]
        if src != current_src:
            flush()
            current_src = src
            group = []
        group.append(
            {
                "number": row["number"],
                "time_epoch": float(row["time_epoch"]),
                "dst_ip": row["dst_ip"],
                "dst_port": int(row["dst_port"]),
                "flags": parse_tcp_flags(row["tcp_flags_raw"], row["tcp_flags"]),
            }
        )
    flush()

    return findings


# ==========================================================================
# rule 2 - dns_nxdomain_burst
# ==========================================================================

def _is_nxdomain(row: dict[str, Any]) -> bool:
    code = _as_int(row.get("rcode"))
    if code is not None:
        return code == 3
    name = (_as_text(row.get("rcode_name")) or "").upper()
    return name in {"NXDOMAIN", "3", "NO SUCH NAME"}


def _rule_dns_nxdomain_burst(analysis_id: str, params: dict[str, Any]) -> list[dict[str, Any]]:
    threshold = int(params["min_nxdomain"])
    rows = _rows(
        """
        SELECT client_ip, server_ip, query_name, packet_number, response_packet,
               time_epoch, rcode, rcode_name, response_delay
        FROM dns_queries WHERE analysis_id = ?
        """,
        (analysis_id,),
    )
    if not rows:
        return []

    by_client: dict[str, list[dict[str, Any]]] = {}
    totals: Counter[str] = Counter()
    for row in rows:
        client = _as_text(row.get("client_ip"))
        if not client:
            continue
        totals[client] += 1
        if _is_nxdomain(row):
            by_client.setdefault(client, []).append(row)

    findings: list[dict[str, Any]] = []
    for client, hits in sorted(by_client.items()):
        if len(hits) < threshold:
            continue
        hits.sort(key=lambda item: (_as_float(item.get("time_epoch")) or 0.0))
        names = _cap([item.get("query_name") for item in hits], 20)
        servers = _cap([item.get("server_ip") for item in hits], 10)
        times = [_as_float(item.get("time_epoch")) for item in hits]
        times = [value for value in times if value is not None]
        answered = totals[client] - len(hits)
        rcode_names = Counter((_as_text(item.get("rcode_name")) or "NXDOMAIN") for item in hits)

        window = f"between epoch {min(times):.3f} and {max(times):.3f}" if times else "in this capture"
        findings.append(
            _finding(
                title=f"{len(hits)} NXDOMAIN responses to {client}",
                key=[client],
                reason=(
                    f"Client {client} received {len(hits)} NXDOMAIN responses for "
                    f"{len(names)} distinct query names {window} "
                    f"(threshold: {threshold} or more NXDOMAIN responses from one client). "
                    f"{answered} other queries from this client were answered normally, and the "
                    f"resolver(s) involved were {', '.join(servers) if servers else 'not recorded'}. "
                    f"Response codes observed: "
                    f"{', '.join(f'{name}={count}' for name, count in sorted(rcode_names.items()))}."
                ),
                evidence={
                    "client_ip": client,
                    "nxdomain_count": len(hits),
                    "other_queries": answered,
                    "total_queries": totals[client],
                    "distinct_query_names": len(names),
                    "sample_query_names": names,
                    "resolvers": servers,
                    "first_epoch": min(times) if times else None,
                    "last_epoch": max(times) if times else None,
                    "threshold": threshold,
                },
                packet_numbers=[
                    (item.get("response_packet") or item.get("packet_number")) for item in hits
                ],
                entities=_entities(
                    ips=[client, *servers],
                    hostnames=names,
                    ports=[53],
                    uris=[],
                ),
                recommendation=(
                    f"Review the queried names listed in the DNS view for {client} and check whether "
                    "they resolve from a different resolver; a burst of nonexistent names is "
                    "consistent with typo-squatting attempts, stale application configuration, "
                    "domain-generation algorithms, or simply a client retrying a bad hostname. "
                    "Confirm which process on the host issued the queries before drawing conclusions."
                ),
            )
        )
    return findings


# ==========================================================================
# rule 3 - dns_high_volume
# ==========================================================================

def _is_query_row(row: dict[str, Any]) -> bool:
    value = _as_int(row.get("is_response"))
    return value in (None, 0)


def _rule_dns_high_volume(analysis_id: str, params: dict[str, Any]) -> list[dict[str, Any]]:
    threshold = int(params["min_queries"])
    rows = _rows(
        """
        SELECT client_ip, server_ip, query_name, query_type, packet_number,
               time_epoch, is_response, response_delay
        FROM dns_queries WHERE analysis_id = ?
        """,
        (analysis_id,),
    )
    queries = [row for row in rows if _is_query_row(row)]
    if not queries:
        return []

    by_client: dict[str, list[dict[str, Any]]] = {}
    for row in queries:
        client = _as_text(row.get("client_ip"))
        if client:
            by_client.setdefault(client, []).append(row)

    findings: list[dict[str, Any]] = []
    for client, hits in sorted(by_client.items()):
        if len(hits) < threshold:
            continue
        names = [(_as_text(item.get("query_name")) or "") for item in hits]
        times = [_as_float(item.get("time_epoch")) for item in hits]
        times = [value for value in times if value is not None]
        span = (max(times) - min(times)) if len(times) >= 2 else 0.0
        rate = (len(hits) / span) if span > 0 else None
        distinctive = [name for name in names if name]
        qtypes = Counter((_as_text(item.get("query_type")) or "unknown") for item in hits)
        servers = _cap([item.get("server_ip") for item in hits], 10)
        unanswered = sum(1 for item in hits if item.get("response_delay") is None)
        top_names = _cap([name for name, _count in Counter(distinctive).most_common(5)], 5)

        findings.append(
            _finding(
                title=f"{len(hits)} DNS queries from {client}",
                key=[client],
                reason=(
                    f"Client {client} issued {len(hits)} DNS queries in this capture over "
                    f"{span:.1f} s"
                    + (f" ({rate:.1f} queries/s)" if rate else "")
                    + f" (threshold: {threshold} or more queries from one client); "
                    f"{len(set(distinctive))} distinct query names and "
                    f"{len(qtypes)} query type(s) "
                    f"({', '.join(f'{name}={count}' for name, count in sorted(qtypes.items()))}) "
                    f"were seen, and {unanswered} query(ies) had no matching response in the capture. "
                    f"Most frequent names: {', '.join(top_names) if top_names else 'none recorded'}."
                ),
                evidence={
                    "client_ip": client,
                    "query_count": len(hits),
                    "distinct_query_names": len(set(distinctive)),
                    "query_types": {name: count for name, count in sorted(qtypes.items())},
                    "unanswered": unanswered,
                    "span_seconds": round(span, 3),
                    "queries_per_second": round(rate, 3) if rate else None,
                    "first_epoch": min(times) if times else None,
                    "last_epoch": max(times) if times else None,
                    "resolvers": servers,
                    "sample_query_names": _cap(distinctive, 25),
                    "threshold": threshold,
                },
                packet_numbers=[item.get("packet_number") for item in hits],
                entities=_entities(
                    ips=[client, *servers],
                    hostnames=_cap(distinctive, MAX_ENTITY_VALUES),
                    ports=[53],
                    uris=[],
                ),
                recommendation=(
                    f"Identify the process on {client} that generated the queries (the DNS view "
                    "groups them per name) and confirm whether this volume matches its expected "
                    "behaviour. High query volume is normal for busy application servers, "
                    "vulnerability scanners and some update agents, so compare the volume against "
                    "the same host on other captures before treating it as anomalous."
                ),
            )
        )
    return findings


# ==========================================================================
# rule 4 - dns_long_labels
# ==========================================================================

def _rule_dns_long_labels(analysis_id: str, params: dict[str, Any]) -> list[dict[str, Any]]:
    max_label = int(params["max_label"])
    max_name = int(params["max_name"])
    max_findings = int(params.get("max_findings", 40))

    rows = _rows(
        """
        SELECT client_ip, query_name, packet_number, response_packet, time_epoch,
               answer_ips, rcode_name, name_length, longest_label
        FROM dns_queries WHERE analysis_id = ? AND query_name IS NOT NULL
        """,
        (analysis_id,),
    )
    if not rows:
        return []

    matches: dict[str, dict[str, Any]] = {}
    for row in rows:
        name = (_as_text(row.get("query_name")) or "").strip(".")
        if not name:
            continue
        labels = name.split(".")
        label_len = max((len(label) for label in labels), default=0)
        # Trust the persisted measurements when the DNS analyser provided them,
        # but never report less than the name itself proves.
        label_len = max(label_len, _as_int(row.get("longest_label")) or 0)
        name_len = max(len(name), _as_int(row.get("name_length")) or 0)
        if label_len < max_label and name_len < max_name:
            continue

        entry = matches.setdefault(
            name,
            {
                "name": name,
                "label_len": label_len,
                "name_len": name_len,
                "labels": len(labels),
                "clients": [],
                "packets": [],
                "answer_ips": [],
                "rcodes": Counter(),
                "times": [],
            },
        )
        entry["label_len"] = max(entry["label_len"], label_len)
        entry["name_len"] = max(entry["name_len"], name_len)
        entry["labels"] = max(entry["labels"], len(labels))
        entry["clients"].append(row.get("client_ip"))
        entry["packets"].append(row.get("response_packet") or row.get("packet_number"))
        answer = _as_text(row.get("answer_ips"))
        if answer:
            entry["answer_ips"].extend(answer.split(","))
        entry["rcodes"][_as_text(row.get("rcode_name")) or "unknown"] += 1
        moment = _as_float(row.get("time_epoch"))
        if moment is not None:
            entry["times"].append(moment)

    if not matches:
        return []

    ordered = sorted(matches.values(), key=lambda item: (-item["label_len"], item["name"]))
    truncated = len(ordered) > max_findings
    ordered = ordered[:max_findings]

    findings: list[dict[str, Any]] = []
    for entry in ordered:
        clients = _cap(entry["clients"], 10)
        answers = _cap([value.strip() for value in entry["answer_ips"]], 10)
        crossed = []
        if entry["label_len"] >= max_label:
            crossed.append(
                f"longest label {entry['label_len']} characters (threshold: >= {max_label})"
            )
        if entry["name_len"] >= max_name:
            crossed.append(
                f"total name length {entry['name_len']} characters (threshold: >= {max_name})"
            )
        findings.append(
            _finding(
                title=f"Unusually long DNS label: {entry['name'][:60]}",
                key=[entry["name"]],
                reason=(
                    f"Query name '{entry['name']}' (asked by "
                    f"{', '.join(clients) if clients else 'an unrecorded client'}) has "
                    f"{entry['labels']} label(s) and exceeds the configured shape threshold: "
                    f"{'; '.join(crossed)}. Query name length alone is not evidence of anything "
                    "malicious: long labels and long names are also common in legitimate CDN, "
                    "DKIM/DMARC, certificate-validation and telemetry domains, so treat this as a "
                    "pattern worth reviewing rather than a verdict on the domain. "
                    f"{'Answer addresses recorded: ' + ', '.join(answers) + '.' if answers else 'No answer addresses were recorded alongside this name in the indexed DNS rows.'}"
                ),
                evidence={
                    "query_name": entry["name"],
                    "longest_label": entry["label_len"],
                    "name_length": entry["name_len"],
                    "label_count": entry["labels"],
                    "clients": clients,
                    "answer_ips": answers,
                    "rcodes": {name: count for name, count in sorted(entry["rcodes"].items())},
                    "first_epoch": min(entry["times"]) if entry["times"] else None,
                    "last_epoch": max(entry["times"]) if entry["times"] else None,
                    "thresholds": {"max_label": max_label, "max_name": max_name},
                    "matches_total": len(matches),
                    "truncated": truncated,
                },
                packet_numbers=entry["packets"],
                entities=_entities(
                    ips=clients + answers,
                    hostnames=[entry["name"]],
                    ports=[53],
                    uris=[],
                ),
                recommendation=(
                    f"Resolve '{entry['name']}' again from a lab host and compare the answer with "
                    "the addresses recorded here. If the label decodes to readable text or the "
                    "answers change on every query, collect the surrounding queries from the same "
                    "client and look for a repeating pattern; if it decodes to a certificate or "
                    "DKIM selector, the name is probably legitimate."
                ),
            )
        )
    return findings


# ==========================================================================
# rule 5 - http_suspicious_path
# ==========================================================================

def _http_uri_candidates(analysis_id: str) -> dict[tuple[str, Any], dict[str, Any]]:
    """URI-bearing rows from http_transactions and packets, de-duplicated.

    Response frames repeat ``http.request.uri`` in TShark's output, so packet
    rows are restricted to frames that carry a request (``http_status`` is NULL);
    otherwise the same request would produce a second, identical finding.
    """
    candidates: dict[tuple[str, Any], dict[str, Any]] = {}

    for row in _rows(
        """
        SELECT id, stream_id, request_packet, response_packet, time_epoch, client_ip,
               server_ip, client_port, server_port, method, host, uri, full_uri, status_code
        FROM http_transactions WHERE analysis_id = ? AND uri IS NOT NULL
        """,
        (analysis_id,),
    ):
        uri = _as_text(row.get("uri"))
        if not uri:
            continue
        key = (uri, row.get("request_packet"))
        candidates.setdefault(
            key,
            {
                "uri": uri,
                "full_uri": _as_text(row.get("full_uri")),
                "host": _as_text(row.get("host")),
                "method": _as_text(row.get("method")),
                "status_code": _as_int(row.get("status_code")),
                "client_ip": _as_text(row.get("client_ip")),
                "server_ip": _as_text(row.get("server_ip")),
                "server_port": _as_int(row.get("server_port")),
                "stream_id": _as_int(row.get("stream_id")),
                "packet_number": _as_int(row.get("request_packet")) or _as_int(row.get("response_packet")),
                "time_epoch": _as_float(row.get("time_epoch")),
                "source": "http_transactions",
            },
        )

    for row in _rows(
        """
        SELECT number, time_epoch, src_ip, dst_ip, dst_port, tcp_stream, http_method,
               http_host, http_uri, http_status
        FROM packets WHERE analysis_id = ? AND http_uri IS NOT NULL
              AND http_status IS NULL
        """,
        (analysis_id,),
    ):
        uri = _as_text(row.get("http_uri"))
        if not uri:
            continue
        key = (uri, row.get("number"))
        candidates.setdefault(
            key,
            {
                "uri": uri,
                "full_uri": None,
                "host": _as_text(row.get("http_host")),
                "method": _as_text(row.get("http_method")),
                "status_code": _as_int(row.get("http_status")),
                "client_ip": _as_text(row.get("src_ip")),
                "server_ip": _as_text(row.get("dst_ip")),
                "server_port": _as_int(row.get("dst_port")),
                "stream_id": _as_int(row.get("tcp_stream")),
                "packet_number": _as_int(row.get("number")),
                "time_epoch": _as_float(row.get("time_epoch")),
                "source": "packets",
            },
        )
    return candidates


def _match_patterns(uri: str) -> tuple[list[str], list[str]]:
    """Match the suspicious-pattern list against a raw and a decoded URI."""
    decoded = unquote(uri)
    labels: list[str] = []
    categories: list[str] = []
    for pattern, label, category in SUSPICIOUS_PATTERNS:
        if pattern.search(uri) or (decoded != uri and pattern.search(decoded)):
            labels.append(label)
            categories.append(category)
    return labels, categories


def _rule_http_suspicious_path(analysis_id: str, params: dict[str, Any]) -> list[dict[str, Any]]:
    candidates = _http_uri_candidates(analysis_id)
    if not candidates:
        return []

    findings: list[dict[str, Any]] = []
    for key, item in sorted(candidates.items(), key=lambda pair: (pair[0][0], str(pair[0][1]))):
        uri = item["uri"]
        labels, categories = _match_patterns(uri)
        if not labels:
            continue

        host = item["host"]
        method = item["method"] or "request"
        packet = item["packet_number"]
        where = f"{host}{uri}" if host and not uri.startswith("http") else uri
        frame_clause = (
            f"Frame {packet} carried the request."
            if packet
            else "The carrying frame could not be determined from the indexed transactions."
        )
        findings.append(
            _finding(
                title=f"Suspicious request path: {where[:80]}",
                key=[uri, item["packet_number"], method],
                reason=(
                    f"HTTP {method} {where} matched {len(labels)} entr"
                    f"{'y' if len(labels) == 1 else 'ies'} in the configured suspicious-pattern "
                    f"list ({'; '.join(labels)}; categories: {', '.join(sorted(set(categories)))}). "
                    f"The rule fires on any match, with no numeric threshold. {frame_clause}"
                ),
                evidence={
                    "uri": uri,
                    "full_uri": item["full_uri"],
                    "host": host,
                    "method": item["method"],
                    "status_code": item["status_code"],
                    "matched_patterns": labels,
                    "categories": sorted(set(categories)),
                    "stream_id": item["stream_id"],
                    "packet_number": packet,
                    "time_epoch": item["time_epoch"],
                    "indexed_from": item["source"],
                },
                packet_numbers=[packet] if packet else [],
                entities=_entities(
                    ips=[item["client_ip"], item["server_ip"]],
                    hostnames=[host],
                    ports=[item["server_port"]],
                    uris=[uri],
                ),
                recommendation=(
                    "Confirm what the server returned for this request: a 404 or 400 is consistent "
                    "with a scanner probing paths that do not exist, whereas a 200 followed by file "
                    "contents means the path was actually served. Check the server's own access log "
                    "for the same URI and review the Objects view for any file exported from this "
                    "stream."
                ),
            )
        )
    return findings


# ==========================================================================
# rule 6 - http_cleartext_credentials
# ==========================================================================

def _parse_header_json(value: Any) -> dict[str, str]:
    if not value:
        return {}
    try:
        parsed = json.loads(value) if isinstance(value, str) else value
    except (TypeError, ValueError):
        return {}
    if not isinstance(parsed, dict):
        return {}
    return {str(key): _safe_label(val, 300) for key, val in parsed.items()}


_REDACTED = "***"


def _redact_uri(uri: str) -> str:
    """Mask the value of any sensitive query parameter in a URI.

    A credential found in plaintext must not be reproduced by the very finding
    that reports the exposure, so the value is replaced with ``***`` while the
    parameter name and the rest of the URL stay readable.
    """
    path, separator, query = uri.partition("?")
    if not separator:
        return uri
    parts: list[str] = []
    for pair in query.split("&"):
        name, equals, value = pair.partition("=")
        if equals and name.strip().lower() in SENSITIVE_FIELDS:
            parts.append(f"{name}={_REDACTED}")
        else:
            parts.append(pair)
    return f"{path}?{'&'.join(parts)}"


def _field_hits_from_query(uri: str) -> list[tuple[str, str, int | None]]:
    """(field, location, value_length) for sensitive names in the query string."""
    hits: list[tuple[str, str, int | None]] = []
    query = urlsplit(uri).query if "://" in uri else uri.partition("?")[2]
    if not query:
        return hits
    try:
        pairs = parse_qsl(query, keep_blank_values=True)
    except ValueError:  # pragma: no cover - parse_qsl is permissive
        pairs = []
    for name, value in pairs:
        key = name.strip().lower()
        if key in SENSITIVE_FIELDS:
            hits.append((name.strip(), "query string", len(value)))
    return hits


def _field_hits_from_body(body: str | None, content_type: str | None) -> list[tuple[str, str, int | None]]:
    if not body:
        return []
    hits: list[tuple[str, str, int | None]] = []
    lowered_type = (content_type or "").lower()
    looks_like_form = "form-urlencoded" in lowered_type or re.search(r"(^|&)[A-Za-z0-9_.\-]+=", body) is not None
    if looks_like_form:
        try:
            for name, value in parse_qsl(body.strip(), keep_blank_values=True):
                key = name.strip().lower()
                if key in SENSITIVE_FIELDS:
                    hits.append((name.strip(), "request body (form)", len(value)))
        except ValueError:  # pragma: no cover
            pass
    for match in re.finditer(r'"([A-Za-z0-9_.\-]{1,64})"\s*:\s*"', body):
        key = match.group(1).lower()
        if key in SENSITIVE_FIELDS:
            hits.append((match.group(1), "request body (JSON)", None))
    return hits


def _rule_http_cleartext_credentials(
    analysis_id: str, params: dict[str, Any]
) -> list[dict[str, Any]]:
    rows = _rows(
        """
        SELECT id, stream_id, request_packet, response_packet, time_epoch, client_ip,
               client_port, server_ip, server_port, method, host, uri, full_uri,
               content_type, request_body, request_body_size, request_headers,
               request_len, status_code
        FROM http_transactions WHERE analysis_id = ?
        """,
        (analysis_id,),
    )

    findings: list[dict[str, Any]] = []
    seen_uris: set[str] = set()

    for row in rows:
        uri = _as_text(row.get("uri"))
        if not uri:
            continue
        host = _as_text(row.get("host"))
        method = _as_text(row.get("method")) or "request"
        content_type = _as_text(row.get("content_type"))
        headers = _parse_header_json(row.get("request_headers"))

        hits = _field_hits_from_query(uri)
        hits += _field_hits_from_body(_as_text(row.get("request_body")), content_type)

        auth = headers.get("Authorization") or headers.get("authorization")
        if auth and auth.strip().lower().startswith("basic"):
            hits.append(("Authorization: Basic", "request header", len(auth)))

        if not hits:
            continue

        packet = _as_int(row.get("request_packet")) or _as_int(row.get("response_packet"))
        locations = _cap([location for _, location, _ in hits], 10)
        field_names = _cap([name for name, _, _ in hits], 10)
        shown_uri = _redact_uri(uri)
        described = []
        for name, location, value_len in hits[:10]:
            described.append(
                f"{name} in the {location} (value withheld"
                + (f", {value_len} characters" if value_len is not None else "")
                + ")"
            )

        findings.append(
            _finding(
                title=f"Cleartext credential field sent to {host or 'an HTTP server'}",
                key=[shown_uri, packet, tuple(sorted(field_names)), method],
                reason=(
                    f"Plaintext HTTP {method} {host or ''}{shown_uri} carried "
                    f"{len(hits)} credential-bearing field name(s) in a transaction that is not "
                    f"protected by TLS: {'; '.join(described)}. The rule fires on any sensitive "
                    "field name visible in plaintext HTTP, with no numeric threshold. "
                    + (
                        f"Frame {packet} carried the request."
                        if packet
                        else "The carrying frame could not be determined from the indexed "
                        "transactions."
                    )
                    + " The rule records the field name and the value length only; it never "
                    "reproduces the secret itself, and the value is masked in this finding."
                ),
                evidence={
                    "uri": shown_uri,
                    "uri_masked": shown_uri != uri,
                    "full_uri": _redact_uri(_as_text(row.get("full_uri")) or "") or None,
                    "host": host,
                    "method": method,
                    "status_code": _as_int(row.get("status_code")),
                    "fields": [
                        {"name": name, "location": location, "value_length": value_len}
                        for name, location, value_len in hits
                    ],
                    "request_body_size": _as_int(row.get("request_body_size")),
                    "locations": locations,
                    "stream_id": _as_int(row.get("stream_id")),
                    "packet_number": packet,
                    "time_epoch": _as_float(row.get("time_epoch")),
                    "value_withheld": True,
                },
                packet_numbers=[packet] if packet else [],
                entities=_entities(
                    ips=[_as_text(row.get("client_ip")), _as_text(row.get("server_ip"))],
                    hostnames=[host],
                    ports=[_as_int(row.get("server_port"))],
                    uris=[shown_uri],
                ),
                recommendation=(
                    f"Treat the credential sent by {_as_text(row.get('client_ip')) or 'the client'} "
                    "as exposed to anyone who could observe this segment, and rotate it if it is "
                    "still valid. Replace the cleartext endpoint with HTTPS, and check whether the "
                    "same field appears on other transactions in the HTTP view, which would show how "
                    "long the value has been travelling unencrypted."
                ),
            )
        )
        seen_uris.add(uri)

    # URIs seen only in the packet index (no http_transactions rows yet).
    for key, item in sorted(_http_uri_candidates(analysis_id).items(), key=lambda pair: pair[0][0]):
        uri = item["uri"]
        if uri in seen_uris:
            continue
        hits = _field_hits_from_query(uri)
        if not hits:
            continue
        packet = item["packet_number"]
        shown_uri = _redact_uri(uri)
        described = [
            f"{name} in the {location} (value withheld"
            + (f", {value_len} characters" if value_len is not None else "")
            + ")"
            for name, location, value_len in hits[:10]
        ]
        findings.append(
            _finding(
                title=f"Cleartext credential field in URI on {item['host'] or 'an HTTP server'}",
                key=[shown_uri, packet, tuple(sorted(name for name, _, _ in hits)), item["method"]],
                reason=(
                    f"Plaintext HTTP {item['method'] or 'request'} {item['host'] or ''}{shown_uri} "
                    f"carried {len(hits)} credential-bearing query parameter(s) in a transaction "
                    f"that is not protected by TLS: {'; '.join(described)}. The rule fires on any "
                    "sensitive field name visible in plaintext HTTP, with no numeric threshold. "
                    + (
                        f"Frame {packet} carried the request."
                        if packet
                        else "The carrying frame could not be determined from the indexed rows."
                    )
                    + " Only the field name and value length are recorded; the value itself is "
                    "never reproduced and is masked in this finding."
                ),
                evidence={
                    "uri": shown_uri,
                    "uri_masked": shown_uri != uri,
                    "host": _as_text(item["host"]),
                    "method": item["method"],
                    "fields": [
                        {"name": name, "location": location, "value_length": value_len}
                        for name, location, value_len in hits
                    ],
                    "stream_id": item["stream_id"],
                    "packet_number": packet,
                    "time_epoch": item["time_epoch"],
                    "indexed_from": item["source"],
                    "value_withheld": True,
                },
                packet_numbers=[packet] if packet else [],
                entities=_entities(
                    ips=[item["client_ip"], item["server_ip"]],
                    hostnames=[item["host"]],
                    ports=[item["server_port"]],
                    uris=[shown_uri],
                ),
                recommendation=(
                    "Confirm whether this request reached a real service and rotate the value if it "
                    "is still valid. Moving the parameter into a POST body would not help: the "
                    "transport is what exposes it, so the endpoint needs HTTPS."
                ),
            )
        )

    return findings


# ==========================================================================
# rule 7 - outbound_volume
# ==========================================================================

def _sender_volumes(analysis_id: str) -> tuple[list[dict[str, Any]], str]:
    """Bytes sent per source host, from the packet index (''hosts'' fallback)."""
    rows = _rows(
        """
        SELECT src_ip AS ip, COUNT(*) AS packets, COALESCE(SUM(frame_len), 0) AS bytes
        FROM packets WHERE analysis_id = ? AND src_ip IS NOT NULL
        GROUP BY src_ip ORDER BY bytes DESC
        """,
        (analysis_id,),
    )
    if rows:
        return rows, "packets"

    fallback = _rows(
        """
        SELECT ip, packets_sent AS packets, bytes_sent AS bytes
        FROM hosts WHERE analysis_id = ? AND bytes_sent > 0
        ORDER BY bytes_sent DESC
        """,
        (analysis_id,),
    )
    return fallback, "hosts" if fallback else "none"


def _rule_outbound_volume(analysis_id: str, params: dict[str, Any]) -> list[dict[str, Any]]:
    max_bytes = int(params["max_bytes"])
    multiplier = float(params["median_multiplier"])
    senders, source_table = _sender_volumes(analysis_id)
    senders = [row for row in senders if _as_int(row.get("bytes"))]
    if not senders:
        return []

    volumes = [int(_as_int(row["bytes"]) or 0) for row in senders]
    median = float(statistics.median(volumes))
    count = len(senders)
    median_branch_possible = count >= 2 and median > 0

    findings: list[dict[str, Any]] = []
    for row in senders:
        ip = _as_text(row.get("ip"))
        sent = int(_as_int(row.get("bytes")) or 0)
        packets = int(_as_int(row.get("packets")) or 0)
        if not ip or sent <= 0:
            continue

        absolute_crossed = sent >= max_bytes
        ratio = (sent / median) if median > 0 else None
        median_crossed = bool(median_branch_possible and ratio is not None and ratio >= multiplier)
        if not (absolute_crossed or median_crossed):
            continue

        crossed = []
        uncrossed = []
        if absolute_crossed:
            crossed.append(f"absolute volume {_mb(sent):.1f} MB >= {max_bytes / (1024 * 1024):g} MB")
        else:
            uncrossed.append(f"absolute volume {_mb(sent):.1f} MB < {max_bytes / (1024 * 1024):g} MB")
        if median_crossed:
            crossed.append(f"{ratio:.1f}x the median sender volume >= {multiplier:g}x")
        elif median_branch_possible:
            uncrossed.append(f"{ratio:.1f}x the median sender volume < {multiplier:g}x")

        per_sender = _cap(
            [
                f"{_as_text(item.get('ip'))}={int(_as_int(item.get('bytes')) or 0)} bytes"
                for item in senders[:5]
            ],
            5,
        )
        top_dst = _rows(
            """
            SELECT dst_ip, COUNT(*) AS packets, COALESCE(SUM(frame_len), 0) AS bytes
            FROM packets WHERE analysis_id = ? AND src_ip = ? AND dst_ip IS NOT NULL
            GROUP BY dst_ip ORDER BY bytes DESC LIMIT 5
            """,
            (analysis_id, ip),
        )
        dst_ips = [_as_text(item.get("dst_ip")) for item in top_dst]
        dst_ports = _rows(
            """
            SELECT dst_port, COUNT(*) AS packets FROM packets
            WHERE analysis_id = ? AND src_ip = ? AND dst_port IS NOT NULL
            GROUP BY dst_port ORDER BY packets DESC LIMIT 10
            """,
            (analysis_id, ip),
        )
        numbers = [
            item["number"]
            for item in _rows(
                """
                SELECT number FROM packets WHERE analysis_id = ? AND src_ip = ?
                ORDER BY number LIMIT ?
                """,
                (analysis_id, ip, MAX_PACKET_NUMBERS),
            )
        ]

        findings.append(
            _finding(
                title=f"High outbound volume from {ip} ({_mb(sent):.1f} MB)",
                key=[ip],
                reason=(
                    f"Host {ip} sent {sent:,} bytes ({_mb(sent):.1f} MB) across {packets:,} packets, "
                    f"which is {ratio:.1f}x the median sender volume of {int(median):,} bytes over "
                    f"{count} sending host(s) in this capture "
                    f"(thresholds: {max_bytes / (1024 * 1024):g} MB absolute, or {multiplier:g}x the "
                    f"median with at least 2 senders). Crossed: {'; '.join(crossed)}. "
                    f"Not crossed: {'; '.join(uncrossed) if uncrossed else 'nothing else applied'}. "
                    f"Volumes came from the {source_table} table; the largest peer was "
                    f"{dst_ips[0] if dst_ips else 'not recorded'}."
                ),
                evidence={
                    "ip": ip,
                    "bytes_sent": sent,
                    "packets_sent": packets,
                    "median_sender_bytes": int(median),
                    "sender_count": count,
                    "ratio_to_median": round(ratio, 3) if ratio is not None else None,
                    "absolute_threshold_crossed": absolute_crossed,
                    "median_threshold_crossed": median_crossed,
                    "thresholds": {"max_bytes": max_bytes, "median_multiplier": multiplier},
                    "volume_source": source_table,
                    "top_destinations": [
                        {
                            "dst_ip": _as_text(item.get("dst_ip")),
                            "packets": int(_as_int(item.get("packets")) or 0),
                            "bytes": int(_as_int(item.get("bytes")) or 0),
                        }
                        for item in top_dst
                    ],
                    "top_senders": per_sender,
                },
                packet_numbers=numbers,
                entities=_entities(
                    ips=[ip, *dst_ips],
                    hostnames=[],
                    ports=[_as_int(item.get("dst_port")) for item in dst_ports],
                    uris=[],
                ),
                recommendation=(
                    f"Confirm what service on {ip} produced this volume by opening the host detail "
                    "view and reading the destination breakdown. Large uploads are also produced by "
                    "backups, telemetry, software distribution and legitimate file transfers, so "
                    "compare the destination addresses and ports against the host's normal role, and "
                    "check whether the transfer is encrypted and continuous or a single burst."
                ),
            )
        )
    return findings


# ==========================================================================
# rule 8 - rare_destination_port
# ==========================================================================

def _rule_rare_destination_port(analysis_id: str, params: dict[str, Any]) -> list[dict[str, Any]]:
    max_findings = int(params.get("max_findings", 40))
    configured = params.get("common_ports")
    common = (
        frozenset(_as_int(value) for value in configured if _as_int(value) is not None)
        if isinstance(configured, list) and configured
        else COMMON_PORTS
    )

    summary = _rows(
        """
        SELECT dst_port, COUNT(*) AS frames FROM packets
        WHERE analysis_id = ? AND dst_port IS NOT NULL
        GROUP BY dst_port
        """,
        (analysis_id,),
    )
    if not summary:
        return []

    distinct_ports = len(summary)
    rare_ports = sorted(
        int(_as_int(row["dst_port"]) or 0)
        for row in summary
        if int(_as_int(row["frames"]) or 0) == 1 and int(_as_int(row["dst_port"]) or 0) not in common
    )
    if not rare_ports:
        return []

    matches_total = len(rare_ports)
    selected = rare_ports[:max_findings]

    findings: list[dict[str, Any]] = []
    for start in range(0, len(selected), 400):
        chunk = selected[start : start + 400]
        placeholders = ",".join("?" for _ in chunk)
        rows = _rows(
            f"""
            SELECT number, time_epoch, src_ip, dst_ip, dst_port, transport, protocol
            FROM packets
            WHERE analysis_id = ? AND dst_port IN ({placeholders})
            ORDER BY number
            """,
            (analysis_id, *chunk),
        )
        for row in rows:
            port = int(_as_int(row["dst_port"]) or 0)
            transport = (_as_text(row.get("transport")) or "unknown").upper()
            protocol = _as_text(row.get("protocol")) or transport
            src = _as_text(row.get("src_ip"))
            dst = _as_text(row.get("dst_ip"))
            moment = _as_float(row.get("time_epoch"))
            findings.append(
                _finding(
                    title=f"Single-use destination port {port}",
                    key=[port, _as_int(row.get("number"))],
                    reason=(
                        f"Destination port {port} ({transport}) was observed in exactly 1 frame in "
                        f"this capture, out of {distinct_ports} distinct destination ports seen "
                        f"(threshold: a port seen only once and absent from the "
                        f"{len(common)}-entry known-common port list). The frame was "
                        f"{src or 'an unrecorded source'} -> {dst or 'an unrecorded destination'} "
                        f"(packet {_as_int(row.get('number'))}"
                        + (f", epoch {moment:.3f}" if moment is not None else "")
                        + f"), dissected as {protocol}. A single observation carries little weight on "
                        "its own; it matters as context next to other findings."
                    ),
                    evidence={
                        "destination_port": port,
                        "transport": _as_text(row.get("transport")),
                        "protocol": protocol,
                        "frames_on_port": 1,
                        "distinct_destination_ports_in_capture": distinct_ports,
                        "common_port_list_size": len(common),
                        "frame": _as_int(row.get("number")),
                        "time_epoch": moment,
                        "source_ip": src,
                        "destination_ip": dst,
                        "matches_total": matches_total,
                        "truncated": matches_total > len(selected),
                    },
                    packet_numbers=[row.get("number")],
                    entities=_entities(
                        ips=[src, dst],
                        hostnames=[],
                        ports=[port],
                        uris=[],
                    ),
                    recommendation=(
                        f"Confirm whether port {port} is expected on {dst or 'the destination'}: "
                        "check the host's service inventory, then look at the Conversations view for "
                        "the same stream to see what the peer sent back. Ports used only once are "
                        "usually harmless (a short-lived service, an ephemeral listener, a scanner "
                        "probe) but they are worth ruling out."
                    ),
                )
            )
    return findings


# ==========================================================================
# rule 9 - repeated_failed_connections
# ==========================================================================

def _rule_repeated_failed_connections(
    analysis_id: str, params: dict[str, Any]
) -> list[dict[str, Any]]:
    min_syn = int(params["min_syn"])
    sql = """
        SELECT number, time_epoch, src_ip, dst_ip, dst_port, tcp_flags_raw, tcp_flags
        FROM packets
        WHERE analysis_id = ? AND transport = 'tcp' AND dst_ip IS NOT NULL
              AND dst_port IS NOT NULL
        ORDER BY dst_ip, dst_port, number
    """

    findings: list[dict[str, Any]] = []
    key: tuple[str, int] | None = None
    group: list[dict[str, Any]] = []

    def flush() -> None:
        nonlocal group, key
        if not group or key is None:
            group = []
            return

        dst_ip, dst_port = key
        frames = group
        group = []

        syns = [item for item in frames if _is_syn_only(item["flags"])]
        syn_acks = [item for item in frames if _is_syn_ack(item["flags"])]
        resets = [item for item in frames if _is_rst(item["flags"])]
        if len(syns) < min_syn or syn_acks:
            return

        sources = _cap([item["src_ip"] for item in syns], 10)
        times = [item["time_epoch"] for item in syns if item["time_epoch"] is not None]
        span = (max(times) - min(times)) if len(times) >= 2 else 0.0
        if resets:
            interpretation = (
                f"{len(resets)} RST frame(s) came back, which is consistent with the destination "
                "port being closed rather than filtered."
            )
        else:
            interpretation = (
                "No reply of any kind was captured, which is consistent with the destination "
                "filtering, rate-limiting, or dropping the attempts."
            )

        findings.append(
            _finding(
                title=f"{len(syns)} unanswered TCP SYNs to {dst_ip}:{dst_port}",
                key=[dst_ip, dst_port],
                reason=(
                    f"{', '.join(sources) if sources else 'An unrecorded source'} sent {len(syns)} "
                    f"TCP SYN frames to {dst_ip}:{dst_port} and 0 SYN/ACK frames were observed for "
                    f"that destination port in this capture "
                    f"(threshold: {min_syn} or more SYNs with no SYN/ACK). The attempts span "
                    f"{span:.1f} s"
                    + (
                        f" from epoch {min(times):.3f} to {max(times):.3f}. "
                        if times
                        else ". "
                    )
                    + interpretation
                ),
                evidence={
                    "destination_ip": dst_ip,
                    "destination_port": dst_port,
                    "syn_only_frames": len(syns),
                    "syn_ack_frames": 0,
                    "rst_frames": len(resets),
                    "sources": sources,
                    "span_seconds": round(span, 3),
                    "first_epoch": min(times) if times else None,
                    "last_epoch": max(times) if times else None,
                    "threshold": min_syn,
                },
                packet_numbers=[item["number"] for item in syns],
                entities=_entities(
                    ips=[*sources, dst_ip],
                    hostnames=[],
                    ports=[dst_port],
                    uris=[],
                ),
                recommendation=(
                    f"Check whether {dst_ip}:{dst_port} should be reachable from "
                    f"{sources[0] if sources else 'the source'}: a wrong port, a blocked firewall "
                    "rule, a service that was moved, and a client retrying after a timeout all look "
                    "like this. Compare the timestamps with the host's own logs to see which process "
                    "was retrying."
                ),
            )
        )

    for row in _stream(sql, (analysis_id,)):
        dst_ip = _as_text(row["dst_ip"])
        dst_port = _as_int(row["dst_port"])
        if dst_ip is None or dst_port is None:
            continue
        current = (dst_ip, dst_port)
        if current != key:
            flush()
            key = current
            group = []
        group.append(
            {
                "number": row["number"],
                "time_epoch": _as_float(row["time_epoch"]),
                "src_ip": _as_text(row["src_ip"]),
                "flags": parse_tcp_flags(row["tcp_flags_raw"], row["tcp_flags"]),
            }
        )
    flush()

    return findings


# ==========================================================================
# rule 10 - indicator_match
# ==========================================================================

def _indicator_rows(analysis_id: str) -> list[dict[str, Any]]:
    rows = _rows(
        """
        SELECT id, analysis_id, type, value, note, created_at
        FROM indicators WHERE analysis_id IS NULL OR analysis_id = ?
        ORDER BY id
        """,
        (analysis_id,),
    )
    out = []
    for row in rows:
        value = _as_text(row.get("value"))
        kind = (_as_text(row.get("type")) or "").lower()
        if value and kind:
            out.append({**row, "value": value, "type": kind})
    return out


def _match_indicator(analysis_id: str, kind: str, value: str) -> dict[str, Any] | None:
    """Return a match summary for one indicator, or ``None`` when nothing matched."""
    if kind == "ip":
        row = db.query_one(
            """
            SELECT COUNT(*) AS total,
                   SUM(CASE WHEN src_ip = ? THEN 1 ELSE 0 END) AS as_source,
                   SUM(CASE WHEN dst_ip = ? THEN 1 ELSE 0 END) AS as_destination,
                   MIN(number) AS first_packet, MIN(time_epoch) AS first_epoch
            FROM packets WHERE analysis_id = ? AND (src_ip = ? OR dst_ip = ?)
            """,
            (value, value, analysis_id, value, value),
        )
        total = _as_int(row["total"]) if row else 0
        if not total:
            return None
        numbers = [
            item["number"]
            for item in _rows(
                "SELECT number FROM packets WHERE analysis_id = ? AND (src_ip = ? OR dst_ip = ?) "
                "ORDER BY number LIMIT ?",
                (analysis_id, value, value, MAX_PACKET_NUMBERS),
            )
        ]
        peers = _rows(
            """
            SELECT peer, COUNT(*) AS hits FROM (
                SELECT CASE WHEN src_ip = ? THEN dst_ip ELSE src_ip END AS peer
                FROM packets WHERE analysis_id = ? AND (src_ip = ? OR dst_ip = ?)
            ) WHERE peer IS NOT NULL GROUP BY peer ORDER BY hits DESC LIMIT 10
            """,
            (value, analysis_id, value, value),
        )
        peers_list = [_as_text(item["peer"]) for item in peers]
        return {
            "rows_matched": int(total),
            "where": "packets (src_ip/dst_ip)",
            "detail": {
                "frames": int(total),
                "frames_as_source": int(_as_int(row["as_source"]) or 0),
                "frames_as_destination": int(_as_int(row["as_destination"]) or 0),
            },
            "packet_numbers": numbers,
            "first_epoch": _as_float(row["first_epoch"]),
            "entities": _entities(ips=[value, *peers_list], ports=[], hostnames=[], uris=[]),
        }

    if kind == "domain":
        suffix = f"%.{value.lower()}"
        dns_rows = _rows(
            """
            SELECT query_name, client_ip, packet_number, response_packet, time_epoch, rcode_name,
                   CASE WHEN LOWER(query_name) = ? THEN 'exact' ELSE 'suffix' END AS kind
            FROM dns_queries
            WHERE analysis_id = ? AND (LOWER(query_name) = ? OR LOWER(query_name) LIKE ?)
            ORDER BY time_epoch LIMIT ?
            """,
            (value.lower(), analysis_id, value.lower(), suffix, MAX_PACKET_NUMBERS),
        )
        http_rows = _rows(
            """
            SELECT host, uri, method, client_ip, server_ip, request_packet, response_packet, time_epoch
            FROM http_transactions
            WHERE analysis_id = ? AND host IS NOT NULL
                  AND (LOWER(host) = ? OR LOWER(host) LIKE ?)
            ORDER BY time_epoch LIMIT ?
            """,
            (analysis_id, value.lower(), suffix, MAX_PACKET_NUMBERS),
        )
        tls_rows = _rows(
            """
            SELECT sni, client_ip, server_ip, client_packet, server_packet, time_epoch
            FROM tls_sessions
            WHERE analysis_id = ? AND sni IS NOT NULL
                  AND (LOWER(sni) = ? OR LOWER(sni) LIKE ?)
            ORDER BY time_epoch LIMIT ?
            """,
            (analysis_id, value.lower(), suffix, MAX_PACKET_NUMBERS),
        )
        total = len(dns_rows) + len(http_rows) + len(tls_rows)
        if not total:
            return None

        hostnames = _cap(
            [item.get("query_name") for item in dns_rows]
            + [item.get("host") for item in http_rows]
            + [item.get("sni") for item in tls_rows],
            MAX_ENTITY_VALUES,
        )
        ips = _cap(
            [item.get("client_ip") for item in dns_rows]
            + [item.get("server_ip") for item in dns_rows]
            + [item.get("client_ip") for item in http_rows]
            + [item.get("server_ip") for item in http_rows]
            + [item.get("client_ip") for item in tls_rows]
            + [item.get("server_ip") for item in tls_rows],
            MAX_ENTITY_VALUES,
        )
        uris = _cap([item.get("uri") for item in http_rows], MAX_ENTITY_VALUES)
        detail = {
            "dns_queries": len(dns_rows),
            "http_transactions": len(http_rows),
            "tls_sessions": len(tls_rows),
            "match_kind": sorted({item["kind"] for item in dns_rows}) or ["suffix-or-exact"],
            "sample_names": hostnames[:10],
        }
        return {
            "rows_matched": total,
            "where": "dns_queries.query_name, http_transactions.host, tls_sessions.sni",
            "detail": detail,
            "packet_numbers": [item.get("packet_number") or item.get("response_packet") for item in dns_rows]
            + [item.get("request_packet") or item.get("response_packet") for item in http_rows]
            + [item.get("client_packet") or item.get("server_packet") for item in tls_rows],
            "first_epoch": min(
                [
                    value_
                    for value_ in [_as_float(item.get("time_epoch")) for item in (*dns_rows, *http_rows, *tls_rows)]
                    if value_ is not None
                ],
                default=None,
            ),
            "entities": _entities(ips=ips, hostnames=hostnames, ports=[], uris=uris),
        }

    if kind == "port":
        port = _as_int(value)
        if port is None:
            return None
        row = db.query_one(
            """
            SELECT COUNT(*) AS total, MIN(number) AS first_packet, MIN(time_epoch) AS first_epoch
            FROM packets WHERE analysis_id = ? AND (dst_port = ? OR src_port = ?)
            """,
            (analysis_id, port, port),
        )
        total = _as_int(row["total"]) if row else 0
        if not total:
            return None
        numbers = [
            item["number"]
            for item in _rows(
                "SELECT number FROM packets WHERE analysis_id = ? AND (dst_port = ? OR src_port = ?) "
                "ORDER BY number LIMIT ?",
                (analysis_id, port, port, MAX_PACKET_NUMBERS),
            )
        ]
        peers = _rows(
            """
            SELECT ip, COUNT(*) AS hits FROM (
                SELECT CASE WHEN dst_port = ? THEN src_ip ELSE dst_ip END AS ip
                FROM packets WHERE analysis_id = ? AND (dst_port = ? OR src_port = ?)
            ) WHERE ip IS NOT NULL GROUP BY ip ORDER BY hits DESC LIMIT 10
            """,
            (port, analysis_id, port, port),
        )
        return {
            "rows_matched": int(total),
            "where": "packets (src_port/dst_port)",
            "detail": {"frames": int(total), "port": port},
            "packet_numbers": numbers,
            "first_epoch": _as_float(row["first_epoch"]),
            "entities": _entities(
                ips=[_as_text(item["ip"]) for item in peers], ports=[port], hostnames=[], uris=[]
            ),
        }

    if kind in {"ja3", "ja4"}:
        column = {"ja3": "ja3", "ja4": "ja4"}[kind]
        rows = _rows(
            f"""
            SELECT sni, client_ip, server_ip, client_packet, server_packet, time_epoch, {column} AS fp
            FROM tls_sessions WHERE analysis_id = ? AND LOWER(COALESCE({column}, '')) = ?
            ORDER BY time_epoch LIMIT ?
            """,
            (analysis_id, value.lower(), MAX_PACKET_NUMBERS),
        )
        if not rows:
            ja3s = _rows(
                """
                SELECT sni, client_ip, server_ip, client_packet, server_packet, time_epoch, ja3s AS fp
                FROM tls_sessions WHERE analysis_id = ? AND LOWER(COALESCE(ja3s, '')) = ?
                ORDER BY time_epoch LIMIT ?
                """,
                (analysis_id, value.lower(), MAX_PACKET_NUMBERS),
            )
            rows = ja3s
        if not rows:
            return None
        snis = _cap([item.get("sni") for item in rows], MAX_ENTITY_VALUES)
        return {
            "rows_matched": len(rows),
            "where": f"tls_sessions.{column}",
            "detail": {
                "sessions": len(rows),
                "snis": snis[:10],
                "fingerprint": value,
            },
            "packet_numbers": [
                item.get("client_packet") or item.get("server_packet") for item in rows
            ],
            "first_epoch": min(
                [
                    moment
                    for moment in (_as_float(item.get("time_epoch")) for item in rows)
                    if moment is not None
                ],
                default=None,
            ),
            "entities": _entities(
                ips=_cap(
                    [item.get("client_ip") for item in rows] + [item.get("server_ip") for item in rows],
                    MAX_ENTITY_VALUES,
                ),
                hostnames=snis,
                ports=[443],
                uris=[],
            ),
        }

    if kind == "ua":
        rows = _rows(
            """
            SELECT host, uri, method, client_ip, server_ip, request_packet, response_packet,
                   time_epoch, user_agent
            FROM http_transactions
            WHERE analysis_id = ? AND user_agent IS NOT NULL AND LOWER(user_agent) = ?
            ORDER BY time_epoch LIMIT ?
            """,
            (analysis_id, value.lower(), MAX_PACKET_NUMBERS),
        )
        if not rows:
            return None
        return {
            "rows_matched": len(rows),
            "where": "http_transactions.user_agent",
            "detail": {
                "transactions": len(rows),
                "hosts": _cap([item.get("host") for item in rows], 10),
                "user_agent": value,
            },
            "packet_numbers": [
                item.get("request_packet") or item.get("response_packet") for item in rows
            ],
            "first_epoch": min(
                [
                    moment
                    for moment in (_as_float(item.get("time_epoch")) for item in rows)
                    if moment is not None
                ],
                default=None,
            ),
            "entities": _entities(
                ips=_cap(
                    [item.get("client_ip") for item in rows] + [item.get("server_ip") for item in rows],
                    MAX_ENTITY_VALUES,
                ),
                hostnames=_cap([item.get("host") for item in rows], MAX_ENTITY_VALUES),
                ports=[80],
                uris=_cap([item.get("uri") for item in rows], MAX_ENTITY_VALUES),
            ),
        }

    if kind == "sha256":
        rows = _rows(
            """
            SELECT id, analysis_id, filename, size, stream_id, src_ip, dst_ip, protocol,
                   packet_numbers, created_at
            FROM objects WHERE analysis_id = ? AND LOWER(COALESCE(sha256, '')) = ?
            """,
            (analysis_id, value.lower()),
        )
        if not rows:
            return None
        numbers: list[Any] = []
        for item in rows:
            try:
                parsed = json.loads(item.get("packet_numbers") or "[]")
            except (TypeError, ValueError):
                parsed = []
            if isinstance(parsed, list):
                numbers.extend(parsed)
        return {
            "rows_matched": len(rows),
            "where": "objects.sha256",
            "detail": {
                "objects": [
                    {
                        "object_id": _as_text(item.get("id")),
                        "filename": _as_text(item.get("filename")),
                        "size": _as_int(item.get("size")),
                    }
                    for item in rows[:10]
                ],
                "sha256": value.lower(),
            },
            "packet_numbers": numbers,
            "first_epoch": min(
                [
                    moment
                    for moment in (_as_float(item.get("created_at")) for item in rows)
                    if moment is not None
                ],
                default=None,
            ),
            "entities": _entities(
                ips=_cap(
                    [item.get("src_ip") for item in rows] + [item.get("dst_ip") for item in rows],
                    MAX_ENTITY_VALUES,
                ),
                hostnames=_cap([item.get("filename") for item in rows], MAX_ENTITY_VALUES),
                ports=[],
                uris=[],
            ),
        }

    return None


def _rule_indicator_match(analysis_id: str, params: dict[str, Any]) -> list[dict[str, Any]]:
    indicators = _indicator_rows(analysis_id)
    if not indicators:
        return []

    supported = {"ip", "domain", "port", "ja3", "ja4", "ua", "sha256"}
    findings: list[dict[str, Any]] = []
    for indicator in indicators[:MAX_FINDINGS_PER_RULE]:
        kind = indicator["type"]
        value = indicator["value"]
        if kind not in supported:
            log.info("indicator %s has unsupported type %r", indicator.get("id"), kind)
            continue

        match = _match_indicator(analysis_id, kind, value)
        if match is None:
            continue

        scope = "analysis" if indicator.get("analysis_id") else "global"
        shown = _safe_label(value, 200)
        first_epoch = match.get("first_epoch")
        findings.append(
            _finding(
                title=f"Indicator match: {kind} {shown[:60]}",
                key=[int(_as_int(indicator.get("id")) or 0), kind, value],
                reason=(
                    f"Analyst indicator #{_as_int(indicator.get('id'))} ({scope}, type {kind}, "
                    f"value '{shown}') matched {match['rows_matched']} record(s) in this capture in "
                    f"{match['where']}. Detail: "
                    f"{'; '.join(f'{key}={val}' for key, val in match['detail'].items() if not isinstance(val, list))}"
                    + (
                        f". The earliest match is at epoch {first_epoch:.3f}."
                        if isinstance(first_epoch, float)
                        else "."
                    )
                    + " The value was supplied by an analyst rather than derived from traffic "
                    "behaviour, so this is a lead to review: confirm the match resolves to the same "
                    "entity the indicator was collected from before acting on it."
                ),
                evidence={
                    "indicator_id": _as_int(indicator.get("id")),
                    "indicator_scope": scope,
                    "indicator_type": kind,
                    "indicator_value": shown,
                    "indicator_note": _safe_label(indicator.get("note"), 300),
                    "matched_table": match["where"],
                    "rows_matched": match["rows_matched"],
                    "detail": match["detail"],
                    "first_epoch": first_epoch,
                },
                packet_numbers=match["packet_numbers"],
                entities=match["entities"],
                recommendation=(
                    f"Confirm that the {kind} '{shown[:80]}' still belongs to the same infrastructure "
                    "it was collected from (addresses and domains change hands), then pivot into the "
                    "views named in the matched table above and check whether the surrounding "
                    "traffic matches the behaviour the indicator was collected for."
                ),
            )
        )
    return findings


# ==========================================================================
# registry
# ==========================================================================

RULES: dict[str, RuleSpec] = {
    spec.rule_id: spec
    for spec in (
        RuleSpec(
            rule_id="tcp_syn_scan",
            title="Possible TCP SYN scan",
            severity="high",
            description=(
                "One source contacted many distinct destination ports in a short window using "
                "SYN-only frames, which is the shape of a port scan. Port scanning is also normal "
                "behaviour for vulnerability scanners, inventory agents, monitoring probes and "
                "administrator troubleshooting, so the finding identifies a lead to attribute to a "
                "known system rather than a conclusion about intent."
            ),
            threshold=(
                "{max_ports} or more distinct destination ports from one source within {window_s:g} s, "
                "with at least {syn_ratio:.0%} of the frames in that window SYN-only"
            ),
            defaults={"max_ports": 20, "window_s": 10.0, "syn_ratio": 0.8},
            run=_rule_tcp_syn_scan,
        ),
        RuleSpec(
            rule_id="dns_nxdomain_burst",
            title="Burst of NXDOMAIN DNS responses",
            severity="medium",
            description=(
                "A client received several NXDOMAIN answers, meaning the queried names do not exist. "
                "That is consistent with a typo, a stale application configuration, a client "
                "retrying a bad hostname, or a domain-generation / typo-squatting lookup pattern. "
                "It is not by itself evidence of malicious activity."
            ),
            threshold="{min_nxdomain} or more NXDOMAIN responses for one client",
            defaults={"min_nxdomain": 5},
            run=_rule_dns_nxdomain_burst,
        ),
        RuleSpec(
            rule_id="dns_high_volume",
            title="High DNS query volume from one client",
            severity="low",
            description=(
                "A single client issued an unusually large number of DNS queries. Busy servers, "
                "software update agents, monitoring systems and vulnerability scanners legitimately "
                "produce high query volumes, so the count is only meaningful next to the host's "
                "expected role and baseline."
            ),
            threshold="{min_queries} or more DNS queries from one client",
            defaults={"min_queries": 100},
            run=_rule_dns_high_volume,
        ),
        RuleSpec(
            rule_id="dns_long_labels",
            title="Unusually long DNS label or name",
            severity="medium",
            description=(
                "A query name contains a very long label or exceeds a long total length. Long labels "
                "appear in DNS tunnelling and in data-encoding abuse, but they are equally common in "
                "legitimate content-delivery, DKIM/DMARC, certificate-validation and telemetry "
                "domains. The pattern is reported for review, never as a verdict about the domain."
            ),
            threshold="any label >= {max_label} characters, or any query name >= {max_name} characters",
            defaults={"max_label": 40, "max_name": 100, "max_findings": 40},
            run=_rule_dns_long_labels,
            notes=(
                "Long labels are also common in legitimate CDN, DKIM and telemetry domains; the "
                "reason string says so explicitly."
            ),
        ),
        RuleSpec(
            rule_id="http_suspicious_path",
            title="Suspicious HTTP request path",
            severity="medium",
            description=(
                "A request path matched a curated list of patterns seen in path traversal, web shell "
                "access, command injection, SQL injection and exposed-metadata probes. Matching "
                "proves only that the string was requested; whether the server acted on it depends "
                "on the response, which the recommendation tells the analyst to check."
            ),
            threshold="any match in the configured suspicious-pattern list",
            defaults={"enabled": True},
            run=_rule_http_suspicious_path,
        ),
        RuleSpec(
            rule_id="http_cleartext_credentials",
            title="Credential field sent over plaintext HTTP",
            severity="high",
            description=(
                "A request carried a credential-bearing field name (password, token, api_key and "
                "similar) inside HTTP, so the value would be readable by anyone able to observe the "
                "path. Applications do still use cleartext endpoints, and a test or internal "
                "credential may be involved, but the exposure itself is real and worth remediating. "
                "The rule records field names and value lengths and never reproduces the secret."
            ),
            threshold="a sensitive field name (password, token, api_key, ...) visible in plaintext HTTP",
            defaults={"enabled": True},
            run=_rule_http_cleartext_credentials,
        ),
        RuleSpec(
            rule_id="outbound_volume",
            title="High outbound traffic volume from one host",
            severity="medium",
            description=(
                "One host sent far more traffic than the rest of the capture, which is the shape "
                "large uploads take. Backups, telemetry, software distribution and legitimate file "
                "transfers produce the same shape, so the finding is only actionable once the "
                "destination and the host's role are known."
            ),
            threshold=(
                "{max_mb:g} MB sent by one host, or {median_multiplier:g}x the median sender volume "
                "with at least 2 senders"
            ),
            defaults={
                "max_bytes": DEFAULT_MAX_BYTES,
                "max_mb": DEFAULT_MAX_BYTES / (1024 * 1024),
                "median_multiplier": 10.0,
            },
            run=_rule_outbound_volume,
        ),
        RuleSpec(
            rule_id="rare_destination_port",
            title="Destination port used only once",
            severity="informational",
            description=(
                "A destination port appeared in exactly one frame of the capture and is not in the "
                "known-common list. A single observation is weak evidence and is recorded as context "
                "next to stronger findings rather than as an anomaly on its own."
            ),
            threshold="a destination port seen exactly once in the capture, outside the known-common port list",
            defaults={"max_findings": 40, "common_ports": None},
            run=_rule_rare_destination_port,
        ),
        RuleSpec(
            rule_id="repeated_failed_connections",
            title="Repeated connection attempts with no reply",
            severity="medium",
            description=(
                "A host sent many TCP SYNs to the same destination port and no SYN/ACK was captured. "
                "That is consistent with a closed or filtered port, a service that moved, a wrong "
                "port in a configuration file, or an aggressive connection retry. A RST reply means "
                "the port is reachable but closed; the absence of any reply points at filtering."
            ),
            threshold="{min_syn} or more TCP SYN frames to one destination port with no SYN/ACK",
            defaults={"min_syn": 10},
            run=_rule_repeated_failed_connections,
        ),
        RuleSpec(
            rule_id="indicator_match",
            title="Traffic matching an analyst-supplied indicator",
            severity="high",
            description=(
                "Traffic in this capture matched a value an analyst entered as an indicator of "
                "interest. The match is a statement about identity, not about intent: the value may "
                "be stale, shared, or belong to a legitimate service, so the analyst has to confirm "
                "the entity is the one the indicator was collected from."
            ),
            threshold="traffic matching an analyst-supplied indicator (ip, domain, port, ja3, ja4, ua, sha256)",
            defaults={"enabled": True},
            run=_rule_indicator_match,
        ),
    )
}

RULE_ORDER: tuple[str, ...] = tuple(RULES)


# ==========================================================================
# configuration
# ==========================================================================

def default_config() -> dict[str, dict[str, Any]]:
    """Every rule with ``enabled`` plus its documented default thresholds."""
    config: dict[str, dict[str, Any]] = {}
    for rule_id, spec in RULES.items():
        entry: dict[str, Any] = {"enabled": True}
        entry.update(spec.defaults)
        config[rule_id] = entry
    return config


def _coerce_rule_config(rule_id: str, raw: Any, base: dict[str, Any]) -> dict[str, Any]:
    spec = RULES[rule_id]
    merged = dict(base)
    if not isinstance(raw, dict):
        if raw is not None:
            log.warning("detection_config[%s] must be an object; using defaults", rule_id)
        return merged

    for key, value in raw.items():
        if key == "enabled":
            merged["enabled"] = bool(value)
            continue
        if key not in spec.defaults:
            log.warning("ignoring unknown detection_config key %s.%s", rule_id, key)
            continue
        if key == "common_ports":
            if isinstance(value, list):
                merged[key] = value
            elif value is None:
                merged[key] = None
            else:
                log.warning("detection_config[%s].common_ports must be a list", rule_id)
            continue

        reference = spec.defaults[key]
        if isinstance(reference, bool):
            merged[key] = bool(value)
        elif isinstance(reference, int):
            number = _as_int(value)
            if number is None or number <= 0:
                log.warning("detection_config[%s].%s must be a positive integer", rule_id, key)
            else:
                merged[key] = number
        elif isinstance(reference, float):
            number = _as_float(value)
            if number is None or number <= 0:
                log.warning("detection_config[%s].%s must be a positive number", rule_id, key)
            else:
                merged[key] = float(number)
        else:
            merged[key] = value

    # ``max_mb`` is a human-facing mirror of ``max_bytes``: it is always derived,
    # never trusted from storage, so a stale JSON value cannot misreport the limit.
    if rule_id == "outbound_volume":
        bytes_value = _as_int(merged.get("max_bytes"))
        if bytes_value:
            merged["max_mb"] = bytes_value / (1024 * 1024)
    return merged


def load_config() -> dict[str, dict[str, Any]]:
    """Default configuration merged with the ``detection_config`` settings row."""
    config = default_config()
    try:
        row = db.query_one("SELECT value FROM settings WHERE key = ?", (CONFIG_KEY,))
    except sqlite3.Error as exc:  # pragma: no cover - defensive
        log.warning("could not read detection_config: %s", exc)
        return config

    if row is None or not row["value"]:
        return config

    try:
        stored = json.loads(row["value"])
    except (TypeError, ValueError) as exc:
        log.warning("detection_config is not valid JSON (%s); using defaults", exc)
        return config

    if not isinstance(stored, dict):
        log.warning("detection_config must be a JSON object; using defaults")
        return config

    for rule_id, raw in stored.items():
        if rule_id not in RULES:
            log.warning("ignoring unknown rule id %r in detection_config", rule_id)
            continue
        config[rule_id] = _coerce_rule_config(rule_id, raw, config[rule_id])
    return config


def save_config(config: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """Validate, persist and return the effective configuration.

    The submitted object is merged over the **currently effective** configuration
    rather than over the built-in defaults, so a partial update (for example
    disabling one rule) cannot silently reset the thresholds another update set.
    """
    effective = load_config()
    if isinstance(config, dict):
        for rule_id, raw in config.items():
            if rule_id not in RULES:
                log.warning("ignoring unknown rule id %r in detection_config", rule_id)
                continue
            effective[rule_id] = _coerce_rule_config(rule_id, raw, effective[rule_id])

    with db.get_conn() as conn:
        conn.execute(
            """
            INSERT INTO settings (key, value, updated_at) VALUES (?, ?, ?)
            ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at
            """,
            (CONFIG_KEY, _json(effective), time.time()),
        )
    log.info("saved detection configuration for %d rules", len(effective))
    return load_config()


def list_rules(analysis_id: str | None = None) -> list[dict[str, Any]]:
    """Rule metadata for the UI, with hit counts when an analysis is given."""
    config = load_config()
    hits: Counter[str] = Counter()
    if analysis_id:
        for row in _rows(
            "SELECT rule_id, COUNT(*) AS hits FROM findings WHERE analysis_id = ? GROUP BY rule_id",
            (analysis_id,),
        ):
            hits[_as_text(row.get("rule_id")) or ""] = int(_as_int(row.get("hits")) or 0)

    items: list[dict[str, Any]] = []
    for rule_id, spec in RULES.items():
        params = config.get(rule_id, {})
        items.append(
            {
                "id": rule_id,
                "rule_id": rule_id,
                "title": spec.title,
                "severity": spec.severity,
                # severity is fixed by the rule definition, never per finding
                "description": spec.description,
                "enabled": bool(params.get("enabled", True)),
                "threshold": spec.threshold_text(params),
                "thresholds": {
                    key: value for key, value in params.items() if key != "enabled"
                },
                "defaults": dict(spec.defaults),
                "notes": spec.notes,
                "hits": int(hits.get(rule_id, 0)),
            }
        )
    return items


# ==========================================================================
# entry point
# ==========================================================================

FINDING_INSERT = """
    INSERT OR REPLACE INTO findings
        (id, analysis_id, rule_id, severity, title, description, reason, evidence,
         packet_numbers, entities, recommendation, created_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
"""


def _persist(analysis_id: str, rows: list[dict[str, Any]], created_at: float) -> int:
    if not rows:
        return 0
    payload = [
        (
            row["id"],
            analysis_id,
            row["rule_id"],
            row["severity"],
            row["title"],
            row["description"],
            row["reason"],
            _json(row["evidence"]),
            _json(row["packet_numbers"]),
            _json(row["entities"]),
            row["recommendation"],
            created_at,
        )
        for row in rows
    ]
    with db.get_conn() as conn:
        conn.executemany(FINDING_INSERT, payload)
    return len(payload)


def analyze(ctx: Any, analysis_id: str, capture_path: Path) -> dict:
    """Run every enabled rule and persist its findings.

    Returns counters suitable for logging::

        {"findings": n, "by_severity": {...}, "rules_run": n, ...}
    """
    started = time.monotonic()
    config = load_config()
    created_at = time.time()

    if ctx is not None:
        # Cancellation must propagate: JobCancelled derives from RuntimeError, so
        # it is deliberately raised outside the progress-writing try block.
        ctx.check_cancelled()
        try:
            ctx.set_stage("Loading detection thresholds", 0.0)
        except Exception:  # pragma: no cover - progress plumbing must not fail us
            log.debug("could not publish detection stage; continuing")

    # Clearing first keeps reruns idempotent; each rule then writes its own rows.
    try:
        with db.get_conn() as conn:
            conn.execute("DELETE FROM findings WHERE analysis_id = ?", (analysis_id,))
    except sqlite3.Error as exc:
        log.error("could not clear previous findings for %s: %s", analysis_id, exc)
        raise

    by_severity: Counter[str] = Counter({name: 0 for name in SEVERITIES})
    rules_run = 0
    rules_enabled = 0
    rule_errors: dict[str, str] = {}
    total = 0

    for index, (rule_id, spec) in enumerate(RULES.items()):
        params = config.get(rule_id, {})
        if not params.get("enabled", True):
            log.debug("rule %s disabled by configuration", rule_id)
            continue

        rules_enabled += 1
        if ctx is not None:
            ctx.check_cancelled()
            try:
                ctx.set_stage(
                    f"Running detection rule {rule_id}",
                    100.0 * index / max(len(RULES), 1),
                )
            except Exception:  # pragma: no cover - progress plumbing must not fail us
                log.debug("could not publish stage for rule %s", rule_id)

        try:
            raw_findings = spec.run(analysis_id, params)
        except Exception as exc:  # a broken rule must never fail the pipeline
            log.exception("detection rule %s failed: %s", rule_id, exc)
            rule_errors[rule_id] = f"{type(exc).__name__}: {exc}"
            continue

        rules_run += 1
        if not raw_findings:
            log.debug("rule %s produced no findings", rule_id)
            continue

        if len(raw_findings) > MAX_FINDINGS_PER_RULE:
            log.info(
                "rule %s produced %d findings; keeping the first %d",
                rule_id,
                len(raw_findings),
                MAX_FINDINGS_PER_RULE,
            )
            raw_findings = raw_findings[:MAX_FINDINGS_PER_RULE]

        finalised = [_finalise(spec, analysis_id, item) for item in raw_findings]

        # Guard against two keys collapsing onto one id inside a single run.
        deduped: dict[str, dict[str, Any]] = {}
        for row in finalised:
            deduped.setdefault(row["id"], row)

        try:
            written = _persist(analysis_id, list(deduped.values()), created_at)
        except sqlite3.Error as exc:
            log.exception("could not persist findings for rule %s: %s", rule_id, exc)
            rule_errors[rule_id] = f"{type(exc).__name__}: {exc}"
            continue

        total += written
        for row in deduped.values():
            by_severity[row["severity"]] += 1
        log.info("rule %s produced %d finding(s)", rule_id, written)

    elapsed = time.monotonic() - started
    stats = {
        "findings": total,
        "by_severity": {name: by_severity[name] for name in SEVERITIES},
        "rules_run": rules_run,
        "rules_enabled": rules_enabled,
        "rules_total": len(RULES),
        "rules_skipped": len(RULES) - rules_enabled,
        "rule_errors": rule_errors,
        "seconds": round(elapsed, 3),
        "capture_present": bool(capture_path and Path(capture_path).exists()),
    }
    log.info(
        "detection finished for %s: %d findings (%s) across %d rule(s) in %.2fs",
        analysis_id,
        total,
        ", ".join(f"{name}={count}" for name, count in stats["by_severity"].items()),
        rules_run,
        elapsed,
    )
    return stats


__all__ = [
    "COMMON_PORTS",
    "CONFIG_KEY",
    "InlineJobContext",
    "MAX_FINDINGS_PER_RULE",
    "MAX_PACKET_NUMBERS",
    "RULES",
    "RULE_ORDER",
    "SEVERITIES",
    "SEVERITY_RANK",
    "SENSITIVE_FIELDS",
    "SUSPICIOUS_PATTERNS",
    "analyze",
    "default_config",
    "finding_id",
    "list_rules",
    "load_config",
    "parse_tcp_flags",
    "save_config",
]
