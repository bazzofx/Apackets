"""DNS analysis.

One row per DNS **query**, with the matching response merged into the same row.
Queries are matched to responses on the transaction id (``dns.id``) plus the
observed client/server address pair, taking the first response that appears after
the query in capture order. An unanswered query keeps ``response_packet`` NULL —
no response is ever invented.

Everything is derived from a single streaming TShark field pass; the row flags are
investigative leads (long labels, high entropy, NXDOMAIN, …) and never verdicts.
"""

from __future__ import annotations

import json
import math
import sqlite3
import time
from dataclasses import dataclass, field
from pathlib import Path

from app.core.config import settings
from app.core.logging import get_logger
from app.db import database as db
from app.services import tshark
from app.services.jobs import JobContext

log = get_logger("shadowpackets.dns")

# Field order of the INSERT below — keep the two in sync.
COLUMNS: tuple[str, ...] = (
    "analysis_id",
    "dns_id",
    "time_epoch",
    "packet_number",
    "response_packet",
    "response_time",
    "response_delay",
    "client_ip",
    "server_ip",
    "query_name",
    "query_type",
    "is_response",
    "rcode",
    "rcode_name",
    "answers",
    "answer_ips",
    "cnames",
    "min_ttl",
    "authoritative",
    "truncated",
    "name_length",
    "label_count",
    "longest_label",
    "entropy",
    "flags",
)

# ``dns.ttl`` does not exist in TShark 4.6.8; the per-resource-record TTL is
# ``dns.resp.ttl`` (verified with ``tshark -G fields``).
_TSHARK_FIELDS: tuple[str, ...] = (
    "frame.number",
    "frame.time_epoch",
    "dns.id",
    "dns.flags.response",
    "dns.flags.rcode",
    "dns.qry.name",
    "dns.qry.type",
    "dns.a",
    "dns.aaaa",
    "dns.cname",
    "dns.resp.ttl",
    "ip.src",
    "ip.dst",
    "dns.flags.authoritative",
    "dns.flags.truncated",
    "dns.count.answers",
)

INSERT_SQL = (
    f"INSERT INTO dns_queries ({', '.join(COLUMNS)}) "
    f"VALUES ({', '.join('?' for _ in COLUMNS)})"
)

BATCH_SIZE = 1000
CANCEL_EVERY = 5000
FIELD_SEPARATOR = ","  # aggregator for repeated values (never inside these values)

RCODE_NAMES = {
    0: "NOERROR",
    1: "FORMERR",
    2: "SERVFAIL",
    3: "NXDOMAIN",
    4: "NOTIMP",
    5: "REFUSED",
}

# Numeric dns.qry.type -> IANA mnemonic (TShark emits the number with -T fields).
QTYPE_NAMES = {
    1: "A", 2: "NS", 3: "MD", 4: "MF", 5: "CNAME", 6: "SOA", 7: "MB", 8: "MG",
    9: "MR", 10: "NULL", 11: "WKS", 12: "PTR", 13: "HINFO", 14: "MINFO", 15: "MX",
    16: "TXT", 17: "RP", 18: "AFSDB", 19: "X25", 20: "ISDN", 21: "RT", 22: "NSAP",
    23: "NSAP-PTR", 24: "SIG", 25: "KEY", 26: "PX", 27: "GPOS", 28: "AAAA",
    29: "LOC", 30: "NXT", 31: "EID", 32: "NIMLOC", 33: "SRV", 34: "ATMA",
    35: "NAPTR", 36: "KX", 37: "CERT", 38: "A6", 39: "DNAME", 40: "SINK",
    41: "OPT", 42: "APL", 43: "DS", 44: "SSHFP", 45: "IPSECKEY", 46: "RRSIG",
    47: "NSEC", 48: "DNSKEY", 49: "DHCID", 50: "NSEC3", 51: "NSEC3PARAM",
    52: "TLSA", 53: "SMIMEA", 55: "HIP", 56: "NINFO", 57: "RKEY", 58: "TALINK",
    59: "CDS", 60: "CDNSKEY", 61: "OPENPGPKEY", 62: "CSYNC", 63: "ZONEMD",
    64: "SVCB", 65: "HTTPS", 99: "SPF", 100: "UINFO", 101: "UID", 102: "GID",
    103: "UNSPEC", 104: "NID", 105: "L32", 106: "L64", 107: "LP", 108: "EUI48",
    109: "EUI64", 249: "TKEY", 250: "TSIG", 251: "IXFR", 252: "AXFR", 253: "MAILB",
    254: "MAILA", 255: "ANY", 256: "URI", 257: "CAA", 258: "AVC", 259: "DOA",
    260: "AMTRELAY", 261: "RESINFO", 32768: "TA", 32769: "DLV",
}

LONG_LABEL = 40
LONG_NAME = 100
HIGH_ENTROPY = 3.8
MANY_IPS = 4


@dataclass
class DnsRecord:
    """One TShark row: either a query or a response."""

    packet: int
    time_epoch: float | None
    dns_id: int | None
    is_response: bool
    rcode: int | None
    query_name: str | None
    query_type: str | None
    addresses: list[str] = field(default_factory=list)
    cnames: list[str] = field(default_factory=list)
    ttls: list[int] = field(default_factory=list)
    src_ip: str | None = None
    dst_ip: str | None = None
    authoritative: bool | None = None
    truncated: bool | None = None
    answer_count: int | None = None


@dataclass
class DnsQueryRow:
    """A persisted ``dns_queries`` row, still mutable while merging."""

    dns_id: int | None
    time_epoch: float | None
    packet_number: int
    client_ip: str | None
    server_ip: str | None
    query_name: str
    query_type: str | None
    response_packet: int | None = None
    response_time: float | None = None
    response_delay: float | None = None
    rcode: int | None = None
    answers: list[dict] = field(default_factory=list)
    answer_ips: list[str] = field(default_factory=list)
    cnames: list[str] = field(default_factory=list)
    min_ttl: int | None = None
    authoritative: int | None = None
    truncated: int | None = None
    flags: list[str] = field(default_factory=list)


# --------------------------------------------------------------------------
# parsing helpers (a malformed value is skipped, never fatal)
# --------------------------------------------------------------------------

def _split(value: str | None) -> list[str]:
    if not value:
        return []
    return [part.strip() for part in value.split(FIELD_SEPARATOR) if part.strip()]


def _int(value: str | None) -> int | None:
    if value is None or not value.strip():
        return None
    try:
        return int(value.strip(), 0)
    except ValueError:
        try:
            return int(float(value.strip()))
        except ValueError:
            return None


def _float(value: str | None) -> float | None:
    if value is None or not value.strip():
        return None
    try:
        return float(value.strip())
    except ValueError:
        return None


def _bool(value: str | None) -> bool | None:
    """TShark prints boolean fields as ``True``/``False``."""
    if value is None:
        return None
    text = value.strip().lower()
    if text in {"true", "1"}:
        return True
    if text in {"false", "0"}:
        return False
    return None


def _first(value: str | None) -> str | None:
    parts = _split(value)
    return parts[0] if parts else None


def rcode_name(rcode: int | None) -> str | None:
    """``0`` -> ``NOERROR`` … ``RCODE_<n>`` for anything not in the IANA table."""
    if rcode is None:
        return None
    if rcode in RCODE_NAMES:
        return RCODE_NAMES[rcode]
    return f"RCODE_{rcode}"


def query_type_name(raw: str | None) -> str | None:
    """TShark gives ``dns.qry.type`` as a number; map it to its mnemonic."""
    value = _first(raw)
    if value is None:
        return None
    number = _int(value)
    if number is None:
        return value  # already a display string
    return QTYPE_NAMES.get(number, f"TYPE{number}")


def shannon_entropy(text: str) -> float:
    """Shannon entropy (base 2) over the characters of ``text``."""
    if not text:
        return 0.0
    counts: dict[str, int] = {}
    for char in text:
        counts[char] = counts.get(char, 0) + 1
    total = len(text)
    entropy = 0.0
    for count in counts.values():
        probability = count / total
        entropy -= probability * math.log2(probability)
    return round(entropy, 2)


def name_stats(name: str) -> tuple[int, int, int, float]:
    """``(name_length, label_count, longest_label, entropy)`` for a query name."""
    labels = [label for label in name.split(".") if label]
    longest = max((len(label) for label in labels), default=0)
    return len(name), len(labels), longest, shannon_entropy("".join(labels))


def lead_flags(row: DnsQueryRow, query_type: str | None) -> list[str]:
    """Investigative leads derived from the observed fields only."""
    flags: list[str] = []
    if row.response_packet is None:
        flags.append("unanswered")
    if row.rcode == 3:
        flags.append("nxdomain")
    if row.rcode == 2:
        flags.append("servfail")
    _, label_count, longest, entropy = name_stats(row.query_name)
    if longest >= LONG_LABEL:
        flags.append("long_label")
    if len(row.query_name) >= LONG_NAME:
        flags.append("long_name")
    if entropy > HIGH_ENTROPY and label_count >= 3:
        flags.append("high_entropy")
    if len(set(row.answer_ips)) >= MANY_IPS:
        flags.append("many_ips")
    if (query_type or "").upper() == "TXT":
        flags.append("txt_record")
    return flags


def _build_record(fields: list[str]) -> DnsRecord | None:
    if len(fields) < len(_TSHARK_FIELDS):
        fields = [*fields, *([""] * (len(_TSHARK_FIELDS) - len(fields)))]

    (
        number, time_epoch, dns_id, is_response, rcode, qname, qtype,
        a_records, aaaa_records, cnames, ttls, src_ip, dst_ip,
        authoritative, truncated, answer_count,
    ) = fields[: len(_TSHARK_FIELDS)]

    packet = _int(number)
    if packet is None:
        return None

    response_flag = _bool(is_response)
    name = _first(qname)
    if response_flag is None and not name:
        return None  # not a DNS packet at all

    record = DnsRecord(
        packet=packet,
        time_epoch=_float(time_epoch),
        dns_id=_int(dns_id),
        is_response=bool(response_flag),
        rcode=_int(rcode),
        query_name=name,
        query_type=query_type_name(qtype),
        addresses=[*_split(a_records), *_split(aaaa_records)],
        cnames=_split(cnames),
        ttls=[ttl for ttl in (_int(v) for v in _split(ttls)) if ttl is not None],
        src_ip=_first(src_ip),
        dst_ip=_first(dst_ip),
        authoritative=_bool(authoritative),
        truncated=_bool(truncated),
        answer_count=_int(answer_count),
    )
    return record


def _merge_response(query: DnsQueryRow, response: DnsRecord) -> None:
    query.response_packet = response.packet
    query.response_time = response.time_epoch
    if response.time_epoch is not None and query.time_epoch is not None:
        query.response_delay = round(response.time_epoch - query.time_epoch, 6)
    query.rcode = response.rcode
    query.answer_ips = list(dict.fromkeys(response.addresses))
    query.cnames = list(dict.fromkeys(response.cnames))
    query.min_ttl = min(response.ttls) if response.ttls else None
    query.authoritative = None if response.authoritative is None else int(response.authoritative)
    query.truncated = None if response.truncated is None else int(response.truncated)
    query.answers = [
        {"type": "A" if ip.count(":") == 0 else "AAAA", "value": ip}
        for ip in query.answer_ips
    ] + [{"type": "CNAME", "value": name} for name in query.cnames]


def build_rows(records: list[DnsRecord], *, max_rows: int | None = None) -> list[DnsQueryRow]:
    """Turn query/response records into merged rows, in capture order."""
    rows: list[DnsQueryRow] = []
    # (dns_id, client, server) -> index of the first still-unanswered query row
    pending: dict[tuple[int | None, str | None, str | None], list[int]] = {}

    for record in records:
        if record.is_response:
            pair = (record.dns_id, record.dst_ip, record.src_ip)
            candidates = pending.get(pair)
            if not candidates:
                continue  # a response whose query was not observed: no row to merge into
            index = candidates.pop(0)
            if not candidates:
                pending.pop(pair, None)
            _merge_response(rows[index], record)
            continue

        if not record.query_name:
            continue
        row = DnsQueryRow(
            dns_id=record.dns_id,
            time_epoch=record.time_epoch,
            packet_number=record.packet,
            client_ip=record.src_ip,
            server_ip=record.dst_ip,
            query_name=record.query_name,
            query_type=record.query_type,
        )
        rows.append(row)
        pending.setdefault((record.dns_id, record.src_ip, record.dst_ip), []).append(len(rows) - 1)
        if max_rows is not None and len(rows) >= max_rows:
            break

    return rows


def to_sql_row(analysis_id: str, row: DnsQueryRow) -> tuple:
    name_length, label_count, longest_label, entropy = name_stats(row.query_name)
    query_type = row.query_type
    answers = json.dumps(row.answers, separators=(",", ":")) if row.answers else None
    return (
        analysis_id,
        row.dns_id,
        row.time_epoch,
        row.packet_number,
        row.response_packet,
        row.response_time,
        row.response_delay,
        row.client_ip,
        row.server_ip,
        row.query_name,
        query_type,
        0,  # is_response: this row represents the query
        row.rcode,
        rcode_name(row.rcode),
        answers,
        ",".join(row.answer_ips) if row.answer_ips else None,
        ",".join(row.cnames) if row.cnames else None,
        row.min_ttl,
        row.authoritative,
        row.truncated,
        name_length,
        label_count,
        longest_label,
        entropy,
        json.dumps(lead_flags(row, query_type), separators=(",", ":")),
    )


def collect(records: list[DnsRecord], *, max_rows: int | None = None) -> list[DnsQueryRow]:
    """Public helper: merge records into query rows (used by tests)."""
    return build_rows(records, max_rows=max_rows)


# --------------------------------------------------------------------------
# entry point
# --------------------------------------------------------------------------

def analyze(ctx: JobContext, analysis_id: str, capture_path: Path) -> dict:
    """Extract DNS queries from ``capture_path`` and persist them."""
    started = time.monotonic()
    ctx.set_stage("Analyzing DNS")

    with db.get_conn() as conn:
        conn.execute("DELETE FROM dns_queries WHERE analysis_id = ?", (analysis_id,))

    records: list[DnsRecord] = []
    scanned = 0
    for fields in tshark.stream_fields(
        capture_path,
        _TSHARK_FIELDS,
        display_filter="dns",
        occurrence="a",
        aggregator=FIELD_SEPARATOR,
        cancel_event=ctx.cancel_event,
    ):
        scanned += 1
        try:
            record = _build_record(fields)
        except Exception as exc:  # a malformed row must never abort the analysis
            log.debug("skipping malformed dns row: %s", exc)
            record = None
        if record is not None:
            records.append(record)
        if scanned % CANCEL_EVERY == 0:
            ctx.check_cancelled()
            ctx.set_stage(f"Analyzing DNS ({scanned:,} packets)")

    ctx.check_cancelled()

    max_rows = getattr(settings, "max_dns_rows", 0) or None
    rows = build_rows(records, max_rows=max_rows)

    conn: sqlite3.Connection = db.connect()
    inserted = 0
    try:
        conn.execute("BEGIN")
        buffer: list[tuple] = []
        for row in rows:
            buffer.append(to_sql_row(analysis_id, row))
            if len(buffer) >= BATCH_SIZE:
                conn.executemany(INSERT_SQL, buffer)
                inserted += len(buffer)
                buffer.clear()
                conn.commit()
                conn.execute("BEGIN")
                ctx.check_cancelled()
        if buffer:
            conn.executemany(INSERT_SQL, buffer)
            inserted += len(buffer)
            buffer.clear()
        conn.commit()
    finally:
        conn.close()

    counters = _counters(analysis_id, inserted)
    elapsed = time.monotonic() - started
    log.info("dns analysis for %s: %s in %.1fs", analysis_id, counters, elapsed)
    return {**counters, "dns_packets_scanned": scanned, "seconds": round(elapsed, 2)}


def _counters(analysis_id: str, total: int) -> dict:
    row = db.query_one(
        """
        SELECT
            SUM(CASE WHEN response_packet IS NOT NULL THEN 1 ELSE 0 END) AS answered,
            SUM(CASE WHEN rcode = 3 THEN 1 ELSE 0 END)                  AS nxdomain,
            SUM(CASE WHEN response_packet IS NULL THEN 1 ELSE 0 END)    AS unanswered,
            SUM(CASE WHEN flags IS NOT NULL AND flags <> '[]' THEN 1 ELSE 0 END) AS flagged
        FROM dns_queries
        WHERE analysis_id = ?
        """,
        (analysis_id,),
    )
    data = dict(row) if row else {}
    return {
        "dns_queries": total,
        "dns_responses": int(data.get("answered") or 0),
        "dns_nxdomain": int(data.get("nxdomain") or 0),
        "dns_unanswered": int(data.get("unanswered") or 0),
        "dns_flagged": int(data.get("flagged") or 0),
    }


__all__ = [
    "COLUMNS",
    "DnsQueryRow",
    "DnsRecord",
    "analyze",
    "build_rows",
    "collect",
    "lead_flags",
    "name_stats",
    "query_type_name",
    "rcode_name",
    "shannon_entropy",
    "to_sql_row",
]
