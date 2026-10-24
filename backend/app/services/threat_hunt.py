"""Threat Hunt indicator engine.

One entry point, :func:`analyze`, turns the rows ShadowPackets already indexed for an
analysis into the indicator envelope described in ``docs/THREAT_HUNT.md`` §3.

Everything here is a SQL aggregate over ``packets``, ``conversations``,
``dns_queries``, ``http_transactions``, ``tls_sessions``, ``hosts`` and
``findings``. No capture is re-read and TShark is never invoked, so the section
stays fast and keeps working after an upload has been purged.

Two rules govern every number in this module:

* it is measured, never estimated — a detection that cannot be computed for a
  capture reports ``availability: "not_applicable"`` with the reason, and one
  that is computable but finds nothing reports ``"empty"`` plus the threshold
  that was applied. ``headline.value`` is therefore ``0`` only when the
  availability is not ``"ok"``, so a zero on screen always means "nothing
  matched" rather than "not computed";
* an indicator is a lead, not a verdict — every indicator carries a ``caveat``
  naming what its pattern does *not* establish.

Internal/external and unicast/multicast decisions come from
:mod:`app.services.host_analyzer` (``is_private_address`` for the private/public
split, ``address_scope`` to keep multicast, broadcast and loopback out of the
egress counts), and the well-known-port list is the detection engine's own
:data:`~app.services.detection_engine.COMMON_PORTS`, so this section cannot
drift from the findings it sits next to.
"""

from __future__ import annotations

import re
import json
import math
import statistics
import time
from dataclasses import dataclass, field
from typing import Any, Iterable, Sequence
from urllib.parse import quote

from app.core.logging import get_logger
from app.db import database as db
from app.services.detection_engine import COMMON_PORTS
from app.services.host_analyzer import address_scope, is_private_address

log = get_logger("shadowpackets.threat_hunt")

# --------------------------------------------------------------------------
# caps and thresholds
# --------------------------------------------------------------------------

# §4: bars and heatmap cap rows at `top`, timeline at 240 buckets, table at 50
# rows, scatter at 200 points.
TIMELINE_CAP = 240
TABLE_CAP = 50
SCATTER_CAP = 200

# Every packet-level query is bounded so a pathological capture cannot make the
# endpoint unbounded; the cap is reported in the visual's note when it bites.
PACKET_SCAN_CAP = 20000
ROW_SCAN_CAP = 500

# Beaconing: a flow must repeat often enough for an interval to mean anything,
# and its intervals must be steady.
BEACON_MIN_FLOWS = 4
BEACON_MIN_INTERVAL = 5.0
BEACON_MAX_CV = 0.35

# Scanning: the documented tcp_syn_scan threshold (CONTRACT §8).
SCAN_PORT_SPAN = 10.0
SCAN_MIN_PORTS = 20

# A host-discovery sweep is the same idea measured over destination hosts: the
# addresses one source probed that never answered it. Measured on this library,
# a source that legitimately reaches many hosts in ten seconds has every one of
# them reply (43 of 43 on sf19us-MTA-lab-01), while an `nmap -sn` sweep of a
# local /24 probed 255 addresses and heard back from 11.
SCAN_HOST_SPAN = 10.0
SCAN_HOST_MIN = 20

# ARP discovery: the probed address survives only in TShark's summary line, because
# an ARP frame carries no IP layer for the indexer to read. The two shapes are
# `Who has <ip>? Tell <ip>` for a request and `<ip> is at <mac>` for a reply.
_ARP_REQUEST = re.compile(r"Who has (\d+\.\d+\.\d+\.\d+)\? Tell (\d+\.\d+\.\d+\.\d+)")
_ARP_REPLY = re.compile(r"^(\d+\.\d+\.\d+\.\d+) is at ")
_ICMP_REQUEST = "Echo (ping) request"

# DNS: the documented dns_nxdomain_burst / dns_high_volume thresholds.
DNS_NXDOMAIN_MIN = 5
DNS_VOLUME_MIN = 100
DNS_FLAGGED_MIN = 3

# Exfiltration / staging: a byte volume is only interesting in bulk.
EXFIL_MIN_BYTES = 1_000_000
EXFIL_RELATIVE_BYTES = 100_000
EXFIL_RELATIVE_FACTOR = 10
STAGING_MIN_BYTES = 1_000_000

# Fan-out: distinct peers before a host counts as high fan-out.
FAN_OUT_MIN_PEERS = 10

# Rare pairs: one conversation, essentially no payload.
RARE_PAIR_MAX_PACKETS = 2

# Bursts: a bucket must both depart from the capture's own baseline and be
# large enough to matter on its own.
BURST_SIGMAS = 3.0
BURST_MIN_PACKETS = 20

# Repeated failures: the documented repeated_failed_connections threshold.
FAILED_MIN_ATTEMPTS = 10

# Tunnelling: many machine-generated names under one domain, from one client.
TUNNEL_MIN_NAMES = 5
TUNNEL_MIN_QUERIES = 10
TUNNEL_MIN_LABEL = 10.0
TUNNEL_MIN_ENTROPY = 3.6

LATERAL_PORTS: dict[int, str] = {
    22: "SSH",
    23: "Telnet",
    111: "rpcbind",
    135: "MS RPC",
    139: "NetBIOS session",
    445: "SMB",
    512: "rexec",
    513: "rlogin",
    514: "rsh",
    1433: "MSSQL",
    1521: "Oracle TNS",
    2049: "NFS",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    5985: "WinRM HTTP",
    5986: "WinRM HTTPS",
    6379: "Redis",
    27017: "MongoDB",
}

# Ports an endpoint is expected to reach out to. Egress on anything else is
# reported as unusual — it is not by itself suspicious.
STANDARD_EGRESS_PORTS: frozenset[int] = frozenset(
    {20, 21, 25, 53, 80, 110, 123, 143, 389, 443, 465, 587, 636, 993, 995, 8080, 8443, 5222, 5228}
)

DANGEROUS_EXTENSIONS: frozenset[str] = frozenset(
    {
        "exe", "dll", "scr", "com", "pif", "bat", "cmd", "ps1", "vbs", "vbe", "js", "jse",
        "wsf", "hta", "cpl", "jar", "msi", "msp", "apk", "bin", "elf", "sh", "run", "lnk",
    }
)

# ``js`` is ubiquitous on the web and is deliberately NOT treated as a payload
# on its own; the executable/script list above is used with a name check that
# keeps bare ``.js`` out of the download indicator.
DANGEROUS_EXTENSIONS_STRICT: frozenset[str] = DANGEROUS_EXTENSIONS - {"js", "sh", "bin"}

DANGEROUS_CONTENT_TYPES: tuple[str, ...] = (
    "application/x-msdownload",
    "application/x-msdos-program",
    "application/x-dosexec",
    "application/vnd.microsoft.portable-executable",
    "application/x-executable",
    "application/x-elf",
    "application/java-archive",
    "application/x-msi",
    "application/x-sh",
    "application/x-bat",
    "application/x-powershell",
    "application/x-msmetafile",
)

# DNS lead flags that mean "this name looks machine-generated or failed".
STRONG_DNS_FLAGS: tuple[str, ...] = (
    "nxdomain",
    "servfail",
    "long_label",
    "long_name",
    "high_entropy",
    "txt_record",
)

PAGE_NOTE = (
    "Every figure on this page is an aggregate over the index ShadowPackets built from this "
    "capture — packets, conversations, DNS, HTTP, TLS, hosts and findings. The capture "
    "itself is not re-read, so the page keeps working after the upload has been purged. "
    "An indicator is a lead to investigate, not a verdict: each one states the threshold "
    "it applied and what its pattern does not prove. Where the index cannot answer a "
    "question at all, the indicator says so instead of showing a zero."
)

FAILED_REASON = "internal error while computing this indicator from the index"

# --------------------------------------------------------------------------
# small helpers
# --------------------------------------------------------------------------


def _to(path: str, **params: Any) -> str:
    """A link target built only from the parameters listed in §5.

    Every interpolated value is percent-encoded the way ``encodeURIComponent``
    would encode it, so an address, stream id, host name or URI cannot break out
    of the query string.
    """
    clean = {key: value for key, value in params.items() if value is not None and value != ""}
    if not clean:
        return path
    query = "&".join(f"{key}={quote(str(value), safe='')}" for key, value in clean.items())
    return f"{path}?{query}"


def _link(path: str, label: str) -> dict:
    return {"to": path, "label": label}


def _cap_note(shown: int, total: int, noun: str = "rows") -> str:
    """§4: a cap that bites is stated as ``top N of M``."""
    if total > shown:
        return f"top {shown} of {total} {noun}"
    return ""


def _bucket_index(value: float, window: int) -> int:
    return int(math.floor(float(value) / float(window)))


def _series(
    events: Iterable[tuple[float | None, float]],
    window: int,
    cap: int = TIMELINE_CAP,
) -> tuple[list[dict], int]:
    """Bucket ``(timestamp, weight)`` pairs into a timeline, oldest first."""
    buckets: dict[int, float] = {}
    for moment, weight in events:
        if moment is None:
            continue
        index = _bucket_index(moment, window)
        buckets[index] = buckets.get(index, 0.0) + weight
    ordered = sorted(buckets.items())
    total = len(ordered)
    points = [
        {"t": float(index * window), "value": _number(value), "marker": False}
        for index, value in ordered[:cap]
    ]
    return points, total


def _number(value: float) -> float | int:
    if isinstance(value, float) and value.is_integer():
        return int(value)
    return value


def _json_list(raw: Any) -> list:
    if isinstance(raw, list):
        return raw
    if not isinstance(raw, str) or not raw.strip():
        return []
    try:
        parsed = json.loads(raw)
    except (TypeError, ValueError):
        return []
    return parsed if isinstance(parsed, list) else []


def _flag_tokens(raw: Any) -> list[str]:
    """The lead flags stored on a row, split down to their prefix token."""
    tokens: list[str] = []
    for value in _json_list(raw):
        token = str(value).split(":", 1)[0].strip()
        if token:
            tokens.append(token)
    return tokens


def _flags_like_sql(column: str, tokens: Sequence[str]) -> tuple[str, list[Any]]:
    clause = " OR ".join(f"{column} LIKE ?" for _ in tokens)
    return f"({clause})", [f'%"{token}"%' for token in tokens]


def _extension(value: Any) -> str:
    text = str(value or "").strip().lower()
    text = text.split("?", 1)[0].split("#", 1)[0]
    name = text.rstrip("/").rsplit("/", 1)[-1]
    if "." not in name:
        return ""
    return name.rsplit(".", 1)[-1]


def _private(value: Any) -> bool:
    return is_private_address(value) == 1


def _is_public_unicast(value: Any) -> bool:
    """True only for a routable address: multicast/broadcast/loopback are not egress."""
    return address_scope(value) == "public"


def _mean(values: Sequence[float]) -> float:
    return float(statistics.fmean(values)) if values else 0.0


def _bucket_label(value: float, edges: Sequence[tuple[float, str]]) -> str:
    for limit, label in edges:
        if value < limit:
            return label
    return edges[-1][1]


# --------------------------------------------------------------------------
# indicator assembly
# --------------------------------------------------------------------------


def _visual(kind: str, title: str, **payload: Any) -> dict:
    visual = {"kind": kind, "title": title}
    visual.update(payload)
    visual.setdefault("note", "")
    return visual


def _bars(title: str, items: list[dict], unit: str, note: str = "") -> dict:
    return _visual("bars", title, items=items, unit=unit, note=note)


def _timeline(title: str, points: list[dict], unit: str, note: str = "") -> dict:
    return _visual("timeline", title, points=points, unit=unit, note=note)


def _histogram(title: str, buckets: list[dict], unit: str, note: str = "") -> dict:
    """A distribution. §4 gives histograms no cap of their own, so §0.3's
    "bound every list" is honoured at the table cap and reported like the rest."""
    if len(buckets) > TABLE_CAP:
        total = len(buckets)
        buckets = buckets[:TABLE_CAP]
        note = f"{_cap_note(len(buckets), total, 'bucket(s)')}; {note}".strip("; ")
    return _visual("histogram", title, buckets=buckets, unit=unit, note=note)


def _scatter(
    title: str, points: list[dict], x_label: str, y_label: str, note: str = ""
) -> dict:
    return _visual(
        "scatter", title, points=points, x_label=x_label, y_label=y_label, note=note
    )


def _heatmap(
    title: str, columns: list[str], rows: list[dict], unit: str, note: str = ""
) -> dict:
    return _visual("heatmap", title, columns=columns, rows=rows, unit=unit, note=note)


def _table(title: str, columns: list[str], rows: list[dict], note: str = "") -> dict:
    return _visual("table", title, columns=columns, rows=rows, note=note)


def _cell(text: Any, *, tone: str | None = None, to: str | None = None) -> dict:
    cell: dict[str, Any] = {"text": "" if text is None else str(text)}
    if tone:
        cell["tone"] = tone
    if to:
        cell["to"] = to
    return cell


@dataclass
class _Spec:
    id: str
    title: str
    question: str
    interpretation: str
    caveat: str
    visuals: tuple[str, ...]


SPECS: tuple[_Spec, ...] = (
    _Spec(
        id="c2_beaconing",
        title="Potential C2 Beaconing",
        question="Is anything contacting the same destination on a regular schedule?",
        interpretation=(
            "Repeated connections to one destination at a steady interval are how "
            "implanted code usually asks its controller for orders: the regularity, not "
            "the destination, is the signal."
        ),
        caveat=(
            "A regular interval does not establish command-and-control. Mail clients, "
            "NTP, monitoring agents, licence checks and software updates all poll on a "
            "schedule, and a jittered beacon can hide below this threshold."
        ),
        visuals=("histogram", "table"),
    ),
    _Spec(
        id="network_scanning",
        title="Network Scanning",
        question="Is one host probing many ports or hosts in a short time?",
        interpretation=(
            "One source opening connections to many destination ports in seconds may "
            "indicate host discovery or service enumeration before an intrusion."
        ),
        caveat=(
            "Scanning does not establish intent or success. Vulnerability scanners, "
            "inventory tools, load balancers and NAT devices produce the same pattern, "
            "and a scan the capture never shows a reply to may simply have been dropped."
        ),
        visuals=("heatmap", "table"),
    ),
    _Spec(
        id="dns_anomalies",
        title="DNS Anomalies",
        question="Are lookups failing, or do names look machine-generated?",
        interpretation=(
            "Bursts of failed lookups and names that look machine-generated may indicate "
            "domain-generation-algorithm malware, a misconfigured resolver, or an "
            "automated client probing names that do not exist."
        ),
        caveat=(
            "NXDOMAIN and high-entropy names do not establish malicious activity. "
            "Typographical errors, search-domain suffixes, content delivery hostnames and "
            "captures that copied most of their answers from cache all look the same here."
        ),
        visuals=("bars", "scatter"),
    ),
    _Spec(
        id="data_exfiltration",
        title="Potential Data Exfiltration",
        question="Is an internal host sending more to a public peer than its traffic explains?",
        interpretation=(
            "Bulk outbound transfers from an internal address to a public destination may "
            "indicate collected data leaving the network, especially when the destination "
            "is not one the host normally talks to."
        ),
        caveat=(
            "Volume does not establish exfiltration. Backups, uploads to cloud services, "
            "mail attachments and video calls move the same volumes with no malicious "
            "intent, and bytes counted here include retransmissions and headers."
        ),
        visuals=("bars", "timeline"),
    ),
    _Spec(
        id="lateral_movement",
        title="Lateral Movement Indicators",
        question="Is an internal host reaching other internal hosts on remote-administration services?",
        interpretation=(
            "Internal-to-internal traffic on remote-administration and file-sharing ports "
            "may indicate an adversary moving between hosts after gaining a foothold."
        ),
        caveat=(
            "Administrative services are used administratively. Management platforms, "
            "backup jobs, domain controllers and help-desk tools produce the same flows, "
            "and a captured session says nothing about who authenticated."
        ),
        visuals=("bars", "table"),
    ),
    _Spec(
        id="suspicious_http",
        title="Suspicious HTTP Activity",
        question="Do requests carry paths, credentials or payload types a normal client would not send?",
        interpretation=(
            "Requests with traversal or shell paths, credentials in clear text, unusual "
            "user agents or executable payload types may indicate exploitation, credential "
            "harvesting or a tool rather than a browser."
        ),
        caveat=(
            "A suspicious-looking request does not establish a compromise. The same "
            "patterns come from vulnerability scanners, security tooling, application "
            "error pages and legitimate administrative interfaces."
        ),
        visuals=("timeline", "histogram"),
    ),
    _Spec(
        id="suspicious_tls",
        title="Suspicious TLS Connections",
        question="Do TLS sessions lack identity, use obsolete versions, or fail mid-handshake?",
        interpretation=(
            "Sessions with no server name, an obsolete protocol version, a self-signed "
            "certificate or a failed handshake may indicate a client talking to a "
            "hard-coded controller rather than to a normal provider."
        ),
        caveat=(
            "None of these establish malicious traffic. Captures that start mid-session, "
            "encrypted ClientHello, appliances with private certificate authorities and "
            "intentionally blocked destinations all produce these flags."
        ),
        visuals=("bars", "table"),
    ),
    _Spec(
        id="unusual_ports",
        title="Unusual Port Usage",
        question="Which destination ports fall outside the capture's ordinary service set?",
        interpretation=(
            "Destination ports outside the well-known service set, especially ports seen "
            "only once, may indicate a service the network does not normally use, an "
            "ephemeral tunnel, or a client reaching a non-standard listener."
        ),
        caveat=(
            "An uncommon port is not a malicious port. A single-use high-numbered "
            "destination port is usually a client's own ephemeral port seen in a "
            "server-to-client reply, and peers, games and appliances use fixed "
            "non-standard ports legitimately."
        ),
        visuals=("bars",),
    ),
    _Spec(
        id="high_fan_out",
        title="High-Fan-Out Hosts",
        question="Which host is talking to the most distinct peers?",
        interpretation=(
            "A host with far more peers than the rest of the capture may be a scanner, a "
            "proxy, a peer-to-peer participant or an infected host contacting many "
            "destinations at once."
        ),
        caveat=(
            "Fan-out does not establish malicious activity. Network gateways, resolvers, "
            "update servers, proxies and monitoring platforms legitimately talk to "
            "everything, and peer counts come from observed conversations alone."
        ),
        visuals=("bars",),
    ),
    _Spec(
        id="rare_pairs",
        title="Rare Communication Pairs",
        question="Which address pairs appear in a single, tiny exchange?",
        interpretation=(
            "An address pair seen exactly once, carrying hardly any payload, may indicate "
            "a probe, a failed connection attempt, or a hard-coded endpoint that was tried "
            "once."
        ),
        caveat=(
            "A rare pair is not evidence of anything. Discovery protocols, NTP, DHCP, "
            "health checks and failed name lookups produce one-packet pairs constantly, "
            "and a pair can only be rare within the window this capture covers."
        ),
        visuals=("table",),
    ),
    _Spec(
        id="malware_download",
        title="Possible Malware Download",
        question="Was an executable or script payload pulled over HTTP?",
        interpretation=(
            "An HTTP transfer carrying an executable or script content type may indicate "
            "a malware download, particularly when the host or file is also referenced by "
            "an IDS signature."
        ),
        caveat=(
            "The transfer alone does not establish malware. Software distribution, "
            "updaters, installers and administrative tooling deliver the same content "
            "types, and this view never inspects the payload's behaviour."
        ),
        visuals=("timeline", "table"),
    ),
    _Spec(
        id="dns_tunnelling",
        title="Possible DNS Tunnelling",
        question="Is one domain answering many machine-generated subdomains from a single client?",
        interpretation=(
            "Many distinct, machine-looking names under one domain, requested by one "
            "client, may indicate data or commands being smuggled through DNS."
        ),
        caveat=(
            "Name shape does not establish a tunnel. Content delivery networks, "
            "anti-tracking and telemetry hostnames, and marketing redirect domains all "
            "generate high-entropy subdomains at volume, and a real tunnel is usually "
            "long-lived enough to be obvious only in a longer capture."
        ),
        visuals=("scatter", "table"),
    ),
    _Spec(
        id="ids_matches",
        title="IDS Signature Matches",
        question="Which recorded IDS signatures fired in this capture?",
        interpretation=(
            "Signature matches are the most specific evidence on this page: a rule written "
            "for a known technique matched frames that were actually captured."
        ),
        caveat=(
            "A signature match is not a confirmed compromise. Rules trade false negatives "
            "for false positives, the alert says nothing about whether the attempt "
            "succeeded, and an empty list only means no rule matched this capture."
        ),
        visuals=("table",),
    ),
    _Spec(
        id="traffic_bursts",
        title="Suspicious Traffic Bursts",
        question="When does packet volume depart sharply from the capture's own baseline?",
        interpretation=(
            "Short bursts far above the capture's own baseline often mark the moment "
            "something happened: a transfer, a sweep, a flood, or an upload of collected "
            "data."
        ),
        caveat=(
            "A burst is not itself suspicious. Bursty traffic is normal for web browsing, "
            "backups and streaming, and the baseline is this capture's own — a capture "
            "that is short or already busy will not show one."
        ),
        visuals=("timeline",),
    ),
    _Spec(
        id="unusual_egress",
        title="Unusual Egress",
        question="Is an internal host reaching out on ports or to addresses the rest of the capture never uses?",
        interpretation=(
            "Internal hosts reaching public addresses on non-standard ports, or on "
            "addresses with no name evidence in this capture, may indicate hard-coded "
            "endpoints, tunnelling, or a client talking to infrastructure the network does "
            "not normally use."
        ),
        caveat=(
            "An unnamed destination is not a hidden one. Addresses are often cached from "
            "before the capture started or reused across connections, and reachable "
            "non-standard ports are ordinary in peer-to-peer, gaming and remote-access "
            "traffic."
        ),
        visuals=("bars",),
    ),
    _Spec(
        id="data_staging",
        title="Potential Data Staging",
        question="Is a large volume moving between two internal hosts?",
        interpretation=(
            "Large transfers between internal hosts may indicate collected data being "
            "gathered on one machine before it is sent out of the network."
        ),
        caveat=(
            "Internal bulk transfer does not establish staging. File servers, backups, "
            "imaging, virtual-machine migration and media shares move far more data than "
            "this threshold between internal hosts every day."
        ),
        visuals=("timeline", "histogram"),
    ),
    _Spec(
        id="failed_connections",
        title="Repeated Failed Connections",
        question="What is repeatedly trying to connect and never being answered?",
        interpretation=(
            "Repeated connection attempts to a destination that never answers may "
            "indicate a client hunting for a controller that is down, a superseded "
            "hard-coded address, or a port that a firewall is silently dropping."
        ),
        caveat=(
            "Unanswered attempts do not establish malicious intent. The destination may be "
            "offline, blocked by policy, or answering outside the capture's window, and "
            "retries are also what a misconfigured client does."
        ),
        visuals=("timeline", "bars"),
    ),
)

SPEC_BY_ID: dict[str, _Spec] = {spec.id: spec for spec in SPECS}


@dataclass
class _Result:
    availability: str
    reason: str | None
    headline_value: float
    headline_label: str
    tone: str = "info"
    visuals: list[dict] = field(default_factory=list)
    links: list[dict] = field(default_factory=list)


def _not_applicable(reason: str) -> _Result:
    return _Result("not_applicable", reason, 0, "not computable from this capture")


def _empty(reason: str, *, visuals: list[dict] | None = None, links: list[dict] | None = None,
           label: str = "nothing matched") -> _Result:
    return _Result("empty", reason, 0, label, "info", visuals or [], links or [])


@dataclass
class _Index:
    """Row counts that decide whether a detection can be computed at all."""

    analysis_id: str
    window: int
    top: int
    packets: int
    tcp_packets: int
    conversations: int
    dns: int
    http: int
    tls: int
    hosts: int
    findings: int

    @property
    def has_traffic(self) -> bool:
        return self.packets > 0


def _load_index(analysis_id: str, window: int, top: int) -> _Index:
    tcp = db.query_one(
        "SELECT COUNT(*) AS n FROM packets WHERE analysis_id = ? AND transport = 'tcp'",
        (analysis_id,),
    )
    return _Index(
        analysis_id=analysis_id,
        window=window,
        top=top,
        packets=db.count(analysis_id, "packets"),
        tcp_packets=int(tcp["n"]) if tcp else 0,
        conversations=db.count(analysis_id, "conversations"),
        dns=db.count(analysis_id, "dns_queries"),
        http=db.count(analysis_id, "http_transactions"),
        tls=db.count(analysis_id, "tls_sessions"),
        hosts=db.count(analysis_id, "hosts"),
        findings=db.count(analysis_id, "findings"),
    )


NO_PACKETS = "the packet index holds no rows for this capture"
NO_TCP = "the packet index holds no TCP frames for this capture"
NO_CONVERSATIONS = "the conversation index holds no rows for this capture"
NO_DNS = "the capture recorded no DNS queries"
NO_HTTP = "the capture recorded no HTTP transactions"
NO_TLS = "the capture recorded no TLS sessions"
NO_HOSTS = "the host index holds no rows for this capture"


# --------------------------------------------------------------------------
# 1. c2_beaconing
# --------------------------------------------------------------------------

_INTERVAL_EDGES: tuple[tuple[float, str], ...] = (
    (1.0, "under 1 s"),
    (5.0, "1-5 s"),
    (30.0, "5-30 s"),
    (60.0, "30-60 s"),
    (300.0, "1-5 min"),
    (1800.0, "5-30 min"),
    (math.inf, "30 min and over"),
)


def _c2_beaconing(index: _Index) -> _Result:
    if not index.conversations:
        return _not_applicable(NO_CONVERSATIONS)

    groups = db.query_all(
        """
        SELECT ip_a, ip_b, port_b, transport, COUNT(*) AS flows,
               MIN(stream_id) AS stream_id
          FROM conversations
         WHERE analysis_id = ? AND ip_a IS NOT NULL AND ip_b IS NOT NULL
           AND start_time IS NOT NULL
         GROUP BY ip_a, ip_b, port_b, transport
        HAVING COUNT(*) >= ?
         ORDER BY flows DESC
         LIMIT ?
        """,
        (index.analysis_id, BEACON_MIN_FLOWS, ROW_SCAN_CAP),
    )

    interval_buckets: dict[str, int] = {}
    regular: list[dict] = []
    repeated = 0

    for group in groups:
        repeated += 1
        times = [
            float(row["start_time"])
            for row in db.query_all(
                """
                SELECT start_time FROM conversations
                 WHERE analysis_id = ? AND ip_a = ? AND ip_b = ? AND transport = ?
                   AND (port_b = ? OR (port_b IS NULL AND ? IS NULL))
                   AND start_time IS NOT NULL
                 ORDER BY start_time ASC
                 LIMIT ?
                """,
                (
                    index.analysis_id,
                    group["ip_a"],
                    group["ip_b"],
                    group["transport"],
                    group["port_b"],
                    group["port_b"],
                    ROW_SCAN_CAP,
                ),
            )
        ]
        intervals = [later - earlier for earlier, later in zip(times, times[1:])]
        positive = [value for value in intervals if value > 0]
        for value in positive:
            label = _bucket_label(value, _INTERVAL_EDGES)
            interval_buckets[label] = interval_buckets.get(label, 0) + 1
        if len(positive) < BEACON_MIN_FLOWS - 1:
            continue

        mean = _mean(positive)
        if mean < BEACON_MIN_INTERVAL:
            continue
        spread = float(statistics.pstdev(positive))
        cv = spread / mean if mean else 0.0
        if cv <= BEACON_MAX_CV:
            regular.append(
                {
                    "ip_a": group["ip_a"],
                    "ip_b": group["ip_b"],
                    "port_b": group["port_b"],
                    "transport": group["transport"],
                    "stream_id": group["stream_id"],
                    "flows": int(group["flows"]),
                    "mean": mean,
                    "cv": cv,
                    "intervals": len(positive),
                    "span": times[-1] - times[0] if len(times) > 1 else 0.0,
                }
            )

    regular.sort(key=lambda item: (item["cv"], -item["flows"], str(item["ip_b"])))
    shown = regular[: index.top]

    histogram_buckets = [
        {"label": label, "value": interval_buckets[label]}
        for _limit, label in _INTERVAL_EDGES
        if interval_buckets.get(label)
    ]

    rows = []
    for item in shown:
        rows.append(
            {
                "cells": [
                    _cell(
                        f"{item['ip_a']} → {item['ip_b']}:{item['port_b']}",
                        tone="watch",
                        # §5: `stream` takes the conversation key (transport:id), not a
                        # bare id - the Conversations page parses exactly that form - and
                        # `transport` there is a filter, which would silently narrow the
                        # page instead of selecting the conversation.
                        to=_to(
                            "/conversations",
                            stream=f"{item['transport']}:{item['stream_id']}",
                        ),
                    ),
                    _cell(f"{item['flows']} flows over {item['span']:.0f} s"),
                    _cell(f"{item['mean']:.1f} s mean interval"),
                    _cell(f"CV {item['cv']:.3f} over {item['intervals']} intervals"),
                ]
            }
        )

    visuals = [
        _histogram(
            "Interval between consecutive connections to the same destination",
            histogram_buckets,
            "flows",
            "conversations grouped by source, destination and destination port, "
            "at least 4 connections to a group",
        ),
        _table(
            "Flows with a regular interval",
            ["destination", "recurrence", "interval", "regularity"],
            rows,
            _cap_note(len(shown), len(regular), "flow(s)"),
        ),
    ]

    links = [
        _link(_to("/conversations", ip=item["ip_b"]), str(item["ip_b"]))
        for item in shown[:5]
    ]

    if not regular:
        reason = (
            f"no source contacted the same destination and port at least {BEACON_MIN_FLOWS} "
            f"times with a mean interval of {BEACON_MIN_INTERVAL:.0f} s or more and a "
            f"coefficient of variation at or below {BEACON_MAX_CV} "
            f"({repeated} repeated flow(s) were measurable)"
        )
        return _empty(reason, visuals=visuals, links=links, label="flow(s) with a regular interval")

    return _Result(
        "ok",
        None,
        len(regular),
        "flow(s) with a regular interval",
        "watch",
        visuals,
        links,
    )


# --------------------------------------------------------------------------
# 2. network_scanning
# --------------------------------------------------------------------------


def _best_scan_window(events: Sequence[tuple[float, int]], span: float) -> int:
    """Most distinct destination ports seen from one source inside ``span`` seconds."""
    counts: dict[int, int] = {}
    distinct = 0
    best = 0
    start = 0
    for end, (moment, port) in enumerate(events):
        counts[port] = counts.get(port, 0) + 1
        if counts[port] == 1:
            distinct += 1
        while moment - events[start][0] > span:
            leaving = events[start][1]
            counts[leaving] -= 1
            if counts[leaving] == 0:
                del counts[leaving]
                distinct -= 1
            start += 1
        best = max(best, distinct)
    return best


def _host_probes(index: _Index) -> tuple[dict[str, list[tuple[float, str]]], set[str]]:
    """Which addresses each source probed, and which addresses ever answered.

    Discovery is not always TCP. ``nmap -sn`` against a link-local range asks "who
    has" for every address in it and sends no TCP frame at all, so a detector that
    reads only TCP SYN sees nothing however large the sweep was. Three probe types are
    collected and one rule is applied to all of them: a probe is unanswered when the
    address never answered anyone in this capture.
    """
    probes: dict[str, list[tuple[float, str]]] = {}
    live: set[str] = set()

    # ARP: the probed address survives only in the summary line, because an ARP frame
    # carries no IP layer for the indexer to store.
    for row in db.query_all(
        """
        SELECT info, time_epoch FROM packets
         WHERE analysis_id = ? AND protocol = 'ARP' AND info IS NOT NULL
         LIMIT ?
        """,
        (index.analysis_id, PACKET_SCAN_CAP),
    ):
        info = str(row["info"] or "")
        moment = float(row["time_epoch"] or 0.0)
        request = _ARP_REQUEST.match(info)
        if request is not None:
            probes.setdefault(request.group(2), []).append((moment, request.group(1)))
            continue
        reply = _ARP_REPLY.match(info)
        if reply is not None:
            live.add(reply.group(1))

    # ICMP echo: a remote ping sweep, where ARP is not used.
    for row in db.query_all(
        """
        SELECT src_ip, dst_ip, time_epoch, info FROM packets
         WHERE analysis_id = ? AND protocol = 'ICMP'
           AND src_ip IS NOT NULL AND dst_ip IS NOT NULL AND info IS NOT NULL
         LIMIT ?
        """,
        (index.analysis_id, PACKET_SCAN_CAP),
    ):
        info = str(row["info"] or "")
        moment = float(row["time_epoch"] or 0.0)
        if info.startswith(_ICMP_REQUEST):
            probes.setdefault(str(row["src_ip"]), []).append((moment, str(row["dst_ip"])))
        elif info.startswith("Echo (ping) reply"):
            live.add(str(row["src_ip"]))

    # TCP: a connection attempt that was never acknowledged.
    for row in db.query_all(
        """
        SELECT src_ip, dst_ip, time_epoch FROM packets
         WHERE analysis_id = ? AND transport = 'tcp'
           AND src_ip IS NOT NULL AND dst_ip IS NOT NULL
           AND (tcp_flags_raw & 2) = 2 AND (tcp_flags_raw & 16) = 0
         LIMIT ?
        """,
        (index.analysis_id, PACKET_SCAN_CAP),
    ):
        probes.setdefault(str(row["src_ip"]), []).append(
            (float(row["time_epoch"] or 0.0), str(row["dst_ip"]))
        )

    # Anyone who completed a handshake was reachable, so their address is not a host
    # that "never answered".
    for row in db.query_all(
        """
        SELECT src_ip FROM packets
         WHERE analysis_id = ? AND transport = 'tcp' AND src_ip IS NOT NULL
           AND (tcp_flags_raw & 2) = 2 AND (tcp_flags_raw & 16) = 16
         LIMIT ?
        """,
        (index.analysis_id, PACKET_SCAN_CAP),
    ):
        live.add(str(row["src_ip"]))

    return probes, live


def _network_scanning(index: _Index) -> _Result:
    """Scanning, measured both ways the brief distinguishes them.

    Vertical is many ports on few hosts; horizontal is one port across many hosts,
    and a local ``nmap -sn`` sweep is neither, because it never opens a port at all -
    it asks the link who is there. Both shapes are computed, and the card is the union
    of the sources that show either.
    """
    if not index.has_traffic:
        return _not_applicable(NO_PACKETS)

    # ---- vertical: one host, many ports -----------------------------------
    attempts = db.query_all(
        """
        SELECT src_ip, dst_ip, dst_port, time_epoch, number
          FROM packets
         WHERE analysis_id = ? AND transport = 'tcp'
           AND src_ip IS NOT NULL AND dst_ip IS NOT NULL AND dst_port IS NOT NULL
           AND (tcp_flags_raw & 2) = 2 AND (tcp_flags_raw & 16) = 0
         ORDER BY src_ip ASC, time_epoch ASC, number ASC
         LIMIT ?
        """,
        (index.analysis_id, PACKET_SCAN_CAP),
    )
    truncated = len(attempts) >= PACKET_SCAN_CAP

    by_source: dict[str, list[tuple[float, int]]] = {}
    port_totals: dict[int, int] = {}
    per_source_pair: dict[str, dict[str, int]] = {}

    for row in attempts:
        source = str(row["src_ip"])
        target = str(row["dst_ip"])
        port = int(row["dst_port"])
        moment = float(row["time_epoch"] or 0.0)
        by_source.setdefault(source, []).append((moment, port))
        port_totals[port] = port_totals.get(port, 0) + 1
        per_source_pair.setdefault(source, {})
        per_source_pair[source][target] = per_source_pair[source].get(target, 0) + 1

    port_scans: dict[str, dict[str, int]] = {}
    for source, events in by_source.items():
        events.sort(key=lambda item: item[0])
        best = _best_scan_window(events, SCAN_PORT_SPAN)
        if best >= SCAN_MIN_PORTS:
            port_scans[source] = {"ports_in_window": best, "attempts": len(events)}

    # ---- horizontal: many hosts that never answered ------------------------
    probes, live = _host_probes(index)
    host_scans: dict[str, dict[str, int]] = {}
    unanswered_by_source: dict[str, list[tuple[float, str]]] = {}
    for source, events in probes.items():
        unanswered = sorted(
            (moment, target) for moment, target in events if target not in live
        )
        unanswered_by_source[source] = unanswered
        best = _best_scan_window(unanswered, SCAN_HOST_SPAN)
        if best >= SCAN_HOST_MIN:
            host_scans[source] = {"hosts_in_window": best, "probes": len(events)}

    sources = sorted(set(port_scans) | set(host_scans))
    scans = [
        {
            "source": source,
            "ports_in_window": port_scans.get(source, {}).get("ports_in_window", 0),
            "hosts_in_window": host_scans.get(source, {}).get("hosts_in_window", 0),
            "destinations": len(per_source_pair.get(source, {})),
            "attempts": port_scans.get(source, {}).get("attempts", 0),
        }
        for source in sources
    ]
    scans.sort(
        key=lambda item: (
            -item["hosts_in_window"],
            -item["ports_in_window"],
            -item["attempts"],
            item["source"],
        )
    )
    shown = scans[: index.top]

    top_sources = sorted(by_source.items(), key=lambda item: (-len(item[1]), item[0]))[: index.top]
    top_ports = sorted(port_totals.items(), key=lambda item: (-item[1], item[0]))[: index.top]
    columns = [str(port) for port, _count in top_ports]
    heat_rows = []
    for source, events in top_sources:
        counts: dict[int, int] = {}
        for _moment, port in events:
            counts[port] = counts.get(port, 0) + 1
        heat_rows.append(
            {"label": source, "cells": [counts.get(port, 0) for port, _c in top_ports]}
        )

    # ---- visuals: one per shape, and only when it has something to show ----
    visuals: list[dict] = []
    if heat_rows and columns:
        heat_note_parts = []
        if len(by_source) > index.top:
            heat_note_parts.append(f"top {len(top_sources)} of {len(by_source)} source(s)")
        if len(port_totals) > index.top:
            heat_note_parts.append(f"top {len(columns)} of {len(port_totals)} port(s)")
        heat_note_parts.append(
            "capped at 20000 attempts" if truncated else "connection attempts only (SYN without ACK)"
        )
        visuals.append(
            _heatmap(
                "Source against destination port",
                columns,
                heat_rows,
                "attempts",
                "; ".join(heat_note_parts),
            )
        )

    host_bars = [
        {
            "label": item["source"],
            "value": item["hosts_in_window"],
            "to": _to("/hosts", ip=item["source"]),
        }
        for item in shown
        if item["hosts_in_window"] > 0
    ]
    if host_bars:
        visuals.append(
            _bars(
                f"Hosts probed with no answer, per source (best {SCAN_HOST_SPAN:.0f} s window)",
                host_bars,
                "hosts",
                _cap_note(len(host_bars), len(host_scans), "scanning source(s)")
                or "addresses probed that never answered anyone in this capture",
            )
        )

    table_rows = [
        {
            "cells": [
                _cell(item["source"], tone="watch", to=_to("/hosts", ip=item["source"])),
                # A real zero is worth showing: an ARP sweep scanned no ports at all,
                # and saying 0 is clearer than leaving the cell blank.
                _cell(item["hosts_in_window"]),
                _cell(item["ports_in_window"]),
                _cell(item["destinations"]),
                _cell(item["attempts"]),
            ]
        }
        for item in shown
    ]
    visuals.append(
        _table(
            "Sources scanning ports or sweeping hosts",
            ["source", "hosts unanswered", "ports in window", "tcp pairs", "tcp attempts"],
            table_rows,
            _cap_note(len(shown), len(scans), "source(s)"),
        )
    )

    links = [_link(_to("/hosts", ip=item["source"]), item["source"]) for item in shown[:5]]

    if not scans:
        best_ports = max(
            (_best_scan_window(sorted(events), SCAN_PORT_SPAN) for events in by_source.values()),
            default=0,
        )
        best_hosts = max(
            (
                _best_scan_window(sorted(events), SCAN_HOST_SPAN)
                for events in unanswered_by_source.values()
            ),
            default=0,
        )
        return _empty(
            f"no source opened {SCAN_MIN_PORTS} or more distinct destination ports, or probed "
            f"{SCAN_HOST_MIN} or more addresses that never answered, within "
            f"{SCAN_PORT_SPAN:.0f} s (best observed: {best_ports} port(s), {best_hosts} "
            f"unanswered host(s))",
            visuals=visuals,
            links=links,
            label="scanning source(s)",
        )

    return _Result(
        "ok",
        None,
        len(scans),
        "source(s) scanning ports or sweeping hosts",
        "watch",
        visuals,
        links,
    )



# --------------------------------------------------------------------------
# 3. dns_anomalies
# --------------------------------------------------------------------------


def _dns_anomalies(index: _Index) -> _Result:
    if not index.dns:
        return _not_applicable(NO_DNS)

    clause, like_params = _flags_like_sql("flags", STRONG_DNS_FLAGS)
    nxdomain_sql = "(rcode_name = 'NXDOMAIN' OR rcode = 3)"
    # Placeholders appear in the SELECT, the WHERE and again in the ORDER BY, so
    # the LIKE parameters are bound twice, in that order.
    clients = db.query_all(
        f"""
        SELECT COALESCE(client_ip, 'unknown') AS client,
               COUNT(*) AS queries,
               SUM(CASE WHEN {nxdomain_sql} THEN 1 ELSE 0 END) AS nxdomain,
               SUM(CASE WHEN {clause} THEN 1 ELSE 0 END) AS flagged
          FROM dns_queries
         WHERE analysis_id = ?
         GROUP BY client
         ORDER BY (SUM(CASE WHEN {nxdomain_sql} THEN 1 ELSE 0 END)
                   + SUM(CASE WHEN {clause} THEN 1 ELSE 0 END)) DESC,
                  client ASC
        """,
        (*like_params, index.analysis_id, *like_params),
    )

    anomalous = [
        row
        for row in clients
        if int(row["nxdomain"] or 0) >= DNS_NXDOMAIN_MIN
        or int(row["queries"] or 0) >= DNS_VOLUME_MIN
        or int(row["flagged"] or 0) >= DNS_FLAGGED_MIN
    ]
    anomalous.sort(
        key=lambda row: (
            -(int(row["nxdomain"] or 0) + int(row["flagged"] or 0)),
            -int(row["queries"] or 0),
            str(row["client"]),
        )
    )

    names = db.query_all(
        f"""
        SELECT query_name,
               COUNT(*) AS queries,
               MAX(longest_label) AS longest_label,
               MAX(entropy) AS entropy,
               SUM(CASE WHEN {clause} THEN 1 ELSE 0 END) AS flagged
          FROM dns_queries
         WHERE analysis_id = ? AND query_name IS NOT NULL
         GROUP BY query_name
         ORDER BY flagged DESC, queries DESC, query_name ASC
         LIMIT ?
        """,
        (*like_params, index.analysis_id, SCATTER_CAP),
    )

    bar_items = [
        {
            "label": str(row["client"]),
            "value": int(row["nxdomain"] or 0) + int(row["flagged"] or 0),
            "to": _to("/dns", client_ip=row["client"]),
        }
        for row in anomalous[: index.top]
    ]

    points = [
        {
            "x": int(row["longest_label"] or 0),
            "y": int(row["queries"] or 0),
            "label": str(row["query_name"]),
            "to": _to("/dns", domain=str(row["query_name"])),
        }
        for row in names[:SCATTER_CAP]
    ]

    visuals = [
        _bars(
            "Anomalous DNS activity by client",
            bar_items,
            "queries",
            _cap_note(len(bar_items), len(anomalous), "client(s)")
            or f"flagged when a client asked \u2265{DNS_NXDOMAIN_MIN} NXDOMAIN names, "
            f"\u2265{DNS_VOLUME_MIN} queries, or \u2265{DNS_FLAGGED_MIN} machine-looking names",
        ),
        _scatter(
            "Query-name length against query count",
            points,
            "longest label",
            "queries",
            f"{len(points)} name(s); markers are the longest label observed for the name",
        ),
    ]

    links = [_link(_to("/dns", client_ip=row["client"]), str(row["client"])) for row in anomalous[:5]]

    if not anomalous:
        return _empty(
            f"no client asked \u2265{DNS_NXDOMAIN_MIN} NXDOMAIN names, \u2265{DNS_VOLUME_MIN} "
            f"queries, or \u2265{DNS_FLAGGED_MIN} machine-looking names "
            f"({len(clients)} client(s) observed)",
            visuals=visuals,
            links=links,
            label="client(s) with anomalous DNS behaviour",
        )

    return _Result(
        "ok",
        None,
        len(anomalous),
        "client(s) with anomalous DNS behaviour",
        "watch",
        visuals,
        links,
    )


# --------------------------------------------------------------------------
# 4. data_exfiltration
# --------------------------------------------------------------------------


def _outbound_pairs(analysis_id: str) -> list[dict]:
    """Bytes an internal address sent to each public destination.

    Direction is taken from the conversation row: ``bytes_a_to_b`` is what
    ``ip_a`` sent to ``ip_b``, and the reverse is counted when the internal host
    is ``ip_b``.
    """
    rows = db.query_all(
        """
        SELECT ip_a, ip_b, bytes_a_to_b, bytes_b_to_a, packets_a_to_b, packets_b_to_a,
               start_time, stream_id, transport
          FROM conversations
         WHERE analysis_id = ? AND ip_a IS NOT NULL AND ip_b IS NOT NULL
         LIMIT ?
        """,
        (analysis_id, PACKET_SCAN_CAP),
    )
    pairs: dict[tuple[str, str], dict] = {}
    for row in rows:
        left, right = str(row["ip_a"]), str(row["ip_b"])
        if _private(left) and _is_public_unicast(right):
            key = (left, right)
            sent, received = int(row["bytes_a_to_b"] or 0), int(row["bytes_b_to_a"] or 0)
            packets = int(row["packets_a_to_b"] or 0)
        elif _private(right) and _is_public_unicast(left):
            key = (right, left)
            sent, received = int(row["bytes_b_to_a"] or 0), int(row["bytes_a_to_b"] or 0)
            packets = int(row["packets_b_to_a"] or 0)
        else:
            continue
        entry = pairs.setdefault(
            key,
            {
                "source": key[0],
                "peer": key[1],
                "sent": 0,
                "received": 0,
                "packets": 0,
                "conversations": 0,
                "start": row["start_time"],
                "transport": row["transport"],
                "stream_id": row["stream_id"],
            },
        )
        entry["sent"] += sent
        entry["received"] += received
        entry["packets"] += packets
        entry["conversations"] += 1
        moment = row["start_time"]
        if moment is not None and (entry["start"] is None or float(moment) < float(entry["start"])):
            entry["start"] = moment
    return list(pairs.values())


def _data_exfiltration(index: _Index) -> _Result:
    if not index.conversations:
        return _not_applicable(NO_CONVERSATIONS)

    pairs = _outbound_pairs(index.analysis_id)
    if not pairs:
        return _empty(
            "the capture records no conversation from a private address to a public "
            "destination, so outbound volume cannot be measured",
            visuals=[
                _bars("Outbound volume by destination", [], "bytes"),
                _timeline("Outbound bytes per bucket", [], "bytes"),
            ],
            label="internal-to-public destination(s) above the threshold",
        )

    volumes = sorted(entry["sent"] for entry in pairs)
    median = float(statistics.median(volumes)) if volumes else 0.0
    relative_floor = max(EXFIL_RELATIVE_BYTES, median * EXFIL_RELATIVE_FACTOR)

    candidates = [
        entry
        for entry in pairs
        if entry["sent"] >= EXFIL_MIN_BYTES or entry["sent"] >= relative_floor
    ]
    candidates.sort(key=lambda entry: (-entry["sent"], entry["peer"]))

    ranked = sorted(pairs, key=lambda entry: (-entry["sent"], entry["peer"]))
    bar_items = [
        {
            "label": f"{entry['peer']} ({entry['packets']} pkt)",
            "value": entry["sent"],
            "to": _to("/conversations", ip=entry["peer"]),
        }
        for entry in ranked[: index.top]
    ]

    points, bucket_total = _series(
        ((entry["start"], entry["sent"]) for entry in pairs), index.window
    )

    visuals = [
        _bars(
            "Outbound volume by destination",
            bar_items,
            "bytes",
            _cap_note(len(bar_items), len(ranked), "destination(s)")
            or f"threshold: \u2265{EXFIL_MIN_BYTES:,} bytes, or "
            f"\u2265{relative_floor:,.0f} bytes ({EXFIL_RELATIVE_FACTOR}\u00d7 the median of "
            f"{len(volumes)} destination(s), floor {EXFIL_RELATIVE_BYTES:,})",
        ),
        _timeline(
            "Outbound bytes per bucket",
            points,
            "bytes",
            _cap_note(len(points), bucket_total, f"bucket(s) of {index.window} s"),
        ),
    ]

    links = [_link(_to("/conversations", ip=entry["peer"]), entry["peer"]) for entry in ranked[:5]]

    if not candidates:
        return _empty(
            f"no internal host sent at least {EXFIL_MIN_BYTES:,} bytes to a public destination "
            f"(largest observed: {max(volumes):,} bytes; the relative threshold was "
            f"{relative_floor:,.0f} bytes, being {EXFIL_RELATIVE_FACTOR}× the median of "
            f"{len(volumes)} destination(s) or a {EXFIL_RELATIVE_BYTES:,}-byte floor)",
            visuals=visuals,
            links=links,
            label="internal-to-public destination(s) above the threshold",
        )

    return _Result(
        "ok",
        None,
        len(candidates),
        "internal-to-public destination(s) above the threshold",
        "watch",
        visuals,
        links,
    )


# --------------------------------------------------------------------------
# 5. lateral_movement
# --------------------------------------------------------------------------


def _lateral_conversations(index: _Index) -> dict[tuple[str, int], tuple[str, int, str]]:
    """``(host, port) -> (transport, stream_id, node column)`` for §5's lateral-movement links.

    The flow buckets are built from ``packets``, which knows the port but not the conversation;
    a link that opens the *conversation* therefore needs the ``conversations`` row behind the
    flow. One query covers every administration port, and the largest conversation wins when a
    host reached one service more than once — the link's ``ip`` and ``port`` parameters still
    filter the page to all of them, so nothing is hidden by picking one.

    The third value is the column the port belongs to **in the flow diagram**, which is decided
    by the conversation's own A/B assignment and not by who spoke first: ``ip_a``/``port_a`` is
    the diagram's left-hand ``source``/``sourcePort`` column, and ``ip_b``/``port_b`` the
    right-hand ``destination``/``destinationPort``. A port node key is ``<column>:<port>``
    (``flowNodeId`` in the frontend), so getting the side wrong would select nothing.
    """
    ports = sorted(LATERAL_PORTS)
    placeholders = ", ".join("?" for _ in ports)
    rows = db.query_all(
        f"""
        SELECT transport, stream_id, ip_a, port_a, ip_b, port_b, bytes_total
          FROM conversations
         WHERE analysis_id = ? AND transport = 'tcp'
           AND (port_a IN ({placeholders}) OR port_b IN ({placeholders}))
         ORDER BY bytes_total DESC, stream_id
        """,
        (index.analysis_id, *ports, *ports),
    )

    resolved: dict[tuple[str, int], tuple[str, int, str]] = {}
    for row in rows:
        stream_id = row["stream_id"]
        if stream_id is None:
            # No reassembled stream means no conversation to open: the simple filter link is
            # all this flow can honestly offer.
            continue
        transport = str(row["transport"])
        for ip_key, port_key, column in (
            ("ip_a", "port_a", "sourcePort"),
            ("ip_b", "port_b", "destinationPort"),
        ):
            host = row[ip_key]
            port = row[port_key]
            if host is None or port is None:
                continue
            key = (str(host), int(port))
            if key in resolved:
                continue  # the rows are largest first, so the first one wins
            resolved[key] = (transport, int(stream_id), column)
    return resolved


def _lateral_movement(index: _Index) -> _Result:
    if not index.has_traffic:
        return _not_applicable(NO_PACKETS)
    if not index.tcp_packets:
        return _not_applicable(NO_TCP)

    ports = sorted(LATERAL_PORTS)
    placeholders = ", ".join("?" for _ in ports)
    rows = db.query_all(
        f"""
        SELECT src_ip, dst_ip, dst_port, COUNT(*) AS packets,
               COALESCE(SUM(frame_len), 0) AS bytes,
               MIN(number) AS first_frame,
               MIN(time_epoch) AS first_time
          FROM packets
         WHERE analysis_id = ? AND transport = 'tcp'
           AND src_ip IS NOT NULL AND dst_ip IS NOT NULL
           AND dst_port IN ({placeholders})
         GROUP BY src_ip, dst_ip, dst_port
         ORDER BY packets DESC
         LIMIT ?
        """,
        (index.analysis_id, *ports, ROW_SCAN_CAP),
    )

    flows = [
        {
            "src": str(row["src_ip"]),
            "dst": str(row["dst_ip"]),
            "port": int(row["dst_port"]),
            "packets": int(row["packets"]),
            "bytes": int(row["bytes"] or 0),
            "frame": int(row["first_frame"]) if row["first_frame"] is not None else None,
            "time": row["first_time"],
        }
        for row in rows
        if _private(row["src_ip"]) and _private(row["dst_ip"])
    ]
    flows.sort(key=lambda flow: (-flow["packets"], flow["src"], flow["dst"]))

    per_host: dict[tuple[str, int], int] = {}
    for flow in flows:
        key = (flow["dst"], flow["port"])
        per_host[key] = per_host.get(key, 0) + flow["packets"]
    ranked = sorted(per_host.items(), key=lambda item: (-item[1], item[0]))

    # §5 allows `/conversations` to be opened on a specific conversation as well as filtered to
    # an address and a port, and the reader clicking `192.168.8.101:445 (SMB)` wants the flow, not
    # a list: `stream=` selects it and `node=` selects the port node it hangs from in the diagram.
    conversations = _lateral_conversations(index)

    def _flow_link(host: str, port: int) -> str:
        """Open the flow itself: the conversation when one is known, the filter otherwise.

        `stream=` selects the conversation and `node=` the port node it hangs from in the flow
        diagram; `ip=` and `port=` stay on the link so the page is filtered to that host and
        service whether or not the stream resolves. A flow with no reassembled stream keeps the
        filter-only link, because there is no conversation to open.
        """
        found = conversations.get((host, port))
        if found is None:
            return _to("/conversations", ip=host, port=port)
        transport, stream_id, column = found
        return _to(
            "/conversations",
            ip=host,
            port=port,
            node=f"{column}:{port}",
            stream=f"{transport}:{stream_id}",
        )

    bar_items = [
        {
            "label": f"{host}:{port} ({LATERAL_PORTS.get(port, 'service')})",
            "value": packets,
            "to": _flow_link(host, port),
        }
        for (host, port), packets in ranked[: index.top]
    ]

    shown = flows[:TABLE_CAP]
    table_rows = [
        {
            "cells": [
                _cell(flow["src"], tone="watch", to=_to("/hosts", ip=flow["src"])),
                _cell(flow["dst"], to=_to("/hosts", ip=flow["dst"])),
                _cell(f"{flow['port']} {LATERAL_PORTS.get(flow['port'], '')}".strip()),
                _cell(
                    flow["packets"],
                    to=_to("/packets", ip=flow["dst"], dst_port=flow["port"], transport="tcp"),
                ),
                _cell(flow["bytes"]),
            ]
        }
        for flow in shown
    ]

    visuals = [
        _bars(
            "Internal hosts reached on administration services",
            bar_items,
            "packets",
            _cap_note(len(bar_items), len(ranked), "service(s)"),
        ),
        _table(
            "Internal-to-internal flows on administration ports",
            ["source", "destination", "service", "packets", "bytes"],
            table_rows,
            _cap_note(len(shown), len(flows), "flow(s)"),
        ),
    ]

    links = [
        _link(_to("/hosts", ip=host), host) for (host, _port), _packets in ranked[:5]
    ]

    if not flows:
        ports_text = ", ".join(str(port) for port in ports)
        return _empty(
            "no TCP flow between two private addresses was observed on the "
            f"remote-administration portfolio used here ({ports_text})",
            visuals=visuals,
            links=links,
            label="internal-to-internal administration flow(s)",
        )

    return _Result(
        "ok",
        None,
        len(flows),
        "internal-to-internal administration flow(s)",
        "watch",
        visuals,
        links,
    )


# --------------------------------------------------------------------------
# 6. suspicious_http
# --------------------------------------------------------------------------


def _http_category(row: Any) -> tuple[str, str]:
    """``(category, label)`` for one transaction; ``("", "")`` when nothing applies."""
    tokens = _flag_tokens(row["flags"])
    for token in tokens:
        if token == "cleartext_credentials":
            return "cleartext_credentials", "credentials in clear text"
        if token == "suspicious_path":
            return "suspicious_path", "suspicious request path"
        if token == "server_error":
            return "server_error", "server error response"
        if token == "client_error":
            return "client_error", "client error response"
        if token == "unusual_method":
            return "unusual_method", "unusual HTTP method"
        if token == "ip_host":
            return "ip_host", "address used as Host header"
        if token == "unusual_user_agent":
            return "unusual_user_agent", "unusual user agent"

    extension = _extension(row["uri"])
    content_type = str(row["content_type"] or "").lower()
    if extension in DANGEROUS_EXTENSIONS_STRICT or any(
        marker in content_type for marker in DANGEROUS_CONTENT_TYPES
    ):
        return "dangerous_payload", "executable or script payload"
    if tokens:
        return tokens[0], tokens[0].replace("_", " ")
    return "", ""


def _suspicious_http(index: _Index) -> _Result:
    if not index.http:
        return _not_applicable(NO_HTTP)

    rows = db.query_all(
        """
        SELECT id, time_epoch, request_packet, client_ip, server_ip, host, method, uri,
               status_code, user_agent, content_type, response_len, flags
          FROM http_transactions
         WHERE analysis_id = ?
         ORDER BY time_epoch IS NULL, time_epoch ASC, id ASC
         LIMIT ?
        """,
        (index.analysis_id, PACKET_SCAN_CAP),
    )

    suspicious: list[dict] = []
    categories: dict[str, int] = {}
    category_labels: dict[str, str] = {}
    for row in rows:
        category, label = _http_category(row)
        if not category:
            continue
        categories[category] = categories.get(category, 0) + 1
        category_labels[category] = label
        suspicious.append({"row": row, "category": category, "label": label})

    suspicious.sort(key=lambda item: (-(item["row"]["time_epoch"] or 0), item["row"]["id"]))
    shown = suspicious[:TABLE_CAP]

    points, bucket_total = _series(
        ((row["time_epoch"], 1) for row in rows), index.window
    )
    marked = {
        _bucket_index(float(row["time_epoch"]), index.window)
        for row in rows
        if row["time_epoch"] is not None and _http_category(row)[0]
    }
    for point in points:
        point["marker"] = _bucket_index(point["t"], index.window) in marked

    histogram = [
        {"label": category_labels[key], "value": value}
        for key, value in sorted(categories.items(), key=lambda item: (-item[1], item[0]))
    ]

    table_rows = [
        {
            "cells": [
                _cell(item["label"], tone="warn"),
                _cell(
                    f"{item['row']['method'] or ''} {item['row']['host'] or item['row']['server_ip'] or ''}"
                    f"{item['row']['uri'] or ''}".strip(),
                    to=_to("/http", tx=item["row"]["id"]),
                ),
                _cell(item["row"]["status_code"]),
                _cell(item["row"]["client_ip"], to=_to("/hosts", ip=item["row"]["client_ip"])),
                _cell(
                    item["row"]["request_packet"],
                    to=_to("/packets", sel=item["row"]["request_packet"]),
                ),
            ]
        }
        for item in shown
    ]

    visuals = [
        _timeline(
            f"HTTP requests per {index.window} s",
            points,
            "requests",
            _cap_note(len(points), bucket_total, f"bucket(s) of {index.window} s")
            or "marked buckets contain at least one request flagged below",
        ),
        # Every flagged transaction is counted here, so this histogram is not capped
        # and carries no cap note. It used to compare the list with itself, which can
        # never report anything.
        _histogram(
            "Flagged transactions by reason",
            histogram,
            "transactions",
        ),
        # The transactions themselves. Without this the timeline's "flagged below" note
        # pointed at nothing: the rows were built and then thrown away, so the reader
        # was promised a list that never appeared.
        _table(
            "Flagged transactions",
            ["reason", "request", "status", "client", "packet"],
            table_rows,
            _cap_note(len(shown), len(suspicious), "flagged transaction(s)"),
        ),
    ]

    host_links = []
    for item in suspicious:
        host = item["row"]["host"]
        if host and all(link["label"] != str(host) for link in host_links):
            host_links.append(_link(_to("/http", host=str(host)), str(host)))
        if len(host_links) >= 5:
            break

    if not suspicious:
        return _empty(
            "no transaction in this capture carried a flag from the HTTP analyzer, an "
            "executable or script payload type, or a dangerous file extension",
            visuals=visuals,
            links=host_links,
            label="flagged HTTP transaction(s)",
        )

    return _Result(
        "ok", None, len(suspicious), "flagged HTTP transaction(s)", "watch", visuals, host_links
    )


# --------------------------------------------------------------------------
# 7. suspicious_tls
# --------------------------------------------------------------------------

_LEGACY_TLS = ("SSL", "TLS 1.0", "TLS 1.1")

_TLS_LABELS = {
    "no_certificate": "no certificate observed",
    "tls10_or_older": "TLS 1.0 or older",
    "self_signed_suspected": "self-signed certificate suspected",
    "alert": "TLS alert",
    "incomplete_handshake": "incomplete handshake",
    "sni_absent": "no server name in the ClientHello",
}


def _tls_reasons(row: Any) -> list[str]:
    reasons = _flag_tokens(row["flags"])
    version = str(row["version"] or "")
    if version and any(version.startswith(prefix) for prefix in _LEGACY_TLS) and "tls10_or_older" not in reasons:
        reasons.append("tls10_or_older")
    if not row["sni"] and "sni_absent" not in reasons:
        reasons.append("sni_absent")
    return reasons


def _suspicious_tls(index: _Index) -> _Result:
    if not index.tls:
        return _not_applicable(NO_TLS)

    rows = db.query_all(
        """
        SELECT id, stream_id, time_epoch, client_ip, server_ip, server_port, sni, version,
               selected_alpn, cipher_suite, ja3, handshake_status, alert, client_packet, flags
          FROM tls_sessions
         WHERE analysis_id = ?
         ORDER BY time_epoch IS NULL, time_epoch ASC, id ASC
         LIMIT ?
        """,
        (index.analysis_id, PACKET_SCAN_CAP),
    )

    suspicious: list[dict] = []
    reasons: dict[str, int] = {}
    for row in rows:
        tokens = _tls_reasons(row)
        if not tokens:
            continue
        for token in tokens:
            reasons[token] = reasons.get(token, 0) + 1
        suspicious.append({"row": row, "reasons": tokens})

    suspicious.sort(key=lambda item: (-len(item["reasons"]), -(item["row"]["time_epoch"] or 0)))

    bar_items = [
        {
            "label": _TLS_LABELS.get(reason, reason.replace("_", " ")),
            "value": count,
        }
        for reason, count in sorted(reasons.items(), key=lambda item: (-item[1], item[0]))
    ][: index.top]

    shown = suspicious[:TABLE_CAP]
    table_rows = [
        {
            "cells": [
                _cell(
                    item["row"]["sni"] or "(no server name)",
                    tone="watch" if not item["row"]["sni"] else None,
                    to=_to("/tls", sni=item["row"]["sni"]) if item["row"]["sni"] else None,
                ),
                _cell(item["row"]["server_ip"], to=_to("/tls", ip=item["row"]["server_ip"])),
                _cell(item["row"]["version"] or ""),
                _cell(", ".join(_TLS_LABELS.get(token, token) for token in item["reasons"])),
                _cell(
                    item["row"]["client_packet"],
                    to=_to("/packets", sel=item["row"]["client_packet"]),
                ),
            ]
        }
        for item in shown
    ]

    visuals = [
        _bars("Sessions by observation", bar_items, "sessions", _cap_note(len(bar_items), len(reasons), "reason(s)")),
        _table(
            "TLS sessions carrying an observation",
            ["server name", "server", "version", "observation", "frame"],
            table_rows,
            _cap_note(len(shown), len(suspicious), "session(s)"),
        ),
    ]

    links = []
    for item in suspicious:
        sni = item["row"]["sni"]
        label = str(sni) if sni else str(item["row"]["server_ip"])
        if all(link["label"] != label for link in links):
            links.append(
                _link(
                    _to("/tls", sni=sni) if sni else _to("/tls", ip=item["row"]["server_ip"]),
                    label,
                )
            )
        if len(links) >= 5:
            break

    if not suspicious:
        return _empty(
            "no session in this capture carried a TLS lead flag, an obsolete protocol "
            "version, or a missing server name",
            visuals=visuals,
            links=links,
            label="TLS session(s) carrying an observation",
        )

    return _Result(
        "ok", None, len(suspicious), "TLS session(s) carrying an observation", "watch", visuals, links
    )


# --------------------------------------------------------------------------
# 8. unusual_ports
# --------------------------------------------------------------------------


def _unusual_ports(index: _Index) -> _Result:
    if not index.has_traffic:
        return _not_applicable(NO_PACKETS)

    rows = db.query_all(
        """
        SELECT dst_port, COUNT(*) AS packets, COUNT(DISTINCT src_ip) AS sources
          FROM packets
         WHERE analysis_id = ? AND dst_port IS NOT NULL
         GROUP BY dst_port
         ORDER BY packets DESC, dst_port ASC
         LIMIT ?
        """,
        (index.analysis_id, ROW_SCAN_CAP * 4),
    )

    uncommon = [row for row in rows if int(row["dst_port"]) not in COMMON_PORTS]
    single_use = [row for row in uncommon if int(row["packets"]) == 1]
    uncommon.sort(key=lambda row: (-int(row["packets"]), int(row["dst_port"])))
    single_use.sort(key=lambda row: int(row["dst_port"]))

    shown = uncommon[: index.top]
    items = [
        {
            "label": f"port {int(row['dst_port'])}",
            "value": int(row["packets"]),
            "to": _to("/packets", dst_port=int(row["dst_port"])),
        }
        for row in shown
    ]

    visuals = [
        _bars(
            "Destination ports outside the common service set, by packets",
            items,
            "packets",
            _cap_note(len(shown), len(uncommon), "port(s)")
            or f"{len(single_use)} of them were used exactly once",
        )
    ]

    links = [
        _link(_to("/packets", dst_port=int(row["dst_port"])), f"port {int(row['dst_port'])}")
        for row in single_use[:5]
    ]

    if not single_use:
        return _empty(
            f"no destination port outside the {len(COMMON_PORTS)} well-known ports the "
            "detection engine treats as common was used exactly once "
            f"({len(uncommon)} uncommon port(s) were observed in total)",
            visuals=visuals,
            links=links,
            label="single-use destination port(s) outside the common set",
        )

    return _Result(
        "ok",
        None,
        len(single_use),
        "single-use destination port(s) outside the common set",
        "info",
        visuals,
        links,
    )


# --------------------------------------------------------------------------
# 9. high_fan_out
# --------------------------------------------------------------------------


def _high_fan_out(index: _Index) -> _Result:
    if not index.hosts:
        return _not_applicable(NO_HOSTS)

    rows = db.query_all(
        """
        SELECT ip, mac, is_private, packets_sent, packets_received, bytes_sent,
               bytes_received, peer_count, dns_names
          FROM hosts
         WHERE analysis_id = ?
         ORDER BY peer_count DESC, ip ASC
         LIMIT ?
        """,
        (index.analysis_id, ROW_SCAN_CAP),
    )

    high = [row for row in rows if int(row["peer_count"] or 0) >= FAN_OUT_MIN_PEERS]
    median = float(statistics.median([int(row["peer_count"] or 0) for row in rows])) if rows else 0.0

    shown = high[: index.top]
    items = [
        {
            "label": str(row["ip"]),
            "value": int(row["peer_count"] or 0),
            "to": _to("/hosts", ip=row["ip"]),
        }
        for row in shown
    ]

    visuals = [
        _bars(
            "Distinct conversation peers per host",
            items,
            "peers",
            _cap_note(len(shown), len(high), "host(s)"),
        )
    ]

    links = [_link(_to("/hosts", ip=row["ip"]), str(row["ip"])) for row in shown[:5]]

    if not high:
        return _empty(
            f"no host reached {FAN_OUT_MIN_PEERS} distinct peers "
            f"(highest observed: {max((int(r['peer_count'] or 0) for r in rows), default=0)}; "
            f"median: {median:.0f})",
            visuals=visuals,
            links=links,
            label=f"host(s) with {FAN_OUT_MIN_PEERS}+ peers",
        )

    return _Result(
        "ok", None, len(high), f"host(s) with {FAN_OUT_MIN_PEERS}+ peers", "info", visuals, links
    )


# --------------------------------------------------------------------------
# 10. rare_pairs
# --------------------------------------------------------------------------


def _rare_pairs(index: _Index) -> _Result:
    if not index.conversations:
        return _not_applicable(NO_CONVERSATIONS)

    rows = db.query_all(
        """
        SELECT ip_a, ip_b, transport, stream_id, packets_total, bytes_total, start_time, state
          FROM conversations
         WHERE analysis_id = ? AND ip_a IS NOT NULL AND ip_b IS NOT NULL
         ORDER BY start_time IS NULL, start_time ASC, conv_id ASC
         LIMIT ?
        """,
        (index.analysis_id, PACKET_SCAN_CAP),
    )

    pairs: dict[tuple[str, str], dict] = {}
    for row in rows:
        key = tuple(sorted((str(row["ip_a"]), str(row["ip_b"]))))  # type: ignore[assignment]
        entry = pairs.setdefault(
            key,
            {"conversations": 0, "packets": 0, "bytes": 0, "first": row},
        )
        entry["conversations"] += 1
        entry["packets"] += int(row["packets_total"] or 0)
        entry["bytes"] += int(row["bytes_total"] or 0)

    rare = [
        entry
        for entry in pairs.values()
        if entry["conversations"] == 1 and entry["packets"] <= RARE_PAIR_MAX_PACKETS
    ]
    rare.sort(
        key=lambda entry: (
            str(entry["first"]["ip_a"]),
            str(entry["first"]["ip_b"]),
        )
    )

    shown = rare[:TABLE_CAP]
    table_rows = []
    for entry in shown:
        row = entry["first"]
        table_rows.append(
            {
                "cells": [
                    _cell(
                        f"{row['ip_a']} ↔ {row['ip_b']}",
                        tone="watch",
                        to=_to("/conversations", ip=row["ip_a"]),
                    ),
                    _cell(row["transport"]),
                    _cell(
                        entry["packets"],
                        to=_to("/packets", ip=row["ip_a"]),
                    ),
                    _cell(entry["bytes"]),
                    _cell(_scope_label(row["ip_a"]) + " / " + _scope_label(row["ip_b"])),
                ]
            }
        )

    visuals = [
        _table(
            "Address pairs seen in exactly one conversation",
            ["pair", "transport", "packets", "bytes", "scope"],
            table_rows,
            _cap_note(len(shown), len(rare), "pair(s)")
            or f"a pair qualifies when it appears in one conversation carrying at most "
            f"{RARE_PAIR_MAX_PACKETS} packets",
        )
    ]

    links = []
    for entry in rare:
        row = entry["first"]
        for value, label in ((row["ip_a"], str(row["ip_a"])), (row["ip_b"], str(row["ip_b"]))):
            if all(link["label"] != label for link in links):
                links.append(_link(_to("/conversations", ip=value), label))
        if len(links) >= 5:
            break

    if not rare:
        return _empty(
            f"no address pair appears in exactly one conversation carrying at most "
            f"{RARE_PAIR_MAX_PACKETS} packets ({len(pairs)} pair(s) observed)",
            visuals=visuals,
            links=links,
            label="rare address pair(s)",
        )

    return _Result("ok", None, len(rare), "rare address pair(s)", "info", visuals, links)


def _scope_label(value: Any) -> str:
    return address_scope(value) or "unknown"


# --------------------------------------------------------------------------
# 11. malware_download
# --------------------------------------------------------------------------


def _payload_kind(uri: Any, content_type: Any) -> str:
    extension = _extension(uri)
    lowered = str(content_type or "").lower()
    if extension in DANGEROUS_EXTENSIONS_STRICT:
        return f".{extension} payload"
    for marker in DANGEROUS_CONTENT_TYPES:
        if marker in lowered:
            return marker
    return ""


def _malware_download(index: _Index) -> _Result:
    if not index.http and not index.packets:
        return _not_applicable(
            "the capture recorded no HTTP transactions and holds no packet rows, so no "
            "download can be identified"
        )

    transactions = db.query_all(
        """
        SELECT id, time_epoch, request_packet, client_ip, server_ip, host, uri,
               content_type, response_len, response_body_size, flags
          FROM http_transactions
         WHERE analysis_id = ?
         ORDER BY time_epoch IS NULL, time_epoch ASC, id ASC
         LIMIT ?
        """,
        (index.analysis_id, PACKET_SCAN_CAP),
    )

    objects = db.query_all(
        """
        SELECT id, filename, content_type, size, protocol, src_ip, dst_ip, stream_id,
               packet_numbers
          FROM objects
         WHERE analysis_id = ?
         ORDER BY size DESC
         LIMIT ?
        """,
        (index.analysis_id, ROW_SCAN_CAP),
    )

    candidates: list[dict] = []
    for row in transactions:
        kind = _payload_kind(row["uri"], row["content_type"])
        if not kind:
            continue
        candidates.append(
            {
                "kind": kind,
                "source": "http",
                "time": row["time_epoch"],
                "client": row["client_ip"],
                "server": row["server_ip"],
                "host": row["host"],
                "name": str(row["uri"] or "").rsplit("/", 1)[-1],
                "uri": row["uri"],
                "size": int(row["response_body_size"] or row["response_len"] or 0),
                "packet": row["request_packet"],
                "transaction": row["id"],
            }
        )
    for row in objects:
        kind = _payload_kind(row["filename"], row["content_type"])
        if not kind:
            continue
        numbers = _json_list(row["packet_numbers"])
        first = next((int(value) for value in numbers if isinstance(value, (int, float))), None)
        candidates.append(
            {
                "kind": kind,
                "source": "object",
                "time": None,
                "client": row["src_ip"],
                "server": row["dst_ip"],
                "host": None,
                "name": str(row["filename"] or ""),
                "uri": None,
                "size": int(row["size"] or 0),
                "packet": first,
                "transaction": None,
                "object_id": row["id"],
            }
        )

    id_alerts = _ids_alert_map(index.analysis_id)
    for item in candidates:
        item["ids_alerts"] = id_alerts.get(str(item["server"]), 0)

    candidates.sort(key=lambda item: (-item["size"], str(item["name"])))

    points, bucket_total = _series(
        (
            (row["time_epoch"], int(row["response_body_size"] or row["response_len"] or 0))
            for row in transactions
        ),
        index.window,
    )
    marked = {
        _bucket_index(float(item["time"]), index.window)
        for item in candidates
        if item["source"] == "http" and item["time"] is not None
    }
    for point in points:
        point["marker"] = _bucket_index(point["t"], index.window) in marked

    shown = candidates[:TABLE_CAP]
    table_rows = [
        {
            "cells": [
                _cell(item["name"] or "(unnamed)", tone="warn", to=(_to("/objects") if item["source"] == "object" else _to("/http", tx=item["transaction"]))),
                _cell(item["host"] or item["server"] or ""),
                _cell(f"{item['size']:,} bytes"),
                _cell(item["kind"]),
                _cell(
                    item["packet"],
                    to=_to("/packets", sel=item["packet"]) if item["packet"] is not None else None,
                ),
                _cell(item["ids_alerts"]),
            ]
        }
        for item in shown
    ]

    visuals = [
        _timeline(
            f"HTTP response bytes per {index.window} s",
            points,
            "bytes",
            _cap_note(len(points), bucket_total, f"bucket(s) of {index.window} s")
            or "marked buckets contain a download listed below"
            if candidates
            else "no transaction in this capture carried an executable or script payload",
        ),
        _table(
            "Executable and script payloads transferred",
            ["payload", "host", "size", "type", "frame", "IDS alerts"],
            table_rows,
            _cap_note(len(shown), len(candidates), "payload(s)"),
        ),
    ]

    links = []
    for item in candidates:
        if item["host"] and all(link["label"] != str(item["host"]) for link in links):
            links.append(_link(_to("/http", host=str(item["host"])), str(item["host"])))
        if len(links) >= 5:
            break

    if not candidates:
        return _empty(
            "no HTTP transfer in this capture carried an executable or script content "
            "type, and no extracted file had such an extension",
            visuals=visuals,
            links=links,
            label="executable or script payload(s) transferred",
        )

    return _Result(
        "ok",
        None,
        len(candidates),
        "executable or script payload(s) transferred",
        "warn",
        visuals,
        links,
    )


def _ids_alert_map(analysis_id: str) -> dict[str, int]:
    """Count of IDS findings per IP, from the ``findings`` table."""
    counts: dict[str, int] = {}
    for row in db.query_all(
        """
        SELECT entities FROM findings
         WHERE analysis_id = ? AND rule_id LIKE 'suricata:%'
         LIMIT ?
        """,
        (analysis_id, ROW_SCAN_CAP),
    ):
        entities = row["entities"]
        data: Any = {}
        if isinstance(entities, str) and entities.strip():
            try:
                data = json.loads(entities)
            except (TypeError, ValueError):
                data = {}
        if not isinstance(data, dict):
            continue
        for value in data.get("ips") or []:
            key = str(value)
            counts[key] = counts.get(key, 0) + 1
    return counts


# --------------------------------------------------------------------------
# 12. dns_tunnelling
# --------------------------------------------------------------------------


def _base_domain(name: str) -> str:
    labels = [label for label in str(name).split(".") if label]
    if len(labels) >= 2:
        return ".".join(labels[-2:])
    return str(name)


def _dns_tunnelling(index: _Index) -> _Result:
    if not index.dns:
        return _not_applicable(NO_DNS)

    rows = db.query_all(
        """
        SELECT COALESCE(client_ip, 'unknown') AS client, query_name, longest_label, entropy
          FROM dns_queries
         WHERE analysis_id = ? AND query_name IS NOT NULL
         LIMIT ?
        """,
        (index.analysis_id, PACKET_SCAN_CAP),
    )

    groups: dict[tuple[str, str], dict] = {}
    for row in rows:
        name = str(row["query_name"])
        key = (str(row["client"]), _base_domain(name))
        entry = groups.setdefault(key, {"names": set(), "queries": 0, "labels": [], "entropy": []})
        entry["names"].add(name)
        entry["queries"] += 1
        entry["labels"].append(int(row["longest_label"] or 0))
        entry["entropy"].append(float(row["entropy"] or 0.0))

    ranked: list[dict] = []
    for (client, domain), entry in groups.items():
        names = len(entry["names"])
        average_label = _mean(entry["labels"])
        average_entropy = _mean(entry["entropy"])
        ranked.append(
            {
                "client": client,
                "domain": domain,
                "names": names,
                "queries": entry["queries"],
                "label": average_label,
                "entropy": average_entropy,
            }
        )
    ranked.sort(key=lambda item: (-item["names"], -item["queries"], item["domain"]))

    suspects = [
        item
        for item in ranked
        if item["names"] >= TUNNEL_MIN_NAMES
        and item["queries"] >= TUNNEL_MIN_QUERIES
        and item["label"] >= TUNNEL_MIN_LABEL
        and item["entropy"] >= TUNNEL_MIN_ENTROPY
    ]

    points = [
        {
            "x": round(item["label"], 2),
            "y": item["queries"],
            "label": item["domain"],
            "to": _to("/dns", domain=item["domain"], client_ip=item["client"]),
        }
        for item in ranked[:SCATTER_CAP]
    ]

    shown = suspects[:TABLE_CAP]
    table_rows = [
        {
            "cells": [
                _cell(
                    item["domain"],
                    tone="watch",
                    to=_to("/dns", domain=item["domain"], client_ip=item["client"]),
                ),
                _cell(item["client"], to=_to("/hosts", ip=item["client"])),
                _cell(item["names"]),
                _cell(item["queries"]),
                _cell(f"{item['label']:.1f}"),
                _cell(f"{item['entropy']:.2f}"),
            ]
        }
        for item in shown
    ]

    visuals = [
        _scatter(
            "Mean longest label against query count",
            points,
            "mean longest label",
            "queries",
            f"{len(points)} client/domain pair(s); the threshold box is "
            f"\u2265{TUNNEL_MIN_LABEL:.0f} label characters, \u2265{TUNNEL_MIN_NAMES} distinct names, "
            f"\u2265{TUNNEL_MIN_QUERIES} queries",
        ),
        _table(
            "Client and domain pairs above every tunnelling threshold",
            ["domain", "client", "names", "queries", "mean label", "mean entropy"],
            table_rows,
            _cap_note(len(shown), len(suspects), "pair(s)"),
        ),
    ]

    links = [
        _link(_to("/dns", domain=item["domain"]), item["domain"]) for item in suspects[:5]
    ]

    if not suspects:
        return _empty(
            f"no client/domain pair reached {TUNNEL_MIN_NAMES} distinct names, "
            f"{TUNNEL_MIN_QUERIES} queries, a mean longest label of {TUNNEL_MIN_LABEL:.0f} "
            f"characters and a mean entropy of {TUNNEL_MIN_ENTROPY} at once "
            f"({len(ranked)} pair(s) observed)",
            visuals=visuals,
            links=links,
            label="client/domain pair(s) above every tunnelling threshold",
        )

    return _Result(
        "ok",
        None,
        len(suspects),
        "client/domain pair(s) above every tunnelling threshold",
        "watch",
        visuals,
        links,
    )


# --------------------------------------------------------------------------
# 13. ids_matches
# --------------------------------------------------------------------------

_SEVERITY_RANK = {"high": 0, "medium": 1, "low": 2, "informational": 3}
_SEVERITY_TONE = {"high": "warn", "medium": "watch", "low": "info", "informational": "info"}


def _ids_matches(index: _Index) -> _Result:
    if not index.findings:
        return _not_applicable(
            "the findings index holds no rows for this capture, so an IDS signature "
            "match cannot be told apart from a detection stage that did not run"
        )

    rows = db.query_all(
        """
        SELECT id, rule_id, severity, title, reason, packet_numbers, entities
          FROM findings
         WHERE analysis_id = ? AND rule_id LIKE 'suricata:%'
         LIMIT ?
        """,
        (index.analysis_id, ROW_SCAN_CAP),
    )

    matches = []
    for row in rows:
        entities: Any = {}
        raw = row["entities"]
        if isinstance(raw, str) and raw.strip():
            try:
                entities = json.loads(raw)
            except (TypeError, ValueError):
                entities = {}
        if not isinstance(entities, dict):
            entities = {}
        numbers = _json_list(row["packet_numbers"])
        matches.append(
            {
                "id": row["id"],
                "rule_id": str(row["rule_id"]).split(":", 1)[-1],
                "severity": str(row["severity"] or "informational").lower(),
                "title": row["title"],
                "endpoints": ", ".join(str(value) for value in (entities.get("ips") or [])[:4]),
                "names": ", ".join(str(value) for value in (entities.get("hostnames") or [])[:3]),
                "packets": [int(value) for value in numbers if isinstance(value, (int, float))],
            }
        )
    matches.sort(
        key=lambda item: (
            _SEVERITY_RANK.get(item["severity"], 4),
            item["rule_id"],
            str(item["id"]),
        )
    )

    shown = matches[:TABLE_CAP]
    table_rows = [
        {
            "cells": [
                _cell(item["severity"], tone=_SEVERITY_TONE.get(item["severity"], "info")),
                _cell(f"suricata:{item['rule_id']}"),
                _cell(
                    item["title"],
                    to=_to(f"/findings/{quote(str(item['id']), safe='')}"),
                ),
                _cell(item["endpoints"] or item["names"] or ""),
                _cell(
                    len(item["packets"]),
                    to=_to("/packets", sel=item["packets"][0]) if item["packets"] else None,
                ),
            ]
        }
        for item in shown
    ]

    visuals = [
        _table(
            "Signature matches recorded for this capture",
            ["severity", "rule", "title", "endpoints", "packets"],
            table_rows,
            _cap_note(len(shown), len(matches), "match(es)"),
        )
    ]

    links = [{"to": f"/findings/{quote(str(item['id']), safe='')}", "label": item["title"]} for item in shown[:5]]

    if not matches:
        return _empty(
            f"none of the {index.findings} finding(s) recorded for this capture carries a "
            "suricata:<sid> rule id",
            visuals=visuals,
            links=links,
            label="IDS signature match(es)",
        )

    tone = "warn" if any(item["severity"] == "high" for item in matches) else "watch"
    return _Result("ok", None, len(matches), "IDS signature match(es)", tone, visuals, links)


# --------------------------------------------------------------------------
# 14. traffic_bursts
# --------------------------------------------------------------------------


def _traffic_bursts(index: _Index) -> _Result:
    rows = db.query_all(
        """
        SELECT CAST(time_epoch / ? AS INTEGER) AS bucket, COUNT(*) AS packets
          FROM packets
         WHERE analysis_id = ? AND time_epoch IS NOT NULL
         GROUP BY bucket
         ORDER BY bucket ASC
        """,
        (index.window, index.analysis_id),
    )
    if not rows:
        return _not_applicable(
            "the packet index holds no timestamped frames for this capture, so no "
            "volume baseline can be measured"
        )

    buckets = [(int(row["bucket"]), int(row["packets"])) for row in rows]
    values = [value for _bucket, value in buckets]
    mean = _mean(values)
    spread = float(statistics.pstdev(values)) if len(values) > 1 else 0.0
    threshold = mean + BURST_SIGMAS * spread

    bursts = [
        (bucket, value)
        for bucket, value in buckets
        if value >= BURST_MIN_PACKETS and value > threshold
    ]

    shown = buckets[:TIMELINE_CAP]
    burst_keys = {bucket for bucket, _value in bursts}
    points = [
        {"t": float(bucket * index.window), "value": value, "marker": bucket in burst_keys}
        for bucket, value in shown
    ]

    visuals = [
        _timeline(
            f"Packets per {index.window} s against the capture's own baseline",
            points,
            "packets",
            _cap_note(len(points), len(buckets), f"bucket(s) of {index.window} s")
            or f"baseline {mean:.0f} packets per bucket, burst threshold "
            f"{threshold:.0f} (mean + {BURST_SIGMAS:.0f}\u03c3, and at least "
            f"{BURST_MIN_PACKETS} packets); marked buckets are bursts",
        )
    ]

    if not bursts:
        return _empty(
            f"no {index.window} s bucket exceeded the burst threshold of {threshold:.0f} "
            f"packets (baseline {mean:.0f}, spread {spread:.0f}, floor "
            f"{BURST_MIN_PACKETS} packets) across {len(buckets)} bucket(s)",
            visuals=visuals,
            label="burst bucket(s)",
        )

    return _Result("ok", None, len(bursts), "burst bucket(s)", "watch", visuals, [])


# --------------------------------------------------------------------------
# 15. unusual_egress
# --------------------------------------------------------------------------


def _host_names(analysis_id: str) -> dict[str, set[str]]:
    names: dict[str, set[str]] = {}
    for row in db.query_all(
        "SELECT ip, dns_names, tls_sni FROM hosts WHERE analysis_id = ? LIMIT ?",
        (analysis_id, PACKET_SCAN_CAP),
    ):
        collected = names.setdefault(str(row["ip"]), set())
        for value in _json_list(row["dns_names"]) + _json_list(row["tls_sni"]):
            text = str(value).strip()
            if text:
                collected.add(text)
    return names


def _unusual_egress(index: _Index) -> _Result:
    if not index.conversations:
        return _not_applicable(NO_CONVERSATIONS)

    names = _host_names(index.analysis_id)
    pairs = _outbound_pairs(index.analysis_id)

    # Ports actually used towards each public peer, from the conversation rows.
    port_rows = db.query_all(
        """
        SELECT ip_a, ip_b, port_a, port_b, bytes_a_to_b, bytes_b_to_a, packets_total
          FROM conversations
         WHERE analysis_id = ? AND ip_a IS NOT NULL AND ip_b IS NOT NULL
         LIMIT ?
        """,
        (index.analysis_id, PACKET_SCAN_CAP),
    )

    findings: dict[tuple[str, str], dict] = {}
    for row in port_rows:
        left, right = str(row["ip_a"]), str(row["ip_b"])
        if _private(left) and _is_public_unicast(right):
            source, peer = left, right
            sent = int(row["bytes_a_to_b"] or 0)
        elif _private(right) and _is_public_unicast(left):
            source, peer = right, left
            sent = int(row["bytes_b_to_a"] or 0)
        else:
            continue
        port = row["port_b"] if source == left else row["port_a"]
        if port is None:
            continue
        port = int(port)
        unusual_port = port not in STANDARD_EGRESS_PORTS
        unnamed = not names.get(peer)
        if not unusual_port and not unnamed:
            continue
        key = (source, peer)
        entry = findings.setdefault(
            key,
            {
                "source": source,
                "peer": peer,
                "ports": {},
                "sent": 0,
                "conversations": 0,
                "unnamed": unnamed,
                "unusual_port": unusual_port,
            },
        )
        entry["sent"] += sent
        entry["conversations"] += 1
        entry["ports"][port] = entry["ports"].get(port, 0) + 1
        entry["unnamed"] = entry["unnamed"] or unnamed
        entry["unusual_port"] = entry["unusual_port"] or unusual_port

    ranked = sorted(findings.values(), key=lambda item: (-item["sent"], item["peer"]))
    shown = ranked[: index.top]

    items = []
    for entry in shown:
        ports = ", ".join(
            str(port) for port, _count in sorted(entry["ports"].items(), key=lambda i: (-i[1], i[0]))[:3]
        )
        reason = "non-standard port" if entry["unusual_port"] else "no name evidence"
        items.append(
            {
                "label": f"{entry['peer']} port {ports} ({reason})",
                "value": entry["sent"],
                "to": _to("/conversations", ip=entry["peer"]),
            }
        )

    visuals = [
        _bars(
            "Outbound volume to public destinations outside the standard egress set",
            items,
            "bytes",
            _cap_note(len(shown), len(ranked), "destination(s)")
            or "a destination qualifies when the port used is outside the standard "
            "egress set or the capture holds no name for it",
        )
    ]

    links = [_link(_to("/conversations", ip=entry["peer"]), entry["peer"]) for entry in shown[:5]]

    if not ranked:
        return _empty(
            "every public destination reached from a private address used a standard "
            "egress port and already had a name in this capture "
            f"({len(pairs)} internal-to-public destination(s) observed; standard ports: "
            + ", ".join(str(port) for port in sorted(STANDARD_EGRESS_PORTS))
            + ")",
            visuals=visuals,
            links=links,
            label="unusual egress destination(s)",
        )

    return _Result(
        "ok", None, len(ranked), "unusual egress destination(s)", "info", visuals, links
    )


# --------------------------------------------------------------------------
# 16. data_staging
# --------------------------------------------------------------------------

_STAGING_BUCKETS: tuple[tuple[float, str], ...] = (
    (10_240, "under 10 KB"),
    (102_400, "10-100 KB"),
    (1_048_576, "100 KB-1 MB"),
    (10_485_760, "1-10 MB"),
    (math.inf, "10 MB and over"),
)


def _data_staging(index: _Index) -> _Result:
    if not index.conversations:
        return _not_applicable(NO_CONVERSATIONS)

    rows = db.query_all(
        """
        SELECT ip_a, ip_b, transport, stream_id, packets_total, bytes_total, start_time
          FROM conversations
         WHERE analysis_id = ? AND ip_a IS NOT NULL AND ip_b IS NOT NULL
         ORDER BY bytes_total DESC
         LIMIT ?
        """,
        (index.analysis_id, PACKET_SCAN_CAP),
    )

    internal = [
        {
            "src": str(row["ip_a"]),
            "dst": str(row["ip_b"]),
            "transport": row["transport"],
            "stream_id": row["stream_id"],
            "packets": int(row["packets_total"] or 0),
            "bytes": int(row["bytes_total"] or 0),
            "start": row["start_time"],
        }
        for row in rows
        if _private(row["ip_a"]) and _private(row["ip_b"])
    ]

    if not internal:
        return _empty(
            "the capture records no conversation between two private addresses, so no "
            "internal transfer can be measured",
            visuals=[
                _timeline("Internal transfer bytes per bucket", [], "bytes"),
                _histogram("Internal transfer sizes", [], "conversations"),
            ],
            label="internal transfer(s) above the threshold",
        )

    internal.sort(key=lambda item: -item["bytes"])
    candidates = [item for item in internal if item["bytes"] >= STAGING_MIN_BYTES]

    sizes: dict[str, int] = {}
    for item in internal:
        label = _bucket_label(float(item["bytes"]), _STAGING_BUCKETS)
        sizes[label] = sizes.get(label, 0) + 1

    points, bucket_total = _series(
        ((item["start"], item["bytes"]) for item in internal), index.window
    )

    visuals = [
        _timeline(
            f"Internal transfer bytes per {index.window} s",
            points,
            "bytes",
            _cap_note(len(points), bucket_total, f"bucket(s) of {index.window} s"),
        ),
        _histogram(
            "Internal transfer sizes",
            [
                {"label": label, "value": sizes[label]}
                for _limit, label in _STAGING_BUCKETS
                if sizes.get(label)
            ],
            "conversations",
            f"{len(internal)} internal conversation(s); staging threshold "
            f"{STAGING_MIN_BYTES:,} bytes",
        ),
    ]

    links = []
    for item in internal:
        for value, label in ((item["src"], item["src"]), (item["dst"], item["dst"])):
            if all(link["label"] != label for link in links):
                links.append(_link(_to("/hosts", ip=value), label))
        if len(links) >= 5:
            break

    if not candidates:
        return _empty(
            f"no conversation between two private addresses carried "
            f"{STAGING_MIN_BYTES:,} bytes or more (largest observed: "
            f"{max(item['bytes'] for item in internal):,} bytes across "
            f"{len(internal)} internal conversation(s))",
            visuals=visuals,
            links=links,
            label="internal transfer(s) above the threshold",
        )

    return _Result(
        "ok",
        None,
        len(candidates),
        "internal transfer(s) above the threshold",
        "watch",
        visuals,
        links,
    )


# --------------------------------------------------------------------------
# 17. failed_connections
# --------------------------------------------------------------------------


def _failed_connections(index: _Index) -> _Result:
    if not index.has_traffic:
        return _not_applicable(NO_PACKETS)
    if not index.tcp_packets:
        return _not_applicable(NO_TCP)

    rows = db.query_all(
        """
        WITH attempts AS (
            SELECT src_ip, dst_ip, dst_port, number, time_epoch
              FROM packets
             WHERE analysis_id = ? AND transport = 'tcp'
               AND src_ip IS NOT NULL AND dst_ip IS NOT NULL AND dst_port IS NOT NULL
               AND (tcp_flags_raw & 2) = 2 AND (tcp_flags_raw & 16) = 0
        ),
        answered AS (
            SELECT DISTINCT src_ip AS server_ip, dst_ip AS client_ip, src_port AS port
              FROM packets
             WHERE analysis_id = ? AND transport = 'tcp'
               AND src_ip IS NOT NULL AND dst_ip IS NOT NULL AND src_port IS NOT NULL
               AND (tcp_flags_raw & 18) = 18
        )
        SELECT a.src_ip, a.dst_ip, a.dst_port, COUNT(*) AS attempts,
               MIN(a.number) AS first_frame, MIN(a.time_epoch) AS first_time
          FROM attempts a
          LEFT JOIN answered s
            ON s.server_ip = a.dst_ip AND s.client_ip = a.src_ip AND s.port = a.dst_port
         WHERE s.server_ip IS NULL
         GROUP BY a.src_ip, a.dst_ip, a.dst_port
         ORDER BY attempts DESC
         LIMIT ?
        """,
        (index.analysis_id, index.analysis_id, ROW_SCAN_CAP),
    )

    flows = [
        {
            "src": str(row["src_ip"]),
            "dst": str(row["dst_ip"]),
            "port": int(row["dst_port"]),
            "attempts": int(row["attempts"]),
            "first_frame": int(row["first_frame"]) if row["first_frame"] is not None else None,
            "first_time": row["first_time"],
        }
        for row in rows
    ]
    flows.sort(key=lambda flow: (-flow["attempts"], flow["src"], flow["dst"]))

    per_destination: dict[tuple[str, str], int] = {}
    for flow in flows:
        key = (flow["src"], flow["dst"])
        per_destination[key] = per_destination.get(key, 0) + flow["attempts"]

    failed = [
        {"source": source, "destination": destination, "attempts": attempts}
        for (source, destination), attempts in per_destination.items()
        if attempts >= FAILED_MIN_ATTEMPTS
    ]
    failed.sort(key=lambda item: (-item["attempts"], item["destination"]))
    shown = failed[: index.top]

    points, bucket_total = _series(
        ((flow["first_time"], flow["attempts"]) for flow in flows), index.window
    )
    marked = {
        _bucket_index(float(flow["first_time"]), index.window)
        for flow in flows
        if flow["first_time"] is not None and flow["attempts"] >= FAILED_MIN_ATTEMPTS
    }
    for point in points:
        point["marker"] = _bucket_index(point["t"], index.window) in marked

    port_rank: dict[int, int] = {}
    for flow in flows:
        port_rank[flow["port"]] = port_rank.get(flow["port"], 0) + flow["attempts"]
    ranked_ports = sorted(port_rank.items(), key=lambda item: (-item[1], item[0]))[: index.top]

    visuals = [
        _timeline(
            f"Unanswered connection attempts per {index.window} s",
            points,
            "attempts",
            _cap_note(len(points), bucket_total, f"bucket(s) of {index.window} s")
            or "marked buckets contain a destination that reached the "
            f"{FAILED_MIN_ATTEMPTS}-attempt threshold",
        ),
        _bars(
            "Unanswered attempts by destination port",
            [
                {
                    "label": f"port {port}",
                    "value": value,
                    # `tcp_flags` is tshark's dotted flag string ("···A··S·"),
                    # so `tcp_flags=SYN` would match nothing: the port filter is
                    # the one that actually lands on these frames.
                    "to": _to("/packets", dst_port=port),
                }
                for port, value in ranked_ports
            ],
            "attempts",
            _cap_note(len(ranked_ports), len(port_rank), "port(s)"),
        ),
    ]

    links = [
        _link(_to("/hosts", ip=item["destination"]), item["destination"]) for item in shown[:5]
    ]

    if not failed:
        total = sum(per_destination.values())
        return _empty(
            f"no source reached {FAILED_MIN_ATTEMPTS} unanswered connection attempts to "
            f"one destination (total unanswered attempts in this capture: {total})",
            visuals=visuals,
            links=links,
            label="destination(s) with repeated unanswered attempts",
        )

    return _Result(
        "ok",
        None,
        len(failed),
        "destination(s) with repeated unanswered attempts",
        "watch",
        visuals,
        links,
    )


# --------------------------------------------------------------------------
# entry point
# --------------------------------------------------------------------------

_BUILDERS = {
    "c2_beaconing": _c2_beaconing,
    "network_scanning": _network_scanning,
    "dns_anomalies": _dns_anomalies,
    "data_exfiltration": _data_exfiltration,
    "lateral_movement": _lateral_movement,
    "suspicious_http": _suspicious_http,
    "suspicious_tls": _suspicious_tls,
    "unusual_ports": _unusual_ports,
    "high_fan_out": _high_fan_out,
    "rare_pairs": _rare_pairs,
    "malware_download": _malware_download,
    "dns_tunnelling": _dns_tunnelling,
    "ids_matches": _ids_matches,
    "traffic_bursts": _traffic_bursts,
    "unusual_egress": _unusual_egress,
    "data_staging": _data_staging,
    "failed_connections": _failed_connections,
}


def _has_data(visual: dict) -> bool:
    return any(visual.get(key) for key in ("items", "points", "buckets", "rows"))


def _render(spec: _Spec, result: _Result) -> dict:
    """Assemble one §3.1 indicator.

    §8 requires that an ``"ok"`` indicator never carries an empty chart, so a
    visual whose series came back empty is dropped from an ``"ok"`` indicator
    rather than rendered as an empty axis. Nothing is invented to fill it: the
    builders only return ``"ok"`` when the collection behind the headline is
    non-empty, and ``headline.value`` is that collection's real length.
    """
    if result.availability == "ok":
        populated = [visual for visual in result.visuals if _has_data(visual)]
        if populated:
            result.visuals = populated
        elif not result.visuals:
            result.visuals = _empty_visuals(spec)
            log.warning("indicator %s reported ok with no data", spec.id)
    return {
        "id": spec.id,
        "title": spec.title,
        "question": spec.question,
        "availability": result.availability,
        "availability_reason": result.reason,
        "headline": {
            "value": result.headline_value,
            "label": result.headline_label,
            "tone": result.tone,
        },
        "visuals": result.visuals,
        "interpretation": spec.interpretation,
        "caveat": spec.caveat,
        "links": result.links,
    }


def _empty_visuals(spec: _Spec) -> list[dict]:
    """The §4 shapes this indicator declares, with no data."""
    payloads: dict[str, dict] = {
        "bars": {"items": []},
        "timeline": {"points": []},
        "histogram": {"buckets": []},
        "scatter": {"points": [], "x_label": "", "y_label": ""},
        "heatmap": {"columns": [], "rows": []},
        "table": {"columns": [], "rows": []},
    }
    visuals = []
    for kind in spec.visuals:
        visual = {"kind": kind, "title": spec.title, **payloads[kind]}
        visual.setdefault("unit", "")
        visual["note"] = ""
        visuals.append(visual)
    return visuals


def analyze(analysis_id: str, *, window: int = 60, top: int = 12) -> dict:
    """Every Threat Hunt indicator for one finished analysis.

    ``window`` is the seconds-per-bucket for every time series and ``top`` caps
    each ranked visual. Both are validated by the route; this function also
    clamps them so it can be called directly (from a test or a script) without
    producing an unbounded response.
    """
    window = max(5, min(3600, int(window)))
    top = max(1, min(50, int(top)))
    started = time.monotonic()

    index = _load_index(analysis_id, window, top)
    indicators: list[dict] = []

    for spec in SPECS:
        try:
            result = _BUILDERS[spec.id](index)
        except Exception:  # noqa: BLE001 - one bad indicator must not sink the page
            log.exception("threat hunt indicator %s failed for %s", spec.id, analysis_id)
            result = _Result(
                "not_applicable",
                FAILED_REASON,
                0,
                "not computable from this index",
                "info",
                _empty_visuals(spec),
                [],
            )
        indicators.append(_render(spec, result))

    elapsed = time.monotonic() - started
    log.info(
        "threat hunt %s: %s indicators in %.3fs (window=%s top=%s)",
        analysis_id,
        len(indicators),
        elapsed,
        window,
        top,
    )

    return {
        "analysis_id": analysis_id,
        "generated_at": time.time(),
        "packets_scanned": index.packets,
        "window": window,
        "top": top,
        "note": PAGE_NOTE,
        "indicators": indicators,
    }


__all__ = [
    "SPECS",
    "analyze",
    "FAILED_REASON",
    "TABLE_CAP",
    "TIMELINE_CAP",
    "SCATTER_CAP",
]
