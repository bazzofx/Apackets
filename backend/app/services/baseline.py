"""The baseline network: one analysed capture that later captures are compared against.

A baseline answers a question this application could not answer before: *is this new
relative to the network I know?* It is deliberately **one capture, not a statistical
model** - the analyst picks a capture they trust to represent the network, marks it as
the baseline, and every later analysis is then diffed against the entities that
capture contained.

What a baseline is
------------------
A profile of one completed analysis, per kind:

===============  ==========================================================
hosts            every address that appeared as a source or a destination
peers            every (src, dst) pair seen, i.e. who talked to whom
services         every (dst_ip, dst_port, transport), i.e. who offered what
dns_names        every name queried
http_hosts       every HTTP Host requested
sni              every TLS server name from the handshake
ja3              every client fingerprint observed
===============  ==========================================================

The baseline is **global**: one capture describes the network, every analysis is
compared against it, and the mode is either on for all of them or off.

What it is not
--------------
It is **not** a baseline of normal *behaviour*. A single capture has no notion of
"usual volume for this host at this hour", and pretending otherwise would be the one
claim this application must not make. So the rules here report **novelty** - an entity
the reference never contained - and never a deviation of degree.

Two honesty rules are structural, not cosmetic:

* everything a finding says about the baseline is *inside the finding*, including
  which capture the reference was and how much of this capture's traffic the two
  share;
* if the capture shares **no host at all** with the baseline, the novelty rules stay
  silent and a single baseline_no_overlap finding says the comparison is not
  meaningful. A different network is not a network full of anomalies.
"""

from __future__ import annotations

import ipaddress
import json
import sqlite3
import time
from typing import Any, Iterable, Sequence

from app.core.errors import bad_request
from app.core.logging import get_logger
from app.db import database as db

log = get_logger("shadowpackets.baseline")

CONFIG_KEY = "baseline_config"

#: Bumped when the set of profile kinds changes, so a profile built by an older build
#: is never compared against a newer candidate.
PROFILE_VERSION = 1

#: How many items one finding may list as evidence.
MAX_ITEMS = 40

#: How many findings one baseline rule may produce for one analysis.
MAX_FINDINGS = 40

#: How many frames one finding may cite.
MAX_PACKET_NUMBERS = 10

#: How many profiles and comparisons are kept in memory.
CACHE_LIMIT = 4

PROFILE_KINDS: tuple[str, ...] = (
    "hosts",
    "peers",
    "services",
    "dns_names",
    "http_hosts",
    "sni",
    "ja3",
)

#: How many novel DNS names are looked up per client when grouping that rule.
MAX_DNS_LOOKUPS = 200

DEFAULTS: dict[str, Any] = {
    "analysis_id": None,
    "enabled": False,
    "label": None,
    "created_at": None,
}

_PROFILE_CACHE: dict[str, dict[str, Any]] = {}
_COMPARE_CACHE: dict[str, dict[str, Any]] = {}


# --------------------------------------------------------------------------
# configuration
# --------------------------------------------------------------------------


def load_config() -> dict[str, Any]:
    """The stored baseline configuration, merged over the defaults."""
    config = dict(DEFAULTS)
    try:
        row = db.query_one("SELECT value FROM settings WHERE key = ?", (CONFIG_KEY,))
    except sqlite3.Error as exc:  # pragma: no cover - defensive
        log.warning("could not read %s: %s", CONFIG_KEY, exc)
        return config
    if row is None or not row["value"]:
        return config
    try:
        stored = json.loads(row["value"])
    except (TypeError, ValueError):
        log.warning("%s is not valid JSON; using the defaults", CONFIG_KEY)
        return config
    if not isinstance(stored, dict):
        return config

    analysis_id = stored.get("analysis_id")
    config["analysis_id"] = (
        str(analysis_id) if isinstance(analysis_id, str) and analysis_id else None
    )
    config["enabled"] = bool(stored.get("enabled", False)) and config["analysis_id"] is not None
    label = stored.get("label")
    config["label"] = str(label)[:120] if isinstance(label, str) and label.strip() else None
    created = stored.get("created_at")
    config["created_at"] = float(created) if isinstance(created, (int, float)) else None
    return config


def save_config(payload: dict[str, Any]) -> dict[str, Any]:
    """Write the baseline configuration.

    analysis_id is validated here rather than trusted: a baseline pointing at a capture
    that does not exist, or that has not finished analysing, would make every comparison
    silently empty - the one failure mode an analyst would never notice.
    """
    clean = dict(load_config())

    if "analysis_id" in payload:
        raw = payload["analysis_id"]
        if raw in (None, ""):
            clean["analysis_id"] = None
            clean["enabled"] = False
            clean["created_at"] = None
        else:
            analysis_id = str(raw).strip()
            row = db.query_one(
                "SELECT id, status, packet_count FROM analyses WHERE id = ?", (analysis_id,)
            )
            if row is None:
                raise bad_request("analysis_not_found", f"No analysis with id '{analysis_id}'.")
            if row["status"] != "completed":
                raise bad_request(
                    "analysis_not_ready",
                    "That capture is '" + str(row["status"]) + "'; a baseline must be a "
                    "completed analysis.",
                    {"analysis_id": analysis_id, "status": row["status"]},
                )
            if int(row["packet_count"] or 0) == 0:
                raise bad_request(
                    "analysis_empty",
                    "That capture indexed no packets, so it cannot describe a network.",
                    {"analysis_id": analysis_id},
                )
            clean["analysis_id"] = analysis_id
            clean["created_at"] = time.time()

    if "enabled" in payload:
        clean["enabled"] = bool(payload["enabled"]) and clean["analysis_id"] is not None
    if "label" in payload:
        label = payload["label"]
        clean["label"] = (str(label).strip()[:120] or None) if label is not None else None

    with db.get_conn() as conn:
        conn.execute(
            """
            INSERT INTO settings (key, value, updated_at) VALUES (?, ?, ?)
            ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at
            """,
            (CONFIG_KEY, json.dumps(clean, separators=(",", ":")), time.time()),
        )
    _PROFILE_CACHE.clear()
    _COMPARE_CACHE.clear()
    log.info("baseline set to %s (enabled=%s)", clean["analysis_id"], clean["enabled"])
    return load_config()


def clear_config() -> dict[str, Any]:
    """Remove the baseline entirely."""
    return save_config({"analysis_id": None})


def status() -> dict[str, Any]:
    """What the baseline is, whether the mode is on, and what it holds."""
    config = load_config()
    if config["analysis_id"] is None:
        return {
            "configured": False,
            "enabled": False,
            "active": False,
            "reason": "no baseline is configured",
            "baseline": None,
            "counts": None,
        }

    row = db.query_one(
        "SELECT id, original_filename, status, packet_count, created_at FROM analyses WHERE id = ?",
        (config["analysis_id"],),
    )
    if row is None:
        return {
            "configured": False,
            "enabled": False,
            "active": False,
            "reason": "the capture this baseline pointed at has been deleted",
            "baseline": None,
            "counts": None,
        }

    reason = None
    if row["status"] != "completed":
        reason = (
            "the baseline capture is '" + str(row["status"]) + "', so it cannot be compared against"
        )
    elif not config["enabled"]:
        reason = "baseline mode is off"

    counts = None
    if row["status"] == "completed":
        counts = profile(config["analysis_id"])["counts"]

    return {
        "configured": True,
        "enabled": bool(config["enabled"]),
        "active": bool(config["enabled"]) and row["status"] == "completed",
        "reason": reason,
        "label": config["label"],
        "created_at": config["created_at"],
        "baseline": {
            "analysis_id": row["id"],
            "original_filename": row["original_filename"],
            "status": row["status"],
            "packet_count": int(row["packet_count"] or 0),
            "created_at": float(row["created_at"]) if row["created_at"] else None,
        },
        "counts": counts,
    }


# --------------------------------------------------------------------------
# profile
# --------------------------------------------------------------------------


def _rows(sql: str, params: Sequence[Any] = ()) -> list[dict[str, Any]]:
    try:
        return [dict(row) for row in db.query_all(sql, params)]
    except sqlite3.Error as exc:  # missing table on an older database
        log.warning("baseline query failed: %s", exc)
        return []


def _build_profile(analysis_id: str) -> dict[str, Any]:
    """Read every profile kind out of one analysed capture."""
    sets: dict[str, set[str]] = {kind: set() for kind in PROFILE_KINDS}

    for row in _rows(
        """
        SELECT DISTINCT src_ip AS ip FROM packets
         WHERE analysis_id = ? AND src_ip IS NOT NULL AND src_ip <> ''
        UNION
        SELECT DISTINCT dst_ip AS ip FROM packets
         WHERE analysis_id = ? AND dst_ip IS NOT NULL AND dst_ip <> ''
        """,
        (analysis_id, analysis_id),
    ):
        sets["hosts"].add(str(row["ip"]).strip())

    for row in _rows(
        """
        SELECT DISTINCT src_ip, dst_ip FROM packets
         WHERE analysis_id = ? AND src_ip IS NOT NULL AND dst_ip IS NOT NULL
           AND src_ip <> '' AND dst_ip <> ''
        """,
        (analysis_id,),
    ):
        sets["peers"].add(str(row["src_ip"]).strip() + "|" + str(row["dst_ip"]).strip())

    for row in _rows(
        """
        SELECT DISTINCT dst_ip, dst_port, transport FROM packets
         WHERE analysis_id = ? AND dst_ip IS NOT NULL AND dst_ip <> ''
           AND dst_port IS NOT NULL AND dst_port < 49152
           AND (
             transport <> 'tcp'
             OR CAST(tcp_flags_raw AS INTEGER) = 2
           )
        """,
        (analysis_id,),
    ):
        transport = str(row["transport"] or "").strip().lower()
        sets["services"].add(
            str(row["dst_ip"]).strip() + "|" + str(int(row["dst_port"])) + "|" + transport
        )

    for kind, sql in (
        (
            "dns_names",
            "SELECT DISTINCT query_name AS value FROM dns_queries"
            " WHERE analysis_id = ? AND query_name IS NOT NULL AND query_name <> ''",
        ),
        (
            "http_hosts",
            "SELECT DISTINCT host AS value FROM http_transactions"
            " WHERE analysis_id = ? AND host IS NOT NULL AND host <> ''",
        ),
        (
            "sni",
            "SELECT DISTINCT sni AS value FROM tls_sessions"
            " WHERE analysis_id = ? AND sni IS NOT NULL AND sni <> ''",
        ),
        (
            "ja3",
            "SELECT DISTINCT ja3 AS value FROM tls_sessions"
            " WHERE analysis_id = ? AND ja3 IS NOT NULL AND ja3 <> ''",
        ),
    ):
        for row in _rows(sql, (analysis_id,)):
            sets[kind].add(str(row["value"]).strip().lower())

    analysis = db.query_one(
        "SELECT id, original_filename, packet_count, created_at FROM analyses WHERE id = ?",
        (analysis_id,),
    )
    return {
        "version": PROFILE_VERSION,
        "analysis_id": analysis_id,
        "filename": analysis["original_filename"] if analysis else None,
        "packets": int(analysis["packet_count"] or 0) if analysis else 0,
        "analysed_at": (
            float(analysis["created_at"]) if analysis and analysis["created_at"] else None
        ),
        "counts": {kind: len(values) for kind, values in sets.items()},
        "sets": sets,
    }


def profile(analysis_id: str) -> dict[str, Any]:
    """The profile of one capture, memoised.

    The cache is dropped whenever the baseline changes, so a comparison can never use a
    reference that is no longer configured. A completed analysis is immutable - only
    re-uploading the file changes its rows - so a memo is safe here in a way it would
    not be for stored findings.
    """
    cached = _PROFILE_CACHE.get(analysis_id)
    if cached is not None:
        return cached
    built = _build_profile(analysis_id)
    while len(_PROFILE_CACHE) >= CACHE_LIMIT:
        _PROFILE_CACHE.pop(next(iter(_PROFILE_CACHE)), None)
    _PROFILE_CACHE[analysis_id] = built
    return built


# --------------------------------------------------------------------------
# comparison
# --------------------------------------------------------------------------


def is_private(value: str) -> bool:
    """Whether an address belongs to the local side of a capture."""
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return False
    return address.is_private or address.is_loopback or address.is_link_local


def is_external(value: str) -> bool:
    """Whether an address is a global unicast destination worth reporting.

    Multicast, broadcast, reserved and unspecified addresses are excluded: a new
    SSDP group or a subnet broadcast is not a destination anyone chose to contact,
    and counting them would put noise in the one rule that reports reach.
    """
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return False
    if address.is_private or address.is_loopback or address.is_link_local:
        return False
    return not (
        address.is_multicast
        or address.is_reserved
        or address.is_unspecified
        or str(address) == "255.255.255.255"
    )


def _cap(values: Iterable[str], limit: int = MAX_ITEMS) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for value in values:
        if not value or value in seen:
            continue
        seen.add(value)
        out.append(value)
        if len(out) >= limit:
            break
    return out


def compare(analysis_id: str) -> dict[str, Any]:
    """Diff one capture against the configured baseline.

    Returns active=False with a reason whenever a comparison cannot be made - no
    baseline, baseline mode off, or the capture *is* the baseline - so callers never
    have to guess whether an empty novelty list means "nothing new" or "nothing
    compared".
    """
    cached = _COMPARE_CACHE.get(analysis_id)
    if cached is not None:
        return cached

    config = load_config()
    if config["analysis_id"] is None:
        return {"active": False, "reason": "no baseline is configured"}
    if not config["enabled"]:
        return {"active": False, "reason": "baseline mode is off"}
    if analysis_id == config["analysis_id"]:
        return {"active": False, "reason": "this capture is the baseline itself"}

    baseline = profile(config["analysis_id"])
    if baseline["counts"]["hosts"] == 0:
        return {
            "active": False,
            "reason": "the baseline capture indexed no addresses, so it describes no network",
        }

    candidate = profile(analysis_id)
    shared_hosts = candidate["sets"]["hosts"] & baseline["sets"]["hosts"]
    # Comparability is decided on the *local* addresses. Two captures that only share
    # a public resolver or a CDN edge are not the same network, and treating them as
    # one would report an entire foreign network as novel.
    shared_private = {ip for ip in shared_hosts if is_private(ip)}
    result: dict[str, Any] = {
        "active": True,
        "comparable": bool(shared_private),
        "baseline": {
            "analysis_id": baseline["analysis_id"],
            "filename": baseline["filename"],
            "label": config["label"],
            "packets": baseline["packets"],
            "counts": baseline["counts"],
            "created_at": config["created_at"],
        },
        "capture": {
            "analysis_id": candidate["analysis_id"],
            "filename": candidate["filename"],
            "packets": candidate["packets"],
            "counts": candidate["counts"],
        },
        "overlap": {
            "capture_hosts": len(candidate["sets"]["hosts"]),
            "baseline_hosts": len(baseline["sets"]["hosts"]),
            "shared_hosts": len(shared_hosts),
            "shared_private_hosts": len(shared_private),
            "shared_dns_names": len(
                candidate["sets"]["dns_names"] & baseline["sets"]["dns_names"]
            ),
            "shared_peers": len(candidate["sets"]["peers"] & baseline["sets"]["peers"]),
        },
        "novel": {},
        "novel_counts": {},
    }

    for kind in PROFILE_KINDS:
        novel = candidate["sets"][kind] - baseline["sets"][kind]
        result["novel"][kind] = novel
        result["novel_counts"][kind] = len(novel)

    while len(_COMPARE_CACHE) >= CACHE_LIMIT:
        _COMPARE_CACHE.pop(next(iter(_COMPARE_CACHE)), None)
    _COMPARE_CACHE[analysis_id] = result
    return result


def summary(analysis_id: str) -> dict[str, Any]:
    """The comparison as JSON: counts and samples, never the full sets."""
    result = compare(analysis_id)
    if not result["active"]:
        return {"active": False, "reason": result["reason"]}
    return {
        "active": True,
        "comparable": result["comparable"],
        "baseline": result["baseline"],
        "capture": result["capture"],
        "overlap": result["overlap"],
        "novel_counts": result["novel_counts"],
        "novel": {kind: _cap(sorted(values)) for kind, values in result["novel"].items()},
    }


# --------------------------------------------------------------------------
# the rules
#
# Every rule reports novelty - an entity the reference capture never contained. The
# reason string carries the baseline's identity and the overlap, so a finding can be
# read on its own months later, and the recommendation never turns novelty into a
# verdict.
# --------------------------------------------------------------------------


def _entities(
    *,
    ips: Sequence[Any] = (),
    hostnames: Sequence[Any] = (),
    ports: Sequence[Any] = (),
) -> dict[str, list[Any]]:
    clean_ports: list[int] = []
    for value in ports:
        try:
            port = int(value)
        except (TypeError, ValueError):
            continue
        if 0 <= port <= 65535:
            clean_ports.append(port)
    return {
        "ips": _cap([str(v) for v in ips]),
        "hostnames": _cap([str(v) for v in hostnames]),
        "ports": clean_ports[:MAX_ITEMS],
        "uris": [],
    }


def _first_packets(analysis_id: str, sql: str, params: Sequence[Any]) -> list[int]:
    """The first frames matching a lookup, in frame order, capped."""
    out: list[int] = []
    for row in _rows(sql, params):
        value = row.get("number")
        if value is None:
            continue
        try:
            out.append(int(value))
        except (TypeError, ValueError):
            continue
        if len(out) >= MAX_PACKET_NUMBERS:
            break
    return out


def _packets_for_host(analysis_id: str, ip: str) -> list[int]:
    return _first_packets(
        analysis_id,
        "SELECT number FROM packets WHERE analysis_id = ?"
        " AND (src_ip = ? OR dst_ip = ?) ORDER BY number LIMIT ?",
        (analysis_id, ip, ip, MAX_PACKET_NUMBERS),
    )


def _baseline_sentence(result: dict[str, Any]) -> str:
    """One sentence naming the reference, for every reason string."""
    baseline = result["baseline"]
    overlap = result["overlap"]
    label = baseline.get("label") or baseline.get("filename") or baseline["analysis_id"]
    return (
        "the baseline network '"
        + str(label)
        + "' ("
        + str(baseline["packets"])
        + " frames) recorded "
        + str(baseline["counts"]["hosts"])
        + " addresses, and this capture shares "
        + str(overlap["shared_hosts"])
        + " of its "
        + str(overlap["capture_hosts"])
        + " with it"
    )


def _evidence(
    result: dict[str, Any],
    kind: str,
    count: int,
    sample: Sequence[str],
    extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    evidence: dict[str, Any] = {
        "baseline": result["baseline"],
        "capture": result["capture"],
        "overlap": result["overlap"],
        "novel_kind": kind,
        "novel_count": count,
        "sample": list(sample)[:MAX_ITEMS],
    }
    if extra:
        evidence.update(extra)
    return evidence


def _item(
    *,
    title: str,
    key: Sequence[Any],
    reason: str,
    evidence: dict[str, Any],
    packet_numbers: Sequence[int],
    entities: dict[str, list[Any]],
    recommendation: str,
) -> dict[str, Any]:
    return {
        "title": title,
        "key": list(key),
        "reason": reason,
        "evidence": evidence,
        "packet_numbers": list(packet_numbers),
        "entities": entities,
        "recommendation": recommendation,
    }


_RECOMMENDATION = (
    "Confirm the entity with the owner of the network: a new address, service or name is "
    "normal after a change, a DHCP renewal or a new CDN edge, and is worth explaining "
    "before it is acted on. If the baseline capture no longer represents the network, "
    "choose a newer capture as the baseline and re-run the rules."
)


def rule_items(kind: str, analysis_id: str, params: dict[str, Any]) -> list[dict[str, Any]]:
    """The findings one baseline rule produces for one analysis.

    Called by the detection engine, so a baseline rule is an ordinary rule: it has a
    severity, a switch and a threshold sentence, and its findings are stored, listed and
    filtered like any other.
    """
    if not params.get("enabled", True):
        return []

    result = compare(analysis_id)
    if not result["active"]:
        return []

    if kind == "no_overlap":
        if result["comparable"]:
            return []
        overlap = result["overlap"]
        label = result["baseline"].get("label") or result["baseline"].get("filename")
        return [
            _item(
                title="This capture shares no local address with the baseline network",
                key=["no_overlap"],
                reason=(
                    "None of this capture's own addresses appear among the "
                    + str(overlap["baseline_hosts"])
                    + " the baseline network '"
                    + str(label)
                    + "' contains, so the novelty rules stay silent: comparing against a "
                    + "different network would report every entity as new and mean nothing. "
                    + "This capture has "
                    + str(overlap["capture_hosts"])
                    + " addresses and shares "
                    + str(overlap.get("shared_hosts", 0))
                    + " with the baseline, none of them local. That is a statement about these "
                    + "two captures, not about this traffic."
                ),
                evidence=_evidence(result, "no_overlap", 0, []),
                packet_numbers=[],
                entities=_entities(),
                recommendation=(
                    "If this capture is from the same network as the baseline, the baseline "
                    "capture does not cover it - pick one that does. If it is from a different "
                    "network, switch baseline mode off while you look at it."
                ),
            )
        ]

    if not result["comparable"]:
        return []

    # Novelty is only reported when the two captures demonstrably overlap.
    novel = result["novel"]
    baseline_sentence = _baseline_sentence(result)
    items: list[dict[str, Any]] = []

    if kind == "new_host":
        fresh = sorted(ip for ip in novel["hosts"] if is_private(ip))
        for ip in fresh[:MAX_FINDINGS]:
            items.append(
                _item(
                    title="New address " + ip + " is not in the baseline network",
                    key=["host", ip],
                    reason=(
                        ip
                        + " appears in this capture as a source or a destination but not in "
                        + baseline_sentence
                        + ". A private address the reference never held is a device or an "
                        "interface that was not on the network when the baseline was taken. "
                        "This is novelty, not intent."
                    ),
                    evidence=_evidence(result, kind, len(fresh), [ip]),
                    packet_numbers=_packets_for_host(analysis_id, ip),
                    entities=_entities(ips=[ip]),
                    recommendation=_RECOMMENDATION,
                )
            )

    elif kind == "new_destination":
        groups: dict[str, list[str]] = {}
        for pair in sorted(novel["peers"]):
            source, _, destination = pair.partition("|")
            if not source or not destination:
                continue
            if not is_external(destination):
                # A new local address is the new_host rule's business, and a multicast
                # or broadcast destination is not a choice anyone made.
                continue
            groups.setdefault(source, []).append(destination)
        for source in sorted(groups)[:MAX_FINDINGS]:
            destinations = _cap(groups[source])
            items.append(
                _item(
                    title=(
                        source
                        + " contacted "
                        + str(len(groups[source]))
                        + " destination(s) not in the baseline network"
                    ),
                    key=["destination", source],
                    reason=(
                        source
                        + " sent traffic to "
                        + str(len(groups[source]))
                        + " address(es) the reference never recorded - not for this host and "
                        "not for any other - against "
                        + baseline_sentence
                        + ". First seen here: "
                        + ", ".join(destinations[:5])
                        + "."
                    ),
                    evidence=_evidence(
                        result, kind, len(groups[source]), destinations, {"source_ip": source}
                    ),
                    packet_numbers=_first_packets(
                        analysis_id,
                        "SELECT number FROM packets WHERE analysis_id = ? AND src_ip = ?"
                        " AND dst_ip = ? ORDER BY number LIMIT ?",
                        (analysis_id, source, groups[source][0], MAX_PACKET_NUMBERS),
                    ),
                    entities=_entities(ips=[source, *destinations]),
                    recommendation=_RECOMMENDATION,
                )
            )

    elif kind == "new_service":
        groups_by_host: dict[str, list[str]] = {}
        ports_by_host: dict[str, list[int]] = {}
        for service in sorted(novel["services"]):
            parts = service.split("|")
            if len(parts) != 3:
                continue
            host, port, transport = parts
            if not is_private(host):
                continue
            groups_by_host.setdefault(host, []).append(port + "/" + (transport or "ip"))
            try:
                ports_by_host.setdefault(host, []).append(int(port))
            except ValueError:
                continue
        for host in sorted(groups_by_host)[:MAX_FINDINGS]:
            services = _cap(groups_by_host[host])
            items.append(
                _item(
                    title=(
                        host
                        + " offered "
                        + str(len(groups_by_host[host]))
                        + " service(s) not in the baseline network"
                    ),
                    key=["service", host],
                    reason=(
                        "Traffic to "
                        + host
                        + " on "
                        + str(len(groups_by_host[host]))
                        + " address/port pair(s) was not in the reference, against "
                        + baseline_sentence
                        + ". First seen here: "
                        + ", ".join(services[:6])
                        + ". A listener that was not there when the baseline was taken is "
                        + "either a new service or a host that moved."
                    ),
                    evidence=_evidence(
                        result, kind, len(groups_by_host[host]), services, {"host": host}
                    ),
                    packet_numbers=_first_packets(
                        analysis_id,
                        "SELECT number FROM packets WHERE analysis_id = ? AND dst_ip = ?"
                        " ORDER BY number LIMIT ?",
                        (analysis_id, host, MAX_PACKET_NUMBERS),
                    ),
                    entities=_entities(ips=[host], ports=ports_by_host.get(host, [])),
                    recommendation=_RECOMMENDATION,
                )
            )

    elif kind == "new_dns":
        by_client: dict[str, list[str]] = {}
        for name in sorted(novel["dns_names"])[:MAX_DNS_LOOKUPS]:
            for row in _rows(
                "SELECT DISTINCT client_ip FROM dns_queries"
                " WHERE analysis_id = ? AND query_name = ? AND client_ip IS NOT NULL",
                (analysis_id, name),
            ):
                client = str(row["client_ip"]).strip()
                if client:
                    by_client.setdefault(client, []).append(name)
        for client in sorted(by_client)[:MAX_FINDINGS]:
            names = _cap(by_client[client])
            items.append(
                _item(
                    title=(
                        client
                        + " resolved "
                        + str(len(by_client[client]))
                        + " name(s) the baseline network never queried"
                    ),
                    key=["dns", client],
                    reason=(
                        client
                        + " asked for "
                        + str(len(by_client[client]))
                        + " name(s) that do not occur in the reference, against "
                        + baseline_sentence
                        + ". First seen here: "
                        + ", ".join(names[:6])
                        + ". New names are routine - a new application, a renewed CDN "
                        + "endpoint, a software update - and are reported so the pattern is "
                        + "visible, not as a conclusion."
                    ),
                    evidence=_evidence(
                        result, kind, len(by_client[client]), names, {"client_ip": client}
                    ),
                    packet_numbers=_first_packets(
                        analysis_id,
                        "SELECT packet_number AS number FROM dns_queries"
                        " WHERE analysis_id = ? AND query_name = ? AND packet_number IS NOT NULL"
                        " ORDER BY packet_number LIMIT ?",
                        (analysis_id, by_client[client][0], MAX_PACKET_NUMBERS),
                    ),
                    entities=_entities(ips=[client], hostnames=names),
                    recommendation=_RECOMMENDATION,
                )
            )

    elif kind == "new_sni":
        for name in sorted(novel["sni"])[:MAX_FINDINGS]:
            items.append(
                _item(
                    title="TLS server name " + name + " is not in the baseline network",
                    key=["sni", name],
                    reason=(
                        "A TLS handshake in this capture named "
                        + name
                        + ", which never appears in "
                        + baseline_sentence
                        + ". The name is what the client asked for; whether the session was "
                        + "legitimate depends on the certificate and the context, which this "
                        + "rule does not judge."
                    ),
                    evidence=_evidence(result, kind, len(novel["sni"]), [name]),
                    packet_numbers=_first_packets(
                        analysis_id,
                        "SELECT client_packet AS number FROM tls_sessions"
                        " WHERE analysis_id = ? AND sni = ? AND client_packet IS NOT NULL"
                        " ORDER BY client_packet LIMIT ?",
                        (analysis_id, name, MAX_PACKET_NUMBERS),
                    ),
                    entities=_entities(hostnames=[name]),
                    recommendation=_RECOMMENDATION,
                )
            )

    elif kind == "new_ja3":
        for fingerprint in sorted(novel["ja3"])[:MAX_FINDINGS]:
            items.append(
                _item(
                    title="New TLS client fingerprint " + fingerprint[:24],
                    key=["ja3", fingerprint],
                    reason=(
                        "The JA3 fingerprint "
                        + fingerprint
                        + " did not occur in the reference, against "
                        + baseline_sentence
                        + ". A fingerprint identifies the client software's TLS settings: a "
                        + "new one means a program that was not talking when the baseline was "
                        + "taken, which is as often a new browser build as it is anything else."
                    ),
                    evidence=_evidence(result, kind, len(novel["ja3"]), [fingerprint]),
                    packet_numbers=_first_packets(
                        analysis_id,
                        "SELECT client_packet AS number FROM tls_sessions"
                        " WHERE analysis_id = ? AND ja3 = ? AND client_packet IS NOT NULL"
                        " ORDER BY client_packet LIMIT ?",
                        (analysis_id, fingerprint, MAX_PACKET_NUMBERS),
                    ),
                    entities=_entities(),
                    recommendation=_RECOMMENDATION,
                )
            )

    return items


__all__ = [
    "CONFIG_KEY",
    "DEFAULTS",
    "MAX_FINDINGS",
    "PROFILE_KINDS",
    "clear_config",
    "compare",
    "is_external",
    "is_private",
    "load_config",
    "profile",
    "rule_items",
    "save_config",
    "status",
    "summary",
]
