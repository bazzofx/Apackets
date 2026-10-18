"""Geography endpoints: the country view of a capture (docs/GEOGRAPHY.md §5).

Four routes, one reading surface - SQL over the ``hosts`` rows an analysis already
holds, plus a country lookup that needs no capture data at all:

* ``GET  /api/geoip/status``                     - §5.1, is the dataset installed
* ``POST /api/geoip/refresh``                    - §5.2, download it (202 + job)
* ``GET  /api/analyses/{id}/geography``          - §5.3, the map's data
* ``GET  /api/analyses/{id}/geography/{code}``   - §5.4, one destination panel

The geography endpoint **aggregates over ``hosts``**: that table is already one row per
observed address with its packet and byte totals, so the answer is a read of one table
per address, never a re-scan of ``packets``. Every address is classified from the
address itself first (§3): ``local`` addresses are the origin hub, ``reserved`` ones are
neither drawn nor geolocated, and only ``public`` ones are offered to the dataset - a
private address is never looked up.

The destination panel (§5.4) is the same reading surface opened one level further: the
same bucket of ``hosts`` rows, plus the ``conversations`` rows that touch those
addresses, grouped here rather than in SQL so that one country costs two queries instead
of one query per address. ``ZZ`` is a bucket like any other - the addresses the dataset
could not place have ports and conversations too.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from typing import Any

from fastapi import APIRouter

from app.api.deps import get_ready_analysis
from app.core.errors import conflict, not_found
from app.core.logging import get_logger
from app.db import database as db
from app.services import geoip

log = get_logger("apackets.api.geo")

router = APIRouter(tags=["geoip"])

# §8's caps, read from the service so one number lives in one place.
COUNTRY_CAP = geoip.COUNTRY_CAP
GEO_IP_CAP = geoip.GEO_IP_CAP
PORT_CAP = geoip.PORT_CAP
GEO_TARGET_DETAIL_CAP = geoip.GEO_TARGET_DETAIL_CAP

#: §5.3's links: how many country pairs one response may carry. A capture that proves
#: more than this many is typical of a span port or a proxy chain, and the busiest pairs
#: are the ones worth drawing.
LINK_CAP = 24

#: §3: the origin is the capture's own network, drawn as one labelled hub, never a
#: point on the map - a private address carries no country and none is invented.
ORIGIN_LABEL = "This capture's own addresses"

# §7's limits, stated on the page in one sentence, always.
GEO_NOTE = (
    "A country here is where the address block is registered rather than where the host "
    "is \u2014 cloud, CDN, VPN and satellite space routinely disagree \u2014 so a block "
    "allocated in one country can be served from another; the origin hub is this "
    "capture's own addresses, which carry no location and are therefore never placed on "
    "the map; an address the dataset answers 'ZZ' for, and every native IPv6 address "
    "\u2014 this build indexes the dataset's IPv4 rows only, although the file itself "
    "carries both families \u2014 is counted as unknown and drawn nowhere rather than "
    "moved into a neighbouring country; no city, coordinate, ASN, organisation or "
    "confidence is claimed; one address in a country means one address in a country; and "
    "the dataset's month and download time say how old the answer is."
)


@dataclass
class _Bucket:
    """One row of the answer: an address count, its volume, and the addresses themselves.

    The addresses are kept so that a country can list which of them it is; they are cut
    to :data:`GEO_IP_CAP` when the row is built, by volume, so the list a reader sees is
    the significant part of the country rather than an arbitrary prefix of it.
    """

    addresses: int = 0
    packets: int = 0
    bytes: int = 0
    entries: list[tuple[int, str]] = field(default_factory=list)

    def add(self, ip: str, packets: int, size: int) -> None:
        self.addresses += 1
        self.packets += packets
        self.bytes += size
        self.entries.append((size, ip))

    def top_ips(self, cap: int) -> tuple[list[str], bool]:
        ordered = sorted(self.entries, key=lambda entry: (-entry[0], entry[1]))
        return [ip for _, ip in ordered[:cap]], len(ordered) > cap

    def listing(self, cap: int = GEO_IP_CAP) -> dict[str, Any]:
        ips, truncated = self.top_ips(cap)
        return {
            "addresses": self.addresses,
            "packets": self.packets,
            "bytes": self.bytes,
            "ips": ips,
            "ips_truncated": truncated,
        }


@dataclass
class _Link:
    """One country pair, summed over the conversations that prove it.

    §5.3's ``links`` are a *relation the capture itself proves*: a ``conversations`` row
    whose two endpoints are both located, in two different countries. The origin side is
    deliberately not a country - a private address carries none (§3) - so an ordinary
    capture of one network talking outward proves no pair at all and reports an empty
    list. Nothing here is inferred from co-occurrence: two countries are linked only when
    a single conversation has an endpoint in each.
    """

    packets: int = 0
    bytes: int = 0
    conversations: int = 0


def _country_links(analysis_id: str, codes: dict[str, str]) -> list[dict[str, Any]]:
    """§5.3's ``links``: country pairs proven by this capture's conversations.

    ``codes`` is the address -> country map the aggregation already built, so a pair
    costs two dictionary lookups per conversation and the dataset is never asked twice.
    Only conversations with *both* endpoints located can link anything; a conversation
    with the capture's own side at one end has no second country to point at.
    """
    pairs: dict[tuple[str, str], _Link] = {}
    rows = db.query_all(
        """
        SELECT ip_a, ip_b,
               COALESCE(packets_total, 0) AS packets,
               COALESCE(bytes_total, 0)   AS bytes
          FROM conversations
         WHERE analysis_id = ?
        """,
        (analysis_id,),
    )
    for row in rows:
        left = codes.get(row["ip_a"]) if row["ip_a"] else None
        right = codes.get(row["ip_b"]) if row["ip_b"] else None
        if left is None or right is None or left == right:
            continue
        key = (left, right) if left < right else (right, left)
        link = pairs.setdefault(key, _Link())
        link.packets += int(row["packets"] or 0)
        link.bytes += int(row["bytes"] or 0)
        link.conversations += 1

    # Busiest first, then by code, so one capture always answers the same.
    ordered = sorted(pairs.items(), key=lambda item: (-item[1].bytes, item[0]))
    return [
        {
            "source": source,
            "target": target,
            "packets": link.packets,
            "bytes": link.bytes,
            "conversations": link.conversations,
        }
        for (source, target), link in ordered[:LINK_CAP]
    ]


def _note(countries: int, truncated: bool) -> str:
    """§7's limits, plus the cap when it bit (§5.3)."""
    if not truncated:
        return GEO_NOTE
    return (
        f"{GEO_NOTE} Only the {COUNTRY_CAP} countries carrying the most bytes are listed; "
        f"{countries - COUNTRY_CAP} further countries are withheld by this response's cap."
    )


#: §5.4's own note: §7's limits, plus which conversation the panel's link opens. A
#: reader who clicks "follow conversation" is owed the reason it is *that* conversation.
PANEL_NOTE = (
    GEO_NOTE + " The conversation each address links to is the earliest one recorded with "
    "it rather than the busiest, so following it opens the first exchange with that "
    "address and not the largest."
)

#: The codes a destination panel can be asked for: every ISO 3166-1 alpha-2 code, §2's
#: one named exception, and ``ZZ`` - the *not placed* bucket, which is a bucket like any
#: other rather than an error.
PANEL_CODES = frozenset(geoip.ISO_CODES | geoip.USER_ASSIGNED_CODES | {geoip.UNKNOWN_CODE})

#: Addresses per ``IN (...)`` clause when the bucket's conversations are read. A country
#: with a few thousand addresses therefore costs a handful of queries, never one per
#: address, and two placeholders per address stay far inside SQLite's parameter ceiling.
_ADDRESS_CHUNK = 400

#: The bucket's own rows: one per address, with the two directions the panel needs *and*
#: the protocol map it lists. ``ports`` is deliberately not read here - §5.4 takes ports
#: from ``conversations``, not from per-packet dissection.
_BUCKET_HOSTS_SQL = """
SELECT ip,
       COALESCE(packets_sent, 0)     AS packets_sent,
       COALESCE(packets_received, 0) AS packets_received,
       COALESCE(bytes_sent, 0)       AS bytes_sent,
       COALESCE(bytes_received, 0)   AS bytes_received,
       protocols
  FROM hosts
 WHERE analysis_id = ?
"""


def _installed_dataset(state: dict[str, Any], analysis_id: str):
    """The dataset this analysis can be read against, or ``None`` when there is none.

    §3: with no dataset installed - or one that cannot be parsed - every public address
    is honestly unknown rather than guessed, which is one and the same answer for §5.3's
    ``unknown`` bucket and for §5.4's ``ZZ`` panel. ``state`` is :func:`geoip.status` as
    the caller already has it: finding ``source.json`` and stat-ing the file per address
    costs more than the search does, so it is resolved once per request.
    """
    if not state["available"]:
        return None
    try:
        return geoip.current_dataset()
    except geoip.DatasetError as exc:  # pragma: no cover - status() just said it parses
        log.warning("analysis %s: dataset unusable, nothing located: %s", analysis_id, exc)
        return None


def _aggregate(analysis_id: str) -> dict[str, Any]:
    """§5.3's envelope: one pass over the analysis's ``hosts`` rows."""
    state = geoip.status()
    dataset = _installed_dataset(state, analysis_id)

    rows = db.query_all(
        """
        SELECT ip,
               COALESCE(packets_sent, 0) + COALESCE(packets_received, 0) AS packets,
               COALESCE(bytes_sent, 0)   + COALESCE(bytes_received, 0)   AS bytes
          FROM hosts
         WHERE analysis_id = ?
        """,
        (analysis_id,),
    )

    local = _Bucket()
    reserved = _Bucket()
    unknown = _Bucket()
    countries: dict[str, _Bucket] = {}
    #: address -> country, so §5.3's links never ask the dataset a second time.
    codes: dict[str, str] = {}
    unparsable = 0

    for row in rows:
        ip = row["ip"]
        # A missing or NULL total is zero here; the row still counts as an address.
        packets = int(row["packets"] or 0)
        size = int(row["bytes"] or 0)

        scope = geoip.classify(ip)
        if scope == geoip.SCOPE_LOCAL:
            local.add(ip, packets, size)
        elif scope == geoip.SCOPE_RESERVED:
            reserved.add(ip, packets, size)
        elif scope is None:
            # Not an address at all: never the capture's own side, never a destination.
            reserved.add(ip, packets, size)
            unparsable += 1
        else:
            # §3: only a public address is offered to the dataset, and with no dataset
            # installed every public address is honestly unknown rather than guessed.
            code = dataset.country_for(ip) if dataset is not None else None
            if code:
                codes[ip] = code
                countries.setdefault(code, _Bucket()).add(ip, packets, size)
            else:
                unknown.add(ip, packets, size)

    if unparsable:
        log.warning(
            "analysis %s: %d host rows are not addresses; counted as reserved",
            analysis_id,
            unparsable,
        )

    # §5.3: by bytes descending, then by code, and capped.
    ordered = sorted(countries.items(), key=lambda item: (-item[1].bytes, item[0]))
    truncated = len(ordered) > COUNTRY_CAP

    payload: list[dict[str, Any]] = []
    for code, bucket in ordered[:COUNTRY_CAP]:
        payload.append(
            {
                "code": code,
                # The API may send null and does: names are the frontend's map asset (§6).
                "name": geoip.country_name(code),
                **bucket.listing(),
            }
        )

    counts: dict[str, Any] = {
        "addresses": len(rows),
        "located": sum(bucket.addresses for _, bucket in ordered),
        "countries": len(ordered),
    }
    if truncated:
        counts["countries_truncated"] = True
    counts["unknown"] = unknown.addresses
    counts["local"] = local.addresses
    if reserved.addresses:
        # §3 has a fourth class and §5.3's counts have no home for it; it is reported
        # only when it is not empty, so an ordinary capture keeps §5.3's exact shape.
        counts["reserved"] = reserved.addresses

    return {
        "analysis_id": analysis_id,
        "generated_at": time.time(),
        "dataset": {
            "available": state["available"],
            "source": state["source"],
            "reason": state["reason"],
        },
        "origin": {
            "label": ORIGIN_LABEL,
            "addresses": local.addresses,
            "packets": local.packets,
            "bytes": local.bytes,
        },
        "countries": payload,
        "links": _country_links(analysis_id, codes),
        "unknown": unknown.listing(),
        "counts": counts,
        "note": _note(len(ordered), truncated),
    }


# --------------------------------------------------------------------------
# one destination panel (§5.4): a bucket of addresses, opened
# --------------------------------------------------------------------------

@dataclass
class _Destination:
    """One address of a bucket, with §5.4's direction already resolved.

    The mapping is read off its source of truth rather than restated: ``hosts`` rows are
    written by ``host_analyzer._HOST_SQL``, which builds them **from the address's own
    perspective** - ``sent`` / ``bytes_sent`` count the frames where that address is the
    ``src_ip``, ``received`` / ``bytes_received`` the frames where it is the ``dst_ip``.
    For a *destination row* that makes the two columns the opposite of this panel's:

    | panel field | ``hosts`` column | meaning |
    |---|---|---|
    | ``sent`` | ``packets_received``, ``bytes_received`` | what this capture's side sent, i.e. what the destination received |
    | ``received`` | ``packets_sent``, ``bytes_sent`` | what this capture's side received, i.e. what the destination sent |

    §5.4 spells the mapping out because the two readings are opposite and nothing in the
    shape of the data distinguishes them - so the fields below are named for the panel's
    directions and assigned from the *reverse* columns, and the tests assert it on rows
    whose two directions differ by an order of magnitude. Measured on the installed
    capture, from the ``packets`` table rather than from either analyzer: its ZA bucket
    reads 210,273,133 bytes received against 873,224 sent (the download), while its S3
    upload keeps the US bucket at 8,856,981 sent against 807,084 received, which is the
    same asymmetry read the other way round.
    """

    ip: str
    sent_packets: int = 0        # hosts.packets_received: what this capture sent
    sent_bytes: int = 0          # hosts.bytes_received
    received_packets: int = 0    # hosts.packets_sent: what this capture received
    received_bytes: int = 0      # hosts.bytes_sent
    protocols: list[str] = field(default_factory=list)

    @property
    def packets(self) -> int:
        return self.sent_packets + self.received_packets

    @property
    def bytes(self) -> int:
        return self.sent_bytes + self.received_bytes


@dataclass
class _Ports:
    """One ``(port, side)`` of the panel and the addresses that used it.

    The packets and bytes are what the **conversation** moved: a port carries an
    exchange, not one half of it, and the direction split is already given by
    ``counts.sent``/``counts.received`` and by each target's own pair. ``addresses``
    counts distinct addresses of the bucket that used the port on that side, not
    conversations (§5.4's ``addresses`` field).
    """

    port: int
    side: str
    packets: int = 0
    bytes: int = 0
    addresses: set[str] = field(default_factory=set)

    def entry(self) -> dict[str, Any]:
        return {
            "port": self.port,
            "side": self.side,
            "packets": self.packets,
            "bytes": self.bytes,
            "addresses": len(self.addresses),
        }


def _protocol_names(raw: object) -> list[str]:
    """``hosts.protocols`` as the list of names §5.4's targets carry.

    The column is ``{name: count}`` JSON in the analyzer's own volume order (most used
    first, then by name) and §5.4 lists the names - ``["tcp", "tls"]`` - so the order is
    kept and the counts dropped: that order is the only volume information the panel
    shows. A row that is not JSON, or not a mapping or list of names, is answered as no
    protocols rather than failing the panel.
    """
    if not raw:
        return []
    try:
        parsed = json.loads(raw)
    except (TypeError, ValueError):
        return []
    if isinstance(parsed, dict):
        return [str(name) for name in parsed]
    if isinstance(parsed, list):
        return [str(name) for name in parsed]
    return []


def _conversation_order(row) -> tuple:
    """§5.4's ordering of conversations: earliest to start, then lowest stream id.

    Never by volume - the panel's link is *follow conversation with this address*, so it
    opens the first exchange and not the biggest one. A missing ``start_time`` (or stream
    id) is unknown rather than earliest and sorts after every known value, and the
    conversation id settles anything still tied, so one capture always answers the same.
    """
    start = row["start_time"]
    stream = row["stream_id"]
    return (
        start is None,
        float(start) if start is not None else 0.0,
        stream is None,
        int(stream) if stream is not None else 0,
        str(row["conv_id"]),
    )


def _conversation_link(row) -> dict[str, Any] | None:
    """§5.4's ``first_conversation``, in exactly the fields the panel links with.

    ``transport`` and ``stream_id`` are the two values the application's conversation
    deep link takes (``/conversations?stream=<transport>:<stream_id>&tab=timeline``);
    ``packets``/``bytes`` are the conversation's totals, and ``start_time`` is the value
    it was chosen by. ``None`` means the address has no conversation at all.
    """
    if row is None:
        return None
    return {
        "conv_id": row["conv_id"],
        "transport": row["transport"],
        "stream_id": row["stream_id"],
        "packets": int(row["packets"] or 0),
        "bytes": int(row["bytes"] or 0),
        "start_time": row["start_time"],
    }


def _bucket_conversations(analysis_id: str, addresses: list[str]) -> list[Any]:
    """Every ``conversations`` row with an endpoint among *addresses*.

    Read in chunks of :data:`_ADDRESS_CHUNK` addresses, so a country holding thousands of
    them costs a handful of queries rather than one query per address. The rows are
    grouped by address in Python (:func:`_panel`), which is also where the two sides of
    each conversation are named.
    """
    rows: list[Any] = []
    for start in range(0, len(addresses), _ADDRESS_CHUNK):
        chunk = addresses[start : start + _ADDRESS_CHUNK]
        marks = ", ".join("?" for _ in chunk)
        rows.extend(
            db.query_all(
                f"""
                SELECT conv_id, transport, stream_id, ip_a, port_a, ip_b, port_b,
                       COALESCE(packets_total, 0) AS packets,
                       COALESCE(bytes_total, 0)   AS bytes,
                       start_time
                  FROM conversations
                 WHERE analysis_id = ?
                   AND (ip_a IN ({marks}) OR ip_b IN ({marks}))
                """,
                (analysis_id, *chunk, *chunk),
            )
        )
    return rows


def _country_not_found(code: str) -> Exception:
    """§5.4's 404: a code this capture sent nothing to."""
    if code == geoip.UNKNOWN_CODE:
        message = (
            "This capture has no address the dataset could not place, so its "
            "'not placed' bucket is empty."
        )
    else:
        message = f"This capture sent nothing to {code}."
    return not_found("country_not_found", message, {"code": code})


def _panel_note(ports_truncated: bool, targets_truncated: bool) -> str:
    """§5.4's note: §7's limits, which conversation is linked, and any cap that bit."""
    note = PANEL_NOTE
    if ports_truncated:
        note += (
            f" Only the {PORT_CAP} ports carrying the most bytes are listed; "
            "ports_truncated marks the cut."
        )
    if targets_truncated:
        note += (
            f" Only the {GEO_TARGET_DETAIL_CAP} addresses carrying the most bytes are "
            "listed; the counts above include every address in this bucket."
        )
    return note


def _panel(analysis_id: str, code: str) -> dict[str, Any]:
    """§5.4's destination panel: one bucket of addresses, its ports and its targets.

    Two reads and then Python: the analysis's ``hosts`` rows (one per address, the same
    table §5.3 aggregates) and the ``conversations`` rows that touch the bucket's
    addresses - never a query per address, and never a re-scan of ``packets``.
    """
    if code not in PANEL_CODES:
        # §2's vocabulary: a code the dataset cannot answer with is one this capture
        # cannot have sent to either, so there is no bucket to report.
        raise _country_not_found(code)

    rows = db.query_all(_BUCKET_HOSTS_SQL, (analysis_id,))

    dataset = _installed_dataset(geoip.status(), analysis_id)
    destinations: dict[str, _Destination] = {}
    for row in rows:
        ip = row["ip"]
        # §3 once more: only a public address is a destination, and it is offered to the
        # dataset only then - a private address is never looked up.
        if geoip.classify(ip) != geoip.SCOPE_PUBLIC:
            continue
        # The addresses the dataset cannot answer for are the *not placed* bucket, the
        # same set §5.3 reports as unknown - including every public address when no
        # dataset is installed, which is honest rather than guessed.
        located = dataset.country_for(ip) if dataset is not None else None
        if (located or geoip.UNKNOWN_CODE) != code:
            continue
        destinations[ip] = _Destination(
            ip=ip,
            # §5.4's mapping, applied exactly as the table in ``_Destination`` states it:
            # the row is the *address's* own perspective (host_analyzer._HOST_SQL), so its
            # sent columns are what this capture received and its received columns are what
            # this capture sent. Assigning these the other way round inverts every panel.
            sent_packets=int(row["packets_received"] or 0),
            sent_bytes=int(row["bytes_received"] or 0),
            received_packets=int(row["packets_sent"] or 0),
            received_bytes=int(row["bytes_sent"] or 0),
            protocols=_protocol_names(row["protocols"]),
        )

    if destinations:
        conversation_rows = _bucket_conversations(analysis_id, list(destinations))
    elif rows:
        raise _country_not_found(code)
    else:
        # §5.4: an analysis that has never been extracted is still a 200 - the buckets
        # are empty, not missing. An empty *bucket* of an extracted capture is the 404
        # above, which is a different statement: this capture sent that country nothing.
        log.debug("analysis %s: no hosts rows, answering an empty %s panel", analysis_id, code)
        conversation_rows = []

    ports: dict[tuple[int, str], _Ports] = {}
    target_ports: dict[str, dict[tuple[int, str], list[int]]] = {}
    first: dict[str, Any] = {}

    for row in conversation_rows:
        packets = int(row["packets"] or 0)
        bytes_moved = int(row["bytes"] or 0)
        ip_a, ip_b = row["ip_a"], row["ip_b"]

        # §5.4: which side a port is on is decided by *which endpoint owns it*, never by
        # which of the two started the conversation: the port on the destination's own
        # address is ``remote`` (the service port a reader is looking for) and the port
        # on the capture's own side is ``local`` (usually the ephemeral one).
        pairs: list[tuple[str, Any, Any]] = []
        if ip_a in destinations:
            pairs.append((ip_a, row["port_a"], row["port_b"]))
        if ip_b in destinations and ip_b != ip_a:
            pairs.append((ip_b, row["port_b"], row["port_a"]))

        for address, own_port, other_port in pairs:
            for port, side in ((own_port, "remote"), (other_port, "local")):
                if port is None:
                    continue
                usage = ports.setdefault((int(port), side), _Ports(int(port), side))
                usage.packets += packets
                usage.bytes += bytes_moved
                usage.addresses.add(address)
                seen = target_ports.setdefault(address, {}).setdefault((int(port), side), [0, 0])
                seen[0] += packets
                seen[1] += bytes_moved

            earliest = first.get(address)
            if earliest is None or _conversation_order(row) < _conversation_order(earliest):
                first[address] = row

    # §5.4: largest first, then by port and side so the order is stable between reads.
    ordered_ports = sorted(
        ports.values(),
        key=lambda usage: (-usage.bytes, -usage.packets, usage.port, usage.side),
    )
    ports_truncated = len(ordered_ports) > PORT_CAP

    ordered_targets = sorted(destinations.values(), key=lambda entry: (-entry.bytes, entry.ip))
    targets_truncated = len(ordered_targets) > GEO_TARGET_DETAIL_CAP

    targets: list[dict[str, Any]] = []
    for destination in ordered_targets[:GEO_TARGET_DETAIL_CAP]:
        entries = sorted(
            target_ports.get(destination.ip, {}).items(),
            key=lambda item: (-item[1][1], -item[1][0], item[0][0], item[0][1]),
        )
        # One address can legitimately have hundreds of ports - a scan has nothing else - so
        # the per-target list is bounded by the same cap, and says when it bit rather than
        # printing a wall of chips or dropping them silently.
        entries_truncated = len(entries) > PORT_CAP
        targets.append(
            {
                "ip": destination.ip,
                "packets": destination.packets,
                "bytes": destination.bytes,
                "sent": {
                    "packets": destination.sent_packets,
                    "bytes": destination.sent_bytes,
                },
                "received": {
                    "packets": destination.received_packets,
                    "bytes": destination.received_bytes,
                },
                # Sorted by the panel's rule and cut by the panel's cap, with its own flag.
                "ports": [
                    {
                        "port": port,
                        "side": side,
                        "packets": moved[0],
                        "bytes": moved[1],
                        # A port on one target belongs to that one address, which is what
                        # the bucket-level entry means by its own `addresses` count.
                        "addresses": 1,
                    }
                    for (port, side), moved in entries[:PORT_CAP]
                ],
                "ports_truncated": entries_truncated,
                "protocols": destination.protocols,
                "first_conversation": _conversation_link(first.get(destination.ip)),
            }
        )

    counts: dict[str, Any] = {
        "addresses": len(destinations),
        # Every address of the bucket is counted here, listed or not (§5.4).
        "packets": sum(destination.packets for destination in destinations.values()),
        "bytes": sum(destination.bytes for destination in destinations.values()),
        "sent": {
            "packets": sum(destination.sent_packets for destination in destinations.values()),
            "bytes": sum(destination.sent_bytes for destination in destinations.values()),
        },
        "received": {
            "packets": sum(
                destination.received_packets for destination in destinations.values()
            ),
            "bytes": sum(destination.received_bytes for destination in destinations.values()),
        },
    }

    return {
        "analysis_id": analysis_id,
        "code": code,
        "generated_at": time.time(),
        "counts": counts,
        "ports": [usage.entry() for usage in ordered_ports[:PORT_CAP]],
        "ports_truncated": ports_truncated,
        "targets": targets,
        "targets_truncated": targets_truncated,
        "note": _panel_note(ports_truncated, targets_truncated),
    }


# --------------------------------------------------------------------------
# dataset status (§5.1)
# --------------------------------------------------------------------------

@router.get("/api/geoip/status")
def geoip_status() -> dict:
    """Whether the country dataset is installed, and why not when it is not."""
    return geoip.status()


# --------------------------------------------------------------------------
# dataset refresh (§5.2)
# --------------------------------------------------------------------------

@router.post("/api/geoip/refresh", status_code=202)
def geoip_refresh() -> dict:
    """Download the newest published monthly file as a background job.

    202 with a job id, like every other long-running action here. The refresh runs in
    this process rather than through ``services.jobs`` because a job row belongs to an
    analysis and this download belongs to the installation: its result is ``source.json``
    (§4.1), and ``GET /api/geoip/status`` reports what happened. A failure installs
    nothing and leaves any previous dataset in force.
    """
    try:
        job = geoip.start_refresh()
    except geoip.RefreshBusy as exc:
        raise conflict(
            "refresh_in_progress",
            str(exc),
            {"job": geoip.refresh_in_progress()},
        ) from exc
    log.info("queued geoip refresh %s", job["job_id"])
    return job


# --------------------------------------------------------------------------
# geography of one analysis (§5.3)
# --------------------------------------------------------------------------

@router.get("/api/analyses/{analysis_id}/geography")
def analysis_geography(analysis_id: str) -> dict:
    """Where this capture's public addresses are, as countries - and where they are not.

    Gated like every other analysis read: a malformed id is a 400 before any work, an
    unknown one a 404, an unfinished one a 409, all from ``get_ready_analysis``.
    """
    get_ready_analysis(analysis_id)
    return _aggregate(analysis_id)


# --------------------------------------------------------------------------
# one destination panel (§5.4)
# --------------------------------------------------------------------------

@router.get("/api/analyses/{analysis_id}/geography/{code}")
def analysis_geography_country(analysis_id: str, code: str) -> dict:
    """Everything one dot on the map opens, in one request: one country, or ``ZZ``.

    The country list of §5.3 stays light because the map draws every country at once and
    almost none of them are opened; this is fetched only when a dot is clicked. The code
    is case-insensitive, and ``ZZ`` is the *not placed* bucket - those addresses have
    ports and conversations like any others, so the panel is the same shape.

    Gated exactly like the rest of the router: a malformed id is a 400, an unknown one a
    404 and an unfinished one a 409, all from ``get_ready_analysis`` and all before the
    country is looked at. A code this capture sent nothing to is a 404
    ``country_not_found``; an analysis that has never been extracted is an empty 200.
    """
    get_ready_analysis(analysis_id)
    return _panel(analysis_id, (code or "").strip().upper())


__all__ = [
    "COUNTRY_CAP",
    "GEO_IP_CAP",
    "GEO_NOTE",
    "GEO_TARGET_DETAIL_CAP",
    "ORIGIN_LABEL",
    "PANEL_CODES",
    "PANEL_NOTE",
    "PORT_CAP",
    "router",
]
