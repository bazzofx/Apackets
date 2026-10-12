"""Geography endpoints: the country view of a capture (docs/GEOGRAPHY.md §5).

Three routes, one reading surface - SQL over the ``hosts`` rows an analysis already
holds, plus a country lookup that needs no capture data at all:

* ``GET  /api/geoip/status``                     - §5.1, is the dataset installed
* ``POST /api/geoip/refresh``                    - §5.2, download it (202 + job)
* ``GET  /api/analyses/{id}/geography``          - §5.3, the map's data

The geography endpoint **aggregates over ``hosts``**: that table is already one row per
observed address with its packet and byte totals, so the answer is a read of one table
per address, never a re-scan of ``packets``. Every address is classified from the
address itself first (§3): ``local`` addresses are the origin hub, ``reserved`` ones are
neither drawn nor geolocated, and only ``public`` ones are offered to the dataset - a
private address is never looked up.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any

from fastapi import APIRouter

from app.api.deps import get_ready_analysis
from app.core.errors import conflict
from app.core.logging import get_logger
from app.db import database as db
from app.services import geoip

log = get_logger("apackets.api.geo")

router = APIRouter(tags=["geoip"])

# §8's caps, read from the service so one number lives in one place.
COUNTRY_CAP = geoip.COUNTRY_CAP
GEO_IP_CAP = geoip.GEO_IP_CAP

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


def _note(countries: int, truncated: bool) -> str:
    """§7's limits, plus the cap when it bit (§5.3)."""
    if not truncated:
        return GEO_NOTE
    return (
        f"{GEO_NOTE} Only the {COUNTRY_CAP} countries carrying the most bytes are listed; "
        f"{countries - COUNTRY_CAP} further countries are withheld by this response's cap."
    )


def _aggregate(analysis_id: str) -> dict[str, Any]:
    """§5.3's envelope: one pass over the analysis's ``hosts`` rows."""
    # The dataset block is also the answer to "should anything be located at all", so
    # the table is resolved once here rather than re-resolved for every address: finding
    # ``source.json`` and stat-ing the file per address costs more than the search does.
    state = geoip.status()
    try:
        dataset = geoip.current_dataset() if state["available"] else None
    except geoip.DatasetError as exc:  # pragma: no cover - status() just said it parses
        log.warning("analysis %s: dataset unusable, nothing located: %s", analysis_id, exc)
        dataset = None

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
        "unknown": unknown.listing(),
        "counts": counts,
        "note": _note(len(ordered), truncated),
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


__all__ = [
    "COUNTRY_CAP",
    "GEO_IP_CAP",
    "GEO_NOTE",
    "ORIGIN_LABEL",
    "router",
]
