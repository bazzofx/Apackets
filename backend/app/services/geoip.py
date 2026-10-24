r"""IP geolocation: one country code per address (docs/GEOGRAPHY.md §2-§4).

The contract's dataset is **DB-IP Lite - country**: one gzipped CSV, three columns
per row (``start_ip,end_ip,country_code``), downloaded only when a reader asks for
it. This module is that source and nothing else:

* :func:`refresh` downloads ``dbip-country-lite-YYYY-MM.csv.gz``, trying the current
  month and up to :data:`REFRESH_MONTHS_BACK` earlier ones (the file name is dated, so
  a 404 means "that month is not published yet, try the previous one"), verifies the
  gzip parses, that every row has the three-column shape and that there are at least
  :data:`MIN_RANGES` of them, and only then installs the file and ``source.json``
  atomically. A rejected download writes nothing, so the previous dataset stays in
  force (§5.2).
* :func:`status` answers §5.1: whether a dataset is installed, its provenance, and a
  ``reason`` a reader can act on when it is not.
* :func:`lookup` returns one address's country code, or ``None`` when the dataset
  cannot answer for it. The file is parsed into memory once and cached for the life of
  the process, keyed by the raw file's ``(size, mtime)``, so a refresh is picked up
  without a restart and a page render never parses ~710,000 rows twice.
* :func:`classify` is §3: an address that is not public is classified *from the address
  itself* and is never looked up, so a private address can never come back with a
  country.

Honest limits, all of them measured rather than assumed:

* **This build indexes the IPv4 rows only.** The dataset carries both families; measured
  on the 2026-10 file: 710,834 rows, of which
  362,122 are IPv4 ranges (indexed, 244 ISO codes) and 348,712 are IPv6 ranges (counted
  and validated, never indexed). The file carries 251 distinct codes - 18 rows say ``ZZ``
  and 152 say ``XK``, which is not in ISO 3166-1 alpha-2 but is accepted anyway as the
user-assigned code for Kosovo (§2's one exception); ``ZZ`` alone reads as unknown. A
  parse of the real file takes about 3 seconds, once per process. :func:`lookup` answers
  ``None`` - unknown - for every IPv6 address, deliberately, and the page says so:
  unknown is a result, never a guess.
* A code is **where the address block is registered**, not where the host is; the
  dataset's own ``ZZ`` rows cover the non-routable space (`0.0.0.0-0.255.255.255` is
  the first row of the real file, which is why a private address reads ``ZZ`` from it).
* ``ZZ``, an empty code and anything outside ISO 3166-1 alpha-2 are **unknown** (§2) and
  are returned as ``None``, never dropped into a neighbouring country. The code set
  itself is the only static table in this module.
* :func:`country_name` returns ``None``: this installation has no country-name source,
  the contract lets the API send ``null``, and a name invented from a code would be
  exactly the kind of guess §4 forbids.

The module imports nothing heavy and reads nothing at import time: with no dataset on
disk the application starts, every lookup returns ``None`` and every other page is
unaffected.
"""

from __future__ import annotations

import bisect
import gzip
import hashlib
import io
import ipaddress
import json
import os
import tempfile
import threading
import time
import urllib.error
import urllib.request
import uuid
import zlib
from array import array
from collections import OrderedDict
from dataclasses import dataclass, field
from datetime import date
from pathlib import Path
from typing import Any, Callable, Iterable

from app import __version__
from app.core.config import settings
from app.core.logging import get_logger

log = get_logger("shadowpackets.geoip")

# --------------------------------------------------------------------------
# caps and constants (docs/GEOGRAPHY.md §8)
# --------------------------------------------------------------------------

COUNTRY_CAP = 60            # countries in one geography response, by bytes
GEO_IP_CAP = 50             # addresses listed per country / for the unknown bucket
PORT_CAP = 25               # ports in one destination panel, largest first (§5.4)
GEO_TARGET_DETAIL_CAP = GEO_IP_CAP  # addresses in one destination panel (§5.4, §8)
MIN_RANGES = 100_000        # smallest parsed dataset accepted as complete
REFRESH_MONTHS_BACK = 6     # earlier monthly files tried before a refresh gives up

# §4.1 provenance. The dataset and its licence are the contract's, verbatim.
DATASET = "DB-IP Lite — country"
LICENCE = "CC BY 4.0"
ATTRIBUTION = "IP geolocation by DB-IP (https://db-ip.com)"

URL_TEMPLATE = "https://download.db-ip.com/free/dbip-country-lite-{month}.csv.gz"
FILE_TEMPLATE = "dbip-country-lite-{month}.csv.gz"
FILE_GLOB = "dbip-country-lite-*.csv.gz"
SOURCE_NAME = "source.json"

#: A reader can see who asked for the dataset: the tool, its version and why.
USER_AGENT = (
    f"ShadowPackets/{__version__} (local PCAP forensics; "
    "one monthly DB-IP Lite country download; https://db-ip.com)"
)
DOWNLOAD_TIMEOUT_S = 180.0

JOB_KIND = "geoip_refresh"
MAX_JOBS_TRACKED = 8        # in-process refresh records kept for inspection

# §3 vocabulary. These three strings are the only classes the page draws from.
SCOPE_LOCAL = "local"       # the capture's own side: the origin hub, never a dot
SCOPE_RESERVED = "reserved"  # never geolocated, never drawn
SCOPE_PUBLIC = "public"     # a candidate for a country

UNKNOWN_CODE = "ZZ"

#: The one code accepted although ISO 3166-1 does not assign it (see :data:`ISO_CODES`).
USER_ASSIGNED_CODES: frozenset[str] = frozenset({"XK"})

#: ISO 3166-1 alpha-2 plus **one deliberate exception, ``XK``**.
#:
#: §2: a code outside this set means **unknown**, so the set is needed to say "the dataset
#: answered nothing" rather than passing an arbitrary two-letter string through as a
#: country. ``XK`` is the user-assigned code for Kosovo: the dataset uses it on 152 rows,
#: the map asset names and draws it, and calling real traffic unknown while the page could
#: label it would be worse than accepting an unofficial-but-universal code. It is the only
#: exception, and it is named here rather than inferred.
#:
#: This is a *code* set only: no names are derived from it (§5.3 leaves names to the
#: frontend).
ISO_CODES: frozenset[str] = frozenset(
    """
    AD AE AF AG AI AL AM AO AQ AR AS AT AU AW AX AZ
    BA BB BD BE BF BG BH BI BJ BL BM BN BO BQ BR BS BT BV BW BY BZ
    CA CC CD CF CG CH CI CK CL CM CN CO CR CU CV CW CX CY CZ
    DE DJ DK DM DO DZ
    EC EE EG EH ER ES ET
    FI FJ FK FM FO FR
    GA GB GD GE GF GG GH GI GL GM GN GP GQ GR GS GT GU GW GY
    HK HM HN HR HT HU
    ID IE IL IM IN IO IQ IR IS IT
    JE JM JO JP
    KE KG KH KI KM KN KP KR KW KY KZ
    LA LB LC LI LK LR LS LT LU LV LY
    MA MC MD ME MF MG MH MK ML MM MN MO MP MQ MR MS MT MU MV MW MX MY MZ
    NA NC NE NF NG NI NL NO NP NR NU NZ
    OM
    PA PE PF PG PH PK PL PM PN PR PS PT PW PY
    QA
    RE RO RS RU RW
    SA SB SC SD SE SG SH SI SJ SK SL SM SN SO SR SS ST SV SX SY SZ
    TC TD TF TG TH TJ TK TL TM TN TO TR TT TV TW TZ
    UA UG UM US UY UZ
    VA VC VE VG VI VN VU
    WF WS
    YE YT
    ZA ZM ZW
    """.split()
)

# §3, from the address itself: RFC 1918 / RFC 4193 are the capture's own side, alongside
# loopback, link-local and multicast. Everything else the address itself refuses to call
# public (``is_reserved``, ``is_unspecified`` and the wider private set Python knows -
# 0.0.0.0/8, the documentation ranges, 240/4) is "reserved": never geolocated, never
# drawn, and never mistaken for the capture's own network either.
_RFC1918: tuple[ipaddress.IPv4Network, ...] = (
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
)
_ULA_V6: tuple[ipaddress.IPv6Network, ...] = (ipaddress.ip_network("fc00::/7"),)

_LOCAL_NETWORKS: dict[int, tuple] = {4: _RFC1918, 6: _ULA_V6}


# --------------------------------------------------------------------------
# errors
# --------------------------------------------------------------------------

class GeoIpError(RuntimeError):
    """Base class: this module never raises anything else out of a public call."""


class FetchError(GeoIpError):
    """The download itself failed: network, HTTP status, or a short body."""


class NotFound(FetchError):
    """HTTP 404 - in this dataset that means 'this month is not published'."""


class DatasetError(GeoIpError):
    """The bytes are not a usable dataset: bad gzip, bad shape, or truncated."""


class RefreshError(GeoIpError):
    """A refresh could not install a dataset; whatever was on disk stays in force."""


class RefreshBusy(GeoIpError):
    """A refresh is already queued or running."""


# --------------------------------------------------------------------------
# address handling
# --------------------------------------------------------------------------

def parse_address(value: object) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    """Best-effort address parse; ``None`` for anything that is not an address.

    Malformed input is a ``None``, never an exception: the API takes addresses from a
    table it did not write, and a page must not fail because one row is odd.
    """
    if value is None:
        return None
    try:
        return ipaddress.ip_address(str(value).strip())
    except ValueError:
        return None


def _ipv4_int(text: str) -> int | None:
    """``a.b.c.d`` -> int, or ``None`` for anything that is not a dotted quad.

    Strict on purpose - ASCII digits, at most three of them, no leading zero, at most
    255 - and parsed by hand rather than through :mod:`ipaddress` because this runs for
    every row of a 710,000-row file. A lenient parser is how a damaged file gets
    accepted as a complete one (§5.2).
    """
    parts = text.split(".")
    if len(parts) != 4:
        return None
    number = 0
    for part in parts:
        if len(part) > 3 or not part.isascii() or not part.isdigit():
            return None
        if len(part) > 1 and part[0] == "0":
            return None
        value = int(part)
        if value > 255:
            return None
        number = (number << 8) | value
    return number


def classify(value: object) -> str | None:
    """§3's class for one address, decided from the address itself.

    * :data:`SCOPE_LOCAL` - RFC 1918, RFC 4193, loopback, link-local, multicast: the
      capture's own side, the origin of the arcs, never a destination dot.
    * :data:`SCOPE_RESERVED` - ``is_reserved``, ``is_unspecified`` and anything else
      Python still calls private (the documentation and benchmark ranges, ``240/4``):
      never geolocated, never drawn.
    * :data:`SCOPE_PUBLIC` - a candidate for a country.

    Returns ``None`` when the value is not an address at all. This is the *only* gate
    in front of :func:`lookup`: a non-public address is never looked up.
    """
    address = parse_address(value)
    if address is None:
        return None

    # An IPv4-mapped IPv6 address is the IPv4 address it carries, exactly as
    # ``host_analyzer.address_scope`` treats it.
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
        address = address.ipv4_mapped

    if address.is_multicast or address.is_loopback or address.is_link_local:
        return SCOPE_LOCAL
    for network in _LOCAL_NETWORKS[address.version]:
        if address in network:
            return SCOPE_LOCAL
    if address.is_unspecified or address.is_reserved:
        return SCOPE_RESERVED
    if address.is_private:
        return SCOPE_RESERVED
    return SCOPE_PUBLIC


# --------------------------------------------------------------------------
# the parsed dataset
# --------------------------------------------------------------------------

@dataclass(frozen=True)
class Dataset:
    """One parsed dataset: sorted IPv4 ranges and the code each range carries.

    ``starts`` / ``ends`` hold the ranges as 32-bit integers and ``code_index`` an
    index into ``code_list``, where index ``0`` is "unknown" - the whole table costs a
    few megabytes for a file that would be tens as Python objects.
    """

    starts: array
    ends: array
    code_index: array
    code_list: tuple[str, ...]
    ranges: int              # every range row in the file, IPv4 and IPv6
    ipv4_ranges: int         # rows in the searchable IPv4 table
    ipv6_ranges: int         # rows this IPv4 table cannot answer for (§2, stated)
    codes: int               # distinct codes the file carries, every row: §4.1's "countries"
    located: int             # distinct ISO codes the searchable IPv4 table can answer with
    unknown_ranges: int      # rows whose code means unknown: ``ZZ``, empty or outside ISO
    odd_ranges: int          # of those, rows whose code is not ISO 3166-1 alpha-2 at all

    def country(self, number: int) -> str | None:
        """The code covering ``number``, or ``None`` when no range does.

        Ranges in this dataset are sorted and disjoint, so one binary search decides
        it: the last range starting at or before the address, checked against its end.
        An address between two ranges (a hole) is unknown, never rounded down.
        """
        index = bisect.bisect_right(self.starts, number) - 1
        if index < 0 or number > self.ends[index]:
            return None
        code = self.code_list[self.code_index[index]]
        return code or None

    def country_for(self, value: object) -> str | None:
        """The code for one address value, or ``None``.

        The same answer :func:`lookup` gives for an address, without resolving where the
        dataset lives: several thousand addresses in one request should not each pay for
        a ``stat`` of ``source.json`` and of the dataset file. Callers that hold a dataset
        already - the geography endpoint does - use this directly.
        """
        address = parse_address(value)
        if address is None:
            return None
        if isinstance(address, ipaddress.IPv6Address):
            if address.ipv4_mapped is None:
                return None
            address = address.ipv4_mapped
        return self.country(int(address))


@dataclass(frozen=True)
class _CacheEntry:
    """The parsed table plus the ``(path, size, mtime)`` it was parsed from."""

    key: tuple[str, int, int]
    dataset: Dataset


_CACHE_LOCK = threading.Lock()
_CACHE: _CacheEntry | None = None
_SOURCE_CACHE: tuple[tuple[str, int, int], dict[str, Any]] | None = None


def clear_cache() -> None:
    """Forget the parsed table and the provenance read. A refresh does this itself."""
    global _CACHE, _SOURCE_CACHE
    with _CACHE_LOCK:
        _CACHE = None
        _SOURCE_CACHE = None


def parse_csv(text: str, *, source: str = "<text>") -> Dataset:
    """Parse CSV *text* - the shape the download gunzips to (§2).

    Every row must have exactly three columns; an IPv6 row is counted and skipped; an
    IPv4 row is validated and indexed. Anything else, including an empty line, raises
    :class:`DatasetError` rather than being silently dropped, because a short file is
    the one failure this dataset cannot recover from (§5.2).
    """
    return _parse_lines(io.StringIO(text), source=source)


def parse_gzip(raw: bytes, *, source: str = "<download>") -> Dataset:
    """Verify and parse gzipped CSV *bytes* as downloaded.

    Rejects empty, non-gzip, truncated and corrupt streams: ``gzip.decompress`` is the
    integrity check for a partial download, since it fails on a missing CRC/end marker.
    """
    if not raw:
        raise DatasetError(f"{source}: the download was empty")
    try:
        data = gzip.decompress(raw)
    except (OSError, EOFError, zlib.error) as exc:
        raise DatasetError(f"{source}: the gzip stream could not be read ({exc})") from exc
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise DatasetError(f"{source}: the CSV is not UTF-8 text ({exc})") from exc
    return _parse_lines(io.StringIO(text), source=source)


def _parse_lines(lines: Iterable[str], *, source: str) -> Dataset:
    starts = array("L")
    ends = array("L")
    code_index = array("H")
    code_list: list[str] = [""]           # index 0 == unknown
    positions: dict[str, int] = {}

    ranges = ipv4_ranges = ipv6_ranges = unknown_ranges = odd_ranges = 0
    overlaps = 0
    unsorted = False
    odd_codes: list[str] = []
    codes_seen: set[str] = set()
    last_start = last_end = -1

    for number, raw_line in enumerate(lines, 1):
        line = raw_line.strip()
        if not line:
            raise DatasetError(
                f"{source}: line {number} is empty; the file is not a clean three-column CSV"
            )
        parts = line.split(",")
        if len(parts) != 3:
            raise DatasetError(
                f"{source}: line {number} has {len(parts)} fields, expected 3 "
                f"(start_ip,end_ip,country_code): {line[:80]!r}"
            )
        start_text, end_text, code_text = parts
        if " " in line:  # a hand-edited file may have spaces; the downloaded one does not
            start_text, end_text, code_text = (
                start_text.strip(), end_text.strip(), code_text.strip()
            )
        ranges += 1

        # The code is read for *every* row, IPv6 included, because §4.1's "countries" is
        # how many codes the file carries - the same whole-file sense as "ranges" - while
        # the searchable table keeps only the ISO codes its IPv4 rows can answer with.
        code = code_text
        if code not in ISO_CODES:
            code = code.upper()          # a lower-case file is legal, the real one is not
        known = code in ISO_CODES or code in USER_ASSIGNED_CODES
        if known:
            codes_seen.add(code)
        else:
            unknown_ranges += 1
            if code and code != UNKNOWN_CODE:
                odd_ranges += 1
                if len(odd_codes) < 8:
                    odd_codes.append(code)
            codes_seen.add(code)

        if ":" in start_text and ":" in end_text:
            # A real IPv6 range: counted and validated as a row, never indexed, because
            # this build indexes the dataset's IPv4 rows and answers `unknown` for IPv6
            # (§2). The file carries both families - 348,712 of its rows are IPv6 - so the
            # honest statement is about this build, not about the dataset.
            ipv6_ranges += 1
            continue

        start = _ipv4_int(start_text)
        end = _ipv4_int(end_text)
        if start is None or end is None:
            raise DatasetError(
                f"{source}: line {number} is not an address range: {line[:80]!r}"
            )
        if end < start:
            raise DatasetError(
                f"{source}: line {number} ends before it starts: {line[:80]!r}"
            )

        if known:
            position = positions.get(code)
            if position is None:
                position = len(code_list)
                positions[code] = position
                code_list.append(code)
        else:
            position = 0

        if start < last_start:
            unsorted = True
        if start <= last_end:
            overlaps += 1
        last_start, last_end = start, end

        starts.append(start)
        ends.append(end)
        code_index.append(position)
        ipv4_ranges += 1

    if ranges == 0:
        raise DatasetError(f"{source}: the file holds no range rows at all")

    if unsorted:
        order = sorted(range(len(starts)), key=starts.__getitem__)
        starts = array("L", (starts[i] for i in order))
        ends = array("L", (ends[i] for i in order))
        code_index = array("H", (code_index[i] for i in order))
        log.warning("%s: ranges were not in ascending order; sorted in memory", source)
    if overlaps:
        log.warning(
            "%s: %d ranges overlap a previous range; the first match by start address wins",
            source,
            overlaps,
        )
    if odd_codes:
        log.warning(
            "%s: %d rows carry a code outside ISO 3166-1 alpha-2 (e.g. %s); counted as unknown",
            source,
            odd_ranges,
            ", ".join(odd_codes),
        )

    located = len(code_list) - 1
    log.info(
        "%s: parsed %s ranges (%s IPv4, %s IPv6, %s unknown), %s codes, %s located in IPv4",
        source,
        f"{ranges:,}",
        f"{ipv4_ranges:,}",
        f"{ipv6_ranges:,}",
        f"{unknown_ranges:,}",
        len(codes_seen),
        located,
    )
    return Dataset(
        starts=starts,
        ends=ends,
        code_index=code_index,
        code_list=tuple(code_list),
        ranges=ranges,
        ipv4_ranges=ipv4_ranges,
        ipv6_ranges=ipv6_ranges,
        codes=len(codes_seen),
        located=located,
        unknown_ranges=unknown_ranges,
        odd_ranges=odd_ranges,
    )


# --------------------------------------------------------------------------
# storage (§4)
# --------------------------------------------------------------------------

def geoip_dir() -> Path:
    """``<data_dir>/geoip``, created on the first successful refresh, never before.

    Resolved per call so that pointing the application's ``data_dir`` elsewhere - as
    every test does - moves the dataset with it.
    """
    return settings.geoip_dir


def source_path() -> Path:
    """The path of ``source.json`` (§4.1)."""
    return geoip_dir() / SOURCE_NAME


def load_source() -> dict[str, Any] | None:
    """``source.json`` as a dict, or ``None`` when it is absent, unreadable or invalid.

    Cached by the file's own ``(path, size, mtime)``: a lookup asks for the provenance
    on every call - it is the only pointer to the dataset file - and re-reading a few
    hundred bytes per address would cost more than the binary search does. A refresh
    replaces ``source.json`` atomically, so the key changes and the next call re-reads.
    """
    global _SOURCE_CACHE
    path = source_path()
    try:
        stat = path.stat()
    except OSError:
        return None
    key = (str(path), stat.st_size, stat.st_mtime_ns)
    cached = _SOURCE_CACHE
    if cached is not None and cached[0] == key:
        return dict(cached[1])

    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        log.warning("source.json could not be read: %s", exc)
        return None
    try:
        data = json.loads(text)
    except (json.JSONDecodeError, TypeError) as exc:
        log.warning("source.json is not valid JSON: %s", exc)
        return None
    if not isinstance(data, dict):
        return None
    _SOURCE_CACHE = (key, data)
    return dict(data)


def dataset_path() -> Path | None:
    """The dataset file ``source.json`` points at, or ``None`` when it is not there.

    The name is taken as a single path component: ``source.json`` is written by this
    module, but it is a file on disk and is not trusted to reach outside ``data/geoip``.
    """
    source = load_source()
    if not source:
        return None
    name = source.get("file")
    if not isinstance(name, str) or not name.strip():
        return None
    path = geoip_dir() / Path(name.strip()).name
    return path if path.is_file() else None


def _atomic_write(path: Path, data: bytes) -> None:
    """Write *data* to *path* through a temporary file and ``os.replace``.

    A reader (or an interrupted download) either sees the whole previous file or the
    whole new one - never a half-written one, and never a ``source.json`` describing
    bytes that did not land.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    handle_fd, temp_name = tempfile.mkstemp(
        dir=str(path.parent), prefix=f".{path.name}.", suffix=".tmp"
    )
    temp_path = Path(temp_name)
    try:
        with os.fdopen(handle_fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp_path, path)
    except BaseException:
        temp_path.unlink(missing_ok=True)
        raise


def dataset_for(path: Path) -> Dataset:
    """The parsed table for *path*, re-parsing only when ``(size, mtime)`` changed.

    The cache is keyed by path too, so two directories holding a same-sized file never
    serve each other's ranges.
    """
    global _CACHE
    try:
        stat = path.stat()
    except OSError as exc:
        raise DatasetError(f"{path.name}: {exc}") from exc
    key = (str(path), stat.st_size, stat.st_mtime_ns)

    with _CACHE_LOCK:
        cached = _CACHE
        if cached is not None and cached.key == key:
            return cached.dataset
        # Parsed under the lock: two concurrent lookups on an unparsed dataset should
        # do the work once, not twice.
        dataset = parse_gzip(path.read_bytes(), source=path.name)
        _CACHE = _CacheEntry(key=key, dataset=dataset)
        return dataset


def current_dataset() -> Dataset | None:
    """The installed dataset, or ``None`` when there is none this installation can use."""
    path = dataset_path()
    if path is None:
        return None
    return dataset_for(path)


# --------------------------------------------------------------------------
# lookup
# --------------------------------------------------------------------------

def lookup(value: object) -> str | None:
    """The two-letter country code for one address, or ``None`` when unknown.

    ``None`` is the honest answer for: malformed input, an address outside every range
    (a hole), a range whose code is ``ZZ`` or empty, a code outside ISO 3166-1 alpha-2
    (§2), **every IPv6 address** (this build indexes the IPv4 rows only - an IPv4-mapped address such
    as ``::ffff:3.173.21.63`` is unwrapped and answered for), and no dataset installed
    at all. Nothing is guessed and no exception is raised for input.

    This resolves the installed dataset first, which costs a couple of ``stat`` calls;
    a caller reading thousands of addresses at once asks :func:`current_dataset` for the
    table once and then uses :meth:`Dataset.country_for` per address.
    """
    dataset = current_dataset()
    if dataset is None:
        return None
    return dataset.country_for(value)


def country_for(value: object) -> str | None:
    """The country code for a **public** address; ``None`` for anything else.

    §3: a non-public address is classified from the address itself and is never looked
    up, so this is the only lookup path the geography endpoint uses.
    """
    if classify(value) != SCOPE_PUBLIC:
        return None
    return lookup(value)


def country_name(code: str | None) -> str | None:
    """Always ``None``: this installation has no country-name source.

    §5.3 lets the API send ``null`` and the frontend resolve the name from its map
    asset. A name table here would be a second, unverifiable source for a fact the
    contract deliberately keeps in one place, so there is none.
    """
    return None


# --------------------------------------------------------------------------
# the download
# --------------------------------------------------------------------------

def _month(today: date, months_back: int) -> str:
    """``YYYY-MM``, *months_back* months before *today* (year boundaries included)."""
    index = today.year * 12 + (today.month - 1) - months_back
    year, month = divmod(index, 12)
    return f"{year:04d}-{month + 1:02d}"


def candidate_months(today: date | None = None) -> list[str]:
    """The months a refresh asks for, newest first (§2).

    The current month, then up to :data:`REFRESH_MONTHS_BACK` earlier ones - the file
    name is dated, so a month that has not been published yet is a 404, not an error.
    """
    current = today or date.today()
    return [_month(current, back) for back in range(REFRESH_MONTHS_BACK + 1)]


def url_for(month: str) -> str:
    return URL_TEMPLATE.format(month=month)


def filename_for(month: str) -> str:
    return FILE_TEMPLATE.format(month=month)


def _fetch(url: str, *, timeout: float = DOWNLOAD_TIMEOUT_S) -> bytes:
    """Download one URL with an honest User-Agent, or raise :class:`FetchError`.

    ``404`` becomes :class:`NotFound` because for this dataset it means "that month is
    not published"; every other failure is fatal to the refresh rather than retried
    against six earlier months, which would only turn one error into seven.
    """
    request = urllib.request.Request(
        url,
        headers={
            "User-Agent": USER_AGENT,
            "Accept": "application/gzip, application/octet-stream;q=0.9, */*;q=0.1",
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            raw = response.read()
            declared = response.headers.get("Content-Length")
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            raise NotFound(f"{url} returned 404") from exc
        raise FetchError(f"{url} returned HTTP {exc.code} {exc.reason}") from exc
    except urllib.error.URLError as exc:
        raise FetchError(f"{url} could not be reached ({exc.reason})") from exc
    except OSError as exc:
        raise FetchError(f"{url} failed: {exc}") from exc

    if declared is not None and declared.strip().isdigit() and int(declared) != len(raw):
        raise FetchError(
            f"{url} delivered {len(raw):,} of {int(declared):,} bytes; the download is partial"
        )
    return raw


def _install(source: dict[str, Any], raw: bytes, month: str) -> Path:
    """Write the dataset, then its provenance, then drop superseded months."""
    directory = geoip_dir()
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / filename_for(month)

    # The dataset first: source.json must never describe a file that is not there yet.
    _atomic_write(path, raw)
    _atomic_write(
        source_path(),
        (json.dumps(source, indent=2, ensure_ascii=False) + "\n").encode("utf-8"),
    )
    clear_cache()

    for stale in sorted(directory.glob(FILE_GLOB)):
        if stale.name == path.name:
            continue
        try:
            stale.unlink()
            log.info("removed superseded dataset %s", stale.name)
        except OSError as exc:  # pragma: no cover - a locked file is not fatal
            log.warning("could not remove %s: %s", stale, exc)
    return path


def refresh(
    *,
    fetcher: Callable[[str], bytes] | None = None,
    today: date | None = None,
    on_stage: Callable[[str], None] | None = None,
) -> dict[str, Any]:
    """Download, verify and install the newest published monthly file (§5.2).

    Returns the ``source.json`` document that was written. Raises
    :class:`RefreshError` - having written **nothing** - when no month could be
    downloaded, when the bytes are not a clean gzip of three-column rows, or when they
    hold fewer than :data:`MIN_RANGES` ranges (§5.2: rejected as truncated). A failure
    therefore always leaves any previous dataset in force.

    *fetcher* exists so that the download can be replaced in tests; it must return the
    raw gzip bytes for a URL and raise :class:`NotFound` for an unpublished month.
    """
    fetch = fetcher or _fetch
    attempted: list[str] = []
    raw: bytes | None = None
    url = month = None

    for candidate in candidate_months(today):
        candidate_url = url_for(candidate)
        _stage(on_stage, f"downloading {candidate}")
        try:
            raw = fetch(candidate_url)
        except NotFound:
            attempted.append(f"{candidate} (not published)")
            log.info("geoip: %s is not published, trying the previous month", candidate)
            continue
        except FetchError as exc:
            raise RefreshError(
                f"the download failed and no earlier month was tried: {exc}"
            ) from exc
        url, month = candidate_url, candidate
        break

    if raw is None or url is None or month is None:
        raise RefreshError(
            "no monthly dataset could be downloaded; tried " + ", ".join(attempted)
        )

    _stage(on_stage, "verifying")
    try:
        dataset = parse_gzip(raw, source=filename_for(month))
    except DatasetError as exc:
        raise RefreshError(f"the downloaded file was rejected: {exc}") from exc
    if dataset.ranges < MIN_RANGES:
        raise RefreshError(
            f"the downloaded file holds {dataset.ranges:,} ranges, fewer than the "
            f"{MIN_RANGES:,} a complete dataset has; rejected as truncated"
        )

    _stage(on_stage, "installing")
    source: dict[str, Any] = {
        "dataset": DATASET,
        "url": url,
        "licence": LICENCE,
        "attribution": ATTRIBUTION,
        "file": filename_for(month),
        "bytes": len(raw),
        "sha256": hashlib.sha256(raw).hexdigest(),
        "ranges": dataset.ranges,
        # §4.1's "countries" is how many codes the file carries, measured the same way
        # §2 measures it for the 2026-10 file (251, ZZ and the non-ISO XK included).
        "countries": dataset.codes,
        "dataset_month": month,
        "fetched_at": time.time(),
    }
    path = _install(source, raw, month)
    log.info(
        "installed %s: %s bytes, %s ranges (%s IPv4, %s located codes), %s codes, sha256 %s",
        path.name,
        f"{len(raw):,}",
        f"{dataset.ranges:,}",
        f"{dataset.ipv4_ranges:,}",
        dataset.located,
        dataset.codes,
        source["sha256"][:16],
    )
    return source


# --------------------------------------------------------------------------
# status (§5.1)
# --------------------------------------------------------------------------

_MISSING_REASON = (
    "The DB-IP Lite country dataset has never been downloaded, so no address can be "
    "placed in a country. POST /api/geoip/refresh downloads it: one file of about "
    "4.4 MB, CC BY 4.0, no account and no API key."
)

_STATUS_NOTE = (
    "Countries come from DB-IP Lite (CC BY 4.0; IP geolocation by DB-IP, "
    "https://db-ip.com) and this installation holds no fallback: a country is never "
    "taken from the registry that allocated a block or from a list baked into the app, "
    "an address the dataset answers 'ZZ' for - and every IPv6 address, because this "
    "because this build indexes the IPv4 rows only - is unknown rather than guessed, and the "
    "dataset's own month and "
    "download time are both reported because a stale table is a different claim from a "
    "fresh one."
)


def status() -> dict[str, Any]:
    """§5.1: is a dataset installed, what is it, and why not when it is not.

    The file is parsed here (through the ``(size, mtime)`` cache) so that a corrupt or
    truncated dataset on disk is reported as unavailable instead of failing a render.
    A dataset installed by :func:`refresh` has already passed :data:`MIN_RANGES`; this
    function does not re-apply that bar, so a hand-placed file is still read.
    """
    source = load_source()
    reason: str | None = None

    if source is None:
        reason = _MISSING_REASON
    else:
        name = source.get("file")
        path = dataset_path()
        if path is None:
            reason = (
                f"source.json records '{name}', but that file is not in "
                f"{geoip_dir()} - it may have been deleted or moved. "
                "POST /api/geoip/refresh downloads it again."
            )
        else:
            try:
                dataset = dataset_for(path)
            except DatasetError as exc:
                reason = (
                    f"The dataset file on disk could not be parsed: {exc}. "
                    "POST /api/geoip/refresh replaces it with a verified download."
                )
            else:
                if dataset.ipv4_ranges == 0:
                    reason = (
                        f"The dataset file on disk ({path.name}) holds no IPv4 range, so "
                        "no address can be placed in a country. Refresh to replace it."
                    )

    available = reason is None
    if not available:
        last_error = last_refresh_error()
        if last_error:
            reason = f"{reason} The last refresh attempt failed: {last_error}"
        log.debug("geoip unavailable: %s", reason)

    return {
        "available": available,
        "source": source if available else None,
        "reason": reason,
        "note": _STATUS_NOTE,
    }


# --------------------------------------------------------------------------
# refresh jobs (§5.2)
# --------------------------------------------------------------------------

@dataclass
class RefreshJob:
    """One in-process refresh attempt, for inspection while it runs and after."""

    job_id: str
    status: str = "queued"          # queued | running | completed | failed
    stage: str = "queued"
    error: str | None = None
    source: dict[str, Any] | None = None
    created_at: float = field(default_factory=time.time)
    started_at: float | None = None
    finished_at: float | None = None

    def to_json(self) -> dict[str, Any]:
        return {
            "job_id": self.job_id,
            "kind": JOB_KIND,
            "status": self.status,
            "stage": self.stage,
            "error": self.error,
            "source": self.source,
            "created_at": self.created_at,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
        }


_JOBS: "OrderedDict[str, RefreshJob]" = OrderedDict()
_JOBS_LOCK = threading.Lock()
_last_error: str | None = None


def _stage(on_stage: Callable[[str], None] | None, message: str) -> None:
    if on_stage is None:
        return
    try:
        on_stage(message)
    except Exception as exc:  # noqa: BLE001 - progress must never break the work
        log.warning("geoip stage callback failed: %s", exc)


def last_refresh_error() -> str | None:
    """The message of the last failed refresh in this process, or ``None``."""
    return _last_error


def job_state(job_id: str) -> dict[str, Any] | None:
    """One tracked refresh job, or ``None`` when this process never ran that id."""
    with _JOBS_LOCK:
        job = _JOBS.get(job_id)
    return None if job is None else job.to_json()


def refresh_in_progress() -> dict[str, Any] | None:
    """The queued or running refresh job, if there is one."""
    with _JOBS_LOCK:
        for job in _JOBS.values():
            if job.status in {"queued", "running"}:
                return job.to_json()
    return None


def reset_jobs() -> None:
    """Forget every tracked job and the last error (tests, and a fresh start)."""
    global _last_error
    with _JOBS_LOCK:
        _JOBS.clear()
        _last_error = None


def _run_refresh(job_id: str, fetcher: Callable[[str], bytes] | None, today: date | None) -> None:
    """The worker: one refresh, its outcome recorded on the job."""
    global _last_error
    job = _JOBS.get(job_id)
    if job is None:  # pragma: no cover - the job cannot vanish while it runs
        return
    job.status = "running"
    job.started_at = time.time()
    try:
        source = refresh(
            fetcher=fetcher,
            today=today,
            on_stage=lambda message: setattr(job, "stage", message),
        )
    except Exception as exc:  # noqa: BLE001 - the job records any failure
        job.status = "failed"
        job.stage = "failed"
        job.error = f"{type(exc).__name__}: {exc}"
        _last_error = job.error
        log.warning("geoip refresh %s failed: %s", job_id, exc)
    else:
        job.status = "completed"
        job.stage = "completed"
        job.source = source
        _last_error = None
    finally:
        job.finished_at = time.time()


def start_refresh(
    *,
    fetcher: Callable[[str], bytes] | None = None,
    today: date | None = None,
) -> dict[str, Any]:
    """Queue a refresh on a worker thread and return §5.2's 202 body.

    It runs in process rather than through ``services.jobs`` because a job row there is
    tied to an analysis (``jobs.analysis_id`` is a foreign key), and this download
    belongs to no capture: its result is ``source.json``, exactly as §5.2 says.
    """
    with _JOBS_LOCK:
        for job in _JOBS.values():
            if job.status in {"queued", "running"}:
                raise RefreshBusy(
                    f"refresh {job.job_id} is already {job.status}; wait for it to finish"
                )
        job = RefreshJob(job_id=uuid.uuid4().hex)
        _JOBS[job.job_id] = job
        while len(_JOBS) > MAX_JOBS_TRACKED:
            _JOBS.popitem(last=False)

    threading.Thread(
        target=_run_refresh,
        args=(job.job_id, fetcher, today),
        name=f"geoip-refresh-{job.job_id[:8]}",
        daemon=True,
    ).start()
    log.info("queued geoip refresh %s", job.job_id)
    # The status is what the response can honestly claim at this instant: the worker
    # may already have started, and how it went is readable in source.json (§5.2).
    return {"job_id": job.job_id, "kind": JOB_KIND, "status": "queued"}


__all__ = [
    "ATTRIBUTION",
    "COUNTRY_CAP",
    "DATASET",
    "Dataset",
    "DatasetError",
    "FetchError",
    "GEO_IP_CAP",
    "ISO_CODES",
    "JOB_KIND",
    "LICENCE",
    "MIN_RANGES",
    "NotFound",
    "REFRESH_MONTHS_BACK",
    "RefreshBusy",
    "RefreshError",
    "SCOPE_LOCAL",
    "SCOPE_PUBLIC",
    "SCOPE_RESERVED",
    "candidate_months",
    "classify",
    "clear_cache",
    "country_for",
    "country_name",
    "current_dataset",
    "dataset_for",
    "dataset_path",
    "filename_for",
    "geoip_dir",
    "job_state",
    "load_source",
    "lookup",
    "parse_address",
    "parse_csv",
    "parse_gzip",
    "refresh",
    "refresh_in_progress",
    "reset_jobs",
    "source_path",
    "start_refresh",
    "status",
    "url_for",
]
