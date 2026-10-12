r"""IP registration lookup: RDAP plus Team Cymru's AS data, and the cache (docs/IP_LOOKUP.md §2-§4).

The panel beside a host's detail answers *whose address is this*. Exactly two public,
unauthenticated, key-free services are asked, and only when a reader presses the button:

* **RDAP** - the JSON successor to port-43 whois, run by the five regional internet
  registries. :data:`BOOTSTRAP_URLS` holds IANA's bootstrap documents; the address's
  version picks one, the **longest matching prefix** in it picks the registry, and
  ``<base>/ip/<address>`` is the record. The bootstrap is kept in memory for the life of
  the process (§2), so a second lookup costs one request, not two.
* **Team Cymru** - the origin AS, prefix, country, registry and allocation date, read from
  ``origin.asn.cymru.com`` TXT. **Over DNS-over-HTTPS**, because outbound DNS to arbitrary
  servers is blocked on this host while HTTPS works; that is a measured property of this
  deployment, not a preference.

What this module will not do (§2, §7):

* **Nothing is inferred.** An organisation is never reconstructed from a network name, a
  country is never taken from a prefix's registry when the registry did not publish one,
  and no city, coordinate, provider, cloud region or reputation is produced anywhere. A
  field a registry does not publish is ``None``.
* **Domains are never looked up**, forwards or backwards: the names in the panel come from
  the capture's own tables (see :mod:`app.api.routes_hosts`), because an observed answer is
  evidence and a PTR record is a claim by whoever controls it.
* **A non-public address is never sent anywhere** (§3.4). :func:`classify` decides from the
  address itself, and a non-public address is answered from that classification with no
  request at all.

Two judgement calls worth reading before changing anything here:

* ``192.168.0.0/16`` **is returned unprompted** - ``kind: private``, ``lookup_possible:
  false`` - and the *address is not sent anywhere*. ARIN's registry does carry an IANA
  reservation record for the block, and that record's own remark says the space is used by
  millions of independent networks that are not registered with ARIN, so it would name
  nobody; §3.4 wants that stated rather than presented as a failed lookup, which is what
  :data:`_SPECIAL_ADDRESSES` does.
* **Only a network object's own top-level ``entities`` are read.** ARIN nests its abuse
  point of contact one level down (``ABUSE5250-ARIN`` under ``GOGL``); walking that
  nesting would fill the contact list with named individuals the network object itself
  never tagged, and RIPE's nested records carry no roles or vcard of their own. So ARIN
  space usually shows a registrant name with no address, which is exactly the limit §7
  states on the panel.

The module imports nothing heavy, holds no dataset, and touches neither the network nor
the database at import time: with no network reachable every call reports a failure, and
every other page is unaffected.
"""

from __future__ import annotations

import ipaddress
import json
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Callable

from app import __version__
from app.core.logging import get_logger
from app.db import database as db

log = get_logger("apackets.ip_lookup")

# --------------------------------------------------------------------------
# caps and constants (docs/IP_LOOKUP.md §6)
# --------------------------------------------------------------------------

LOOKUP_TIMEOUT_S = 20.0     # the whole lookup, all steps together (§5.2)
LOCAL_NAME_CAP = 25         # names taken from the capture, by rows seen (§5.1)
CONTACT_CAP = 10            # contacts kept, registrant and abuse roles first
REMARK_CAP = 5              # registry remarks kept
REMARK_CHARS = 400          # ... each truncated to this many characters
LOOKUP_MAX_AGE_DAYS = 30.0  # when a cached record is reported stale (still shown, never hidden)

MAX_BODY_BYTES = 4 * 1024 * 1024   # a registry document is a few kilobytes; this is a guard
MIN_REQUEST_TIMEOUT_S = 0.5        # never hand a socket a timeout that rounds to zero

#: A reader can see who asked for an address, and why it left the host.
USER_AGENT = (
    f"APackets/{__version__} (local PCAP forensics; "
    "one RDAP record and one origin-AS query for the single address an analyst asked about)"
)

#: §2: the address's version picks the bootstrap document.
BOOTSTRAP_URLS: dict[int, str] = {
    4: "https://data.iana.org/rdap/ipv4.json",
    6: "https://data.iana.org/rdap/ipv6.json",
}

#: §2: the AS query goes over DNS-over-HTTPS, because outbound DNS is blocked on this host.
DOH_URL = "https://dns.google/resolve?name={name}&type=TXT"

#: Team Cymru's zones: IPv4 under ``origin.asn``, IPv6 under ``origin6.asn``.
CYMRU_ZONES: dict[int, str] = {4: "origin.asn.cymru.com", 6: "origin6.asn.cymru.com"}

#: The registry is named from the base URL the bootstrap chose - the service that answered
#: is a fact about the answer, while the network's name is only a registry label. A host
#: outside this table is reported as its own hostname rather than guessed at.
REGISTRY_NAMES: dict[str, str] = {
    "rdap.arin.net": "ARIN",
    "rdap.db.ripe.net": "RIPE NCC",
    "rdap.apnic.net": "APNIC",
    "rdap.lacnic.net": "LACNIC",
    "rdap.afrinic.net": "AFRINIC",
}

# --------------------------------------------------------------------------
# §4's kind vocabulary
# --------------------------------------------------------------------------

KIND_PUBLIC = "public"
KIND_PRIVATE = "private"
KIND_RESERVED = "reserved"
KIND_LOOPBACK = "loopback"
KIND_MULTICAST = "multicast"
KIND_LINK_LOCAL = "link_local"
KIND_UNKNOWN = "unknown"

#: Every kind this module can store or report. §5.1 names ``link_local`` among the kinds
#: for which ``lookup_possible`` is false; §4's comment omits it from the column's own
#: enumeration, and this module follows §5.1 because it is the more specific answer.
KINDS: tuple[str, ...] = (
    KIND_PUBLIC,
    KIND_PRIVATE,
    KIND_RESERVED,
    KIND_LOOPBACK,
    KIND_MULTICAST,
    KIND_LINK_LOCAL,
    KIND_UNKNOWN,
)

#: The tail every non-public reason ends with: nothing was asked, and nothing could be.
_NOTHING_TO_ASK = (
    "No registry allocates that space, so there is nothing to ask and the address was not "
    "sent anywhere."
)

#: §3.4's measured special case. ARIN's registry really does answer for 192.168.0.0/16 with
#: an IANA reservation record whose own remark says the space is used by millions of
#: independent networks that are not registered with ARIN; the panel states that instead of
#: presenting the address as an unanswerable lookup - and the address still goes nowhere.
IANA_192_168_NOTE = (
    "RFC 1918 private space, and the one private block ARIN's registry answers for with an "
    "IANA reservation record whose own remark says these addresses are used by millions of "
    "independent networks that are not registered with ARIN, so that record would name "
    "nobody"
)

#: The address's own class, checked in order, with the reason the panel shows (§3.4, §5.1).
#: Anything not listed here that the ``ipaddress`` module refuses to call global - the
#: documentation and benchmark ranges, ``0.0.0.0/8``, ``240/4``, RFC 6598 shared space -
#: is :data:`KIND_RESERVED`, decided by the same rule rather than by a table that would
#: have to be kept complete.
_SPECIAL_ADDRESSES: dict[int, tuple[tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, str, str], ...]] = {
    4: (
        (ipaddress.ip_network("192.168.0.0/16"), KIND_PRIVATE, IANA_192_168_NOTE),
        (ipaddress.ip_network("10.0.0.0/8"), KIND_PRIVATE, "RFC 1918 private space, which no registry allocates"),
        (ipaddress.ip_network("172.16.0.0/12"), KIND_PRIVATE, "RFC 1918 private space, which no registry allocates"),
        (ipaddress.ip_network("127.0.0.0/8"), KIND_LOOPBACK, "the IPv4 loopback range"),
        (ipaddress.ip_network("169.254.0.0/16"), KIND_LINK_LOCAL, "IPv4 link-local space (RFC 3927), which no registry allocates"),
        (ipaddress.ip_network("224.0.0.0/4"), KIND_MULTICAST, "IPv4 multicast space (RFC 5771), which no registry allocates"),
    ),
    6: (
        (ipaddress.ip_network("fc00::/7"), KIND_PRIVATE, "RFC 4193 unique local space, which no registry allocates"),
        (ipaddress.ip_network("::1/128"), KIND_LOOPBACK, "the IPv6 loopback address"),
        (ipaddress.ip_network("fe80::/10"), KIND_LINK_LOCAL, "IPv6 link-local space (RFC 4291), which no registry allocates"),
        (ipaddress.ip_network("ff00::/8"), KIND_MULTICAST, "IPv6 multicast space, which no registry allocates"),
    ),
}

_REQUIRED_ADDRESS_TAIL = (
    "It is not globally routable - the reserved space the ``ipaddress`` module refuses to "
    "call global, such as the documentation and benchmark ranges, 0.0.0.0/8, 240/4 and "
    "RFC 6598 shared space - so no registry allocates it to an end user and the address "
    "was not sent anywhere."
)

#: §5.1's ``note``, sent with every response in both states.
NOTE = (
    "The registration record comes from the registry's own RDAP service - reached through "
    "IANA's bootstrap for the address's version - and the origin AS from Team Cymru over "
    "DNS-over-HTTPS. A country here is where the block or the AS is registered rather than "
    "where the host is, and it can disagree with the geography panel, which reads a "
    "different dataset; both are shown with their sources rather than reconciled. Contacts "
    "are the registry's published ones - often an abuse desk, frequently redacted - and an "
    "empty list means the registry published nothing, not that nobody owns the address. The "
    "names listed are the ones this capture observed pointing at the address, never a "
    "reverse lookup. The record is a snapshot: the fetch time is shown with it and a record "
    "older than 30 days is marked stale rather than silently served as current. Nothing "
    "here is scored and no finding is raised from it. The address goes to those two public "
    "services only when the lookup is asked for; opening a host panel sends nothing."
)


# --------------------------------------------------------------------------
# errors
# --------------------------------------------------------------------------

class IpLookupError(RuntimeError):
    """Base class: this module never raises anything else out of a public call."""


class FetchError(IpLookupError):
    """One step of the lookup could not be completed: network, HTTP status or a bad body."""


class LookupFailed(IpLookupError):
    """Nothing at all came back, so there is nothing to cache (§5.2: 502 ``lookup_failed``)."""

    def __init__(self, ip: str, failures: tuple[str, ...]) -> None:
        self.ip = ip
        self.failures = tuple(failures)
        if self.failures:
            message = f"Nothing could be retrieved for {ip}: " + "; ".join(self.failures)
        else:  # pragma: no cover - a lookup that fails always names why
            message = f"Nothing could be retrieved for {ip}."
        super().__init__(message)


# --------------------------------------------------------------------------
# address handling (§3.4)
# --------------------------------------------------------------------------

def parse_address(value: object) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    """Best-effort address parse; ``None`` for anything that is not an address.

    An IPv4-mapped IPv6 address is returned as the IPv4 address it carries, so
    ``::ffff:8.8.8.8`` is classified, queried and cached as ``8.8.8.8`` rather than
    becoming a second key for one address. Malformed input is a ``None``, never an
    exception: the API takes addresses from tables it did not write.
    """
    if value is None:
        return None
    try:
        address = ipaddress.ip_address(str(value).strip())
    except ValueError:
        return None
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
        return address.ipv4_mapped
    return address


def classify(value: object) -> str | None:
    """§3.4's class for one address, decided from the address itself.

    Returns ``None`` only when the value is not an address at all - which the API answers
    as a ``422`` before it ever reaches a lookup. This is the *only* gate in front of the
    network: anything but :data:`KIND_PUBLIC` is answered from this function's result and
    is sent nowhere.
    """
    address = parse_address(value)
    if address is None:
        return None
    for network, kind, _reason in _SPECIAL_ADDRESSES.get(address.version, ()):
        if address in network:
            return kind
    if address.is_global:
        return KIND_PUBLIC
    return KIND_RESERVED


def reason_for(value: object) -> str | None:
    """Why an address cannot be looked up, or ``None`` when it can.

    The reason names the block and says that nothing was asked, because §3.4's promise is
    about what left the host, and a reader is entitled to see it stated.
    """
    address = parse_address(value)
    if address is None:
        return f"'{value}' is not an IP address, so there is no registry to ask."
    if classify(address) == KIND_PUBLIC:
        return None
    for network, _kind, reason in _SPECIAL_ADDRESSES.get(address.version, ()):
        if address in network:
            return f"{address} is in {network} - {reason}. {_NOTHING_TO_ASK}"
    return f"{address} is not a public address. {_REQUIRED_ADDRESS_TAIL}"


def canonical(value: object) -> str | None:
    """The address as it is keyed in ``ip_lookups`` and sent in a query, or ``None``."""
    address = parse_address(value)
    return None if address is None else str(address)


# --------------------------------------------------------------------------
# the IANA bootstrap (§2)
# --------------------------------------------------------------------------

class Bootstrap:
    """One parsed bootstrap document: the prefixes and the RDAP base URL each is served by.

    The IANA documents do not name the registries - only the base URLs - so the choice is
    made on prefixes alone and the registry is named from the URL that won.
    """

    __slots__ = ("entries", "source")

    def __init__(
        self,
        entries: tuple[tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, str], ...],
        source: str,
    ) -> None:
        self.entries = entries
        self.source = source

    def base_url_for(self, address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> str | None:
        """The base URL of the **longest** prefix containing *address*, or ``None``.

        Longest prefix wins because that is what the bootstrap means: a service entry may
        cover a whole ``/8`` and another a ``/16`` inside it, and the narrower entry is the
        registry that actually holds the space. A tie keeps the earlier entry, and the URLs
        within an entry are already ordered https-first by :func:`parse_bootstrap`.
        """
        best: tuple[int, str] | None = None
        for network, url in self.entries:
            if network.version != address.version or address not in network:
                continue
            if best is None or network.prefixlen > best[0]:
                best = (network.prefixlen, url)
        return best[1] if best else None

    def __len__(self) -> int:
        return len(self.entries)


def parse_bootstrap(raw: bytes | str, *, source: str = "<bootstrap>") -> Bootstrap:
    """Parse one ``data.iana.org/rdap/ipvN.json`` document.

    Only the ``services`` array is read: each entry is ``[prefixes, urls]``, and the first
    **https** URL is kept (ARIN publishes an ``http://`` alternative next to it, and an
    address should not leave the host in the clear because of the order of a list). An
    entry whose prefixes or URLs are unusable is skipped rather than failing the document,
    because one malformed entry must not cost the reader the other four registries.
    """
    text = raw.decode("utf-8", "replace") if isinstance(raw, bytes) else raw
    try:
        document = json.loads(text)
    except (json.JSONDecodeError, TypeError) as exc:
        raise FetchError(f"{source} is not JSON ({exc})") from exc
    if not isinstance(document, dict):
        raise FetchError(f"{source} is not a JSON object")

    entries: list[tuple[Any, str]] = []
    for service in document.get("services") or []:
        if not isinstance(service, list) or len(service) < 2:
            continue
        prefixes, urls = service[0], service[1]
        if not isinstance(prefixes, list) or not isinstance(urls, list):
            continue
        url = None
        for candidate in urls:
            if not isinstance(candidate, str) or not candidate.strip():
                continue
            candidate = candidate.strip()
            if candidate.lower().startswith("https://"):
                url = candidate
                break
            url = url or candidate
        if url is None:
            continue
        for prefix in prefixes:
            try:
                network = ipaddress.ip_network(str(prefix).strip(), strict=False)
            except ValueError:
                log.warning("bootstrap entry %r is not a prefix; skipped", prefix)
                continue
            entries.append((network, url))

    if not entries:
        raise FetchError(f"{source} carries no usable RDAP service entry")
    return Bootstrap(entries=tuple(entries), source=source)


_BOOTSTRAP_LOCK = threading.Lock()
#: §2: "Cached in memory for the process". A failure is never cached, so a resolver that
#: was down is retried on the next lookup rather than remembered as unavailable.
_BOOTSTRAP: dict[int, Bootstrap] = {}


def clear_cache() -> None:
    """Forget the in-memory bootstraps. A test calls this between fixture fetchers."""
    with _BOOTSTRAP_LOCK:
        _BOOTSTRAP.clear()


def bootstrap(
    version: int,
    *,
    fetcher: "Fetcher | None" = None,
    deadline: float | None = None,
) -> Bootstrap:
    """The parsed bootstrap for an address version, fetched once per process (§2)."""
    with _BOOTSTRAP_LOCK:
        cached = _BOOTSTRAP.get(version)
    if cached is not None:
        return cached

    url = BOOTSTRAP_URLS.get(version)
    if url is None:  # pragma: no cover - parse_address only ever yields version 4 or 6
        raise FetchError(f"no IANA RDAP bootstrap is published for IP version {version}")
    parsed = parse_bootstrap(_get(fetcher, url, deadline), source=url)
    with _BOOTSTRAP_LOCK:
        _BOOTSTRAP.setdefault(version, parsed)
        return _BOOTSTRAP[version]


def base_url_for(
    address: ipaddress.IPv4Address | ipaddress.IPv6Address,
    *,
    fetcher: "Fetcher | None" = None,
    deadline: float | None = None,
) -> str | None:
    """The RDAP base URL that serves *address*, or ``None`` when the bootstrap is silent."""
    return bootstrap(address.version, fetcher=fetcher, deadline=deadline).base_url_for(address)


def rdap_url(base_url: str, address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> str:
    """``<base>/ip/<address>`` - the record's own URL, and the one shown as its link."""
    return f"{base_url.rstrip('/')}/ip/{address}"


def registry_name(base_url: str | None) -> str | None:
    """The registry behind a base URL: the five RIRs by name, anyone else by hostname."""
    if not base_url:
        return None
    host = (urllib.parse.urlsplit(base_url).hostname or "").lower()
    if not host:
        return None
    return REGISTRY_NAMES.get(host, host)


# --------------------------------------------------------------------------
# the network, bounded by the shared budget (§5.2)
# --------------------------------------------------------------------------

#: A fetcher serves one URL within *timeout* seconds and returns its raw body, raising
#: anything on failure. Tests inject one; production uses :func:`_fetch`.
Fetcher = Callable[[str, float], bytes]


def _accept_for(url: str) -> str:
    """Ask for what the step actually wants - a registry document or a DNS answer."""
    if url.startswith(DOH_URL.split("?", 1)[0]):
        return "application/dns-json, application/json;q=0.9"
    return "application/rdap+json, application/json;q=0.9"


def _fetch(url: str, timeout: float) -> bytes:
    """One HTTPS GET with an honest User-Agent, or :class:`FetchError`.

    The body is read with a hard ceiling: a registry document is a few kilobytes and this
    is a local tool on a home connection, so a megabyte-scale body means something is
    wrong rather than that a bigger buffer is needed.
    """
    request = urllib.request.Request(
        url,
        headers={"User-Agent": USER_AGENT, "Accept": _accept_for(url)},
    )
    try:
        with urllib.request.urlopen(request, timeout=max(MIN_REQUEST_TIMEOUT_S, timeout)) as response:
            raw = response.read(MAX_BODY_BYTES + 1)
    except urllib.error.HTTPError as exc:
        raise FetchError(f"HTTP {exc.code} {exc.reason}") from exc
    except urllib.error.URLError as exc:
        raise FetchError(f"could not be reached ({exc.reason})") from exc
    except (OSError, ValueError) as exc:
        raise FetchError(f"failed ({exc})") from exc
    if len(raw) > MAX_BODY_BYTES:
        raise FetchError(f"returned more than {MAX_BODY_BYTES // 1024} kB, which is not a lookup answer")
    return raw


def _get(fetcher: Fetcher | None, url: str, deadline: float | None) -> bytes:
    """Fetch one URL, spending the shared budget rather than a budget of its own.

    §5.2 bounds *the whole lookup* by :data:`LOOKUP_TIMEOUT_S`, so every request gets what
    is left of it: three steps of twenty seconds each would not be the contract, and a step
    started after the budget is gone fails immediately with that stated.
    """
    if deadline is None:
        timeout = LOOKUP_TIMEOUT_S
    else:
        left = deadline - time.monotonic()
        if left <= 0:
            raise FetchError(
                f"the {LOOKUP_TIMEOUT_S:.0f} s lookup budget was already spent before this step"
            )
        timeout = left
    fetch = fetcher or _fetch
    try:
        return fetch(url, timeout)
    except FetchError:
        raise
    except Exception as exc:  # a fetcher may raise anything; the lookup names one failure
        raise FetchError(f"failed ({exc})") from exc


def _json_document(raw: bytes, *, source: str) -> dict:
    """Decode one JSON object, or :class:`FetchError` naming what arrived instead."""
    try:
        document = json.loads(raw.decode("utf-8", "replace"))
    except (json.JSONDecodeError, UnicodeError, TypeError) as exc:
        raise FetchError(f"{source} did not return JSON ({exc})") from exc
    if not isinstance(document, dict):
        raise FetchError(f"{source} returned {type(document).__name__}, not a JSON object")
    return document


# --------------------------------------------------------------------------
# Team Cymru over DNS-over-HTTPS (§2)
# --------------------------------------------------------------------------

def origin_name(address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> str:
    """The Cymru query name for an address: its octets (or nibbles) in reverse.

    ``8.8.8.8`` -> ``8.8.8.8.origin.asn.cymru.com`` and
    ``150.171.109.217`` -> ``217.109.171.150.origin.asn.cymru.com``.
    """
    zone = CYMRU_ZONES[address.version]
    labels = address.reverse_pointer.split(".")[: -2]
    return ".".join([*labels, zone])


def asn_url(address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> str:
    """The DNS-over-HTTPS URL that answers the AS question for one address."""
    return DOH_URL.format(name=urllib.parse.quote(origin_name(address)))


def parse_cymru(text: object) -> dict | None:
    """One Cymru TXT answer into §5.1's ``asn`` object, or ``None`` when it names no AS.

    The answer is pipe-separated, as measured:
    ``15169 | 8.8.8.0/24 | US | arin | 2023-12-28``. A leading ``AS`` (the port-43 form) is
    accepted and dropped, and a field carrying Cymru's ``NA`` marker is ``None`` - its way
    of saying the field is not available, which §2 requires to stay null. That reading is
    deliberate: ``NA`` is also Namibia's ISO 3166-1 code, and this module cannot tell the
    marker from the country, so it takes the marker's meaning; an answer whose AS number is
    ``NA`` is no answer at all and is rejected outright a line later.
    """
    if not isinstance(text, str):
        return None
    fields = [part.strip() for part in text.split("|")]
    if len(fields) < 5:
        fields += [""] * (5 - len(fields))

    def _known(value: str) -> str | None:
        return None if not value or value.upper() in {"NA", "N/A", "NONE"} else value

    number = fields[0].upper()
    if number.startswith("AS"):
        number = number[2:].strip()
    if not number.isdigit():
        return None

    country = (_known(fields[2]) or "").upper()
    if len(country) != 2 or not country.isalpha():
        country = None

    return {
        "number": number,
        "prefix": _known(fields[1]),
        "country": country,
        "registry": (_known(fields[3]) or "").lower() or None,
        "allocated": _known(fields[4]),
    }


def fetch_asn(
    address: ipaddress.IPv4Address | ipaddress.IPv6Address,
    *,
    fetcher: Fetcher | None = None,
    deadline: float | None = None,
) -> dict:
    """The origin AS for one address, or :class:`FetchError`.

    A resolver that answers with no TXT record at all - Cymru publishes nothing for space
    it does not carry - is a failed step, not a record with empty fields, so §5.2 can name
    it in ``failures`` instead of the panel showing an ASN that does not exist.
    """
    document = _json_document(
        _get(fetcher, asn_url(address), deadline),
        source="the DNS-over-HTTPS resolver",
    )
    answers = document.get("Answer")
    if not isinstance(answers, list):
        answers = []
    for answer in answers:
        if not isinstance(answer, dict):
            continue
        # 16 is TXT; the resolver echoes the question as well, and that entry carries none.
        if answer.get("type") not in (16, "TXT", None):
            continue
        data = answer.get("data")
        if not isinstance(data, str):
            continue
        parsed = parse_cymru(data.strip().strip('"'))
        if parsed is not None:
            return parsed
    raise FetchError(f"no origin AS was published for this address (status {document.get('Status')})")


# --------------------------------------------------------------------------
# normalising the registry's record (§5.1)
# --------------------------------------------------------------------------

def _text(value: object) -> str | None:
    """A stripped string, or ``None`` - an empty field is a field the registry left out."""
    if value is None or isinstance(value, (dict, list)):
        return None
    text = str(value).strip()
    return text or None


def _vcard(value: object) -> tuple[str | None, list[str]]:
    """``fn`` and the ``email`` entries of one RDAP ``vcardArray``.

    The vcard is a flat array of 4-element properties (``name, parameters, type, value``);
    only ``fn`` (the formatted name) and ``email`` are read, which is all §5.1 asks for.
    A redacted or absent name stays ``None`` rather than becoming the handle: the handle
    is shown beside it as it is.
    """
    if not isinstance(value, list) or len(value) < 2 or not isinstance(value[1], list):
        return None, []
    name: str | None = None
    emails: list[str] = []
    for item in value[1]:
        if not isinstance(item, list) or len(item) < 4:
            continue
        key = str(item[0]).strip().lower()
        text = _text(item[3])
        if text is None:
            continue
        if key == "fn" and name is None:
            name = text
        elif key == "email" and text not in emails:
            emails.append(text)
    return name, emails


#: §6: contacts are kept registrant and abuse first, then technical and administrative,
#: then whatever else the registry published, in the order the record lists it.
ROLE_ORDER: tuple[str, ...] = ("registrant", "abuse", "technical", "administrative")


def contacts(entity_list: object) -> list[dict]:
    """§5.1's ``contacts``: the entities' roles with the names and mailboxes they publish.

    Only the network object's own top-level entities are read (see the module docstring).
    An entity that publishes no role keeps ``role: None`` and sorts with "the rest" - the
    panel says the registry published no role rather than this module inventing one.
    """
    items: list[tuple[int, int, dict]] = []
    if not isinstance(entity_list, list):
        return []
    for position, entity in enumerate(entity_list):
        if not isinstance(entity, dict):
            continue
        roles = [
            str(role).strip().lower()
            for role in (entity.get("roles") or [])
            if str(role).strip()
        ]
        name, emails = _vcard(entity.get("vcardArray"))
        handle = _text(entity.get("handle"))
        role = next((candidate for candidate in ROLE_ORDER if candidate in roles), None)
        if role is None and roles:
            role = roles[0]
        if handle is None and name is None and not emails:
            continue    # an entity that publishes nothing this panel shows
        rank = ROLE_ORDER.index(role) if role in ROLE_ORDER else len(ROLE_ORDER)
        items.append((rank, position, {"role": role, "handle": handle, "name": name, "emails": emails}))

    items.sort(key=lambda item: (item[0], item[1]))
    return [item[2] for item in items[:CONTACT_CAP]]


def remarks(document: dict) -> list[str]:
    """§5.1's ``remarks``: the registry's own remarks, capped and truncated (§6).

    A remark's description is a list of lines; they are joined into one string so the panel
    shows one remark per entry, with the remark's title in front of it when it has one. The
    cut is at :data:`REMARK_CHARS` characters, and what was cut is not signalled in the
    text: the frontend owns presentation.
    """
    collected: list[str] = []
    entries = document.get("remarks")
    if not isinstance(entries, list):
        return []
    for remark in entries:
        if not isinstance(remark, dict):
            continue
        lines = [
            str(line).strip()
            for line in (remark.get("description") or [])
            if str(line).strip()
        ]
        if not lines:
            continue
        title = _text(remark.get("title"))
        text = " ".join(lines)
        collected.append(f"{title}: {text}"[:REMARK_CHARS] if title else text[:REMARK_CHARS])
        if len(collected) >= REMARK_CAP:
            break
    return collected


def _range(document: dict) -> dict | None:
    start = _text(document.get("startAddress"))
    end = _text(document.get("endAddress"))
    if start is None and end is None:
        return None
    return {"start": start, "end": end}


def _statuses(document: dict) -> list[str]:
    statuses = document.get("status")
    if not isinstance(statuses, list):
        return []
    return [str(status).strip() for status in statuses if str(status).strip()]


def normalise(
    address: ipaddress.IPv4Address | ipaddress.IPv6Address,
    *,
    base_url: str | None,
    document: dict | None,
    asn: dict | None,
    failures: tuple[str, ...] = (),
) -> dict:
    """§5.1's ``record``: exactly the fields the two services published, and nothing else.

    *country* is RDAP's when the registry publishes one and Cymru's otherwise - ARIN's
    network objects carry no country while Cymru's answer always does, so the fallback is
    the normal path for ARIN space. It is never taken from the network name, the handle or
    the registry, and when neither source has one it is ``None``.

    A step that failed leaves its fields ``None`` while the other step's are filled in, and
    *failures* names what did not come back, so a partial answer is never presented as a
    whole one (§5.2).
    """
    document = document or {}
    country = _text(document.get("country")) or (asn or {}).get("country")
    return {
        "registry": registry_name(base_url),
        "network_name": _text(document.get("name")),
        "handle": _text(document.get("handle")),
        "range": _range(document),
        "allocation_type": _text(document.get("type")),
        "status": _statuses(document),
        "country": country,
        "port43": _text(document.get("port43")),
        "rdap_url": rdap_url(base_url, address) if base_url else None,
        "asn": asn,
        "contacts": contacts(document.get("entities")),
        "remarks": remarks(document),
        "failures": list(failures),
    }


# --------------------------------------------------------------------------
# one lookup (§2-§5.2)
# --------------------------------------------------------------------------

@dataclass(frozen=True)
class Lookup:
    """The outcome of one lookup, before and after it is cached.

    ``record`` is ``None`` for a non-public address - there is nothing to record - which is
    also what stops :func:`refresh` from writing a cache row for one.
    """

    ip: str
    kind: str
    lookup_possible: bool = False
    reason: str | None = None
    source: str | None = None
    asn: str | None = None
    country: str | None = None
    record: dict | None = None
    failures: tuple[str, ...] = ()
    fetched_at: float = field(default_factory=time.time)

    @property
    def queried(self) -> bool:
        """Whether anything was actually asked of a third party."""
        return self.lookup_possible


def lookup(
    ip: object,
    *,
    fetcher: Fetcher | None = None,
    now: float | None = None,
) -> Lookup:
    """Look one address up in RDAP and Team Cymru, without touching the cache.

    The whole thing is bounded by :data:`LOOKUP_TIMEOUT_S` shared across its steps. Each
    step fails on its own: RDAP may fail while Cymru answers, and the record then carries
    what came back plus the failures. Nothing at all coming back raises
    :class:`LookupFailed`, which §5.2 answers as ``502 lookup_failed`` with no cache write.

    A non-public address returns immediately: no bootstrap, no request, no resolver - the
    only thing that decides it is :func:`classify`.
    """
    stamp = time.time() if now is None else float(now)
    address = parse_address(ip)

    if address is None:
        return Lookup(
            ip=str(ip),
            kind=KIND_UNKNOWN,
            reason=f"'{ip}' is not an IP address, so there is no registry to ask.",
            fetched_at=stamp,
        )

    kind = classify(address)
    if kind != KIND_PUBLIC:
        # §3.4: answered from the address itself, before any request exists to make.
        log.info("registration lookup skipped for %s: %s", address, kind)
        return Lookup(
            ip=str(address),
            kind=kind or KIND_UNKNOWN,
            reason=reason_for(address),
            fetched_at=stamp,
        )

    deadline = time.monotonic() + LOOKUP_TIMEOUT_S
    failures: list[str] = []

    base_url: str | None = None
    try:
        base_url = base_url_for(address, fetcher=fetcher, deadline=deadline)
    except IpLookupError as exc:
        failures.append(f"IANA RDAP bootstrap: {exc}")
    if base_url is None and not failures:
        failures.append("IANA RDAP bootstrap: no base URL is published for this address")

    document: dict | None = None
    if base_url is not None:
        url = rdap_url(base_url, address)
        try:
            document = _json_document(
                _get(fetcher, url, deadline),
                source=url,
            )
            error_code = document.get("errorCode")
            if error_code is not None:
                # RDAP answers some failures with 200 and an error document in the body.
                title = _text(document.get("title")) or "no title"
                raise FetchError(f"HTTP {error_code} {title}")
        except IpLookupError as exc:
            document = None
            failures.append(f"RDAP ({url}): {exc}")

    asn: dict | None = None
    try:
        asn = fetch_asn(address, fetcher=fetcher, deadline=deadline)
    except IpLookupError as exc:
        failures.append(f"Team Cymru AS data: {exc}")

    if document is None and asn is None:
        # §5.2: nothing at all came back - a 502, and nothing is cached.
        log.warning("registration lookup failed for %s: %s", address, "; ".join(failures))
        raise LookupFailed(str(address), tuple(failures))

    record = normalise(
        address,
        base_url=base_url,
        document=document,
        asn=asn,
        failures=tuple(failures),
    )
    result = Lookup(
        ip=str(address),
        kind=KIND_PUBLIC,
        lookup_possible=True,
        source=base_url,
        asn=(asn or {}).get("number"),
        country=record.get("country"),
        record=record,
        failures=tuple(failures),
        fetched_at=stamp,
    )
    log.info(
        "registration lookup for %s: registry=%s asn=%s country=%s failures=%d",
        result.ip, record.get("registry"), result.asn, result.country, len(result.failures),
    )
    return result


# --------------------------------------------------------------------------
# the cache (§4)
# --------------------------------------------------------------------------

CACHE_COLUMNS: tuple[str, ...] = ("ip", "kind", "source", "asn", "country", "fetched_at", "payload")


def cached(ip: object) -> dict | None:
    """The stored row for one address, or ``None`` when nothing was ever looked up.

    ``payload`` is the parsed §5.1 record; a row whose payload cannot be parsed is treated
    as no record rather than as an error, because a page must not fail over one bad row.
    """
    address = canonical(ip)
    if address is None:
        return None
    row = db.query_one(f"SELECT {', '.join(CACHE_COLUMNS)} FROM ip_lookups WHERE ip = ?", (address,))
    if row is None:
        return None

    payload: Any = row["payload"]
    try:
        payload = json.loads(payload) if isinstance(payload, str) else payload
    except (json.JSONDecodeError, TypeError):
        log.warning("cached lookup for %s has an unreadable payload", address)
        payload = None
    if not isinstance(payload, dict):
        payload = None

    return {
        "ip": row["ip"],
        "kind": row["kind"],
        "source": row["source"],
        "asn": row["asn"],
        "country": row["country"],
        "fetched_at": float(row["fetched_at"]),
        "payload": payload,
    }


def store(result: Lookup) -> bool:
    """Write §4's row for a completed lookup; ``False`` when there is nothing to write.

    A lookup that produced no record and a non-public address both write nothing: the
    table remembers what a third party answered, and neither of those has an answer. Two
    captures that contain the same peer share the row, which is why the key is the address
    alone.
    """
    if result.record is None or not result.lookup_possible:
        return False
    with db.get_conn() as conn:
        conn.execute(
            """
            INSERT INTO ip_lookups (ip, kind, source, asn, country, fetched_at, payload)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(ip) DO UPDATE SET
                kind = excluded.kind,
                source = excluded.source,
                asn = excluded.asn,
                country = excluded.country,
                fetched_at = excluded.fetched_at,
                payload = excluded.payload
            """,
            (
                result.ip,
                result.kind,
                result.source,
                result.asn,
                result.country,
                result.fetched_at,
                json.dumps(result.record, ensure_ascii=False, separators=(",", ":")),
            ),
        )
    log.info("cached registration record for %s (%s)", result.ip, result.source or "no source")
    return True


def refresh(
    ip: object,
    *,
    fetcher: Fetcher | None = None,
    now: float | None = None,
) -> Lookup:
    """§5.2: perform the lookup now **and cache it**. Raises :class:`LookupFailed`.

    A failed lookup writes nothing, and a non-public address writes nothing either - it was
    answered from itself, and there is no fetched answer for the cache to keep.
    """
    result = lookup(ip, fetcher=fetcher, now=now)
    store(result)
    return result


def cache_state(ip: object, *, now: float | None = None) -> dict | None:
    """§5.1's ``cache`` block: when the record was fetched and whether it is stale.

    ``stale`` is §6's :data:`LOOKUP_MAX_AGE_DAYS`; a stale record is still shown, never
    hidden - §7 asks for the fetch time to be reported rather than an old answer served as
    a current one.
    """
    row = cached(ip)
    if row is None:
        return None
    current = time.time() if now is None else float(now)
    age_days = max(0.0, (current - row["fetched_at"]) / 86400.0)
    return {
        "fetched_at": row["fetched_at"],
        "age_days": age_days,
        "stale": age_days > LOOKUP_MAX_AGE_DAYS,
        "source": row["source"],
    }


# --------------------------------------------------------------------------
# §5.1's envelope
# --------------------------------------------------------------------------

def envelope(ip: object, *, local: dict | None = None, now: float | None = None) -> dict:
    """§5.1's response body: the cached record, the capture-local block, and the class.

    **This never fetches.** Everything in it is either the address itself or a row this
    installation already holds. ``record`` is ``None`` when nothing has been looked up yet,
    and also when the address is not public - there is no registration record for space no
    registry holds, and the cached row of such an address is not shown as one.

    ``local`` is built by the route from the analysis's own tables (the DB-IP country and
    the names this capture observed); the service never reads capture data itself.
    """
    address = parse_address(ip)
    kind = classify(address) if address is not None else KIND_UNKNOWN
    possible = kind == KIND_PUBLIC

    row = cached(address) if address is not None else None
    record = None
    cache = None
    if row is not None:
        cache = cache_state(address, now=now)
        if possible and row["kind"] == KIND_PUBLIC:
            record = row["payload"]

    return {
        "ip": str(address) if address is not None else str(ip),
        "kind": kind or KIND_UNKNOWN,
        "lookup_possible": possible,
        "reason": None if possible else reason_for(address if address is not None else ip),
        "cache": cache,
        "record": record,
        "local": local,
        "note": NOTE,
    }
