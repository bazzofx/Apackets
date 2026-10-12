"""Registration lookup tests: RDAP, Team Cymru, the cache and the API (docs/IP_LOOKUP.md §2-§6).

Everything here is built in the test: the bootstrap document, both registry record shapes,
the Cymru TXT answer and the capture rows. **No test reaches the network** - the service's
fetcher is either injected or replaced by one that serves the fixtures and records every URL
it was asked for, so "the address was sent nowhere" is an assertion about calls rather than a
hope. No test touches the live ``data/`` directory or the live database.

The expected values are the ones the measured services really return - ``15169 | 8.8.8.0/24 |
US | arin | 2023-12-28``, ARIN's network objects carrying no country, RIPE's role-tagged
abuse mailbox - and nothing is inferred from a network name, a handle or a prefix.
"""

from __future__ import annotations

import gzip
import importlib
import io
import ipaddress
import json
import shutil
import time
import uuid
from pathlib import Path

import pytest

from app.core.config import settings
from app.db import database as db
from app.services import geoip, ip_lookup

ANALYSIS_ID = "a1b2c3d4e5f60718293a4b5c6d7e8f90"
OTHER_ID = "bbbad262b2c04c9c966fb7c794a35ae5"
READY_ID = "0123456789abcdef0123456789abcdef"
BUSY_ID = "fedcba9876543210fedcba9876543210"

#: Per-test directories live inside the repository, never in ``tempfile``: ``mkdtemp``
#: creates 0o700 directories some sandboxed environments cannot write into.
SCRATCH_ROOT = Path(__file__).resolve().parents[2] / ".tmp" / "ip-lookup-tests"

#: The addresses the contract measured, and the two that only exercise the bootstrap.
APNIC_IP = "150.171.109.217"      # Microsoft, AS8075, served by APNIC's RDAP
RIPE_IP = "51.132.193.108"        # Microsoft, AS8075, served by RIPE's RDAP
ARIN_IP = "8.8.8.8"               # Google, AS15169, served by ARIN's RDAP
WIDE_IP = "45.33.32.156"          # inside both the fixture's /8 and its narrower /16
WIDE_BASE = "https://rdap.wide.example/"
NARROW_BASE = "https://rdap.narrow.example/"

APNIC_BASE = "https://rdap.apnic.net/"
RIPE_BASE = "https://rdap.db.ripe.net/"
ARIN_BASE = "https://rdap.arin.net/registry/"

#: The bootstrap in miniature, with every shape the parser must survive: an address covered
#: by a ``/8`` **and** by a narrower ``/16`` served by a different base URL (the longer prefix
#: must win), an http URL published next to an https one (https must win), and IPv6.
FIXTURE_BOOTSTRAP = {
    "description": "fixture: services in miniature",
    "publication": "2026-10-01T00:00:00Z",
    "version": "1.0",
    "services": [
        [["1.0.0.0/8"], [APNIC_BASE]],
        [["8.0.0.0/8"], [ARIN_BASE, "http://rdap.arin.net/registry/"]],
        [["45.0.0.0/8"], [WIDE_BASE]],
        [["45.33.0.0/16"], [NARROW_BASE]],
        [["51.0.0.0/8"], [RIPE_BASE]],
        [["150.0.0.0/8"], [APNIC_BASE]],
        [["2001:db8::/32"], ["https://rdap.example-v6.test/"]],
    ],
}

#: ARIN's shape, measured on ``8.8.8.8``: no ``country`` key at all, a registrant that
#: publishes a name and no mailbox, and the abuse point of contact only *nested* inside it.
#: §7 says ARIN often publishes a name and no address - this is that record.
ARIN_RECORD = {
    "objectClassName": "ip network",
    "handle": "NET-8-8-8-0-2",
    "name": "GOGL",
    "type": "DIRECT ALLOCATION",
    "status": ["active"],
    "startAddress": "8.8.8.0",
    "endAddress": "8.8.8.255",
    "parentHandle": "NET-8-0-0-0-0",
    "port43": "whois.arin.net",
    "entities": [
        {
            "objectClassName": "entity",
            "handle": "GOGL",
            "roles": ["registrant"],
            "vcardArray": ["vcard", [
                ["version", {}, "text", "4.0"],
                ["fn", {}, "text", "Google LLC"],
                ["kind", {}, "text", "org"],
            ]],
            "entities": [
                {
                    "objectClassName": "entity",
                    "handle": "ABUSE5250-ARIN",
                    "roles": ["abuse"],
                    "vcardArray": ["vcard", [
                        ["fn", {}, "text", "Abuse Contact"],
                        ["email", {"type": "work"}, "text", "abuse@example.com"],
                    ]],
                }
            ],
        }
    ],
    "notices": [{"title": "Terms of Service", "description": ["By using ARIN RDAP you agree."]}],
}

#: RIPE's shape, measured on ``51.132.193.108``: a country, four role-tagged entities, and an
#: abuse mailbox.
RIPE_RECORD = {
    "objectClassName": "ip network",
    "handle": "51.132.128.0 - 51.132.255.255",
    "name": "cloud",
    "type": "LEGACY",
    "country": "GB",
    "status": ["active"],
    "startAddress": "51.132.128.0",
    "endAddress": "51.132.255.255",
    "parentHandle": "51.132.0.0 - 51.132.255.255",
    "port43": "whois.ripe.net",
    "entities": [
        {
            "handle": "DH5439-RIPE",
            "roles": ["administrative"],
            "vcardArray": ["vcard", [["fn", {}, "text", "Divya Quamara"]]],
        },
        {
            "handle": "MICROSOFT-MAINT",
            "roles": ["registrant"],
            "vcardArray": ["vcard", [["fn", {}, "text", "MICROSOFT-MAINT"]]],
        },
        {
            "handle": "MRPA3-RIPE",
            "roles": ["technical"],
            "vcardArray": ["vcard", [["fn", {}, "text", "Microsoft Routing, Peering, and DNS"]]],
        },
        {
            "handle": "MAC274-RIPE",
            "roles": ["abuse"],
            "vcardArray": ["vcard", [
                ["fn", {}, "text", "Microsoft Abuse Contact"],
                ["email", {"type": "abuse"}, "text", "abuse@microsoft.com"],
            ]],
        },
    ],
    "remarks": [{"title": "Registration Comments", "description": ["Allocated to Microsoft."]}],
}

#: APNIC's service answering with an ARIN-shaped record: measured, APNIC's RDAP holds ARIN's
#: ``NET-150-171-0-0-1``, so the registry that answered and the ``port43`` differ.
APNIC_RECORD = {
    "objectClassName": "ip network",
    "handle": "NET-150-171-0-0-1",
    "name": "MSFT",
    "type": "DIRECT ALLOCATION",
    "status": ["active"],
    "startAddress": "150.171.0.0",
    "endAddress": "150.171.255.255",
    "port43": "whois.arin.net",
    "entities": [
        {
            "handle": "MSFT",
            "roles": ["registrant"],
            "vcardArray": ["vcard", [["fn", {}, "text", "Microsoft Corporation"]]],
        }
    ],
}

#: The three Cymru answers the contract measured, and one more for a record with no country.
CYMRU_GOOGLE = "15169 | 8.8.8.0/24 | US | arin | 2023-12-28"
CYMRU_APNIC = "8075 | 150.171.0.0/16 | US | arin | 2015-11-24"
CYMRU_RIPE = "8075 | 51.132.0.0/16 | GB | ripencc | 1993-09-01"
CYMRU_CLOUDFLARE = "13335 | 1.1.1.0/24 | AU | apnic | 2011-08-11"


# --------------------------------------------------------------------------
# fixture helpers
# --------------------------------------------------------------------------

def _json_bytes(document: object) -> bytes:
    return json.dumps(document).encode("utf-8")


def _txt_bytes(text: str) -> bytes:
    """A DNS-over-HTTPS answer carrying one TXT record, as the resolver returns it."""
    return _json_bytes({"Status": 0, "Answer": [{"name": "fixture", "type": 16, "TTL": 60, "data": text}]})


class FakeNetwork:
    """A fetcher that serves prepared bodies and remembers every URL it was asked for.

    A route missing from ``routes`` is a 404-shaped :class:`ip_lookup.FetchError`, and a
    route whose value is an exception raises it, so a test can fail one step without
    simulating a socket.
    """

    def __init__(self, routes: dict[str, object] | None = None) -> None:
        self.routes = dict(routes or {})
        self.urls: list[str] = []
        self.timeouts: list[float] = []

    def __call__(self, url: str, timeout: float) -> bytes:
        self.urls.append(url)
        self.timeouts.append(timeout)
        payload = self.routes.get(url)
        if payload is None:
            raise ip_lookup.FetchError("HTTP 404 Not Found")
        if isinstance(payload, BaseException):
            raise payload
        if isinstance(payload, str):
            return payload.encode("utf-8")
        return payload  # type: ignore[return-value]


class ForbiddenNetwork:
    """A fetcher that fails the test if anything asks it for anything (§3, §3.4)."""

    def __init__(self) -> None:
        self.urls: list[str] = []

    def __call__(self, url: str, timeout: float) -> bytes:
        self.urls.append(url)
        raise AssertionError(f"{url} was fetched, but nothing should have left the host")


def _serving(
    address: str,
    *,
    base: str | None = APNIC_BASE,
    rdap: object = None,
    cymru: object = None,
    bootstrap: object = FIXTURE_BOOTSTRAP,
) -> FakeNetwork:
    """A fixture network for one address: bootstrap, RDAP record and Cymru answer.

    ``rdap`` and ``cymru`` are the bodies to serve, an exception to raise, or ``None`` to
    leave that step unreachable - which is how a partial or a total failure is built.
    """
    ip = ipaddress.ip_address(address)
    routes: dict[str, object] = {}
    if bootstrap is not None:
        routes[ip_lookup.BOOTSTRAP_URLS[ip.version]] = (
            bootstrap if isinstance(bootstrap, (bytes, BaseException)) else _json_bytes(bootstrap)
        )
    if base is not None:
        url = ip_lookup.rdap_url(base, ip)
        if rdap is None:
            routes[url] = ip_lookup.FetchError("HTTP 500 Internal Server Error")
        elif isinstance(rdap, (bytes, BaseException)):
            routes[url] = rdap
        else:
            routes[url] = _json_bytes(rdap)
    if cymru is not None:
        # A string is the TXT answer itself, so it is wrapped the way the resolver returns it.
        if isinstance(cymru, (bytes, BaseException)):
            routes[ip_lookup.asn_url(ip)] = cymru
        else:
            routes[ip_lookup.asn_url(ip)] = _txt_bytes(str(cymru))
    return FakeNetwork(routes)


def _rows() -> int:
    """How many cache rows this installation holds."""
    row = db.query_one("SELECT COUNT(*) AS n FROM ip_lookups")
    return int(row["n"]) if row else 0


# --------------------------------------------------------------------------
# fixtures
# --------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def _fresh_bootstraps():
    """§2's bootstrap cache is process state, and every test wants its own fixture document."""
    ip_lookup.clear_cache()
    yield
    ip_lookup.clear_cache()


@pytest.fixture()
def scratch() -> Path:
    directory = SCRATCH_ROOT / uuid.uuid4().hex
    directory.mkdir(parents=True, exist_ok=True)
    yield directory
    shutil.rmtree(directory, ignore_errors=True)


@pytest.fixture()
def lookups(fresh_db):  # noqa: ARG001 - fresh_db prepares the schema and empties the tables
    """An empty ``ip_lookups`` before each test.

    The table is keyed by address alone, so ``fresh_db``'s per-analysis wipe does not reach
    it: a row left behind by an earlier test would be a cache hit in the next one.
    """
    with db.get_conn() as conn:
        conn.execute("DELETE FROM ip_lookups")
    ip_lookup.clear_cache()
    yield
    ip_lookup.clear_cache()


@pytest.fixture()
def make_analysis(fresh_db):  # noqa: ARG001 - fresh_db empties the tables first
    """A completed analysis row with a real (if tiny) capture on disk.

    The hosts routes gate on ``analysis_ready_row``, which insists the retained capture is
    still present, so the file is written rather than described.
    """

    def _make(
        rows: list[tuple[str, int]] = (),
        *,
        analysis_id: str = ANALYSIS_ID,
        status: str = "completed",
        capture: bool = True,
    ) -> str:
        now = time.time()
        path = settings.uploads_dir / f"{analysis_id}.pcap"
        path.parent.mkdir(parents=True, exist_ok=True)
        if capture:
            path.write_bytes(b"\xd4\xc3\xb2\xa1fixture-not-a-real-capture")
        with db.get_conn() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO analyses (
                    id, original_filename, stored_path, file_size, file_type, status,
                    progress, stage, packet_count, created_at, updated_at
                ) VALUES (?, 'fixture.pcap', ?, 0, 'pcap', ?, 100, ?, 0, ?, ?)
                """,
                (analysis_id, str(path), status, status, now, now),
            )
            for ip, packets in rows:
                conn.execute(
                    """
                    INSERT OR REPLACE INTO hosts (
                        analysis_id, ip, packets_sent, packets_received,
                        bytes_sent, bytes_received, is_private, ip_version, peer_count
                    ) VALUES (?, ?, ?, ?, ?, ?, 0, ?, 0)
                    """,
                    (analysis_id, ip, packets // 2, packets - packets // 2, 100, 100,
                     6 if ":" in ip else 4),
                )
        return analysis_id

    return _make


def _dns_row(analysis_id: str, name: str, answer_ips: str, *, client: str = "192.168.8.229") -> None:
    with db.get_conn() as conn:
        conn.execute(
            """
            INSERT INTO dns_queries (analysis_id, query_name, answer_ips, client_ip, is_response)
            VALUES (?, ?, ?, ?, 1)
            """,
            (analysis_id, name, answer_ips, client),
        )


def _tls_row(analysis_id: str, *, client: str, server: str, sni: str) -> None:
    with db.get_conn() as conn:
        conn.execute(
            """
            INSERT INTO tls_sessions (analysis_id, client_ip, server_ip, sni, version)
            VALUES (?, ?, ?, ?, 'TLSv1.3')
            """,
            (analysis_id, client, server, sni),
        )


def _cache_row(
    ip: str,
    *,
    age_days: float = 0.0,
    record: dict | None = None,
    source: str | None = ARIN_BASE,
) -> None:
    """A cached lookup as a previous POST would have left it."""
    with db.get_conn() as conn:
        conn.execute(
            """
            INSERT OR REPLACE INTO ip_lookups (ip, kind, source, asn, country, fetched_at, payload)
            VALUES (?, 'public', ?, '15169', 'US', ?, ?)
            """,
            (ip, source, time.time() - age_days * 86400.0, json.dumps(record or ARIN_RECORD)),
        )


def _install_dataset(home: Path, text: str, *, month: str = "2026-10") -> Path:
    """Install a tiny DB-IP dataset and its provenance, as ``geoip.refresh`` would."""
    home.mkdir(parents=True, exist_ok=True)
    buffer = io.BytesIO()
    with gzip.GzipFile(fileobj=buffer, mode="wb", mtime=0) as handle:
        handle.write(text.encode("utf-8"))
    raw = buffer.getvalue()
    dataset = geoip.parse_gzip(raw, source="fixture")
    path = home / geoip.filename_for(month)
    path.write_bytes(raw)
    (home / geoip.SOURCE_NAME).write_text(
        json.dumps(
            {
                "dataset": geoip.DATASET,
                "file": path.name,
                "dataset_month": month,
                "ranges": dataset.ranges,
                "countries": dataset.codes,
                "fetched_at": time.time(),
            }
        ),
        encoding="utf-8",
    )
    geoip.clear_cache()
    return path


@pytest.fixture()
def geoip_home(scratch: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Point the geography service at a throwaway ``data/geoip``, as its own tests do."""
    home = scratch / "geoip"
    monkeypatch.setattr(geoip, "geoip_dir", lambda: home)
    geoip.clear_cache()
    yield home
    geoip.clear_cache()


# --------------------------------------------------------------------------
# 1. the bootstrap and the longest matching prefix (§2)
# --------------------------------------------------------------------------

def test_bootstrap_parses_every_service_and_prefers_https():
    parsed = ip_lookup.parse_bootstrap(_json_bytes(FIXTURE_BOOTSTRAP), source="fixture")

    assert len(parsed) == 7                        # six IPv4 entries and the IPv6 one
    assert parsed.source == "fixture"
    # The http alternative ARIN publishes is not what an address leaves the host through.
    assert parsed.base_url_for(ipaddress.ip_address(ARIN_IP)) == ARIN_BASE
    assert not any(url.startswith("http://") for _network, url in parsed.entries)


def test_bootstrap_uses_the_longest_matching_prefix():
    """An address inside both a ``/8`` and a narrower entry is served by the narrower one."""
    parsed = ip_lookup.parse_bootstrap(_json_bytes(FIXTURE_BOOTSTRAP), source="fixture")

    assert parsed.base_url_for(ipaddress.ip_address(WIDE_IP)) == NARROW_BASE
    # ... and the /8 still answers for its own space outside the /16.
    assert parsed.base_url_for(ipaddress.ip_address("45.10.0.1")) == WIDE_BASE
    # The measured addresses are served by their single /8.
    assert parsed.base_url_for(ipaddress.ip_address(RIPE_IP)) == RIPE_BASE
    assert parsed.base_url_for(ipaddress.ip_address(APNIC_IP)) == APNIC_BASE
    # An address no entry covers is not guessed into a neighbour.
    assert parsed.base_url_for(ipaddress.ip_address("9.9.9.9")) is None


def test_lookup_asks_the_narrower_registry_and_not_the_wider_one():
    """The address reaches one registry, and it is the one holding the narrower prefix."""
    network = _serving(WIDE_IP, base=NARROW_BASE, rdap={**RIPE_RECORD, "name": "LINODE"}, cymru="63949 | 45.33.0.0/16 | US | arin | 2015-04-01")

    result = ip_lookup.lookup(WIDE_IP, fetcher=network)

    assert network.urls == [
        ip_lookup.BOOTSTRAP_URLS[4],
        ip_lookup.rdap_url(NARROW_BASE, ipaddress.ip_address(WIDE_IP)),
        ip_lookup.asn_url(ipaddress.ip_address(WIDE_IP)),
    ]
    assert WIDE_BASE not in network.urls          # the /8 that lost is never even asked
    assert result.record["rdap_url"] == f"{NARROW_BASE}ip/{WIDE_IP}"
    # A host outside the five RIRs is reported as itself rather than guessed at.
    assert result.record["registry"] == "rdap.narrow.example"


def test_the_bootstrap_is_fetched_once_per_process():
    network = _serving(APNIC_IP, rdap=APNIC_RECORD, cymru=CYMRU_APNIC)

    ip_lookup.lookup(APNIC_IP, fetcher=network)
    ip_lookup.lookup(APNIC_IP, fetcher=network)

    assert network.urls.count(ip_lookup.BOOTSTRAP_URLS[4]) == 1
    assert len(network.urls) == 5                 # once, then both steps for each lookup


@pytest.mark.parametrize(
    "body, fragment",
    [
        (b"not json at all", "is not JSON"),
        (b"[]", "not a JSON object"),
        (b'{"services": []}', "no usable RDAP service entry"),
        (b'{"services": [["not a list", ["https://x/"]]]}', "no usable RDAP service entry"),
    ],
)
def test_a_bootstrap_that_cannot_be_used_is_a_failure(body, fragment):
    with pytest.raises(ip_lookup.FetchError) as excinfo:
        ip_lookup.parse_bootstrap(body, source="fixture")

    assert fragment in str(excinfo.value)


# --------------------------------------------------------------------------
# 2. normalising the two registry shapes (§5.1)
# --------------------------------------------------------------------------

def test_ripe_record_normalises_with_contacts_and_a_country():
    result = ip_lookup.lookup(
        RIPE_IP, fetcher=_serving(RIPE_IP, base=RIPE_BASE, rdap=RIPE_RECORD, cymru=CYMRU_RIPE)
    )

    assert set(result.record) == {
        "registry", "network_name", "handle", "range", "allocation_type", "status", "country",
        "port43", "rdap_url", "asn", "contacts", "remarks", "failures",
    }
    record = result.record
    assert record["registry"] == "RIPE NCC"
    assert record["network_name"] == "cloud"
    assert record["handle"] == "51.132.128.0 - 51.132.255.255"
    assert record["range"] == {"start": "51.132.128.0", "end": "51.132.255.255"}
    assert record["allocation_type"] == "LEGACY"
    assert record["status"] == ["active"]
    assert record["country"] == "GB"
    assert record["port43"] == "whois.ripe.net"
    assert record["rdap_url"] == f"{RIPE_BASE}ip/{RIPE_IP}"
    assert record["asn"] == {
        "number": "8075", "prefix": "51.132.0.0/16", "country": "GB",
        "registry": "ripencc", "allocated": "1993-09-01",
    }
    assert record["remarks"] == ["Registration Comments: Allocated to Microsoft."]
    assert record["failures"] == []

    # §6: registrant and abuse first, then technical and administrative - whatever order the
    # record itself lists them in.
    assert [contact["role"] for contact in record["contacts"]] == [
        "registrant", "abuse", "technical", "administrative",
    ]
    assert record["contacts"][0] == {
        "role": "registrant", "handle": "MICROSOFT-MAINT", "name": "MICROSOFT-MAINT", "emails": [],
    }
    assert record["contacts"][1]["emails"] == ["abuse@microsoft.com"]
    assert record["contacts"][1]["name"] == "Microsoft Abuse Contact"


def test_arin_record_normalises_with_no_country_and_a_registrant_only():
    """§7's stated limit: ARIN's network objects carry no country, and often no mailbox.

    The abuse entity ARIN nests inside its registrant is deliberately not walked (see the
    module docstring), so these contacts are the registrant alone - and the country falls
    back to Cymru, which is the normal path for ARIN space rather than an exception.
    """
    result = ip_lookup.lookup(ARIN_IP, fetcher=_serving(ARIN_IP, base=ARIN_BASE, rdap=ARIN_RECORD, cymru=CYMRU_GOOGLE))

    record = result.record
    assert record["registry"] == "ARIN"
    assert record["network_name"] == "GOGL"
    assert record["handle"] == "NET-8-8-8-0-2"
    assert record["range"] == {"start": "8.8.8.0", "end": "8.8.8.255"}
    assert record["port43"] == "whois.arin.net"
    assert record["country"] == "US"                    # Cymru's, because RDAP publishes none
    assert "country" not in ARIN_RECORD                 # the fixture really has none
    assert record["contacts"] == [
        {"role": "registrant", "handle": "GOGL", "name": "Google LLC", "emails": []},
    ]
    assert "abuse@example.com" not in json.dumps(record["contacts"])   # the nested entity
    assert record["asn"]["number"] == "15169"
    assert record["asn"]["country"] == "US"
    assert record["failures"] == []


def test_a_record_with_no_country_and_no_contacts_at_all():
    """§5.1: a field a registry does not publish is null, and an empty list stays empty.

    Neither this network object nor Cymru names a country of its own - so the record's is
    Cymru's, which is the normal path for ARIN space - and the object publishes no entity at
    all, which is not the same as publishing nobody.
    """
    bare = {**ARIN_RECORD, "entities": []}
    assert "country" not in bare                       # the fixture really has none

    result = ip_lookup.lookup("1.1.1.1", fetcher=_serving(
        "1.1.1.1", base=APNIC_BASE, rdap=bare, cymru=CYMRU_CLOUDFLARE,
    ))

    assert result.record["contacts"] == []
    assert result.record["country"] == "AU"             # Cymru's answer is the only one
    assert result.record["asn"] == {
        "number": "13335", "prefix": "1.1.1.0/24", "country": "AU",
        "registry": "apnic", "allocated": "2011-08-11",
    }
    assert result.record["failures"] == []


def test_a_document_with_nothing_in_it_normalises_to_nulls_and_empties():
    result = ip_lookup.lookup(ARIN_IP, fetcher=_serving(ARIN_IP, base=ARIN_BASE, rdap={}))

    record = result.record
    assert record["registry"] == "ARIN"                 # from the base URL, not the body
    assert record["rdap_url"] == f"{ARIN_BASE}ip/{ARIN_IP}"
    assert record["network_name"] is None
    assert record["handle"] is None
    assert record["range"] is None
    assert record["allocation_type"] is None
    assert record["status"] == []
    assert record["country"] is None                    # neither source named one
    assert record["port43"] is None
    assert record["asn"] is None
    assert record["contacts"] == []
    assert record["remarks"] == []
    assert len(record["failures"]) == 1                 # Cymru was never reachable here


def test_rdap_country_wins_over_cymru_and_the_two_are_not_reconciled():
    # Registration is not location, and the two sources can disagree (§7): RDAP's country is
    # the record's, while Cymru's stays on the AS where it belongs.
    result = ip_lookup.lookup(
        RIPE_IP, fetcher=_serving(RIPE_IP, base=RIPE_BASE, rdap=RIPE_RECORD, cymru=CYMRU_GOOGLE)
    )

    assert result.record["country"] == "GB"
    assert result.record["asn"]["country"] == "US"
    assert result.country == "GB"


def test_an_rdap_body_that_is_an_error_document_is_a_failure():
    document = {"errorCode": 404, "title": "Not Found", "rdapConformance": ["rdap_level_0"]}

    result = ip_lookup.lookup(
        ARIN_IP, fetcher=_serving(ARIN_IP, base=ARIN_BASE, rdap=document, cymru=CYMRU_GOOGLE)
    )

    assert result.record["network_name"] is None
    assert result.record["asn"]["number"] == "15169"          # the other step still answered
    assert any("HTTP 404" in failure for failure in result.failures)


# --------------------------------------------------------------------------
# 3. Team Cymru over DNS-over-HTTPS (§2)
# --------------------------------------------------------------------------

def test_origin_name_reverses_the_address():
    assert ip_lookup.origin_name(ipaddress.ip_address(APNIC_IP)) == "217.109.171.150.origin.asn.cymru.com"
    assert ip_lookup.origin_name(ipaddress.ip_address(ARIN_IP)) == "8.8.8.8.origin.asn.cymru.com"
    # IPv6 is nibble-reversed, and Cymru's IPv6 zone is origin6.
    assert ip_lookup.origin_name(ipaddress.ip_address("2001:4860:4860::8888")).endswith(
        ".origin6.asn.cymru.com"
    )
    assert ip_lookup.asn_url(ipaddress.ip_address(ARIN_IP)) == (
        "https://dns.google/resolve?name=8.8.8.8.origin.asn.cymru.com&type=TXT"
    )


@pytest.mark.parametrize(
    "text, expected",
    [
        (CYMRU_GOOGLE, {"number": "15169", "prefix": "8.8.8.0/24", "country": "US",
                        "registry": "arin", "allocated": "2023-12-28"}),
        (CYMRU_APNIC, {"number": "8075", "prefix": "150.171.0.0/16", "country": "US",
                       "registry": "arin", "allocated": "2015-11-24"}),
        (CYMRU_RIPE, {"number": "8075", "prefix": "51.132.0.0/16", "country": "GB",
                      "registry": "ripencc", "allocated": "1993-09-01"}),
    ],
)
def test_the_measured_cymru_answers_parse(text, expected):
    assert ip_lookup.parse_cymru(text) == expected


def test_cymru_answers_that_name_no_as_are_none():
    # "NA" in the AS field is Cymru saying the answer carries no data at all: that is not a
    # country, a registry or a date, and none of them is invented here.
    for text in ("NA | NA | NA | NA | NA", "", "   ", "not an answer at all", None, 12345):
        assert ip_lookup.parse_cymru(text) is None

    # The port-43 form of the same record is accepted, and a partially filled answer keeps
    # only what it actually carries.
    assert ip_lookup.parse_cymru("AS15169 | 8.8.8.0/24 | US | arin | 2023-12-28")["number"] == "15169"
    partial = ip_lookup.parse_cymru("15169 | NA | NA | arin")
    assert partial == {"number": "15169", "prefix": None, "country": None,
                       "registry": "arin", "allocated": None}


def test_a_resolver_with_no_txt_answer_is_a_named_failure():
    network = FakeNetwork({
        ip_lookup.BOOTSTRAP_URLS[4]: _json_bytes(FIXTURE_BOOTSTRAP),
        ip_lookup.rdap_url(ARIN_BASE, ipaddress.ip_address(ARIN_IP)): _json_bytes(ARIN_RECORD),
        ip_lookup.asn_url(ipaddress.ip_address(ARIN_IP)): _json_bytes({"Status": 3, "Answer": []}),
    })

    result = ip_lookup.lookup(ARIN_IP, fetcher=network)

    assert result.record["asn"] is None
    assert result.asn is None
    assert any("Team Cymru" in failure for failure in result.failures)


# --------------------------------------------------------------------------
# 4. the egress policy: the address's own class decides (§3.4)
# --------------------------------------------------------------------------

@pytest.mark.parametrize(
    "value, kind",
    [
        ("192.168.8.229", ip_lookup.KIND_PRIVATE),
        ("10.0.0.1", ip_lookup.KIND_PRIVATE),
        ("172.16.0.1", ip_lookup.KIND_PRIVATE),
        ("fd00::1", ip_lookup.KIND_PRIVATE),
        ("127.0.0.1", ip_lookup.KIND_LOOPBACK),
        ("::1", ip_lookup.KIND_LOOPBACK),
        ("169.254.1.1", ip_lookup.KIND_LINK_LOCAL),
        ("fe80::1", ip_lookup.KIND_LINK_LOCAL),
        ("224.0.0.251", ip_lookup.KIND_MULTICAST),
        ("ff02::1", ip_lookup.KIND_MULTICAST),
        ("240.0.0.1", ip_lookup.KIND_RESERVED),
        ("0.0.0.0", ip_lookup.KIND_RESERVED),
        ("255.255.255.255", ip_lookup.KIND_RESERVED),
        ("192.0.2.1", ip_lookup.KIND_RESERVED),
        ("198.51.100.7", ip_lookup.KIND_RESERVED),
        ("2001:db8::1", ip_lookup.KIND_RESERVED),
        ("100.64.0.1", ip_lookup.KIND_RESERVED),      # RFC 6598 shared space: not routable
        (APNIC_IP, ip_lookup.KIND_PUBLIC),
        (ARIN_IP, ip_lookup.KIND_PUBLIC),
        ("::ffff:8.8.8.8", ip_lookup.KIND_PUBLIC),    # an IPv4-mapped address is its IPv4 self
        ("::ffff:192.168.1.1", ip_lookup.KIND_PRIVATE),
    ],
)
def test_every_class_is_decided_from_the_address_itself(value, kind):
    assert ip_lookup.classify(value) == kind
    if kind == ip_lookup.KIND_PUBLIC:
        assert ip_lookup.reason_for(value) is None
    else:
        assert ip_lookup.reason_for(value), f"{value} must say why it cannot be looked up"
        assert "not sent anywhere" in ip_lookup.reason_for(value)


def test_an_ipv4_mapped_address_is_keyed_as_its_ipv4_self():
    assert ip_lookup.canonical("::ffff:8.8.8.8") == "8.8.8.8"
    assert ip_lookup.canonical("2001:4860:4860::8888") == "2001:4860:4860::8888"


@pytest.mark.parametrize("value", [None, "", "   ", "not-an-ip", "1.2.3", "1.2.3.4.5", "300.1.1.1", 12345])
def test_an_unparsable_address_has_no_class(value):
    assert ip_lookup.parse_address(value) is None
    assert ip_lookup.classify(value) is None
    assert ip_lookup.canonical(value) is None
    assert "not an IP address" in ip_lookup.reason_for(value)


@pytest.mark.parametrize(
    "value",
    ["192.168.8.229", "10.0.0.1", "172.16.0.1", "127.0.0.1", "::1", "169.254.1.1", "fe80::1",
     "224.0.0.251", "ff02::1", "240.0.0.1", "0.0.0.0", "255.255.255.255", "192.0.2.1",
     "100.64.0.1", "2001:db8::1", "fd00::1"],
)
def test_a_non_public_address_is_answered_without_a_single_request(value):
    forbidden = ForbiddenNetwork()

    result = ip_lookup.lookup(value, fetcher=forbidden)

    assert forbidden.urls == []
    assert result.lookup_possible is False
    assert result.queried is False
    assert result.record is None
    assert result.reason


def test_192_168_0_0_16_is_stated_rather_than_failed():
    """§3.4's named special case, answered from the address and sent nowhere.

    ARIN really does hold an IANA reservation for the block whose own remark says millions of
    independent networks use it, so the panel states that instead of showing a lookup that
    "failed" - and the address still does not leave the host.
    """
    forbidden = ForbiddenNetwork()
    address = "192.168.0.42"

    result = ip_lookup.lookup(address, fetcher=forbidden)

    assert forbidden.urls == []
    assert result.kind == ip_lookup.KIND_PRIVATE
    assert result.lookup_possible is False
    assert "192.168.0.0/16" in result.reason
    assert "millions of independent networks" in result.reason
    assert "not sent anywhere" in result.reason

    # ... and it is not cached either: nothing was fetched, so there is nothing to keep.
    assert ip_lookup.refresh(address, fetcher=forbidden).record is None
    assert _rows() == 0


def test_a_private_address_never_reaches_the_live_fetcher(client, lookups, make_analysis, monkeypatch):
    """The API path for a private address: 200, ``lookup_possible: false``, no request."""
    make_analysis([("192.168.8.229", 10)])
    forbidden = ForbiddenNetwork()
    monkeypatch.setattr(ip_lookup, "_fetch", forbidden)

    response = client.post(f"/api/analyses/{ANALYSIS_ID}/hosts/192.168.8.229/lookup")

    assert response.status_code == 200, response.text
    body = response.json()
    assert forbidden.urls == []
    assert body["kind"] == "private"
    assert body["lookup_possible"] is False
    assert body["reason"]
    assert body["record"] is None
    assert body["cache"] is None
    assert _rows() == 0


# --------------------------------------------------------------------------
# 5. partial and total failure (§5.2)
# --------------------------------------------------------------------------

def test_rdap_failing_while_cymru_answers_keeps_the_as_and_names_the_failure():
    network = _serving(
        ARIN_IP, base=ARIN_BASE, rdap=ip_lookup.FetchError("HTTP 404 Not Found"), cymru=CYMRU_GOOGLE
    )

    result = ip_lookup.lookup(ARIN_IP, fetcher=network)

    assert result.record["asn"] == {
        "number": "15169", "prefix": "8.8.8.0/24", "country": "US",
        "registry": "arin", "allocated": "2023-12-28",
    }
    assert result.record["country"] == "US"                  # Cymru's, the only one there is
    assert result.record["handle"] is None
    assert result.record["range"] is None
    assert result.record["contacts"] == []
    assert len(result.failures) == 1
    assert "RDAP" in result.failures[0] and "404" in result.failures[0]
    assert result.record["failures"] == list(result.failures)
    # The base URL is known from the bootstrap, so the record still says where it would live.
    assert result.record["registry"] == "ARIN"
    assert result.record["rdap_url"] == f"{ARIN_BASE}ip/{ARIN_IP}"


def test_cymru_failing_while_rdap_answers_keeps_the_record_and_names_the_failure():
    network = _serving(ARIN_IP, base=ARIN_BASE, rdap=ARIN_RECORD, cymru=ip_lookup.FetchError("could not be reached"))

    result = ip_lookup.lookup(ARIN_IP, fetcher=network)

    assert result.record["handle"] == "NET-8-8-8-0-2"
    assert result.record["asn"] is None
    assert result.asn is None
    assert result.record["country"] is None        # neither source named one; none was guessed
    assert len(result.failures) == 1
    assert "Team Cymru" in result.failures[0]


def test_a_bootstrap_that_cannot_be_read_leaves_the_as_answer_intact():
    network = _serving(
        ARIN_IP,
        bootstrap=ip_lookup.FetchError("could not be reached (getaddrinfo failed)"),
        cymru=CYMRU_GOOGLE,
    )

    result = ip_lookup.lookup(ARIN_IP, fetcher=network)

    assert result.record["asn"]["number"] == "15169"
    assert result.record["registry"] is None
    assert result.record["rdap_url"] is None
    assert "IANA RDAP bootstrap" in result.failures[0]
    assert network.urls == [
        ip_lookup.BOOTSTRAP_URLS[4],
        ip_lookup.asn_url(ipaddress.ip_address(ARIN_IP)),
    ]


def test_total_failure_raises_lookup_failed_with_every_reason():
    network = FakeNetwork({ip_lookup.BOOTSTRAP_URLS[4]: _json_bytes(FIXTURE_BOOTSTRAP)})

    with pytest.raises(ip_lookup.LookupFailed) as excinfo:
        ip_lookup.lookup(APNIC_IP, fetcher=network)

    assert len(excinfo.value.failures) == 2
    assert "RDAP" in excinfo.value.failures[0]
    assert "Team Cymru" in excinfo.value.failures[1]
    assert "Nothing could be retrieved for 150.171.109.217" in str(excinfo.value)


def test_no_service_answering_leaves_no_base_url_and_still_fails_cleanly():
    network = _serving(
        APNIC_IP,
        bootstrap={"services": [[["10.0.0.0/8"], ["https://rdap.example.test/"]]]},
        cymru=None,
    )

    with pytest.raises(ip_lookup.LookupFailed) as excinfo:
        ip_lookup.lookup(APNIC_IP, fetcher=network)

    assert any("no base URL is published" in failure for failure in excinfo.value.failures)
    assert any("Team Cymru" in failure for failure in excinfo.value.failures)


def test_the_lookup_budget_is_shared_across_its_steps(monkeypatch):
    """§5.2: one :data:`LOOKUP_TIMEOUT_S` for the whole lookup, not one budget per step."""
    monkeypatch.setattr(ip_lookup, "LOOKUP_TIMEOUT_S", 0.05)
    asked: list[float] = []

    def _slow(url: str, timeout: float) -> bytes:
        asked.append(timeout)
        if url == ip_lookup.BOOTSTRAP_URLS[4]:
            time.sleep(0.12)                     # spends the whole budget on step one
            return _json_bytes(FIXTURE_BOOTSTRAP)
        raise AssertionError("no request may be made once the budget is spent")

    with pytest.raises(ip_lookup.LookupFailed) as excinfo:
        ip_lookup.lookup(APNIC_IP, fetcher=_slow)

    assert len(asked) == 1                       # the first step got what was left of it
    assert asked[0] == pytest.approx(0.05, abs=0.005)
    assert len(excinfo.value.failures) == 2
    assert all("budget was already spent" in failure for failure in excinfo.value.failures)


# --------------------------------------------------------------------------
# 6. caps (§6)
# --------------------------------------------------------------------------

def test_contacts_are_capped_with_registrant_and_abuse_first():
    entities = [
        {"handle": f"NOC{index}-RIPE", "roles": ["noc"],
         "vcardArray": ["vcard", [["fn", {}, "text", f"NOC {index}"]]]}
        for index in range(12)
    ]
    entities += [
        {"handle": "ADMIN-RIPE", "roles": ["administrative"],
         "vcardArray": ["vcard", [["fn", {}, "text", "Admin"]]]},
        {"handle": "TECH-RIPE", "roles": ["technical"],
         "vcardArray": ["vcard", [["fn", {}, "text", "Tech"]]]},
        {"handle": "ABUSE-RIPE", "roles": ["abuse"],
         "vcardArray": ["vcard", [["email", {"type": "abuse"}, "text", "abuse@example.net"]]]},
        {"handle": "REG-RIPE", "roles": ["registrant"],
         "vcardArray": ["vcard", [["fn", {}, "text", "Holder"]]]},
    ]

    record = ip_lookup.lookup(RIPE_IP, fetcher=_serving(
        RIPE_IP, base=RIPE_BASE, rdap={**RIPE_RECORD, "entities": entities}, cymru=CYMRU_RIPE,
    )).record

    assert len(record["contacts"]) == ip_lookup.CONTACT_CAP == 10
    assert [contact["role"] for contact in record["contacts"]][:4] == [
        "registrant", "abuse", "technical", "administrative",
    ]
    assert all(contact["handle"].startswith("NOC") for contact in record["contacts"][4:])
    assert record["contacts"][1]["emails"] == ["abuse@example.net"]


def test_an_entity_without_a_role_keeps_none_and_sorts_last():
    entities = [
        {"handle": "NOBODY", "vcardArray": ["vcard", [["fn", {}, "text", "Unlabelled"]]]},
        {"handle": "ABUSE-RIPE", "roles": ["abuse"], "vcardArray": ["vcard", [["fn", {}, "text", "Abuse"]]]},
    ]

    record = ip_lookup.lookup(RIPE_IP, fetcher=_serving(
        RIPE_IP, base=RIPE_BASE, rdap={**RIPE_RECORD, "entities": entities}, cymru=CYMRU_RIPE,
    )).record

    assert [contact["role"] for contact in record["contacts"]] == ["abuse", None]
    assert record["contacts"][1]["name"] == "Unlabelled"


def test_a_handle_alone_is_still_a_contact_and_a_bare_role_is_not():
    # RIPE really does publish entities whose name is redacted; the handle is what is left,
    # and dropping it would say the registry published nobody.
    entities = [
        {"handle": "REDACTED-RIPE", "roles": ["registrant"]},
        {"roles": ["technical"]},                     # no handle, no name, no mailbox
    ]

    record = ip_lookup.lookup(RIPE_IP, fetcher=_serving(
        RIPE_IP, base=RIPE_BASE, rdap={**RIPE_RECORD, "entities": entities}, cymru=CYMRU_RIPE,
    )).record

    assert record["contacts"] == [
        {"role": "registrant", "handle": "REDACTED-RIPE", "name": None, "emails": []},
    ]


def test_remarks_are_capped_and_each_is_truncated():
    document = {
        **RIPE_RECORD,
        "remarks": [
            {"title": f"Remark {index}", "description": ["x" * 900 if index == 0 else f"Short {index}."]}
            for index in range(9)
        ],
    }

    record = ip_lookup.lookup(RIPE_IP, fetcher=_serving(
        RIPE_IP, base=RIPE_BASE, rdap=document, cymru=CYMRU_RIPE,
    )).record

    assert len(record["remarks"]) == ip_lookup.REMARK_CAP == 5
    assert all(len(remark) <= ip_lookup.REMARK_CHARS == 400 for remark in record["remarks"])
    assert record["remarks"][0].startswith("Remark 0: ")
    assert len(record["remarks"][0]) == 400
    assert record["remarks"][1] == "Remark 1: Short 1."


def test_a_remark_without_a_description_is_not_a_remark():
    document = {**RIPE_RECORD, "remarks": [{"title": "Empty"}, {"description": ["Real."]}]}

    record = ip_lookup.lookup(RIPE_IP, fetcher=_serving(
        RIPE_IP, base=RIPE_BASE, rdap=document, cymru=CYMRU_RIPE,
    )).record

    assert record["remarks"] == ["Real."]


# --------------------------------------------------------------------------
# 7. the API: GET never fetches (§5.1)
# --------------------------------------------------------------------------

def test_get_before_any_lookup_returns_the_capture_block_and_no_record(client, lookups, make_analysis, monkeypatch):
    make_analysis([(APNIC_IP, 200)])
    _dns_row(ANALYSIS_ID, "download.sysinternals.com", APNIC_IP)
    _tls_row(ANALYSIS_ID, client="192.168.8.229", server=APNIC_IP, sni="ctldl.windowsupdate.com")
    forbidden = ForbiddenNetwork()
    monkeypatch.setattr(ip_lookup, "_fetch", forbidden)

    response = client.get(f"/api/analyses/{ANALYSIS_ID}/hosts/{APNIC_IP}/lookup")

    assert response.status_code == 200, response.text
    body = response.json()
    assert forbidden.urls == [], "the panel's first paint must not fetch anything"
    assert set(body) == {"ip", "kind", "lookup_possible", "reason", "cache", "record", "local", "note"}
    assert body["ip"] == APNIC_IP
    assert body["kind"] == "public"
    assert body["lookup_possible"] is True
    assert body["reason"] is None
    assert body["cache"] is None
    assert body["record"] is None
    assert body["note"]
    assert set(body["local"]) == {"country", "country_source", "names", "names_truncated"}
    assert body["local"]["country"] is None            # no dataset installed in this fixture
    assert body["local"]["country_source"] is None
    # Both were seen once, so the tie is broken by name: the order is deterministic, and it
    # is the number of rows that decides, never the table the name came from.
    assert body["local"]["names"] == [
        {"name": "ctldl.windowsupdate.com", "from": "tls_sni", "rows": 1},
        {"name": "download.sysinternals.com", "from": "dns_answer", "rows": 1},
    ]
    assert body["local"]["names_truncated"] is False


def test_get_serves_a_cached_record_without_asking_again(client, lookups, make_analysis, monkeypatch):
    make_analysis([(ARIN_IP, 10)])
    _cache_row(ARIN_IP, age_days=2.4, source=ARIN_BASE)
    forbidden = ForbiddenNetwork()
    monkeypatch.setattr(ip_lookup, "_fetch", forbidden)

    body = client.get(f"/api/analyses/{ANALYSIS_ID}/hosts/{ARIN_IP}/lookup").json()

    assert forbidden.urls == []
    assert body["record"]["handle"] == "NET-8-8-8-0-2"
    assert body["cache"]["source"] == ARIN_BASE
    assert body["cache"]["stale"] is False
    assert body["cache"]["age_days"] == pytest.approx(2.4, abs=0.01)
    assert body["cache"]["fetched_at"] < time.time()


def test_a_cached_record_past_the_max_age_is_stale_and_still_shown(client, lookups, make_analysis):
    make_analysis([(ARIN_IP, 10)])
    _cache_row(ARIN_IP, age_days=ip_lookup.LOOKUP_MAX_AGE_DAYS + 1)

    body = client.get(f"/api/analyses/{ANALYSIS_ID}/hosts/{ARIN_IP}/lookup").json()

    assert body["cache"]["stale"] is True
    assert body["cache"]["age_days"] == pytest.approx(ip_lookup.LOOKUP_MAX_AGE_DAYS + 1, abs=0.01)
    assert body["record"] is not None, "a stale record is reported, never hidden"


def test_a_cached_row_whose_payload_is_unreadable_is_not_a_record(client, lookups, make_analysis):
    make_analysis([(ARIN_IP, 10)])
    with db.get_conn() as conn:
        conn.execute(
            "INSERT INTO ip_lookups (ip, kind, source, asn, country, fetched_at, payload) VALUES (?,?,?,?,?,?,?)",
            (ARIN_IP, "public", ARIN_BASE, "15169", "US", time.time(), "{not json"),
        )

    body = client.get(f"/api/analyses/{ANALYSIS_ID}/hosts/{ARIN_IP}/lookup").json()

    assert body["record"] is None
    assert body["cache"] is not None            # the fetch still happened, and is still dated


def test_a_non_public_address_never_shows_a_record_even_from_a_cached_row(client, lookups, make_analysis):
    """§5.1: ``record`` is null when ``kind`` is not public, whatever a row happens to say."""
    make_analysis([("192.168.8.229", 10)])
    _cache_row("192.168.8.229")

    body = client.get(f"/api/analyses/{ANALYSIS_ID}/hosts/192.168.8.229/lookup").json()

    assert body["kind"] == "private"
    assert body["lookup_possible"] is False
    assert body["record"] is None


# --------------------------------------------------------------------------
# 8. the API: POST looks up, caches and reports (§5.2)
# --------------------------------------------------------------------------

def test_post_looks_up_caches_and_the_next_get_serves_it(client, lookups, make_analysis, monkeypatch):
    make_analysis([(APNIC_IP, 200)])
    _dns_row(ANALYSIS_ID, "download.sysinternals.com", f"{APNIC_IP},150.171.109.218")
    _dns_row(ANALYSIS_ID, "download.sysinternals.com", APNIC_IP)
    _tls_row(ANALYSIS_ID, client="192.168.8.229", server=APNIC_IP, sni="download.sysinternals.com")
    network = _serving(APNIC_IP, rdap=APNIC_RECORD, cymru=CYMRU_APNIC)
    monkeypatch.setattr(ip_lookup, "_fetch", network)

    response = client.post(f"/api/analyses/{ANALYSIS_ID}/hosts/{APNIC_IP}/lookup")

    assert response.status_code == 200, response.text
    body = response.json()
    assert network.urls == [
        ip_lookup.BOOTSTRAP_URLS[4],
        ip_lookup.rdap_url(APNIC_BASE, ipaddress.ip_address(APNIC_IP)),
        ip_lookup.asn_url(ipaddress.ip_address(APNIC_IP)),
    ]
    assert body["record"]["registry"] == "APNIC"
    assert body["record"]["network_name"] == "MSFT"
    assert body["record"]["handle"] == "NET-150-171-0-0-1"
    assert body["record"]["range"] == {"start": "150.171.0.0", "end": "150.171.255.255"}
    assert body["record"]["allocation_type"] == "DIRECT ALLOCATION"
    assert body["record"]["country"] == "US"           # Cymru's: ARIN publishes none
    assert body["record"]["port43"] == "whois.arin.net"
    assert body["record"]["rdap_url"] == f"{APNIC_BASE}ip/{APNIC_IP}"
    assert body["record"]["asn"]["number"] == "8075"
    assert body["record"]["contacts"] == [
        {"role": "registrant", "handle": "MSFT", "name": "Microsoft Corporation", "emails": []},
    ]
    assert body["record"]["failures"] == []
    assert body["cache"]["source"] == APNIC_BASE
    assert body["cache"]["stale"] is False
    assert 0.0 <= body["cache"]["age_days"] < 1.0
    assert _rows() == 1

    # The capture's own names travel with both states, and the second paint asks nothing.
    assert body["local"]["names"] == [
        {"name": "download.sysinternals.com", "from": "dns_answer", "rows": 2},
        {"name": "download.sysinternals.com", "from": "tls_sni", "rows": 1},
    ]
    network.urls.clear()
    painted = client.get(f"/api/analyses/{ANALYSIS_ID}/hosts/{APNIC_IP}/lookup").json()
    assert network.urls == []
    assert painted["record"] == body["record"]
    assert painted["cache"]["fetched_at"] == body["cache"]["fetched_at"]
    assert painted["local"] == body["local"]


def test_post_replaces_an_earlier_row_for_the_same_address(client, lookups, make_analysis, monkeypatch):
    make_analysis([(ARIN_IP, 10)])
    _cache_row(ARIN_IP, age_days=90, source=RIPE_BASE)
    monkeypatch.setattr(
        ip_lookup, "_fetch", _serving(ARIN_IP, base=ARIN_BASE, rdap=ARIN_RECORD, cymru=CYMRU_GOOGLE)
    )

    body = client.post(f"/api/analyses/{ANALYSIS_ID}/hosts/{ARIN_IP}/lookup").json()

    assert _rows() == 1                              # one address, one record, whoever fetched it
    assert body["cache"]["source"] == ARIN_BASE
    assert body["cache"]["stale"] is False
    assert body["record"]["network_name"] == "GOGL"


def test_a_partial_answer_is_reported_with_its_failures_and_still_cached(client, lookups, make_analysis, monkeypatch):
    make_analysis([(ARIN_IP, 10)])
    monkeypatch.setattr(ip_lookup, "_fetch", _serving(
        ARIN_IP, base=ARIN_BASE, rdap=ip_lookup.FetchError("HTTP 500 Internal Server Error"),
        cymru=CYMRU_GOOGLE,
    ))

    response = client.post(f"/api/analyses/{ANALYSIS_ID}/hosts/{ARIN_IP}/lookup")

    assert response.status_code == 200, response.text
    body = response.json()
    assert body["record"]["asn"]["number"] == "15169"
    assert body["record"]["handle"] is None
    assert len(body["record"]["failures"]) == 1
    assert _rows() == 1, "a partial answer is what came back, and it is kept"


def test_two_captures_share_one_record_for_the_same_peer(client, lookups, make_analysis, monkeypatch):
    """§4: the cache is keyed by address, so a second capture costs nothing."""
    make_analysis([(ARIN_IP, 10)])
    make_analysis([(ARIN_IP, 20)], analysis_id=OTHER_ID)
    network = _serving(ARIN_IP, base=ARIN_BASE, rdap=ARIN_RECORD, cymru=CYMRU_GOOGLE)
    monkeypatch.setattr(ip_lookup, "_fetch", network)

    first = client.post(f"/api/analyses/{ANALYSIS_ID}/hosts/{ARIN_IP}/lookup").json()
    network.urls.clear()
    second = client.get(f"/api/analyses/{OTHER_ID}/hosts/{ARIN_IP}/lookup").json()

    assert network.urls == []
    assert _rows() == 1
    assert second["record"] == first["record"]
    assert second["cache"]["fetched_at"] == first["cache"]["fetched_at"]


def test_total_failure_is_502_and_writes_nothing(client, lookups, make_analysis, monkeypatch):
    make_analysis([(APNIC_IP, 200)])
    monkeypatch.setattr(
        ip_lookup, "_fetch", FakeNetwork({ip_lookup.BOOTSTRAP_URLS[4]: _json_bytes(FIXTURE_BOOTSTRAP)})
    )

    response = client.post(f"/api/analyses/{ANALYSIS_ID}/hosts/{APNIC_IP}/lookup")

    assert response.status_code == 502, response.text
    error = response.json()["error"]
    assert error["code"] == "lookup_failed"
    assert error["details"]["ip"] == APNIC_IP
    assert len(error["details"]["failures"]) == 2
    assert "150.171.109.217" in error["message"]
    assert _rows() == 0, "§4: a failed lookup writes nothing"

    # ... and the panel still paints: a failure is not a broken cache row.
    after = client.get(f"/api/analyses/{ANALYSIS_ID}/hosts/{APNIC_IP}/lookup").json()
    assert after["record"] is None
    assert after["cache"] is None


def test_a_failure_after_a_success_leaves_the_earlier_record_in_place(client, lookups, make_analysis, monkeypatch):
    make_analysis([(ARIN_IP, 10)])
    _cache_row(ARIN_IP, age_days=2.0, source=ARIN_BASE)
    monkeypatch.setattr(ip_lookup, "_fetch", _serving(ARIN_IP, base=ARIN_BASE, rdap=None, cymru=None))

    failed = client.post(f"/api/analyses/{ANALYSIS_ID}/hosts/{ARIN_IP}/lookup")
    kept = client.get(f"/api/analyses/{ANALYSIS_ID}/hosts/{ARIN_IP}/lookup").json()

    assert failed.status_code == 502
    assert _rows() == 1
    assert kept["record"]["handle"] == "NET-8-8-8-0-2"
    assert kept["cache"]["age_days"] == pytest.approx(2.0, abs=0.01)


# --------------------------------------------------------------------------
# 9. the capture-local block (§5.1)
# --------------------------------------------------------------------------

def test_local_names_come_only_from_the_capture_and_say_which_table(client, lookups, make_analysis):
    make_analysis([(APNIC_IP, 20)])
    for _ in range(3):
        _dns_row(ANALYSIS_ID, "download.sysinternals.com", APNIC_IP)
    _dns_row(ANALYSIS_ID, "ctldl.windowsupdate.com", APNIC_IP, client="192.168.8.230")
    # Decoys: a different address whose answer merely contains this one as a substring, a name
    # answered with another address, and a session where this address is the *client* asking
    # for somebody else's name. None of them points at this address.
    _dns_row(ANALYSIS_ID, "evil.example", "1.2.3.40", client="192.168.8.229")
    _dns_row(ANALYSIS_ID, "elsewhere.example", "150.171.109.218")
    _tls_row(ANALYSIS_ID, client=APNIC_IP, server="8.8.8.8", sni="asked-for.example")

    body = client.get(f"/api/analyses/{ANALYSIS_ID}/hosts/{APNIC_IP}/lookup").json()

    assert body["local"]["names"] == [
        {"name": "download.sysinternals.com", "from": "dns_answer", "rows": 3},
        {"name": "ctldl.windowsupdate.com", "from": "dns_answer", "rows": 1},
    ]
    assert "asked-for.example" not in json.dumps(body["local"])


def test_an_address_that_is_only_a_substring_of_an_answer_is_not_named(client, lookups, make_analysis):
    make_analysis([("1.2.3.4", 5)])
    _dns_row(ANALYSIS_ID, "decoy.example", "1.2.3.40")

    body = client.get(f"/api/analyses/{ANALYSIS_ID}/hosts/1.2.3.4/lookup").json()

    assert body["local"]["names"] == []


def test_a_tls_name_points_at_the_server_side_of_the_session(client, lookups, make_analysis):
    make_analysis([(ARIN_IP, 5), (APNIC_IP, 5)])
    _tls_row(ANALYSIS_ID, client=APNIC_IP, server=ARIN_IP, sni="dns.google")

    assert client.get(f"/api/analyses/{ANALYSIS_ID}/hosts/{ARIN_IP}/lookup").json()["local"]["names"] == [
        {"name": "dns.google", "from": "tls_sni", "rows": 1},
    ]
    assert client.get(f"/api/analyses/{ANALYSIS_ID}/hosts/{APNIC_IP}/lookup").json()["local"]["names"] == []


def test_local_names_are_capped_by_rows_seen_and_the_cap_is_reported(client, lookups, make_analysis):
    make_analysis([(APNIC_IP, 5)])
    extra = 3
    names = ip_lookup.LOCAL_NAME_CAP + extra
    for index in range(names):
        for _ in range(index + 1):               # name-00 once, name-27 twenty-eight times
            _dns_row(ANALYSIS_ID, f"name-{index:02d}.example", APNIC_IP)

    local = client.get(f"/api/analyses/{ANALYSIS_ID}/hosts/{APNIC_IP}/lookup").json()["local"]

    assert len(local["names"]) == ip_lookup.LOCAL_NAME_CAP == 25
    assert local["names_truncated"] is True
    # By rows seen, not by name: the loudest names are the ones kept, so the first is the
    # busiest and the last is the quietest of the twenty-five.
    assert local["names"][0] == {"name": f"name-{names - 1:02d}.example", "from": "dns_answer", "rows": names}
    assert local["names"][-1] == {
        "name": f"name-{names - ip_lookup.LOCAL_NAME_CAP:02d}.example",
        "from": "dns_answer",
        "rows": names - ip_lookup.LOCAL_NAME_CAP + 1,
    }


def test_local_country_comes_from_the_installed_dataset_with_its_source(
    client, lookups, make_analysis, geoip_home
):
    _install_dataset(geoip_home, "150.171.0.0,150.171.255.255,ZA\n", month="2026-10")
    make_analysis([(APNIC_IP, 20)])

    local = client.get(f"/api/analyses/{ANALYSIS_ID}/hosts/{APNIC_IP}/lookup").json()["local"]

    assert local["country"] == "ZA"
    assert local["country_source"] == f"{geoip.DATASET} 2026-10"
    assert "2026-10" in local["country_source"]


def test_a_private_address_is_never_offered_to_the_geography_dataset(client, lookups, make_analysis, geoip_home):
    _install_dataset(geoip_home, "192.168.0.0,192.168.255.255,US\n")
    make_analysis([("192.168.8.229", 20)])

    local = client.get(f"/api/analyses/{ANALYSIS_ID}/hosts/192.168.8.229/lookup").json()["local"]

    # Even with a dataset that places the block, §3.4 does not geolocate private space: the
    # country is where a block is registered, which is not a claim this address can support.
    assert local["country"] is None
    assert local["country_source"] is None


# --------------------------------------------------------------------------
# 10. validation and the analysis gates (§5.2)
# --------------------------------------------------------------------------

@pytest.mark.parametrize("method", ["get", "post"])
@pytest.mark.parametrize("value", ["not-an-ip", "1.2.3", "1.2.3.4.5", "150.171.109.217.1", "300.1.1.1"])
def test_a_malformed_address_is_422_and_sends_nothing(client, lookups, make_analysis, monkeypatch, method, value):
    make_analysis([(APNIC_IP, 5)])
    forbidden = ForbiddenNetwork()
    monkeypatch.setattr(ip_lookup, "_fetch", forbidden)

    response = getattr(client, method)(f"/api/analyses/{ANALYSIS_ID}/hosts/{value}/lookup")

    assert response.status_code == 422, response.text
    assert response.json()["error"]["code"] == "validation_error"
    assert forbidden.urls == []
    assert _rows() == 0


def test_the_analysis_gates_match_every_other_route(client, lookups, make_analysis):
    make_analysis([(APNIC_IP, 5)])

    missing = client.get(f"/api/analyses/{READY_ID}/hosts/{APNIC_IP}/lookup")
    assert missing.status_code == 404
    assert missing.json()["error"]["code"] == "analysis_not_found"

    make_analysis([(APNIC_IP, 5)], analysis_id=BUSY_ID, status="processing")
    unfinished = client.post(f"/api/analyses/{BUSY_ID}/hosts/{APNIC_IP}/lookup")
    assert unfinished.status_code == 409
    assert unfinished.json()["error"]["code"] == "analysis_not_ready"
    assert unfinished.json()["error"]["details"]["status"] == "processing"

    malformed = client.get("/api/analyses/not-an-id/hosts/8.8.8.8/lookup")
    assert malformed.status_code == 400
    assert malformed.json()["error"]["code"] == "invalid_analysis_id"


def test_the_analysis_gate_answers_before_the_address_is_even_parsed(client, lookups, make_analysis):
    response = client.get(f"/api/analyses/{READY_ID}/hosts/not-an-ip/lookup")

    assert response.status_code == 404
    assert response.json()["error"]["code"] == "analysis_not_found"


def test_a_missing_capture_is_still_reported(client, lookups, make_analysis):
    make_analysis([(APNIC_IP, 5)], capture=False)

    response = client.get(f"/api/analyses/{ANALYSIS_ID}/hosts/{APNIC_IP}/lookup")

    assert response.status_code == 410
    assert response.json()["error"]["code"] == "capture_missing"


def test_the_host_itself_need_not_be_in_the_capture(client, lookups, make_analysis):
    """The lookup is about the address, not about the analysis's own host inventory."""
    make_analysis([(ARIN_IP, 5)])

    body = client.get(f"/api/analyses/{ANALYSIS_ID}/hosts/{APNIC_IP}/lookup").json()

    assert body["ip"] == APNIC_IP
    assert body["local"]["names"] == []


def test_another_analyses_names_are_not_shown(client, lookups, make_analysis):
    make_analysis([(APNIC_IP, 20)])
    make_analysis([(APNIC_IP, 20)], analysis_id=OTHER_ID)
    _dns_row(OTHER_ID, "elsewhere.example", APNIC_IP)

    body = client.get(f"/api/analyses/{ANALYSIS_ID}/hosts/{APNIC_IP}/lookup").json()

    assert body["local"]["names"] == []


def test_a_public_ipv6_address_goes_through_the_ipv6_bootstrap(
    client, lookups, make_analysis, monkeypatch
):
    """The v6 bootstrap document, the v6 Cymru zone and an IPv6 record, end to end."""
    address = "2001:4860:4860::8888"
    make_analysis([(address, 5)])
    network = FakeNetwork({
        ip_lookup.BOOTSTRAP_URLS[6]: _json_bytes(
            {"services": [[["2001:4860::/32"], ["https://rdap.example-v6.test/"]]]}
        ),
        f"https://rdap.example-v6.test/ip/{address}": _json_bytes({
            "handle": "2001:4860::/32",
            "name": "GOOGLE-IPV6",
            "country": "US",
            "startAddress": "2001:4860::",
            "endAddress": "2001:4860:ffff:ffff:ffff:ffff:ffff:ffff",
        }),
        ip_lookup.asn_url(ipaddress.ip_address(address)): _txt_bytes(
            "15169 | 2001:4860::/32 | US | arin | 2005-03-14"
        ),
    })
    monkeypatch.setattr(ip_lookup, "_fetch", network)

    response = client.post(f"/api/analyses/{ANALYSIS_ID}/hosts/{address}/lookup")

    assert response.status_code == 200, response.text
    body = response.json()
    assert network.urls[0] == ip_lookup.BOOTSTRAP_URLS[6]
    assert network.urls[1] == f"https://rdap.example-v6.test/ip/{address}"
    assert network.urls[2].endswith(".origin6.asn.cymru.com&type=TXT")
    assert body["kind"] == "public"
    assert body["ip"] == address
    assert body["record"]["network_name"] == "GOOGLE-IPV6"
    assert body["record"]["country"] == "US"
    assert body["record"]["asn"]["number"] == "15169"
    assert _rows() == 1


def test_a_documentation_ipv6_address_is_reserved_and_is_never_sent(
    client, lookups, make_analysis, monkeypatch
):
    address = "2001:db8::1"
    make_analysis([(address, 5)])
    forbidden = ForbiddenNetwork()
    monkeypatch.setattr(ip_lookup, "_fetch", forbidden)

    body = client.post(f"/api/analyses/{ANALYSIS_ID}/hosts/{address}/lookup").json()

    assert forbidden.urls == []
    assert body["kind"] == "reserved"
    assert body["lookup_possible"] is False
    assert body["record"] is None
    assert _rows() == 0


# --------------------------------------------------------------------------
# 11. import safety and the published caps (§6)
# --------------------------------------------------------------------------

def test_the_module_imports_without_a_network_or_a_database(lookups):
    module = importlib.reload(ip_lookup)

    assert module._BOOTSTRAP == {}                       # nothing was fetched at import
    assert module.BOOTSTRAP_URLS[4] == "https://data.iana.org/rdap/ipv4.json"
    assert module.BOOTSTRAP_URLS[6] == "https://data.iana.org/rdap/ipv6.json"
    assert module.classify(APNIC_IP) == module.KIND_PUBLIC
    assert module.canonical("::ffff:8.8.8.8") == "8.8.8.8"
    assert module.cached(ARIN_IP) is None                # and nothing was read either
    assert (module.LOOKUP_TIMEOUT_S, module.LOCAL_NAME_CAP, module.CONTACT_CAP,
            module.REMARK_CAP, module.LOOKUP_MAX_AGE_DAYS) == (20.0, 25, 10, 5, 30.0)
    assert module.KINDS == (
        "public", "private", "reserved", "loopback", "multicast", "link_local", "unknown",
    )
    assert module.ROLE_ORDER == ("registrant", "abuse", "technical", "administrative")


def test_the_lookup_routes_are_the_only_ones_that_fetch(client, lookups, make_analysis, monkeypatch):
    """Every other host route still makes no request at all."""
    make_analysis([(APNIC_IP, 5)])
    forbidden = ForbiddenNetwork()
    monkeypatch.setattr(ip_lookup, "_fetch", forbidden)

    for path in (
        f"/api/analyses/{ANALYSIS_ID}/hosts",
        f"/api/analyses/{ANALYSIS_ID}/hosts/graph",
        f"/api/analyses/{ANALYSIS_ID}/hosts/{APNIC_IP}",
    ):
        assert client.get(path).status_code == 200, path

    assert forbidden.urls == []
