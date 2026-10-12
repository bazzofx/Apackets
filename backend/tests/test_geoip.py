"""Geography tests: the DB-IP dataset, the lookup, its cache and the API (§2-§5).

Everything here is built in the test: the fixtures are tiny CSVs written as gzip into a
throwaway ``data/geoip``, and the network is replaced by an injected fetcher that records
the URLs it was asked for. **No test downloads anything**, and no test touches the live
``data/`` directory or the live database.

The expected values are the countries the fixture ranges carry and the volumes the
``hosts`` rows were inserted with - nothing is inferred from a port, a name or a pattern.
"""

from __future__ import annotations

import functools
import gzip
import hashlib
import importlib
import io
import json
import os
import shutil
import threading
import time
import uuid
from datetime import date
from pathlib import Path

import pytest

from app.api import routes_geo
from app.db import database as db
from app.services import geoip

ANALYSIS_ID = "a1b2c3d4e5f60718293a4b5c6d7e8f90"
READY_ID = "0123456789abcdef0123456789abcdef"
BUSY_ID = "fedcba9876543210fedcba9876543210"

#: Per-test directories live inside the repository, never in ``tempfile``:
#: ``mkdtemp`` creates 0o700 directories some sandboxed environments cannot write
#: into, which is exactly why ``conftest`` does the same for the session data dir.
SCRATCH_ROOT = Path(__file__).resolve().parents[2] / ".tmp" / "geoip-tests"

# A handful of ranges with every shape the parser has to survive: a leading ZZ block
# (the real file's first row is 0.0.0.0-0.255.255.255, ZZ), boundaries inside one
# country, a wide range, a hole after it, another ZZ block over RFC1918 space and one
# IPv6 range that must be counted but never indexed.
FIXTURE_CSV = """\
0.0.0.0,0.255.255.255,ZZ
1.0.0.0,1.0.0.255,AU
1.0.1.0,1.0.3.255,CN
3.0.0.0,3.255.255.255,US
5.0.0.0,5.0.0.255,GB
10.0.0.0,10.255.255.255,ZZ
2001:db8::,2001:db8::ffff,DE
"""


# --------------------------------------------------------------------------
# fixture helpers
# --------------------------------------------------------------------------

def _gzip_bytes(text: str) -> bytes:
    """Deterministic gzip (no header timestamp) of *text*."""
    buffer = io.BytesIO()
    with gzip.GzipFile(fileobj=buffer, mode="wb", mtime=0) as handle:
        handle.write(text.encode("utf-8"))
    return buffer.getvalue()


def _source_document(path: Path, raw: bytes, *, month: str, dataset) -> dict:
    """A §4.1 document for a dataset already written to disk."""
    return {
        "dataset": geoip.DATASET,
        "url": geoip.url_for(month),
        "licence": geoip.LICENCE,
        "attribution": geoip.ATTRIBUTION,
        "file": path.name,
        "bytes": len(raw),
        "sha256": hashlib.sha256(raw).hexdigest(),
        "ranges": dataset.ranges,
        "countries": dataset.codes,
        "dataset_month": month,
        "fetched_at": time.time(),
    }


def _install_csv(home: Path, text: str, *, month: str = "2026-10") -> Path:
    """Write a fixture dataset *and* its provenance, as a refresh would."""
    home.mkdir(parents=True, exist_ok=True)
    raw = _gzip_bytes(text)
    dataset = geoip.parse_gzip(raw, source="fixture")
    path = home / geoip.filename_for(month)
    path.write_bytes(raw)
    (home / geoip.SOURCE_NAME).write_text(
        json.dumps(_source_document(path, raw, month=month, dataset=dataset), indent=2),
        encoding="utf-8",
    )
    geoip.clear_cache()
    return path


def _range_csv(codes: list[str], *, prefix: int = 11) -> str:
    """One /16 per code, in ascending order: ``11.<i>.0.0-11.<i>.255.255``."""
    return "".join(
        f"{prefix}.{index}.0.0,{prefix}.{index}.255.255,{code}\n"
        for index, code in enumerate(codes)
    )


@functools.lru_cache(maxsize=1)
def _big_csv(rows: int = geoip.MIN_RANGES + 1) -> str:
    """A dataset at least MIN_RANGES long, so a refresh will accept it."""
    lines = []
    for index in range(rows):
        start = index * 256
        quad = f"{start >> 24 & 255}.{start >> 16 & 255}.{start >> 8 & 255}.{start & 255}"
        end = start + 255
        last = f"{end >> 24 & 255}.{end >> 16 & 255}.{end >> 8 & 255}.{end & 255}"
        lines.append(f"{quad},{last},{'GB' if index % 3 == 0 else 'US'}\n")
    return "".join(lines)


class RecordingFetcher:
    """A fetcher that serves prepared bytes and remembers every URL it was asked for."""

    def __init__(self, payloads: dict[str, bytes] | None = None) -> None:
        self.payloads = payloads or {}
        self.urls: list[str] = []

    def __call__(self, url: str) -> bytes:
        self.urls.append(url)
        payload = self.payloads.get(url)
        if payload is None:
            raise geoip.NotFound(f"{url} returned 404")
        return payload


# --------------------------------------------------------------------------
# fixtures
# --------------------------------------------------------------------------

@pytest.fixture()
def scratch() -> Path:
    """A throwaway directory of this test's own, inside the repository."""
    directory = SCRATCH_ROOT / uuid.uuid4().hex
    directory.mkdir(parents=True, exist_ok=True)
    yield directory
    shutil.rmtree(directory, ignore_errors=True)


@pytest.fixture()
def geoip_home(scratch: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Point the service at a throwaway ``data/geoip`` and forget all cached state.

    ``geoip_dir()`` is patched rather than ``settings.data_dir`` so that the API tests
    keep the session database while the dataset lives in the scratch directory.
    """
    home = scratch / "geoip"
    monkeypatch.setattr(geoip, "geoip_dir", lambda: home)
    geoip.clear_cache()
    geoip.reset_jobs()
    yield home
    geoip.clear_cache()
    geoip.reset_jobs()


@pytest.fixture()
def dataset(geoip_home: Path) -> Path:
    """The fixture dataset installed as if a refresh had written it."""
    return _install_csv(geoip_home, FIXTURE_CSV)


@pytest.fixture()
def lookup_calls(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    """Record every address the endpoint offers to the dataset.

    The endpoint resolves the dataset once and asks it per address, so this patches the
    table's own ``country_for``; a call here means a *public* address reached the data.
    """
    calls: list[str] = []
    real = geoip.Dataset.country_for

    def _record(self, value: object) -> str | None:
        calls.append(str(value))
        return real(self, value)

    monkeypatch.setattr(geoip.Dataset, "country_for", _record)
    return calls


@pytest.fixture()
def make_analysis(fresh_db):  # noqa: ARG001 - fresh_db empties the tables first
    """A completed analysis row plus crafted ``hosts`` rows (no upload, no pipeline)."""

    def _make(rows: list[tuple[str, int, int]], *, analysis_id: str = ANALYSIS_ID,
              status: str = "completed") -> str:
        now = time.time()
        with db.get_conn() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO analyses (
                    id, original_filename, stored_path, file_size, file_type, status,
                    progress, stage, packet_count, created_at, updated_at
                ) VALUES (?, 'fixture.pcap', 'fixture.pcap', 0, 'pcap', ?, 100, ?, 0, ?, ?)
                """,
                (analysis_id, status, status, now, now),
            )
            for ip, packets, size in rows:
                conn.execute(
                    """
                    INSERT OR REPLACE INTO hosts (
                        analysis_id, ip, packets_sent, packets_received,
                        bytes_sent, bytes_received, is_private, ip_version, peer_count
                    ) VALUES (?, ?, ?, ?, ?, ?, 0, ?, 0)
                    """,
                    (
                        analysis_id,
                        ip,
                        packets // 2,
                        packets - packets // 2,
                        size // 2,
                        size - size // 2,
                        6 if ":" in ip else 4,
                    ),
                )
        return analysis_id

    return _make


def _wait_for_job(job_id: str, *, timeout: float = 120.0) -> dict:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        state = geoip.job_state(job_id)
        assert state is not None, f"job {job_id} is not tracked"
        if state["status"] in {"completed", "failed"}:
            return state
        time.sleep(0.02)
    raise AssertionError(f"geoip job {job_id} did not settle within {timeout}s")


# --------------------------------------------------------------------------
# 1. parsing the file (§2, §4)
# --------------------------------------------------------------------------

def test_fixture_parses_into_ipv4_ranges_and_counts_ipv6(geoip_home):
    dataset = geoip.parse_gzip(_gzip_bytes(FIXTURE_CSV), source="fixture")

    assert dataset.ranges == 7           # every row, IPv4 and IPv6
    assert dataset.ipv4_ranges == 6
    assert dataset.ipv6_ranges == 1      # counted, validated, never indexed
    assert dataset.located == 4          # AU, CN, US, GB - what the IPv4 table can answer
    assert dataset.codes == 6            # those plus ZZ and the IPv6-only DE (§4.1's sense)
    assert dataset.unknown_ranges == 2   # the two ZZ blocks
    assert dataset.odd_ranges == 0
    assert len(dataset.starts) == 6      # only IPv4 is searchable


def test_parse_csv_matches_parse_gzip():
    from_bytes = geoip.parse_gzip(_gzip_bytes(FIXTURE_CSV), source="fixture")
    from_text = geoip.parse_csv(FIXTURE_CSV)

    assert list(from_bytes.starts) == list(from_text.starts)
    assert list(from_bytes.ends) == list(from_text.ends)
    assert from_bytes.code_list == from_text.code_list


def test_ranges_are_sorted_even_when_the_file_is_not():
    unsorted = "5.0.0.0,5.0.0.255,GB\n1.0.0.0,1.0.0.255,AU\n"
    dataset = geoip.parse_csv(unsorted)

    assert list(dataset.starts) == sorted(dataset.starts)
    assert dataset.country(0x01000001) == "AU"


@pytest.mark.parametrize(
    "text, fragment",
    [
        ("1.0.0.0,1.0.0.255\n", "has 2 fields"),
        ("1.0.0.0,1.0.0.255,US,extra\n", "has 4 fields"),
        ("\n", "empty"),
        ("1.0.0.0,1.0.0.255,US\n\n1.0.1.0,1.0.1.255,US\n", "empty"),
        ("nonsense\n", "expected 3"),
        ("1.0.0.0,not-an-ip,US\n", "not an address range"),
        ("1.0.1.0,1.0.0.255,US\n", "ends before it starts"),
        ("1.0.0.256,1.0.0.255,US\n", "not an address range"),
        ("010.0.0.0,010.0.0.255,US\n", "not an address range"),
    ],
)
def test_malformed_rows_are_rejected(text, fragment):
    with pytest.raises(geoip.DatasetError) as excinfo:
        geoip.parse_csv(text, source="fixture")

    assert fragment in str(excinfo.value)


def test_gzip_that_is_truncated_or_not_gzip_is_rejected():
    good = _gzip_bytes(FIXTURE_CSV)

    with pytest.raises(geoip.DatasetError):
        geoip.parse_gzip(good[: len(good) // 2], source="fixture")
    with pytest.raises(geoip.DatasetError):
        geoip.parse_gzip(b"not gzip at all", source="fixture")
    with pytest.raises(geoip.DatasetError):
        geoip.parse_gzip(b"", source="fixture")


def test_unknown_codes_are_unknown_not_countries():
    # ZZ is the dataset's own "no country known"; an empty code and a code outside ISO
    # 3166-1 alpha-2 mean the same thing (§2) and are never passed through as a country.
    text = "1.0.0.0,1.0.0.255,ZZ\n2.0.0.0,2.0.0.255,\n3.0.0.0,3.0.0.255,Q9\n4.0.0.0,4.0.0.255,US\n"
    dataset = geoip.parse_gzip(_gzip_bytes(text), source="fixture")

    assert dataset.located == 1
    assert dataset.codes == 4            # US plus the three unknown markers
    assert dataset.unknown_ranges == 3
    assert dataset.odd_ranges == 1          # only Q9 is unusual; ZZ and "" are the dataset's
    assert dataset.country(0x01000001) is None
    assert dataset.country(0x02000001) is None
    assert dataset.country(0x03000001) is None
    assert dataset.country(0x04000001) == "US"


def test_kosovo_is_the_one_code_accepted_outside_iso():
    """§2's single named exception.

    ``XK`` is not assigned by ISO 3166-1, but it is the code DB-IP uses for Kosovo on 152 rows
    of the real file and the map asset both names and draws it. Calling that traffic unknown
    while the page could label it would be the worse error, so it is accepted — and nothing
    else outside the assigned set is.
    """
    text = "1.0.0.0,1.0.0.255,XK\n2.0.0.0,2.0.0.255,Q9\n3.0.0.0,3.0.0.255,ZZ\n"
    dataset = geoip.parse_csv(text)

    assert dataset.country(0x01000001) == "XK"      # the exception
    assert dataset.country(0x02000001) is None      # Q9 is still not a country
    assert dataset.country(0x03000001) is None      # nor is ZZ
    assert dataset.located == 1
    assert dataset.unknown_ranges == 2
    assert dataset.odd_ranges == 1                  # only Q9 is unusual now
    assert "XK" in geoip.USER_ASSIGNED_CODES
    assert geoip.USER_ASSIGNED_CODES == frozenset({"XK"})   # exactly one


def test_rows_with_spaces_are_still_read():
    dataset = geoip.parse_csv("1.0.0.0, 1.0.0.255, us\n")

    assert dataset.country(0x01000001) == "US"


def test_lowercase_codes_are_normalised():
    dataset = geoip.parse_csv("1.0.0.0,1.0.0.255,us\n")

    assert dataset.country(0x01000001) == "US"


def test_iso_code_set_is_the_officially_assigned_one():
    assert len(geoip.ISO_CODES) == 249
    assert "ZZ" not in geoip.ISO_CODES
    assert {"US", "GB", "ZA", "DE"} <= geoip.ISO_CODES


# --------------------------------------------------------------------------
# 2. lookup (§2, §3)
# --------------------------------------------------------------------------

def test_lookup_finds_countries_inside_boundaries_and_between_ranges(dataset):
    # inside
    assert geoip.lookup("3.173.21.63") == "US"
    assert geoip.lookup("1.0.2.7") == "CN"
    # both boundaries of one range
    assert geoip.lookup("1.0.1.0") == "CN"
    assert geoip.lookup("1.0.3.255") == "CN"
    # the boundaries of the range before it
    assert geoip.lookup("1.0.0.0") == "AU"
    assert geoip.lookup("1.0.0.255") == "AU"
    # the hole between 1.0.3.255 and 3.0.0.0 is unknown, never rounded down
    assert geoip.lookup("1.0.4.0") is None
    assert geoip.lookup("2.255.255.255") is None
    # outside every range, in both directions
    assert geoip.lookup("9.9.9.9") is None
    assert geoip.lookup("250.0.0.1") is None


def test_zz_and_empty_codes_read_as_unknown(dataset):
    assert geoip.lookup("0.0.0.1") is None       # ZZ block
    assert geoip.lookup("10.1.2.3") is None      # ZZ block over RFC1918 space
    assert geoip.lookup("192.168.8.229") is None


def test_ipv6_is_unknown_even_where_the_dataset_has_a_range(dataset):
    # The fixture carries 2001:db8::/112 -> DE, and the real file carries 348,712 IPv6
    # rows: they are counted, and this IPv4 table still answers unknown. Stated (§2).
    assert geoip.lookup("2001:db8::1") is None
    assert geoip.lookup("2001:4860:4860::8888") is None
    # ... but an IPv4-mapped address is the IPv4 address it carries.
    assert geoip.lookup("::ffff:3.173.21.63") == "US"


@pytest.mark.parametrize(
    "value",
    [None, "", "   ", "not-an-ip", "3.173.21.63.5", "300.1.1.1", "1.2.3", "1.2.3.4.5",
     "0x7f.1.1.1", 12345, object()],
)
def test_malformed_input_is_none_not_an_exception(dataset, value):
    assert geoip.lookup(value) is None
    assert geoip.parse_address(value) is None


def test_lookup_without_a_dataset_is_none(geoip_home):
    assert not geoip_home.exists()
    assert geoip.lookup("3.173.21.63") is None
    assert geoip.current_dataset() is None
    assert geoip.country_for("8.8.8.8") is None


def test_lookup_survives_a_file_that_vanishes(geoip_home, dataset):
    dataset.unlink()

    assert geoip.lookup("3.173.21.63") is None
    assert geoip.current_dataset() is None


# --------------------------------------------------------------------------
# 3. classification (§3)
# --------------------------------------------------------------------------

@pytest.mark.parametrize(
    "value",
    ["192.168.8.229", "10.0.0.1", "172.16.0.1", "172.31.255.255", "127.0.0.1",
     "169.254.1.1", "224.0.0.251", "239.255.255.250", "::1", "fe80::1", "fd00::1",
     "fc00::1", "::ffff:192.168.1.1"],
)
def test_local_addresses(value):
    assert geoip.classify(value) == geoip.SCOPE_LOCAL


@pytest.mark.parametrize(
    "value",
    ["0.0.0.0", "240.0.0.1", "255.255.255.255", "192.0.2.1", "198.51.100.7",
     "203.0.113.9", "198.18.0.1", "::"],
)
def test_reserved_addresses(value):
    assert geoip.classify(value) == geoip.SCOPE_RESERVED


@pytest.mark.parametrize(
    "value",
    ["3.173.21.63", "8.8.8.8", "100.64.0.1", "2001:4860:4860::8888"],
)
def test_public_addresses(value):
    assert geoip.classify(value) == geoip.SCOPE_PUBLIC


@pytest.mark.parametrize("value", [None, "", "nonsense", "1.2.3"])
def test_unparsable_has_no_class(value):
    assert geoip.classify(value) is None


def test_non_public_addresses_are_never_looked_up(dataset, monkeypatch):
    def _explode(value):
        raise AssertionError(f"lookup was called for {value!r}")

    monkeypatch.setattr(geoip, "lookup", _explode)

    for value in ["192.168.8.229", "10.1.2.3", "127.0.0.1", "169.254.1.1",
                  "224.0.0.251", "240.0.0.1", "0.0.0.0", "255.255.255.255", "fe80::1"]:
        assert geoip.country_for(value) is None


def test_country_name_is_never_invented(dataset):
    # §5.3: the API may send null, and this installation has no name source.
    assert geoip.country_name("US") is None
    assert geoip.country_name(None) is None
    assert geoip.country_name("ZZ") is None


# --------------------------------------------------------------------------
# 4. the (size, mtime) cache (§4)
# --------------------------------------------------------------------------

def test_cache_is_reused_and_invalidated_by_a_new_file(geoip_home):
    path = _install_csv(geoip_home, "3.0.0.0,3.0.0.255,US\n")
    assert geoip.lookup("3.0.0.1") == "US"

    cached = geoip._CACHE
    assert geoip.lookup("3.0.0.1") == "US"
    assert geoip._CACHE is cached          # parsed once, served from memory

    # A different size is enough on its own.
    path.write_bytes(_gzip_bytes("3.0.0.0,3.0.0.255,US\n5.0.0.0,5.0.0.255,GB\n"))
    assert geoip.lookup("5.0.0.1") == "GB"
    assert geoip.lookup("3.0.0.1") == "US"


def test_cache_is_invalidated_by_mtime_alone(geoip_home):
    # The same gzipped length, the same path: only mtime says anything changed, which
    # is exactly what §4 promises to notice.
    before = "3.0.0.0,3.0.0.255,US\n5.0.0.0,5.0.0.255,GB\n"
    after = "3.0.0.0,3.0.0.255,GB\n5.0.0.0,5.0.0.255,US\n"
    path = _install_csv(geoip_home, before)
    assert geoip.lookup("3.0.0.1") == "US"

    raw = _gzip_bytes(after)
    assert len(raw) == path.stat().st_size        # size cannot explain the change
    path.write_bytes(raw)
    stamp = path.stat().st_mtime + 5
    os.utime(path, (stamp, stamp))

    assert geoip.lookup("3.0.0.1") == "GB"
    assert geoip.lookup("5.0.0.1") == "US"


def test_cache_is_keyed_by_path_too(geoip_home, scratch: Path):
    _install_csv(geoip_home, "3.0.0.0,3.0.0.255,US\n")
    assert geoip.lookup("3.0.0.1") == "US"

    other = scratch / "other"
    _install_csv(other, "3.0.0.0,3.0.0.255,GB\n")
    geoip.clear_cache()

    # dataset_for() is the cache's only entry point, so ask it directly for both files.
    assert geoip.dataset_for(geoip_home / geoip.filename_for("2026-10")).country(0x03000001) == "US"
    assert geoip.dataset_for(other / geoip.filename_for("2026-10")).country(0x03000001) == "GB"


# --------------------------------------------------------------------------
# 5. refresh (§5.2)
# --------------------------------------------------------------------------

def test_candidate_months_and_url_shape():
    months = geoip.candidate_months(date(2026, 10, 12))

    assert months[0] == "2026-10"
    assert months[1] == "2026-09"
    assert months[-1] == "2026-04"                      # six months back, no further
    assert len(months) == geoip.REFRESH_MONTHS_BACK + 1
    assert geoip.candidate_months(date(2026, 1, 15))[:3] == ["2026-01", "2025-12", "2025-11"]
    assert geoip.url_for("2026-10") == (
        "https://download.db-ip.com/free/dbip-country-lite-2026-10.csv.gz"
    )
    assert geoip.filename_for("2026-10") == "dbip-country-lite-2026-10.csv.gz"


def test_refresh_asks_for_this_month_first_then_walks_back_over_404s(geoip_home):
    big = _gzip_bytes(_big_csv())
    fetcher = RecordingFetcher(
        {
            geoip.url_for("2026-08"): big,
        }
    )

    source = geoip.refresh(fetcher=fetcher, today=date(2026, 10, 12))

    assert fetcher.urls == [
        geoip.url_for("2026-10"),
        geoip.url_for("2026-09"),
        geoip.url_for("2026-08"),
    ]
    assert source["dataset_month"] == "2026-08"
    assert source["url"] == geoip.url_for("2026-08")
    assert source["file"] == "dbip-country-lite-2026-08.csv.gz"
    assert (geoip_home / source["file"]).read_bytes() == big


def test_refresh_installs_the_file_and_source_json_atomically(geoip_home):
    big = _gzip_bytes(_big_csv())
    fetcher = RecordingFetcher({geoip.url_for("2026-10"): big})

    source = geoip.refresh(fetcher=fetcher, today=date(2026, 10, 12))

    # §4.1's shape, exactly.
    assert set(source) == {
        "dataset", "url", "licence", "attribution", "file", "bytes", "sha256",
        "ranges", "countries", "dataset_month", "fetched_at",
    }
    assert source["dataset"] == "DB-IP Lite — country"
    assert source["licence"] == "CC BY 4.0"
    assert source["attribution"] == "IP geolocation by DB-IP (https://db-ip.com)"
    assert source["bytes"] == len(big)
    assert source["sha256"] == hashlib.sha256(big).hexdigest()
    assert source["ranges"] == geoip.MIN_RANGES + 1
    assert source["countries"] == 2
    assert isinstance(source["fetched_at"], float)

    on_disk = json.loads((geoip_home / geoip.SOURCE_NAME).read_text(encoding="utf-8"))
    assert on_disk == source
    # Exactly the two files §4 lists, and no temporary left behind.
    assert sorted(path.name for path in geoip_home.iterdir()) == [
        "dbip-country-lite-2026-10.csv.gz", "source.json",
    ]
    assert geoip.status()["available"] is True


def test_refresh_replaces_an_earlier_month_and_prunes_it(geoip_home):
    geoip.refresh(
        fetcher=RecordingFetcher({geoip.url_for("2026-09"): _gzip_bytes(_big_csv())}),
        today=date(2026, 9, 10),
    )
    stale = geoip_home / geoip.filename_for("2026-09")
    assert stale.is_file()

    geoip.refresh(
        fetcher=RecordingFetcher({geoip.url_for("2026-10"): _gzip_bytes(_big_csv())}),
        today=date(2026, 10, 12),
    )

    assert not stale.exists(), "a superseded month should not be left on disk"
    assert sorted(path.name for path in geoip_home.iterdir()) == [
        "dbip-country-lite-2026-10.csv.gz", "source.json",
    ]


def test_a_truncated_download_is_rejected_and_nothing_is_written(geoip_home):
    short = _gzip_bytes(FIXTURE_CSV)
    fetcher = RecordingFetcher({geoip.url_for("2026-10"): short})

    with pytest.raises(geoip.RefreshError) as excinfo:
        geoip.refresh(fetcher=fetcher, today=date(2026, 10, 12))

    assert "truncated" in str(excinfo.value)
    assert geoip.MIN_RANGES > geoip.parse_gzip(short).ranges
    assert not (geoip_home / geoip.SOURCE_NAME).exists()
    assert list(geoip_home.glob("*.csv.gz")) == []
    assert list(geoip_home.glob(".*.tmp")) == []
    assert geoip.status()["available"] is False


def test_a_failed_download_writes_nothing_on_a_clean_installation(geoip_home):
    fetcher = RecordingFetcher()          # every month is a 404

    with pytest.raises(geoip.RefreshError) as excinfo:
        geoip.refresh(fetcher=fetcher, today=date(2026, 10, 12))

    assert len(fetcher.urls) == geoip.REFRESH_MONTHS_BACK + 1
    assert "no monthly dataset could be downloaded" in str(excinfo.value)
    assert not (geoip_home / geoip.SOURCE_NAME).exists()
    assert list(geoip_home.glob("*.csv.gz")) == []
    assert geoip.dataset_path() is None


def test_a_previous_dataset_survives_a_failed_refresh(geoip_home, dataset):
    before = (geoip_home / geoip.SOURCE_NAME).read_bytes()
    before_file = dataset.read_bytes()
    assert geoip.lookup("3.173.21.63") == "US"

    for payload in ({}, {geoip.url_for("2026-10"): b"not gzip"}, {geoip.url_for("2026-10"): b""}):
        with pytest.raises(geoip.RefreshError):
            geoip.refresh(fetcher=RecordingFetcher(payload), today=date(2026, 10, 12))

    assert (geoip_home / geoip.SOURCE_NAME).read_bytes() == before
    assert dataset.read_bytes() == before_file
    assert geoip.lookup("3.173.21.63") == "US"
    assert geoip.status()["available"] is True


def test_a_network_failure_is_not_retried_against_six_earlier_months(geoip_home):
    calls: list[str] = []

    def _fetch(url: str) -> bytes:
        calls.append(url)
        raise geoip.FetchError(f"{url} could not be reached (connection refused)")

    with pytest.raises(geoip.RefreshError) as excinfo:
        geoip.refresh(fetcher=_fetch, today=date(2026, 10, 12))

    assert calls == [geoip.url_for("2026-10")]
    assert "connection refused" in str(excinfo.value)


def test_the_real_url_is_never_touched_unless_a_fetcher_says_so(geoip_home, monkeypatch):
    # The default fetcher is only reached for a real request; here it is replaced, which
    # is also the assertion that tests never download anything.
    monkeypatch.setattr(geoip, "_fetch", lambda url, **kwargs: _gzip_bytes(FIXTURE_CSV))

    with pytest.raises(geoip.RefreshError):
        geoip.refresh(today=date(2026, 10, 12))


# --------------------------------------------------------------------------
# 6. status (§5.1)
# --------------------------------------------------------------------------

def test_status_when_no_dataset_was_ever_downloaded(geoip_home):
    state = geoip.status()

    assert state["available"] is False
    assert state["source"] is None
    assert "never been downloaded" in state["reason"]
    assert "/api/geoip/refresh" in state["reason"]      # a reason a reader can act on
    assert state["note"]


def test_status_when_the_dataset_is_installed(geoip_home, dataset):
    state = geoip.status()

    assert state["available"] is True
    assert state["reason"] is None
    assert state["source"] == json.loads((geoip_home / geoip.SOURCE_NAME).read_text("utf-8"))
    assert state["source"]["dataset_month"] == "2026-10"
    assert state["note"]


def test_status_when_the_file_is_missing_or_unreadable(geoip_home, dataset):
    dataset.unlink()
    assert geoip.status()["available"] is False
    assert "not in" in geoip.status()["reason"]

    dataset.write_bytes(b"this is not gzip")
    state = geoip.status()
    assert state["available"] is False
    assert state["source"] is None
    assert "could not be parsed" in state["reason"]


def test_status_reports_a_refresh_that_failed(geoip_home):
    job = geoip.start_refresh(fetcher=RecordingFetcher(), today=date(2026, 10, 12))
    state = _wait_for_job(job["job_id"])

    assert state["status"] == "failed"
    assert "RefreshError" in state["error"]
    assert "last refresh attempt failed" in geoip.status()["reason"]


# --------------------------------------------------------------------------
# 7. the refresh job and its endpoint (§5.2)
# --------------------------------------------------------------------------

def test_refresh_job_records_its_stages_and_result(geoip_home):
    big = _gzip_bytes(_big_csv())
    job = geoip.start_refresh(
        fetcher=RecordingFetcher({geoip.url_for("2026-10"): big}),
        today=date(2026, 10, 12),
    )

    assert set(job) == {"job_id", "kind", "status"}
    assert job["kind"] == "geoip_refresh"
    state = _wait_for_job(job["job_id"])

    assert state["status"] == "completed"
    assert state["source"]["file"] == "dbip-country-lite-2026-10.csv.gz"
    assert state["started_at"] and state["finished_at"] >= state["started_at"]
    assert geoip.status()["available"] is True


def test_a_second_refresh_while_one_runs_is_refused(geoip_home):
    release = threading.Event()
    started = threading.Event()
    first: dict | None = None

    def _slow(url: str) -> bytes:
        started.set()
        release.wait(30)
        return _gzip_bytes(_big_csv())

    try:
        first = geoip.start_refresh(fetcher=_slow, today=date(2026, 10, 12))
        assert started.wait(10), "the first refresh never started"

        with pytest.raises(geoip.RefreshBusy):
            geoip.start_refresh(fetcher=_slow, today=date(2026, 10, 12))
        assert geoip.refresh_in_progress()["job_id"] == first["job_id"]
    finally:
        release.set()
        if first is not None:
            _wait_for_job(first["job_id"])


def test_status_endpoint(client, geoip_home):
    body = client.get("/api/geoip/status").json()

    assert set(body) == {"available", "source", "reason", "note"}
    assert body["available"] is False
    assert body["source"] is None
    assert body["reason"]


def test_refresh_endpoint_queues_a_job_and_the_dataset_arrives(client, geoip_home, monkeypatch):
    big = _gzip_bytes(_big_csv())
    fetched: list[str] = []

    def _fetch(url: str, **kwargs) -> bytes:
        fetched.append(url)
        if url == geoip.url_for("2026-10"):
            return big
        raise geoip.NotFound(f"{url} returned 404")

    monkeypatch.setattr(geoip, "_fetch", _fetch)

    response = client.post("/api/geoip/refresh")

    assert response.status_code == 202, response.text
    body = response.json()
    assert body["kind"] == "geoip_refresh"
    assert body["status"] == "queued"
    assert set(body) == {"job_id", "kind", "status"}

    state = _wait_for_job(body["job_id"])
    assert state["status"] == "completed", state["error"]
    assert fetched[0] == geoip.url_for(date.today().strftime("%Y-%m"))

    after = client.get("/api/geoip/status").json()
    assert after["available"] is True
    assert after["reason"] is None
    assert after["source"]["dataset"] == "DB-IP Lite — country"


def test_refresh_endpoint_refuses_a_second_job(client, geoip_home, monkeypatch):
    release = threading.Event()
    started = threading.Event()

    def _slow(url: str, **kwargs) -> bytes:
        started.set()
        release.wait(30)
        return _gzip_bytes(_big_csv())

    monkeypatch.setattr(geoip, "_fetch", _slow)

    try:
        assert client.post("/api/geoip/refresh").status_code == 202
        assert started.wait(10)
        refused = client.post("/api/geoip/refresh")
        assert refused.status_code == 409
        assert refused.json()["error"]["code"] == "refresh_in_progress"
    finally:
        release.set()
        deadline = time.monotonic() + 120
        while geoip.refresh_in_progress() and time.monotonic() < deadline:
            time.sleep(0.02)


def test_capabilities_lists_the_geography_router(client):
    assert client.get("/api/capabilities").json()["features"]["geo"] is True


# --------------------------------------------------------------------------
# 8. the geography endpoint (§5.3)
# --------------------------------------------------------------------------

ROWS = [
    # (ip, packets, bytes)
    ("3.0.0.1", 100, 1000),        # US
    ("3.0.0.2", 50, 500),          # US
    ("1.0.1.5", 10, 200),          # CN
    ("1.0.0.7", 5, 300),           # AU
    ("8.8.8.8", 2, 100),           # public, no range: unknown
    ("192.168.8.229", 200, 5000),  # local
    ("10.0.0.5", 20, 400),         # local, inside the dataset's ZZ block
    ("240.0.0.1", 1, 10),          # reserved
    ("255.255.255.255", 1, 10),    # reserved
]


def test_geography_envelope_end_to_end(client, dataset, make_analysis, lookup_calls):
    make_analysis(ROWS)

    response = client.get(f"/api/analyses/{ANALYSIS_ID}/geography")
    assert response.status_code == 200, response.text
    body = response.json()

    assert set(body) == {
        "analysis_id", "generated_at", "dataset", "origin", "countries", "unknown",
        "counts", "note",
    }
    assert body["analysis_id"] == ANALYSIS_ID
    assert isinstance(body["generated_at"], float)

    # The dataset block is §5.1 without its note.
    assert body["dataset"] == {
        "available": True,
        "source": geoip.status()["source"],
        "reason": None,
    }

    # §3: the origin is the capture's own side, labelled, never placed on the map.
    assert body["origin"] == {
        "label": routes_geo.ORIGIN_LABEL,
        "addresses": 2,
        "packets": 220,
        "bytes": 5400,
    }

    # Countries by bytes descending, then by code; the wide US range is one country.
    assert [country["code"] for country in body["countries"]] == ["US", "AU", "CN"]
    assert body["countries"][0] == {
        "code": "US",
        "name": None,
        "addresses": 2,
        "packets": 150,
        "bytes": 1500,
        "ips": ["3.0.0.1", "3.0.0.2"],
        "ips_truncated": False,
    }
    assert body["countries"][1]["bytes"] == 300
    assert body["countries"][2]["bytes"] == 200
    assert all(country["name"] is None for country in body["countries"])

    # Unknown is a result: the public address the dataset does not answer for.
    assert body["unknown"] == {
        "addresses": 1,
        "packets": 2,
        "bytes": 100,
        "ips": ["8.8.8.8"],
        "ips_truncated": False,
    }

    assert body["counts"] == {
        "addresses": 9,
        "located": 4,
        "countries": 3,
        "unknown": 1,
        "local": 2,
        "reserved": 2,
    }
    assert "countries_truncated" not in body["counts"]
    assert "registered" in body["note"]
    assert "unknown" in body["note"]

    # §3, finally: a private, loopback, multicast or reserved address is never looked up.
    assert sorted(lookup_calls) == ["1.0.0.7", "1.0.1.5", "3.0.0.1", "3.0.0.2", "8.8.8.8"]


def test_geography_sums_both_directions_of_every_host_row(client, dataset, make_analysis):
    make_analysis([("3.0.0.1", 10, 900)])
    with db.get_conn() as conn:
        conn.execute(
            "UPDATE hosts SET packets_sent = 7, packets_received = 3, bytes_sent = 400, "
            "bytes_received = 500 WHERE ip = '3.0.0.1'"
        )

    body = client.get(f"/api/analyses/{ANALYSIS_ID}/geography").json()

    assert body["countries"][0]["packets"] == 10
    assert body["countries"][0]["bytes"] == 900


def test_geography_without_a_dataset_reports_it_and_unknown_country(client, geoip_home, make_analysis):
    make_analysis([("3.0.0.1", 10, 900), ("192.168.0.1", 5, 100)])

    body = client.get(f"/api/analyses/{ANALYSIS_ID}/geography").json()

    assert body["dataset"]["available"] is False
    assert body["dataset"]["source"] is None
    assert body["dataset"]["reason"]
    assert body["countries"] == []
    assert body["counts"]["unknown"] == 1
    assert body["counts"]["located"] == 0
    assert body["origin"]["addresses"] == 1


def test_geography_of_an_analysis_with_no_hosts(client, dataset, make_analysis):
    make_analysis([])

    body = client.get(f"/api/analyses/{ANALYSIS_ID}/geography").json()

    assert body["origin"] == {
        "label": routes_geo.ORIGIN_LABEL, "addresses": 0, "packets": 0, "bytes": 0,
    }
    assert body["countries"] == []
    assert body["unknown"]["addresses"] == 0
    assert body["counts"] == {
        "addresses": 0, "located": 0, "countries": 0, "unknown": 0, "local": 0,
    }


def test_countries_are_capped_and_the_cap_is_reported(client, geoip_home, make_analysis):
    codes = sorted(geoip.ISO_CODES)[: routes_geo.COUNTRY_CAP + 5]
    _install_csv(geoip_home, _range_csv(codes))
    rows = [(f"11.{index}.0.7", 10, 1000 + index) for index in range(len(codes))]
    make_analysis(rows)

    body = client.get(f"/api/analyses/{ANALYSIS_ID}/geography").json()

    assert len(body["countries"]) == routes_geo.COUNTRY_CAP == 60
    assert body["counts"]["countries"] == len(codes)
    assert body["counts"]["countries_truncated"] is True
    assert body["counts"]["located"] == len(codes)
    # The cap keeps the biggest by bytes, sorted descending, never an arbitrary prefix.
    assert [country["code"] for country in body["countries"]] == list(reversed(codes))[:60]
    assert body["countries"][0]["bytes"] == 1000 + len(codes) - 1
    assert str(len(codes) - routes_geo.COUNTRY_CAP) in body["note"]


def test_a_country_lists_at_most_geo_ip_cap_addresses(client, dataset, make_analysis):
    addresses = [f"3.0.0.{index}" for index in range(1, routes_geo.GEO_IP_CAP + 6)]
    make_analysis([(ip, 1, index) for index, ip in enumerate(addresses, start=1)])

    body = client.get(f"/api/analyses/{ANALYSIS_ID}/geography").json()
    country = body["countries"][0]

    assert country["code"] == "US"
    assert country["addresses"] == len(addresses)
    assert len(country["ips"]) == routes_geo.GEO_IP_CAP == 50
    assert country["ips_truncated"] is True
    # The listed addresses are the loudest ones, not the first ones.
    assert country["ips"][0] == addresses[-1]
    assert addresses[0] not in country["ips"]


def test_the_unknown_bucket_is_capped_too(client, dataset, make_analysis):
    addresses = [f"9.9.{index // 250}.{index % 250 + 1}" for index in range(55, 0, -1)]
    make_analysis([(ip, 1, index) for index, ip in enumerate(addresses, start=1)])

    body = client.get(f"/api/analyses/{ANALYSIS_ID}/geography").json()

    assert body["unknown"]["addresses"] == len(addresses)
    assert len(body["unknown"]["ips"]) == routes_geo.GEO_IP_CAP
    assert body["unknown"]["ips_truncated"] is True
    assert body["counts"]["unknown"] == len(addresses)


def test_ips_are_not_flagged_truncated_when_they_fit(client, dataset, make_analysis):
    make_analysis([("3.0.0.1", 1, 10), ("3.0.0.2", 1, 20)])

    body = client.get(f"/api/analyses/{ANALYSIS_ID}/geography").json()

    assert body["countries"][0]["ips_truncated"] is False
    assert body["unknown"]["ips_truncated"] is False


def test_geography_gates_match_the_rest_of_the_application(client, dataset, make_analysis):
    missing = client.get(f"/api/analyses/{READY_ID}/geography")
    assert missing.status_code == 404
    assert missing.json()["error"]["code"] == "analysis_not_found"

    malformed = client.get("/api/analyses/not-an-id/geography")
    assert malformed.status_code == 400
    assert malformed.json()["error"]["code"] == "invalid_analysis_id"

    make_analysis([("3.0.0.1", 1, 10)], analysis_id=BUSY_ID, status="processing")
    unfinished = client.get(f"/api/analyses/{BUSY_ID}/geography")
    assert unfinished.status_code == 409
    assert unfinished.json()["error"]["code"] == "analysis_not_ready"
    assert unfinished.json()["error"]["details"]["status"] == "processing"


def test_geography_never_reads_packets(client, dataset, make_analysis):
    # The endpoint aggregates over hosts; a packet table full of other addresses must
    # not change a thing.
    make_analysis([("3.0.0.1", 10, 900)])
    with db.get_conn() as conn:
        conn.execute(
            """
            INSERT INTO packets (analysis_id, number, frame_len, src_ip, dst_ip)
            VALUES (?, 1, 100, '5.0.0.9', '8.8.8.8')
            """,
            (ANALYSIS_ID,),
        )

    body = client.get(f"/api/analyses/{ANALYSIS_ID}/geography").json()

    assert body["counts"]["addresses"] == 1
    assert [country["code"] for country in body["countries"]] == ["US"]


def test_module_import_reads_nothing_and_needs_no_dataset(geoip_home, monkeypatch):
    module = importlib.reload(geoip)
    # The reload rebuilt the module's namespace, so point it at the fixture again.
    monkeypatch.setattr(module, "geoip_dir", lambda: geoip_home)

    assert module._CACHE is None
    assert module.current_dataset() is None
    assert not geoip_home.exists(), "importing the module must not create data/geoip"
    assert module.lookup("3.173.21.63") is None
    assert module.status()["available"] is False
