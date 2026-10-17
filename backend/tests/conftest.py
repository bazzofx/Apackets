"""Shared pytest fixtures.

Test isolation rules:

* Scapy is told where to cache before it is imported, otherwise it tries to write
  outside the workspace and fails.
* The application's data directory is redirected to a throwaway session
  directory *before* ``app.core.config`` is imported, so the suite never touches
  a developer's real analyses, uploads or database.
* Captures are generated once per session (Scapy builds them deterministically),
  not once per test.
"""

from __future__ import annotations

import os
import shutil
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
BACKEND_DIR = REPO_ROOT / "backend"
TESTS_DIR = Path(__file__).resolve().parent

# --- environment must be prepared before importing application code ---------

_CACHE_DIR = REPO_ROOT / ".cache"
_CACHE_DIR.mkdir(parents=True, exist_ok=True)
os.environ.setdefault("XDG_CACHE_HOME", str(_CACHE_DIR))
os.environ.setdefault("XDG_CONFIG_HOME", str(REPO_ROOT / ".config"))

# The session data directory lives inside the repository rather than in the
# system temp directory: `tempfile.mkdtemp` creates 0o700 directories, which some
# sandboxed environments cannot write into. `.tmp/` is gitignored.
_TMP_ROOT = REPO_ROOT / ".tmp"
_TMP_ROOT.mkdir(parents=True, exist_ok=True)
_SESSION_DATA = _TMP_ROOT / f"pytest-data-{os.getpid()}"
_SESSION_DATA.mkdir(parents=True, exist_ok=True)
os.environ["APACKETS_DATA_DIR"] = str(_SESSION_DATA)
os.environ.setdefault("APACKETS_TSHARK_TIMEOUT_S", "180")
# A baseline change sweeps every analysis in a background thread; in a test process
# that would write while assertions run. The sweep is exercised directly instead
# (tests/test_baseline.py::test_a_baseline_change_recomputes_only_the_baseline_rules).
os.environ["APACKETS_BASELINE_AUTO_RECALC"] = "0"

if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))
if str(TESTS_DIR) not in sys.path:
    sys.path.insert(0, str(TESTS_DIR))


def _force_data_dir() -> None:
    """Point the settings singleton at the session directory.

    The environment variable is set before import, which is enough in a fresh
    interpreter; this also covers the case where a plugin imported the settings
    module earlier.
    """
    try:
        from app.core.config import settings
    except Exception:  # pragma: no cover - app not importable yet
        return
    settings.data_dir = _SESSION_DATA
    settings.ensure_dirs()


_force_data_dir()


def pytest_addoption(parser: pytest.Parser) -> None:
    parser.addoption(
        "--run-slow",
        action="store_true",
        default=False,
        help="also run slow tests (large captures, multi-second processing)",
    )


def pytest_configure(config: pytest.Config) -> None:
    config.addinivalue_line("markers", "slow: long-running test; enable with --run-slow")


def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    if config.getoption("--run-slow"):
        return
    skip = pytest.mark.skip(reason="slow test; pass --run-slow to run it")
    for item in items:
        if "slow" in item.keywords:
            item.add_marker(skip)


def pytest_sessionfinish(session: pytest.Session, exitstatus: int) -> None:  # noqa: ARG001
    shutil.rmtree(_SESSION_DATA, ignore_errors=True)


# --------------------------------------------------------------------------
# paths
# --------------------------------------------------------------------------

@pytest.fixture(scope="session")
def repo_root() -> Path:
    return REPO_ROOT


@pytest.fixture(scope="session")
def backend_dir() -> Path:
    return BACKEND_DIR


@pytest.fixture(scope="session")
def scratch_dir() -> Path:
    directory = _SESSION_DATA / "scratch"
    directory.mkdir(parents=True, exist_ok=True)
    return directory


# --------------------------------------------------------------------------
# captures (generated once per session)
# --------------------------------------------------------------------------

@pytest.fixture(scope="session")
def captures(scratch_dir: Path) -> dict[str, Path]:
    import generators

    directory = scratch_dir / "captures"
    directory.mkdir(parents=True, exist_ok=True)
    return generators.build_all(directory)


@pytest.fixture(scope="session")
def http_capture(captures: dict[str, Path]) -> Path:
    return captures["http"]


@pytest.fixture(scope="session")
def dns_capture(captures: dict[str, Path]) -> Path:
    return captures["dns"]


@pytest.fixture(scope="session")
def tls_capture(captures: dict[str, Path]) -> Path:
    return captures["tls"]


@pytest.fixture(scope="session")
def syn_scan_capture(captures: dict[str, Path]) -> Path:
    return captures["syn_scan"]


@pytest.fixture(scope="session")
def arp_sweep_capture(captures: dict[str, Path]) -> Path:
    return captures["arp_sweep"]


@pytest.fixture(scope="session")
def failed_connections_capture(captures: dict[str, Path]) -> Path:
    return captures["failed_connections"]


@pytest.fixture(scope="session")
def ipv6_capture(captures: dict[str, Path]) -> Path:
    return captures["ipv6"]


@pytest.fixture(scope="session")
def udp_capture(captures: dict[str, Path]) -> Path:
    return captures["udp"]


@pytest.fixture(scope="session")
def retransmission_capture(captures: dict[str, Path]) -> Path:
    return captures["retransmission"]


@pytest.fixture(scope="session")
def http_object_capture(captures: dict[str, Path]) -> Path:
    return captures["http_object"]


@pytest.fixture(scope="session")
def combined_capture(captures: dict[str, Path]) -> Path:
    return captures["combined"]


@pytest.fixture(scope="session")
def empty_capture(captures: dict[str, Path]) -> Path:
    return captures["empty"]


@pytest.fixture(scope="session")
def malformed_capture(captures: dict[str, Path]) -> Path:
    return captures["malformed"]


@pytest.fixture(scope="session")
def truncated_capture(captures: dict[str, Path]) -> Path:
    return captures["truncated"]


@pytest.fixture(scope="session")
def large_capture(captures: dict[str, Path]) -> Path:
    return captures["large"]


# --------------------------------------------------------------------------
# database and API client
# --------------------------------------------------------------------------

@pytest.fixture(scope="session", autouse=True)
def _prepared_database():
    """Create the schema once for the whole session."""
    _force_data_dir()
    from app.db import database as db

    db.init_db()
    yield


@pytest.fixture()
def fresh_db(_prepared_database):  # noqa: ARG001
    """Empty every table that holds per-analysis data before each test."""
    from app.core import runtime_settings
    from app.db import database as db

    _force_data_dir()
    runtime_settings.clear_cache()

    tables = (
        "packets", "conversations", "streams", "http_transactions", "dns_queries",
        "tls_sessions", "protocol_sessions", "hosts", "findings", "objects",
        "credentials", "stats_cache", "jobs", "indicators", "settings", "analyses",
        "suricata_rules",
    )
    with db.get_conn() as conn:
        for table in tables:
            conn.execute(f"DELETE FROM {table}")

    # Remove uploaded captures and analysis directories from previous tests.
    from app.core.config import settings

    for directory in (settings.uploads_dir, settings.analyses_dir):
        if directory.exists():
            shutil.rmtree(directory, ignore_errors=True)
    settings.ensure_dirs()

    yield


@pytest.fixture()
def client(fresh_db):  # noqa: ARG001
    """A FastAPI test client with an isolated database and data directory."""
    try:
        from app.main import app
    except Exception as exc:  # pragma: no cover - app not importable yet
        pytest.skip(f"application is not importable: {exc}")

    from fastapi.testclient import TestClient

    with TestClient(app) as test_client:
        yield test_client


# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------

@pytest.fixture()
def run_analysis(client):  # noqa: ARG001
    """Upload a capture through the real API and wait for processing to finish.

    Returns ``(analysis_id, final_analysis_dict)``.
    """
    import time

    def _run(capture: Path, *, timeout: float = 300.0, poll: float = 0.2):
        with open(capture, "rb") as handle:
            response = client.post(
                "/api/analyses",
                files={"file": (capture.name, handle, "application/octet-stream")},
            )
        assert response.status_code == 202, response.text
        analysis_id = response.json()["id"]

        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            detail = client.get(f"/api/analyses/{analysis_id}").json()
            if detail["status"] in {"completed", "failed", "cancelled"}:
                return analysis_id, detail
            time.sleep(poll)
        raise AssertionError(f"analysis {analysis_id} did not finish within {timeout}s")

    return _run
