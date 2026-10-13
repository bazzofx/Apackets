"""The packet pivot: filter composition, process start-up and the route.

Everything here is asserted without opening a window. The process start is
intercepted at :func:`subprocess.Popen`, which is the only place a program can
leave this application from a request, so "nothing was launched" and "exactly
this was launched" are both statements about recorded calls rather than about a
GUI that may or may not have appeared.
"""

from __future__ import annotations

import ipaddress
import shutil
import subprocess
import time
import uuid
from pathlib import Path

import pytest

from app.core.config import settings
from app.db import database as db
from app.services import tshark, wireshark

ANALYSIS_ID = "a1b2c3d4e5f60718293a4b5c6d7e8f90"
PUBLIC_IP = "150.171.109.217"

#: Scratch files live inside the repository, never in the OS temp directory: the
#: test process is not always allowed to write there, and a test that cannot
#: create its fixture is a test that reports nothing.
SCRATCH_ROOT = Path(__file__).resolve().parents[2] / ".tmp" / "wireshark-tests"


@pytest.fixture()
def scratch() -> Path:
    """A fresh directory for one test, removed afterwards."""
    path = SCRATCH_ROOT / uuid.uuid4().hex
    path.mkdir(parents=True, exist_ok=True)
    yield path
    shutil.rmtree(path, ignore_errors=True)


@pytest.fixture()
def make_analysis(fresh_db):  # noqa: ARG001 - fresh_db empties the tables first
    """A completed analysis whose capture really exists on disk.

    The routes gate on ``analysis_ready_row``, which insists the retained capture
    is still there, so the file is written rather than described — and a test can
    delete it to check the ``410``.
    """

    def _make(*, status: str = "completed", capture: bool = True) -> dict:
        now = time.time()
        path = settings.uploads_dir / f"{ANALYSIS_ID}.pcap"
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
                (ANALYSIS_ID, str(path), status, status, now, now),
            )
        return {"id": ANALYSIS_ID, "stored_path": str(path)}

    return _make


@pytest.fixture(autouse=True)
def reset_caches():
    """Both binary caches are process-wide; a test must not inherit a path."""
    tshark._reset_binary_cache()
    wireshark._reset_binary_cache()
    yield
    tshark._reset_binary_cache()
    wireshark._reset_binary_cache()


class Spawn:
    """Records every ``Popen`` and answers with a fake process."""

    def __init__(self, fail: Exception | None = None) -> None:
        self.calls: list[tuple[list[str], dict]] = []
        self.fail = fail

    def __call__(self, argv, **kwargs):  # noqa: ANN001, ANN003
        self.calls.append((list(argv), dict(kwargs)))
        if self.fail is not None:
            raise self.fail
        return _FakeProcess()


class _FakeProcess:
    pid = 4242

    def wait(self, timeout=None):  # noqa: ANN001
        return 0


@pytest.fixture
def spawn(monkeypatch: pytest.MonkeyPatch) -> Spawn:
    recorder = Spawn()
    monkeypatch.setattr(subprocess, "Popen", recorder)
    return recorder


@pytest.fixture
def installed(monkeypatch: pytest.MonkeyPatch, scratch: Path) -> str:
    """A Wireshark that seems to be installed, without one being."""
    binary = scratch / "Wireshark.exe"
    binary.write_bytes(b"MZ")
    monkeypatch.setattr(wireshark, "resolve_binary", lambda: str(binary))
    return str(binary)


@pytest.fixture
def capture(scratch: Path) -> Path:
    path = scratch / "capture.pcap"
    path.write_bytes(b"\xd4\xc3\xb2\xa1")
    return path


# --------------------------------------------------------------------------
# 1. the filter is composed here, and cannot be syntax from outside
# --------------------------------------------------------------------------


def test_an_address_alone_selects_every_frame_it_appears_in():
    assert wireshark.build_filter(PUBLIC_IP) == f"ip.addr == {PUBLIC_IP}"


def test_a_tcp_conversation_narrows_to_that_stream_and_that_address():
    """"tcp.stream == N" is the number this application stores, so it is exact."""
    assert wireshark.build_filter(PUBLIC_IP, transport="tcp", stream_id=7) == (
        f"ip.addr == {PUBLIC_IP} && tcp.stream == 7"
    )


def test_a_udp_conversation_never_uses_a_stream_id():
    """Wireshark's udp.stream is not the number in conversations.stream_id."""
    display = wireshark.build_filter(PUBLIC_IP, transport="udp", stream_id=7, port=53)
    assert "stream" not in display
    assert display == f"ip.addr == {PUBLIC_IP} && port == 53"


@pytest.mark.parametrize(
    "value",
    [
        "8.8.8.8 && tcp.port == 80",
        "8.8.8.8; rm -rf /",
        "8.8.8.8'",
        '"8.8.8.8"',
        "$(whoami)",
        "8.8.8.8 -Y ip",
        "not-an-address",
        "",
        "8.8.8.8/24",
    ],
)
def test_anything_that_is_not_an_address_is_refused_before_a_filter_exists(value):
    """The one door onto a command line accepts addresses and nothing else."""
    with pytest.raises(wireshark.WiresharkError):
        wireshark.build_filter(value)


def test_the_filter_carries_only_what_this_module_produced():
    display = wireshark.build_filter("::ffff:150.171.109.217", transport="tcp", stream_id=12)
    assert display == "ip.addr == 150.171.109.217 && tcp.stream == 12"


@pytest.mark.parametrize("stream_id", [-1, "7", 1.5, None])
def test_a_stream_id_that_is_not_a_stream_id_is_refused(stream_id):
    if stream_id is None:
        assert wireshark.build_filter(PUBLIC_IP, transport="tcp") == f"ip.addr == {PUBLIC_IP}"
        return
    with pytest.raises(wireshark.WiresharkError):
        wireshark.build_filter(PUBLIC_IP, transport="tcp", stream_id=stream_id)


@pytest.mark.parametrize("port", [-1, 70000, "53"])
def test_a_port_that_is_not_a_port_is_refused(port):
    with pytest.raises(wireshark.WiresharkError):
        wireshark.build_filter(PUBLIC_IP, transport="udp", stream_id=3, port=port)


def test_a_canonical_address_is_what_reaches_the_filter():
    """A hostname, a padded address or a mapped one all become one exact string."""
    assert wireshark.build_filter("  8.8.8.8  ") == "ip.addr == 8.8.8.8"
    assert wireshark.build_filter("::ffff:8.8.8.8") == "ip.addr == 8.8.8.8"


# --------------------------------------------------------------------------
# 2. what is started, and how
# --------------------------------------------------------------------------


def test_the_window_opens_filtered_not_pre_processed(installed, spawn, capture):
    """-Y shows the conversation at once; -R would mean waiting for a full pass."""
    result = wireshark.open_capture(capture, PUBLIC_IP)
    argv, kwargs = spawn.calls[0]
    assert argv[:3] == [installed, "-r", str(capture)]
    assert argv[3:5] == ["-Y", f"ip.addr == {PUBLIC_IP}"]
    assert "-R" not in argv and "-2" not in argv
    assert kwargs["shell"] is False
    assert result["filter"] == f"ip.addr == {PUBLIC_IP}"
    assert result["launched"] is True
    assert result["pid"] == 4242


def test_the_selection_jumps_to_the_first_matching_packet(installed, spawn, capture):
    """-J is what opens "those specific packets" rather than the whole file."""
    wireshark.open_capture(capture, PUBLIC_IP)
    argv = spawn.calls[0][0]
    assert argv[5:7] == ["-J", f"ip.addr == {PUBLIC_IP}"], argv
    # The display filter and the jump filter are the same expression: one defines
    # the view, the other selects the first frame in it.
    assert argv[4] == argv[6]


def test_the_jump_filter_follows_the_conversation_too(installed, spawn, capture):
    wireshark.open_capture(capture, PUBLIC_IP, transport="tcp", stream_id=30)
    argv = spawn.calls[0][0]
    conversation = f"ip.addr == {PUBLIC_IP} && tcp.stream == 30"
    assert argv[3:5] == ["-Y", conversation]
    assert argv[5:7] == ["-J", conversation]
    assert "-g" not in argv, "a packet number would be wrong here: the filter is the precise thing"


def test_no_shell_is_ever_used(installed, spawn, capture):
    wireshark.open_capture(capture, PUBLIC_IP)
    _argv, kwargs = spawn.calls[0]
    assert kwargs["shell"] is False
    assert isinstance(spawn.calls[0][0], list)


def test_the_process_is_detached_so_the_request_does_not_wait_for_the_gui(installed, spawn, capture):
    wireshark.open_capture(capture, PUBLIC_IP)
    _argv, kwargs = spawn.calls[0]
    assert kwargs["close_fds"] is True
    if subprocess.os.name == "nt":
        # DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP
        assert kwargs["creationflags"] == 0x00000008 | 0x00000200
    else:  # pragma: no cover - platform dependent
        assert kwargs["start_new_session"] is True


def test_the_capture_named_is_the_one_given(installed, spawn, capture):
    wireshark.open_capture(capture, PUBLIC_IP, transport="tcp", stream_id=36)
    argv = spawn.calls[0][0]
    assert argv[2] == str(capture)
    assert argv[4] == f"ip.addr == {PUBLIC_IP} && tcp.stream == 36"


def test_a_read_filter_is_available_when_a_caller_wants_to_wait(installed, spawn, capture):
    wireshark.open_capture(capture, PUBLIC_IP, read_filter=True)
    argv = spawn.calls[0][0]
    assert argv[3:5] == ["-2", "-R"]


def test_a_missing_capture_is_refused_and_nothing_is_started(installed, spawn, scratch):
    with pytest.raises(wireshark.WiresharkError) as excinfo:
        wireshark.open_capture(scratch / "gone.pcap", PUBLIC_IP)
    assert "no longer on disk" in str(excinfo.value)
    assert spawn.calls == []


def test_no_wireshark_means_no_process_and_a_reason(monkeypatch, spawn, capture):
    monkeypatch.setattr(wireshark, "resolve_binary", lambda: None)
    with pytest.raises(wireshark.WiresharkError) as excinfo:
        wireshark.open_capture(capture, PUBLIC_IP)
    assert "not found" in str(excinfo.value)
    assert spawn.calls == []


def test_a_wireshark_that_cannot_be_started_reports_why(monkeypatch, installed, capture):
    failing = Spawn(fail=OSError("Access is denied"))
    monkeypatch.setattr(subprocess, "Popen", failing)
    with pytest.raises(wireshark.WiresharkError) as excinfo:
        wireshark.open_capture(capture, PUBLIC_IP)
    assert "could not be started" in str(excinfo.value)


# --------------------------------------------------------------------------
# 3. finding the binary
# --------------------------------------------------------------------------


def test_the_gui_is_looked_for_next_to_the_dissector(scratch, monkeypatch):
    """TShark and Wireshark ship together, so TShark's directory is the best hint."""
    wireshark._reset_binary_cache()
    binary = scratch / "Wireshark.exe"
    binary.write_bytes(b"MZ")
    monkeypatch.setattr(settings, "wireshark_path", "wireshark")
    monkeypatch.setattr(tshark, "resolve_binary", lambda name="tshark": str(scratch / "tshark.exe"))
    monkeypatch.setattr(tshark, "install_dirs", lambda: [])
    monkeypatch.setattr(wireshark.shutil, "which", lambda name: None)
    assert wireshark.resolve_binary() == str(binary)


def test_an_explicit_path_wins(scratch, monkeypatch):
    wireshark._reset_binary_cache()
    binary = scratch / "gui.exe"
    binary.write_bytes(b"MZ")
    monkeypatch.setattr(settings, "wireshark_path", str(binary))
    assert wireshark.resolve_binary() == str(binary)


def test_availability_reports_the_reason_rather_than_raising(monkeypatch):
    monkeypatch.setattr(wireshark, "resolve_binary", lambda: None)
    state = wireshark.availability()
    assert state["available"] is False
    assert state["path"] is None
    assert "not found" in state["error"]


def test_availability_finds_the_real_install_here():
    """On this machine Wireshark is installed; if it is not, this says so."""
    state = wireshark.availability()
    if state["available"]:
        assert Path(state["path"]).is_file()
        assert Path(state["path"]).name.lower().startswith("wireshark")
    else:
        assert state["error"]


# --------------------------------------------------------------------------
# 4. the routes
# --------------------------------------------------------------------------


def test_the_get_reports_availability_without_starting_the_gui(client, make_analysis, spawn, monkeypatch):
    analysis = make_analysis()
    response = client.get(f"/api/analyses/{analysis['id']}/wireshark")
    assert response.status_code == 200
    body = response.json()
    assert set(body) == {"analysis_id", "available", "executable", "version", "reason"}
    assert spawn.calls, "the version probe is a subprocess too"
    started = [call[0][0] for call in spawn.calls]
    assert not any("wireshark" in Path(binary).name.lower() for binary in started), (
        f"the availability probe must not start a GUI: {started}"
    )
    assert all(Path(binary).name.lower().startswith("tshark") for binary in started), started


def test_availability_asks_for_the_version_once_per_process(monkeypatch, spawn):
    """It is asked on every page load, so the answer is memoised."""
    wireshark._reset_binary_cache()
    for _ in range(4):
        wireshark.availability()
    assert len(spawn.calls) == 1, f"{len(spawn.calls)} version probes for four calls"
    assert spawn.calls[0][0][1] == "--version"


def test_the_post_starts_the_gui_with_the_composed_filter(
    client, make_analysis, spawn, installed
):
    analysis = make_analysis()
    response = client.post(
        f"/api/analyses/{analysis['id']}/wireshark",
        json={"ip": PUBLIC_IP},
    )
    assert response.status_code == 200
    body = response.json()
    assert body["launched"] is True
    assert body["filter"] == f"ip.addr == {PUBLIC_IP}"
    assert body["pid"] == 4242
    argv = spawn.calls[0][0]
    assert argv[0] == installed
    assert argv[1] == "-r"
    assert argv[3] == "-Y"


def test_the_post_carries_the_conversation_into_the_filter(client, make_analysis, spawn, installed):
    analysis = make_analysis()
    response = client.post(
        f"/api/analyses/{analysis['id']}/wireshark",
        json={"ip": PUBLIC_IP, "transport": "tcp", "stream_id": 30},
    )
    assert response.status_code == 200
    assert response.json()["filter"] == f"ip.addr == {PUBLIC_IP} && tcp.stream == 30"


def test_the_post_never_accepts_a_filter_from_the_client(client, make_analysis, spawn, installed):
    """A field the model does not declare cannot reach the command line."""
    analysis = make_analysis()
    response = client.post(
        f"/api/analyses/{analysis['id']}/wireshark",
        json={"ip": PUBLIC_IP, "filter": "ip.addr == 8.8.8.8; calc.exe"},
    )
    assert response.status_code == 200
    argv = spawn.calls[0][0]
    assert "calc.exe" not in " ".join(argv)
    assert argv[-1] == f"ip.addr == {PUBLIC_IP}"


@pytest.mark.parametrize(
    "payload",
    [
        {"ip": "not-an-address"},
        {"ip": "8.8.8.8 && tcp.port == 80"},
        {"ip": PUBLIC_IP, "stream_id": -1},
        {"ip": PUBLIC_IP, "port": 70000},
        {},
    ],
)
def test_a_request_that_is_not_an_address_is_422_and_starts_nothing(
    client, make_analysis, spawn, installed, payload
):
    analysis = make_analysis()
    response = client.post(f"/api/analyses/{analysis['id']}/wireshark", json=payload)
    assert response.status_code == 422
    assert spawn.calls == []


def test_no_wireshark_is_503_with_the_reason(client, make_analysis, spawn, monkeypatch):
    monkeypatch.setattr(wireshark, "resolve_binary", lambda: None)
    analysis = make_analysis()
    response = client.post(f"/api/analyses/{analysis['id']}/wireshark", json={"ip": PUBLIC_IP})
    assert response.status_code == 503
    error = response.json()["error"]
    assert error["code"] == "wireshark_unavailable"
    assert "not found" in error["message"]
    assert spawn.calls == []


def test_a_missing_capture_is_410(client, make_analysis, spawn, installed):
    analysis = make_analysis()
    Path(analysis["stored_path"]).unlink()
    response = client.post(f"/api/analyses/{analysis['id']}/wireshark", json={"ip": PUBLIC_IP})
    assert response.status_code == 410
    assert response.json()["error"]["code"] == "capture_missing"
    assert spawn.calls == []


def test_an_unfinished_analysis_is_409(client, make_analysis, spawn, installed):
    analysis = make_analysis(status="running")
    response = client.post(f"/api/analyses/{analysis['id']}/wireshark", json={"ip": PUBLIC_IP})
    assert response.status_code == 409
    assert spawn.calls == []


def test_an_unknown_analysis_is_404(client, spawn, installed):
    response = client.post("/api/analyses/deadbeefdeadbeefdeadbeefdeadbeef/wireshark", json={"ip": PUBLIC_IP})
    assert response.status_code == 404
    assert spawn.calls == []


def test_capabilities_reports_the_pivot(client, monkeypatch):
    body = client.get("/api/capabilities").json()
    assert "wireshark" in body
    assert set(body["wireshark"]) == {"available", "path", "version", "error"}
    assert body["features"]["wireshark"] is True


def test_a_private_address_is_still_a_valid_pivot(client, make_analysis, spawn, installed):
    """The menu works on a private address too: it is a capture, not a registry."""
    analysis = make_analysis()
    response = client.post(f"/api/analyses/{analysis['id']}/wireshark", json={"ip": "10.10.1.128"})
    assert response.status_code == 200
    assert response.json()["filter"] == "ip.addr == 10.10.1.128"


def test_ipv6_is_composed_the_same_way(client, make_analysis, spawn, installed):
    analysis = make_analysis()
    address = str(ipaddress.ip_address("2001:4860:4860::8888"))
    response = client.post(f"/api/analyses/{analysis['id']}/wireshark", json={"ip": address})
    assert response.status_code == 200
    assert response.json()["filter"] == f"ip.addr == {address}"
