"""The .env bootstrap: it must not corrupt Windows paths.

``python-dotenv`` expands escape sequences in double-quoted values, so a plain
``"C:\\...\\tshark.exe"`` loses the ``\\t`` to a tab. The bootstrap therefore
writes single-quoted paths; this test pins that contract.
"""

from __future__ import annotations

import io
import runpy
from pathlib import Path

from dotenv import dotenv_values

TOOL = Path(__file__).resolve().parents[1] / "tools" / "init_env.py"


def test_bootstrap_quotes_windows_paths_without_escape_expansion() -> None:
    module = runpy.run_path(str(TOOL))
    lines: list[str] = []
    path = r"C:\Program Files\Wireshark\tshark.exe"

    module["set_setting"](lines, "SHADOWPACKETS_TSHARK_PATH", path)

    assert lines == [f"SHADOWPACKETS_TSHARK_PATH='{path}'"]
    parsed = dotenv_values(stream=io.StringIO("\n".join(lines)))
    assert parsed["SHADOWPACKETS_TSHARK_PATH"] == path
    assert "\t" not in parsed["SHADOWPACKETS_TSHARK_PATH"]


def test_bootstrap_candidates_differ_by_operating_system() -> None:
    module = runpy.run_path(str(TOOL))

    linux = [str(path) for path in module["_candidate_paths"]("tshark", "Linux")]
    windows = [str(path) for path in module["_candidate_paths"]("tshark", "Windows")]

    assert any(Path(path).parts[-2:] == ("bin", "tshark") for path in linux)
    assert any("Wireshark" in path and path.endswith("tshark.exe") for path in windows)
