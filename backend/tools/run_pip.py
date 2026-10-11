"""Run pip in-process with the sandbox mkdir shim applied.

Usage (from the repository root)::

    backend\\.venv\\Scripts\\python.exe backend\\tools\\run_pip.py install fastapi

Only needed in the DSH sandboxed development environment; see pip_shim.py.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import pip_shim  # noqa: E402  (applies the mkdir patch on import)

if __name__ == "__main__":
    sys.exit(pip_shim.main())
