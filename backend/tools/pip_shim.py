"""Development-environment shim — NOT used by the application at runtime.

CPython on Windows emulates POSIX modes by writing a restrictive ACL when a
directory is created with ``mode=0o700``.  Under the DSH ``workspace-write``
file sandbox the resulting directory is not writable by the process token, so
``tempfile.mkdtemp()`` (used internally by pip, and by ``python -m venv``)
fails with ``PermissionError``.

This module forces permissive directory creation.  It is imported explicitly
before invoking pip::

    python tools/pip_shim.py install <packages...>

It has no effect on the application itself and is not required inside Docker or
on a normal developer machine.
"""

from __future__ import annotations

import os
import sys
import tempfile

_real_mkdir = os.mkdir


def _permissive_mkdir(path, mode=0o777, *args, **kwargs):  # noqa: ANN001
    return _real_mkdir(path, 0o777, *args, **kwargs)


# Patch os.mkdir for this process, and the alias tempfile holds.
os.mkdir = _permissive_mkdir  # type: ignore[assignment]
if hasattr(tempfile, "_os"):
    tempfile._os.mkdir = _permissive_mkdir  # type: ignore[attr-defined]


def main() -> int:
    from pip._internal.cli.main import main as pip_main

    return pip_main(sys.argv[1:])


if __name__ == "__main__":
    raise SystemExit(main())
