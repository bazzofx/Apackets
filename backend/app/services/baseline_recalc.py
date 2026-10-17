"""Re-run the baseline rules after the reference capture changes.

Choosing a baseline - or switching the mode, or clearing it - changes what the seven
``baseline_*`` rules would say about *every* analysis, not just the one on screen. The
findings they already wrote are therefore out of date the moment the configuration is
written, and asking the analyst to remember **Re-run rules** on each capture in turn is
how a comparison silently lies.

This module closes that gap: the baseline endpoints call :func:`start`, which sweeps the
completed analyses in a background thread and replaces only the baseline findings. Three
properties matter and are why it is a sweep of one rule family rather than ``analyze``:

* **It is scoped.** ``detection_engine.rerun_rules`` deletes and re-writes only the
  ``baseline_*`` rows, so Suricata matches (which ``analyze`` erases and a separate run
  re-creates) and the other built-in findings are untouched. The cost is one rule family
  per analysis, not seventeen.
* **It is off the request path.** A full library takes tens of seconds - the measured
  figures are in ``Documentation/Baseline.md`` - so the endpoint returns immediately and
  the interface polls :func:`state` while the sweep runs.
* **It is single-flight.** A second change while a sweep is running does not start a
  second thread; it marks the sweep to run again afterwards, so the final state on disk
  always matches the final configuration.
"""

from __future__ import annotations

import threading
import time
from collections.abc import Sequence
from typing import Any

from app.core.config import settings
from app.core.logging import get_logger
from app.db import database as db
from app.services import detection_engine

log = get_logger("apackets.baseline_recalc")

#: The rule family this module owns. Every rule the baseline contributes is named this way.
RULE_IDS: tuple[str, ...] = tuple(
    rule_id for rule_id in detection_engine.RULES if rule_id.startswith("baseline_")
)

_lock = threading.Lock()
_thread: threading.Thread | None = None
_pending = False
_state: dict[str, Any] = {
    "running": False,
    "trigger": None,
    "started_at": None,
    "finished_at": None,
    "total": 0,
    "done": 0,
    "current": None,
    "current_id": None,
    "findings": 0,
    "errors": [],
    "seconds": None,
}


def state() -> dict[str, Any]:
    """The sweep's progress, safe to serialise into an API response."""
    with _lock:
        snapshot = dict(_state)
        snapshot["errors"] = list(_state["errors"])
    snapshot["rule_ids"] = list(RULE_IDS)
    snapshot["auto"] = bool(settings.baseline_auto_recalc)
    return snapshot


def recompute(analysis_id: str) -> dict[str, Any]:
    """Replace one analysis' baseline findings, synchronously.

    The building block of the sweep, and the piece worth testing directly: it does not
    touch findings from any other rule, so it can be called on a live analysis.
    """
    return detection_engine.rerun_rules(analysis_id, RULE_IDS)


def _candidates() -> list[dict[str, Any]]:
    """Completed captures that can carry findings, newest first."""
    return [
        dict(row)
        for row in db.query_all(
            """
            SELECT id, original_filename, packet_count FROM analyses
             WHERE status = 'completed' AND COALESCE(packet_count, 0) > 0
             ORDER BY created_at DESC
            """
        )
    ]


def _sweep_once() -> None:
    started = time.monotonic()
    rows: Sequence[dict[str, Any]] = _candidates()
    with _lock:
        _state.update(total=len(rows), done=0, findings=0, errors=[], current=None, current_id=None)

    for row in rows:
        with _lock:
            _state["current"] = row["original_filename"]
            _state["current_id"] = row["id"]
        try:
            stats = recompute(row["id"])
        except Exception as exc:  # one bad analysis must not stop the sweep
            log.exception("baseline recompute failed for %s", row["id"])
            with _lock:
                _state["errors"].append(f"{row['original_filename']}: {type(exc).__name__}: {exc}")
        else:
            with _lock:
                _state["findings"] += int(stats.get("findings") or 0)
            log.info(
                "baseline findings recomputed for %s: %d finding(s) in %.2fs",
                row["original_filename"],
                stats.get("findings", 0),
                stats.get("seconds", 0.0),
            )
        finally:
            with _lock:
                _state["done"] += 1

    with _lock:
        _state["seconds"] = round(time.monotonic() - started, 3)


def _worker() -> None:
    """Run sweeps until no further change arrived while one was running."""
    global _pending, _thread
    while True:
        with _lock:
            if not _pending:
                _state["running"] = False
                _state["current"] = None
                _state["current_id"] = None
                _state["finished_at"] = time.time()
                _thread = None
                return
            _pending = False
        try:
            _sweep_once()
        except Exception:  # pragma: no cover - defensive: never kill the sweeper
            log.exception("baseline recompute sweep failed")


def start(trigger: str = "baseline changed") -> dict[str, Any]:
    """Schedule a sweep (or a second one) and return the current state.

    Returns immediately: the caller is an HTTP request. When auto-recalculation is
    switched off - ``APACKETS_BASELINE_AUTO_RECALC=0``, which the test suite sets -
    nothing is scheduled and the state says so.
    """
    global _pending, _thread
    if not settings.baseline_auto_recalc:
        return state()

    with _lock:
        _pending = True
        if _thread is not None:
            # A sweep is already running. It will pick this change up on its next
            # pass, so the last write always wins.
            return dict(_state)
        _state.update(
            running=True,
            trigger=trigger,
            started_at=time.time(),
            finished_at=None,
            errors=[],
            seconds=None,
        )
        thread = threading.Thread(target=_worker, name="baseline-recalc", daemon=True)
        _thread = thread
    thread.start()
    return state()


def reset() -> None:
    """Forget the recorded state. Used by tests; never called by the application."""
    global _pending, _thread
    with _lock:
        _pending = False
        _thread = None
        _state.update(
            running=False,
            trigger=None,
            started_at=None,
            finished_at=None,
            total=0,
            done=0,
            current=None,
            current_id=None,
            findings=0,
            errors=[],
            seconds=None,
        )


__all__ = ["RULE_IDS", "recompute", "reset", "start", "state"]
