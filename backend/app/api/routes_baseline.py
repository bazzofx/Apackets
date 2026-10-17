"""The baseline network: which capture describes the network, and whether it is in force.

One global baseline. The baseline is an ordinary analysed capture that has been marked
as the reference; this router only decides *which* one it is, whether comparison is on,
and reports what it holds. The comparison itself, and the rules built on it, live in
app.services.baseline.

Nothing here re-analyses anything: picking a baseline is a pointer change, and the
stored findings of existing analyses keep the baseline they were computed with until
they are re-run. That is stated in the response rather than left to be discovered.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends

from app.api.deps import get_ready_analysis
from app.services import baseline, baseline_recalc

router = APIRouter(prefix="/api", tags=["baseline"])


def _status() -> dict:
    """The baseline state plus the progress of any findings recalculation.

    The two travel together because they are one answer: a baseline that was just
    chosen while the findings still describe the previous one is a state an interface
    has to be able to draw, so it is reported rather than left to be guessed.
    """
    body = baseline.status()
    body["recalc"] = baseline_recalc.state()
    return body


@router.get("/baseline")
def get_baseline() -> dict:
    """What the baseline is, whether baseline mode is on, and what it holds."""
    return _status()


@router.put("/baseline")
def put_baseline(payload: dict) -> dict:
    """Choose the baseline capture and/or switch baseline mode.

    Body: analysis_id (an analysis id, or null to clear), enabled (true/false), label,
    and recalc (false to skip the findings sweep, which a scripted caller may prefer to
    run itself).

    An id that does not exist is 400 analysis_not_found; one that has not finished
    analysing is 400 analysis_not_ready; one that indexed no packets is 400
    analysis_empty. A baseline that cannot be compared against is worse than none,
    because it fails silently.

    Every accepted change schedules a background recalculation of the baseline findings,
    because the comparison the seven rules describe changed for every analysis, not only
    for the one being looked at. It returns immediately; the response carries the
    recalculation's progress under ``recalc``.
    """
    baseline.save_config(payload)
    if payload.get("recalc", True):
        baseline_recalc.start("the baseline was changed")
    return _status()


@router.delete("/baseline")
def delete_baseline() -> dict:
    """Clear the baseline and switch the mode off.

    The baseline rules stop reporting anything, so their stored findings are swept away
    the same way a change is: in the background, under ``recalc``.
    """
    baseline.clear_config()
    baseline_recalc.start("the baseline was cleared")
    return _status()


@router.post("/baseline/recalculate")
def recalculate_baseline_findings() -> dict:
    """Re-run the baseline rules over every analysis, on request.

    The same sweep a change triggers, exposed so it can be repeated after, say,
    re-enabling a baseline rule in Alert Settings. Answers 200 either way: the sweep
    runs in the background and ``recalc`` reports it.
    """
    baseline_recalc.start("a manual request")
    return _status()


@router.get("/analyses/{analysis_id}/baseline")
def get_analysis_baseline(analysis_id: str, row=Depends(get_ready_analysis)) -> dict:
    """The comparison for one capture: counts and samples of what the baseline lacks."""
    del row  # the dependency is what makes a not-ready analysis a 4xx
    return baseline.summary(analysis_id)
