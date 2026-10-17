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
from app.services import baseline

router = APIRouter(prefix="/api", tags=["baseline"])


@router.get("/baseline")
def get_baseline() -> dict:
    """What the baseline is, whether baseline mode is on, and what it holds."""
    return baseline.status()


@router.put("/baseline")
def put_baseline(payload: dict) -> dict:
    """Choose the baseline capture and/or switch baseline mode.

    Body: analysis_id (an analysis id, or null to clear), enabled (true/false), label.

    An id that does not exist is 400 analysis_not_found; one that has not finished
    analysing is 400 analysis_not_ready; one that indexed no packets is 400
    analysis_empty. A baseline that cannot be compared against is worse than none,
    because it fails silently.
    """
    baseline.save_config(payload)
    return baseline.status()


@router.delete("/baseline")
def delete_baseline() -> dict:
    """Clear the baseline and switch the mode off."""
    baseline.clear_config()
    return baseline.status()


@router.get("/analyses/{analysis_id}/baseline")
def get_analysis_baseline(analysis_id: str, row=Depends(get_ready_analysis)) -> dict:
    """The comparison for one capture: counts and samples of what the baseline lacks."""
    del row  # the dependency is what makes a not-ready analysis a 4xx
    return baseline.summary(analysis_id)
