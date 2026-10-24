"""Threat Hunt endpoint.

``GET /api/analyses/{analysis_id}/threat-hunt`` returns the 17 indicators of
``docs/THREAT_HUNT.md`` §1 for one finished analysis. All computation lives in
:mod:`app.services.threat_hunt`; this module only validates the query parameters
and applies the shared readiness gate, so an unknown id is 404
``analysis_not_found`` and an unfinished one is 409 ``analysis_not_ready``
exactly as everywhere else in the API.
"""

from __future__ import annotations

from fastapi import APIRouter, Query

from app.api import deps
from app.core.logging import get_logger
from app.services import threat_hunt

log = get_logger("shadowpackets.api.threat_hunt")

router = APIRouter(prefix="/api/analyses/{analysis_id}", tags=["threat-hunt"])

DEFAULT_WINDOW = 60
DEFAULT_TOP = 12
MIN_WINDOW = 5
MAX_WINDOW = 3600
MIN_TOP = 1
MAX_TOP = 50


@router.get("/threat-hunt")
def get_threat_hunt(
    analysis_id: str,
    window: int = Query(
        DEFAULT_WINDOW,
        ge=MIN_WINDOW,
        le=MAX_WINDOW,
        description="Seconds per bucket for every time series",
    ),
    top: int = Query(
        DEFAULT_TOP,
        ge=MIN_TOP,
        le=MAX_TOP,
        description="Rows per ranked visual",
    ),
) -> dict:
    """Every Threat Hunt indicator for this analysis, in the order of §1.

    The response is an aggregate over the index ShadowPackets built for the capture —
    no capture is re-read — so it stays fast and keeps working after the upload
    has been purged. Each indicator reports whether it could be computed at all
    (``availability``), the threshold it applied when it found nothing, and what
    its pattern does not prove (``caveat``).
    """
    deps.get_ready_analysis(analysis_id)
    return threat_hunt.analyze(analysis_id, window=window, top=top)
