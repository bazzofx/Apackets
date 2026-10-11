"""Entity profile endpoints for the Investigate section.

``GET /api/analyses/{analysis_id}/profile`` resolves a free-text query to the
entities the analysis contains, and
``GET /api/analyses/{analysis_id}/profile/{kind}/{entity}`` answers the question
set of ``docs/ENTITY_PROFILE.md`` §4 for one of them. All computation lives in
:mod:`app.services.entity_profile`; this module only validates the parameters and
applies the shared readiness gate, so an unknown id is 404 ``analysis_not_found``
and an unfinished one is 409 ``analysis_not_ready`` exactly as everywhere else.

An unknown *entity* is not an error: the profile endpoint answers 200 with every
question ``not_applicable`` and a reason, so a stale link explains itself instead
of 404ing (§2).
"""

from __future__ import annotations

from typing import Literal

from fastapi import APIRouter, Query

from app.api import deps
from app.core.errors import unprocessable
from app.core.logging import get_logger
from app.services import entity_profile

log = get_logger("apackets.api.profile")

router = APIRouter(prefix="/api/analyses/{analysis_id}", tags=["profile"])

MIN_QUERY_LENGTH = 1
MAX_QUERY_LENGTH = 200
DEFAULT_LIMIT = 25
MAX_LIMIT = 100


@router.get("/profile")
def search_entities(
    analysis_id: str,
    q: str = Query(
        ...,
        min_length=MIN_QUERY_LENGTH,
        max_length=MAX_QUERY_LENGTH,
        description="Free-text query: an address, part of one, a name or a URL",
    ),
    limit: int = Query(
        DEFAULT_LIMIT,
        ge=1,
        le=MAX_LIMIT,
        description="Maximum matches returned",
    ),
) -> dict:
    """Resolve one free-text query to the entities this analysis contains.

    Matching is a case-insensitive substring over the indexed value (§2): an
    address-shaped query matches addresses, one containing ``://`` or starting
    with ``/`` matches URLs, and anything else matches all three kinds. The
    response is empty when nothing matches — the page says so rather than showing
    a placeholder entity.
    """
    deps.get_ready_analysis(analysis_id)

    # A query of nothing but spaces trims away to nothing, which is not a query.
    # The length bound is enforced by `Query` above; this is the other half of
    # "1–200 characters after trimming".
    query = q.strip()
    if not query:
        raise unprocessable(
            "invalid_query",
            "`q` must contain at least one non-space character.",
            {"q": q},
        )
    return entity_profile.search(analysis_id, query, limit=limit)


@router.get("/profile/{kind}/{entity:path}")
def get_profile(
    analysis_id: str,
    kind: Literal["ip", "domain", "url"],
    entity: str,
) -> dict:
    """Every §4 question for one entity, in contract order.

    ``{entity}`` is the ``entity`` value of a search match, percent-encoded. It is
    captured as a path so a request URI — which contains ``/`` — survives the trip
    through the client and the URL. A ``kind`` outside the three of §2 is a 422,
    and an entity the index does not contain is a 200 whose questions all report
    ``not_applicable`` with the reason.
    """
    deps.get_ready_analysis(analysis_id)
    return entity_profile.profile(analysis_id, kind, entity)
