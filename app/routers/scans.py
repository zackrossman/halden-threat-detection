"""Detection routes.

Each route reads the scope resolved from the caller's verified token: a tenant
id filters the query to that tenant, and None reads across the estate. Every
read is recorded in the audit log with the caller and the scope it ran under.
"""

import logging
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app import audit
from app.auth import Caller, caller
from app.db import get_session
from app.models import Detection
from app.reporting.summary import summarise
from app.schemas import (
    ESTATE_SCOPE,
    DetectionOut,
    ScanListOut,
    ScanSummaryOut,
    TopResourceOut,
)

router = APIRouter(prefix="/v1/scans", tags=["scans"])

SessionDep = Annotated[Session, Depends(get_session)]
CallerDep = Annotated[Caller, Depends(caller)]

TOP_RESOURCE_COUNT = 5

# A caller that names no page gets this many detections; no caller can ask for
# more than the ceiling. Without a bound, one estate-wide request loads every
# detection in the table into memory and serialises it.
DEFAULT_PAGE_SIZE = 100
MAX_PAGE_SIZE = 1000


def _record_estate_wide_read(route: str, *, caller: Caller, **fields: object) -> None:
    """Record an unfiltered read, before the query runs.

    An estate-wide read crosses every tenant boundary at once. It is legitimate
    for the platform's own scheduled work and for nothing else, so it is
    recorded ahead of the query and at a level that stands out from the
    per-tenant reads around it — something to alert on, not something to find
    later by grepping.
    """
    if caller.scope is not None:
        return
    audit.record(
        "estate_wide_read",
        level=logging.WARNING,
        subject=caller.subject,
        route=route,
        **fields,
    )


@router.get("", response_model=ScanListOut)
def list_scans(
    caller: CallerDep,
    session: SessionDep,
    limit: Annotated[int, Query(ge=1, le=MAX_PAGE_SIZE)] = DEFAULT_PAGE_SIZE,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> ScanListOut:
    _record_estate_wide_read("/v1/scans", caller=caller, limit=limit, offset=offset)
    query = select(Detection).order_by(Detection.detected_at.desc())
    if caller.scope is not None:
        query = query.where(Detection.tenant_id == caller.scope)
    detections = session.scalars(query.limit(limit).offset(offset)).all()
    by_severity = summarise(session, caller.scope)

    audit.record(
        "detections_listed",
        subject=caller.subject,
        scope=caller.audited_scope,
        route="/v1/scans",
        returned=len(detections),
        limit=limit,
        offset=offset,
    )
    return ScanListOut(
        scope=caller.scope or ESTATE_SCOPE,
        detections=[DetectionOut.model_validate(d) for d in detections],
        summary=by_severity,
        limit=limit,
        offset=offset,
        total=sum(by_severity.values()),
    )


@router.get("/summary", response_model=ScanSummaryOut)
def summarise_scans(caller: CallerDep, session: SessionDep) -> ScanSummaryOut:
    """Counts by severity plus the most recent detections, over the read scope."""
    _record_estate_wide_read("/v1/scans/summary", caller=caller)
    recent = select(Detection).order_by(Detection.detected_at.desc())
    if caller.scope is not None:
        recent = recent.where(Detection.tenant_id == caller.scope)
    by_severity = summarise(session, caller.scope)
    top_resources = session.scalars(recent.limit(TOP_RESOURCE_COUNT)).all()

    audit.record(
        "detections_summarised",
        subject=caller.subject,
        scope=caller.audited_scope,
        route="/v1/scans/summary",
        returned=len(top_resources),
    )
    return ScanSummaryOut(
        scope=caller.scope or ESTATE_SCOPE,
        total=sum(by_severity.values()),
        by_severity=by_severity,
        top_resources=[TopResourceOut.model_validate(d) for d in top_resources],
    )


@router.get("/{scan_id}", response_model=DetectionOut)
def get_scan(scan_id: str, caller: CallerDep, session: SessionDep) -> DetectionOut:
    _record_estate_wide_read("/v1/scans/{scan_id}", caller=caller, detection_id=scan_id)
    query = select(Detection).where(Detection.id == scan_id)
    if caller.scope is not None:
        query = query.where(Detection.tenant_id == caller.scope)
    detection = session.scalars(query).one_or_none()

    audit.record(
        "detection_fetched",
        subject=caller.subject,
        scope=caller.audited_scope,
        route="/v1/scans/{scan_id}",
        detection_id=scan_id,
        found=detection is not None,
    )
    if detection is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="detection not found"
        )
    return DetectionOut.model_validate(detection)
