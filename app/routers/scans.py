"""Detection routes.

Each route reads the scope resolved from the caller's verified token: a tenant
id filters the query to that tenant, and None reads across the estate.
"""

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.auth import caller_read_scope
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
ReadScopeDep = Annotated[str | None, Depends(caller_read_scope)]

TOP_RESOURCE_COUNT = 5


@router.get("", response_model=ScanListOut)
def list_scans(scope: ReadScopeDep, session: SessionDep) -> ScanListOut:
    query = select(Detection).order_by(Detection.detected_at.desc())
    if scope is not None:
        query = query.where(Detection.tenant_id == scope)
    detections = session.scalars(query).all()
    return ScanListOut(
        scope=scope or ESTATE_SCOPE,
        detections=[DetectionOut.model_validate(d) for d in detections],
        summary=summarise(session, scope),
    )


@router.get("/summary", response_model=ScanSummaryOut)
def summarise_scans(scope: ReadScopeDep, session: SessionDep) -> ScanSummaryOut:
    """Counts by severity plus the most recent detections, over the read scope."""
    recent = select(Detection).order_by(Detection.detected_at.desc())
    if scope is not None:
        recent = recent.where(Detection.tenant_id == scope)
    by_severity = summarise(session, scope)
    top_resources = session.scalars(recent.limit(TOP_RESOURCE_COUNT)).all()
    return ScanSummaryOut(
        scope=scope or ESTATE_SCOPE,
        total=sum(by_severity.values()),
        by_severity=by_severity,
        top_resources=[TopResourceOut.model_validate(d) for d in top_resources],
    )


@router.get("/{scan_id}", response_model=DetectionOut)
def get_scan(scan_id: str, scope: ReadScopeDep, session: SessionDep) -> DetectionOut:
    query = select(Detection).where(Detection.id == scan_id)
    if scope is not None:
        query = query.where(Detection.tenant_id == scope)
    detection = session.scalars(query).one_or_none()
    if detection is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="detection not found"
        )
    return DetectionOut.model_validate(detection)
