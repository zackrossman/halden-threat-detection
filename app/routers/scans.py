"""Detection routes.

Each route filters on the tenant resolved by the `tenant_id` dependency.
"""

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db import get_session
from app.deps import require_gateway_key, tenant_id
from app.models import Detection
from app.reporting.summary import summarise
from app.schemas import DetectionOut, ScanListOut

router = APIRouter(
    prefix="/v1/scans",
    tags=["scans"],
    dependencies=[Depends(require_gateway_key)],
)

SessionDep = Annotated[Session, Depends(get_session)]
TenantDep = Annotated[str, Depends(tenant_id)]


@router.get("", response_model=ScanListOut)
def list_scans(tenant: TenantDep, session: SessionDep) -> ScanListOut:
    detections = session.scalars(
        select(Detection)
        .where(Detection.tenant_id == tenant)
        .order_by(Detection.detected_at.desc())
    ).all()
    return ScanListOut(
        tenant_id=tenant,
        detections=[DetectionOut.model_validate(d) for d in detections],
        summary=summarise(session, tenant),
    )


@router.get("/{scan_id}", response_model=DetectionOut)
def get_scan(scan_id: str, tenant: TenantDep, session: SessionDep) -> DetectionOut:
    detection = session.scalars(
        select(Detection)
        .where(Detection.tenant_id == tenant)
        .where(Detection.id == scan_id)
    ).one_or_none()
    if detection is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="detection not found"
        )
    return DetectionOut.model_validate(detection)
