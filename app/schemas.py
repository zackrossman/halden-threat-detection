"""Response models for the public routes."""

from datetime import datetime

from pydantic import BaseModel, ConfigDict


class DetectionOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    resource_name: str
    malware_family: str
    severity: str
    detected_at: datetime
    status: str


class ScanListOut(BaseModel):
    tenant_id: str
    detections: list[DetectionOut]
    summary: dict[str, int]
