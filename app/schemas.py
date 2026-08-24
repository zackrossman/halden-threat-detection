"""Response models for the public routes."""

from datetime import datetime

from pydantic import BaseModel, ConfigDict

# Reported as the scope of a response served to an estate-wide caller, where a
# single tenant id would be the wrong answer.
ESTATE_SCOPE = "estate"


class DetectionOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    resource_name: str
    malware_family: str
    severity: str
    detected_at: datetime
    status: str


class TopResourceOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    tenant_id: str
    resource_name: str
    malware_family: str


class ScanListOut(BaseModel):
    scope: str
    detections: list[DetectionOut]
    summary: dict[str, int]


class ScanSummaryOut(BaseModel):
    scope: str
    total: int
    by_severity: dict[str, int]
    top_resources: list[TopResourceOut]
