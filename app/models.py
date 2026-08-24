"""Database models."""

from datetime import datetime

from sqlalchemy import DateTime, Index, String
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    pass


class Detection(Base):
    """A single malware detection raised against a protected resource."""

    __tablename__ = "detections"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    resource_name: Mapped[str] = mapped_column(String(512), nullable=False)
    malware_family: Mapped[str] = mapped_column(String(128), nullable=False)
    severity: Mapped[str] = mapped_column(String(16), nullable=False)
    detected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False)


Index("ix_detections_tenant_detected_at", Detection.tenant_id, Detection.detected_at.desc())
