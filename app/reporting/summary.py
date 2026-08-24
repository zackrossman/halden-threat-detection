"""Aggregate counts over a tenant's detections."""

from sqlalchemy import text
from sqlalchemy.orm import Session

# The set of columns detections may be grouped by. This tuple is the only
# source of group-by column names in this module; request data never reaches
# the statement text, only the bound tenant parameter.
SUMMARY_DIMENSIONS = ("severity", "status", "malware_family")


def build_summary_query(dimension: str) -> str:
    if dimension not in SUMMARY_DIMENSIONS:
        raise ValueError(f"unknown summary dimension: {dimension}")
    return (
        f"SELECT {dimension} AS bucket, COUNT(*) AS total "
        "FROM detections WHERE tenant_id = :tenant_id "
        f"GROUP BY {dimension}"
    )


def summarise(session: Session, tenant: str, dimension: str = "severity") -> dict[str, int]:
    rows = session.execute(
        text(build_summary_query(dimension)), {"tenant_id": tenant}
    ).all()
    return {row.bucket: row.total for row in rows}
