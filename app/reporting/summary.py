"""Aggregate counts over detections, for one tenant or across the estate."""

from sqlalchemy import text
from sqlalchemy.orm import Session

# The set of columns detections may be grouped by. This tuple is the only
# source of group-by column names in this module; request data never reaches
# the statement text, only the bound tenant parameter.
SUMMARY_DIMENSIONS = ("severity", "status", "malware_family")


def build_summary_query(dimension: str, scoped_to_tenant: bool) -> str:
    if dimension not in SUMMARY_DIMENSIONS:
        raise ValueError(f"unknown summary dimension: {dimension}")
    where = "WHERE tenant_id = :tenant_id " if scoped_to_tenant else ""
    return (
        f"SELECT {dimension} AS bucket, COUNT(*) AS total "
        f"FROM detections {where}"
        f"GROUP BY {dimension}"
    )


def summarise(
    session: Session, tenant: str | None, dimension: str = "severity"
) -> dict[str, int]:
    """Count detections by `dimension`, for one tenant or for every tenant.

    A `tenant` of None counts across the estate and binds no parameter.
    """
    query = build_summary_query(dimension, tenant is not None)
    params = {"tenant_id": tenant} if tenant is not None else {}
    rows = session.execute(text(query), params).all()
    return {row.bucket: row.total for row in rows}
