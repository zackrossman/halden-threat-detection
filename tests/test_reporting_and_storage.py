import pytest

from app.db import session_factory
from app.reporting.summary import SUMMARY_DIMENSIONS, build_summary_query, summarise
from app.storage.artifacts import ArtifactStore, content_checksum


@pytest.mark.parametrize("dimension", SUMMARY_DIMENSIONS)
def test_every_allowed_dimension_builds_a_tenant_filtered_query(dimension):
    sql = build_summary_query(dimension)

    assert f"GROUP BY {dimension}" in sql
    assert "tenant_id = :tenant_id" in sql


def test_unknown_dimension_is_refused():
    with pytest.raises(ValueError):
        build_summary_query("severity; DROP TABLE detections")


def test_summarise_groups_by_the_requested_dimension():
    with session_factory()() as session:
        assert summarise(session, "northwind") == {
            "critical": 1,
            "high": 1,
            "medium": 1,
        }
        assert summarise(session, "northwind", "status") == {
            "quarantined": 2,
            "under_review": 1,
        }


def test_checksum_is_stable_and_content_dependent():
    assert content_checksum(b"sample") == content_checksum(b"sample")
    assert content_checksum(b"sample") != content_checksum(b"other")


def test_store_writes_once_per_distinct_content(tmp_path):
    store = ArtifactStore(tmp_path)

    first = store.store("northwind", b"sample")
    again = store.store("northwind", b"sample")
    other = store.store("northwind", b"other")

    assert first == again
    assert first != other
    assert sorted(p.name for p in (tmp_path / "northwind").iterdir()) == sorted(
        [first.name, other.name]
    )


def test_artifacts_are_separated_by_tenant(tmp_path):
    store = ArtifactStore(tmp_path)

    northwind = store.store("northwind", b"sample")
    contoso = store.store("contoso", b"sample")

    assert northwind != contoso
    assert northwind.parent.name == "northwind"
    assert contoso.parent.name == "contoso"
