"""The tenant id is untrusted input, even inside a verified token.

A verified token proves who minted it. It does not prove the `tenant_id` claim
is a safe value, and this service uses that claim two ways: as a query filter,
and as a directory name in the artifact store. A claim carrying `..` or a
separator would resolve outside its own tenant's directory.

Two independent checks stand between the claim and those uses — the format
check when the scope is resolved, and the containment check in the store — so
neither one is a single point of failure.
"""

import pytest

from app.auth import TENANT_ID_PATTERN, read_scope
from app.storage.artifacts import ArtifactStore
from tests.conftest import bearer, make_token

ROUTE = "/v1/scans"

# Values that must never reach a query filter or a path segment.
MALFORMED_TENANT_IDS = [
    "../contoso",
    "..",
    "../../etc/passwd",
    "north/wind",
    "north\\wind",
    "/absolute",
    "northwind\x00",
    "north wind",
    "%2e%2e%2f",
    "north.wind",
    "north;wind",
    "'; DROP TABLE detections--",
]


@pytest.mark.parametrize("tenant", MALFORMED_TENANT_IDS)
def test_a_malformed_tenant_claim_is_refused(client, tenant):
    token = make_token({"tenant_id": tenant})

    response = client.get(ROUTE, headers=bearer(token))

    assert response.status_code == 400


@pytest.mark.parametrize("tenant", MALFORMED_TENANT_IDS)
def test_read_scope_refuses_a_malformed_tenant(tenant):
    from fastapi import HTTPException

    with pytest.raises(HTTPException) as exc:
        read_scope({"sub": "auth0|attacker", "tenant_id": tenant})

    assert exc.value.status_code == 400


@pytest.mark.parametrize("tenant", ["northwind", "contoso", "acme-corp", "acme_corp", "T3nant"])
def test_a_well_formed_tenant_is_accepted(tenant):
    assert read_scope({"sub": "auth0|user", "tenant_id": tenant}) == tenant


def test_the_pattern_anchors_both_ends():
    """An unanchored pattern would pass `../contoso` on its trailing segment."""
    assert not TENANT_ID_PATTERN.match("../contoso")
    assert not TENANT_ID_PATTERN.match("contoso/..")
    assert not TENANT_ID_PATTERN.match("contoso\nnorthwind")


def test_a_malformed_tenant_never_reaches_the_detections_of_another(client):
    """The refusal must not be a redirect to someone else's rows."""
    token = make_token({"tenant_id": "../contoso"})

    response = client.get(ROUTE, headers=bearer(token))

    assert response.status_code == 400
    assert "detections" not in response.json()


# --- the store's own containment check, independent of the format check ---


@pytest.mark.parametrize("tenant", ["../contoso", "..", "a/b", "/etc", ""])
def test_the_store_refuses_a_tenant_that_escapes_its_root(tmp_path, tenant):
    store = ArtifactStore(tmp_path)

    with pytest.raises(ValueError):
        store.path_for(tenant, b"sample")


def test_the_store_writes_a_well_formed_tenant_under_the_root(tmp_path):
    store = ArtifactStore(tmp_path)

    written = store.store("northwind", b"sample")

    assert written.is_relative_to(tmp_path.resolve())
    assert written.parent.name == "northwind"


def test_a_traversing_tenant_writes_nothing_outside_the_root(tmp_path):
    root = tmp_path / "artifacts"
    root.mkdir()
    outside = tmp_path / "secrets"
    outside.mkdir()
    store = ArtifactStore(root)

    with pytest.raises(ValueError):
        store.store("../secrets", b"payload")

    assert list(outside.iterdir()) == []


def test_traversal_cannot_reach_another_tenants_existing_artifact(tmp_path):
    store = ArtifactStore(tmp_path)
    victim = store.store("contoso", b"confidential")

    with pytest.raises(ValueError):
        store.path_for("../contoso", b"confidential")

    assert victim.read_bytes() == b"confidential"
