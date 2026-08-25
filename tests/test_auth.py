from datetime import timedelta

import pytest

from app.auth import PLATFORM_AGGREGATE_SCOPE
from tests.conftest import bearer, make_token, other_private_key

PROTECTED_ROUTES = ["/v1/scans", "/v1/scans/summary", "/v1/scans/scan_nw_0001"]


@pytest.mark.parametrize("route", PROTECTED_ROUTES)
def test_missing_authorization_header_is_a_401(client, route):
    assert client.get(route).status_code == 401


@pytest.mark.parametrize("route", PROTECTED_ROUTES)
def test_valid_token_is_accepted_on_every_route(client, tenant_headers, route):
    assert client.get(route, headers=tenant_headers("northwind")).status_code == 200


def test_non_bearer_authorization_scheme_is_a_401(client):
    token = make_token({"tenant_id": "northwind"})

    response = client.get("/v1/scans", headers={"Authorization": f"Basic {token}"})

    assert response.status_code == 401


def test_garbage_instead_of_a_token_is_a_401(client):
    response = client.get("/v1/scans", headers=bearer("not-a-jwt"))

    assert response.status_code == 401


def test_token_signed_with_another_key_is_a_401(client):
    token = make_token({"tenant_id": "northwind"}, key=other_private_key())

    response = client.get("/v1/scans", headers=bearer(token))

    assert response.status_code == 401


def test_expired_token_is_a_401(client):
    token = make_token({"tenant_id": "northwind"}, expires_in=timedelta(minutes=-1))

    response = client.get("/v1/scans", headers=bearer(token))

    assert response.status_code == 401


def test_token_without_an_expiry_is_a_401(client):
    token = make_token({"tenant_id": "northwind"}, expires_in=None)

    response = client.get("/v1/scans", headers=bearer(token))

    assert response.status_code == 401


def test_token_for_another_audience_is_a_401(client):
    token = make_token({"tenant_id": "northwind"}, audience="halden-billing")

    response = client.get("/v1/scans", headers=bearer(token))

    assert response.status_code == 401


def test_token_without_an_audience_is_a_401(client):
    token = make_token({"tenant_id": "northwind"}, audience=None)

    response = client.get("/v1/scans", headers=bearer(token))

    assert response.status_code == 401


def test_token_from_another_issuer_is_a_401(client):
    token = make_token({"tenant_id": "northwind"}, issuer="halden-billing")

    response = client.get("/v1/scans", headers=bearer(token))

    assert response.status_code == 401


def test_token_without_an_issuer_is_a_401(client):
    token = make_token({"tenant_id": "northwind"}, issuer=None)

    response = client.get("/v1/scans", headers=bearer(token))

    assert response.status_code == 401


@pytest.mark.parametrize("route", PROTECTED_ROUTES)
def test_token_carrying_no_read_scope_is_a_403(client, route):
    token = make_token({"sub": "svc-unrelated"})

    response = client.get(route, headers=bearer(token))

    assert response.status_code == 403


def test_token_with_an_empty_tenant_is_a_403(client):
    token = make_token({"tenant_id": ""})

    response = client.get("/v1/scans", headers=bearer(token))

    assert response.status_code == 403


def test_unrelated_scopes_do_not_produce_an_estate_wide_read(client):
    token = make_token({"scopes": ["reports:read", "platform:health"]})

    response = client.get("/v1/scans", headers=bearer(token))

    assert response.status_code == 403


def test_aggregate_scope_resolves_without_a_tenant_claim(client, aggregate_headers):
    response = client.get("/v1/scans", headers=aggregate_headers)

    assert response.status_code == 200
    assert response.json()["scope"] == "estate"


def test_read_scope_prefers_the_aggregate_scope_over_a_tenant_claim():
    from app.auth import read_scope

    claims = {"sub": "halden-identity/jobs", "tenant_id": "northwind", "scopes": [PLATFORM_AGGREGATE_SCOPE]}

    assert read_scope(claims) is None
    assert read_scope({"tenant_id": "northwind"}) == "northwind"


def test_healthz_needs_no_token(client):
    response = client.get("/healthz")

    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_unknown_halden_env_vars_do_not_break_settings(monkeypatch):
    """The deployment may pass extra HALDEN_* metadata; it must not stop startup."""
    from app.config import Settings
    from tests.conftest import TOKEN_PUBLIC_KEY

    monkeypatch.setenv("HALDEN_ENV", "alpha")
    monkeypatch.setenv("HALDEN_SERVICE_NAME", "halden-threat-detection")

    settings = Settings()

    assert settings.internal_token_public_key == TOKEN_PUBLIC_KEY


def test_aggregate_scope_from_a_foreign_principal_is_refused(client):
    # A token that carries the estate-wide scope but is not one of the platform's
    # own scheduled principals must not be granted estate-wide access.
    token = make_token({"sub": "auth0|northwind-admin", "scopes": [PLATFORM_AGGREGATE_SCOPE]})

    response = client.get("/v1/scans", headers=bearer(token))

    assert response.status_code == 403


def test_read_scope_refuses_the_aggregate_scope_for_an_unlisted_subject():
    from fastapi import HTTPException

    from app.auth import read_scope

    with pytest.raises(HTTPException) as exc:
        read_scope({"sub": "auth0|northwind-admin", "scopes": [PLATFORM_AGGREGATE_SCOPE]})
    assert exc.value.status_code == 403


def test_token_without_a_subject_is_a_401(client):
    # Every audit record names the caller, so a token that names no subject is
    # not usable. halden-identity sets `sub` on both token kinds it mints.
    token = make_token({"tenant_id": "northwind"}, subject=None)

    response = client.get("/v1/scans", headers=bearer(token))

    assert response.status_code == 401


def test_aggregate_token_without_a_subject_is_a_401(client):
    token = make_token({"scopes": [PLATFORM_AGGREGATE_SCOPE]}, subject=None)

    response = client.get("/v1/scans", headers=bearer(token))

    assert response.status_code == 401
