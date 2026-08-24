from tests.conftest import GATEWAY_KEY


def test_missing_gateway_key_is_rejected(client):
    response = client.get("/v1/scans", headers={"X-Halden-Tenant-ID": "northwind"})

    assert response.status_code == 401


def test_wrong_gateway_key_is_rejected(client):
    response = client.get(
        "/v1/scans",
        headers={
            "X-Halden-Tenant-ID": "northwind",
            "X-Halden-Gateway-Key": GATEWAY_KEY + "x",
        },
    )

    assert response.status_code == 401


def test_gateway_key_is_required_on_the_detail_route(client):
    response = client.get(
        "/v1/scans/scan_nw_0001", headers={"X-Halden-Tenant-ID": "northwind"}
    )

    assert response.status_code == 401


def test_missing_tenant_header_is_a_400(client):
    response = client.get("/v1/scans", headers={"X-Halden-Gateway-Key": GATEWAY_KEY})

    assert response.status_code == 400


def test_healthz_needs_no_headers(client):
    response = client.get("/healthz")

    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_unknown_halden_env_vars_do_not_break_settings(monkeypatch):
    """The deployment may pass extra HALDEN_* metadata; it must not stop startup."""
    from app.config import Settings

    monkeypatch.setenv("HALDEN_ENV", "alpha")
    monkeypatch.setenv("HALDEN_SERVICE_NAME", "halden-threat-detection")

    settings = Settings()

    assert settings.gateway_key == GATEWAY_KEY
