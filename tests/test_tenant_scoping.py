def test_list_returns_only_the_calling_tenants_detections(client, tenant_headers):
    body = client.get("/v1/scans", headers=tenant_headers("northwind")).json()

    assert body["scope"] == "northwind"
    assert {d["id"] for d in body["detections"]} == {
        "scan_nw_0001",
        "scan_nw_0002",
        "scan_nw_0003",
    }
    resources = " ".join(d["resource_name"] for d in body["detections"])
    assert "contoso" not in resources


def test_each_tenant_sees_a_disjoint_set(client, tenant_headers):
    northwind = client.get("/v1/scans", headers=tenant_headers("northwind")).json()
    contoso = client.get("/v1/scans", headers=tenant_headers("contoso")).json()

    nw_ids = {d["id"] for d in northwind["detections"]}
    ct_ids = {d["id"] for d in contoso["detections"]}
    assert nw_ids and ct_ids
    assert nw_ids.isdisjoint(ct_ids)


def test_summary_counts_only_the_calling_tenant(client, tenant_headers):
    body = client.get("/v1/scans", headers=tenant_headers("contoso")).json()

    assert sum(body["summary"].values()) == len(body["detections"]) == 3
    assert body["summary"]["critical"] == 1


def test_fetching_another_tenants_detection_by_id_is_a_404(client, tenant_headers):
    response = client.get("/v1/scans/scan_ct_0001", headers=tenant_headers("northwind"))

    assert response.status_code == 404


def test_fetching_own_detection_by_id_succeeds(client, tenant_headers):
    response = client.get("/v1/scans/scan_ct_0001", headers=tenant_headers("contoso"))

    assert response.status_code == 200
    assert response.json()["resource_name"].startswith("//contoso-nas01/hr/")


def test_unknown_tenant_sees_nothing(client, tenant_headers):
    body = client.get("/v1/scans", headers=tenant_headers("fabrikam")).json()

    assert body["detections"] == []
    assert body["summary"] == {}


def test_estate_wide_token_lists_every_tenants_detections(client, aggregate_headers):
    body = client.get("/v1/scans", headers=aggregate_headers).json()

    assert body["scope"] == "estate"
    assert {d["id"] for d in body["detections"]} == {
        "scan_nw_0001",
        "scan_nw_0002",
        "scan_nw_0003",
        "scan_ct_0001",
        "scan_ct_0002",
        "scan_ct_0003",
    }


def test_estate_wide_token_fetches_a_detection_from_any_tenant(
    client, aggregate_headers
):
    northwind = client.get("/v1/scans/scan_nw_0001", headers=aggregate_headers)
    contoso = client.get("/v1/scans/scan_ct_0001", headers=aggregate_headers)

    assert northwind.status_code == 200
    assert contoso.status_code == 200


def test_estate_wide_list_summary_counts_every_tenant(client, aggregate_headers):
    body = client.get("/v1/scans", headers=aggregate_headers).json()

    assert sum(body["summary"].values()) == 6
    assert body["summary"]["critical"] == 2
