def test_list_returns_only_the_calling_tenants_detections(client, auth_headers):
    body = client.get("/v1/scans", headers=auth_headers("northwind")).json()

    assert body["tenant_id"] == "northwind"
    assert {d["id"] for d in body["detections"]} == {
        "scan_nw_0001",
        "scan_nw_0002",
        "scan_nw_0003",
    }
    resources = " ".join(d["resource_name"] for d in body["detections"])
    assert "contoso" not in resources


def test_each_tenant_sees_a_disjoint_set(client, auth_headers):
    northwind = client.get("/v1/scans", headers=auth_headers("northwind")).json()
    contoso = client.get("/v1/scans", headers=auth_headers("contoso")).json()

    nw_ids = {d["id"] for d in northwind["detections"]}
    ct_ids = {d["id"] for d in contoso["detections"]}
    assert nw_ids and ct_ids
    assert nw_ids.isdisjoint(ct_ids)


def test_summary_counts_only_the_calling_tenant(client, auth_headers):
    body = client.get("/v1/scans", headers=auth_headers("contoso")).json()

    assert sum(body["summary"].values()) == len(body["detections"]) == 3
    assert body["summary"]["critical"] == 1


def test_fetching_another_tenants_detection_by_id_is_a_404(client, auth_headers):
    response = client.get("/v1/scans/scan_ct_0001", headers=auth_headers("northwind"))

    assert response.status_code == 404


def test_fetching_own_detection_by_id_succeeds(client, auth_headers):
    response = client.get("/v1/scans/scan_ct_0001", headers=auth_headers("contoso"))

    assert response.status_code == 200
    assert response.json()["resource_name"].startswith("//contoso-nas01/hr/")


def test_unknown_tenant_sees_nothing(client, auth_headers):
    body = client.get("/v1/scans", headers=auth_headers("fabrikam")).json()

    assert body["detections"] == []
    assert body["summary"] == {}
