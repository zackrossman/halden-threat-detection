SUMMARY = "/v1/scans/summary"


def test_summary_is_scoped_to_the_calling_tenant(client, tenant_headers):
    body = client.get(SUMMARY, headers=tenant_headers("northwind")).json()

    assert body["scope"] == "northwind"
    assert body["total"] == 3
    assert body["by_severity"] == {"critical": 1, "high": 1, "medium": 1}
    assert {r["tenant_id"] for r in body["top_resources"]} == {"northwind"}


def test_summary_total_matches_the_severity_counts(client, tenant_headers):
    body = client.get(SUMMARY, headers=tenant_headers("contoso")).json()

    assert body["total"] == sum(body["by_severity"].values())


def test_summary_for_an_unknown_tenant_is_empty(client, tenant_headers):
    body = client.get(SUMMARY, headers=tenant_headers("fabrikam")).json()

    assert body == {
        "scope": "fabrikam",
        "total": 0,
        "by_severity": {},
        "top_resources": [],
    }


def test_estate_wide_summary_covers_every_tenant(client, aggregate_headers):
    body = client.get(SUMMARY, headers=aggregate_headers).json()

    assert body["scope"] == "estate"
    assert body["total"] == 6
    assert body["by_severity"] == {"critical": 2, "high": 2, "medium": 2}
    assert {r["tenant_id"] for r in body["top_resources"]} == {"northwind", "contoso"}


def test_estate_wide_summary_names_the_tenant_on_each_resource(
    client, aggregate_headers
):
    body = client.get(SUMMARY, headers=aggregate_headers).json()

    rows = {r["resource_name"]: r for r in body["top_resources"]}
    assert (
        rows["//contoso-nas03/backups/vm-images/build-server.vhdx"]["tenant_id"]
        == "contoso"
    )
    assert (
        rows["//contoso-nas03/backups/vm-images/build-server.vhdx"]["malware_family"]
        == "LockBit"
    )


def test_top_resources_are_the_five_most_recent_detections(client, aggregate_headers):
    body = client.get(SUMMARY, headers=aggregate_headers).json()

    assert len(body["top_resources"]) == 5
    # The oldest of the six seeded detections is the one left out.
    assert "//nwfs01/finance/quarterly-forecast.xlsx" not in {
        r["resource_name"] for r in body["top_resources"]
    }


def test_top_resources_are_capped_by_the_available_rows(client, tenant_headers):
    body = client.get(SUMMARY, headers=tenant_headers("contoso")).json()

    assert len(body["top_resources"]) == 3
