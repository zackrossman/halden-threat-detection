"""Bounds on how much one request can return.

Before this, `GET /v1/scans` returned every detection in scope. An estate-wide
caller loaded the whole table into memory and serialised it, which is a way to
take the service down with a single request.
"""

from app.routers.scans import DEFAULT_PAGE_SIZE, MAX_PAGE_SIZE

ROUTE = "/v1/scans"


def test_a_page_is_returned_with_the_bounds_it_used(client, aggregate_headers):
    body = client.get(ROUTE, headers=aggregate_headers).json()

    assert body["limit"] == DEFAULT_PAGE_SIZE
    assert body["offset"] == 0


def test_limit_caps_the_detections_returned(client, aggregate_headers):
    body = client.get(f"{ROUTE}?limit=2", headers=aggregate_headers).json()

    assert len(body["detections"]) == 2


def test_offset_walks_through_the_detections(client, aggregate_headers):
    first = client.get(f"{ROUTE}?limit=2&offset=0", headers=aggregate_headers).json()
    second = client.get(f"{ROUTE}?limit=2&offset=2", headers=aggregate_headers).json()

    first_ids = [d["id"] for d in first["detections"]]
    second_ids = [d["id"] for d in second["detections"]]
    assert len(first_ids) == len(second_ids) == 2
    assert set(first_ids).isdisjoint(second_ids)


def test_every_detection_is_reachable_by_paging(client, aggregate_headers):
    seen: list[str] = []
    for offset in (0, 2, 4):
        body = client.get(
            f"{ROUTE}?limit=2&offset={offset}", headers=aggregate_headers
        ).json()
        seen.extend(d["id"] for d in body["detections"])

    assert len(set(seen)) == 6


def test_total_reports_the_whole_scope_not_the_page(client, aggregate_headers):
    body = client.get(f"{ROUTE}?limit=1", headers=aggregate_headers).json()

    assert len(body["detections"]) == 1
    assert body["total"] == 6


def test_total_is_scoped_to_the_calling_tenant(client, tenant_headers):
    body = client.get(f"{ROUTE}?limit=1", headers=tenant_headers("northwind")).json()

    assert body["total"] == 3


def test_a_limit_above_the_ceiling_is_refused(client, aggregate_headers):
    response = client.get(f"{ROUTE}?limit={MAX_PAGE_SIZE + 1}", headers=aggregate_headers)

    assert response.status_code == 422


def test_a_limit_of_zero_is_refused(client, aggregate_headers):
    assert client.get(f"{ROUTE}?limit=0", headers=aggregate_headers).status_code == 422


def test_a_negative_offset_is_refused(client, aggregate_headers):
    assert client.get(f"{ROUTE}?offset=-1", headers=aggregate_headers).status_code == 422


def test_paging_does_not_widen_the_read_scope(client, tenant_headers):
    """A page boundary must not become a way to see another tenant's rows."""
    body = client.get(
        f"{ROUTE}?limit={MAX_PAGE_SIZE}", headers=tenant_headers("northwind")
    ).json()

    assert {d["id"] for d in body["detections"]} == {
        "scan_nw_0001",
        "scan_nw_0002",
        "scan_nw_0003",
    }


def test_an_offset_past_the_end_returns_an_empty_page(client, aggregate_headers):
    body = client.get(f"{ROUTE}?offset=500", headers=aggregate_headers).json()

    assert body["detections"] == []
    assert body["total"] == 6
