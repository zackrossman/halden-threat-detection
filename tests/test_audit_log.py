"""What the audit log records, checked on the rendered JSON.

These assertions parse the formatter's output rather than reading the
`LogRecord`. A field the formatter drops is a field that never reaches the
cluster's log store, and an assertion against the record cannot see that.
"""

import io
import json
import logging
from datetime import timedelta
from typing import Callable

from app import audit
from app.db import connect_args
from tests.conftest import TOKEN_PUBLIC_KEY, bearer, make_token, other_private_key


def capture(action: Callable[[], object]) -> list[dict]:
    """Run `action` and return the audit records it wrote, parsed from JSON."""
    stream = io.StringIO()
    handler = logging.StreamHandler(stream)
    handler.setFormatter(audit.JsonFormatter())

    logger = logging.getLogger(audit.AUDIT_LOGGER_NAME)
    previous_handlers = logger.handlers[:]
    previous_level = logger.level
    logger.handlers = [handler]
    logger.setLevel(logging.INFO)
    try:
        action()
    finally:
        handler.flush()
        logger.handlers = previous_handlers
        logger.setLevel(previous_level)

    return [
        json.loads(line) for line in stream.getvalue().splitlines() if line.strip()
    ]


def only(lines: list[dict], event: str) -> dict:
    matching = [line for line in lines if line["event"] == event]
    assert len(matching) == 1, f"expected one {event!r}, got {len(matching)}"
    return matching[0]


def test_missing_token_is_recorded_as_an_authentication_failure(client):
    lines = capture(lambda: client.get("/v1/scans"))

    record = only(lines, "authentication_failed")
    assert record["outcome"] == "refused"
    assert record["status_code"] == 401
    assert record["reason"] == "no_bearer_token"


def test_an_expired_token_records_why_it_was_refused(client):
    token = make_token({"tenant_id": "northwind"}, expires_in=timedelta(minutes=-1))
    lines = capture(lambda: client.get("/v1/scans", headers=bearer(token)))

    assert only(lines, "authentication_failed")["reason"] == "ExpiredSignatureError"


def test_a_token_with_no_subject_records_the_missing_claim(client):
    token = make_token({"tenant_id": "northwind"}, subject=None)
    lines = capture(lambda: client.get("/v1/scans", headers=bearer(token)))

    assert only(lines, "authentication_failed")["reason"] == "MissingRequiredClaimError"


def test_a_refused_aggregate_scope_records_the_subject(client):
    token = make_token(
        {"scopes": ["platform:aggregate"]}, subject="auth0|northwind-admin"
    )
    lines = capture(lambda: client.get("/v1/scans", headers=bearer(token)))

    record = only(lines, "authorization_denied")
    assert record["status_code"] == 403
    assert record["reason"] == "aggregate_scope_for_unlisted_principal"
    assert record["subject"] == "auth0|northwind-admin"


def test_a_successful_list_records_the_caller_scope_and_count(client):
    token = make_token({"tenant_id": "northwind"}, subject="auth0|nw-analyst")
    lines = capture(lambda: client.get("/v1/scans", headers=bearer(token)))

    record = only(lines, "detections_listed")
    assert record["subject"] == "auth0|nw-analyst"
    assert record["scope"] == "northwind"
    assert record["returned"] == 3
    assert record["route"] == "/v1/scans"


def test_an_estate_wide_read_is_recorded_as_estate(client, aggregate_headers):
    lines = capture(lambda: client.get("/v1/scans", headers=aggregate_headers))

    record = only(lines, "detections_listed")
    assert record["subject"] == "halden-identity/jobs"
    assert record["scope"] == "estate"


def test_the_summary_route_records_its_own_read(client, aggregate_headers):
    lines = capture(lambda: client.get("/v1/scans/summary", headers=aggregate_headers))

    assert only(lines, "detections_summarised")["scope"] == "estate"


def test_a_missing_detection_is_recorded_as_not_found(client, tenant_headers):
    lines = capture(
        lambda: client.get(
            "/v1/scans/scan_ct_0001", headers=tenant_headers("northwind")
        )
    )

    record = only(lines, "detection_fetched")
    assert record["found"] is False
    assert record["detection_id"] == "scan_ct_0001"


def test_every_record_carries_a_timestamp_and_a_level(client, tenant_headers):
    lines = capture(lambda: client.get("/v1/scans", headers=tenant_headers("contoso")))

    assert lines
    for record in lines:
        assert record["timestamp"]
        assert record["level"] in {"INFO", "WARNING", "ERROR"}


def test_the_token_never_appears_in_the_audit_log(client):
    token = make_token({"tenant_id": "northwind"}, subject="auth0|nw-analyst")
    lines = capture(lambda: client.get("/v1/scans", headers=bearer(token)))

    rendered = json.dumps(lines)
    assert token not in rendered
    assert token.rsplit(".", 1)[-1] not in rendered  # not even the signature


def test_a_refused_token_is_not_written_to_the_audit_log(client):
    token = make_token({"tenant_id": "northwind"}, key=other_private_key())
    lines = capture(lambda: client.get("/v1/scans", headers=bearer(token)))

    assert token not in json.dumps(lines)


def test_key_material_never_appears_in_the_audit_log(client, tenant_headers):
    lines = capture(
        lambda: client.get("/v1/scans", headers=tenant_headers("northwind"))
    )

    rendered = json.dumps(lines)
    assert TOKEN_PUBLIC_KEY not in rendered
    assert "PRIVATE KEY" not in rendered


def test_postgres_connections_carry_a_statement_timeout():
    args = connect_args("postgresql+psycopg://user:pw@host:5432/halden")

    assert "statement_timeout" in args["options"]


def test_sqlite_connections_take_no_server_options():
    assert connect_args("sqlite+pysqlite:///:memory:") == {}
