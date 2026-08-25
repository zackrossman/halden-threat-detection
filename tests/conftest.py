import os
import secrets

# The suite generates its own signing secret so that no credential value is
# checked in; the app still reads it from the environment.
os.environ.setdefault("HALDEN_INTERNAL_TOKEN_SECRET", secrets.token_hex(32))
os.environ.setdefault("HALDEN_DATABASE_URL", "sqlite+pysqlite:///:memory:")

from datetime import datetime, timedelta, timezone

import jwt
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.pool import StaticPool

import app.db as db
from app.auth import PLATFORM_AGGREGATE_SCOPE, TOKEN_AUDIENCE, TOKEN_ISSUER
from app.main import app as fastapi_app
from scripts.seed import SEED_DETECTIONS

TOKEN_SECRET = os.environ["HALDEN_INTERNAL_TOKEN_SECRET"]


# Stands in for the customer subject halden-identity copies from the Auth0
# access token. Every token it mints carries one, so the default token here
# does too; a test that is about the subject passes its own.
DEFAULT_SUBJECT = "auth0|test-user"


def make_token(
    claims: dict | None = None,
    *,
    secret: str = TOKEN_SECRET,
    issuer: str | None = TOKEN_ISSUER,
    audience: str | None = TOKEN_AUDIENCE,
    subject: str | None = DEFAULT_SUBJECT,
    expires_in: timedelta | None = timedelta(minutes=5),
    algorithm: str = "HS256",
) -> str:
    """Sign an internal token. Every registered claim is overridable, so a test
    can produce a token that fails one specific check."""
    payload = dict(claims or {})
    if issuer is not None:
        payload["iss"] = issuer
    if audience is not None:
        payload["aud"] = audience
    if subject is not None:
        payload.setdefault("sub", subject)
    if expires_in is not None:
        payload["exp"] = datetime.now(tz=timezone.utc) + expires_in
    return jwt.encode(payload, secret, algorithm=algorithm)


def bearer(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture(autouse=True)
def database():
    db._engine = create_engine(
        "sqlite+pysqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    db._SessionLocal = None
    db.create_schema()
    with db.session_factory()() as session:
        for detection in SEED_DETECTIONS:
            session.merge(detection)
        session.commit()
    yield
    db._engine = None
    db._SessionLocal = None


@pytest.fixture
def client():
    with TestClient(fastapi_app) as test_client:
        yield test_client


@pytest.fixture
def tenant_headers():
    def _headers(tenant: str) -> dict[str, str]:
        return bearer(make_token({"tenant_id": tenant}))

    return _headers


@pytest.fixture
def aggregate_headers():
    return bearer(make_token({"sub": "halden-identity/jobs", "scopes": [PLATFORM_AGGREGATE_SCOPE]}))
