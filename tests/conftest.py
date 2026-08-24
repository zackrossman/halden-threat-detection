import os
import secrets

# The suite generates its own gateway key so that no credential value is
# checked in; the app still reads it from the environment.
os.environ.setdefault("HALDEN_GATEWAY_KEY", secrets.token_hex(16))
os.environ.setdefault("HALDEN_DATABASE_URL", "sqlite+pysqlite:///:memory:")

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.pool import StaticPool

import app.db as db
from app.main import app as fastapi_app
from scripts.seed import SEED_DETECTIONS

GATEWAY_KEY = os.environ["HALDEN_GATEWAY_KEY"]


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
def auth_headers():
    def _headers(tenant: str) -> dict[str, str]:
        return {
            "X-Halden-Tenant-ID": tenant,
            "X-Halden-Gateway-Key": GATEWAY_KEY,
        }

    return _headers
