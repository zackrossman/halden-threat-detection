"""The database connection must be encrypted, and the service must prove it.

Detection records carry customer resource names and malware findings, and the
connection crosses the cluster network to a managed Postgres server. The
deployment sets `sslmode=require` today, but that was a property of one
Terraform file rather than of the service — a URL pasted without it connects in
plaintext and reports nothing. libpq's default, `prefer`, is the trap: it asks
for TLS and silently accepts a plaintext connection if the server declines.
"""

import pytest

from app.config import INSECURE_SSL_MODES, Settings

PUBLIC_KEY = "-----BEGIN PUBLIC KEY-----\nstub\n-----END PUBLIC KEY-----\n"


def settings_for(url: str) -> Settings:
    return Settings(
        internal_token_public_key=PUBLIC_KEY, database_url=url, _env_file=None
    )


@pytest.mark.parametrize(
    "url",
    [
        "postgresql+psycopg://u:p@h:5432/halden?sslmode=require",
        "postgresql+psycopg://u:p@h:5432/halden?sslmode=verify-ca",
        "postgresql+psycopg://u:p@h:5432/halden?sslmode=verify-full",
        "postgresql://u:p@h/halden?sslmode=REQUIRE",
    ],
)
def test_an_encrypted_postgres_url_is_accepted(url):
    assert settings_for(url).database_url == url


@pytest.mark.parametrize("mode", sorted(INSECURE_SSL_MODES))
def test_every_downgrading_sslmode_is_refused(mode):
    with pytest.raises(ValueError):
        settings_for(f"postgresql+psycopg://u:p@h:5432/halden?sslmode={mode}")


def test_a_postgres_url_with_no_sslmode_is_refused():
    """The silent case: libpq defaults to `prefer` and downgrades quietly."""
    with pytest.raises(ValueError):
        settings_for("postgresql+psycopg://u:p@h:5432/halden")


def test_the_refusal_names_the_variable_and_the_fix():
    with pytest.raises(ValueError) as exc:
        settings_for("postgresql+psycopg://u:p@h:5432/halden")

    message = str(exc.value)
    assert "HALDEN_DATABASE_URL" in message
    assert "sslmode=require" in message


def test_a_later_sslmode_cannot_override_an_earlier_one():
    """Last value wins in libpq, so the check must read the last one too."""
    with pytest.raises(ValueError):
        settings_for("postgresql://u:p@h/halden?sslmode=require&sslmode=disable")


def test_sqlite_needs_no_sslmode():
    """The tests run on SQLite, which has no connection to encrypt."""
    assert settings_for("sqlite+pysqlite:///:memory:").database_url


def test_the_url_is_not_rewritten_when_it_is_already_safe():
    """Validation must not quietly repair a URL — an operator fixes it."""
    url = "postgresql+psycopg://u:p@h:5432/halden?sslmode=verify-full&application_name=halden"

    assert settings_for(url).database_url == url
