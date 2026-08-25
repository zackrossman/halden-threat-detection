"""Runtime configuration, read from the environment."""

from functools import lru_cache
from urllib.parse import parse_qs, urlsplit

from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

# Postgres `sslmode` values that leave the connection unencrypted, or let the
# server talk the client out of encrypting it. `prefer` is the libpq default,
# and it downgrades silently — which is the whole reason this is checked here
# rather than assumed from the deployment.
INSECURE_SSL_MODES = frozenset({"disable", "allow", "prefer"})


class Settings(BaseSettings):
    """Settings for halden-threat-detection.

    Every value comes from the environment. The token public key and the
    database URL are injected by the platform from the
    `halden-threat-detection-runtime` Kubernetes secret; neither has a default.

    Unknown `HALDEN_`-prefixed variables are ignored rather than rejected, so the
    deployment can pass extra environment metadata without stopping the service
    from starting.
    """

    model_config = SettingsConfigDict(
        env_prefix="HALDEN_", env_file=".env", extra="ignore"
    )

    # PEM public key for the RS256 tokens halden-identity mints. Required and
    # with no default: the service cannot verify anything without it, so it
    # fails at startup rather than refusing every request once it is serving.
    # This is a public key, not a secret.
    internal_token_public_key: str
    database_url: str

    @field_validator("database_url")
    @classmethod
    def require_encrypted_postgres(cls, url: str) -> str:
        """Refuse a Postgres URL that would connect without TLS.

        Detection records carry customer resource names and malware findings,
        and the connection crosses the cluster network to a managed server. The
        deployment does set `sslmode=require`, but nothing made that a property
        of the service: a URL pasted without it, or with libpq's default
        `prefer`, connects in plaintext and says nothing. Checking it here means
        an unencrypted deployment fails at startup instead of running.

        Only Postgres URLs are checked. SQLite, which the tests run on, has no
        connection to encrypt.
        """
        scheme = urlsplit(url).scheme.split("+", 1)[0]
        if scheme not in {"postgres", "postgresql"}:
            return url

        modes = parse_qs(urlsplit(url).query).get("sslmode")
        if not modes:
            raise ValueError(
                "HALDEN_DATABASE_URL must set sslmode; use sslmode=require or stronger"
            )
        mode = modes[-1].lower()
        if mode in INSECURE_SSL_MODES:
            raise ValueError(
                f"HALDEN_DATABASE_URL has sslmode={mode}, which permits an "
                "unencrypted connection; use sslmode=require or stronger"
            )
        return url

    artifact_dir: str = "/var/lib/halden/artifacts"
    # Ceiling on a single database statement. A caller that asks for an
    # expensive read gets an error rather than holding a connection open and
    # starving everyone else.
    query_timeout_ms: int = 5000


@lru_cache
def get_settings() -> Settings:
    return Settings()
