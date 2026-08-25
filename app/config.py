"""Runtime configuration, read from the environment."""

from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


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
    artifact_dir: str = "/var/lib/halden/artifacts"
    # Ceiling on a single database statement. A caller that asks for an
    # expensive read gets an error rather than holding a connection open and
    # starving everyone else.
    query_timeout_ms: int = 5000


@lru_cache
def get_settings() -> Settings:
    return Settings()
