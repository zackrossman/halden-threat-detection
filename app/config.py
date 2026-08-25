"""Runtime configuration, read from the environment."""

from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Settings for halden-threat-detection.

    Every value comes from the environment. The internal token secret and the
    database URL are injected by the platform from the
    `halden-threat-detection-runtime` Kubernetes secret; neither has a default.

    Unknown `HALDEN_`-prefixed variables are ignored rather than rejected, so the
    deployment can pass extra environment metadata without stopping the service
    from starting.
    """

    model_config = SettingsConfigDict(
        env_prefix="HALDEN_", env_file=".env", extra="ignore"
    )

    internal_token_secret: str
    # PEM public key for the RS256 tokens halden-identity will mint once the
    # platform is off the shared secret. Empty until then: an RS256 token is
    # refused rather than trusted while no key is configured.
    internal_token_public_key: str = ""
    database_url: str
    artifact_dir: str = "/var/lib/halden/artifacts"
    # Ceiling on a single database statement. A caller that asks for an
    # expensive read gets an error rather than holding a connection open and
    # starving everyone else.
    query_timeout_ms: int = 5000


@lru_cache
def get_settings() -> Settings:
    return Settings()
