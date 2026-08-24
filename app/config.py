"""Runtime configuration, read from the environment."""

from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Settings for halden-threat-detection.

    Every value comes from the environment. The gateway key and the database URL
    are injected by the platform from the `halden-threat-detection-runtime`
    Kubernetes secret; neither has a default.

    Unknown `HALDEN_`-prefixed variables are ignored rather than rejected, so the
    deployment can pass extra environment metadata without stopping the service
    from starting.
    """

    model_config = SettingsConfigDict(
        env_prefix="HALDEN_", env_file=".env", extra="ignore"
    )

    gateway_key: str
    database_url: str
    artifact_dir: str = "/var/lib/halden/artifacts"


@lru_cache
def get_settings() -> Settings:
    return Settings()
