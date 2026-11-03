"""Runtime settings loaded from environment variables (or a local .env file).

Scoring weights and thresholds will live separately in scoring.toml (Phase 5);
this module only holds deployment settings such as the database URL.
"""

from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Deployment settings. Each field maps to an env var of the same name, upper-cased."""

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    app_name: str = "Scam Campaign Linker"
    database_url: str = "postgresql+psycopg://scam:change-me@localhost:5432/scam_linker"
    log_level: str = "INFO"


@lru_cache
def get_settings() -> Settings:
    """Return the settings, read once and cached for the life of the process."""
    return Settings()
