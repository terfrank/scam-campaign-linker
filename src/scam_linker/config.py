"""Runtime settings loaded from environment variables (or a local .env file).

Linker weights and thresholds live separately in scoring.toml; this module holds
deployment settings such as the database URL and API limits.
"""

from functools import lru_cache
from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Deployment settings. Each field maps to an env var of the same name, upper-cased."""

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    app_name: str = "Scam Campaign Linker"
    database_url: str = "postgresql+psycopg://scam:change-me@localhost:5432/scam_linker"
    log_level: str = "INFO"

    # Requests per minute, per client IP, to the endpoints that trigger collection.
    collect_rate_limit_per_minute: int = Field(default=10, ge=1)
    # A different scoring.toml (default: the copy shipped inside the package).
    scoring_config_path: Path | None = None


@lru_cache
def get_settings() -> Settings:
    """Return the settings, read once and cached for the life of the process."""
    return Settings()
