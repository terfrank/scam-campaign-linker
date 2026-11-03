"""FastAPI application entry point."""

import logging

from fastapi import FastAPI
from pydantic import BaseModel

from scam_linker import __version__
from scam_linker.config import get_settings


class HealthResponse(BaseModel):
    """Body returned by GET /health."""

    status: str
    version: str


def create_app() -> FastAPI:
    """Build the FastAPI app. A factory makes it easy to create fresh apps in tests."""
    settings = get_settings()
    logging.basicConfig(level=settings.log_level)

    app = FastAPI(title=settings.app_name, version=__version__)

    @app.get("/health", response_model=HealthResponse)
    def health() -> HealthResponse:
        """Liveness check: the process is up and serving requests."""
        return HealthResponse(status="ok", version=__version__)

    return app


app = create_app()
