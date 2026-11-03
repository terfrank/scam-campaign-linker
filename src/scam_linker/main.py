"""FastAPI application factory.

Run with `uvicorn --factory scam_linker.main:create_app`. Using a factory (instead of a
module-level `app`) means importing this module opens nothing, and tests can build an app
wired to SQLite and fake network clients.
"""

import logging
from collections.abc import AsyncIterator, Callable
from contextlib import asynccontextmanager

from fastapi import FastAPI, Response, status
from fastapi.staticfiles import StaticFiles
from sqlalchemy import Engine, text
from sqlalchemy.exc import SQLAlchemyError

from scam_linker import __version__
from scam_linker.api import campaigns, pages, sites
from scam_linker.api.deps import AppContext, Context
from scam_linker.api.ratelimit import SlidingWindowLimiter
from scam_linker.api.schemas import HealthResponse
from scam_linker.config import Settings, get_settings
from scam_linker.db.session import make_engine, make_session_factory
from scam_linker.dns_client import DnsClient
from scam_linker.fetcher import SafeFetcher
from scam_linker.linker.config import ScoringConfig, load_scoring_config


def create_app(
    settings: Settings | None = None,
    *,
    engine: Engine | None = None,
    fetcher: SafeFetcher | None = None,
    dns: DnsClient | None = None,
    scoring: ScoringConfig | None = None,
) -> FastAPI:
    """Build the app. Anything not passed in is created from settings (and closed on shutdown)."""
    settings = settings or get_settings()
    logging.basicConfig(level=settings.log_level)

    cleanups: list[Callable[[], None]] = []  # close only what this app opened itself
    if engine is None:
        engine = make_engine(settings.database_url)
        cleanups.append(engine.dispose)
    if fetcher is None:
        fetcher = SafeFetcher()
        cleanups.append(fetcher.close)

    context = AppContext(
        engine=engine,
        session_factory=make_session_factory(engine),
        fetcher=fetcher,
        dns=dns or DnsClient(),
        scoring=scoring or load_scoring_config(settings.scoring_config_path),
        collect_limiter=SlidingWindowLimiter(settings.collect_rate_limit_per_minute),
    )

    @asynccontextmanager
    async def lifespan(_app: FastAPI) -> AsyncIterator[None]:
        yield
        for cleanup in cleanups:
            cleanup()

    app = FastAPI(title=settings.app_name, version=__version__, lifespan=lifespan)
    app.state.context = context
    app.include_router(sites.router)
    app.include_router(campaigns.router)
    app.include_router(pages.router)
    app.mount("/static", StaticFiles(packages=[("scam_linker", "static")]), name="static")

    @app.get("/health")
    def health(response: Response, ctx: Context) -> HealthResponse:
        """200 when the API and database are both reachable; 503 if the database is not."""
        try:
            with ctx.engine.connect() as connection:
                connection.execute(text("SELECT 1"))
        except SQLAlchemyError:
            response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
            return HealthResponse(status="degraded", version=__version__, database="unavailable")
        return HealthResponse(status="ok", version=__version__, database="ok")

    return app
