"""Engine and session factory."""

from typing import Any

from sqlalchemy import Engine, create_engine, event
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from scam_linker.config import get_settings


def make_engine(url: str | None = None) -> Engine:
    """Create an engine for `url` (default: settings.database_url)."""
    url = url or get_settings().database_url
    if not url.startswith("sqlite"):
        return create_engine(url, pool_pre_ping=True)

    kwargs: dict[str, Any] = {"connect_args": {"check_same_thread": False}}
    if ":memory:" in url or url == "sqlite://":
        kwargs["poolclass"] = StaticPool  # one shared connection, or each would see an empty DB
    engine = create_engine(url, **kwargs)

    @event.listens_for(engine, "connect")
    def _enable_foreign_keys(dbapi_connection: Any, _record: Any) -> None:
        # SQLite ignores foreign keys (and ON DELETE CASCADE) unless asked, per connection.
        dbapi_connection.execute("PRAGMA foreign_keys=ON")

    return engine


def make_session_factory(engine: Engine) -> sessionmaker[Session]:
    # expire_on_commit=False: objects stay readable after commit (handy in API responses).
    return sessionmaker(engine, expire_on_commit=False)
