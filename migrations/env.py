"""Alembic environment: connects migrations to our models and our DATABASE_URL setting."""

from logging.config import fileConfig
from typing import Any, Literal

from alembic import context
from alembic.autogenerate.api import AutogenContext

from scam_linker.config import get_settings
from scam_linker.db.models import Base, UTCDateTime
from scam_linker.db.session import make_engine

config = context.config
if config.config_file_name is not None:
    # Keep the app's loggers working when migrations run inside the app or the tests.
    fileConfig(config.config_file_name, disable_existing_loggers=False)

target_metadata = Base.metadata


def database_url() -> str:
    """A URL set programmatically (tests) wins; otherwise DATABASE_URL from settings."""
    return config.get_main_option("sqlalchemy.url") or get_settings().database_url


def render_item(type_: str, obj: Any, autogen_context: AutogenContext) -> str | Literal[False]:
    """Write UTCDateTime as a plain DateTime(timezone=True) in migration files.

    Migrations must not import application code: models change over time, but an old
    migration has to keep producing exactly the schema it produced when it was written.
    """
    if type_ == "type" and isinstance(obj, UTCDateTime):
        return "sa.DateTime(timezone=True)"
    return False  # use Alembic's default rendering


def run_migrations_offline() -> None:
    """Emit SQL to stdout instead of running it (alembic upgrade --sql)."""
    context.configure(
        url=database_url(),
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        render_item=render_item,
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    url = database_url()
    engine = make_engine(url)  # same engine setup as the app, e.g. SQLite foreign keys on
    try:
        with engine.connect() as connection:
            context.configure(
                connection=connection,
                target_metadata=target_metadata,
                render_item=render_item,
                render_as_batch=url.startswith("sqlite"),  # SQLite can't ALTER most things
            )
            with context.begin_transaction():
                context.run_migrations()
    finally:
        engine.dispose()  # one-off script: close pooled connections


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
