"""The Alembic migrations must build exactly the schema the models describe."""

import os
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config

PROJECT_ROOT = Path(__file__).parents[1]


@pytest.fixture
def alembic_config(tmp_path: Path) -> Config:
    """Alembic pointed at a throwaway database (a temp SQLite file unless TEST_DATABASE_URL)."""
    config = Config(file_=PROJECT_ROOT / "alembic.ini", toml_file=PROJECT_ROOT / "pyproject.toml")
    url = os.environ.get(
        "TEST_DATABASE_URL", f"sqlite:///{(tmp_path / 'migrations.db').as_posix()}"
    )
    config.set_main_option("sqlalchemy.url", url)
    return config


def test_upgrade_matches_models_and_downgrade_works(alembic_config: Config) -> None:
    command.upgrade(alembic_config, "head")
    command.check(alembic_config)  # raises if models and migrations disagree
    command.downgrade(alembic_config, "base")
