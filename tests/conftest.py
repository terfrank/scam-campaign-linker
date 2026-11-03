"""Shared pytest fixtures."""

from collections.abc import Iterator

import pytest
from fastapi.testclient import TestClient

from scam_linker.main import create_app


@pytest.fixture
def client() -> Iterator[TestClient]:
    """An in-process HTTP client for the API. No network, no real server."""
    with TestClient(create_app()) as test_client:
        yield test_client
