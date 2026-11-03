"""Shared pytest fixtures."""

import os
from collections.abc import Iterator

import pytest
import respx
from fastapi.testclient import TestClient
from sqlalchemy import Engine
from sqlalchemy.orm import Session

from fakes import PUBLIC_IP, FakeClock, FakeDnsResolver
from scam_linker.config import Settings
from scam_linker.db.models import Base
from scam_linker.db.session import make_engine, make_session_factory
from scam_linker.dns_client import DnsClient
from scam_linker.fetcher import RateLimiter, SafeFetcher
from scam_linker.main import create_app


@pytest.fixture
def clock() -> FakeClock:
    return FakeClock()


@pytest.fixture
def addresses() -> dict[str, list[str]]:
    """Fake DNS for the fetcher's SSRF check: hostname -> IPs. Unknown hosts get a public IP."""
    return {}


@pytest.fixture
def fetcher(clock: FakeClock, addresses: dict[str, list[str]]) -> Iterator[SafeFetcher]:
    def resolver(host: str) -> list[str]:
        return addresses.get(host, [PUBLIC_IP])

    with SafeFetcher(resolver=resolver, clock=clock, sleep=clock.sleep) as safe_fetcher:
        yield safe_fetcher


@pytest.fixture
def router() -> Iterator[respx.MockRouter]:
    """Mock network. robots.txt is 404 (no rules) unless a test changes router['robots'].

    Any request without a matching route raises, so no test can reach the real internet.
    """
    with respx.mock(assert_all_called=False) as mock:
        mock.get(path="/robots.txt", name="robots").respond(404)
        yield mock


@pytest.fixture
def dns_resolver() -> FakeDnsResolver:
    return FakeDnsResolver()


@pytest.fixture
def dns_client(dns_resolver: FakeDnsResolver, clock: FakeClock) -> DnsClient:
    return DnsClient(resolver=dns_resolver, limiter=RateLimiter(0.2, clock, clock.sleep))


@pytest.fixture
def engine() -> Iterator[Engine]:
    """A fresh, empty database per test.

    In-memory SQLite by default. CI also sets TEST_DATABASE_URL to a real PostgreSQL service,
    so the same tests catch differences between the two (JSONB, timezones, constraints).
    """
    db_engine = make_engine(os.environ.get("TEST_DATABASE_URL", "sqlite://"))
    Base.metadata.create_all(db_engine)
    yield db_engine
    Base.metadata.drop_all(db_engine)
    db_engine.dispose()


@pytest.fixture
def db_session(engine: Engine) -> Iterator[Session]:
    with make_session_factory(engine)() as session:
        yield session


@pytest.fixture
def client(engine: Engine, fetcher: SafeFetcher, dns_client: DnsClient) -> Iterator[TestClient]:
    """The real app over HTTP, wired to a test database, fake DNS and respx-mocked HTTP."""
    app = create_app(Settings(_env_file=None), engine=engine, fetcher=fetcher, dns=dns_client)
    with TestClient(app) as test_client:
        yield test_client
