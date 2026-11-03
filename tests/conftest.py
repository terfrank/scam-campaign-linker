"""Shared pytest fixtures."""

from collections.abc import Iterator

import pytest
import respx
from fastapi.testclient import TestClient

from fakes import PUBLIC_IP, FakeClock, FakeDnsResolver
from scam_linker.dns_client import DnsClient
from scam_linker.fetcher import RateLimiter, SafeFetcher
from scam_linker.main import create_app


@pytest.fixture
def client() -> Iterator[TestClient]:
    """An in-process HTTP client for the API. No network, no real server."""
    with TestClient(create_app()) as test_client:
        yield test_client


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
