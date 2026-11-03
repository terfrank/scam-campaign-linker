"""Test doubles shared across test modules. No network, no real DNS, no real time."""

import json
from pathlib import Path
from typing import Any

import dns.rdata
import dns.resolver
import respx

from scam_linker.collectors.base import SiteContext
from scam_linker.dns_client import DnsClient
from scam_linker.domains import hostname_of, registered_domain
from scam_linker.fetcher import FetchResult, FetchStatus, SafeFetcher

PUBLIC_IP = "93.184.215.14"
FIXTURES = Path(__file__).parent / "fixtures"


def fixture_bytes(relative_path: str) -> bytes:
    return (FIXTURES / relative_path).read_bytes()


def fixture_text(relative_path: str) -> str:
    return (FIXTURES / relative_path).read_text(encoding="utf-8")


def make_context(
    url: str, html: str | None, *, fetcher: SafeFetcher, dns: DnsClient
) -> SiteContext:
    """A SiteContext as if `url` had been fetched and returned `html` (None = fetch failed)."""
    hostname = hostname_of(url) or ""
    if html is None:
        page = FetchResult(requested_url=url, status=FetchStatus.TIMEOUT)
    else:
        page = FetchResult(
            requested_url=url,
            status=FetchStatus.OK,
            final_url=url,
            http_status=200,
            content_type="text/html",
            charset="utf-8",
            body=html.encode(),
        )
    return SiteContext(
        url=url,
        hostname=hostname,
        domain=registered_domain(hostname),
        page=page,
        fetcher=fetcher,
        dns=dns,
    )


class FakeClock:
    """A controllable clock. `step` seconds pass on every read; sleeping advances time."""

    def __init__(self, step: float = 0.0) -> None:
        self.now = 0.0
        self.step = step
        self.sleeps: list[float] = []

    def __call__(self) -> float:
        self.now += self.step
        return self.now

    def sleep(self, seconds: float) -> None:
        self.sleeps.append(seconds)
        self.now += seconds


class FakeDnsResolver:
    """Answers DNS queries from tests/fixtures/dns/answers.json using real dnspython rdata."""

    def __init__(self, answers: dict[str, dict[str, list[str]]] | None = None) -> None:
        self.answers = (
            answers if answers is not None else json.loads(fixture_text("dns/answers.json"))
        )
        self.queries: list[tuple[str, str]] = []

    def resolve(self, qname: str, rdtype: str) -> list[Any]:
        self.queries.append((qname, rdtype))
        records = self.answers.get(qname)
        if records is None:
            raise dns.resolver.NXDOMAIN
        if rdtype not in records:
            raise dns.resolver.NoAnswer
        return [dns.rdata.from_text("IN", rdtype, text) for text in records[rdtype]]


def serve(router: respx.MockRouter, url: str, fixture: str) -> None:
    router.get(url).respond(200, html=fixture_text(f"html/{fixture}"))
