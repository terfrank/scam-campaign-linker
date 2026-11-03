"""Tests for collect_site: all collectors together, and failures being logged and skipped."""

import logging

import pytest
import respx

from fakes import fixture_bytes, fixture_text
from scam_linker.collectors import dns_records, title
from scam_linker.collectors.base import Signal, SignalType, SiteContext
from scam_linker.collectors.runner import collect_site
from scam_linker.dns_client import DnsClient
from scam_linker.fetcher import FetchStatus, SafeFetcher

URL_A = "https://examplebank-secure-a.xyz/"
DOMAIN_A = "examplebank-secure-a.xyz"


def _mock_site_a(router: respx.MockRouter) -> None:
    router.get(URL_A).respond(200, html=fixture_text("html/kit_a.html"))
    router.get(f"{URL_A}assets/fav.ico").respond(
        200, headers={"content-type": "image/x-icon"}, content=fixture_bytes("favicons/kit.ico")
    )
    router.get(f"https://rdap.org/domain/{DOMAIN_A}").respond(
        200,
        headers={"content-type": "application/rdap+json"},
        content=fixture_bytes(f"rdap/{DOMAIN_A}.json"),
    )
    router.get("https://crt.sh/").respond(
        200,
        headers={"content-type": "application/json"},
        content=fixture_bytes(f"crtsh/{DOMAIN_A}.json"),
    )


def test_collects_every_signal_type(
    fetcher: SafeFetcher, dns_client: DnsClient, router: respx.MockRouter
) -> None:
    _mock_site_a(router)

    result = collect_site(URL_A, fetcher, dns_client)

    assert result.fetch_status is FetchStatus.OK
    assert result.domain == DOMAIN_A
    assert result.errors == {}
    assert {signal.type for signal in result.signals} == set(SignalType)


def test_failing_collector_is_logged_and_skipped(
    fetcher: SafeFetcher,
    dns_client: DnsClient,
    router: respx.MockRouter,
    caplog: pytest.LogCaptureFixture,
) -> None:
    router.get(URL_A).respond(200, html=fixture_text("html/kit_a.html"))

    def broken(ctx: SiteContext) -> list[Signal]:
        raise RuntimeError("parser exploded")

    with caplog.at_level(logging.WARNING):
        result = collect_site(
            URL_A, fetcher, dns_client, collectors={"broken": broken, "title": title.collect}
        )

    assert result.errors == {"broken": "RuntimeError: parser exploded"}
    assert Signal(SignalType.TITLE, "examplebank - secure login") in result.signals
    assert "collector broken skipped" in caplog.text


def test_dead_site_still_gets_dns_signals(
    fetcher: SafeFetcher, dns_client: DnsClient, router: respx.MockRouter
) -> None:
    router.get(URL_A).respond(503)

    result = collect_site(
        URL_A,
        fetcher,
        dns_client,
        collectors={"title": title.collect, "ip_and_asn": dns_records.collect_ip_and_asn},
    )

    assert result.fetch_status is FetchStatus.HTTP_ERROR
    assert result.errors == {}
    assert [s.type for s in result.signals] == [SignalType.ASN, SignalType.IP]


def test_invalid_url_makes_no_requests(
    fetcher: SafeFetcher, dns_client: DnsClient, router: respx.MockRouter
) -> None:
    result = collect_site("not a url", fetcher, dns_client)

    assert result.fetch_status is FetchStatus.INVALID_URL
    assert result.signals == ()
    assert len(router.calls) == 0
