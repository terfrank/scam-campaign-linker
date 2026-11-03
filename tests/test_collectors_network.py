"""Tests for collectors that make their own lookups: favicon, DNS, RDAP and crt.sh.

HTTP is mocked with respx and DNS is answered from tests/fixtures/dns/answers.json.
"""

import pytest
import respx

from fakes import FakeClock, FakeDnsResolver, fixture_bytes, fixture_text, make_context
from scam_linker.collectors import crtsh, dns_records, favicon, rdap
from scam_linker.collectors.base import CollectorError, Signal, SignalType
from scam_linker.dns_client import DnsClient
from scam_linker.fetcher import RateLimiter, SafeFetcher

URL_A = "https://examplebank-secure-a.xyz/"
DOMAIN_A = "examplebank-secure-a.xyz"
ICON = fixture_bytes("favicons/kit.ico")


# --- favicon -------------------------------------------------------------------


def test_favicon_hash_uses_shodan_scheme() -> None:
    """Pinned values: changing the hashing scheme would silently break every stored link."""
    assert favicon.favicon_hash(b"hello") == "1155597304"
    assert favicon.favicon_hash(ICON) == "495416780"


def test_favicon_follows_link_rel_icon(
    fetcher: SafeFetcher, dns_client: DnsClient, router: respx.MockRouter
) -> None:
    icon = router.get(f"{URL_A}assets/fav.ico").respond(
        200, headers={"content-type": "image/x-icon"}, content=ICON
    )
    ctx = make_context(URL_A, fixture_text("html/kit_a.html"), fetcher=fetcher, dns=dns_client)

    signals = favicon.collect(ctx)

    assert icon.call_count == 1
    assert signals == [Signal(SignalType.FAVICON_HASH, favicon.favicon_hash(ICON))]


def test_favicon_falls_back_to_favicon_ico(
    fetcher: SafeFetcher, dns_client: DnsClient, router: respx.MockRouter
) -> None:
    default = router.get(f"{URL_A}favicon.ico").respond(
        200, headers={"content-type": "image/vnd.microsoft.icon"}, content=ICON
    )
    ctx = make_context(URL_A, fixture_text("html/tiny.html"), fetcher=fetcher, dns=dns_client)

    favicon.collect(ctx)

    assert default.call_count == 1


def test_favicon_fetch_failure_raises_collector_error(
    fetcher: SafeFetcher, dns_client: DnsClient, router: respx.MockRouter
) -> None:
    router.get(f"{URL_A}favicon.ico").respond(404)
    ctx = make_context(URL_A, None, fetcher=fetcher, dns=dns_client)

    with pytest.raises(CollectorError, match="http_error"):
        favicon.collect(ctx)


# --- DNS: ip, asn, nameservers -------------------------------------------------


def test_ip_and_asn(fetcher: SafeFetcher, dns_client: DnsClient) -> None:
    ctx = make_context(URL_A, None, fetcher=fetcher, dns=dns_client)

    assert dns_records.collect_ip_and_asn(ctx) == [
        Signal(SignalType.ASN, "AS64500"),
        Signal(SignalType.IP, "45.67.89.10"),
    ]


def test_multiple_ips_and_multi_origin_asn(fetcher: SafeFetcher, dns_client: DnsClient) -> None:
    ctx = make_context("https://examplebank-secure-b.xyz/", None, fetcher=fetcher, dns=dns_client)

    values = {(s.type, s.value) for s in dns_records.collect_ip_and_asn(ctx)}

    assert values == {
        (SignalType.IP, "45.67.89.10"),
        (SignalType.IP, "45.67.89.11"),
        (SignalType.ASN, "AS64500"),
        (SignalType.ASN, "AS64501"),
    }


def test_nameservers_use_registered_domain_and_are_normalised(
    fetcher: SafeFetcher, dns_client: DnsClient
) -> None:
    ctx = make_context(
        "https://login.examplebank-secure-a.xyz/", None, fetcher=fetcher, dns=dns_client
    )

    assert dns_records.collect_nameservers(ctx) == [
        Signal(SignalType.NAMESERVER, "ns1.example-host.xyz"),
        Signal(SignalType.NAMESERVER, "ns2.example-host.xyz"),
    ]


def test_unknown_domain_gives_no_signals(fetcher: SafeFetcher, dns_client: DnsClient) -> None:
    ctx = make_context("https://no-such-site.xyz/", None, fetcher=fetcher, dns=dns_client)

    assert dns_records.collect_ip_and_asn(ctx) == []
    assert dns_records.collect_nameservers(ctx) == []


def test_ip_literal_url_skips_a_lookup(
    fetcher: SafeFetcher, dns_client: DnsClient, dns_resolver: FakeDnsResolver
) -> None:
    ctx = make_context("http://45.67.89.10/login", None, fetcher=fetcher, dns=dns_client)

    signals = dns_records.collect_ip_and_asn(ctx)

    assert Signal(SignalType.IP, "45.67.89.10") in signals
    assert ("45.67.89.10", "A") not in dns_resolver.queries
    with pytest.raises(CollectorError, match="no registered domain"):
        dns_records.collect_nameservers(ctx)


def test_private_ips_are_not_sent_to_asn_lookup(fetcher: SafeFetcher, clock: FakeClock) -> None:
    resolver = FakeDnsResolver({"sinkholed.xyz": {"A": ["10.0.0.1"]}})
    dns = DnsClient(resolver=resolver, limiter=RateLimiter(0.2, clock, clock.sleep))
    ctx = make_context("https://sinkholed.xyz/", None, fetcher=fetcher, dns=dns)

    assert dns_records.collect_ip_and_asn(ctx) == [Signal(SignalType.IP, "10.0.0.1")]
    assert [rdtype for _, rdtype in resolver.queries] == ["A"]


def test_dns_queries_are_rate_limited(dns_client: DnsClient, clock: FakeClock) -> None:
    dns_client.a_records(DOMAIN_A)
    dns_client.ns_records(DOMAIN_A)

    assert clock.sleeps == [0.2]


# --- RDAP ----------------------------------------------------------------------

RDAP_URL = f"https://rdap.org/domain/{DOMAIN_A}"


def test_rdap_registrar_and_created_date(
    fetcher: SafeFetcher, dns_client: DnsClient, router: respx.MockRouter
) -> None:
    router.get(RDAP_URL).respond(
        200,
        headers={"content-type": "application/rdap+json"},
        content=fixture_bytes(f"rdap/{DOMAIN_A}.json"),
    )
    ctx = make_context(URL_A, None, fetcher=fetcher, dns=dns_client)

    assert rdap.collect(ctx) == [
        Signal(SignalType.REGISTRAR, "example registrar, inc."),
        Signal(SignalType.CREATED_DATE, "2026-11-02"),
    ]
    assert router["robots"].call_count == 0  # APIs are not crawled pages


def test_rdap_ignores_redacted_registrant() -> None:
    registrar, _ = rdap.parse_rdap({"entities": [{"roles": ["registrant"], "vcardArray": []}]})

    assert registrar is None


def test_rdap_not_found_raises(
    fetcher: SafeFetcher, dns_client: DnsClient, router: respx.MockRouter
) -> None:
    router.get(RDAP_URL).respond(404)
    ctx = make_context(URL_A, None, fetcher=fetcher, dns=dns_client)

    with pytest.raises(CollectorError, match="RDAP lookup"):
        rdap.collect(ctx)


def test_rdap_invalid_json_raises(
    fetcher: SafeFetcher, dns_client: DnsClient, router: respx.MockRouter
) -> None:
    router.get(RDAP_URL).respond(200, headers={"content-type": "application/json"}, content=b"{")
    ctx = make_context(URL_A, None, fetcher=fetcher, dns=dns_client)

    with pytest.raises(CollectorError, match="not JSON"):
        rdap.collect(ctx)


# --- crt.sh --------------------------------------------------------------------


def _mock_crtsh(router: respx.MockRouter) -> respx.Route:
    return router.get("https://crt.sh/", params={"q": DOMAIN_A, "output": "json"}).respond(
        200,
        headers={"content-type": "application/json"},
        content=fixture_bytes(f"crtsh/{DOMAIN_A}.json"),
    )


def test_crtsh_reports_only_certificates_shared_with_other_domains(
    fetcher: SafeFetcher, dns_client: DnsClient, router: respx.MockRouter
) -> None:
    """3 rows: a single-domain cert (ignored) and a precert/cert pair (one signal)."""
    _mock_crtsh(router)
    ctx = make_context(URL_A, None, fetcher=fetcher, dns=dns_client)

    assert crtsh.collect(ctx) == [
        Signal(SignalType.CERT, "295813:03bb00000000000000000000000000000002")
    ]


def test_cert_domains_handles_wildcards_and_subdomains() -> None:
    entry = {"common_name": "a.xyz", "name_value": "www.a.xyz\n*.b.top\nlogin.c.co.uk"}

    assert crtsh.cert_domains(entry) == {"a.xyz", "b.top", "c.co.uk"}


def test_crtsh_html_error_page_is_refused(
    fetcher: SafeFetcher, dns_client: DnsClient, router: respx.MockRouter
) -> None:
    router.get("https://crt.sh/").respond(200, html="<html>Busy, try later</html>")
    ctx = make_context(URL_A, None, fetcher=fetcher, dns=dns_client)

    with pytest.raises(CollectorError, match="disallowed_content_type"):
        crtsh.collect(ctx)
