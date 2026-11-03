"""Tests proving every safety limit in scam_linker.fetcher.

respx intercepts all httpx traffic: any request without a matching route raises an error,
so these tests cannot reach the network even by accident. DNS is replaced by a fake resolver
and time by a fake clock, so nothing here sleeps or resolves real names.
"""

import socket
import threading
from collections.abc import Iterator

import httpx
import pytest
import respx

from fakes import PUBLIC_IP, FakeClock
from scam_linker.fetcher import (
    MAX_BYTES,
    MAX_REDIRECTS,
    TIMEOUT_SECONDS,
    USER_AGENT,
    FetchStatus,
    RateLimiter,
    ResourceKind,
    SafeFetcher,
    build_client,
)

SITE = "http://scam.example"


# --- basic behaviour -------------------------------------------------------


def test_fetches_html(fetcher: SafeFetcher, router: respx.MockRouter) -> None:
    router.get(f"{SITE}/").respond(200, html="<html><title>Hi</title></html>")

    result = fetcher.fetch(f"{SITE}/", ResourceKind.HTML)

    assert result.status is FetchStatus.OK
    assert result.text() == "<html><title>Hi</title></html>"
    assert result.content_type == "text/html"
    assert result.final_url == f"{SITE}/"


def test_client_is_configured_with_safety_limits() -> None:
    client = build_client()

    assert client.timeout == httpx.Timeout(TIMEOUT_SECONDS)
    assert client.follow_redirects is False
    assert client.trust_env is False
    assert client.headers["user-agent"] == USER_AGENT
    client.close()


def test_http_error_status_is_reported(fetcher: SafeFetcher, router: respx.MockRouter) -> None:
    router.get(f"{SITE}/gone").respond(404)

    result = fetcher.fetch(f"{SITE}/gone", ResourceKind.HTML)

    assert result.status is FetchStatus.HTTP_ERROR
    assert result.http_status == 404


def test_network_error_never_raises(fetcher: SafeFetcher, router: respx.MockRouter) -> None:
    router.get(f"{SITE}/").mock(side_effect=httpx.ConnectError("refused"))

    result = fetcher.fetch(f"{SITE}/", ResourceKind.HTML)

    assert result.status is FetchStatus.NETWORK_ERROR


def test_dns_failure_never_raises(clock: FakeClock, router: respx.MockRouter) -> None:
    def broken_resolver(host: str) -> list[str]:
        raise socket.gaierror("no such host")

    with SafeFetcher(resolver=broken_resolver, clock=clock, sleep=clock.sleep) as fetcher:
        result = fetcher.fetch(f"{SITE}/", ResourceKind.HTML)

    assert result.status is FetchStatus.NETWORK_ERROR
    assert len(router.calls) == 0


# --- user agent and cookies --------------------------------------------------


def test_sends_research_user_agent_and_never_sends_cookies(
    fetcher: SafeFetcher, router: respx.MockRouter
) -> None:
    router.get(f"{SITE}/login").respond(
        302, headers={"location": "/home", "set-cookie": "session=abc123; Path=/"}
    )
    home = router.get(f"{SITE}/home").respond(200, html="<html></html>")

    fetcher.fetch(f"{SITE}/login", ResourceKind.HTML)
    fetcher.fetch(f"{SITE}/home", ResourceKind.HTML)

    for call in home.calls:
        assert call.request.headers["user-agent"] == USER_AGENT
        assert "cookie" not in call.request.headers


# --- no JavaScript, no sub-resources, allowed content types only -------------


def test_never_requests_scripts_or_submits_forms(
    fetcher: SafeFetcher, router: respx.MockRouter
) -> None:
    page = (
        '<html><script src="/evil.js"></script><script>fetch("/beacon")</script>'
        '<form action="/steal" method="post"><input name="pw"></form></html>'
    )
    router.get(f"{SITE}/").respond(200, html=page)
    side_effects = router.route(path__regex=r"^/(evil\.js|beacon|steal)$").respond(200)

    result = fetcher.fetch(f"{SITE}/", ResourceKind.HTML)

    assert result.text() == page  # returned as raw text, nothing executed
    assert side_effects.call_count == 0
    assert {call.request.method for call in router.calls} == {"GET"}


@pytest.mark.parametrize(
    ("kind", "content_type"),
    [
        (ResourceKind.HTML, "application/javascript"),
        (ResourceKind.HTML, "application/zip"),
        (ResourceKind.HTML, ""),
        (ResourceKind.FAVICON, "text/html"),
        (ResourceKind.FAVICON, "application/x-msdownload"),
    ],
)
def test_rejects_disallowed_content_types(
    fetcher: SafeFetcher, router: respx.MockRouter, kind: ResourceKind, content_type: str
) -> None:
    router.get(f"{SITE}/file").respond(200, headers={"content-type": content_type}, content=b"x")

    result = fetcher.fetch(f"{SITE}/file", kind)

    assert result.status is FetchStatus.DISALLOWED_CONTENT_TYPE
    assert result.body == b""


def test_accepts_favicon(fetcher: SafeFetcher, router: respx.MockRouter) -> None:
    router.get(f"{SITE}/favicon.ico").respond(
        200, headers={"content-type": "image/x-icon"}, content=b"\x00\x00\x01\x00"
    )

    result = fetcher.fetch(f"{SITE}/favicon.ico", ResourceKind.FAVICON)

    assert result.status is FetchStatus.OK
    assert result.body == b"\x00\x00\x01\x00"


# --- size cap ------------------------------------------------------------------


def test_rejects_large_declared_content_length(
    fetcher: SafeFetcher, router: respx.MockRouter
) -> None:
    router.get(f"{SITE}/").respond(
        200, headers={"content-type": "text/html"}, content=b"x" * (MAX_BYTES + 1)
    )

    result = fetcher.fetch(f"{SITE}/", ResourceKind.HTML)

    assert result.status is FetchStatus.TOO_LARGE
    assert result.body == b""


def test_stops_reading_a_stream_that_exceeds_the_cap(
    fetcher: SafeFetcher, router: respx.MockRouter
) -> None:
    """No Content-Length header: the cap must still hold while streaming."""
    chunk_size = 64 * 1024
    total_chunks = 100  # 6.4 MB on offer
    chunks_sent = 0

    def endless_body() -> Iterator[bytes]:
        nonlocal chunks_sent
        for _ in range(total_chunks):
            chunks_sent += 1
            yield b"x" * chunk_size

    router.get(f"{SITE}/").respond(
        200, headers={"content-type": "text/html"}, content=endless_body()
    )

    result = fetcher.fetch(f"{SITE}/", ResourceKind.HTML)

    assert result.status is FetchStatus.TOO_LARGE
    assert chunks_sent == MAX_BYTES // chunk_size + 1  # stopped right after crossing 2 MB
    assert chunks_sent < total_chunks


# --- timeouts ------------------------------------------------------------------


@pytest.mark.parametrize("error", [httpx.ConnectTimeout, httpx.ReadTimeout])
def test_network_timeouts_are_reported(
    fetcher: SafeFetcher, router: respx.MockRouter, error: type[httpx.TimeoutException]
) -> None:
    router.get(f"{SITE}/").mock(side_effect=error("too slow"))

    result = fetcher.fetch(f"{SITE}/", ResourceKind.HTML)

    assert result.status is FetchStatus.TIMEOUT


def test_slow_drip_download_hits_total_deadline(router: respx.MockRouter) -> None:
    """A server sending tiny chunks slowly never trips the read timeout, so we cap total time."""
    clock = FakeClock(step=2.0)  # every clock read is 2 s later
    router.get(f"{SITE}/").respond(
        200, headers={"content-type": "text/html"}, content=iter([b"<"] * 50)
    )

    with SafeFetcher(resolver=lambda _: [PUBLIC_IP], clock=clock, sleep=clock.sleep) as fetcher:
        result = fetcher.fetch(f"{SITE}/", ResourceKind.HTML)

    assert result.status is FetchStatus.TIMEOUT


# --- redirects -----------------------------------------------------------------


def _redirect_chain(router: respx.MockRouter, hops: int) -> respx.Route:
    """Create /r1 -> /r2 -> ... -> /final with `hops` redirects. Returns the /final route."""
    for i in range(1, hops + 1):
        target = f"/r{i + 1}" if i < hops else "/final"
        router.get(f"{SITE}/r{i}").respond(302, headers={"location": target})
    return router.get(f"{SITE}/final").respond(200, html="<html>end</html>")


def test_follows_up_to_three_redirects(fetcher: SafeFetcher, router: respx.MockRouter) -> None:
    _redirect_chain(router, hops=MAX_REDIRECTS)

    result = fetcher.fetch(f"{SITE}/r1", ResourceKind.HTML)

    assert result.status is FetchStatus.OK
    assert result.final_url == f"{SITE}/final"
    assert len(result.redirect_chain) == MAX_REDIRECTS


def test_stops_after_three_redirects(fetcher: SafeFetcher, router: respx.MockRouter) -> None:
    final = _redirect_chain(router, hops=MAX_REDIRECTS + 1)

    result = fetcher.fetch(f"{SITE}/r1", ResourceKind.HTML)

    assert result.status is FetchStatus.TOO_MANY_REDIRECTS
    assert final.call_count == 0


# --- URL and address checks (SSRF) -------------------------------------------


@pytest.mark.parametrize(
    "url",
    [
        "file:///etc/passwd",
        "ftp://scam.example/kit.zip",
        "javascript:alert(1)",
        "http://user:password@scam.example/",
        "http:///no-host",
    ],
)
def test_rejects_unsafe_urls(fetcher: SafeFetcher, router: respx.MockRouter, url: str) -> None:
    result = fetcher.fetch(url, ResourceKind.HTML)

    assert result.status is FetchStatus.INVALID_URL
    assert len(router.calls) == 0


@pytest.mark.parametrize(
    "ip", ["127.0.0.1", "10.0.0.5", "192.168.1.1", "169.254.169.254", "::1", "fd00::1"]
)
def test_refuses_hosts_resolving_to_internal_addresses(
    fetcher: SafeFetcher,
    router: respx.MockRouter,
    addresses: dict[str, list[str]],
    ip: str,
) -> None:
    addresses["internal.example"] = [ip]

    result = fetcher.fetch("http://internal.example/", ResourceKind.HTML)

    assert result.status is FetchStatus.BLOCKED_ADDRESS
    assert len(router.calls) == 0


def test_refuses_redirect_to_internal_address(
    fetcher: SafeFetcher, router: respx.MockRouter, addresses: dict[str, list[str]]
) -> None:
    addresses["metadata.internal"] = ["169.254.169.254"]
    router.get(f"{SITE}/").respond(302, headers={"location": "http://metadata.internal/latest/"})

    result = fetcher.fetch(f"{SITE}/", ResourceKind.HTML)

    assert result.status is FetchStatus.BLOCKED_ADDRESS
    assert result.redirect_chain == (f"{SITE}/",)


# --- robots.txt ------------------------------------------------------------------


def test_respects_robots_disallow(fetcher: SafeFetcher, router: respx.MockRouter) -> None:
    router["robots"].respond(200, text="User-agent: *\nDisallow: /private/\n")
    private = router.get(f"{SITE}/private/page").respond(200, html="<html></html>")

    result = fetcher.fetch(f"{SITE}/private/page", ResourceKind.HTML)

    assert result.status is FetchStatus.BLOCKED_BY_ROBOTS
    assert private.call_count == 0


def test_robots_server_error_means_disallow_all(
    fetcher: SafeFetcher, router: respx.MockRouter
) -> None:
    """RFC 9309: if robots.txt is unreachable (5xx), assume everything is disallowed."""
    router["robots"].respond(503)
    page = router.get(f"{SITE}/").respond(200, html="<html></html>")

    result = fetcher.fetch(f"{SITE}/", ResourceKind.HTML)

    assert result.status is FetchStatus.BLOCKED_BY_ROBOTS
    assert page.call_count == 0


def test_robots_is_fetched_once_per_origin(fetcher: SafeFetcher, router: respx.MockRouter) -> None:
    router.get(f"{SITE}/a").respond(200, html="<html></html>")
    router.get(f"{SITE}/b").respond(200, html="<html></html>")

    fetcher.fetch(f"{SITE}/a", ResourceKind.HTML)
    fetcher.fetch(f"{SITE}/b", ResourceKind.HTML)

    assert router["robots"].call_count == 1


# --- rate limiting ---------------------------------------------------------------


def test_rate_limiter_spaces_requests_to_the_same_host() -> None:
    clock = FakeClock()
    limiter = RateLimiter(1.0, clock, clock.sleep)

    limiter.wait("a.example")
    limiter.wait("a.example")
    limiter.wait("a.example")

    assert clock.sleeps == [1.0, 1.0]


def test_rate_limiter_does_not_delay_different_hosts() -> None:
    clock = FakeClock()
    limiter = RateLimiter(1.0, clock, clock.sleep)

    limiter.wait("a.example")
    limiter.wait("b.example")

    assert clock.sleeps == []


def test_fetcher_rate_limits_every_request(
    fetcher: SafeFetcher, router: respx.MockRouter, clock: FakeClock
) -> None:
    router.get(f"{SITE}/").respond(200, html="<html></html>")

    fetcher.fetch(f"{SITE}/", ResourceKind.HTML)  # robots.txt, then the page
    fetcher.fetch(f"{SITE}/", ResourceKind.HTML)  # the page again

    assert clock.sleeps == [1.0, 1.0]


# --- JSON APIs (crt.sh, RDAP) ----------------------------------------------------


def test_json_kind_accepts_api_responses_without_checking_robots(
    fetcher: SafeFetcher, router: respx.MockRouter
) -> None:
    """robots.txt governs crawling pages, not public APIs built for programmatic queries."""
    router["robots"].respond(200, text="User-agent: *\nDisallow: /\n")
    router.get("https://rdap.example/domain/a.xyz").respond(
        200, headers={"content-type": "application/rdap+json"}, content=b"{}"
    )

    result = fetcher.fetch("https://rdap.example/domain/a.xyz", ResourceKind.JSON)

    assert result.status is FetchStatus.OK
    assert router["robots"].call_count == 0


def test_rate_limiter_reserves_distinct_slots_across_threads() -> None:
    """Concurrent callers for one host must queue up 1 s apart, never fire together."""
    sleeps: list[float] = []
    limiter = RateLimiter(1.0, clock=lambda: 0.0, sleep=sleeps.append)

    threads = [threading.Thread(target=limiter.wait, args=("a.example",)) for _ in range(3)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert sorted(sleeps) == [1.0, 2.0]  # slots at 0 s, 1 s and 2 s
