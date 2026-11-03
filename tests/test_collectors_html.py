"""Tests for collectors that only read the page HTML."""

from collections.abc import Callable

import pytest

from fakes import fixture_text, make_context
from scam_linker.collectors import html_fingerprint, kit_paths, title, tracking_ids
from scam_linker.collectors.base import Signal, SignalType, SiteContext
from scam_linker.collectors.html_parse import parse_html
from scam_linker.dns_client import DnsClient
from scam_linker.fetcher import SafeFetcher

URL_A = "https://examplebank-secure-a.xyz/"
URL_B = "https://examplebank-secure-b.xyz/"

ContextFactory = Callable[[str, str | None], SiteContext]


@pytest.fixture
def context_for(fetcher: SafeFetcher, dns_client: DnsClient) -> ContextFactory:
    """Build a SiteContext for a URL serving one of the HTML fixtures."""

    def build(url: str, fixture: str | None) -> SiteContext:
        html = fixture_text(f"html/{fixture}") if fixture else None
        return make_context(url, html, fetcher=fetcher, dns=dns_client)

    return build


# --- parsing -------------------------------------------------------------------


def test_parser_extracts_title_icons_and_links() -> None:
    page = parse_html(fixture_text("html/kit_a.html"))

    assert page.title == "Examplebank - Secure Login"
    assert page.icon_hrefs == ("/assets/fav.ico",)
    assert "/secure/verify.php" in page.links
    assert page.tags[:3] == ("html", "head", "meta")


def test_parser_treats_script_content_as_text_not_tags() -> None:
    page = parse_html("<script>document.write('<iframe src=/x>')</script>")

    assert page.tags == ("script",)
    assert page.links == ()


# --- title ---------------------------------------------------------------------


def test_title_is_normalised(context_for: ContextFactory) -> None:
    a = title.collect(context_for(URL_A, "kit_a.html"))
    b = title.collect(context_for(URL_B, "kit_b.html"))

    assert a == b == [Signal(SignalType.TITLE, "examplebank - secure login")]


def test_title_skipped_when_page_not_fetched(context_for: ContextFactory) -> None:
    assert title.collect(context_for(URL_A, None)) == []


# --- html fingerprint ----------------------------------------------------------


def test_same_kit_with_different_text_has_same_fingerprint(context_for: ContextFactory) -> None:
    a = html_fingerprint.collect(context_for(URL_A, "kit_a.html"))
    b = html_fingerprint.collect(context_for(URL_B, "kit_b.html"))

    assert len(a) == 1
    assert a == b


def test_different_page_has_different_fingerprint(context_for: ContextFactory) -> None:
    a = html_fingerprint.collect(context_for(URL_A, "kit_a.html"))
    other = html_fingerprint.collect(context_for("https://harmless-blog.org/", "unrelated.html"))

    assert other and a != other


def test_tiny_pages_are_not_fingerprinted(context_for: ContextFactory) -> None:
    """Every '403 Forbidden' page looks alike; fingerprinting them would link unrelated sites."""
    assert html_fingerprint.collect(context_for(URL_A, "tiny.html")) == []


# --- kit paths -----------------------------------------------------------------


def test_kit_paths_found_in_links_and_page_url(context_for: ContextFactory) -> None:
    ctx = context_for("https://examplebank-secure-a.xyz/login/index.php", "kit_a.html")

    values = [signal.value for signal in kit_paths.collect(ctx)]

    assert values == ["/account/update", "/login/index.php", "/secure/verify.php"]


def test_ordinary_pages_have_no_kit_paths(context_for: ContextFactory) -> None:
    """'/author/jane' contains 'auth' as a substring but not as a whole word."""
    ctx = context_for("https://harmless-blog.org/", "unrelated.html")

    assert kit_paths.collect(ctx) == []


@pytest.mark.parametrize(
    ("link", "expected"),
    [
        ("/secure/login.php", True),
        ("https://other.example/next.php?id=1", True),
        ("/Verify/", True),
        ("/assets/login-bg.png", False),  # static file
        ("/author/jane", False),
        ("mailto:help@example.com", False),
        ("javascript:void(0)", False),
    ],
)
def test_kit_path_rules(link: str, expected: bool) -> None:
    assert bool(kit_paths.kit_paths([link])) is expected


# --- tracking IDs --------------------------------------------------------------


def test_tracking_ids_found(context_for: ContextFactory) -> None:
    values = [s.value for s in tracking_ids.collect(context_for(URL_A, "kit_a.html"))]

    assert values == ["G-EXMPL12345", "fb-pixel:123456789012345"]


def test_tracking_ids_ignore_lookalike_text(context_for: ContextFactory) -> None:
    """'G-STRING' and 'SHA-256' in page text must not be reported."""
    values = [s.value for s in tracking_ids.collect(context_for(URL_A, "unrelated.html"))]

    assert values == ["UA-12345678-1"]


@pytest.mark.parametrize(
    "snippet",
    ["UA-1234567-12", "G-ABCD123456", "GTM-K9X2PQ", "AW-123456789", "fbq('init', '9876543210')"],
)
def test_each_tracking_id_format_is_recognised(snippet: str) -> None:
    assert len(tracking_ids.tracking_ids(f"<script>{snippet}</script>")) == 1
