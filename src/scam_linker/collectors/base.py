"""Types shared by every collector."""

from collections.abc import Callable
from dataclasses import dataclass
from enum import StrEnum
from functools import cached_property

from scam_linker.collectors.html_parse import ParsedPage, parse_html
from scam_linker.dns_client import DnsClient
from scam_linker.fetcher import FetchResult, SafeFetcher


class SignalType(StrEnum):
    FAVICON_HASH = "favicon_hash"
    HTML_FINGERPRINT = "html_fingerprint"
    TITLE = "title"
    KIT_PATH = "kit_path"
    TRACKING_ID = "tracking_id"
    IP = "ip"
    ASN = "asn"
    NAMESERVER = "nameserver"
    REGISTRAR = "registrar"
    CREATED_DATE = "created_date"
    CERT = "cert"  # a certificate (issuer:serial) that also covers other registered domains


@dataclass(frozen=True, order=True)
class Signal:
    """One observed fact about a site, e.g. Signal('favicon_hash', '-1234567')."""

    type: SignalType
    value: str


class CollectorError(Exception):
    """A collector could not produce its signal (fetch failed, no domain, bad data)."""


@dataclass
class SiteContext:
    """Everything collectors may use for one site. The page is fetched once and shared."""

    url: str
    hostname: str
    domain: str | None
    page: FetchResult
    fetcher: SafeFetcher
    dns: DnsClient

    @cached_property
    def html(self) -> str | None:
        """Raw page HTML, or None if the page could not be fetched."""
        return self.page.text() if self.page.ok else None

    @cached_property
    def parsed(self) -> ParsedPage | None:
        """Parsed page structure, or None if the page could not be fetched."""
        return parse_html(self.html) if self.html is not None else None

    def require_domain(self) -> str:
        """The registered domain, for collectors that cannot work without one."""
        if self.domain is None:
            raise CollectorError(f"no registered domain for {self.hostname}")
        return self.domain


Collector = Callable[[SiteContext], list[Signal]]
