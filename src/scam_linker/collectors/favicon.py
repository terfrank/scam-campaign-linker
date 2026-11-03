"""favicon_hash: MurmurHash3 of the site's favicon, using the same scheme as Shodan.

Shodan computes mmh3(base64 of the icon bytes, with a newline every 76 characters).
Matching that convention means our hashes can be searched on Shodan as http.favicon.hash.
"""

import base64
from urllib.parse import urljoin, urlsplit

import mmh3

from scam_linker.collectors.base import CollectorError, Signal, SignalType, SiteContext
from scam_linker.fetcher import ResourceKind


def favicon_hash(data: bytes) -> str:
    return str(mmh3.hash(base64.encodebytes(data)))


def favicon_url(ctx: SiteContext) -> str:
    """The first <link rel="icon"> target, or /favicon.ico on the page's final URL."""
    base = ctx.page.final_url or ctx.url
    hrefs = ctx.parsed.icon_hrefs if ctx.parsed is not None else ()
    for href in hrefs:
        candidate = urljoin(base, href)
        if urlsplit(candidate).scheme in ("http", "https"):  # skips data: URIs
            return candidate
    return urljoin(base, "/favicon.ico")


def collect(ctx: SiteContext) -> list[Signal]:
    url = favicon_url(ctx)
    result = ctx.fetcher.fetch(url, ResourceKind.FAVICON)
    if not result.ok:
        raise CollectorError(f"favicon fetch {url} failed: {result.status} {result.detail}")
    if not result.body:
        return []
    return [Signal(SignalType.FAVICON_HASH, favicon_hash(result.body))]
