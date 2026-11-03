"""Safe HTTP fetcher: the ONLY module allowed to make HTTP requests to scanned sites.

Every safety rule lives here so it can be tested in one place:

- GET only, http/https only, no credentials in URLs, no cookies, no proxy/.netrc from the env
- 5 s timeout per network operation AND for each whole download
- 2 MB response cap, checked on Content-Length and again while streaming
- at most 3 redirects, followed by hand so every hop is re-checked
- only HTML or favicon content types from scanned sites (plus JSON from the public crt.sh and
  RDAP APIs); sub-resources (scripts, images, forms) are never requested, and nothing is ever
  executed: the body is returned as raw bytes
- refuses hosts that resolve to private/internal addresses (SSRF protection)
- robots.txt respected (RFC 9309) for scanned sites, and a minimum delay between requests to
  the same host

`fetch()` never raises. Every outcome, including refusals, is a FetchResult with a status,
so a caller can log and skip a failure without crashing the run.
"""

import ipaddress
import logging
import socket
import time
from collections.abc import Callable
from dataclasses import dataclass
from enum import StrEnum
from http.cookiejar import CookieJar, DefaultCookiePolicy
from types import TracebackType
from urllib.parse import urljoin, urlsplit
from urllib.robotparser import RobotFileParser

import httpx

logger = logging.getLogger(__name__)

USER_AGENT = "ScamCampaignLinker/0.1 (passive defensive research; no JS, no forms)"
TIMEOUT_SECONDS = 5.0
MAX_BYTES = 2 * 1024 * 1024
MAX_REDIRECTS = 3
MIN_INTERVAL_SECONDS = 1.0  # minimum gap between two requests to the same host
ROBOTS_MAX_BYTES = 512 * 1024  # RFC 9309: parsers must handle at least 500 KiB


class ResourceKind(StrEnum):
    """What we are allowed to download. Anything else is refused."""

    HTML = "html"
    FAVICON = "favicon"
    ROBOTS = "robots"
    JSON = "json"  # public APIs only (crt.sh, RDAP), never scanned sites


# robots.txt governs crawlers visiting a site's pages. It does not apply to fetching robots.txt
# itself, or to public APIs (crt.sh, RDAP) that are designed for programmatic queries.
ROBOTS_APPLIES_TO = frozenset({ResourceKind.HTML, ResourceKind.FAVICON})


# None means "any content type" (robots.txt is often served with the wrong type).
ALLOWED_CONTENT_TYPES: dict[ResourceKind, frozenset[str] | None] = {
    ResourceKind.HTML: frozenset({"text/html", "application/xhtml+xml"}),
    ResourceKind.FAVICON: frozenset(
        {
            "image/x-icon",
            "image/vnd.microsoft.icon",
            "image/png",
            "image/gif",
            "image/jpeg",
            "image/svg+xml",
            "image/webp",
            "application/octet-stream",  # many servers send .ico files as this
        }
    ),
    ResourceKind.ROBOTS: None,
    ResourceKind.JSON: frozenset({"application/json", "application/rdap+json"}),
}

MAX_BYTES_BY_KIND: dict[ResourceKind, int] = {
    ResourceKind.HTML: MAX_BYTES,
    ResourceKind.FAVICON: MAX_BYTES,
    ResourceKind.ROBOTS: ROBOTS_MAX_BYTES,
    ResourceKind.JSON: MAX_BYTES,
}


class FetchStatus(StrEnum):
    """Outcome of a fetch. Stored later as Site.fetch_status."""

    OK = "ok"
    INVALID_URL = "invalid_url"
    BLOCKED_ADDRESS = "blocked_address"
    BLOCKED_BY_ROBOTS = "blocked_by_robots"
    DISALLOWED_CONTENT_TYPE = "disallowed_content_type"
    TOO_LARGE = "too_large"
    TOO_MANY_REDIRECTS = "too_many_redirects"
    TIMEOUT = "timeout"
    HTTP_ERROR = "http_error"
    NETWORK_ERROR = "network_error"


@dataclass(frozen=True)
class FetchResult:
    """Everything a collector needs from one fetch. `body` is empty unless status is OK."""

    requested_url: str
    status: FetchStatus
    final_url: str | None = None
    http_status: int | None = None
    content_type: str | None = None
    charset: str | None = None
    body: bytes = b""
    redirect_chain: tuple[str, ...] = ()
    detail: str = ""

    @property
    def ok(self) -> bool:
        return self.status is FetchStatus.OK

    def text(self) -> str:
        """Decode the body using the declared charset, falling back to UTF-8."""
        try:
            return self.body.decode(self.charset or "utf-8", errors="replace")
        except LookupError:  # unknown charset name sent by the server
            return self.body.decode("utf-8", errors="replace")


Resolver = Callable[[str], list[str]]


def resolve_host(host: str) -> list[str]:
    """Return every IP address a hostname resolves to (IPv4 and IPv6)."""
    infos = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    return sorted({str(info[4][0]) for info in infos})


def build_client() -> httpx.Client:
    """An httpx client configured with the safety limits. Redirects are handled by SafeFetcher."""
    return httpx.Client(
        headers={
            "User-Agent": USER_AGENT,
            "Accept": "text/html,application/xhtml+xml,image/*;q=0.8",
            # Ask for uncompressed bodies so a small compressed "zip bomb" can't expand in memory.
            "Accept-Encoding": "identity",
        },
        timeout=httpx.Timeout(TIMEOUT_SECONDS),
        follow_redirects=False,
        cookies=CookieJar(policy=DefaultCookiePolicy(allowed_domains=[])),  # rejects every cookie
        trust_env=False,  # ignore env proxies and ~/.netrc credentials
    )


class RateLimiter:
    """Keeps at least `min_interval` seconds between two requests to the same host."""

    def __init__(
        self,
        min_interval: float,
        clock: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        self._min_interval = min_interval
        self._clock = clock
        self._sleep = sleep
        self._last_request: dict[str, float] = {}

    def wait(self, host: str) -> None:
        """Block until a request to `host` is allowed, then record it."""
        now = self._clock()
        last = self._last_request.get(host)
        if last is not None:
            delay = last + self._min_interval - now
            if delay > 0:
                self._sleep(delay)
                now += delay
        self._last_request[host] = now


class SafeFetcher:
    """Fetches HTML pages and favicons while enforcing every safety rule.

    The resolver, clock and sleep function are injectable so tests run instantly
    and never touch real DNS or the network.
    """

    def __init__(
        self,
        *,
        client: httpx.Client | None = None,
        resolver: Resolver = resolve_host,
        clock: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], None] = time.sleep,
        min_interval: float = MIN_INTERVAL_SECONDS,
    ) -> None:
        self._client = client or build_client()
        self._resolver = resolver
        self._clock = clock
        self._limiter = RateLimiter(min_interval, clock, sleep)
        self._robots: dict[str, RobotFileParser] = {}

    def __enter__(self) -> "SafeFetcher":
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self.close()

    def close(self) -> None:
        self._client.close()

    def fetch(self, url: str, kind: ResourceKind) -> FetchResult:
        """GET one resource, following at most MAX_REDIRECTS redirects. Never raises."""
        chain: list[str] = []
        current = url
        while True:
            refusal = self._preflight(current, kind)
            if refusal is not None:
                status, detail = refusal
                return self._refuse(url, status, chain, detail)

            host = urlsplit(current).hostname or ""
            self._limiter.wait(host)
            started = self._clock()
            try:
                with self._client.stream("GET", current) as response:
                    if response.is_redirect:
                        if len(chain) >= MAX_REDIRECTS:
                            return self._refuse(
                                url, FetchStatus.TOO_MANY_REDIRECTS, chain, f"limit {MAX_REDIRECTS}"
                            )
                        chain.append(current)
                        current = urljoin(current, response.headers["location"])
                        continue
                    return self._read(url, current, chain, response, kind, started)
            except httpx.TimeoutException as exc:
                return self._refuse(url, FetchStatus.TIMEOUT, chain, type(exc).__name__)
            except httpx.InvalidURL as exc:
                return self._refuse(url, FetchStatus.INVALID_URL, chain, str(exc))
            except httpx.HTTPError as exc:
                return self._refuse(url, FetchStatus.NETWORK_ERROR, chain, type(exc).__name__)

    def _preflight(self, url: str, kind: ResourceKind) -> tuple[FetchStatus, str] | None:
        """Checks done before any request: URL shape, target address, robots.txt."""
        try:
            parts = urlsplit(url)
            hostname = parts.hostname
        except ValueError as exc:
            return FetchStatus.INVALID_URL, str(exc)
        if parts.scheme not in ("http", "https"):
            return FetchStatus.INVALID_URL, f"scheme {parts.scheme!r} not allowed"
        if not hostname:
            return FetchStatus.INVALID_URL, "missing host"
        if parts.username or parts.password:
            return FetchStatus.INVALID_URL, "credentials in URL not allowed"

        try:
            addresses = self._resolver(hostname)
        except OSError as exc:
            return FetchStatus.NETWORK_ERROR, f"DNS lookup failed: {exc}"
        if not addresses:
            return FetchStatus.NETWORK_ERROR, "DNS lookup returned no addresses"
        for address in addresses:
            if not ipaddress.ip_address(address).is_global:
                return FetchStatus.BLOCKED_ADDRESS, f"{hostname} resolves to {address}"

        if kind in ROBOTS_APPLIES_TO and not self._robots_allows(url):
            return FetchStatus.BLOCKED_BY_ROBOTS, "disallowed by robots.txt"
        return None

    def _robots_allows(self, url: str) -> bool:
        """Check robots.txt for the URL's origin, downloading it once per origin."""
        parts = urlsplit(url)
        origin = f"{parts.scheme}://{parts.netloc}"
        if origin not in self._robots:
            self._robots[origin] = self._load_robots(origin)
        return self._robots[origin].can_fetch(USER_AGENT, url)

    def _load_robots(self, origin: str) -> RobotFileParser:
        """Follows RFC 9309: a 4xx means "no rules", an error or 5xx means "disallow all"."""
        parser = RobotFileParser()
        result = self.fetch(f"{origin}/robots.txt", ResourceKind.ROBOTS)
        if result.ok:
            parser.parse(result.text().splitlines())
        elif result.http_status is not None and 400 <= result.http_status < 500:
            parser.parse([])  # no rules: everything allowed
        else:
            parser.parse(["User-agent: *", "Disallow: /"])
        return parser

    def _read(
        self,
        requested_url: str,
        final_url: str,
        chain: list[str],
        response: httpx.Response,
        kind: ResourceKind,
        started: float,
    ) -> FetchResult:
        """Validate status and content type, then stream the body within the size and time caps."""
        if not response.is_success:
            return self._refuse(
                requested_url,
                FetchStatus.HTTP_ERROR,
                chain,
                f"HTTP {response.status_code}",
                http_status=response.status_code,
            )

        media_type, charset = _parse_content_type(response.headers.get("content-type", ""))
        allowed = ALLOWED_CONTENT_TYPES[kind]
        if allowed is not None and media_type not in allowed:
            return self._refuse(
                requested_url,
                FetchStatus.DISALLOWED_CONTENT_TYPE,
                chain,
                f"{media_type or 'missing'} not allowed for {kind}",
                http_status=response.status_code,
            )

        limit = MAX_BYTES_BY_KIND[kind]
        declared = response.headers.get("content-length", "")
        if declared.isdigit() and int(declared) > limit:
            return self._refuse(
                requested_url,
                FetchStatus.TOO_LARGE,
                chain,
                f"Content-Length {declared} > {limit}",
                http_status=response.status_code,
            )

        body = bytearray()
        for chunk in response.iter_bytes():
            body.extend(chunk)
            if len(body) > limit:
                return self._refuse(
                    requested_url,
                    FetchStatus.TOO_LARGE,
                    chain,
                    f"body exceeded {limit} bytes",
                    http_status=response.status_code,
                )
            if self._clock() - started > TIMEOUT_SECONDS:
                return self._refuse(
                    requested_url,
                    FetchStatus.TIMEOUT,
                    chain,
                    f"download took longer than {TIMEOUT_SECONDS}s",
                    http_status=response.status_code,
                )

        return FetchResult(
            requested_url=requested_url,
            status=FetchStatus.OK,
            final_url=final_url,
            http_status=response.status_code,
            content_type=media_type,
            charset=charset,
            body=bytes(body),
            redirect_chain=tuple(chain),
        )

    @staticmethod
    def _refuse(
        requested_url: str,
        status: FetchStatus,
        chain: list[str],
        detail: str,
        http_status: int | None = None,
    ) -> FetchResult:
        logger.info("fetch %s -> %s (%s)", requested_url, status, detail)
        return FetchResult(
            requested_url=requested_url,
            status=status,
            http_status=http_status,
            redirect_chain=tuple(chain),
            detail=detail,
        )


def _parse_content_type(header: str) -> tuple[str, str | None]:
    """Split 'text/html; charset=UTF-8' into ('text/html', 'utf-8')."""
    media_type, _, params = header.partition(";")
    charset = None
    for param in params.split(";"):
        key, _, value = param.strip().partition("=")
        if key.lower() == "charset" and value:
            charset = value.strip("\"' ").lower()
    return media_type.strip().lower(), charset
