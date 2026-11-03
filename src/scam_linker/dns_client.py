"""Small DNS client used by the collectors. Passive lookups only, rate-limited."""

from collections.abc import Iterable
from typing import Any, Protocol

import dns.resolver

from scam_linker.fetcher import TIMEOUT_SECONDS, RateLimiter

DNS_MIN_INTERVAL_SECONDS = 0.2  # DNS is cheap for resolvers, but we still pace ourselves


class DnsResolver(Protocol):
    """The part of dns.resolver.Resolver we use. Lets tests pass a fake with saved answers."""

    def resolve(self, qname: str, rdtype: str) -> Iterable[Any]: ...


def default_resolver() -> dns.resolver.Resolver:
    """The system resolver with the same 5 s budget as HTTP requests."""
    resolver = dns.resolver.Resolver()
    resolver.lifetime = TIMEOUT_SECONDS
    return resolver


class DnsClient:
    """A, NS and TXT lookups returning plain strings. "No such record" is an empty list."""

    def __init__(
        self, resolver: DnsResolver | None = None, limiter: RateLimiter | None = None
    ) -> None:
        self._resolver = resolver or default_resolver()
        self._limiter = limiter or RateLimiter(DNS_MIN_INTERVAL_SECONDS)

    def a_records(self, hostname: str) -> list[str]:
        return sorted(rdata.address for rdata in self._query(hostname, "A"))

    def ns_records(self, domain: str) -> list[str]:
        return sorted(str(rdata.target).rstrip(".").lower() for rdata in self._query(domain, "NS"))

    def txt_records(self, name: str) -> list[str]:
        return [
            b"".join(rdata.strings).decode(errors="replace") for rdata in self._query(name, "TXT")
        ]

    def _query(self, name: str, rdtype: str) -> list[Any]:
        """Run one query. Other errors (timeouts, SERVFAIL) propagate to the collector runner."""
        self._limiter.wait("dns")
        try:
            return list(self._resolver.resolve(name, rdtype))
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            return []
