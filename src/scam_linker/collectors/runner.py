"""Run every collector for one site. A failing collector is logged and skipped, never fatal."""

import logging
from dataclasses import dataclass, field

from scam_linker.collectors import (
    crtsh,
    dns_records,
    favicon,
    html_fingerprint,
    kit_paths,
    rdap,
    title,
    tracking_ids,
)
from scam_linker.collectors.base import Collector, Signal, SiteContext
from scam_linker.dns_client import DnsClient
from scam_linker.domains import hostname_of, registered_domain
from scam_linker.fetcher import FetchStatus, ResourceKind, SafeFetcher

logger = logging.getLogger(__name__)

ALL_COLLECTORS: dict[str, Collector] = {
    "title": title.collect,
    "html_fingerprint": html_fingerprint.collect,
    "kit_paths": kit_paths.collect,
    "tracking_ids": tracking_ids.collect,
    "favicon_hash": favicon.collect,
    "ip_and_asn": dns_records.collect_ip_and_asn,
    "nameservers": dns_records.collect_nameservers,
    "rdap": rdap.collect,
    "cert_siblings": crtsh.collect,
}


@dataclass(frozen=True)
class SiteCollection:
    """The outcome of collecting one site: its signals plus why any collector was skipped."""

    url: str
    hostname: str | None
    domain: str | None
    fetch_status: FetchStatus
    final_url: str | None = None
    signals: tuple[Signal, ...] = ()
    errors: dict[str, str] = field(default_factory=dict)


def collect_site(
    url: str,
    fetcher: SafeFetcher,
    dns: DnsClient,
    collectors: dict[str, Collector] | None = None,
) -> SiteCollection:
    """Fetch the page once, then run each collector against it.

    DNS, RDAP and crt.sh collectors still run when the page itself can't be fetched:
    a site that is already down still has DNS records and certificates.
    """
    hostname = hostname_of(url)
    if not hostname:
        return SiteCollection(
            url=url, hostname=None, domain=None, fetch_status=FetchStatus.INVALID_URL
        )

    page = fetcher.fetch(url, ResourceKind.HTML)
    ctx = SiteContext(
        url=url,
        hostname=hostname,
        domain=registered_domain(hostname),
        page=page,
        fetcher=fetcher,
        dns=dns,
    )

    signals: set[Signal] = set()
    errors: dict[str, str] = {}
    for name, collector in (collectors or ALL_COLLECTORS).items():
        try:
            signals.update(collector(ctx))
        except Exception as exc:  # one bad collector must never stop the others
            logger.warning("collector %s skipped for %s: %s", name, url, exc)
            errors[name] = f"{type(exc).__name__}: {exc}"

    return SiteCollection(
        url=url,
        hostname=hostname,
        domain=ctx.domain,
        fetch_status=page.status,
        final_url=page.final_url,
        signals=tuple(sorted(signals)),
        errors=errors,
    )
