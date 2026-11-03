"""Hostname and registered-domain helpers."""

import ipaddress
from urllib.parse import urlsplit

import tldextract

# Use the Public Suffix List snapshot bundled with tldextract: no network fetch, no disk cache.
_extract = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None)


def hostname_of(url: str) -> str | None:
    """Return the lower-cased hostname of a URL, or None if it has none."""
    try:
        return urlsplit(url).hostname
    except ValueError:
        return None


def is_ip_address(hostname: str) -> bool:
    """True for IPv4/IPv6 literals such as '203.0.113.5'."""
    try:
        ipaddress.ip_address(hostname)
    except ValueError:
        return False
    return True


def registered_domain(hostname: str) -> str | None:
    """'login.secure.example.co.uk' -> 'example.co.uk'. None for IPs or unknown suffixes.

    This is the ICANN registrable domain, which is what DNS NS, RDAP and crt.sh are keyed on.
    """
    if is_ip_address(hostname):
        return None
    return _extract(hostname).top_domain_under_public_suffix or None
