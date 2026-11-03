"""ip, asn and nameserver signals from DNS.

ASN lookup uses Team Cymru's public IP-to-ASN DNS service: a TXT query for
<reversed IPv4>.origin.asn.cymru.com returns "ASN | prefix | country | registry | date".
It is a plain DNS lookup, so it stays passive.
"""

import ipaddress

from scam_linker.collectors.base import Signal, SignalType, SiteContext
from scam_linker.domains import is_ip_address

CYMRU_ORIGIN_ZONE = "origin.asn.cymru.com"


def cymru_query_name(ip: str) -> str:
    """'45.67.89.10' -> '10.89.67.45.origin.asn.cymru.com'."""
    return ".".join(reversed(ip.split("."))) + "." + CYMRU_ORIGIN_ZONE


def parse_cymru_txt(txt: str) -> list[str]:
    """'13335 209242 | 104.16.0.0/13 | US | arin | 2014-03-28' -> ['AS13335', 'AS209242']."""
    asn_field = txt.split("|", 1)[0]
    return [f"AS{asn}" for asn in asn_field.split() if asn.isdigit()]


def collect_ip_and_asn(ctx: SiteContext) -> list[Signal]:
    """IPv4 addresses from A records, plus the ASN announcing each public address."""
    if is_ip_address(ctx.hostname):
        addresses = [ctx.hostname]
    else:
        addresses = ctx.dns.a_records(ctx.hostname)

    signals = {Signal(SignalType.IP, ip) for ip in addresses}
    for ip in addresses:
        parsed = ipaddress.ip_address(ip)
        if parsed.version != 4 or not parsed.is_global:
            continue
        for txt in ctx.dns.txt_records(cymru_query_name(ip)):
            signals.update(Signal(SignalType.ASN, asn) for asn in parse_cymru_txt(txt))
    return sorted(signals)


def collect_nameservers(ctx: SiteContext) -> list[Signal]:
    """NS records of the registered domain (subdomains usually have none of their own)."""
    domain = ctx.require_domain()
    return [Signal(SignalType.NAMESERVER, ns) for ns in ctx.dns.ns_records(domain)]
