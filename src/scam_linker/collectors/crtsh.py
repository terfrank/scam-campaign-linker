"""cert_siblings: certificates (from crt.sh CT logs) that also cover other registered domains.

The stored value identifies the certificate itself ("issuer_ca_id:serial"), so two sites that
share a certificate get the *same* signal value and the linker can match them directly.
crt.sh lists a precertificate and the final certificate as separate rows with different ids,
but they share issuer and serial number, so this key also removes those duplicates.
"""

import json
from typing import Any
from urllib.parse import urlencode

from scam_linker.collectors.base import CollectorError, Signal, SignalType, SiteContext
from scam_linker.domains import registered_domain
from scam_linker.fetcher import ResourceKind

CRTSH_URL = "https://crt.sh/"


def crtsh_url(domain: str) -> str:
    return f"{CRTSH_URL}?{urlencode({'q': domain, 'output': 'json'})}"


def cert_domains(entry: dict[str, Any]) -> set[str]:
    """Registered domains named on one certificate (wildcards included)."""
    names = str(entry.get("name_value", "")).splitlines()
    names.append(str(entry.get("common_name", "")))
    domains = set()
    for name in names:
        name = name.strip().lower().removeprefix("*.")
        domain = registered_domain(name) if name else None
        if domain:
            domains.add(domain)
    return domains


def shared_certificates(entries: list[dict[str, Any]], domain: str) -> set[str]:
    """Keys of certificates for `domain` that also name at least one other registered domain."""
    shared = set()
    for entry in entries:
        domains = cert_domains(entry)
        if domain in domains and len(domains) > 1:
            shared.add(f"{entry.get('issuer_ca_id')}:{str(entry.get('serial_number', '')).lower()}")
    return shared


def collect(ctx: SiteContext) -> list[Signal]:
    domain = ctx.require_domain()
    result = ctx.fetcher.fetch(crtsh_url(domain), ResourceKind.JSON)
    if not result.ok:
        raise CollectorError(f"crt.sh lookup for {domain} failed: {result.status} {result.detail}")
    try:
        entries = json.loads(result.body)
    except json.JSONDecodeError as exc:
        raise CollectorError(f"crt.sh response for {domain} is not JSON") from exc
    if not isinstance(entries, list):
        raise CollectorError(f"crt.sh response for {domain} is not a list")

    return [Signal(SignalType.CERT, key) for key in sorted(shared_certificates(entries, domain))]
