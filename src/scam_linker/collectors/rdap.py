"""registrar and created_date from RDAP, the JSON successor to WHOIS.

rdap.org redirects each query to the authoritative registry's RDAP server, so we don't need
to maintain a TLD-to-server table ourselves.
"""

import json
from typing import Any

from scam_linker.collectors.base import CollectorError, Signal, SignalType, SiteContext
from scam_linker.fetcher import ResourceKind

RDAP_URL = "https://rdap.org/domain/{domain}"


def _vcard_name(entity: dict[str, Any]) -> str | None:
    """Pull the 'fn' (formatted name) out of an RDAP entity's jCard."""
    vcard = entity.get("vcardArray")
    if not isinstance(vcard, list) or len(vcard) < 2:
        return None
    for prop in vcard[1]:
        if isinstance(prop, list) and len(prop) >= 4 and prop[0] == "fn":
            return str(prop[3])
    return None


def parse_rdap(data: dict[str, Any]) -> tuple[str | None, str | None]:
    """Return (registrar name, registration date as YYYY-MM-DD) from an RDAP domain object."""
    registrar = None
    for entity in data.get("entities", []):
        if "registrar" in entity.get("roles", []):
            name = _vcard_name(entity)
            if name:
                registrar = " ".join(name.split()).casefold()
                break

    created = None
    for event in data.get("events", []):
        if event.get("eventAction") == "registration" and event.get("eventDate"):
            created = str(event["eventDate"])[:10]
            break
    return registrar, created


def collect(ctx: SiteContext) -> list[Signal]:
    domain = ctx.require_domain()
    result = ctx.fetcher.fetch(RDAP_URL.format(domain=domain), ResourceKind.JSON)
    if not result.ok:
        raise CollectorError(f"RDAP lookup for {domain} failed: {result.status} {result.detail}")
    try:
        data = json.loads(result.body)
    except json.JSONDecodeError as exc:
        raise CollectorError(f"RDAP response for {domain} is not JSON") from exc

    registrar, created = parse_rdap(data)
    signals = []
    if registrar:
        signals.append(Signal(SignalType.REGISTRAR, registrar))
    if created:
        signals.append(Signal(SignalType.CREATED_DATE, created))
    return signals
