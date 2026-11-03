"""html_fingerprint: hash of the page's tag structure, ignoring all text and attributes.

Two copies of the same phishing kit usually keep the same markup even when the brand name,
wording or links change, so they get the same fingerprint.
"""

import hashlib

from scam_linker.collectors.base import Signal, SignalType, SiteContext

# Tiny pages ("403 Forbidden", parking pages) share structure by accident; don't fingerprint them.
MIN_TAGS = 10


def fingerprint(tags: tuple[str, ...]) -> str | None:
    """SHA-256 of the start-tag sequence, or None if the page is too small to be meaningful."""
    if len(tags) < MIN_TAGS:
        return None
    return hashlib.sha256(" ".join(tags).encode()).hexdigest()


def collect(ctx: SiteContext) -> list[Signal]:
    if ctx.parsed is None:
        return []
    value = fingerprint(ctx.parsed.tags)
    return [Signal(SignalType.HTML_FINGERPRINT, value)] if value else []
