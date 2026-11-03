"""tracking_ids: analytics and ad-tag IDs embedded in the HTML.

Scammers reuse their own analytics accounts across sites to measure their campaigns, so an
identical ID on two sites is strong evidence of a shared operator.
"""

import re

from scam_linker.collectors.base import Signal, SignalType, SiteContext

# Each pattern's group 1 is the value stored.
PATTERNS = (
    re.compile(r"\b(UA-\d{4,10}-\d{1,4})\b"),  # Universal Analytics
    re.compile(r"\b(G-[A-Z0-9]{8,12})\b"),  # Google Analytics 4
    re.compile(r"\b(GTM-[A-Z0-9]{4,10})\b"),  # Google Tag Manager
    re.compile(r"\b(AW-\d{9,11})\b"),  # Google Ads
)
FACEBOOK_PIXEL = re.compile(r"""fbq\(\s*['"]init['"]\s*,\s*['"](\d{10,20})['"]""")


def tracking_ids(html: str) -> set[str]:
    found = {match.group(1) for pattern in PATTERNS for match in pattern.finditer(html)}
    found |= {f"fb-pixel:{match.group(1)}" for match in FACEBOOK_PIXEL.finditer(html)}
    return found


def collect(ctx: SiteContext) -> list[Signal]:
    if ctx.html is None:
        return []
    return [Signal(SignalType.TRACKING_ID, value) for value in sorted(tracking_ids(ctx.html))]
