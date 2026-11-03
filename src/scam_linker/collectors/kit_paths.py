"""kit_paths: suspicious paths referenced by the page, e.g. /secure/login.php or /verify.

Phishing kits are copied between sites with their folder layout intact, so an unusual shared
path is good evidence. Whether a path is *rare* is decided later by the linker, across all sites.
"""

import re
from urllib.parse import urlsplit

from scam_linker.collectors.base import Signal, SignalType, SiteContext

SUSPICIOUS_WORDS = frozenset(
    {
        "login",
        "logon",
        "signin",
        "signon",
        "verify",
        "verification",
        "secure",
        "security",
        "account",
        "accounts",
        "update",
        "confirm",
        "confirmation",
        "auth",
        "authenticate",
        "wallet",
        "banking",
        "billing",
        "payment",
        "recover",
        "recovery",
        "unlock",
        "validate",
        "validation",
        "webscr",
        "otp",
        "2fa",
        "kyc",
    }
)
STATIC_EXTENSIONS = (
    *(".css", ".js", ".map"),
    *(".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp"),
    *(".woff", ".woff2", ".ttf", ".eot"),
)


def normalise_path(link: str) -> str | None:
    """Return the lower-cased path of an http(s) or relative link, without a trailing slash."""
    try:
        parts = urlsplit(link.strip())
    except ValueError:
        return None
    if parts.scheme not in ("", "http", "https"):
        return None  # mailto:, javascript:, data: ...
    path = parts.path.lower().rstrip("/")
    return path or None


def is_kit_path(path: str) -> bool:
    """A .php script, or a path containing a suspicious word as a whole token."""
    if path.endswith(STATIC_EXTENSIONS):
        return False
    if path.endswith(".php"):
        return True
    tokens = re.split(r"[^a-z0-9]+", path)
    return any(token in SUSPICIOUS_WORDS for token in tokens)


def kit_paths(links: list[str]) -> set[str]:
    paths = (normalise_path(link) for link in links)
    return {path for path in paths if path and is_kit_path(path)}


def collect(ctx: SiteContext) -> list[Signal]:
    # The site's own URL counts too: the seed is often the kit page itself.
    links = [ctx.url]
    if ctx.page.final_url:
        links.append(ctx.page.final_url)
    if ctx.parsed is not None:
        links.extend(ctx.parsed.links)
    return [Signal(SignalType.KIT_PATH, path) for path in sorted(kit_paths(links))]
