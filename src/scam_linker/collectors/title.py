"""title: the normalised <title> text."""

from scam_linker.collectors.base import Signal, SignalType, SiteContext

MAX_TITLE_LENGTH = 200


def normalise_title(raw: str | None) -> str | None:
    """Case-fold and collapse whitespace so '  Bank -  LOGIN ' == 'bank - login'."""
    if raw is None:
        return None
    title = " ".join(raw.split()).casefold()
    return title[:MAX_TITLE_LENGTH] or None


def collect(ctx: SiteContext) -> list[Signal]:
    if ctx.parsed is None:
        return []
    title = normalise_title(ctx.parsed.title)
    return [Signal(SignalType.TITLE, title)] if title else []
