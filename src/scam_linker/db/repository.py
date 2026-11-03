"""Repository functions: the only code that reads or writes sites and signals.

Functions take a Session and `flush()` but never `commit()`. The caller (an API request,
a script) owns the transaction, so several repository calls can succeed or fail together.
"""

import logging
from collections.abc import Iterable
from datetime import datetime
from urllib.parse import urlsplit, urlunsplit

from sqlalchemy import select, tuple_
from sqlalchemy.orm import Session

from scam_linker.collectors.base import Signal, SignalType
from scam_linker.collectors.runner import SiteCollection
from scam_linker.db import models

logger = logging.getLogger(__name__)

# Postgres can't index a value bigger than ~2.7 KB in a B-tree (signals has a unique index),
# and no legitimate signal is anywhere near this long.
MAX_SIGNAL_VALUE_LENGTH = 1000


def normalise_url(url: str) -> str:
    """Lower-case scheme and host, drop the #fragment, use '/' for an empty path.

    'HTTPS://Scam.XYZ#top' and 'https://scam.xyz/' are the same site, so they share one row.
    The path and query are kept as-is: they are case-sensitive on most servers.
    """
    parts = urlsplit(url.strip())
    return urlunsplit(
        (parts.scheme.lower(), parts.netloc.lower(), parts.path or "/", parts.query, "")
    )


def get_site_by_url(session: Session, url: str) -> models.Site | None:
    return session.scalar(select(models.Site).where(models.Site.url == normalise_url(url)))


def save_collection(
    session: Session, collection: SiteCollection, now: datetime | None = None
) -> models.Site:
    """Insert or update a site from a collection run, replacing its signals with the new set.

    Signals no longer observed are unlinked, so stale infrastructure (an old nameserver,
    an expired certificate) can't link this site to others.
    """
    now = now or models.utcnow()
    url = normalise_url(collection.url)
    site = get_site_by_url(session, url)
    if site is None:
        site = models.Site(url=url, first_seen=now)
        session.add(site)

    site.domain = collection.domain
    site.last_checked = now
    site.fetch_status = collection.fetch_status.value
    site.collector_errors = dict(collection.errors)

    rows = _get_or_create_signals(session, collection.signals)
    # Swapping in a new list deletes the old links (cascade="delete-orphan"). A link that is
    # kept has the same (site_id, signal_id) key; SQLAlchemy's "row switch" turns that
    # delete + insert pair into a single UPDATE of observed_at.
    site.signal_links = [models.SiteSignal(signal=row, observed_at=now) for row in rows]
    session.flush()
    return site


def _get_or_create_signals(session: Session, signals: Iterable[Signal]) -> list[models.Signal]:
    """Return a row for each signal, inserting the ones not seen before (one SELECT total)."""
    wanted: set[tuple[str, str]] = set()
    for signal in signals:
        if len(signal.value) > MAX_SIGNAL_VALUE_LENGTH:
            logger.warning(
                "skipping oversized %s signal (%d chars)", signal.type, len(signal.value)
            )
            continue
        wanted.add((str(signal.type), signal.value))
    if not wanted:
        return []

    existing = session.scalars(
        select(models.Signal).where(tuple_(models.Signal.type, models.Signal.value).in_(wanted))
    )
    by_key = {(row.type, row.value): row for row in existing}
    for signal_type, value in wanted - by_key.keys():
        row = models.Signal(type=signal_type, value=value)
        session.add(row)
        by_key[(signal_type, value)] = row
    return [by_key[key] for key in sorted(wanted)]


def signals_for_site(session: Session, site_id: int) -> list[Signal]:
    """The site's current signals, as collector Signal values, sorted."""
    rows = session.execute(
        select(models.Signal.type, models.Signal.value)
        .join(models.SiteSignal, models.SiteSignal.signal_id == models.Signal.id)
        .where(models.SiteSignal.site_id == site_id)
    )
    return sorted(Signal(SignalType(type_), value) for type_, value in rows)


def sites_with_signal(session: Session, signal: Signal) -> list[models.Site]:
    """Every site currently observed with this exact signal."""
    return list(
        session.scalars(
            select(models.Site)
            .join(models.SiteSignal, models.SiteSignal.site_id == models.Site.id)
            .join(models.Signal, models.Signal.id == models.SiteSignal.signal_id)
            .where(models.Signal.type == str(signal.type), models.Signal.value == signal.value)
            .order_by(models.Site.id)
        )
    )


def site_signal_index(session: Session) -> dict[int, set[Signal]]:
    """site_id -> its signals, for every site that has any. This is the linker's input."""
    rows = session.execute(
        select(models.SiteSignal.site_id, models.Signal.type, models.Signal.value).join(
            models.Signal, models.Signal.id == models.SiteSignal.signal_id
        )
    )
    index: dict[int, set[Signal]] = {}
    for site_id, type_, value in rows:
        index.setdefault(site_id, set()).add(Signal(SignalType(type_), value))
    return index
