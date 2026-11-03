"""Tests for the repository layer: saving sites and signals, and reading the graph back."""

from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import delete, func, select
from sqlalchemy.exc import StatementError
from sqlalchemy.orm import Session

from scam_linker.collectors.base import Signal, SignalType
from scam_linker.collectors.runner import SiteCollection
from scam_linker.db import models, repository
from scam_linker.fetcher import FetchStatus

URL_A = "https://examplebank-secure-a.xyz/"
URL_B = "https://examplebank-secure-b.xyz/"
FAVICON = Signal(SignalType.FAVICON_HASH, "495416780")
NS1 = Signal(SignalType.NAMESERVER, "ns1.example-host.xyz")
NS2 = Signal(SignalType.NAMESERVER, "ns2.other-host.xyz")
TITLE = Signal(SignalType.TITLE, "examplebank - secure login")
DAY_1 = datetime(2026, 11, 1, 9, 0, tzinfo=UTC)
DAY_2 = DAY_1 + timedelta(days=1)


def collection(
    url: str,
    *signals: Signal,
    status: FetchStatus = FetchStatus.OK,
    errors: dict[str, str] | None = None,
) -> SiteCollection:
    return SiteCollection(
        url=url,
        hostname=None,
        domain=url.split("/")[2],
        fetch_status=status,
        signals=signals,
        errors=errors or {},
    )


def count(session: Session, model: type[models.Base]) -> int:
    return session.scalar(select(func.count()).select_from(model)) or 0


def test_saves_site_with_signals(db_session: Session) -> None:
    site = repository.save_collection(db_session, collection(URL_A, FAVICON, TITLE), now=DAY_1)

    assert site.url == URL_A
    assert site.domain == "examplebank-secure-a.xyz"
    assert site.fetch_status == "ok"
    assert site.first_seen == site.last_checked == DAY_1
    assert repository.signals_for_site(db_session, site.id) == [FAVICON, TITLE]


def test_url_variants_map_to_one_site(db_session: Session) -> None:
    first = repository.save_collection(
        db_session, collection("HTTPS://ExampleBank-Secure-A.xyz#top", FAVICON), now=DAY_1
    )
    second = repository.save_collection(db_session, collection(URL_A, FAVICON), now=DAY_2)

    assert first.id == second.id
    assert second.url == URL_A
    assert second.first_seen == DAY_1  # unchanged by re-collection
    assert second.last_checked == DAY_2
    assert count(db_session, models.Site) == 1


def test_shared_signal_is_stored_once_and_found_from_both_sites(db_session: Session) -> None:
    repository.save_collection(db_session, collection(URL_A, FAVICON, NS1))
    repository.save_collection(db_session, collection(URL_B, FAVICON))

    sites = repository.sites_with_signal(db_session, FAVICON)

    assert [site.url for site in sites] == [URL_A, URL_B]
    assert count(db_session, models.Signal) == 2  # FAVICON and NS1, not three rows


def test_recollection_replaces_signals(db_session: Session) -> None:
    """A site that moved to a new nameserver must no longer link via the old one."""
    site = repository.save_collection(db_session, collection(URL_A, NS1, TITLE), now=DAY_1)
    repository.save_collection(db_session, collection(URL_A, NS2, TITLE), now=DAY_2)

    assert repository.signals_for_site(db_session, site.id) == [NS2, TITLE]
    assert repository.sites_with_signal(db_session, NS1) == []
    observed = {link.signal.value: link.observed_at for link in site.signal_links}
    assert observed[TITLE.value] == DAY_2


def test_status_and_collector_errors_are_stored(db_session: Session) -> None:
    errors = {"rdap": "CollectorError: RDAP lookup failed: timeout"}
    site = repository.save_collection(
        db_session, collection(URL_A, status=FetchStatus.HTTP_ERROR, errors=errors)
    )
    db_session.commit()
    db_session.expire_all()  # force a real read from the database

    assert site.fetch_status == "http_error"
    assert site.collector_errors == errors


def test_oversized_signal_is_skipped(db_session: Session) -> None:
    huge = Signal(SignalType.KIT_PATH, "/" + "a" * repository.MAX_SIGNAL_VALUE_LENGTH)

    site = repository.save_collection(db_session, collection(URL_A, huge, TITLE))

    assert repository.signals_for_site(db_session, site.id) == [TITLE]


def test_site_signal_index(db_session: Session) -> None:
    a = repository.save_collection(db_session, collection(URL_A, FAVICON, NS1))
    b = repository.save_collection(db_session, collection(URL_B, FAVICON))
    repository.save_collection(db_session, collection("https://empty.xyz/"))

    assert repository.site_signal_index(db_session) == {a.id: {FAVICON, NS1}, b.id: {FAVICON}}


def test_deleting_a_site_cascades_in_the_database(db_session: Session) -> None:
    """A bulk SQL DELETE bypasses the ORM, so this proves the FK's ON DELETE CASCADE works
    (on SQLite that needs PRAGMA foreign_keys=ON, set in make_engine)."""
    site = repository.save_collection(db_session, collection(URL_A, FAVICON, NS1))
    db_session.commit()

    db_session.execute(delete(models.Site).where(models.Site.id == site.id))
    db_session.commit()

    assert count(db_session, models.SiteSignal) == 0
    assert count(db_session, models.Signal) == 2  # the facts themselves are kept


def test_datetimes_are_utc_after_a_round_trip(db_session: Session) -> None:
    site = repository.save_collection(db_session, collection(URL_A), now=DAY_1)
    db_session.commit()
    db_session.expire_all()

    assert site.last_checked == DAY_1
    assert site.last_checked is not None and site.last_checked.tzinfo is not None


def test_naive_datetimes_are_rejected(db_session: Session) -> None:
    with pytest.raises(StatementError, match="naive datetime"):
        repository.save_collection(db_session, collection(URL_A), now=datetime(2026, 11, 1))


@pytest.mark.parametrize(
    ("url", "expected"),
    [
        ("HTTPS://Scam.XYZ", "https://scam.xyz/"),
        ("https://scam.xyz/Login.php?Next=A#frag", "https://scam.xyz/Login.php?Next=A"),
        ("  https://scam.xyz/a  ", "https://scam.xyz/a"),
    ],
)
def test_normalise_url(url: str, expected: str) -> None:
    assert repository.normalise_url(url) == expected
