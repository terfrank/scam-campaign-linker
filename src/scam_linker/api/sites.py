"""/sites: collect signals for one URL now, or queue many in the background."""

from fastapi import APIRouter, BackgroundTasks, status
from sqlalchemy.orm import Session

from scam_linker import services
from scam_linker.api.deps import Context, DbSession, RateLimited
from scam_linker.api.schemas import BulkAccepted, BulkRequest, SignalOut, SiteOut, UrlRequest
from scam_linker.db import models, repository

router = APIRouter(prefix="/sites", tags=["sites"])


def site_out(session: Session, site: models.Site) -> SiteOut:
    return SiteOut(
        id=site.id,
        url=site.url,
        domain=site.domain,
        fetch_status=site.fetch_status,
        first_seen=site.first_seen,
        last_checked=site.last_checked,
        collector_errors=site.collector_errors,
        signals=[
            SignalOut(type=signal.type, value=signal.value)
            for signal in repository.signals_for_site(session, site.id)
        ],
    )


@router.post("", dependencies=[RateLimited])
def collect_one(body: UrlRequest, session: DbSession, context: Context) -> SiteOut:
    """Collect every signal for one URL (passive only) and store it."""
    site = services.collect_and_save(session, str(body.url), context.fetcher, context.dns)
    return site_out(session, site)


@router.post("/bulk", status_code=status.HTTP_202_ACCEPTED, dependencies=[RateLimited])
def collect_bulk(body: BulkRequest, background: BackgroundTasks, context: Context) -> BulkAccepted:
    """Queue URLs (e.g. from a public feed) to be collected one at a time after responding.

    Uses FastAPI's in-process BackgroundTasks: simple, no extra services, but queued work
    is lost if the API restarts. Re-submitting is safe because saving is an upsert.
    """
    urls = list(dict.fromkeys(repository.normalise_url(str(url)) for url in body.urls))
    background.add_task(
        services.collect_many, urls, context.session_factory, context.fetcher, context.dns
    )
    return BulkAccepted(queued=len(urls), duplicates_skipped=len(body.urls) - len(urls))
