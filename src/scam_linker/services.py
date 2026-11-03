"""Use cases tying collectors, storage and the linker together.

The API routes and the evaluation script both call these, so the logic lives in one place.
Each function that changes data commits its own transaction.
"""

import logging
from collections.abc import Iterable
from dataclasses import dataclass

from sqlalchemy.orm import Session, sessionmaker

from scam_linker.collectors.runner import collect_site
from scam_linker.db import models, repository
from scam_linker.dns_client import DnsClient
from scam_linker.fetcher import SafeFetcher
from scam_linker.linker import link_sites
from scam_linker.linker.config import ScoringConfig
from scam_linker.linker.explain import campaign_explanation
from scam_linker.linker.grouping import CampaignGroup, LinkResult
from scam_linker.linker.scoring import SiteIndex

logger = logging.getLogger(__name__)


def collect_and_save(
    session: Session, url: str, fetcher: SafeFetcher, dns: DnsClient
) -> models.Site:
    """Collect every signal for one URL and store the result."""
    site = repository.save_collection(session, collect_site(url, fetcher, dns))
    session.commit()
    return site


@dataclass(frozen=True)
class BulkOutcome:
    saved: int
    failed: int


def collect_many(
    urls: Iterable[str],
    session_factory: sessionmaker[Session],
    fetcher: SafeFetcher,
    dns: DnsClient,
) -> BulkOutcome:
    """Collect URLs one at a time, each in its own transaction. One failure never stops the rest."""
    saved = failed = 0
    for url in urls:
        try:
            with session_factory() as session:
                collect_and_save(session, url, fetcher, dns)
            saved += 1
        except Exception:
            logger.exception("bulk collection failed for %s", url)
            failed += 1
    logger.info("bulk collection finished: %d saved, %d failed", saved, failed)
    return BulkOutcome(saved, failed)


@dataclass(frozen=True)
class Linking:
    result: LinkResult
    index: SiteIndex
    rows: list[models.Campaign]  # stored campaigns, same order as result.campaigns

    def stored_campaign_for(self, site_id: int) -> tuple[CampaignGroup, models.Campaign] | None:
        for group, row in zip(self.result.campaigns, self.rows, strict=True):
            if site_id in group.site_ids:
                return group, row
        return None


def rebuild_campaigns(session: Session, config: ScoringConfig) -> Linking:
    """Run the linker over every stored site and replace the stored campaigns."""
    index = repository.site_signal_index(session)
    result = link_sites(index, config)
    rows = repository.replace_campaigns(
        session,
        [(group, campaign_explanation(group, index, config)) for group in result.campaigns],
    )
    session.commit()
    return Linking(result, index, rows)


@dataclass(frozen=True)
class SeedOutcome:
    seed: models.Site
    linking: Linking
    campaign: tuple[CampaignGroup, models.Campaign] | None  # None means UNKNOWN


def campaign_from_seed(
    session: Session,
    url: str,
    fetcher: SafeFetcher,
    dns: DnsClient,
    config: ScoringConfig,
) -> SeedOutcome:
    """Find the campaign containing `url`, collecting it first if we have never seen it.

    A seed we already know is not re-collected here (use POST /sites to refresh it).
    """
    seed = repository.get_site_by_url(session, url) or collect_and_save(session, url, fetcher, dns)
    linking = rebuild_campaigns(session, config)
    return SeedOutcome(seed, linking, linking.stored_campaign_for(seed.id))
