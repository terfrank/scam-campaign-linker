"""/campaigns: find the campaign around a seed URL, or read a stored campaign."""

from typing import Any

from fastapi import APIRouter, HTTPException, status
from sqlalchemy.orm import Session

from scam_linker import services
from scam_linker.api.deps import Context, DbSession, RateLimited
from scam_linker.api.schemas import (
    CampaignOut,
    EvidenceOut,
    MemberOut,
    RelatedOut,
    SeedCampaignOut,
    SeedOut,
    UrlRequest,
)
from scam_linker.db import models, repository
from scam_linker.linker.config import ScoringConfig
from scam_linker.linker.explain import describe_pair
from scam_linker.linker.scoring import PairScore

router = APIRouter(prefix="/campaigns", tags=["campaigns"])


def _evidence(explanation: dict[str, Any]) -> list[EvidenceOut]:
    return [EvidenceOut(**item) for item in explanation.get("evidence", [])]


def _members(row: models.Campaign, urls: dict[int, str], seed_id: int | None) -> list[MemberOut]:
    members = [
        MemberOut(
            url=urls[member.site_id],
            link_strength=member.link_strength,
            shared=member.shared_signals,
            is_seed=member.site_id == seed_id,
        )
        for member in row.members
    ]
    return sorted(members, key=lambda m: (not m.is_seed, -m.link_strength, m.url))


def campaign_out(row: models.Campaign, urls: dict[int, str]) -> CampaignOut:
    return CampaignOut(
        campaign_id=row.id,
        created_at=row.created_at,
        confidence=row.confidence,
        summary=row.explanation["summary"],
        registered_from=row.explanation.get("registered_from"),
        registered_to=row.explanation.get("registered_to"),
        evidence=_evidence(row.explanation),
        members=_members(row, urls, seed_id=None),
    )


def _possibly_related(
    session: Session,
    pairs: list[tuple[int, PairScore]],
    config: ScoringConfig,
) -> list[RelatedOut]:
    """One entry per outside site, keeping its strongest unlinked pair."""
    best: dict[int, PairScore] = {}
    for other, pair in pairs:
        if other not in best or pair.strength > best[other].strength:
            best[other] = pair
    sites = repository.get_sites(session, best)
    ranked = sorted(best.items(), key=lambda item: (-item[1].strength, sites[item[0]].url))
    return [
        RelatedOut(
            url=sites[other].url,
            strength=pair.strength,
            shared=[item.label for item in pair.evidence],
            explanation=describe_pair(pair, config),
        )
        for other, pair in ranked
    ]


def _unknown_summary(seed: models.Site, related: int) -> str:
    """Say plainly why there is no answer, instead of guessing one."""
    reasons = ["UNKNOWN: no other known site shares strong or medium evidence with this URL"]
    if seed.fetch_status != "ok":
        reasons.append(f"the page itself could not be fetched ({seed.fetch_status})")
    if related:
        reasons.append(f"{related} site(s) share only weaker evidence (listed as possibly related)")
    return "; ".join(reasons) + "."


@router.post("/from-seed", dependencies=[RateLimited])
def from_seed(body: UrlRequest, session: DbSession, context: Context) -> SeedCampaignOut:
    """The campaign containing the seed URL, its evidence, and weakly related sites."""
    outcome = services.campaign_from_seed(
        session, str(body.url), context.fetcher, context.dns, context.scoring
    )
    seed = outcome.seed
    seed_out = SeedOut(
        url=seed.url, fetch_status=seed.fetch_status, collector_errors=seed.collector_errors
    )

    if outcome.campaign is None:
        pairs = outcome.linking.result.possibly_related_to(frozenset({seed.id}))
        related = _possibly_related(session, pairs, context.scoring)
        return SeedCampaignOut(
            status="unknown",
            seed=seed_out,
            campaign_id=None,
            confidence=None,
            summary=_unknown_summary(seed, len(related)),
            evidence=[],
            members=[],
            possibly_related_unknown=related,
        )

    group, row = outcome.campaign
    urls = {
        site_id: site.url for site_id, site in repository.get_sites(session, group.site_ids).items()
    }
    pairs = outcome.linking.result.possibly_related_to(group.site_ids)
    return SeedCampaignOut(
        status="linked",
        seed=seed_out,
        campaign_id=row.id,
        confidence=row.confidence,
        summary=row.explanation["summary"],
        evidence=_evidence(row.explanation),
        members=_members(row, urls, seed_id=seed.id),
        possibly_related_unknown=_possibly_related(session, pairs, context.scoring),
    )


@router.get("/{campaign_id}")
def get_campaign(campaign_id: int, session: DbSession) -> CampaignOut:
    """A stored campaign. Campaigns are rebuilt on each from-seed call, so ids are snapshots."""
    row = repository.get_campaign(session, campaign_id)
    if row is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="campaign not found")
    return campaign_out(row, {member.site_id: member.site.url for member in row.members})
