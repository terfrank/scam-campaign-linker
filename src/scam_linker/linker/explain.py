"""Plain-English explanations of links and campaigns, built only from stored evidence."""

from collections import Counter
from typing import Any

from scam_linker.linker.config import EvidenceKind, ScoringConfig
from scam_linker.linker.grouping import CampaignGroup
from scam_linker.linker.scoring import TIER_ORDER, Evidence, PairScore, SiteIndex, created_date

# Short noun for summaries, and a full sentence fragment for per-link explanations.
NOUNS = {
    EvidenceKind.FAVICON_HASH: "favicon",
    EvidenceKind.HTML_FINGERPRINT: "page structure",
    EvidenceKind.TRACKING_ID: "tracking ID",
    EvidenceKind.CERT: "TLS certificate",
    EvidenceKind.RARE_KIT_PATH: "kit path",
    EvidenceKind.NAMESERVERS_AND_REGISTRATION: "nameservers",
    EvidenceKind.REGISTRAR_AND_TITLE: "registrar and title",
    EvidenceKind.IP: "IP address",
    EvidenceKind.ASN: "network",
}
DESCRIPTIONS = {
    EvidenceKind.FAVICON_HASH: "same favicon (hash {value})",
    EvidenceKind.HTML_FINGERPRINT: "same page structure (fingerprint {value})",
    EvidenceKind.TRACKING_ID: "same analytics/ad tracking ID {value}",
    EvidenceKind.CERT: "same TLS certificate ({value})",
    EvidenceKind.RARE_KIT_PATH: "same uncommon kit path {value}",
    EvidenceKind.NAMESERVERS_AND_REGISTRATION: (
        "same nameservers ({value}) and registered within {days} days of each other"
    ),
    EvidenceKind.REGISTRAR_AND_TITLE: "same registrar and page title ({value})",
    EvidenceKind.IP: "same IP address {value} (weak on its own: shared hosting is common)",
    EvidenceKind.ASN: "same network {value} (weak on its own: one network hosts many sites)",
}
SUMMARY_ITEMS = 3
HASH_LIKE = frozenset({EvidenceKind.HTML_FINGERPRINT, EvidenceKind.CERT})
HASH_DISPLAY_LENGTH = 12


def display_value(evidence: Evidence) -> str:
    """Shorten long hashes ('3f9a0c2b71de…') for readability; show everything else in full."""
    value = evidence.value
    if evidence.kind in HASH_LIKE and len(value) > HASH_DISPLAY_LENGTH:
        return value[:HASH_DISPLAY_LENGTH] + "…"
    return value


def describe(evidence: Evidence, config: ScoringConfig) -> str:
    return DESCRIPTIONS[evidence.kind].format(
        value=display_value(evidence), days=config.registration_window_days
    )


def describe_pair(pair: PairScore, config: ScoringConfig) -> str:
    """e.g. 'Linked (strength 1.0): same favicon (...); same nameservers (...)'."""
    verdict = "Linked" if pair.linked else "Possibly related (UNKNOWN)"
    reasons = "; ".join(describe(item, config) for item in pair.evidence)
    return f"{verdict} (strength {pair.strength:.2f}): {reasons}"


def _join(items: list[str]) -> str:
    return items[0] if len(items) == 1 else ", ".join(items[:-1]) + " and " + items[-1]


def registration_range(campaign: CampaignGroup, index: SiteIndex) -> tuple[str, str] | None:
    dates = sorted(
        found
        for site_id in campaign.site_ids
        if (found := created_date(index.get(site_id, set()))) is not None
    )
    return (dates[0].isoformat(), dates[-1].isoformat()) if dates else None


def ranked_evidence(campaign: CampaignGroup, config: ScoringConfig) -> list[tuple[Evidence, int]]:
    """Campaign evidence with how many members share it: strongest tier first, then most shared.

    Tier comes first so weak evidence (a shared ASN) never headlines a campaign that is
    actually held together by strong evidence.
    """
    counts = Counter(item for member in campaign.members for item in member.shared)
    order = sorted(
        counts, key=lambda item: (TIER_ORDER.index(config.tier(item.kind)), -counts[item], item)
    )
    return [(item, counts[item]) for item in order]


def summarize(campaign: CampaignGroup, index: SiteIndex, config: ScoringConfig) -> str:
    """e.g. '3 sites share favicon 495416780 and kit path /verify; registered 2026-11-02 to ...'"""
    top = [item for item, _ in ranked_evidence(campaign, config)][:SUMMARY_ITEMS]
    parts = [f"{NOUNS[item.kind]} {display_value(item)}" for item in top]
    summary = f"{len(campaign.members)} sites share {_join(parts)}"
    dates = registration_range(campaign, index)
    if dates:
        first, last = dates
        summary += f"; registered {first}" if first == last else f"; registered {first} to {last}"
    return summary


def campaign_explanation(
    campaign: CampaignGroup, index: SiteIndex, config: ScoringConfig
) -> dict[str, Any]:
    """The JSON stored in Campaign.explanation: summary plus every piece of evidence."""
    dates = registration_range(campaign, index)
    return {
        "summary": summarize(campaign, index, config),
        "evidence": [
            {"label": item.label, "description": describe(item, config), "sites": count}
            for item, count in ranked_evidence(campaign, config)
        ],
        "registered_from": dates[0] if dates else None,
        "registered_to": dates[1] if dates else None,
    }
