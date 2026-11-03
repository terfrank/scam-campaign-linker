"""Pairwise scoring: what evidence do two sites share, and is it enough to link them?

Instead of comparing every site with every other site, we build an inverted index
(evidence -> sites that have it) and only score pairs that share at least one key.
"""

from collections import defaultdict
from dataclasses import dataclass
from datetime import date
from itertools import combinations

from scam_linker.collectors.base import Signal, SignalType
from scam_linker.linker.config import EvidenceKind, ScoringConfig, Tier

SiteIndex = dict[int, set[Signal]]  # site_id -> its signals (repository.site_signal_index)

# Signal types where an identical value on two sites is evidence on its own.
DIRECT_EVIDENCE = {
    SignalType.FAVICON_HASH: EvidenceKind.FAVICON_HASH,
    SignalType.HTML_FINGERPRINT: EvidenceKind.HTML_FINGERPRINT,
    SignalType.TRACKING_ID: EvidenceKind.TRACKING_ID,
    SignalType.CERT: EvidenceKind.CERT,
    SignalType.KIT_PATH: EvidenceKind.RARE_KIT_PATH,
    SignalType.IP: EvidenceKind.IP,
    SignalType.ASN: EvidenceKind.ASN,
}
TIER_ORDER = (Tier.STRONG, Tier.MEDIUM, Tier.WEAK)


@dataclass(frozen=True, order=True)
class Evidence:
    """One shared fact, e.g. Evidence(FAVICON_HASH, '495416780')."""

    kind: EvidenceKind
    value: str

    @property
    def label(self) -> str:
        return f"{self.kind}:{self.value}"


@dataclass(frozen=True)
class PairScore:
    """The verdict for two sites (site_a < site_b) that share at least one piece of evidence."""

    site_a: int
    site_b: int
    evidence: tuple[Evidence, ...]
    strength: float
    tier: Tier  # the strongest tier among the evidence
    linked: bool


def candidate_evidence(signals: set[Signal], config: ScoringConfig) -> set[Evidence]:
    """Turn one site's signals into the evidence keys it could share with other sites."""
    values: dict[SignalType, list[str]] = defaultdict(list)
    for signal in signals:
        if signal.value not in config.ignore.get(signal.type, []):
            values[signal.type].append(signal.value)

    evidence = {
        Evidence(kind, value)
        for signal_type, kind in DIRECT_EVIDENCE.items()
        for value in values[signal_type]
    }
    # Combined keys: these only mean something together.
    if values[SignalType.NAMESERVER]:
        nameservers = ",".join(sorted(values[SignalType.NAMESERVER]))
        evidence.add(Evidence(EvidenceKind.NAMESERVERS_AND_REGISTRATION, nameservers))
    for registrar in values[SignalType.REGISTRAR]:
        for title in values[SignalType.TITLE]:
            evidence.add(Evidence(EvidenceKind.REGISTRAR_AND_TITLE, f"{registrar} | {title}"))
    return evidence


def created_date(signals: set[Signal]) -> date | None:
    for signal in signals:
        if signal.type is SignalType.CREATED_DATE:
            try:
                return date.fromisoformat(signal.value)
            except ValueError:
                return None
    return None


def registered_close(a: set[Signal], b: set[Signal], window_days: int) -> bool:
    """True if both registration dates are known and at most `window_days` apart."""
    date_a, date_b = created_date(a), created_date(b)
    return date_a is not None and date_b is not None and abs((date_a - date_b).days) <= window_days


def score_pair(a: int, b: int, evidence: set[Evidence], config: ScoringConfig) -> PairScore:
    """Sum the weights of the distinct evidence kinds (capped at 1.0) and decide the link."""
    kinds = {item.kind for item in evidence}
    # Round away float noise, so 0.7 + 0.1 counts as 0.8 and passes a 0.8 threshold.
    strength = round(min(1.0, sum(config.weight(kind) for kind in kinds)), 6)
    tier = min((config.tier(kind) for kind in kinds), key=TIER_ORDER.index)
    linked = strength >= config.link_threshold and tier is not Tier.WEAK
    return PairScore(a, b, tuple(sorted(evidence)), strength, tier, linked)


def score_pairs(index: SiteIndex, config: ScoringConfig) -> list[PairScore]:
    """Score every pair of sites that shares at least one usable piece of evidence."""
    sites_by_evidence: dict[Evidence, list[int]] = defaultdict(list)
    for site_id, signals in index.items():
        for item in candidate_evidence(signals, config):
            sites_by_evidence[item].append(site_id)

    shared: dict[tuple[int, int], set[Evidence]] = defaultdict(set)
    for item, site_ids in sites_by_evidence.items():
        if not 2 <= len(site_ids) <= _max_sites(item.kind, config):
            continue  # unique to one site, or too common to mean anything
        for a, b in combinations(sorted(site_ids), 2):
            if item.kind is EvidenceKind.NAMESERVERS_AND_REGISTRATION and not registered_close(
                index[a], index[b], config.registration_window_days
            ):
                continue
            shared[(a, b)].add(item)

    return [score_pair(a, b, items, config) for (a, b), items in sorted(shared.items())]


def _max_sites(kind: EvidenceKind, config: ScoringConfig) -> int:
    """How many sites may share a key before it stops counting as evidence."""
    if kind is EvidenceKind.RARE_KIT_PATH:
        return config.rare_kit_path_max_sites
    return config.max_sites_per_signal
