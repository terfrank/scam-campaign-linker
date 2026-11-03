"""Group linked sites into campaigns (connected components over linked pairs only).

Pairs that share evidence but are not linked (weak-only, or below the threshold) never
join components. They are reported as "possibly related" so a human can judge them.
"""

from dataclasses import dataclass
from statistics import mean

from scam_linker.linker.scoring import Evidence, PairScore


@dataclass(frozen=True)
class Member:
    site_id: int
    link_strength: float  # its strongest link to another member
    shared: tuple[Evidence, ...]  # everything it shares with other members, via its links


@dataclass(frozen=True)
class CampaignGroup:
    members: tuple[Member, ...]
    links: tuple[PairScore, ...]
    confidence: float  # mean member link strength

    @property
    def site_ids(self) -> frozenset[int]:
        return frozenset(member.site_id for member in self.members)


@dataclass(frozen=True)
class LinkResult:
    campaigns: tuple[CampaignGroup, ...]
    possibly_related: tuple[PairScore, ...]  # shared evidence, but not enough to link

    def campaign_for(self, site_id: int) -> CampaignGroup | None:
        """The campaign containing this site, or None (UNKNOWN: no link strong enough)."""
        return next((c for c in self.campaigns if site_id in c.site_ids), None)

    def possibly_related_to(self, site_ids: frozenset[int]) -> list[tuple[int, PairScore]]:
        """Sites outside `site_ids` with unlinked evidence pointing at one of them."""
        related = []
        for pair in self.possibly_related:
            if pair.site_a in site_ids and pair.site_b not in site_ids:
                related.append((pair.site_b, pair))
            elif pair.site_b in site_ids and pair.site_a not in site_ids:
                related.append((pair.site_a, pair))
        return related


class UnionFind:
    """Disjoint sets with path halving: near-constant time per operation."""

    def __init__(self) -> None:
        self._parent: dict[int, int] = {}

    def find(self, item: int) -> int:
        self._parent.setdefault(item, item)
        while self._parent[item] != item:
            self._parent[item] = self._parent[self._parent[item]]
            item = self._parent[item]
        return item

    def union(self, a: int, b: int) -> None:
        root_a, root_b = self.find(a), self.find(b)
        if root_a != root_b:
            self._parent[max(root_a, root_b)] = min(root_a, root_b)


def group_campaigns(pairs: list[PairScore]) -> LinkResult:
    """Build campaigns from linked pairs; collect the rest as possibly related."""
    linked = [pair for pair in pairs if pair.linked]
    sets = UnionFind()
    for pair in linked:
        sets.union(pair.site_a, pair.site_b)

    links_by_root: dict[int, list[PairScore]] = {}
    for pair in linked:
        links_by_root.setdefault(sets.find(pair.site_a), []).append(pair)
    campaigns = tuple(_build_campaign(links) for _, links in sorted(links_by_root.items()))

    # An unlinked pair inside one campaign adds nothing: both sites are already grouped.
    # (A site in no campaign is its own root, so "same root" means "same campaign".)
    possibly_related = tuple(
        pair
        for pair in pairs
        if not pair.linked and sets.find(pair.site_a) != sets.find(pair.site_b)
    )
    return LinkResult(campaigns=campaigns, possibly_related=possibly_related)


def _build_campaign(links: list[PairScore]) -> CampaignGroup:
    site_ids = sorted({site for pair in links for site in (pair.site_a, pair.site_b)})
    members = []
    for site_id in site_ids:
        own = [pair for pair in links if site_id in (pair.site_a, pair.site_b)]
        shared = sorted({item for pair in own for item in pair.evidence})
        members.append(Member(site_id, max(pair.strength for pair in own), tuple(shared)))
    confidence = round(mean(member.link_strength for member in members), 2)
    return CampaignGroup(tuple(members), tuple(links), confidence)
