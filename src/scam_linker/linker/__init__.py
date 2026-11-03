"""The linker: score pairs of sites on shared evidence, then group linked sites into campaigns.

Pure functions over in-memory data (no database, no network), so every rule is unit-testable.
"""

from scam_linker.linker.config import ScoringConfig
from scam_linker.linker.grouping import LinkResult, group_campaigns
from scam_linker.linker.scoring import SiteIndex, score_pairs


def link_sites(index: SiteIndex, config: ScoringConfig) -> LinkResult:
    """Score all pairs that share evidence and group the linked ones into campaigns."""
    return group_campaigns(score_pairs(index, config))
