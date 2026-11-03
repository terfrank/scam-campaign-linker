"""Evaluate the linker on a real feed sample: read the feed, report, export for hand-checking.

Everything written out is defanged (hxxps://evil[.]xyz) so no output file contains a
clickable link to a live phishing site.

The CSV has one row per decision the linker made about a pair of sites. A human fills in
`same_campaign` (yes / no / unsure); `score_csv` then turns those verdicts into precision.
Recall can't be measured this way: there is no ground truth for pairs the linker never saw.
"""

import csv
import random
from collections import Counter
from dataclasses import dataclass
from pathlib import Path

from pydantic import HttpUrl, TypeAdapter, ValidationError
from sqlalchemy import select
from sqlalchemy.orm import Session

from scam_linker.db import models, repository
from scam_linker.linker.config import ScoringConfig
from scam_linker.linker.explain import describe_pair
from scam_linker.linker.scoring import PairScore
from scam_linker.services import Linking

_HTTP_URL: TypeAdapter[HttpUrl] = TypeAdapter(HttpUrl)
CSV_FIELDS = [
    "decision",
    "campaign_id",
    "strength",
    "tier",
    "site_a",
    "site_b",
    "evidence",
    "explanation",
    "same_campaign",  # filled in by hand: yes / no / unsure
    "notes",
]
VERDICTS = ("yes", "no", "unsure")


def defang(url: str) -> str:
    """'https://evil.xyz/a' -> 'hxxps://evil[.]xyz/a': readable, but not a clickable link."""
    if url[:4].lower() == "http":
        url = "hxxp" + url[4:]
    return url.replace(".", "[.]")


# --- reading and sampling the feed ----------------------------------------------------


def read_feed(path: Path) -> tuple[list[str], int]:
    """URLs from a feed file: one per line, '#' comments and blank lines ignored.

    Returns (unique valid URLs in file order, number of lines rejected as not http(s)).
    Uses the same URL validation as the API, so the script accepts exactly what /sites would.
    """
    urls: dict[str, None] = {}
    rejected = 0
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        try:
            urls[repository.normalise_url(str(_HTTP_URL.validate_python(line)))] = None
        except ValidationError:
            rejected += 1
    return list(urls), rejected


def sample(urls: list[str], limit: int, seed: int | None) -> list[str]:
    """The first `limit` URLs, or a reproducible random sample when `seed` is given."""
    if seed is None:
        return urls[:limit]
    # Not security-relevant: a seeded, reproducible sample is the point here.
    return random.Random(seed).sample(urls, min(limit, len(urls)))  # noqa: S311


# --- the run report -------------------------------------------------------------------


@dataclass(frozen=True)
class CampaignLine:
    campaign_id: int
    confidence: float
    summary: str
    urls: list[str]


@dataclass(frozen=True)
class Report:
    sites: int
    fetch_status: dict[str, int]
    collector_failures: dict[str, int]
    sites_with_signals: int
    signal_coverage: dict[str, int]  # signal type -> number of sites that have it
    campaigns: list[CampaignLine]
    linked_pairs: int
    possibly_related_pairs: int

    @property
    def sites_in_campaigns(self) -> int:
        return sum(len(campaign.urls) for campaign in self.campaigns)


def build_report(session: Session, linking: Linking) -> Report:
    """Count what happened in this database: collection outcomes, coverage and campaigns."""
    sites = list(session.scalars(select(models.Site)))
    urls = {site.id: site.url for site in sites}
    coverage: Counter[str] = Counter()
    for signals in linking.index.values():
        coverage.update({signal.type.value for signal in signals})

    campaigns = [
        CampaignLine(
            campaign_id=row.id,
            confidence=row.confidence,
            summary=row.explanation["summary"],
            urls=sorted(urls[site_id] for site_id in group.site_ids),
        )
        for group, row in zip(linking.result.campaigns, linking.rows, strict=True)
    ]
    return Report(
        sites=len(sites),
        fetch_status=dict(Counter(site.fetch_status or "unknown" for site in sites).most_common()),
        collector_failures=dict(
            Counter(name for site in sites for name in site.collector_errors).most_common()
        ),
        sites_with_signals=len(linking.index),
        signal_coverage=dict(coverage.most_common()),
        campaigns=sorted(campaigns, key=lambda c: (-len(c.urls), c.campaign_id)),
        linked_pairs=sum(len(group.links) for group in linking.result.campaigns),
        possibly_related_pairs=len(linking.result.possibly_related),
    )


def _percent(part: int, whole: int) -> str:
    return f"{part} ({part / whole:.0%})" if whole else str(part)


def format_report(report: Report) -> str:
    """The report as Markdown: real counts only, ready to quote in the README."""
    n = report.sites
    sizes = Counter(len(campaign.urls) for campaign in report.campaigns)
    size_text = ", ".join(f"{count} of size {size}" for size, count in sorted(sizes.items()))
    lines = [
        "# Evaluation run",
        "",
        f"- Sites in this evaluation database: {n}",
        "- Fetch outcome: "
        + ", ".join(
            f"{status} {_percent(count, n)}" for status, count in report.fetch_status.items()
        ),
        f"- Sites with at least one signal: {_percent(report.sites_with_signals, n)}",
        "- Signal coverage (sites with each signal type): "
        + ", ".join(f"{kind} {count}" for kind, count in report.signal_coverage.items()),
        "- Collector failures (sites where a collector was skipped): "
        + (
            ", ".join(f"{name} {count}" for name, count in report.collector_failures.items())
            or "none"
        ),
        f"- Campaigns: {len(report.campaigns)}" + (f" ({size_text})" if size_text else ""),
        f"- Sites placed in a campaign: {_percent(report.sites_in_campaigns, n)}",
        f"- Sites with no campaign (UNKNOWN): {_percent(n - report.sites_in_campaigns, n)}",
        f"- Linked pairs: {report.linked_pairs}",
        f"- Possibly related (UNKNOWN) pairs: {report.possibly_related_pairs}",
        "",
        "## Campaigns",
    ]
    if not report.campaigns:
        lines.append("\nNone.")
    for campaign in report.campaigns:
        lines += [
            "",
            f"### Campaign {campaign.campaign_id}: {len(campaign.urls)} sites, "
            f"confidence {campaign.confidence:.2f}",
            "",
            defang(campaign.summary),
            "",
            *(f"- {defang(url)}" for url in campaign.urls),
        ]
    return "\n".join(lines) + "\n"


# --- hand-check CSV -------------------------------------------------------------------


def export_pairs_csv(session: Session, linking: Linking, config: ScoringConfig, path: Path) -> int:
    """Write every linked and possibly-related pair for hand-checking. Returns the row count."""
    rows: list[tuple[str, int | None, PairScore]] = []
    for group, row in zip(linking.result.campaigns, linking.rows, strict=True):
        rows += [("linked", row.id, pair) for pair in group.links]
    rows += [("possibly_related", None, pair) for pair in linking.result.possibly_related]

    site_ids = {site for _, _, pair in rows for site in (pair.site_a, pair.site_b)}
    urls = {site_id: site.url for site_id, site in repository.get_sites(session, site_ids).items()}
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=CSV_FIELDS)
        writer.writeheader()
        for decision, campaign_id, pair in rows:
            writer.writerow(
                {
                    "decision": decision,
                    "campaign_id": campaign_id if campaign_id is not None else "",
                    "strength": f"{pair.strength:.2f}",
                    "tier": pair.tier.value,
                    "site_a": defang(urls[pair.site_a]),
                    "site_b": defang(urls[pair.site_b]),
                    "evidence": "; ".join(defang(item.label) for item in pair.evidence),
                    "explanation": defang(describe_pair(pair, config)),
                    "same_campaign": "",
                    "notes": "",
                }
            )
    return len(rows)


@dataclass(frozen=True)
class VerdictCounts:
    yes: int = 0
    no: int = 0
    unsure: int = 0
    unchecked: int = 0

    @property
    def checked(self) -> int:
        return self.yes + self.no

    @property
    def yes_rate(self) -> float | None:
        """Share of checked pairs judged to be the same campaign (unsure excluded)."""
        return self.yes / self.checked if self.checked else None


def score_csv(path: Path) -> dict[str, VerdictCounts]:
    """Count hand-checked verdicts per decision ('linked', 'possibly_related').

    For 'linked' rows the yes-rate is the linker's precision. For 'possibly_related' rows a
    high yes-rate means real links are being missed, so the threshold may be too strict.
    """
    counts: dict[str, Counter[str]] = {}
    with path.open(newline="", encoding="utf-8") as handle:
        for line, row in enumerate(csv.DictReader(handle), start=2):
            verdict = (row.get("same_campaign") or "").strip().lower()
            if verdict and verdict not in VERDICTS:
                raise ValueError(f"line {line}: same_campaign must be yes, no, unsure or empty")
            counts.setdefault(row["decision"], Counter())[verdict or "unchecked"] += 1
    return {
        decision: VerdictCounts(c["yes"], c["no"], c["unsure"], c["unchecked"])
        for decision, c in counts.items()
    }
