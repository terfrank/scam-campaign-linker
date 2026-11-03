"""Tests for the linker: config validation, pair scoring, grouping and explanations."""

from typing import Any

import pytest
from pydantic import ValidationError

from fakes import fixture_text, make_context
from scam_linker.collectors import html_fingerprint, kit_paths, title, tracking_ids
from scam_linker.collectors.base import Signal, SignalType
from scam_linker.dns_client import DnsClient
from scam_linker.fetcher import SafeFetcher
from scam_linker.linker import link_sites
from scam_linker.linker.config import EvidenceKind, ScoringConfig, Tier, load_scoring_config
from scam_linker.linker.explain import campaign_explanation, describe_pair, summarize
from scam_linker.linker.scoring import SiteIndex, score_pairs

CONFIG = load_scoring_config()
STRONG = {str(kind): weight for kind, weight in CONFIG.strong.items()}
WEAK = {str(kind): weight for kind, weight in CONFIG.weak.items()}

FAVICON = Signal(SignalType.FAVICON_HASH, "495416780")
TRACKING = Signal(SignalType.TRACKING_ID, "G-EXMPL12345")
TRACKING_2 = Signal(SignalType.TRACKING_ID, "GTM-ABC1234")
CERT = Signal(SignalType.CERT, "295813:03bb")
KIT_PATH = Signal(SignalType.KIT_PATH, "/secure/verify.php")
NS1 = Signal(SignalType.NAMESERVER, "ns1.example-host.xyz")
NS2 = Signal(SignalType.NAMESERVER, "ns2.example-host.xyz")
REGISTRAR = Signal(SignalType.REGISTRAR, "example registrar, inc.")
TITLE = Signal(SignalType.TITLE, "examplebank - secure login")
IP = Signal(SignalType.IP, "45.67.89.10")
ASN = Signal(SignalType.ASN, "AS64500")


def registered(day: str) -> Signal:
    return Signal(SignalType.CREATED_DATE, day)


def config_with(**changes: Any) -> ScoringConfig:
    """The shipped config with some values replaced (and re-validated)."""
    return ScoringConfig.model_validate({**CONFIG.model_dump(), **changes})


# --- config ----------------------------------------------------------------------


def test_shipped_config_matches_the_spec() -> None:
    assert CONFIG.link_threshold == 0.8
    assert CONFIG.tier(EvidenceKind.FAVICON_HASH) is Tier.STRONG
    assert CONFIG.weight(EvidenceKind.FAVICON_HASH) == 0.9
    assert CONFIG.tier(EvidenceKind.REGISTRAR_AND_TITLE) is Tier.MEDIUM
    assert CONFIG.weight(EvidenceKind.ASN) == 0.1


@pytest.mark.parametrize(
    ("changes", "message"),
    [
        ({"link_threshold": 1.5}, "less than or equal to 1"),
        ({"strong": {**STRONG, "favicon_hash": 0}}, "greater than 0"),
        ({"strong": {**STRONG, "favicon_hsah": 0.9}}, "favicon_hsah"),
        ({"weak": {"ip": 0.1}}, "evidence kinds with no weight"),
        ({"weak": {**WEAK, "cert": 0.1}}, "more than one tier"),
        ({"surprise": 1}, "Extra inputs are not permitted"),
    ],
)
def test_invalid_config_is_rejected(changes: dict[str, Any], message: str) -> None:
    with pytest.raises(ValidationError, match=message):
        config_with(**changes)


# --- pair scoring ------------------------------------------------------------------


def test_one_strong_signal_links_two_sites() -> None:
    [pair] = score_pairs({1: {FAVICON}, 2: {FAVICON}}, CONFIG)

    assert (pair.site_a, pair.site_b) == (1, 2)
    assert pair.strength == 0.9
    assert pair.tier is Tier.STRONG
    assert pair.linked
    assert [item.label for item in pair.evidence] == ["favicon_hash:495416780"]


def test_each_evidence_kind_counts_once() -> None:
    """Two shared tracking IDs are still one kind of evidence: 0.9, not 1.8."""
    [pair] = score_pairs({1: {TRACKING, TRACKING_2}, 2: {TRACKING, TRACKING_2}}, CONFIG)

    assert pair.strength == 0.9
    assert len(pair.evidence) == 2  # both IDs are still reported


def test_strength_is_capped_at_one() -> None:
    [pair] = score_pairs({1: {FAVICON, CERT, IP}, 2: {FAVICON, CERT, IP}}, CONFIG)

    assert pair.strength == 1.0


def test_two_medium_signals_link() -> None:
    a = {NS1, NS2, REGISTRAR, TITLE, registered("2026-11-02")}
    b = {NS1, NS2, REGISTRAR, TITLE, registered("2026-11-06")}

    [pair] = score_pairs({1: a, 2: b}, CONFIG)

    assert pair.strength == 1.0
    assert pair.tier is Tier.MEDIUM
    assert pair.linked


def test_one_medium_signal_is_not_enough() -> None:
    [pair] = score_pairs({1: {REGISTRAR, TITLE}, 2: {REGISTRAR, TITLE}}, CONFIG)

    assert pair.strength == 0.5
    assert not pair.linked


@pytest.mark.parametrize(
    ("a", "b"),
    [
        ({NS1, NS2, registered("2026-11-02")}, {NS1, NS2, registered("2026-12-02")}),  # 30 days
        ({NS1, NS2, registered("2026-11-02")}, {NS1, NS2}),  # one date unknown
        ({NS1, NS2, registered("2026-11-02")}, {NS1, registered("2026-11-02")}),  # NS differ
        ({NS1, registered("not-a-date")}, {NS1, registered("2026-11-02")}),  # bad date
    ],
)
def test_nameserver_evidence_needs_same_set_and_close_registration(
    a: set[Signal], b: set[Signal]
) -> None:
    assert score_pairs({1: a, 2: b}, CONFIG) == []


def test_weak_only_evidence_is_possibly_related_not_linked() -> None:
    result = link_sites({1: {IP, ASN}, 2: {IP, ASN}}, CONFIG)

    assert result.campaigns == ()
    [pair] = result.possibly_related
    assert pair.strength == pytest.approx(0.2)
    assert pair.tier is Tier.WEAK
    assert result.campaign_for(1) is None  # UNKNOWN, not a guess


def test_float_noise_does_not_break_the_threshold() -> None:
    """0.7 + 0.1 is 0.7999999999999999 in floating point; it must still pass 0.8."""
    config = config_with(medium={"nameservers_and_registration": 0.5, "registrar_and_title": 0.7})

    [pair] = score_pairs({1: {REGISTRAR, TITLE, IP}, 2: {REGISTRAR, TITLE, IP}}, config)

    assert pair.strength == 0.8
    assert pair.linked


# --- noise filters -----------------------------------------------------------------


def test_shared_kit_path_counts_only_when_rare() -> None:
    two_sites = {1: {KIT_PATH}, 2: {KIT_PATH}}
    four_sites = {i: {KIT_PATH} for i in range(1, 5)}  # rare_kit_path_max_sites is 3

    assert score_pairs(two_sites, CONFIG)[0].linked
    assert score_pairs(four_sites, CONFIG) == []


def test_signal_shared_by_too_many_sites_is_ignored() -> None:
    """e.g. a hosting provider's default favicon must not merge all its customers."""
    config = config_with(max_sites_per_signal=3)
    index: SiteIndex = {i: {FAVICON} for i in range(1, 5)}

    assert score_pairs(index, config) == []


def test_ignore_list_removes_known_benign_values() -> None:
    config = config_with(ignore={"favicon_hash": [FAVICON.value]})

    assert score_pairs({1: {FAVICON}, 2: {FAVICON}}, config) == []


# --- grouping ------------------------------------------------------------------------


@pytest.mark.parametrize("threshold", [0.8, 0.05])
def test_shared_asn_does_not_merge_two_campaigns(threshold: float) -> None:
    """Campaign {1,2} (favicon) and campaign {3,4} (tracking ID) share only an ASN via 2-3.

    They must stay separate, and the ASN link must be reported as possibly related.
    The low threshold proves this holds because weak evidence can never link, not because
    0.1 happens to be below 0.8.
    """
    index: SiteIndex = {
        1: {FAVICON},
        2: {FAVICON, ASN},
        3: {TRACKING, ASN},
        4: {TRACKING},
    }

    result = link_sites(index, config_with(link_threshold=threshold))

    assert [sorted(c.site_ids) for c in result.campaigns] == [[1, 2], [3, 4]]
    [weak] = result.possibly_related
    assert (weak.site_a, weak.site_b) == (2, 3)
    assert [item.kind for item in weak.evidence] == [EvidenceKind.ASN]
    assert result.possibly_related_to(frozenset({1, 2})) == [(3, weak)]


def test_campaigns_are_transitive_with_member_strengths() -> None:
    """1-2 share a favicon, 2-3 share a tracking ID and a certificate: one campaign of three."""
    index: SiteIndex = {1: {FAVICON}, 2: {FAVICON, TRACKING, CERT}, 3: {TRACKING, CERT}}

    [campaign] = link_sites(index, CONFIG).campaigns

    strengths = {m.site_id: m.link_strength for m in campaign.members}
    assert strengths == {1: 0.9, 2: 1.0, 3: 1.0}
    assert campaign.confidence == 0.97  # mean of 0.9, 1.0, 1.0
    shared_by_2 = {item.kind for item in campaign.members[1].shared}
    assert shared_by_2 == {EvidenceKind.FAVICON_HASH, EvidenceKind.TRACKING_ID, EvidenceKind.CERT}


def test_weak_pair_inside_a_campaign_is_not_reported_separately() -> None:
    index: SiteIndex = {1: {FAVICON, ASN}, 2: {FAVICON}, 3: {FAVICON, ASN}}

    result = link_sites(index, CONFIG)

    assert len(result.campaigns) == 1
    assert result.possibly_related == ()


# --- explanations ------------------------------------------------------------------


def test_pair_explanation_is_plain_english() -> None:
    [pair] = score_pairs({1: {FAVICON, IP}, 2: {FAVICON, IP}}, CONFIG)

    assert describe_pair(pair, CONFIG) == (
        "Linked (strength 1.00): same favicon (hash 495416780); "
        "same IP address 45.67.89.10 (weak on its own: shared hosting is common)"
    )


def test_campaign_summary_and_explanation() -> None:
    index: SiteIndex = {
        1: {FAVICON, KIT_PATH, registered("2026-11-02")},
        2: {FAVICON, KIT_PATH, TRACKING, registered("2026-11-04")},
        3: {FAVICON, TRACKING, registered("2026-11-03")},
    }
    [campaign] = link_sites(index, CONFIG).campaigns

    # Most-shared first; ties (kit path, tracking ID: 2 sites each) in a fixed order.
    assert summarize(campaign, index, CONFIG) == (
        "3 sites share favicon 495416780, kit path /secure/verify.php and "
        "tracking ID G-EXMPL12345; registered 2026-11-02 to 2026-11-04"
    )
    explanation = campaign_explanation(campaign, index, CONFIG)
    assert explanation["registered_from"] == "2026-11-02"
    assert explanation["evidence"][0] == {
        "label": "favicon_hash:495416780",
        "description": "same favicon (hash 495416780)",
        "sites": 3,
    }


# --- end to end with the Phase 3 collectors -----------------------------------------


def test_two_copies_of_a_kit_are_linked_and_a_blog_is_not(
    fetcher: SafeFetcher, dns_client: DnsClient
) -> None:
    """Collect HTML signals from the fixtures, then link: kit_a and kit_b must link."""
    collectors = (title.collect, html_fingerprint.collect, kit_paths.collect, tracking_ids.collect)
    pages = {
        1: ("https://examplebank-secure-a.xyz/", "kit_a.html"),
        2: ("https://examplebank-secure-b.xyz/", "kit_b.html"),
        3: ("https://harmless-blog.org/", "unrelated.html"),
    }
    index: SiteIndex = {}
    for site_id, (url, fixture) in pages.items():
        ctx = make_context(url, fixture_text(f"html/{fixture}"), fetcher=fetcher, dns=dns_client)
        index[site_id] = {signal for collect in collectors for signal in collect(ctx)}

    result = link_sites(index, CONFIG)

    [campaign] = result.campaigns
    assert campaign.site_ids == {1, 2}
    kinds = {item.kind for item in campaign.links[0].evidence}
    assert kinds == {
        EvidenceKind.HTML_FINGERPRINT,
        EvidenceKind.TRACKING_ID,
        EvidenceKind.RARE_KIT_PATH,
    }
    assert result.campaign_for(3) is None


def test_weak_evidence_never_headlines_a_campaign() -> None:
    """Sites 1-2 share a favicon and an ASN; 2-3 share a certificate and the same ASN.

    The ASN is shared by the most members (all 3 count it via their links), but it is weak:
    the summary must lead with the strong evidence that actually holds the campaign together.
    """
    index: SiteIndex = {1: {FAVICON, ASN}, 2: {FAVICON, CERT, ASN}, 3: {CERT, ASN}}
    [campaign] = link_sites(index, CONFIG).campaigns

    summary = summarize(campaign, index, CONFIG)

    assert summary.startswith("3 sites share TLS certificate 295813:03bb")
    assert "network AS64500" in summary  # still mentioned, but last
    assert summary.index("network") > summary.index("favicon")
