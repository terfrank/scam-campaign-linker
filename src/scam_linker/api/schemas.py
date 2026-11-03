"""Request and response bodies. These are the public contract shown in /docs."""

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field, HttpUrl

MAX_BULK_URLS = 1000


class HealthResponse(BaseModel):
    status: Literal["ok", "degraded"]
    version: str
    database: Literal["ok", "unavailable"]


class UrlRequest(BaseModel):
    """HttpUrl rejects anything that isn't http(s) with a host, before any work is done."""

    url: HttpUrl


class BulkRequest(BaseModel):
    urls: list[HttpUrl] = Field(min_length=1, max_length=MAX_BULK_URLS)


class BulkAccepted(BaseModel):
    queued: int
    duplicates_skipped: int


class SignalOut(BaseModel):
    type: str
    value: str


class SiteOut(BaseModel):
    id: int
    url: str
    domain: str | None
    fetch_status: str | None
    first_seen: datetime
    last_checked: datetime | None
    collector_errors: dict[str, str]
    signals: list[SignalOut]


class SeedOut(BaseModel):
    url: str
    fetch_status: str | None
    collector_errors: dict[str, str]


class MemberOut(BaseModel):
    url: str
    link_strength: float
    shared: list[str]
    is_seed: bool = False


class EvidenceOut(BaseModel):
    label: str
    description: str
    sites: int


class LinkOut(BaseModel):
    """A linked pair of campaign members: one edge of the campaign graph."""

    source: str
    target: str
    strength: float
    shared: list[str]
    explanation: str


class RelatedOut(BaseModel):
    """A site with some shared evidence, but not enough to link: UNKNOWN, not a member."""

    url: str
    related_to: str  # the member (or seed) it shares evidence with
    strength: float
    shared: list[str]
    explanation: str


class CampaignOut(BaseModel):
    campaign_id: int
    created_at: datetime
    confidence: float
    summary: str
    registered_from: str | None
    registered_to: str | None
    evidence: list[EvidenceOut]
    members: list[MemberOut]


class SeedCampaignOut(BaseModel):
    """Answer to "which campaign is this URL part of?". status=unknown means no campaign."""

    status: Literal["linked", "unknown"]
    seed: SeedOut
    campaign_id: int | None
    confidence: float | None
    summary: str
    evidence: list[EvidenceOut]
    members: list[MemberOut]
    links: list[LinkOut]
    possibly_related_unknown: list[RelatedOut]
