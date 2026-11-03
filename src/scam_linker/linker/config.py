"""Load and validate the linker's weights and thresholds (scoring.toml)."""

import tomllib
from enum import StrEnum
from importlib import resources
from pathlib import Path
from typing import Annotated, Self

from pydantic import BaseModel, ConfigDict, Field, model_validator

from scam_linker.collectors.base import SignalType


class EvidenceKind(StrEnum):
    """A reason two sites may be related. Each kind has one weight in scoring.toml."""

    FAVICON_HASH = "favicon_hash"
    HTML_FINGERPRINT = "html_fingerprint"
    TRACKING_ID = "tracking_id"
    CERT = "cert"
    RARE_KIT_PATH = "rare_kit_path"
    NAMESERVERS_AND_REGISTRATION = "nameservers_and_registration"
    REGISTRAR_AND_TITLE = "registrar_and_title"
    IP = "ip"
    ASN = "asn"


class Tier(StrEnum):
    STRONG = "strong"
    MEDIUM = "medium"
    WEAK = "weak"


Weight = Annotated[float, Field(gt=0, le=1)]


class ScoringConfig(BaseModel):
    """The validated contents of scoring.toml."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    link_threshold: Annotated[float, Field(gt=0, le=1)]
    registration_window_days: Annotated[int, Field(ge=0)]
    rare_kit_path_max_sites: Annotated[int, Field(ge=2)]
    max_sites_per_signal: Annotated[int, Field(ge=2)]
    strong: dict[EvidenceKind, Weight]
    medium: dict[EvidenceKind, Weight]
    weak: dict[EvidenceKind, Weight]
    ignore: dict[SignalType, list[str]] = Field(default_factory=dict)

    @model_validator(mode="after")
    def _each_kind_in_exactly_one_tier(self) -> Self:
        listed = [*self.strong, *self.medium, *self.weak]
        duplicated = sorted({kind for kind in listed if listed.count(kind) > 1})
        missing = sorted(set(EvidenceKind) - set(listed))
        if duplicated:
            raise ValueError(f"evidence kinds in more than one tier: {duplicated}")
        if missing:
            raise ValueError(f"evidence kinds with no weight: {missing}")
        return self

    def tier(self, kind: EvidenceKind) -> Tier:
        if kind in self.strong:
            return Tier.STRONG
        if kind in self.medium:
            return Tier.MEDIUM
        return Tier.WEAK

    def weight(self, kind: EvidenceKind) -> float:
        return {**self.strong, **self.medium, **self.weak}[kind]


def load_scoring_config(path: Path | None = None) -> ScoringConfig:
    """Read scoring.toml (the copy shipped in the package unless `path` is given)."""
    if path is None:
        text = resources.files("scam_linker").joinpath("scoring.toml").read_text(encoding="utf-8")
    else:
        text = path.read_text(encoding="utf-8")
    return ScoringConfig.model_validate(tomllib.loads(text))
