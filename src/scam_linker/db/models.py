"""SQLAlchemy 2.0 models. The site/signal graph is: Site --SiteSignal--> Signal.

Schema changes go through Alembic (migrations/). Never edit a table here without adding a
migration: CI runs `alembic check`, which fails if models and migrations disagree.
"""

from datetime import UTC, datetime
from typing import Any

from sqlalchemy import (
    JSON,
    DateTime,
    Dialect,
    Float,
    ForeignKey,
    MetaData,
    String,
    Text,
    TypeDecorator,
    UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship

# Predictable constraint names, so migrations can refer to (and drop) them by name.
NAMING_CONVENTION = {
    "ix": "ix_%(table_name)s_%(column_0_N_name)s",
    "uq": "uq_%(table_name)s_%(column_0_N_name)s",
    "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
    "pk": "pk_%(table_name)s",
}

# JSONB on PostgreSQL (indexable, compact); plain JSON on SQLite for tests.
JSONType = JSON().with_variant(JSONB(), "postgresql")


def utcnow() -> datetime:
    return datetime.now(UTC)


class UTCDateTime(TypeDecorator[datetime]):
    """Timezone-aware UTC datetimes on every database.

    SQLite has no timezone support and hands back naive datetimes; this puts UTC back on
    read, and refuses naive datetimes on write so local times can't sneak in.
    """

    impl = DateTime(timezone=True)
    cache_ok = True

    def process_bind_param(self, value: datetime | None, dialect: Dialect) -> datetime | None:
        if value is None:
            return None
        if value.tzinfo is None:
            raise ValueError("naive datetime; use datetime.now(UTC)")
        return value.astimezone(UTC)

    def process_result_value(self, value: datetime | None, dialect: Dialect) -> datetime | None:
        if value is not None and value.tzinfo is None:
            return value.replace(tzinfo=UTC)
        return value


class Base(DeclarativeBase):
    metadata = MetaData(naming_convention=NAMING_CONVENTION)


class Site(Base):
    """One scanned URL."""

    __tablename__ = "sites"

    id: Mapped[int] = mapped_column(primary_key=True)
    url: Mapped[str] = mapped_column(Text, unique=True)
    domain: Mapped[str | None] = mapped_column(Text, index=True)
    first_seen: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    last_checked: Mapped[datetime | None] = mapped_column(UTCDateTime)
    fetch_status: Mapped[str | None] = mapped_column(String(32))
    collector_errors: Mapped[dict[str, str]] = mapped_column(JSONType, default=dict)

    signal_links: Mapped[list["SiteSignal"]] = relationship(
        back_populates="site", cascade="all, delete-orphan"
    )


class Signal(Base):
    """One distinct observed fact, e.g. (favicon_hash, '495416780'). Shared by many sites."""

    __tablename__ = "signals"
    __table_args__ = (UniqueConstraint("type", "value"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    type: Mapped[str] = mapped_column(String(32))
    value: Mapped[str] = mapped_column(Text)


class SiteSignal(Base):
    """Graph edge: `site` was observed with `signal` (most recently at `observed_at`)."""

    __tablename__ = "site_signals"

    site_id: Mapped[int] = mapped_column(
        ForeignKey("sites.id", ondelete="CASCADE"), primary_key=True
    )
    # The primary key index starts with site_id, so it can't serve "which sites have signal X?".
    # This separate index makes that reverse lookup, which the linker relies on, fast.
    signal_id: Mapped[int] = mapped_column(
        ForeignKey("signals.id", ondelete="CASCADE"), primary_key=True, index=True
    )
    observed_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)

    site: Mapped[Site] = relationship(back_populates="signal_links")
    signal: Mapped[Signal] = relationship()


class Campaign(Base):
    """A group of sites linked by strong/medium evidence."""

    __tablename__ = "campaigns"

    id: Mapped[int] = mapped_column(primary_key=True)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    confidence: Mapped[float] = mapped_column(Float)
    explanation: Mapped[dict[str, Any]] = mapped_column(JSONType, default=dict)

    members: Mapped[list["CampaignMember"]] = relationship(
        back_populates="campaign", cascade="all, delete-orphan"
    )


class CampaignMember(Base):
    """A site's membership in a campaign, with the evidence that put it there."""

    __tablename__ = "campaign_members"

    campaign_id: Mapped[int] = mapped_column(
        ForeignKey("campaigns.id", ondelete="CASCADE"), primary_key=True
    )
    site_id: Mapped[int] = mapped_column(
        ForeignKey("sites.id", ondelete="CASCADE"), primary_key=True, index=True
    )
    link_strength: Mapped[float] = mapped_column(Float)
    shared_signals: Mapped[list[str]] = mapped_column(JSONType, default=list)

    campaign: Mapped[Campaign] = relationship(back_populates="members")
    site: Mapped[Site] = relationship()
