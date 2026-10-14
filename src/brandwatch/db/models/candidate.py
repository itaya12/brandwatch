"""Discovery lifecycle (spec §21 — candidates, candidate_sources, observations*).

Candidate != Finding: a candidate is a hypothesis observed over time. Identity is
``(brand_id, canonical_url)`` so N discovery sources collapse into one candidate.
"""

from __future__ import annotations

import uuid
from datetime import datetime

import sqlalchemy as sa
from sqlalchemy.orm import Mapped, mapped_column, relationship

from brandwatch.db.base import Base
from brandwatch.db.enums import CandidateState, DiscoverySource, ScannerProfile, Surface
from brandwatch.db.types import JSONB, CIText, TZDateTime, enum_type, fk, utcnow, uuid_pk

_DUE_STATES = sa.text("state IN ('watching', 'long_watch')")


class Candidate(Base):
    __tablename__ = "candidates"
    __table_args__ = (
        sa.UniqueConstraint(
            "brand_id", "canonical_url", name="uq_candidates_brand_id_canonical_url"
        ),
        sa.Index("ix_candidates_brand_id_state", "brand_id", "state"),
        sa.Index(
            "ix_candidates_due",
            "next_scan_at",
            postgresql_where=_DUE_STATES,
            sqlite_where=_DUE_STATES,
        ),
    )

    id: Mapped[uuid.UUID] = uuid_pk()
    brand_id: Mapped[uuid.UUID] = fk("brands.id")
    canonical_domain: Mapped[str] = mapped_column(CIText, nullable=False)
    canonical_url: Mapped[str] = mapped_column(sa.Text, nullable=False)
    hostname: Mapped[str] = mapped_column(CIText, nullable=False)
    priority: Mapped[int] = mapped_column(sa.Integer, nullable=False, default=0)
    state: Mapped[CandidateState] = mapped_column(
        enum_type(CandidateState), nullable=False, default=CandidateState.NEW
    )
    surface: Mapped[Surface] = mapped_column(enum_type(Surface), nullable=False)
    first_seen: Mapped[datetime] = mapped_column(TZDateTime, nullable=False, default=utcnow)
    last_seen: Mapped[datetime] = mapped_column(TZDateTime, nullable=False, default=utcnow)
    next_scan_at: Mapped[datetime | None] = mapped_column(TZDateTime, nullable=True)
    scan_count: Mapped[int] = mapped_column(sa.Integer, nullable=False, default=0)
    content_hash: Mapped[str | None] = mapped_column(sa.String(64), nullable=True)
    last_analysis: Mapped[dict | None] = mapped_column(JSONB, nullable=True)  # ML feature store
    last_scored_at: Mapped[datetime | None] = mapped_column(TZDateTime, nullable=True)

    sources: Mapped[list[CandidateSource]] = relationship(back_populates="candidate")
    observations: Mapped[list[Observation]] = relationship(
        back_populates="candidate", order_by="Observation.observed_at"
    )


class CandidateSource(Base):
    __tablename__ = "candidate_sources"
    __table_args__ = (
        sa.UniqueConstraint(
            "candidate_id", "source", name="uq_candidate_sources_candidate_id_source"
        ),
    )

    id: Mapped[uuid.UUID] = uuid_pk()
    candidate_id: Mapped[uuid.UUID] = fk("candidates.id")
    source: Mapped[DiscoverySource] = mapped_column(enum_type(DiscoverySource), nullable=False)
    matched_pattern: Mapped[str | None] = mapped_column(sa.Text, nullable=True)
    found_at: Mapped[datetime] = mapped_column(TZDateTime, nullable=False, default=utcnow)

    candidate: Mapped[Candidate] = relationship(back_populates="sources")


class Observation(Base):
    """One timestamped look at a candidate (immutable — the observation timeline)."""

    __tablename__ = "observations"
    __table_args__ = (
        sa.Index("ix_observations_candidate_id_observed_at", "candidate_id", "observed_at"),
    )

    id: Mapped[uuid.UUID] = uuid_pk()
    candidate_id: Mapped[uuid.UUID] = fk("candidates.id")
    observed_at: Mapped[datetime] = mapped_column(TZDateTime, nullable=False, default=utcnow)
    source: Mapped[DiscoverySource] = mapped_column(enum_type(DiscoverySource), nullable=False)
    scanner_profile: Mapped[ScannerProfile] = mapped_column(
        enum_type(ScannerProfile), nullable=False, default=ScannerProfile.DATACENTER
    )
    state_at_time: Mapped[CandidateState] = mapped_column(enum_type(CandidateState), nullable=False)
    content_hash: Mapped[str | None] = mapped_column(sa.String(64), nullable=True)
    screenshot_evidence_id: Mapped[uuid.UUID | None] = fk("evidence.id", nullable=True)
    http_status: Mapped[int | None] = mapped_column(sa.Integer, nullable=True)
    changed: Mapped[bool] = mapped_column(sa.Boolean, nullable=False, default=False)

    candidate: Mapped[Candidate] = relationship(back_populates="observations")
