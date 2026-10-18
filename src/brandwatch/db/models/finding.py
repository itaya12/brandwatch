"""Findings (spec §21 — findings, finding_evidence, analyst_labels).

A Finding is a scored, evidenced conclusion that an analyst confirms or dismisses.
Resolution of the spec's circular FK (findings.current_risk_score_id <-> risk_scores.finding_id):
that column does not exist; the current score is the one ``risk_scores`` row with
``is_current = TRUE`` (enforced by a partial unique index), exposed as ``Finding.current_score``.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from decimal import Decimal
from typing import Any

import sqlalchemy as sa
from sqlalchemy.orm import Mapped, mapped_column, relationship

from brandwatch.db.base import Base
from brandwatch.db.enums import AnalystVerdict, EvidenceRole, FindingState, Severity
from brandwatch.db.types import (
    GUID,
    JSONB,
    Percent,
    TZDateTime,
    created_at,
    enum_type,
    fk,
    utcnow,
    uuid_pk,
)


class Finding(Base):
    __tablename__ = "findings"
    __table_args__ = (
        sa.Index("ix_findings_brand_id_state_severity", "brand_id", "state", "severity"),
        sa.Index("ix_findings_campaign_id", "campaign_id"),
    )

    id: Mapped[uuid.UUID] = uuid_pk()
    candidate_id: Mapped[uuid.UUID] = fk("candidates.id", index=True)
    brand_id: Mapped[uuid.UUID] = fk("brands.id")
    state: Mapped[FindingState] = mapped_column(
        enum_type(FindingState), nullable=False, default=FindingState.OPEN
    )
    severity: Mapped[Severity] = mapped_column(enum_type(Severity), nullable=False)
    confidence: Mapped[Decimal | None] = mapped_column(Percent, nullable=True)
    analyst_verdict: Mapped[AnalystVerdict | None] = mapped_column(
        enum_type(AnalystVerdict), nullable=True
    )
    campaign_id: Mapped[uuid.UUID | None] = fk("campaigns.id", nullable=True)
    kind: Mapped[str] = mapped_column(
        sa.String(16), nullable=False, default="phishing", server_default="phishing"
    )  # phishing | shop | social
    # suspicious shops: the analyst's conclusion {level, proof, note, system_level, by, at} —
    # detection/shop_levels.py; null until a shop finding is confirmed
    conclusion: Mapped[dict[str, Any] | None] = mapped_column(JSONB, nullable=True)
    # "snooze until": out of the open queue until then (it comes back by itself)
    snoozed_until: Mapped[datetime | None] = mapped_column(TZDateTime, nullable=True)
    created_at: Mapped[datetime] = created_at()
    updated_at: Mapped[datetime] = mapped_column(
        TZDateTime, nullable=False, default=utcnow, onupdate=utcnow
    )

    risk_scores: Mapped[list[RiskScore]] = relationship(  # noqa: F821
        "RiskScore", back_populates="finding", order_by="RiskScore.created_at"
    )
    current_score: Mapped[RiskScore | None] = relationship(  # noqa: F821
        "RiskScore",
        primaryjoin="and_(RiskScore.finding_id == Finding.id, RiskScore.is_current == True)",
        uselist=False,
        viewonly=True,
    )
    evidence_links: Mapped[list[FindingEvidence]] = relationship(back_populates="finding")
    labels: Mapped[list[AnalystLabel]] = relationship(back_populates="finding")


class FindingNote(Base):
    """An analyst's working note on a finding ("asked the registrar on Monday"). Kept, never edited; shown in the
    finding's History and in Activity."""

    __tablename__ = "finding_notes"

    id: Mapped[uuid.UUID] = uuid_pk()
    finding_id: Mapped[uuid.UUID] = fk("findings.id", index=True)
    author_id: Mapped[uuid.UUID | None] = fk("users.id", nullable=True)
    text: Mapped[str] = mapped_column(sa.Text, nullable=False)
    created_at: Mapped[datetime] = created_at()


class FindingEvidence(Base):
    """Explicit Finding <-> Evidence link with a role; drives the detail UI."""

    __tablename__ = "finding_evidence"

    finding_id: Mapped[uuid.UUID] = mapped_column(
        GUID, sa.ForeignKey("findings.id", ondelete="RESTRICT"), primary_key=True
    )
    evidence_id: Mapped[uuid.UUID] = mapped_column(
        GUID, sa.ForeignKey("evidence.id", ondelete="RESTRICT"), primary_key=True
    )
    role: Mapped[EvidenceRole] = mapped_column(enum_type(EvidenceRole), nullable=False)

    finding: Mapped[Finding] = relationship(back_populates="evidence_links")


class AnalystLabel(Base):
    """Analyst feedback loop; later the ML training dataset."""

    __tablename__ = "analyst_labels"

    id: Mapped[uuid.UUID] = uuid_pk()
    finding_id: Mapped[uuid.UUID] = fk("findings.id", index=True)
    label: Mapped[str] = mapped_column(sa.String(64), nullable=False)
    reason: Mapped[str | None] = mapped_column(sa.Text, nullable=True)
    analyst_id: Mapped[uuid.UUID] = fk("users.id")
    at: Mapped[datetime] = mapped_column(TZDateTime, nullable=False, default=utcnow)

    finding: Mapped[Finding] = relationship(back_populates="labels")
