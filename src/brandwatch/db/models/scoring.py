"""Versioned, append-only scoring (spec §2, §5, §21).

Re-scoring appends a new ``risk_scores`` row and flips ``is_current``; the partial unique index
``uq_risk_scores_current`` guarantees exactly one current score per finding. The immutability
trigger (migration 001) blocks DELETE and blocks UPDATE of every column except ``is_current``.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from decimal import Decimal
from typing import Any

import sqlalchemy as sa
from sqlalchemy.orm import Mapped, mapped_column, relationship

from brandwatch.db.base import Base
from brandwatch.db.enums import Severity
from brandwatch.db.types import JSONB, Percent, created_at, enum_type, fk, uuid_pk

_IS_CURRENT = sa.text("is_current")


class RiskScore(Base):
    __tablename__ = "risk_scores"
    __table_args__ = (
        sa.Index(
            "uq_risk_scores_current",
            "finding_id",
            unique=True,
            postgresql_where=_IS_CURRENT,
            sqlite_where=_IS_CURRENT,
        ),
    )

    id: Mapped[uuid.UUID] = uuid_pk()
    finding_id: Mapped[uuid.UUID] = fk("findings.id")
    is_current: Mapped[bool] = mapped_column(sa.Boolean, nullable=False, default=True)
    score: Mapped[int] = mapped_column(sa.Integer, nullable=False)  # 0–100 normalized
    raw_score: Mapped[int] = mapped_column(sa.Integer, nullable=False)  # 0–150 pre-normalization
    severity: Mapped[Severity] = mapped_column(enum_type(Severity), nullable=False)
    confidence: Mapped[Decimal] = mapped_column(Percent, nullable=False)
    scoring_version: Mapped[str] = mapped_column(sa.String(32), nullable=False)
    signals: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)
    groups: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)
    created_at: Mapped[datetime] = created_at()

    finding: Mapped[Finding] = relationship("Finding", back_populates="risk_scores")  # noqa: F821


# Columns of risk_scores that MAY change after insert. Everything else is frozen by trigger.
RISK_SCORES_MUTABLE_COLUMNS: tuple[str, ...] = ("is_current",)


class RiskScoreVersion(Base):
    """Snapshot of weights/thresholds/rules so every old score stays interpretable."""

    __tablename__ = "risk_score_versions"

    id: Mapped[uuid.UUID] = uuid_pk()
    version: Mapped[str] = mapped_column(sa.String(32), nullable=False, unique=True)
    weights: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    thresholds: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    combination_rules: Mapped[list[Any]] = mapped_column(JSONB, nullable=False)
    created_at: Mapped[datetime] = created_at()


class RuleVersion(Base):
    """Versioned payloads for vertical profiles, AI prompts, parsers (kind + version)."""

    __tablename__ = "rule_versions"
    __table_args__ = (sa.UniqueConstraint("kind", "version", name="uq_rule_versions_kind_version"),)

    id: Mapped[uuid.UUID] = uuid_pk()
    kind: Mapped[str] = mapped_column(sa.String(32), nullable=False)
    version: Mapped[str] = mapped_column(sa.String(32), nullable=False)
    payload: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    created_at: Mapped[datetime] = created_at()
