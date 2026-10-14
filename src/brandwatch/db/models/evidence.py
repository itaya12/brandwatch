"""Immutable evidence with full provenance / chain of custody (spec §2, §21).

``evidence`` is the polymorphic parent; each typed child shares its PK (1:1). No application
code updates or deletes these rows, and migration 001 adds DB triggers that reject
UPDATE/DELETE as defense in depth.
"""

from __future__ import annotations

import uuid
from datetime import date, datetime
from typing import Any

import sqlalchemy as sa
from sqlalchemy.orm import Mapped, mapped_column, relationship

from brandwatch.db.base import Base
from brandwatch.db.enums import EvidenceType, ProviderStatus
from brandwatch.db.types import (
    GUID,
    INET,
    JSONB,
    TZDateTime,
    created_at,
    enum_type,
    fk,
    utcnow,
    uuid_pk,
)


class Evidence(Base):
    __tablename__ = "evidence"
    __table_args__ = (
        sa.Index(
            "ix_evidence_candidate_id_type_observed_at", "candidate_id", "type", "observed_at"
        ),
    )

    id: Mapped[uuid.UUID] = uuid_pk()
    candidate_id: Mapped[uuid.UUID] = fk("candidates.id")
    finding_id: Mapped[uuid.UUID | None] = fk("findings.id", nullable=True)
    type: Mapped[EvidenceType] = mapped_column(enum_type(EvidenceType), nullable=False)
    observed_at: Mapped[datetime] = mapped_column(TZDateTime, nullable=False, default=utcnow)
    created_at: Mapped[datetime] = created_at()
    # provenance / chain of custody
    source: Mapped[str] = mapped_column(sa.String(64), nullable=False)
    source_type: Mapped[str] = mapped_column(sa.String(32), nullable=False)
    collector: Mapped[str] = mapped_column(sa.String(64), nullable=False)
    collector_version: Mapped[str] = mapped_column(sa.String(32), nullable=False)
    parser_version: Mapped[str | None] = mapped_column(sa.String(32), nullable=True)
    scoring_version: Mapped[str | None] = mapped_column(sa.String(32), nullable=True)
    request_profile: Mapped[dict[str, Any] | None] = mapped_column(JSONB, nullable=True)
    response_meta: Mapped[dict[str, Any] | None] = mapped_column(JSONB, nullable=True)
    content_sha256: Mapped[str | None] = mapped_column(sa.String(64), nullable=True)
    artifact_location: Mapped[str | None] = mapped_column(sa.Text, nullable=True)
    trust_level: Mapped[str | None] = mapped_column(sa.String(16), nullable=True)
    parent_evidence_id: Mapped[uuid.UUID | None] = mapped_column(
        GUID, sa.ForeignKey("evidence.id", ondelete="RESTRICT"), nullable=True, index=True
    )

    parent: Mapped[Evidence | None] = relationship(remote_side=[id], viewonly=True)


class Screenshot(Base):
    __tablename__ = "screenshots"

    evidence_id: Mapped[uuid.UUID] = mapped_column(
        GUID, sa.ForeignKey("evidence.id", ondelete="RESTRICT"), primary_key=True
    )
    width: Mapped[int | None] = mapped_column(sa.Integer, nullable=True)
    height: Mapped[int | None] = mapped_column(sa.Integer, nullable=True)
    phash: Mapped[str | None] = mapped_column(sa.String(64), nullable=True)
    path: Mapped[str] = mapped_column(sa.Text, nullable=False)


class HtmlSnapshot(Base):
    __tablename__ = "html_snapshots"

    evidence_id: Mapped[uuid.UUID] = mapped_column(
        GUID, sa.ForeignKey("evidence.id", ondelete="RESTRICT"), primary_key=True
    )
    dom_hash: Mapped[str | None] = mapped_column(sa.String(64), nullable=True)
    title: Mapped[str | None] = mapped_column(sa.Text, nullable=True)
    meta: Mapped[dict[str, Any] | None] = mapped_column(JSONB, nullable=True)
    path: Mapped[str] = mapped_column(sa.Text, nullable=False)


class HttpResponse(Base):
    __tablename__ = "http_responses"

    evidence_id: Mapped[uuid.UUID] = mapped_column(
        GUID, sa.ForeignKey("evidence.id", ondelete="RESTRICT"), primary_key=True
    )
    status: Mapped[int | None] = mapped_column(sa.Integer, nullable=True)
    headers: Mapped[dict[str, Any] | None] = mapped_column(JSONB, nullable=True)
    ip: Mapped[str | None] = mapped_column(INET, nullable=True)
    redirect_chain: Mapped[list[Any] | None] = mapped_column(JSONB, nullable=True)
    size_bytes: Mapped[int | None] = mapped_column(sa.Integer, nullable=True)


class DnsObservation(Base):
    __tablename__ = "dns_observations"

    evidence_id: Mapped[uuid.UUID] = mapped_column(
        GUID, sa.ForeignKey("evidence.id", ondelete="RESTRICT"), primary_key=True
    )
    records: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    resolver: Mapped[str | None] = mapped_column(sa.String(64), nullable=True)


class WhoisObservation(Base):
    __tablename__ = "whois_observations"

    evidence_id: Mapped[uuid.UUID] = mapped_column(
        GUID, sa.ForeignKey("evidence.id", ondelete="RESTRICT"), primary_key=True
    )
    registered_at: Mapped[date | None] = mapped_column(sa.Date, nullable=True)
    registrar: Mapped[str | None] = mapped_column(sa.Text, nullable=True)
    registrant: Mapped[dict[str, Any] | None] = mapped_column(JSONB, nullable=True)
    raw: Mapped[dict[str, Any] | None] = mapped_column(JSONB, nullable=True)
    age_days: Mapped[int | None] = mapped_column(sa.Integer, nullable=True)


class SslObservation(Base):
    __tablename__ = "ssl_observations"

    evidence_id: Mapped[uuid.UUID] = mapped_column(
        GUID, sa.ForeignKey("evidence.id", ondelete="RESTRICT"), primary_key=True
    )
    issuer: Mapped[str | None] = mapped_column(sa.Text, nullable=True)
    not_before: Mapped[date | None] = mapped_column(sa.Date, nullable=True)
    not_after: Mapped[date | None] = mapped_column(sa.Date, nullable=True)
    sans: Mapped[list[Any] | None] = mapped_column(JSONB, nullable=True)
    fingerprint_sha256: Mapped[str | None] = mapped_column(sa.String(64), nullable=True)


class ReputationObservation(Base):
    """``status = unknown`` (e.g. VT not_found) is never interpreted as clean."""

    __tablename__ = "reputation_observations"

    evidence_id: Mapped[uuid.UUID] = mapped_column(
        GUID, sa.ForeignKey("evidence.id", ondelete="RESTRICT"), primary_key=True
    )
    provider: Mapped[str] = mapped_column(sa.String(64), nullable=False)
    status: Mapped[ProviderStatus] = mapped_column(enum_type(ProviderStatus), nullable=False)
    verdict: Mapped[str | None] = mapped_column(sa.Text, nullable=True)
    raw: Mapped[dict[str, Any] | None] = mapped_column(JSONB, nullable=True)


EVIDENCE_CHILD_TABLES: tuple[str, ...] = (
    "screenshots",
    "html_snapshots",
    "http_responses",
    "dns_observations",
    "whois_observations",
    "ssl_observations",
    "reputation_observations",
)
