"""Providers, encrypted API keys, cost accounting (spec §4, §12, §13, §21)."""

from __future__ import annotations

import uuid
from datetime import datetime
from decimal import Decimal
from typing import Any

import sqlalchemy as sa
from sqlalchemy.orm import Mapped, mapped_column

from brandwatch.db.base import Base
from brandwatch.db.types import JSONB, Money, TZDateTime, created_at, fk, utcnow, uuid_pk


class ApiProvider(Base):
    __tablename__ = "api_providers"

    id: Mapped[uuid.UUID] = uuid_pk()
    key: Mapped[str] = mapped_column(sa.String(64), nullable=False, unique=True)  # "virustotal"
    kind: Mapped[str] = mapped_column(sa.String(32), nullable=False)  # "reputation"
    config: Mapped[dict[str, Any] | None] = mapped_column(JSONB, nullable=True)


class ApiKey(Base):
    """Envelope-encrypted secret: ``ciphertext`` (AES-256-GCM under a per-record DEK) and the
    DEK wrapped by the KEK. ``last4`` is the only thing the UI ever shows."""

    __tablename__ = "api_keys"
    __table_args__ = (
        sa.UniqueConstraint("workspace_id", "provider", name="uq_api_keys_workspace_id_provider"),
    )

    id: Mapped[uuid.UUID] = uuid_pk()
    workspace_id: Mapped[uuid.UUID] = fk("workspaces.id")
    provider: Mapped[str] = mapped_column(sa.String(64), nullable=False)
    ciphertext: Mapped[bytes] = mapped_column(sa.LargeBinary, nullable=False)
    dek_wrapped: Mapped[bytes] = mapped_column(sa.LargeBinary, nullable=False)
    last4: Mapped[str] = mapped_column(sa.String(8), nullable=False)
    created_at: Mapped[datetime] = created_at()
    rotated_at: Mapped[datetime | None] = mapped_column(TZDateTime, nullable=True)


class ApiUsage(Base):
    __tablename__ = "api_usage"
    __table_args__ = (sa.Index("ix_api_usage_provider_at", "provider", "at"),)

    id: Mapped[uuid.UUID] = uuid_pk()
    workspace_id: Mapped[uuid.UUID] = fk("workspaces.id")
    provider: Mapped[str] = mapped_column(sa.String(64), nullable=False)
    job_id: Mapped[uuid.UUID | None] = fk("scan_jobs.id", nullable=True)
    calls: Mapped[int] = mapped_column(sa.Integer, nullable=False, default=1)
    cost_usd: Mapped[Decimal] = mapped_column(Money, nullable=False, default=Decimal("0"))
    at: Mapped[datetime] = mapped_column(TZDateTime, nullable=False, default=utcnow)
