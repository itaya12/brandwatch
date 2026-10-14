"""Reports and takedown case management (spec §14, §21)."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

import sqlalchemy as sa
from sqlalchemy.orm import Mapped, mapped_column

from brandwatch.db.base import Base
from brandwatch.db.enums import TakedownState
from brandwatch.db.types import JSONB, TZDateTime, created_at, enum_type, fk, utcnow, uuid_pk


class Report(Base):
    __tablename__ = "reports"

    id: Mapped[uuid.UUID] = uuid_pk()
    brand_id: Mapped[uuid.UUID] = fk("brands.id", index=True)
    finding_id: Mapped[uuid.UUID | None] = fk("findings.id", nullable=True, index=True)
    kind: Mapped[str] = mapped_column(sa.String(32), nullable=False)
    format: Mapped[str] = mapped_column(sa.String(16), nullable=False)
    path: Mapped[str] = mapped_column(sa.Text, nullable=False)
    created_at: Mapped[datetime] = created_at()


class TakedownDraft(Base):
    """draft -> review -> approved -> sent -> acknowledged -> in_progress -> resolved
    (+ rejected / reopened). A human approves before any send — never automatic."""

    __tablename__ = "takedown_drafts"

    id: Mapped[uuid.UUID] = uuid_pk()
    finding_id: Mapped[uuid.UUID] = fk("findings.id", index=True)
    state: Mapped[TakedownState] = mapped_column(
        enum_type(TakedownState), nullable=False, default=TakedownState.DRAFT
    )
    abuse_contact: Mapped[str | None] = mapped_column(sa.Text, nullable=True)
    registrar: Mapped[str | None] = mapped_column(sa.Text, nullable=True)
    host: Mapped[str | None] = mapped_column(sa.Text, nullable=True)
    reference: Mapped[str | None] = mapped_column(sa.Text, nullable=True)
    body: Mapped[str | None] = mapped_column(sa.Text, nullable=True)
    sent_at: Mapped[datetime | None] = mapped_column(TZDateTime, nullable=True)
    response_at: Mapped[datetime | None] = mapped_column(TZDateTime, nullable=True)
    resolved_at: Mapped[datetime | None] = mapped_column(TZDateTime, nullable=True)
    # registrar / hosting / CDN contacts, what was sent where, report portals notified (migration 007)
    channels: Mapped[dict[str, Any] | None] = mapped_column(JSONB, nullable=True)
    created_at: Mapped[datetime] = created_at()
    updated_at: Mapped[datetime] = mapped_column(
        TZDateTime, nullable=False, default=utcnow, onupdate=utcnow
    )
