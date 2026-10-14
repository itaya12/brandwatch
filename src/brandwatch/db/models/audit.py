"""Audit trail (spec §21 — audit_events*, immutable).

Every state transition and every analyst action writes a row: who (system vs analyst), what,
on which object, old -> new, why, when. Append-only; backed by a DB trigger (migration 001).
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

import sqlalchemy as sa
from sqlalchemy.orm import Mapped, mapped_column

from brandwatch.db.base import Base
from brandwatch.db.types import GUID, JSONB, TZDateTime, fk, utcnow, uuid_pk


class AuditEvent(Base):
    __tablename__ = "audit_events"
    __table_args__ = (
        sa.Index("ix_audit_events_workspace_at", "workspace_id", "at"),
        sa.Index("ix_audit_events_object", "object_type", "object_id"),
    )

    id: Mapped[uuid.UUID] = uuid_pk()
    workspace_id: Mapped[uuid.UUID] = fk("workspaces.id")
    actor_type: Mapped[str] = mapped_column(sa.String(32), nullable=False)  # "system" | "analyst"
    actor_id: Mapped[uuid.UUID | None] = mapped_column(GUID, nullable=True)
    action: Mapped[str] = mapped_column(sa.String(100), nullable=False)
    object_type: Mapped[str] = mapped_column(sa.String(64), nullable=False)
    object_id: Mapped[uuid.UUID | None] = mapped_column(GUID, nullable=True)
    old_value: Mapped[dict[str, Any] | None] = mapped_column(JSONB, nullable=True)
    new_value: Mapped[dict[str, Any] | None] = mapped_column(JSONB, nullable=True)
    reason: Mapped[str | None] = mapped_column(sa.Text, nullable=True)
    at: Mapped[datetime] = mapped_column(
        TZDateTime, nullable=False, default=utcnow, server_default=sa.func.now()
    )
