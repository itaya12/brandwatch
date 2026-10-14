"""Normalized indicators of compromise (spec §10, §21)."""

from __future__ import annotations

import uuid
from datetime import datetime

import sqlalchemy as sa
from sqlalchemy.orm import Mapped, mapped_column

from brandwatch.db.base import Base
from brandwatch.db.enums import IocType
from brandwatch.db.types import TZDateTime, enum_type, fk, utcnow, uuid_pk


class Ioc(Base):
    __tablename__ = "iocs"
    __table_args__ = (
        sa.UniqueConstraint(
            "workspace_id", "type", "value", name="uq_iocs_workspace_id_type_value"
        ),
    )

    id: Mapped[uuid.UUID] = uuid_pk()
    workspace_id: Mapped[uuid.UUID] = fk("workspaces.id")
    type: Mapped[IocType] = mapped_column(enum_type(IocType), nullable=False)
    value: Mapped[str] = mapped_column(sa.Text, nullable=False)
    finding_id: Mapped[uuid.UUID | None] = fk("findings.id", nullable=True, index=True)
    campaign_id: Mapped[uuid.UUID | None] = fk("campaigns.id", nullable=True, index=True)
    source_evidence_id: Mapped[uuid.UUID | None] = fk("evidence.id", nullable=True)
    first_seen: Mapped[datetime] = mapped_column(TZDateTime, nullable=False, default=utcnow)
