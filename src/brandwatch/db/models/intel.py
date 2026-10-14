"""Site & network intel cache (the "Investigate site and its network" page).

One row per (subject, source, relation): e.g. ``domain/3commas.vip/virustotal/resolutions`` or
``ip/104.21.37.218/virustotal/report``. It is a mutable cache — not evidence — refreshed on demand
and expired after ``expires_at``; the analyst can force a refresh at any time.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

import sqlalchemy as sa
from sqlalchemy.orm import Mapped, mapped_column

from brandwatch.db.base import Base
from brandwatch.db.types import JSONB, TZDateTime, fk, utcnow, uuid_pk


class IntelLookup(Base):
    __tablename__ = "intel_lookups"
    __table_args__ = (
        sa.UniqueConstraint(
            "workspace_id",
            "subject_type",
            "subject",
            "source",
            "relation",
            name="uq_intel_lookups_subject",  # one row per lookup; Postgres caps names at 63 characters
        ),  # fmt: skip
        sa.Index(
            "ix_intel_lookups_workspace_id_subject_type_subject",
            "workspace_id",
            "subject_type",
            "subject",
        ),
    )

    id: Mapped[uuid.UUID] = uuid_pk()
    workspace_id: Mapped[uuid.UUID] = fk("workspaces.id")
    subject_type: Mapped[str] = mapped_column(sa.String(16), nullable=False)  # domain | ip | url
    subject: Mapped[str] = mapped_column(sa.String(255), nullable=False)
    source: Mapped[str] = mapped_column(sa.String(32), nullable=False)  # virustotal | rdap | …
    relation: Mapped[str] = mapped_column(sa.String(32), nullable=False, default="report")
    payload: Mapped[dict[str, Any] | list[Any] | None] = mapped_column(JSONB, nullable=True)
    status: Mapped[str] = mapped_column(sa.String(16), nullable=False, default="ok")
    error: Mapped[str | None] = mapped_column(sa.Text, nullable=True)
    fetched_at: Mapped[datetime] = mapped_column(TZDateTime, nullable=False, default=utcnow)
    expires_at: Mapped[datetime | None] = mapped_column(TZDateTime, nullable=True)
