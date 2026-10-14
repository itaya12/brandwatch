"""Jobs, stages and the durable SSE event feed (spec §14, §21).

``scan_events`` carries ``seq`` (monotonic per job, UNIQUE with job_id) so a client can replay
from ``Last-Event-ID`` after a reconnect; ``level``, ``counts`` and ``elapsed_ms`` complete the
§14 ``ScanEvent`` schema.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from decimal import Decimal
from typing import Any

import sqlalchemy as sa
from sqlalchemy.orm import Mapped, mapped_column, relationship

from brandwatch.db.base import Base
from brandwatch.db.enums import JobState
from brandwatch.db.types import JSONB, Money, TZDateTime, created_at, enum_type, fk, utcnow, uuid_pk


class ScanJob(Base):
    __tablename__ = "scan_jobs"
    __table_args__ = (sa.Index("ix_scan_jobs_workspace_id_state", "workspace_id", "state"),)

    id: Mapped[uuid.UUID] = uuid_pk()
    workspace_id: Mapped[uuid.UUID] = fk("workspaces.id")
    brand_id: Mapped[uuid.UUID | None] = fk("brands.id", nullable=True)
    kind: Mapped[str] = mapped_column(sa.String(64), nullable=False)
    state: Mapped[JobState] = mapped_column(
        enum_type(JobState), nullable=False, default=JobState.QUEUED
    )
    payload: Mapped[dict[str, Any] | None] = mapped_column(JSONB, nullable=True)
    error: Mapped[str | None] = mapped_column(sa.Text, nullable=True)
    cost_usd: Mapped[Decimal] = mapped_column(Money, nullable=False, default=Decimal("0"))
    created_at: Mapped[datetime] = created_at()
    started_at: Mapped[datetime | None] = mapped_column(TZDateTime, nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(TZDateTime, nullable=True)

    stages: Mapped[list[ScanStage]] = relationship(back_populates="job")
    events: Mapped[list[ScanEventRecord]] = relationship(
        back_populates="job", order_by="ScanEventRecord.seq"
    )


class ScanStage(Base):
    __tablename__ = "scan_stages"

    id: Mapped[uuid.UUID] = uuid_pk()
    job_id: Mapped[uuid.UUID] = fk("scan_jobs.id", index=True)
    name: Mapped[str] = mapped_column(sa.String(64), nullable=False)
    state: Mapped[JobState] = mapped_column(
        enum_type(JobState), nullable=False, default=JobState.QUEUED
    )
    hits: Mapped[int] = mapped_column(sa.Integer, nullable=False, default=0)
    api_calls: Mapped[int] = mapped_column(sa.Integer, nullable=False, default=0)
    cost_usd: Mapped[Decimal] = mapped_column(Money, nullable=False, default=Decimal("0"))
    elapsed_ms: Mapped[int] = mapped_column(sa.Integer, nullable=False, default=0)
    started_at: Mapped[datetime | None] = mapped_column(TZDateTime, nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(TZDateTime, nullable=True)

    job: Mapped[ScanJob] = relationship(back_populates="stages")


class ScanEventRecord(Base):
    """Persisted ScanEvent (the SSE feed). The wire model lives in ``brandwatch.events``."""

    __tablename__ = "scan_events"
    __table_args__ = (
        sa.UniqueConstraint("job_id", "seq", name="uq_scan_events_job_id_seq"),
        sa.Index("ix_scan_events_job_id_at", "job_id", "at"),
    )

    id: Mapped[uuid.UUID] = uuid_pk()
    job_id: Mapped[uuid.UUID] = fk("scan_jobs.id")
    seq: Mapped[int] = mapped_column(sa.Integer, nullable=False)
    stage: Mapped[str] = mapped_column(sa.String(64), nullable=False)
    step: Mapped[str] = mapped_column(sa.String(64), nullable=False)
    status: Mapped[str] = mapped_column(sa.String(16), nullable=False)
    level: Mapped[str] = mapped_column(sa.String(8), nullable=False, default="info")
    message: Mapped[str] = mapped_column(sa.Text, nullable=False)
    progress: Mapped[dict[str, Any] | None] = mapped_column(JSONB, nullable=True)
    counts: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)
    elapsed_ms: Mapped[int] = mapped_column(sa.Integer, nullable=False, default=0)
    data: Mapped[dict[str, Any] | None] = mapped_column(JSONB, nullable=True)
    at: Mapped[datetime] = mapped_column(TZDateTime, nullable=False, default=utcnow)

    job: Mapped[ScanJob] = relationship(back_populates="events")
