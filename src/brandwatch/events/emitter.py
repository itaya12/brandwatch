"""ScanEvent (wire model, spec §14) and the emitter that persists it to ``scan_events``.

Guarantees (spec §14 "Transport & guarantees"):
* ordered   — ``seq`` is monotonic per job and UNIQUE with ``job_id`` in the DB;
* durable   — every event is a row before it is published; a reconnecting client replays
              with ``?from_seq=N`` (SSE endpoint arrives in Phase 3);
* no secrets — configured secret values are redacted from message and data.
The ``publish`` hook is a no-op in Phase 0; Phase 3 plugs Redis pub/sub in.
"""

from __future__ import annotations

import time
import uuid
from collections.abc import Callable
from datetime import datetime
from typing import Any, Literal

import sqlalchemy as sa
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy.orm import Session

from brandwatch.db.models import ScanEventRecord
from brandwatch.db.types import utcnow

EventStatus = Literal["running", "done", "error", "skipped", "pending"]
EventLevel = Literal["info", "warn", "error"]


class ScanEvent(BaseModel):
    model_config = ConfigDict(frozen=True)

    job_id: uuid.UUID
    seq: int
    ts: datetime
    stage: str
    step: str
    status: EventStatus
    level: EventLevel = "info"
    message: str
    progress: dict[str, Any] | None = None  # {"current": 3, "total": 10}
    counts: dict[str, Any] = Field(default_factory=dict)  # {"hits": 12, "cost_usd": 0.02}
    elapsed_ms: int = 0
    data: dict[str, Any] | None = None  # {"finding_id": ..., "severity": ...}


def _redact(value: Any, secrets: list[str]) -> Any:
    if not secrets:
        return value
    if isinstance(value, str):
        for s in secrets:
            value = value.replace(s, "***")
        return value
    if isinstance(value, dict):
        return {k: _redact(v, secrets) for k, v in value.items()}
    if isinstance(value, list):
        return [_redact(v, secrets) for v in value]
    return value


class ScanEventEmitter:
    def __init__(
        self,
        session: Session,
        job_id: uuid.UUID,
        *,
        publish: Callable[[ScanEvent], None] | None = None,
        secrets: list[str] | None = None,
        clock: Callable[[], float] = time.monotonic,
        commit: bool = False,
    ) -> None:
        self.session = session
        # commit=True makes every event visible to the UI the moment it happens (long live scans);
        # never inside a savepoint, where a commit would end the caller's nested transaction.
        self._commit = commit
        self.job_id = job_id
        self._publish = publish
        self._secrets = sorted({s for s in (secrets or []) if s}, key=len, reverse=True)
        self._clock = clock
        self._started = clock()
        last = session.execute(
            sa.select(sa.func.max(ScanEventRecord.seq)).where(ScanEventRecord.job_id == job_id)
        ).scalar()
        self._seq = int(last or 0)

    @property
    def elapsed_ms(self) -> int:
        return int((self._clock() - self._started) * 1000)

    def emit(
        self,
        stage: str,
        step: str,
        status: EventStatus,
        message: str,
        *,
        level: EventLevel = "info",
        progress: dict[str, Any] | None = None,
        counts: dict[str, Any] | None = None,
        data: dict[str, Any] | None = None,
    ) -> ScanEvent:
        self._seq += 1
        event = ScanEvent(
            job_id=self.job_id,
            seq=self._seq,
            ts=utcnow(),
            stage=stage,
            step=step,
            status=status,
            level=level,
            message=_redact(message, self._secrets),
            progress=progress,
            counts=_redact(dict(counts or {}), self._secrets),
            elapsed_ms=self.elapsed_ms,
            data=_redact(data, self._secrets),
        )
        self.session.add(
            ScanEventRecord(
                job_id=event.job_id,
                seq=event.seq,
                stage=event.stage,
                step=event.step,
                status=event.status,
                level=event.level,
                message=event.message,
                progress=event.progress,
                counts=event.counts,
                elapsed_ms=event.elapsed_ms,
                data=event.data,
                at=event.ts,
            )
        )
        self.session.flush()
        if self._commit and not self.session.in_nested_transaction():
            self.session.commit()
        if self._publish is not None:
            self._publish(event)
        return event

    # convenience wrappers --------------------------------------------------------------------
    def running(self, stage: str, step: str, message: str, **kw: Any) -> ScanEvent:
        return self.emit(stage, step, "running", message, **kw)

    def done(self, stage: str, step: str, message: str, **kw: Any) -> ScanEvent:
        return self.emit(stage, step, "done", message, **kw)

    def skipped(self, stage: str, step: str, message: str, **kw: Any) -> ScanEvent:
        return self.emit(stage, step, "skipped", message, level="warn", **kw)

    def error(self, stage: str, step: str, message: str, **kw: Any) -> ScanEvent:
        return self.emit(stage, step, "error", message, level="error", **kw)


def replay(session: Session, job_id: uuid.UUID, from_seq: int = 0) -> list[ScanEvent]:
    """Events for a job with ``seq > from_seq`` (the SSE reconnect path)."""
    rows = session.scalars(
        sa.select(ScanEventRecord)
        .where(ScanEventRecord.job_id == job_id, ScanEventRecord.seq > from_seq)
        .order_by(ScanEventRecord.seq)
    ).all()
    return [
        ScanEvent(
            job_id=r.job_id,
            seq=r.seq,
            ts=r.at,
            stage=r.stage,
            step=r.step,
            status=r.status,  # type: ignore[arg-type]
            level=r.level,  # type: ignore[arg-type]
            message=r.message,
            progress=r.progress,
            counts=r.counts or {},
            elapsed_ms=r.elapsed_ms,
            data=r.data,
        )
        for r in rows
    ]
