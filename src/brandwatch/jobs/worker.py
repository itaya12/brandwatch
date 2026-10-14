"""No-op worker: proves the job model end to end (queued → running → done, with a stage and a
replayable event stream). Real pipeline handlers register alongside it in Phase 1."""

from __future__ import annotations

import time
import uuid
from decimal import Decimal
from typing import Any

from sqlalchemy.orm import Session

from brandwatch.db.enums import JobState
from brandwatch.db.models import ScanJob, ScanStage
from brandwatch.db.types import utcnow
from brandwatch.events.emitter import ScanEventEmitter


def summary_payload(job: ScanJob, stages: list[ScanStage], *, criticals: int = 0) -> dict[str, Any]:
    """The final event's ``data``: what the Live Console's summary card renders (spec §14)."""
    started = job.started_at or job.created_at
    finished = job.finished_at or utcnow()
    return {
        "duration_ms": int((finished - started).total_seconds() * 1000),
        "hits": sum(s.hits for s in stages),
        "criticals": criticals,
        "api_calls": sum(s.api_calls for s in stages),
        "cost_usd": float(sum((s.cost_usd for s in stages), Decimal("0"))),
        "next_run": None,
        "stages": [
            {"name": s.name, "state": s.state.value, "elapsed_ms": s.elapsed_ms} for s in stages
        ],
    }


def run_noop_job(session: Session, job_id: uuid.UUID) -> None:
    job = session.get(ScanJob, job_id)
    if job is None:
        raise LookupError(f"scan_job {job_id} not found")

    job.state = JobState.RUNNING
    job.started_at = utcnow()
    session.flush()

    emitter = ScanEventEmitter(session, job_id)
    stage = ScanStage(job_id=job_id, name="noop", state=JobState.RUNNING, started_at=utcnow())
    session.add(stage)
    session.flush()

    t0 = time.monotonic()
    emitter.running("noop", "start", "No-op worker started (Phase 0 job model check)")
    emitter.running(
        "noop", "work", "Doing nothing, deliberately", progress={"current": 1, "total": 1}
    )

    stage.state = JobState.DONE
    stage.finished_at = utcnow()
    stage.elapsed_ms = int((time.monotonic() - t0) * 1000)
    job.state = JobState.DONE
    job.finished_at = utcnow()
    job.cost_usd = Decimal("0")
    session.flush()

    emitter.done(
        "noop",
        "finish",
        "No-op worker finished",
        counts={"hits": 0, "api_calls": 0, "cost_usd": 0.0},
        data=summary_payload(job, [stage]),
    )


DEFAULT_HANDLERS = {"noop": run_noop_job}
