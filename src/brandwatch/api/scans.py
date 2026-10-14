"""Scan jobs API (spec §14 Operations Center, Phase 1 subset): job list/detail and the durable
event feed. The UI polls ``/events?from_seq=N``; the SSE transport arrives in Phase 3 over the
same replay function."""

from __future__ import annotations

import asyncio
import json
import uuid
from typing import Annotated, Any

import sqlalchemy as sa
from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from fastapi.responses import PlainTextResponse, StreamingResponse
from sqlalchemy.orm import Session

from brandwatch.api.auth import audit, current_user, require_analyst
from brandwatch.api.deps import get_session
from brandwatch.db.enums import JobState
from brandwatch.db.models import Brand, ScanJob, ScanStage, User
from brandwatch.detection import regions as regions_mod
from brandwatch.events.emitter import replay

router = APIRouter(prefix="/api/jobs", tags=["jobs"])


def job_out(session: Session, job: ScanJob) -> dict[str, Any]:
    brand = session.get(Brand, job.brand_id) if job.brand_id else None
    return {
        "id": str(job.id),
        "kind": job.kind,
        "state": job.state.value,
        "brand_id": str(job.brand_id) if job.brand_id else None,
        "brand_name": brand.name if brand else None,
        "cost_usd": float(job.cost_usd or 0),
        "error": job.error,
        "campaign_id": (job.payload or {}).get("campaign_id"),
        "finding_id": (job.payload or {}).get("finding_id"),
        "created_at": job.created_at.isoformat(),
        "started_at": job.started_at.isoformat() if job.started_at else None,
        "finished_at": job.finished_at.isoformat() if job.finished_at else None,
    }


def _get_job(session: Session, user: User, job_id: uuid.UUID) -> ScanJob:
    job = session.get(ScanJob, job_id)
    if job is None or job.workspace_id != user.workspace_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "job not found")
    return job


@router.get("")
def list_jobs(
    session: Annotated[Session, Depends(get_session, scope="function")],
    user: Annotated[User, Depends(current_user)],
    brand_id: uuid.UUID | None = None,
    limit: int = Query(default=50, ge=1, le=500),
) -> list[dict[str, Any]]:
    q = sa.select(ScanJob).where(ScanJob.workspace_id == user.workspace_id)
    if brand_id:
        q = q.where(ScanJob.brand_id.in_(regions_mod.with_regions(session, brand_id)))
    jobs = session.scalars(q.order_by(ScanJob.created_at.desc()).limit(limit)).all()
    return [job_out(session, j) for j in jobs]


@router.get("/{job_id}")
def get_job(
    job_id: uuid.UUID,
    session: Annotated[Session, Depends(get_session, scope="function")],
    user: Annotated[User, Depends(current_user)],
) -> dict[str, Any]:
    job = _get_job(session, user, job_id)
    stages = session.scalars(
        sa.select(ScanStage).where(ScanStage.job_id == job.id).order_by(ScanStage.started_at)
    ).all()
    out = job_out(session, job)
    out["stages"] = [
        {
            "name": s.name,
            "state": s.state.value,
            "hits": s.hits,
            "api_calls": s.api_calls,
            "cost_usd": float(s.cost_usd or 0),
            "elapsed_ms": s.elapsed_ms,
        }
        for s in stages
    ]
    return out


@router.get("/{job_id}/trace", response_class=PlainTextResponse)
def get_trace(
    job_id: uuid.UUID,
    request: Request,
    session: Annotated[Session, Depends(get_session, scope="function")],
    user: Annotated[User, Depends(require_analyst)],
    host: str = "",
) -> PlainTextResponse:
    """The full engineering trace of a scan: every provider call (LLM prompts included), every
    generated name and DNS answer, each candidate's evidence, signals and scoring arithmetic.
    ``?host=`` returns only that candidate's section (its evidence and scoring maths)."""
    job = _get_job(session, user, job_id)
    from brandwatch import trace as trace_mod

    path = trace_mod.trace_path(request.app.state.settings.evidence_dir, job.id)
    if not path.is_file():
        raise HTTPException(status.HTTP_404_NOT_FOUND, "no trace for this job (older scan?)")
    text = path.read_text(encoding="utf-8")
    if host:
        head = text.split("\n==== ", 1)[0]
        parts = [
            p for p in text.split("\n==== ")[1:] if p.startswith(f"CANDIDATE · {host.lower()} ")
        ]
        text = (
            head + "".join("\n==== " + p for p in parts)
            if parts
            else f"no section for {host} in this scan's trace\n"
        )
    return PlainTextResponse(text, media_type="text/plain; charset=utf-8")


@router.post("/{job_id}/cancel")
def cancel_job(
    job_id: uuid.UUID,
    session: Annotated[Session, Depends(get_session, scope="function")],
    user: Annotated[User, Depends(require_analyst)],
) -> dict[str, Any]:
    """Stop a queued or running scan. The worker notices at its next checkpoint (between
    discovery streams, DNS batches and candidates) and closes the job; collected evidence stays."""
    job = _get_job(session, user, job_id)
    if job.state not in (JobState.QUEUED, JobState.RUNNING):
        raise HTTPException(status.HTTP_409_CONFLICT, f"job is already {job.state.value}")
    job.state = JobState.CANCELLED
    session.flush()
    audit(
        session, workspace_id=user.workspace_id, actor_type="analyst", actor_id=user.id,
        action="scan.cancelled", object_type="scan_job", object_id=job.id,
    )  # fmt: skip
    return {"job_id": str(job.id), "state": job.state.value}


@router.get("/{job_id}/events")
def get_events(
    job_id: uuid.UUID,
    session: Annotated[Session, Depends(get_session, scope="function")],
    user: Annotated[User, Depends(current_user)],
    from_seq: int = Query(default=0, ge=0),
    limit: int = Query(default=500, ge=1, le=5000),
) -> dict[str, Any]:
    job = _get_job(session, user, job_id)
    events = replay(session, job.id, from_seq=from_seq)[:limit]
    return {
        "job_id": str(job.id),
        "state": job.state.value,
        "events": [e.model_dump(mode="json") for e in events],
        "last_seq": events[-1].seq if events else from_seq,
    }


@router.get("/{job_id}/events/stream")
async def stream_events(
    job_id: uuid.UUID,
    request: Request,
    session: Annotated[Session, Depends(get_session, scope="function")],
    user: Annotated[User, Depends(current_user)],
    from_seq: int = Query(default=0, ge=0),
):
    """Server-Sent Events: replays from ``Last-Event-ID`` / ``from_seq`` then follows the job
    until it finishes (durable table polled; Redis pub/sub is an optional accelerator)."""
    job = _get_job(session, user, job_id)
    last_header = request.headers.get("last-event-id")
    seq = int(last_header) if last_header and last_header.isdigit() else from_seq
    factory = request.app.state.session_factory
    jid = job.id

    async def gen():
        nonlocal seq
        idle = 0
        while True:
            with factory() as s:
                events = replay(s, jid, from_seq=seq)
                state = s.get(ScanJob, jid).state.value
            for e in events:
                seq = e.seq
                payload = json.dumps(e.model_dump(mode="json"), default=str)
                yield (
                    f"id: {e.seq}"
                    + chr(10)
                    + "event: scan"
                    + chr(10)
                    + f"data: {payload}"
                    + chr(10)
                    + chr(10)
                )
            if state in ("done", "failed", "cancelled") and not events:
                yield (
                    "event: end"
                    + chr(10)
                    + f"data: {json.dumps({'state': state, 'last_seq': seq})}"
                    + chr(10)
                    + chr(10)
                )
                return
            if await request.is_disconnected():
                return
            idle = 0 if events else idle + 1
            if idle and idle % 20 == 0:
                yield ": keep-alive" + chr(10) + chr(10)
            await asyncio.sleep(0.5)

    return StreamingResponse(
        gen(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )
