"""Job queue abstraction (spec §1, §16).

Phase 0 ships ``InMemoryJobQueue`` (runs the handler inline — enough for the vertical slice and
for tests) and an ``ArqJobQueue`` placeholder that validates its dependency and names the phase
in which the Redis-backed worker pool arrives. Both create the durable ``scan_jobs`` row first,
so the job model (jobs → stages → events) is identical whichever backend runs it.
"""

from __future__ import annotations

import threading
import traceback
import uuid
from collections.abc import Callable
from typing import Any, Protocol

from sqlalchemy.orm import Session, sessionmaker

from brandwatch.db.enums import JobState
from brandwatch.db.models import ScanJob
from brandwatch.db.types import utcnow

JobHandler = Callable[[Session, uuid.UUID], None]


class JobQueue(Protocol):
    def enqueue(
        self,
        kind: str,
        payload: dict[str, Any] | None = None,
        *,
        workspace_id: uuid.UUID,
        brand_id: uuid.UUID | None = None,
    ) -> uuid.UUID: ...


def create_job(
    session: Session,
    kind: str,
    payload: dict[str, Any] | None,
    *,
    workspace_id: uuid.UUID,
    brand_id: uuid.UUID | None,
) -> ScanJob:
    job = ScanJob(
        workspace_id=workspace_id,
        brand_id=brand_id,
        kind=kind,
        payload=payload,
        state=JobState.QUEUED,
    )
    session.add(job)
    session.flush()
    return job


def mark_failed(session: Session, job_id: uuid.UUID, error: str) -> None:
    job = session.get(ScanJob, job_id)
    if job is not None:
        job.state = JobState.FAILED
        job.error = error[:4000]
        job.finished_at = utcnow()
        session.flush()


class InMemoryJobQueue:
    """Runs handlers synchronously in the caller's process.

    Pass either a ``session_factory`` (each job gets its own session + commit) or an explicit
    ``session`` (tests: everything stays inside the test transaction).
    """

    def __init__(
        self,
        *,
        session_factory: sessionmaker[Session] | None = None,
        session: Session | None = None,
        handlers: dict[str, JobHandler] | None = None,
    ) -> None:
        if (session_factory is None) == (session is None):
            raise ValueError("provide exactly one of session_factory or session")
        self._factory = session_factory
        self._session = session
        self.handlers: dict[str, JobHandler] = dict(handlers or {})

    def register(self, kind: str, handler: JobHandler) -> None:
        self.handlers[kind] = handler

    def _run(self, fn: Callable[[Session], Any]) -> Any:
        if self._session is not None:
            result = fn(self._session)
            self._session.commit()
            return result
        assert self._factory is not None
        session = self._factory()
        try:
            result = fn(session)
            session.commit()
            return result
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()

    def enqueue(
        self,
        kind: str,
        payload: dict[str, Any] | None = None,
        *,
        workspace_id: uuid.UUID,
        brand_id: uuid.UUID | None = None,
    ) -> uuid.UUID:
        handler = self.handlers.get(kind)
        if handler is None:
            raise KeyError(f"no handler registered for job kind '{kind}'")

        job_id: uuid.UUID = self._run(
            lambda s: create_job(s, kind, payload, workspace_id=workspace_id, brand_id=brand_id).id
        )

        def execute(s: Session) -> None:
            try:
                handler(s, job_id)
            except Exception as exc:  # noqa: BLE001 - a failing job must be recorded, not crash
                s.rollback() if self._session is None else None
                mark_failed(s, job_id, f"{type(exc).__name__}: {exc}\n{traceback.format_exc()}")

        self._run(execute)
        return job_id


class ArqJobQueue:
    """Redis-backed worker pool via Arq (Phase 3). ``arq brandwatch.jobs.arq_worker.WorkerSettings``
    runs the jobs; this side only creates the durable ``scan_jobs`` row and queues ``run_job``."""

    def __init__(
        self, redis_url: str | None, session_factory: sessionmaker[Session] | None = None
    ) -> None:
        if not redis_url:
            raise RuntimeError("ArqJobQueue needs REDIS_URL (e.g. redis://localhost:6379/0)")
        try:
            import arq  # noqa: F401
        except ImportError as exc:  # pragma: no cover - arq is a declared dependency
            raise RuntimeError("the 'arq' package is required for ArqJobQueue") from exc
        self.redis_url = redis_url
        self._factory = session_factory

    def enqueue(
        self,
        kind: str,
        payload: dict[str, Any] | None = None,
        *,
        workspace_id: uuid.UUID,
        brand_id: uuid.UUID | None = None,
    ) -> uuid.UUID:
        import asyncio

        if self._factory is None:
            raise RuntimeError("ArqJobQueue needs a session_factory to create the scan_jobs row")
        session = self._factory()
        try:
            job_id = create_job(
                session, kind, payload, workspace_id=workspace_id, brand_id=brand_id
            ).id
            session.commit()
        finally:
            session.close()

        async def _push() -> None:
            from arq import create_pool
            from arq.connections import RedisSettings

            pool = await create_pool(RedisSettings.from_dsn(self.redis_url))
            try:
                await pool.enqueue_job("run_job", str(job_id), kind, _job_id=f"bw:{job_id}")
            finally:
                await pool.aclose()

        try:
            asyncio.get_running_loop()
        except RuntimeError:
            asyncio.run(_push())
        else:  # called from inside an event loop (async endpoint): push from a worker thread
            t = threading.Thread(target=lambda: asyncio.run(_push()), daemon=True)
            t.start()
            t.join(timeout=10)
        return job_id


class ThreadedJobQueue:
    """In-process queue that runs each job on a daemon thread with its own DB session.

    The API uses it so a scan request returns immediately and the UI can follow the event feed.
    Still single-process (Phase 1); the Arq/Redis pool replaces it in Phase 3 behind the same
    ``JobQueue`` protocol.
    """

    def __init__(
        self, session_factory: sessionmaker[Session], handlers: dict[str, JobHandler] | None = None
    ) -> None:
        self._factory = session_factory
        self.handlers: dict[str, JobHandler] = dict(handlers or {})
        self.threads: dict[uuid.UUID, threading.Thread] = {}

    def register(self, kind: str, handler: JobHandler) -> None:
        self.handlers[kind] = handler

    def _execute(self, job_id: uuid.UUID, handler: JobHandler) -> None:
        from brandwatch.db.base import writer_thread

        writer_thread()  # job threads are writers: BEGIN IMMEDIATE, wait instead of "locked"
        session = self._factory()
        try:
            handler(session, job_id)
            session.commit()
        except Exception as exc:  # noqa: BLE001 - record, never crash the thread silently
            session.rollback()
            mark_failed(session, job_id, f"{type(exc).__name__}: {exc}\n{traceback.format_exc()}")
            session.commit()
        finally:
            session.close()
            self.threads.pop(job_id, None)

    def enqueue(
        self,
        kind: str,
        payload: dict[str, Any] | None = None,
        *,
        workspace_id: uuid.UUID,
        brand_id: uuid.UUID | None = None,
    ) -> uuid.UUID:
        handler = self.handlers.get(kind)
        if handler is None:
            raise KeyError(f"no handler registered for job kind '{kind}'")
        session = self._factory()
        try:
            job_id = create_job(
                session, kind, payload, workspace_id=workspace_id, brand_id=brand_id
            ).id
            session.commit()
        finally:
            session.close()
        t = threading.Thread(
            target=self._execute, args=(job_id, handler), daemon=True, name=f"job-{job_id}"
        )
        self.threads[job_id] = t
        t.start()
        return job_id

    def wait(self, job_id: uuid.UUID, timeout: float | None = None) -> None:
        t = self.threads.get(job_id)
        if t is not None:
            t.join(timeout)

    def join_all(self, timeout: float = 30.0) -> int:
        """Wait (bounded) for every in-flight job thread; returns how many were still running."""
        import time

        deadline = time.monotonic() + timeout
        for t in list(self.threads.values()):
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            t.join(remaining)
        return sum(1 for t in list(self.threads.values()) if t.is_alive())
