"""Arq worker (Redis-backed job pool), Phase 3.

    arq brandwatch.jobs.arq_worker.WorkerSettings

Every queued job is ``run_job(ctx, job_id, kind)``: open a DB session, dispatch to the registered
handler (the same handlers the in-process queues use), commit, or mark the job failed. The
``scan_jobs`` row is created by ``ArqJobQueue.enqueue`` *before* the Arq job is queued, so the
job model is identical whichever backend executes it.
"""

from __future__ import annotations

import logging
import traceback
import uuid
from typing import Any

from brandwatch.config.settings import get_settings
from brandwatch.db.base import make_engine, make_session_factory
from brandwatch.detection.runner import handlers_for
from brandwatch.evidence.store import LocalEvidenceStore
from brandwatch.jobs.queue import mark_failed
from brandwatch.jobs.worker import DEFAULT_HANDLERS

log = logging.getLogger("brandwatch.arq")


def _redis_settings():
    from arq.connections import RedisSettings

    settings = get_settings()
    if not settings.redis_url:
        raise RuntimeError("REDIS_URL is required for the Arq worker")
    return RedisSettings.from_dsn(settings.redis_url)


async def startup(ctx: dict[str, Any]) -> None:
    settings = get_settings()
    engine = make_engine(settings.database_url)
    ctx["engine"] = engine
    ctx["session_factory"] = make_session_factory(engine)
    ctx["handlers"] = {
        **DEFAULT_HANDLERS,
        **handlers_for(settings, LocalEvidenceStore(settings.evidence_dir)),
    }
    log.info("arq worker ready: %s", sorted(ctx["handlers"]))


async def shutdown(ctx: dict[str, Any]) -> None:
    ctx["engine"].dispose()


async def run_job(ctx: dict[str, Any], job_id: str, kind: str) -> str:
    """Executed on the worker; handlers are sync, so run them in a thread."""
    import asyncio

    jid = uuid.UUID(job_id)
    handler = ctx["handlers"].get(kind)
    session = ctx["session_factory"]()
    try:
        if handler is None:
            raise KeyError(f"no handler for job kind '{kind}'")
        await asyncio.to_thread(handler, session, jid)
        session.commit()
        return "done"
    except Exception as exc:  # noqa: BLE001
        session.rollback()
        mark_failed(session, jid, f"{type(exc).__name__}: {exc}\n{traceback.format_exc()}")
        session.commit()
        return "failed"
    finally:
        session.close()


class WorkerSettings:
    functions = [run_job]
    on_startup = startup
    on_shutdown = shutdown
    max_jobs = 4
    job_timeout = 60 * 30
    redis_settings = property(lambda self: _redis_settings())

    @staticmethod
    def redis_settings_factory():
        return _redis_settings()


# arq reads a class attribute, not a property; resolve lazily so importing this module never
# requires Redis.
try:  # pragma: no cover - evaluated only when REDIS_URL is configured
    WorkerSettings.redis_settings = _redis_settings()  # type: ignore[assignment]
except Exception:  # noqa: BLE001
    pass
