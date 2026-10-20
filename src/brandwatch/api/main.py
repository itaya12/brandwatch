"""FastAPI application factory. ``uvicorn brandwatch.api.main:app``."""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from typing import Annotated, Any

import sqlalchemy as sa
from fastapi import Depends, FastAPI
from fastapi.responses import RedirectResponse
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session

from brandwatch import __version__
from brandwatch.api import (
    admin,
    auth,
    brands,
    campaigns,
    candidates,
    dashboard,
    findings,
    intel,
    ml,
    reports,
    scans,
    tokens,
    ui,
    ui_intel,  # noqa: F401  (registers the intel page)
    ui_settings,  # noqa: F401  (registers /ui/settings and the brand editor)
)
from brandwatch.api.deps import get_session, get_settings_dep
from brandwatch.config.settings import Settings, get_settings
from brandwatch.db.base import immediate_writes, make_engine, make_session_factory
from brandwatch.detection.runner import handlers_for
from brandwatch.detection.scheduler import WatchScheduler
from brandwatch.evidence.store import LocalEvidenceStore
from brandwatch.jobs.queue import ArqJobQueue, ThreadedJobQueue
from brandwatch.jobs.worker import DEFAULT_HANDLERS
from brandwatch.notifications import NotificationService
from brandwatch.providers.registry import ProviderRegistry

log = logging.getLogger(__name__)


def create_app(settings: Settings | None = None, engine: Engine | None = None) -> FastAPI:
    resolved_settings = settings or get_settings()
    owns_engine = engine is None

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        eng = engine or make_engine(resolved_settings.database_url)
        factory = make_session_factory(eng)
        app.state.settings = resolved_settings
        app.state.engine = eng
        app.state.session_factory = factory
        app.state.providers = ProviderRegistry(resolved_settings)
        app.state.store = LocalEvidenceStore(resolved_settings.evidence_dir)
        app.state.notifier = NotificationService(resolved_settings)
        handlers = {
            **DEFAULT_HANDLERS,
            **handlers_for(resolved_settings, app.state.store, app.state.notifier),
        }
        if resolved_settings.queue_backend == "arq" and resolved_settings.redis_url:
            app.state.queue = ArqJobQueue(resolved_settings.redis_url, factory)
        else:
            app.state.queue = ThreadedJobQueue(factory, handlers)
        app.state.scheduler = WatchScheduler(
            factory, app.state.queue, resolved_settings, notifier=app.state.notifier
        )
        if resolved_settings.scheduler_enabled:
            app.state.scheduler.start()
        with factory() as session, immediate_writes():
            session.connection()
            auth.bootstrap_admin(session, resolved_settings)
            _fail_interrupted_jobs(session)
        yield
        app.state.scheduler.stop()
        join = getattr(app.state.queue, "join_all", None)
        if join is not None:  # let in-flight jobs finish (bounded) so a restart does not cut them
            import asyncio

            await asyncio.get_running_loop().run_in_executor(
                None, join, resolved_settings.shutdown_job_wait_seconds
            )
        if owns_engine:
            eng.dispose()

    def _fail_interrupted_jobs(session) -> None:  # noqa: ANN001
        """In-process jobs die with the server: mark them failed with a clear reason."""
        import sqlalchemy as sa

        from brandwatch.db.enums import JobState
        from brandwatch.db.models import ScanJob
        from brandwatch.jobs.queue import mark_failed

        stale = session.scalars(
            sa.select(ScanJob).where(ScanJob.state.in_([JobState.QUEUED, JobState.RUNNING]))
        ).all()
        for job in stale:
            mark_failed(
                session, job.id,
                "Interrupted: the server was restarted while this scan was queued or running. "
                "Nothing is lost — evidence already collected is kept. Start the scan again.",
            )  # fmt: skip
        session.commit()

    app = FastAPI(
        title="BrandWatch API",
        version=__version__,
        description=(
            "Phishing-domain intelligence: discover look-alike domains of a brand, visit each one in an "
            "SSRF-guarded sandbox, score it with an explainable model, map the attacker's infrastructure "
            "and draft the takedown — a human decides every step.\n\n"
            "**The UI calls the same service functions as this API**, so RBAC (admin / analyst / viewer) "
            "and the audit trail are identical. Authenticate with `POST /api/auth/login` or a personal "
            "token (`Authorization: Bearer bw_…`). Scans stream their narration as Server-Sent Events "
            "(`/api/jobs/{id}/events/stream`, resumable), can be cancelled, and keep a full engineering "
            "trace. Indicators export as CSV, JSON or STIX 2.1 (`/api/iocs`)."
        ),
        openapi_tags=[
            {"name": "auth", "description": "Sign-in and the current user"},
            {
                "name": "brands",
                "description": "Brands, official domains, detection config, whitelist, scans",
            },
            {
                "name": "scans",
                "description": "Jobs: state, live events (SSE), cancel, engineering trace",
            },
            {"name": "findings", "description": "Findings, verdicts, evidence and the watchlist"},
            {"name": "candidates", "description": "Watched domains: rescan, known-legit dismissal"},
            {
                "name": "campaigns",
                "description": "Attack infrastructure maps and IOC export (STIX 2.1)",
            },
            {"name": "reports", "description": "Evidence packages and takedown requests"},
            {"name": "intel", "description": "Site & network intel (VirusTotal-style lookups)"},
            {"name": "dashboard", "description": "Aggregates for the dashboard"},
            {"name": "ops", "description": "Health and facts about this deployment"},
        ],
        lifespan=lifespan,
    )
    app.include_router(auth.router)
    app.include_router(brands.router)
    app.include_router(scans.router)
    app.include_router(findings.router)
    app.include_router(reports.router)
    app.include_router(candidates.router)
    app.include_router(campaigns.router)
    app.include_router(dashboard.router)
    app.include_router(ml.router)
    app.include_router(admin.router)
    app.include_router(tokens.router)
    app.include_router(intel.router)
    app.include_router(ui.router)

    @app.get("/favicon.ico", include_in_schema=False)
    def _favicon():  # noqa: ANN202 - a browser asks the root for it before reading any page
        from fastapi.responses import RedirectResponse as _R

        return _R("/ui/assets/favicon-32.png", status_code=301)

    from fastapi import HTTPException as _HTTPException
    from fastapi.exception_handlers import (
        http_exception_handler,
        request_validation_exception_handler,
    )
    from fastapi.exceptions import RequestValidationError
    from starlette.exceptions import HTTPException as StarletteHTTPException

    def _is_ui(request) -> bool:  # noqa: ANN001
        return request.url.path.startswith("/ui")

    @app.exception_handler(StarletteHTTPException)
    async def _ui_http_errors(request, exc):  # noqa: ANN001, ANN202
        """/ui/* errors become a page; /api/* keeps the JSON contract."""
        if _is_ui(request) and exc.status_code >= 400:
            detail = (
                exc.detail if isinstance(exc.detail, str) else "The request could not be completed."
            )
            return ui.render_error(request, exc.status_code, detail)
        return await http_exception_handler(request, exc)

    @app.exception_handler(RequestValidationError)
    async def _ui_validation_errors(request, exc):  # noqa: ANN001, ANN202
        if _is_ui(request):
            fields = ", ".join(str(e.get("loc", ["?"])[-1]) for e in exc.errors()[:4])
            return ui.render_error(request, 422, f"Invalid value for: {fields}.")
        return await request_validation_exception_handler(request, exc)

    from sqlalchemy.exc import OperationalError

    @app.exception_handler(OperationalError)
    async def _db_busy(request, exc):  # noqa: ANN001, ANN202
        """SQLite allows one writer: when a scan holds the lock longer than ``busy_timeout``, say so
        plainly and let the analyst press the button again (nothing was saved)."""
        if "database is locked" not in str(exc):
            raise exc
        msg = ("A scan is writing to the database right now, so this was not saved. "
               "Wait a few seconds and press the button again.")  # fmt: skip
        if _is_ui(request):
            return ui.render_error(request, 409, msg)
        from fastapi.responses import JSONResponse

        return JSONResponse({"detail": msg}, status_code=503, headers={"Retry-After": "5"})

    _ = _HTTPException  # FastAPI's HTTPException subclasses Starlette's: one handler covers both

    @app.exception_handler(Exception)
    async def _unexpected(request, exc):  # noqa: ANN001, ANN202
        """Anything else: the traceback goes to the log; a /ui page gets a plain error page with the ways back."""
        import logging

        logging.getLogger("brandwatch").exception("unhandled error on %s", request.url.path)
        if _is_ui(request):
            return ui.render_error(request, 500, "Something went wrong on our side. The error was logged; try again, "
                                                 "and if it keeps happening tell an admin what you were doing.")  # fmt: skip
        from fastapi.responses import JSONResponse

        return JSONResponse({"detail": "internal error"}, status_code=500)

    @app.get("/", include_in_schema=False)
    def root() -> RedirectResponse:
        return RedirectResponse("/ui/dashboard", status_code=303)

    @app.get("/health", tags=["ops"])
    def health(
        session: Annotated[Session, Depends(get_session, scope="function")],
        settings: Annotated[Settings, Depends(get_settings_dep)],
    ) -> dict[str, Any]:
        session.execute(sa.text("SELECT 1"))
        return {
            "status": "ok",
            "version": __version__,
            "db": "ok",
            "demo_mode": settings.demo_mode,
            "environment": settings.environment,
            "providers": app.state.providers.describe(),
            "job_kinds": sorted(getattr(app.state.queue, "handlers", {})) or ["arq"],
            "queue_backend": type(app.state.queue).__name__,
            "scheduler": "running" if app.state.scheduler._thread else "stopped",
            "notify_channels": [n.name for n in app.state.notifier.notifiers],
            "facts": _health_facts(),
        }

    def _health_facts() -> dict[str, Any] | None:
        from brandwatch.about import project_facts

        try:  # descriptive extras: they must never turn the liveness check into a 500
            f = project_facts(app)
        except Exception:  # noqa: BLE001
            log.warning("project facts unavailable", exc_info=True)
            return None
        return {
            k: f.get(k)
            for k in (
                "signals",
                "signal_groups",
                "providers",
                "golden",
                "tests",
                "api_operations",
                "scoring_version",
            )
        }

    return app


app = create_app()
