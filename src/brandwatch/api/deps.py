"""FastAPI dependencies: settings and a per-request DB session."""

from __future__ import annotations

import inspect
from collections.abc import Iterator

from fastapi import Request
from sqlalchemy.orm import Session

from brandwatch.config.settings import Settings
from brandwatch.db.base import immediate_writes


def get_settings_dep(request: Request) -> Settings:
    return request.app.state.settings


def get_session(request: Request) -> Iterator[Session]:
    """Commit on success, roll back on exception, always close (sync; runs in the threadpool).

    Always declare it as ``Depends(get_session, scope="function")``: FastAPI's default "request"
    scope runs the code after ``yield`` only once the response is sent, so a client would get its
    2xx before the commit (a GET right after a DELETE still saw the row, and a failed commit was
    invisible). tests/test_flow.py walks every route to keep it that way."""
    session: Session = request.app.state.session_factory()
    endpoint = getattr(request.scope.get("route"), "endpoint", None)
    if request.method not in ("GET", "HEAD", "OPTIONS") and not inspect.iscoroutinefunction(
        endpoint
    ):
        # sync write handlers take the write lock up front (wait for a job, never "locked");
        # async handlers await slow network calls first, so they must not hold it meanwhile
        with immediate_writes():
            session.connection()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()
