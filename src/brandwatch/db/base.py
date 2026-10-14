"""Engine / session factory and the declarative base.

Sync SQLAlchemy 2.0 for Phase 0 (Alembic-native, trivial on SQLite). Providers are async;
FastAPI endpoints that touch the DB are plain ``def`` and run in the threadpool.
"""

from __future__ import annotations

import threading
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from contextvars import ContextVar

import sqlalchemy as sa
from sqlalchemy import event
from sqlalchemy.engine import Engine
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker
from sqlalchemy.pool import StaticPool

# Stable, predictable constraint names so Alembic migrations and tests can refer to them.
NAMING_CONVENTION = {
    "ix": "ix_%(table_name)s_%(column_0_N_name)s",
    "uq": "uq_%(table_name)s_%(column_0_N_name)s",
    "ck": "ck_%(table_name)s_%(constraint_name)s",
    "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
    "pk": "pk_%(table_name)s",
}


class Base(DeclarativeBase):
    metadata = sa.MetaData(naming_convention=NAMING_CONVENTION)


def is_sqlite(url: str | sa.URL) -> bool:
    return sa.make_url(url).get_backend_name() == "sqlite"


def make_engine(url: str | sa.URL, *, echo: bool = False) -> Engine:
    """Create an engine. SQLite gets foreign-key enforcement turned on per connection."""
    kwargs: dict = {"echo": echo, "future": True}
    if is_sqlite(url):
        kwargs["connect_args"] = {"check_same_thread": False}
        if str(url).endswith(":memory:") or sa.make_url(url).database in (None, "", ":memory:"):
            kwargs["poolclass"] = StaticPool
    engine = sa.create_engine(url, **kwargs)
    in_memory = kwargs.get("poolclass") is StaticPool
    if is_sqlite(url):

        @event.listens_for(engine, "connect")
        def _sqlite_pragmas(dbapi_connection, _record) -> None:  # pragma: no cover - trivial
            cursor = dbapi_connection.cursor()
            cursor.execute("PRAGMA foreign_keys=ON")
            cursor.execute("PRAGMA busy_timeout=30000")
            if not in_memory:
                # WAL: readers never block the job thread's writes (and vice versa).
                cursor.execute("PRAGMA journal_mode=WAL")
            cursor.close()
            # pysqlite's own transaction handling is disabled (SQLAlchemy recipe "Serializable
            # isolation / Savepoints / Transactional DDL") so that SAVEPOINT works and so that
            # *we* choose BEGIN vs BEGIN IMMEDIATE (see ``immediate_writes``).
            dbapi_connection.isolation_level = None

        @event.listens_for(engine, "begin")
        def _begin(conn) -> None:  # pragma: no cover - trivial
            conn.exec_driver_sql(
                "BEGIN IMMEDIATE" if getattr(_immediate, "flag", False) else "BEGIN"
            )

    return engine


_immediate = threading.local()


def writer_thread() -> None:
    """Mark the current thread (a job worker) as a writer: every transaction it begins takes the
    write lock up front, so it never hits "database is locked" after a request committed."""
    _immediate.flag = True


@contextmanager
def immediate_writes() -> Iterator[None]:
    """Transactions begun inside this block take SQLite's write lock up front (``BEGIN
    IMMEDIATE``). A request that reads first and writes later cannot upgrade its lock while a
    job thread is writing — SQLite answers "database is locked" at once instead of waiting
    ``busy_timeout``. Beginning immediately makes the request *wait* for the job's next
    checkpoint instead of failing."""
    _immediate.flag = True
    try:
        yield
    finally:
        _immediate.flag = False


def take_write_lock(session: Session) -> None:
    """For an ``async`` handler that writes. ``get_session`` pre-locks only sync handlers (an async one awaits its
    form or the network first and must not hold the lock meanwhile), so by the time it writes, the user lookup has
    begun a read transaction that cannot be upgraded while a scan is writing — SQLite answers "database is locked"
    at once. Call this after the awaiting is done and before the first write: it ends that read transaction and
    begins an immediate one, so the request waits for the scan's next checkpoint instead of failing."""
    if session.in_nested_transaction():
        return
    session.commit()  # nothing is pending; expire_on_commit is off, so the loaded user stays usable
    with immediate_writes():
        session.connection()


_checkpoint: ContextVar[Callable[[], None] | None] = ContextVar(
    "brandwatch_checkpoint", default=None
)


def set_checkpoint(session: Session | None) -> None:
    """Register the scan's session: every provider call first commits what is pending, so the
    SQLite write lock is never held across a 20-second browser fetch (other users could not
    log in, stop the scan or save anything meanwhile)."""

    def commit() -> None:
        if (
            session is not None
            and not session.in_nested_transaction()
            and (session.new or session.dirty or session.deleted or session.in_transaction())
        ):
            session.commit()

    _checkpoint.set(commit if session is not None else None)


def checkpoint() -> None:
    cb = _checkpoint.get()
    if cb is not None:
        cb()


def make_session_factory(engine: Engine) -> sessionmaker[Session]:
    return sessionmaker(bind=engine, expire_on_commit=False, autoflush=False)


@contextmanager
def session_scope(factory: sessionmaker[Session]) -> Iterator[Session]:
    """Commit on success, roll back on error, always close."""
    session = factory()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()
