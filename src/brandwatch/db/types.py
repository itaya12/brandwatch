"""Dialect-portable column types and column helpers.

PostgreSQL is the production/demo database; SQLite is accepted for local Phase-0/1 development
(spec §1, §16). Every Postgres-specific type gets a SQLite-compatible base so the same models and
the same Alembic migration work on both:

    GUID        -> uuid (PG) / CHAR(32) (SQLite)
    CIText      -> citext (PG) / VARCHAR COLLATE NOCASE (SQLite)
    INET        -> inet (PG) / VARCHAR(45) (SQLite)
    JSONB       -> jsonb (PG) / JSON (SQLite)
    TZDateTime  -> timestamptz (PG) / DATETIME (SQLite; app code always stores UTC-aware values)
"""

from __future__ import annotations

import uuid
from collections.abc import Callable
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql
from sqlalchemy.orm import Mapped, mapped_column

from brandwatch.db.enums import ENUM_TYPE_NAMES

GUID = sa.Uuid(as_uuid=True)
CIText = sa.String(collation="NOCASE").with_variant(postgresql.CITEXT(), "postgresql")
JSONB = sa.JSON().with_variant(postgresql.JSONB(), "postgresql")
TZDateTime = sa.DateTime(timezone=True)
Money = sa.Numeric(10, 4)
Percent = sa.Numeric(5, 2)


class _Inet(sa.types.TypeDecorator):
    """inet on PostgreSQL, VARCHAR(45) on SQLite — and a plain ``str`` in Python on both (psycopg would hand
    back an ``IPv4Address``, and the code compares, lowercases and joins addresses as text)."""

    impl = sa.String(45)
    cache_ok = True

    def load_dialect_impl(self, dialect: sa.Dialect) -> sa.types.TypeEngine[Any]:
        return dialect.type_descriptor(postgresql.INET() if dialect.name == "postgresql" else sa.String(45))

    def process_bind_param(self, value: Any, dialect: sa.Dialect) -> str | None:
        return None if value is None else str(value)

    def process_result_value(self, value: Any, dialect: sa.Dialect) -> str | None:
        return None if value is None else str(value)


INET = _Inet()


def utcnow() -> datetime:
    """Timezone-aware UTC now. The only clock the persistence layer uses."""
    return datetime.now(UTC)


def enum_type(py_enum: type[StrEnum]) -> sa.Enum:
    """A DB enum that persists the enum *values* (``"admin"``), not member names (``"ADMIN"``).

    On PostgreSQL this becomes a native ``CREATE TYPE``; on SQLite a VARCHAR with a CHECK
    constraint. The DB type name comes from :data:`brandwatch.db.enums.ENUM_TYPE_NAMES`.
    """
    return sa.Enum(
        py_enum,
        name=ENUM_TYPE_NAMES[py_enum],
        native_enum=True,
        create_constraint=True,
        values_callable=lambda e: [m.value for m in e],
        validate_strings=True,
    )


def uuid_pk() -> Mapped[uuid.UUID]:
    """UUID primary key with an application-side default (portable across dialects)."""
    return mapped_column(GUID, primary_key=True, default=uuid.uuid4)


def created_at() -> Mapped[datetime]:
    return mapped_column(TZDateTime, nullable=False, default=utcnow, server_default=sa.func.now())


def fk(
    target: str,
    *,
    nullable: bool = False,
    ondelete: str = "RESTRICT",
    index: bool = False,
    unique: bool = False,
    default: Callable[[], Any] | None = None,
) -> Mapped[Any]:
    """Foreign key column. ``ON DELETE RESTRICT`` by default: history never cascade-deletes."""
    return mapped_column(
        GUID,
        sa.ForeignKey(target, ondelete=ondelete),
        nullable=nullable,
        index=index,
        unique=unique,
        default=default,
    )
