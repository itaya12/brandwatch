"""A site that a flagged look-alike redirects to is itself a candidate: ``redirect`` as a discovery source.

* ``discovery_source`` += ``redirect``. PostgreSQL: ``ALTER TYPE``. SQLite keeps enums as a CHECK
  constraint, so ``candidate_sources`` and ``observations`` are rebuilt (as in 009) and the append-only
  triggers of ``observations`` are recreated.

Revision ID: 013
Revises: 012
Create Date: 2026-10-13
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "013"
down_revision: str | None = "012"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

SOURCES_BEFORE = ["dnstwist", "combosquat", "llm", "ct", "nrd", "serpapi", "urlscan", "urlhaus", "phishtank", "logo_search", "manual", "meta_ads", "social"]  # fmt: skip
SOURCES_AFTER = [*SOURCES_BEFORE, "redirect"]
SOURCE_TABLES = ("candidate_sources", "observations")
TRIGGERS = ("UPDATE", "DELETE")


def _check_sql(values: list[str]) -> str:
    return "source IN (" + ", ".join(f"'{v}'" for v in values) + ")"


def _drop_triggers() -> None:
    for verb in TRIGGERS:
        op.execute(f"DROP TRIGGER IF EXISTS trg_observations_no_{verb.lower()}")


def _create_triggers() -> None:
    for verb in TRIGGERS:  # same SQL as 001_initial_schema
        op.execute(
            f"CREATE TRIGGER trg_observations_no_{verb.lower()} BEFORE {verb} ON observations "
            f"BEGIN SELECT RAISE(ABORT, 'immutable table observations: {verb} not allowed'); END"
        )


def _sqlite_set_sources(values: list[str]) -> None:
    _drop_triggers()  # the rebuild below drops them anyway; recreated at the end
    for table in SOURCE_TABLES:
        with op.batch_alter_table(table, recreate="always") as batch:
            batch.drop_constraint("discovery_source", type_="check")
            batch.create_check_constraint("discovery_source", sa.text(_check_sql(values)))
    _create_triggers()


def upgrade() -> None:
    if op.get_bind().dialect.name == "postgresql":
        with op.get_context().autocommit_block():
            op.execute("ALTER TYPE discovery_source ADD VALUE IF NOT EXISTS 'redirect'")
    else:
        _sqlite_set_sources(SOURCES_AFTER)


def downgrade() -> None:
    # PostgreSQL cannot drop a value from an enum type; the unused 'redirect' label stays.
    if op.get_bind().dialect.name == "postgresql":
        return
    # rows that would break the old CHECK: the redirect source becomes "manual" (the site stays)
    _drop_triggers()
    op.execute("DELETE FROM candidate_sources WHERE source = 'redirect'")
    op.execute("UPDATE observations SET source = 'manual' WHERE source = 'redirect'")
    _sqlite_set_sources(SOURCES_BEFORE)
