"""Fake social accounts: a discovery source for Facebook pages and Instagram profiles found under
the brand's name.

* ``discovery_source`` += ``social``. PostgreSQL: ``ALTER TYPE``. SQLite keeps enums as a CHECK
  constraint, so ``candidate_sources`` and ``observations`` are rebuilt (as in 008) and the
  append-only triggers of ``observations`` are recreated.
* A social account is a candidate like a site: its address is the page / profile URL, its surface
  ``content`` and its finding kind ``social`` (``findings.kind`` is a free string since 008).

Revision ID: 009
Revises: 008
Create Date: 2026-10-11
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "009"
down_revision: str | None = "008"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

SOURCES_BEFORE = ["dnstwist", "combosquat", "llm", "ct", "nrd", "serpapi", "urlscan", "urlhaus", "phishtank", "logo_search", "manual", "meta_ads"]  # fmt: skip
SOURCES_AFTER = [*SOURCES_BEFORE, "social"]
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
            op.execute("ALTER TYPE discovery_source ADD VALUE IF NOT EXISTS 'social'")
    else:
        _sqlite_set_sources(SOURCES_AFTER)


def downgrade() -> None:
    # PostgreSQL cannot drop a value from an enum type; the unused 'social' label stays.
    if op.get_bind().dialect.name == "postgresql":
        return
    # rows that would break the old CHECK: the social source becomes "manual" (the account stays)
    _drop_triggers()
    op.execute("DELETE FROM candidate_sources WHERE source = 'social'")
    op.execute("UPDATE observations SET source = 'manual' WHERE source = 'social'")
    _sqlite_set_sources(SOURCES_BEFORE)
