"""Suspicious shops: what kind of brand this is, its commerce profile, the kind of each finding,
and a new discovery source for ads found in Meta's Ad Library.

* ``brands.kind`` — ``retail`` (its products are resold by other shops) or ``service``.
* ``brands.profile`` — countries, ad keywords, official prices, official social pages (JSON).
* ``findings.kind`` — ``phishing`` or ``shop``.
* ``discovery_source`` += ``meta_ads``. PostgreSQL: ``ALTER TYPE``. SQLite keeps enums as a CHECK
  constraint, which can only change by rebuilding the table; ``observations`` is append-only, so
  its immutability triggers are recreated after the rebuild.

Revision ID: 008
Revises: 007
Create Date: 2026-10-11
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "008"
down_revision: str | None = "007"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

JSONB = sa.JSON().with_variant(postgresql.JSONB(), "postgresql")

SOURCES_BEFORE = ["dnstwist", "combosquat", "llm", "ct", "nrd", "serpapi", "urlscan", "urlhaus", "phishtank", "logo_search", "manual"]  # fmt: skip
SOURCES_AFTER = [*SOURCES_BEFORE, "meta_ads"]
SOURCE_TABLES = ("candidate_sources", "observations")


def _check_sql(values: list[str]) -> str:
    return "source IN (" + ", ".join(f"'{v}'" for v in values) + ")"


def _sqlite_set_sources(values: list[str]) -> None:
    for table in SOURCE_TABLES:
        if table == "observations":  # the rebuild below drops the table's triggers
            op.execute("DROP TRIGGER IF EXISTS trg_observations_no_update")
            op.execute("DROP TRIGGER IF EXISTS trg_observations_no_delete")
        with op.batch_alter_table(table, recreate="always") as batch:
            batch.drop_constraint(
                "discovery_source", type_="check"
            )  # the naming convention adds ck_<table>_
            batch.create_check_constraint("discovery_source", sa.text(_check_sql(values)))
    for verb in ("UPDATE", "DELETE"):  # same SQL as 001_initial_schema
        op.execute(
            f"CREATE TRIGGER trg_observations_no_{verb.lower()} BEFORE {verb} ON observations "
            f"BEGIN SELECT RAISE(ABORT, 'immutable table observations: {verb} not allowed'); END"
        )


def upgrade() -> None:
    with op.batch_alter_table("brands") as batch:
        batch.add_column(sa.Column("kind", sa.String(16), nullable=False, server_default="service"))
        batch.add_column(sa.Column("profile", JSONB, nullable=True))
    with op.batch_alter_table("findings") as batch:
        batch.add_column(
            sa.Column("kind", sa.String(16), nullable=False, server_default="phishing")
        )
    if op.get_bind().dialect.name == "postgresql":
        with op.get_context().autocommit_block():
            op.execute("ALTER TYPE discovery_source ADD VALUE IF NOT EXISTS 'meta_ads'")
    else:
        _sqlite_set_sources(SOURCES_AFTER)


def downgrade() -> None:
    # PostgreSQL cannot drop a value from an enum type; the unused 'meta_ads' label stays.
    if op.get_bind().dialect.name != "postgresql":
        _sqlite_set_sources(SOURCES_BEFORE)
    with op.batch_alter_table("findings") as batch:
        batch.drop_column("kind")
    with op.batch_alter_table("brands") as batch:
        batch.drop_column("profile")
        batch.drop_column("kind")
