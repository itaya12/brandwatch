"""Candidates remember their latest analysis (signals / flags / score) — the ML feature store.

Revision ID: 004
Revises: 003
Create Date: 2026-10-08
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "004"
down_revision: str | None = "003"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

JSONB = sa.JSON().with_variant(postgresql.JSONB(), "postgresql")


def upgrade() -> None:
    with op.batch_alter_table("candidates") as batch:
        batch.add_column(sa.Column("last_analysis", JSONB, nullable=True))
        batch.add_column(sa.Column("last_scored_at", sa.DateTime(timezone=True), nullable=True))


def downgrade() -> None:
    with op.batch_alter_table("candidates") as batch:
        batch.drop_column("last_scored_at")
        batch.drop_column("last_analysis")
