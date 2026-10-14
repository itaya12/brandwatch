"""Automatic scans per brand: how often, at what time, and which tasks.

* ``brands.schedule`` (JSON, nullable): ``{enabled, every_hours, hour, tz_offset, tasks, updated_at,
  updated_by}`` — see ``detection/schedule.py``. Null = never set = no automatic scans.

Revision ID: 010
Revises: 009
Create Date: 2026-10-11
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "010"
down_revision: str | None = "009"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

JSONB = sa.JSON().with_variant(postgresql.JSONB(), "postgresql")


def upgrade() -> None:
    with op.batch_alter_table("brands") as batch:
        batch.add_column(sa.Column("schedule", JSONB, nullable=True))


def downgrade() -> None:
    with op.batch_alter_table("brands") as batch:
        batch.drop_column("schedule")
