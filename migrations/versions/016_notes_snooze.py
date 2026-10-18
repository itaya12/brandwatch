"""``finding_notes`` (an analyst's working notes on a finding) and ``findings.snoozed_until`` (out of the queue until then).

Revision ID: 016
Revises: 015
Create Date: 2026-10-19
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

from brandwatch.db.types import GUID, TZDateTime

revision: str = "016"
down_revision: str | None = "015"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # a plain ADD COLUMN (no table rebuild): the findings table keeps its foreign keys as they are
    op.add_column("findings", sa.Column("snoozed_until", TZDateTime, nullable=True))
    op.create_table(
        "finding_notes",
        sa.Column("id", GUID, primary_key=True),
        sa.Column("finding_id", GUID, sa.ForeignKey("findings.id", ondelete="RESTRICT"), nullable=False, index=True),
        sa.Column("author_id", GUID, sa.ForeignKey("users.id", ondelete="RESTRICT"), nullable=True),
        sa.Column("text", sa.Text, nullable=False),
        sa.Column("created_at", TZDateTime, nullable=False, server_default=sa.func.now()),
    )


def downgrade() -> None:
    op.drop_table("finding_notes")
    with op.batch_alter_table("findings") as batch:
        batch.drop_column("snoozed_until")
