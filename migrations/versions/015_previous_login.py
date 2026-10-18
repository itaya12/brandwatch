"""``users.previous_login_at``: when the user signed in the time before this one.

The findings queue's "new since my last visit" filter needs the login *before* the current one;
``last_login_at`` is overwritten at every sign-in, so the previous value is kept here.

Revision ID: 015
Revises: 014
Create Date: 2026-10-18
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

from brandwatch.db.types import TZDateTime

revision: str = "015"
down_revision: str | None = "014"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    with op.batch_alter_table("users") as batch:
        batch.add_column(sa.Column("previous_login_at", TZDateTime, nullable=True))


def downgrade() -> None:
    with op.batch_alter_table("users") as batch:
        batch.drop_column("previous_login_at")
