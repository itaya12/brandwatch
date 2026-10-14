"""Takedown channels: registrar / hosting / CDN contacts, what was sent where, and which phishing
report portals were notified — stored as JSON on the draft.

Revision ID: 007
Revises: 006
Create Date: 2026-10-09
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "007"
down_revision: str | None = "006"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

JSONB = sa.JSON().with_variant(postgresql.JSONB(), "postgresql")


def upgrade() -> None:
    op.add_column("takedown_drafts", sa.Column("channels", JSONB, nullable=True))


def downgrade() -> None:
    op.drop_column("takedown_drafts", "channels")
