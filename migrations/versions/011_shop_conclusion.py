"""The analyst's conclusion on a suspicious-shop finding: how sure we are that it sells fakes.

* ``findings.conclusion`` (JSON, nullable): ``{level, proof, note, system_level, by, at}`` with
  ``level`` = suspicious_retailer | likely_counterfeit | confirmed_counterfeit — see
  ``detection/shop_levels.py``. Null = no conclusion yet (and always null for phishing / social).

Revision ID: 011
Revises: 010
Create Date: 2026-10-11
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "011"
down_revision: str | None = "010"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

JSONB = sa.JSON().with_variant(postgresql.JSONB(), "postgresql")


def upgrade() -> None:
    with op.batch_alter_table("findings") as batch:
        batch.add_column(sa.Column("conclusion", JSONB, nullable=True))


def downgrade() -> None:
    with op.batch_alter_table("findings") as batch:
        batch.drop_column("conclusion")
