"""IP geolocation on ip_addresses (dashboard globe: where the impersonating infrastructure lives).

Revision ID: 003
Revises: 002
Create Date: 2026-10-07
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "003"
down_revision: str | None = "002"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    with op.batch_alter_table("ip_addresses") as batch:
        batch.add_column(sa.Column("country", sa.String(length=2), nullable=True))
        batch.add_column(sa.Column("city", sa.String(length=120), nullable=True))
        batch.add_column(sa.Column("lat", sa.Float(), nullable=True))
        batch.add_column(sa.Column("lon", sa.Float(), nullable=True))
        batch.add_column(sa.Column("org", sa.Text(), nullable=True))
        batch.add_column(sa.Column("geo_source", sa.String(length=64), nullable=True))
        batch.add_column(sa.Column("last_seen", sa.DateTime(timezone=True), nullable=True))


def downgrade() -> None:
    with op.batch_alter_table("ip_addresses") as batch:
        for col in ("last_seen", "geo_source", "org", "lon", "lat", "city", "country"):
            batch.drop_column(col)
