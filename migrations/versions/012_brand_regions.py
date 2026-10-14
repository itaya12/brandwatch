"""Regional child campaigns of a global brand (The North Face → The North Face · Israel).

* ``brands.parent_id`` (GUID, nullable, FK→brands, RESTRICT): the main brand a regional campaign belongs to.
* ``brands.region`` (String(64), nullable): "Israel", "USA/Global" …

A region is an ordinary brand (its own domains, fingerprint, queries, prices, schedule); the family of a
main brand and its regions protects each other's sites. See ``detection/regions.py``.

Revision ID: 012
Revises: 011
Create Date: 2026-10-12
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "012"
down_revision: str | None = "011"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

GUID = sa.Uuid(as_uuid=True)


def upgrade() -> None:
    with op.batch_alter_table("brands") as batch:
        batch.add_column(sa.Column("parent_id", GUID, nullable=True))
        batch.add_column(sa.Column("region", sa.String(64), nullable=True))
        batch.create_foreign_key("fk_brands_parent_id_brands", "brands", ["parent_id"], ["id"], ondelete="RESTRICT")
        batch.create_index("ix_brands_parent_id", ["parent_id"])


def downgrade() -> None:
    with op.batch_alter_table("brands") as batch:
        batch.drop_index("ix_brands_parent_id")
        batch.drop_constraint("fk_brands_parent_id_brands", type_="foreignkey")
        batch.drop_column("region")
        batch.drop_column("parent_id")
