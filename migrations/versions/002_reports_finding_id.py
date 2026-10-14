"""Reports link to the finding they package (Phase 2 evidence packages).

Revision ID: 002
Revises: 001
Create Date: 2026-10-07
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "002"
down_revision: str | None = "001"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

GUID = sa.Uuid(as_uuid=True)


def upgrade() -> None:
    with op.batch_alter_table("reports") as batch:
        batch.add_column(sa.Column("finding_id", GUID, nullable=True))
        batch.create_foreign_key(
            "fk_reports_finding_id_findings",
            "findings",
            ["finding_id"],
            ["id"],
            ondelete="RESTRICT",
        )
        batch.create_index("ix_reports_finding_id", ["finding_id"])


def downgrade() -> None:
    with op.batch_alter_table("reports") as batch:
        batch.drop_index("ix_reports_finding_id")
        batch.drop_constraint("fk_reports_finding_id_findings", type_="foreignkey")
        batch.drop_column("finding_id")
