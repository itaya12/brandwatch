"""Site & network intel cache: one row per (subject, source, relation) lookup, 24h TTL.

Revision ID: 006
Revises: 005
Create Date: 2026-10-08
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "006"
down_revision: str | None = "005"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

GUID = sa.Uuid(as_uuid=True)
JSONB = sa.JSON().with_variant(postgresql.JSONB(), "postgresql")
TZDateTime = sa.DateTime(timezone=True)


def upgrade() -> None:
    op.create_table(
        "intel_lookups",
        sa.Column("id", GUID, nullable=False),
        sa.Column("workspace_id", GUID, nullable=False),
        sa.Column("subject_type", sa.String(length=16), nullable=False),
        sa.Column("subject", sa.String(length=255), nullable=False),
        sa.Column("source", sa.String(length=32), nullable=False),
        sa.Column("relation", sa.String(length=32), nullable=False, server_default="report"),
        sa.Column("payload", JSONB, nullable=True),
        sa.Column("status", sa.String(length=16), nullable=False, server_default="ok"),
        sa.Column("error", sa.Text, nullable=True),
        sa.Column("fetched_at", TZDateTime, nullable=False, server_default=sa.func.now()),
        sa.Column("expires_at", TZDateTime, nullable=True),
        sa.PrimaryKeyConstraint("id", name="pk_intel_lookups"),
        sa.ForeignKeyConstraint(
            ["workspace_id"],
            ["workspaces.id"],
            name="fk_intel_lookups_workspace_id_workspaces",
            ondelete="RESTRICT",
        ),  # fmt: skip
        sa.UniqueConstraint(
            "workspace_id",
            "subject_type",
            "subject",
            "source",
            "relation",
            name="uq_intel_lookups_subject",  # one row per lookup; Postgres caps names at 63 characters
        ),  # fmt: skip
    )
    op.create_index(
        "ix_intel_lookups_workspace_id_subject_type_subject",
        "intel_lookups",
        ["workspace_id", "subject_type", "subject"],
    )


def downgrade() -> None:
    op.drop_index("ix_intel_lookups_workspace_id_subject_type_subject", table_name="intel_lookups")
    op.drop_table("intel_lookups")
