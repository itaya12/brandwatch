"""Phase 6 productization: personal access tokens, workspace settings (budget), user last login.

Revision ID: 005
Revises: 004
Create Date: 2026-10-08
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "005"
down_revision: str | None = "004"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

GUID = sa.Uuid(as_uuid=True)
JSONB = sa.JSON().with_variant(postgresql.JSONB(), "postgresql")
TZDateTime = sa.DateTime(timezone=True)


def upgrade() -> None:
    op.create_table(
        "access_tokens",
        sa.Column("id", GUID, nullable=False),
        sa.Column("workspace_id", GUID, nullable=False),
        sa.Column("user_id", GUID, nullable=False),
        sa.Column("name", sa.String(length=120), nullable=False),
        sa.Column("token_hash", sa.String(length=64), nullable=False),
        sa.Column("prefix", sa.String(length=16), nullable=False),
        sa.Column("scope", sa.String(length=16), nullable=False),
        sa.Column("created_at", TZDateTime, nullable=False, server_default=sa.func.now()),
        sa.Column("expires_at", TZDateTime, nullable=True),
        sa.Column("last_used_at", TZDateTime, nullable=True),
        sa.Column("revoked_at", TZDateTime, nullable=True),
        sa.PrimaryKeyConstraint("id", name="pk_access_tokens"),
        sa.ForeignKeyConstraint(
            ["workspace_id"],
            ["workspaces.id"],
            name="fk_access_tokens_workspace_id_workspaces",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["user_id"], ["users.id"], name="fk_access_tokens_user_id_users", ondelete="RESTRICT"
        ),
        sa.UniqueConstraint("token_hash", name="uq_access_tokens_token_hash"),
    )
    op.create_index("ix_access_tokens_user_id", "access_tokens", ["user_id"], unique=False)
    with op.batch_alter_table("workspaces") as batch:
        batch.add_column(sa.Column("settings", JSONB, nullable=True))
    with op.batch_alter_table("users") as batch:
        batch.add_column(sa.Column("last_login_at", TZDateTime, nullable=True))


def downgrade() -> None:
    with op.batch_alter_table("users") as batch:
        batch.drop_column("last_login_at")
    with op.batch_alter_table("workspaces") as batch:
        batch.drop_column("settings")
    op.drop_index("ix_access_tokens_user_id", table_name="access_tokens")
    op.drop_table("access_tokens")
