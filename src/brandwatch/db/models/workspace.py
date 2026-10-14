"""Tenancy, users and personal access tokens (spec §21 — workspaces, users; Phase 6 tokens)."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

import sqlalchemy as sa
from sqlalchemy.orm import Mapped, mapped_column, relationship

from brandwatch.db.base import Base
from brandwatch.db.enums import UserRole
from brandwatch.db.types import JSONB, CIText, TZDateTime, created_at, enum_type, fk, uuid_pk


class Workspace(Base):
    __tablename__ = "workspaces"

    id: Mapped[uuid.UUID] = uuid_pk()
    name: Mapped[str] = mapped_column(sa.String(200), nullable=False)
    # workspace-level knobs: {"economic_limits": {...}} — brand configs inherit from here
    settings: Mapped[dict[str, Any] | None] = mapped_column(JSONB, nullable=True)
    created_at: Mapped[datetime] = created_at()

    users: Mapped[list[User]] = relationship(back_populates="workspace")


class User(Base):
    __tablename__ = "users"

    id: Mapped[uuid.UUID] = uuid_pk()
    workspace_id: Mapped[uuid.UUID] = fk("workspaces.id", index=True)
    email: Mapped[str] = mapped_column(CIText, nullable=False, unique=True)
    password_hash: Mapped[str] = mapped_column(sa.String(255), nullable=False)  # Argon2id
    role: Mapped[UserRole] = mapped_column(enum_type(UserRole), nullable=False)
    is_active: Mapped[bool] = mapped_column(sa.Boolean, nullable=False, default=True)
    created_at: Mapped[datetime] = created_at()
    last_login_at: Mapped[datetime | None] = mapped_column(TZDateTime, nullable=True)

    workspace: Mapped[Workspace] = relationship(back_populates="users")


class AccessToken(Base):
    """Personal API token for automation (public API). Only the SHA-256 of the token is stored;
    the plaintext is shown once at creation. ``scope = read`` caps the holder at viewer rights."""

    __tablename__ = "access_tokens"
    __table_args__ = (sa.Index("ix_access_tokens_user_id", "user_id"),)

    id: Mapped[uuid.UUID] = uuid_pk()
    workspace_id: Mapped[uuid.UUID] = fk("workspaces.id")
    user_id: Mapped[uuid.UUID] = fk("users.id")
    name: Mapped[str] = mapped_column(sa.String(120), nullable=False)
    token_hash: Mapped[str] = mapped_column(sa.String(64), nullable=False, unique=True)
    prefix: Mapped[str] = mapped_column(sa.String(16), nullable=False)
    scope: Mapped[str] = mapped_column(sa.String(16), nullable=False)  # read | write
    created_at: Mapped[datetime] = created_at()
    expires_at: Mapped[datetime | None] = mapped_column(TZDateTime, nullable=True)
    last_used_at: Mapped[datetime | None] = mapped_column(TZDateTime, nullable=True)
    revoked_at: Mapped[datetime | None] = mapped_column(TZDateTime, nullable=True)
