"""Personal API access tokens (Phase 6 public API).

``Authorization: Bearer bw_…`` authenticates as the token's owner. ``scope=read`` caps the holder
at viewer rights even when the owner is an analyst or admin. The plaintext is returned once;
only its SHA-256 is stored. Revocation is immediate.
"""

from __future__ import annotations

import hashlib
import secrets
import uuid
from datetime import UTC, datetime, timedelta
from typing import Annotated, Any, Literal

import sqlalchemy as sa
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from brandwatch.api.auth import audit, current_user
from brandwatch.api.deps import get_session
from brandwatch.db.enums import UserRole
from brandwatch.db.models import AccessToken, User

router = APIRouter(prefix="/api/tokens", tags=["tokens"])

TOKEN_PREFIX = "bw_"


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


class TokenCreate(BaseModel):
    name: str = Field(min_length=2, max_length=120)
    scope: Literal["read", "write"] = "read"
    expires_days: int | None = Field(default=90, ge=1, le=3650)


def token_out(t: AccessToken) -> dict[str, Any]:
    iso = lambda d: d.isoformat() if d else None  # noqa: E731
    return {"id": str(t.id), "name": t.name, "prefix": t.prefix, "scope": t.scope, "created_at": iso(t.created_at),
            "expires_at": iso(t.expires_at), "last_used_at": iso(t.last_used_at), "revoked": t.revoked_at is not None}  # fmt: skip


@router.get("")
def list_tokens(
    session: Annotated[Session, Depends(get_session, scope="function")],
    user: Annotated[User, Depends(current_user)],
) -> list[dict[str, Any]]:
    rows = session.scalars(
        sa.select(AccessToken)
        .where(AccessToken.user_id == user.id)
        .order_by(AccessToken.created_at.desc())
    ).all()
    return [token_out(t) for t in rows]


@router.post("", status_code=status.HTTP_201_CREATED)
def create_token(
    body: TokenCreate,
    session: Annotated[Session, Depends(get_session, scope="function")],
    user: Annotated[User, Depends(current_user)],
) -> dict[str, Any]:
    if body.scope == "write" and user.role is UserRole.VIEWER:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "viewers can only create read tokens")
    token = TOKEN_PREFIX + secrets.token_urlsafe(32)
    row = AccessToken(
        workspace_id=user.workspace_id, user_id=user.id, name=body.name.strip(), token_hash=hash_token(token),
        prefix=token[:10], scope=body.scope,
        expires_at=datetime.now(UTC) + timedelta(days=body.expires_days) if body.expires_days else None,
    )  # fmt: skip
    session.add(row)
    session.flush()
    audit(session, workspace_id=user.workspace_id, actor_type="analyst", actor_id=user.id, action="token.created",
          object_type="access_token", object_id=row.id, new={"name": row.name, "scope": row.scope, "prefix": row.prefix})  # fmt: skip
    return {**token_out(row), "token": token, "note": "store it now — it is not shown again"}


@router.delete("/{token_id}", status_code=status.HTTP_204_NO_CONTENT)
def revoke_token(
    token_id: uuid.UUID,
    session: Annotated[Session, Depends(get_session, scope="function")],
    user: Annotated[User, Depends(current_user)],
) -> None:
    row = session.get(AccessToken, token_id)
    if row is None or (
        row.user_id != user.id
        and not (user.role is UserRole.ADMIN and row.workspace_id == user.workspace_id)
    ):
        raise HTTPException(status.HTTP_404_NOT_FOUND, "token not found")
    if row.revoked_at is None:
        row.revoked_at = datetime.now(UTC)
        audit(session, workspace_id=user.workspace_id, actor_type="analyst", actor_id=user.id, action="token.revoked",
              object_type="access_token", object_id=row.id, new={"prefix": row.prefix})  # fmt: skip
