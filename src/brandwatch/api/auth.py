"""Basic admin auth for Phase 0 (spec §17: single workspace, admin only; full RBAC in Phase 6).

* Argon2id password hashes (``users.password_hash``)
* HS256 JWT bearer tokens signed with ``SECRET_KEY``
* ``POST /api/auth/login`` and ``GET /api/auth/me``
* ``require_role(...)`` dependency — ``require_admin`` is the only one used in Phase 0
* every login attempt writes an ``audit_events`` row (never the password)
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from typing import Annotated, Any

import jwt
import sqlalchemy as sa
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerifyMismatchError
from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from brandwatch.api.deps import get_session, get_settings_dep
from brandwatch.config.settings import Settings
from brandwatch.db.enums import UserRole
from brandwatch.db.models import AuditEvent, User, Workspace

TOKEN_PREFIX = "bw_"  # personal access tokens (see api/tokens.py)
_hasher = PasswordHasher()
# Verified against when the user does not exist, so the response time does not reveal that.
_DUMMY_HASH = _hasher.hash("dummy-password-for-constant-time")

bearer = HTTPBearer(auto_error=False)
router = APIRouter(prefix="/api/auth", tags=["auth"])


# --------------------------------------------------------------------------------------------
# passwords / tokens
# --------------------------------------------------------------------------------------------
def hash_password(password: str) -> str:
    return _hasher.hash(password)


def verify_password(password_hash: str, password: str) -> bool:
    try:
        return _hasher.verify(password_hash, password)
    except (VerifyMismatchError, InvalidHashError):
        return False


def create_access_token(user: User, settings: Settings) -> tuple[str, int]:
    now = datetime.now(UTC)
    expires_in = settings.jwt_expires_minutes * 60
    payload: dict[str, Any] = {
        "sub": str(user.id),
        "ws": str(user.workspace_id),
        "role": user.role.value,
        "email": user.email,
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(seconds=expires_in)).timestamp()),
    }
    token = jwt.encode(payload, settings.secret_key.get_secret_value(), settings.jwt_algorithm)
    return token, expires_in


def decode_token(token: str, settings: Settings) -> dict[str, Any]:
    try:
        return jwt.decode(
            token, settings.secret_key.get_secret_value(), algorithms=[settings.jwt_algorithm]
        )
    except jwt.PyJWTError as exc:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid or expired token") from exc


# --------------------------------------------------------------------------------------------
# audit helper
# --------------------------------------------------------------------------------------------
def audit(
    session: Session,
    *,
    workspace_id: uuid.UUID,
    actor_type: str,
    actor_id: uuid.UUID | None,
    action: str,
    object_type: str,
    object_id: uuid.UUID | None = None,
    old: dict[str, Any] | None = None,
    new: dict[str, Any] | None = None,
    reason: str | None = None,
) -> AuditEvent:
    event = AuditEvent(
        workspace_id=workspace_id,
        actor_type=actor_type,
        actor_id=actor_id,
        action=action,
        object_type=object_type,
        object_id=object_id,
        old_value=old,
        new_value=new,
        reason=reason,
    )
    session.add(event)
    session.flush()
    return event


# --------------------------------------------------------------------------------------------
# dependencies
# --------------------------------------------------------------------------------------------
SESSION_COOKIE = "bw_session"


def current_user(
    request: Request,
    creds: Annotated[HTTPAuthorizationCredentials | None, Depends(bearer)],
    session: Annotated[Session, Depends(get_session, scope="function")],
    settings: Annotated[Settings, Depends(get_settings_dep)],
) -> User:
    token: str | None = None
    if creds is not None and creds.scheme.lower() == "bearer":
        token = creds.credentials
    else:
        token = request.cookies.get(SESSION_COOKIE)  # the server-rendered UI
    if not token:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "missing bearer token")
    if token.startswith(TOKEN_PREFIX):
        return _user_from_access_token(request, session, token)
    request.state.token_scope = "write"
    claims = decode_token(token, settings)
    try:
        user_id = uuid.UUID(str(claims.get("sub")))
    except ValueError as exc:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid token subject") from exc
    user = session.get(User, user_id)
    if user is None or not user.is_active:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "unknown or inactive user")
    return user


def _user_from_access_token(request: Request, session: Session, token: str) -> User:
    import hashlib

    from brandwatch.db.models import AccessToken

    row = session.scalars(
        sa.select(AccessToken).where(
            AccessToken.token_hash == hashlib.sha256(token.encode()).hexdigest()
        )
    ).first()
    now = datetime.now(UTC)
    if row is None:
        raise HTTPException(
            status.HTTP_401_UNAUTHORIZED, "invalid, expired or revoked access token"
        )
    expires = row.expires_at
    if expires is not None and expires.tzinfo is None:
        expires = expires.replace(tzinfo=UTC)  # SQLite returns naive datetimes
    if row.revoked_at is not None or (expires is not None and expires < now):
        raise HTTPException(
            status.HTTP_401_UNAUTHORIZED, "invalid, expired or revoked access token"
        )
    user = session.get(User, row.user_id)
    if user is None or not user.is_active or user.workspace_id != row.workspace_id:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "unknown or inactive user")
    row.last_used_at = now
    request.state.token_scope = row.scope
    return user


def require_role(*roles: UserRole):
    def dependency(request: Request, user: Annotated[User, Depends(current_user)]) -> User:
        if user.role not in roles:
            raise HTTPException(status.HTTP_403_FORBIDDEN, "insufficient role")
        if (
            getattr(request.state, "token_scope", "write") == "read"
            and UserRole.VIEWER not in roles
        ):
            raise HTTPException(status.HTTP_403_FORBIDDEN, "read-only access token")
        return user

    return dependency


require_admin = require_role(UserRole.ADMIN)
require_analyst = require_role(UserRole.ADMIN, UserRole.ANALYST)
require_viewer = require_role(UserRole.ADMIN, UserRole.ANALYST, UserRole.VIEWER)


# --------------------------------------------------------------------------------------------
# bootstrap (single workspace, admin only)
# --------------------------------------------------------------------------------------------
def bootstrap_admin(session: Session, settings: Settings) -> Workspace:
    """Idempotent: create the default workspace + admin user on first start."""
    workspace = session.scalars(sa.select(Workspace).order_by(Workspace.created_at)).first()
    if workspace is None:
        workspace = Workspace(name="default")
        session.add(workspace)
        session.flush()
        audit(
            session,
            workspace_id=workspace.id,
            actor_type="system",
            actor_id=None,
            action="workspace.bootstrap",
            object_type="workspace",
            object_id=workspace.id,
            new={"name": workspace.name},
        )

    email = settings.bootstrap_admin_email.strip()
    admin = session.scalars(sa.select(User).where(User.email == email)).first()
    if admin is None:
        admin = User(
            workspace_id=workspace.id,
            email=email,
            password_hash=hash_password(settings.bootstrap_admin_password.get_secret_value()),
            role=UserRole.ADMIN,
        )
        session.add(admin)
        session.flush()
        audit(
            session,
            workspace_id=workspace.id,
            actor_type="system",
            actor_id=None,
            action="user.bootstrap",
            object_type="user",
            object_id=admin.id,
            new={"email": email, "role": UserRole.ADMIN.value},
        )
    session.commit()
    return workspace


# --------------------------------------------------------------------------------------------
# routes
# --------------------------------------------------------------------------------------------
class LoginRequest(BaseModel):
    # a username ("admin") or an e-mail address; stored in users.email either way
    email: str = Field(min_length=2, max_length=320, pattern=r"^[^@\s]+(@[^@\s]+\.[^@\s]+)?$")
    password: str = Field(min_length=1, max_length=1024)


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int


class MeResponse(BaseModel):
    id: uuid.UUID
    email: str
    role: UserRole
    workspace_id: uuid.UUID


@router.post("/login", response_model=TokenResponse)
def login(
    body: LoginRequest,
    session: Annotated[Session, Depends(get_session, scope="function")],
    settings: Annotated[Settings, Depends(get_settings_dep)],
) -> TokenResponse:
    user = session.scalars(sa.select(User).where(User.email == body.email.strip())).first()
    ok = verify_password(user.password_hash if user else _DUMMY_HASH, body.password)
    if user is None or not ok or not user.is_active:
        if user is not None:
            audit(
                session,
                workspace_id=user.workspace_id,
                actor_type="analyst",
                actor_id=user.id,
                action="user.login_failed",
                object_type="user",
                object_id=user.id,
            )
        session.commit()  # keep the audit row even though we are about to raise
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid credentials")

    audit(
        session,
        workspace_id=user.workspace_id,
        actor_type="analyst",
        actor_id=user.id,
        action="user.login",
        object_type="user",
        object_id=user.id,
    )
    user.last_login_at = datetime.now(UTC)
    token, expires_in = create_access_token(user, settings)
    return TokenResponse(access_token=token, expires_in=expires_in)


@router.get("/me", response_model=MeResponse)
def me(user: Annotated[User, Depends(current_user)]) -> MeResponse:
    return MeResponse(id=user.id, email=user.email, role=user.role, workspace_id=user.workspace_id)
