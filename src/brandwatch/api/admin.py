"""Administration API (spec §14 Settings, §17 Phase 6): users & roles, workspace budget, provider
API keys (encrypted), tenants. Admin-only; every change is audited."""

from __future__ import annotations

import uuid
from typing import Annotated, Any

import sqlalchemy as sa
from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from brandwatch import keys as keystore
from brandwatch import tenancy
from brandwatch.api.auth import audit, hash_password, require_admin
from brandwatch.api.deps import get_session
from brandwatch.db.enums import UserRole
from brandwatch.db.models import ApiKey, User, Workspace
from brandwatch.providers.impl import REAL_PROVIDERS

router = APIRouter(prefix="/api/admin", tags=["admin"])

EMAIL_RE = r"^[^@\s]+@[^@\s]+\.[^@\s]+$"


class UserCreate(BaseModel):
    email: str = Field(min_length=3, max_length=320, pattern=EMAIL_RE)
    password: str = Field(min_length=10, max_length=256)
    role: UserRole = UserRole.ANALYST


class UserPatch(BaseModel):
    role: UserRole | None = None
    is_active: bool | None = None
    password: str | None = Field(default=None, min_length=10, max_length=256)


class WorkspacePatch(BaseModel):
    name: str | None = Field(default=None, min_length=2, max_length=200)
    economic_limits: dict[str, Any] | None = None


class KeyPut(BaseModel):
    key: str = Field(min_length=8, max_length=4096)


class WorkspaceCreate(BaseModel):
    name: str = Field(min_length=2, max_length=200)
    admin_email: str = Field(min_length=3, max_length=320, pattern=EMAIL_RE)
    admin_password: str = Field(min_length=10, max_length=256)


def user_out(u: User) -> dict[str, Any]:
    return {
        "id": str(u.id), "email": u.email, "role": u.role.value, "is_active": u.is_active,
        "created_at": u.created_at.isoformat(), "last_login_at": u.last_login_at.isoformat() if u.last_login_at else None,
    }  # fmt: skip


def _active_admins(session: Session, workspace_id: uuid.UUID) -> int:
    return int(
        session.scalar(
            sa.select(sa.func.count())
            .select_from(User)
            .where(
                User.workspace_id == workspace_id,
                User.role == UserRole.ADMIN,
                User.is_active.is_(True),
            )
        )
        or 0
    )


# ------------------------------------------------------------------------------------------ users
@router.get("/users")
def list_users(
    session: Annotated[Session, Depends(get_session, scope="function")],
    admin: Annotated[User, Depends(require_admin)],
) -> list[dict[str, Any]]:
    rows = session.scalars(
        sa.select(User).where(User.workspace_id == admin.workspace_id).order_by(User.created_at)
    ).all()
    return [user_out(u) for u in rows]


@router.post("/users", status_code=status.HTTP_201_CREATED)
def create_user(
    body: UserCreate,
    session: Annotated[Session, Depends(get_session, scope="function")],
    admin: Annotated[User, Depends(require_admin)],
) -> dict[str, Any]:
    if session.scalars(sa.select(User).where(User.email == body.email.strip())).first():
        raise HTTPException(status.HTTP_409_CONFLICT, "a user with this e-mail already exists")
    u = User(
        workspace_id=admin.workspace_id,
        email=body.email.strip(),
        password_hash=hash_password(body.password),
        role=body.role,
    )
    session.add(u)
    session.flush()
    audit(session, workspace_id=admin.workspace_id, actor_type="analyst", actor_id=admin.id, action="user.created",
          object_type="user", object_id=u.id, new={"email": u.email, "role": u.role.value})  # fmt: skip
    return user_out(u)


@router.patch("/users/{user_id}")
def patch_user(
    user_id: uuid.UUID, body: UserPatch,
    session: Annotated[Session, Depends(get_session, scope="function")], admin: Annotated[User, Depends(require_admin)],
) -> dict[str, Any]:  # fmt: skip
    u = session.get(User, user_id)
    if u is None or u.workspace_id != admin.workspace_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "user not found")
    old = {"role": u.role.value, "is_active": u.is_active}
    demoting = (
        body.role is not None and body.role is not UserRole.ADMIN and u.role is UserRole.ADMIN
    )
    deactivating = body.is_active is False and u.is_active and u.role is UserRole.ADMIN
    if (demoting or deactivating) and _active_admins(session, admin.workspace_id) <= 1:
        raise HTTPException(
            status.HTTP_409_CONFLICT, "a workspace must keep at least one active admin"
        )
    if body.role is not None:
        u.role = body.role
    if body.is_active is not None:
        u.is_active = body.is_active
    if body.password:
        u.password_hash = hash_password(body.password)
    session.flush()
    audit(session, workspace_id=admin.workspace_id, actor_type="analyst", actor_id=admin.id, action="user.updated",
          object_type="user", object_id=u.id, old=old,
          new={"role": u.role.value, "is_active": u.is_active, "password_reset": bool(body.password)})  # fmt: skip
    return user_out(u)


# ------------------------------------------------------------------------------------------ workspace + budget
@router.get("/workspace")
def get_workspace(
    request: Request,
    session: Annotated[Session, Depends(get_session, scope="function")],
    admin: Annotated[User, Depends(require_admin)],
) -> dict[str, Any]:
    ws = session.get(Workspace, admin.workspace_id)
    limits = tenancy.workspace_limits(session, ws.id, request.app.state.settings)
    return {"id": str(ws.id), "name": ws.name, "economic_limits": limits.model_dump(),
            "is_platform_workspace": tenancy.platform_admin_workspace(session).id == ws.id}  # fmt: skip


@router.patch("/workspace")
def patch_workspace(
    body: WorkspacePatch, request: Request,
    session: Annotated[Session, Depends(get_session, scope="function")], admin: Annotated[User, Depends(require_admin)],
) -> dict[str, Any]:  # fmt: skip
    ws = session.get(Workspace, admin.workspace_id)
    old = {
        "name": ws.name,
        "economic_limits": tenancy.workspace_limits(
            session, ws.id, request.app.state.settings
        ).model_dump(),
    }
    if body.name:
        ws.name = body.name.strip()
    if body.economic_limits is not None:
        try:
            tenancy.set_workspace_limits(session, ws.id, body.economic_limits)
        except ValueError as exc:
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, str(exc)) from exc
    session.flush()
    out = get_workspace(request, session, admin)
    audit(session, workspace_id=ws.id, actor_type="analyst", actor_id=admin.id, action="workspace.updated",
          object_type="workspace", object_id=ws.id, old=old, new={"name": out["name"], "economic_limits": out["economic_limits"]})  # fmt: skip
    return out


# ------------------------------------------------------------------------------------------ tenants
@router.get("/workspaces")
def list_workspaces(
    session: Annotated[Session, Depends(get_session, scope="function")],
    admin: Annotated[User, Depends(require_admin)],
) -> list[dict[str, Any]]:
    platform = tenancy.platform_admin_workspace(session)
    if platform is None or admin.workspace_id != platform.id:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "only platform admins manage tenants")
    rows = session.scalars(sa.select(Workspace).order_by(Workspace.created_at)).all()
    return [{"id": str(w.id), "name": w.name, "created_at": w.created_at.isoformat(),
             "users": session.scalar(sa.select(sa.func.count()).select_from(User).where(User.workspace_id == w.id))} for w in rows]  # fmt: skip


@router.post("/workspaces", status_code=status.HTTP_201_CREATED)
def create_workspace(
    body: WorkspaceCreate,
    session: Annotated[Session, Depends(get_session, scope="function")],
    admin: Annotated[User, Depends(require_admin)],
) -> dict[str, Any]:
    platform = tenancy.platform_admin_workspace(session)
    if platform is None or admin.workspace_id != platform.id:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "only platform admins manage tenants")
    if session.scalars(sa.select(User).where(User.email == body.admin_email.strip())).first():
        raise HTTPException(status.HTTP_409_CONFLICT, "a user with this e-mail already exists")
    ws = Workspace(name=body.name.strip())
    session.add(ws)
    session.flush()
    u = User(
        workspace_id=ws.id,
        email=body.admin_email.strip(),
        password_hash=hash_password(body.admin_password),
        role=UserRole.ADMIN,
    )
    session.add(u)
    session.flush()
    audit(session, workspace_id=admin.workspace_id, actor_type="analyst", actor_id=admin.id, action="workspace.created",
          object_type="workspace", object_id=ws.id, new={"name": ws.name, "admin": u.email})  # fmt: skip
    audit(session, workspace_id=ws.id, actor_type="system", actor_id=None, action="workspace.bootstrap",
          object_type="workspace", object_id=ws.id, new={"name": ws.name, "created_by": str(admin.id)})  # fmt: skip
    return {"id": str(ws.id), "name": ws.name, "admin": user_out(u)}


# ------------------------------------------------------------------------------------------ provider API keys
@router.get("/api-keys")
def list_api_keys(
    session: Annotated[Session, Depends(get_session, scope="function")],
    admin: Annotated[User, Depends(require_admin)],
    request: Request,
) -> list[dict[str, Any]]:
    settings = request.app.state.settings
    rows = {
        r.provider: r
        for r in session.scalars(
            sa.select(ApiKey).where(ApiKey.workspace_id == admin.workspace_id)
        ).all()
    }
    out = []
    for p in keystore.KNOWN_PROVIDERS:
        r = rows.get(p)
        out.append({
            "provider": p, "configured": r is not None or settings.has_key(p),
            "source": "workspace" if r else ("environment" if settings.has_key(p) else None),
            "masked": f"…{r.last4}" if r else (f"…{settings.provider_key(p)[-4:]}" if settings.has_key(p) else None),
            "rotated_at": r.rotated_at.isoformat() if r and r.rotated_at else None,
            "created_at": r.created_at.isoformat() if r else None,
        })  # fmt: skip
    return out


@router.put("/api-keys/{provider}")
def put_api_key(
    provider: str, body: KeyPut, request: Request,
    session: Annotated[Session, Depends(get_session, scope="function")], admin: Annotated[User, Depends(require_admin)],
) -> dict[str, Any]:  # fmt: skip
    try:
        row = keystore.store_key(
            session, admin.workspace_id, provider, body.key, request.app.state.settings
        )
    except ValueError as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, str(exc)) from exc
    audit(
        session,
        workspace_id=admin.workspace_id,
        actor_type="analyst",
        actor_id=admin.id,
        action="api_key.rotated" if row.rotated_at else "api_key.created",
        object_type="api_key",
        object_id=row.id,
        new={"provider": provider, "last4": row.last4},
    )  # fmt: skip — never the key itself
    return {
        "provider": provider,
        "masked": f"…{row.last4}",
        "rotated_at": row.rotated_at.isoformat() if row.rotated_at else None,
    }


@router.delete("/api-keys/{provider}", status_code=status.HTTP_204_NO_CONTENT)
def delete_api_key(
    provider: str,
    session: Annotated[Session, Depends(get_session, scope="function")],
    admin: Annotated[User, Depends(require_admin)],
) -> None:
    if not keystore.delete_key(session, admin.workspace_id, provider):
        raise HTTPException(status.HTTP_404_NOT_FOUND, "no key stored for this provider")
    audit(session, workspace_id=admin.workspace_id, actor_type="analyst", actor_id=admin.id, action="api_key.deleted",
          object_type="api_key", object_id=None, new={"provider": provider})  # fmt: skip


_TEST_CALLS: dict[str, tuple[str, tuple]] = {
    "virustotal": ("lookup_domain", ("example.com",)),
    "urlscan": ("search_pages", ("example", 1)),
    "serpapi": ("search", ("example",)),
    "scraperapi": ("search", ("example",)),
    "searchapi": ("account", ()),  # free: is the key valid, and how many requests are left (a search would spend one)
    "companies_house": ("lookup", ("00000006", "GB")),
    "shodan": ("host", ("8.8.8.8",)),
    "whoisxml": ("balance", ()),  # free: is the key valid, and how many credits has each product (a WHOIS lookup would spend one)
    # the WHOIS History product is separate (its own credits - "Domain Research Suite" - and its own errors): the free balance
    # first, and one 1-credit preview only when there is something to spend; only when an admin presses its button
    "whoisxml-history": ("history_ready", ("google.com",)),
    "openai": (
        "analyze",
        (
            "Reply for a connectivity test.",
            {
                "title": "ping",
                "type": "object",
                "properties": {"ok": {"type": "boolean"}},
                "required": ["ok"],
                "additionalProperties": False,
            },
        ),
    ),
}


@router.post("/api-keys/{provider}/test")
async def test_api_key(
    provider: str, request: Request,
    session: Annotated[Session, Depends(get_session, scope="function")], admin: Annotated[User, Depends(require_admin)],
) -> dict[str, Any]:  # fmt: skip
    settings = request.app.state.settings
    key_name = "whoisxml" if provider == "whoisxml-history" else provider  # one account key, two products
    secret = keystore.load_keys(session, admin.workspace_id, settings).get(
        key_name
    ) or settings.provider_key(key_name)
    if not secret:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "no key configured for this provider")
    if settings.demo_mode:
        return {
            "provider": provider,
            "ok": True,
            "detail": "demo mode: key decrypts; provider not contacted",
        }
    call = _TEST_CALLS.get(provider)
    cls = REAL_PROVIDERS.get(key_name)
    if call is None or cls is None:
        return {
            "provider": provider,
            "ok": True,
            "detail": "stored; no live test available for this provider",
        }
    method, args = call
    try:
        res = await getattr(cls(api_key=secret), method)(*args)
        data = res.data if isinstance(res.data, dict) else {}
        return {
            "provider": provider,
            "ok": bool(res.ok and data.get("ok", True)),  # a valid key with nothing to spend is not "working"
            "detail": res.error or data.get("summary") or res.status.value,
            "latency_ms": res.latency_ms,
        }
    except Exception as exc:  # noqa: BLE001 - surface the provider error to the admin
        return {
            "provider": provider,
            "ok": False,
            "detail": f"{type(exc).__name__}: {str(exc)[:200]}",
        }
