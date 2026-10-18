"""Phase 6 UI routes: settings (workspace budget, users & roles, API keys, tokens, tenants,
classifier) and the brand configuration editor (scoring weights + live preview, whitelist).

Registered on the same ``/ui`` router as ``brandwatch.api.ui``. Role rules mirror the JSON API:
viewers are read-only (``ui_writer``), admin-only actions call ``_admin_only``; every action goes
through the same service functions, so the audit trail is identical."""

from __future__ import annotations

import uuid
from typing import Annotated, Any

from fastapi import Depends, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlalchemy.orm import Session

from brandwatch import tenancy
from brandwatch.api import admin as admin_api
from brandwatch.api import brands as brands_api
from brandwatch.api import campaigns as campaigns_api
from brandwatch.api import ml as ml_api
from brandwatch.api import tokens as tokens_api
from brandwatch.api.auth import audit
from brandwatch.api.deps import get_session
from brandwatch.api.ui import _login_redirect, _render, router, ui_user, ui_writer
from brandwatch.config.brand_config import BRAND_SWITCHES, PRESET_PROFILES
from brandwatch.db.base import take_write_lock
from brandwatch.db.enums import UserRole
from brandwatch.db.models import User, Workspace


def _err(exc: Exception) -> str:
    return str(getattr(exc, "detail", exc))


def _settings_ctx(request: Request, session: Session, user: User) -> dict[str, Any]:
    ctx: dict[str, Any] = {
        "settings": request.app.state.settings,
        "channels": [n.name for n in request.app.state.notifier.notifiers],
        "tokens": tokens_api.list_tokens(session, user),
        "ml": ml_api.get_model(session, user)
        if user.role is not UserRole.VIEWER
        else {"model": None, "labelled_candidates": {"analyst": 0, "golden": 0}, "min_samples": 0},
        "workspaces": None,
        "users": [],
        "api_keys": [],
        "proxy": tenancy.workspace_proxy_settings(session, user.workspace_id),
        "proxy_mobile": tenancy.workspace_mobile_proxy_settings(session, user.workspace_id),
        "probe": tenancy.workspace_probe_settings(session, user.workspace_id),
        "notify": tenancy.workspace_notify(session, user.workspace_id, request.app.state.settings),
        "notify_brands": brands_api.list_brands(session, user),
        "facts": _facts(request),
        "PRESET_DEEP_SITES": PRESET_PROFILES["enterprise"]["max_candidates"],
    }
    if user.role is UserRole.ADMIN:
        ctx["ws"] = admin_api.get_workspace(request, session, user)
        ctx["users"] = admin_api.list_users(session, user)
        ctx["api_keys"] = admin_api.list_api_keys(session, user, request)
        ctx["start_here"] = start_here(ctx["api_keys"], ctx["ws"]["economic_limits"])
        if ctx["ws"]["is_platform_workspace"]:
            ctx["workspaces"] = admin_api.list_workspaces(session, user)
    else:
        ws = session.get(Workspace, user.workspace_id)
        limits = tenancy.workspace_limits(session, ws.id, request.app.state.settings)
        ctx["ws"] = {"id": str(ws.id), "name": ws.name, "economic_limits": limits.model_dump()}
    return ctx


def start_here(api_keys: list[dict[str, Any]], limits: dict[str, Any]) -> list[dict[str, Any]]:
    """The "Start here" checklist of a live workspace, each step with ``ok``: all its keys set (or any one, for a
    step with ``any``), or a daily spend cap above 0."""
    from brandwatch.api.labels import START_HERE

    have = {k["provider"] for k in api_keys if k.get("configured")}
    out = []
    for step in START_HERE:
        if step.get("budget"):
            ok = float(limits.get("max_daily_spend") or 0) > 0
        else:
            keys = step["keys"]
            ok = any(k in have for k in keys) if step.get("any") else all(k in have for k in keys)
        out.append({**step, "ok": ok})
    return out


def _settings_page(request: Request, session: Session, user: User, **extra: Any) -> HTMLResponse:
    return _render(
        request,
        "settings.html",
        user,
        active="settings",
        lookups=tenancy.workspace_lookups(session, user.workspace_id),
        **_settings_ctx(request, session, user),
        **extra,
    )


def _admin_only(user: User) -> None:
    if user.role is not UserRole.ADMIN:
        raise HTTPException(403, "admin only")


def _num(v: str, cast=float):
    v = (v or "").strip()
    return cast(v) if v else None


@router.get("/settings", response_class=HTMLResponse)
def settings_page(
    request: Request,
    session: Annotated[Session, Depends(get_session, scope="function")],
    user: Annotated[User | None, Depends(ui_user)],
):
    if user is None:
        return _login_redirect(request)
    saved = request.query_params.get("saved", "")
    return _settings_page(request, session, user, saved=saved if saved.isidentifier() else "")


@router.post("/settings/notify")
async def settings_notify(
    request: Request,
    session: Annotated[Session, Depends(get_session, scope="function")],
    user: Annotated[User | None, Depends(ui_writer)],
):
    """Settings → Notifications: the threshold, the channels, the muted brands and the digest."""
    if user is None:
        return _login_redirect(request)
    _admin_only(user)
    form = await request.form()
    configured = [n.name for n in request.app.state.notifier.notifiers]
    chosen = [c for c in form.getlist("channels") if c in configured]
    on = {str(b) for b in form.getlist("brand_on")}
    brands_off = [str(b["id"]) for b in brands_api.list_brands(session, user) if str(b["id"]) not in on]
    tenancy.set_workspace_notify(
        session, user.workspace_id, min_severity=str(form.get("min_severity") or ""),
        channels=chosen if form.get("pick_channels") == "on" else None, brands_off=brands_off, digest=form.get("digest") == "on",
    )  # fmt: skip
    audit(
        session, workspace_id=user.workspace_id, actor_type="analyst", actor_id=user.id,
        action="workspace.notify_updated", object_type="workspace", object_id=user.workspace_id,
        new={"min_severity": form.get("min_severity"), "channels": chosen if form.get("pick_channels") == "on" else "all",
             "brands_off": len(brands_off), "digest": form.get("digest") == "on"},
    )  # fmt: skip
    return RedirectResponse("/ui/settings?saved=notify#system", status_code=303)


@router.post("/settings/notify/test")
def settings_notify_test(
    request: Request,
    session: Annotated[Session, Depends(get_session, scope="function")],
    user: Annotated[User | None, Depends(ui_writer)],
):
    if user is None:
        return _login_redirect(request)
    _admin_only(user)
    n = request.app.state.notifier.send_test(session, user.workspace_id, by=user.email)
    return RedirectResponse(f"/ui/settings?saved={'notify_test' if n else 'notify_test_failed'}#system", status_code=303)


@router.post("/settings/workspace")
def settings_workspace(
    request: Request,
    session: Annotated[Session, Depends(get_session, scope="function")],
    user: Annotated[User | None, Depends(ui_writer)],
    name: Annotated[str, Form()] = "",
    max_daily_spend: Annotated[str, Form()] = "",
    max_api_calls: Annotated[str, Form()] = "",
    max_residential_gb: Annotated[str, Form()] = "",
    max_investigation_cost: Annotated[str, Form()] = "",
    max_candidate_count: Annotated[str, Form()] = "",
):
    if user is None:
        return _login_redirect(request)
    _admin_only(user)
    try:
        raw = {
            "max_daily_spend": _num(max_daily_spend),
            "max_api_calls": _num(max_api_calls, int),
            "max_residential_gb": _num(max_residential_gb),
            "max_investigation_cost": _num(max_investigation_cost),
            "max_candidate_count": _num(max_candidate_count, int),
        }
        limits = {k: v for k, v in raw.items() if v is not None}
        admin_api.patch_workspace(
            admin_api.WorkspacePatch(name=name or None, economic_limits=limits),
            request,
            session,
            user,
        )
    except (ValueError, HTTPException) as exc:
        return _settings_page(request, session, user, error=_err(exc))
    return RedirectResponse("/ui/settings?saved=budget#budget", status_code=303)


async def _save_proxy(request: Request, session: Session, user: User):
    from brandwatch import keys as keystore

    form = await request.form()
    tenancy.set_workspace_proxy(session, user.workspace_id, {
        "mode": form.get("mode"), "host": form.get("host"), "port": form.get("port"),
        "username": form.get("username"), "rotating": form.get("rotating") == "on",
    })  # fmt: skip
    tenancy.set_workspace_mobile_proxy(session, user.workspace_id, {
        "mode": "manual" if form.get("mobile_enabled") == "on" else "off", "host": form.get("mobile_host"),
        "port": form.get("mobile_port"), "username": form.get("mobile_username"),
    })  # fmt: skip
    tenancy.set_workspace_probe(session, user.workspace_id, str(form.get("proxy_kind") or ""), str(form.get("devices") or ""))
    settings = request.app.state.settings
    for field, secret in (
        ("password", "residential_proxy_password"),
        ("webshare_token", "webshare_token"),
        ("mobile_password", "mobile_proxy_password"),
    ):
        val = (form.get(field) or "").strip()
        if val:
            keystore.store_key(session, user.workspace_id, secret, val, settings)
    audit(
        session, workspace_id=user.workspace_id, actor_type="analyst", actor_id=user.id,
        action="workspace.proxy_updated", object_type="workspace", object_id=user.workspace_id,
        new={"mode": form.get("mode"), "host": form.get("host"), "proxy_kind": form.get("proxy_kind"), "devices": form.get("devices")},
    )  # fmt: skip
    return form


@router.post("/settings/proxy")
async def settings_proxy(
    request: Request,
    session: Annotated[Session, Depends(get_session, scope="function")],
    user: Annotated[User | None, Depends(ui_writer)],
):
    if user is None:
        return _login_redirect(request)
    _admin_only(user)
    await _save_proxy(request, session, user)
    return RedirectResponse("/ui/settings?saved=proxy#proxy", status_code=303)


@router.post("/settings/proxy/test")
async def settings_proxy_test(
    request: Request,
    session: Annotated[Session, Depends(get_session, scope="function")],
    user: Annotated[User | None, Depends(ui_writer)],
):
    if user is None:
        return _login_redirect(request)
    _admin_only(user)
    form = await _save_proxy(request, session, user)
    session.commit()
    from brandwatch import proxy as proxy_mod

    cfg = await tenancy.resolve_proxy(session, user.workspace_id, request.app.state.settings)
    if not cfg.enabled:
        kind = tenancy.workspace_probe_settings(session, user.workspace_id)["proxy_kind"]
        result: dict[str, Any] = {
            "error": f"the {kind} proxy is off or incomplete — fill its fields" + (" (or the Webshare token)" if kind == "residential" else "") + " and save first"
        }
    else:
        country = (form.get("test_country") or "").strip() or None
        try:
            result = await proxy_mod.test_proxy(cfg.url(country))
        except proxy_mod.ProxyError as exc:
            result = {"error": str(exc)}
    return _settings_page(request, session, user, proxy_test=result)


@router.post("/settings/lookups")
async def settings_lookups(
    request: Request,
    session: Annotated[Session, Depends(get_session, scope="function")],
    user: Annotated[User | None, Depends(ui_writer)],
):
    if user is None:
        return _login_redirect(request)
    _admin_only(user)
    form = await request.form()
    new = {
        kind: {
            "mode": "service" if form.get(f"{kind}_mode") == "service" else "python",
            "fallback": form.get(f"{kind}_fallback") == "on",
        }
        for kind in ("dns", "whois")
    }
    tenancy.set_workspace_lookups(session, user.workspace_id, new)
    audit(
        session, workspace_id=user.workspace_id, actor_type="analyst", actor_id=user.id,
        action="workspace.lookups_updated", object_type="workspace", object_id=user.workspace_id,
        new=new,
    )  # fmt: skip
    return RedirectResponse("/ui/settings?saved=lookups#lookups", status_code=303)


@router.post("/settings/users")
def settings_add_user(
    request: Request,
    session: Annotated[Session, Depends(get_session, scope="function")],
    user: Annotated[User | None, Depends(ui_writer)],
    email: Annotated[str, Form()],
    password: Annotated[str, Form()],
    role: Annotated[str, Form()] = "analyst",
):
    if user is None:
        return _login_redirect(request)
    _admin_only(user)
    try:
        admin_api.create_user(
            admin_api.UserCreate(email=email, password=password, role=UserRole(role)), session, user
        )
    except (ValueError, HTTPException) as exc:
        return _settings_page(request, session, user, error=_err(exc))
    return RedirectResponse("/ui/settings?saved=team#team", status_code=303)


@router.post("/settings/users/{user_id}")
def settings_patch_user(
    user_id: uuid.UUID,
    request: Request,
    session: Annotated[Session, Depends(get_session, scope="function")],
    user: Annotated[User | None, Depends(ui_writer)],
    role: Annotated[str, Form()] = "",
    is_active: Annotated[str, Form()] = "",
    password: Annotated[str, Form()] = "",
):
    if user is None:
        return _login_redirect(request)
    _admin_only(user)
    try:
        patch = admin_api.UserPatch(
            role=UserRole(role) if role else None,
            is_active=None if not is_active else is_active == "true",
            password=password or None,  # "set a new password" (a forgotten one is reset here)
        )
        admin_api.patch_user(user_id, patch, session, user)
    except (ValueError, HTTPException) as exc:
        return _settings_page(request, session, user, error=_err(exc))
    return RedirectResponse("/ui/settings?saved=team#team", status_code=303)


@router.post("/settings/api-keys/{provider}")
def settings_put_key(
    provider: str,
    request: Request,
    session: Annotated[Session, Depends(get_session, scope="function")],
    user: Annotated[User | None, Depends(ui_writer)],
    key: Annotated[str, Form()] = "",
):
    if user is None:
        return _login_redirect(request)
    _admin_only(user)
    try:
        admin_api.put_api_key(provider, admin_api.KeyPut(key=key), request, session, user)
    except (ValueError, HTTPException) as exc:
        return _settings_page(request, session, user, error=_err(exc))
    return RedirectResponse("/ui/settings?saved=keys#keys", status_code=303)


@router.post("/settings/api-keys/{provider}/delete")
def settings_delete_key(
    provider: str,
    request: Request,
    session: Annotated[Session, Depends(get_session, scope="function")],
    user: Annotated[User | None, Depends(ui_writer)],
):
    if user is None:
        return _login_redirect(request)
    _admin_only(user)
    try:
        admin_api.delete_api_key(provider, session, user)
    except HTTPException as exc:
        return _settings_page(request, session, user, error=_err(exc))
    return RedirectResponse("/ui/settings?saved=keys#keys", status_code=303)


@router.post("/settings/workspaces")
def settings_create_workspace(
    request: Request,
    session: Annotated[Session, Depends(get_session, scope="function")],
    user: Annotated[User | None, Depends(ui_writer)],
    name: Annotated[str, Form()],
    admin_email: Annotated[str, Form()],
    admin_password: Annotated[str, Form()],
):
    if user is None:
        return _login_redirect(request)
    _admin_only(user)
    try:
        body = admin_api.WorkspaceCreate(
            name=name, admin_email=admin_email, admin_password=admin_password
        )
        admin_api.create_workspace(body, session, user)
    except (ValueError, HTTPException) as exc:
        return _settings_page(request, session, user, error=_err(exc))
    return RedirectResponse("/ui/settings?saved=tenants#tenants", status_code=303)


@router.post("/settings/tokens")
def settings_create_token(
    request: Request,
    session: Annotated[Session, Depends(get_session, scope="function")],
    user: Annotated[User | None, Depends(ui_user)],  # viewers may create read tokens
    name: Annotated[str, Form()],
    scope: Annotated[str, Form()] = "read",
    expires_days: Annotated[str, Form()] = "90",
):
    if user is None:
        return _login_redirect(request)
    try:
        days = int(expires_days) if expires_days.strip() else None
        out = tokens_api.create_token(
            tokens_api.TokenCreate(name=name, scope=scope, expires_days=days), session, user
        )  # type: ignore[arg-type]
    except (ValueError, HTTPException) as exc:
        return _settings_page(request, session, user, error=_err(exc))
    # rendered directly — the secret is never put in a redirect URL — and shown exactly once
    return _settings_page(request, session, user, new_token=out["token"])


@router.post("/settings/tokens/{token_id}/revoke")
def settings_revoke_token(
    token_id: uuid.UUID,
    request: Request,
    session: Annotated[Session, Depends(get_session, scope="function")],
    user: Annotated[User | None, Depends(ui_user)],
):
    if user is None:
        return _login_redirect(request)
    tokens_api.revoke_token(token_id, session, user)
    return RedirectResponse("/ui/settings?saved=tokens#tokens", status_code=303)


@router.post("/settings/ml/train")
def settings_train(
    request: Request,
    session: Annotated[Session, Depends(get_session, scope="function")],
    user: Annotated[User | None, Depends(ui_writer)],
    source: Annotated[str, Form()] = "analyst",
):
    if user is None:
        return _login_redirect(request)
    try:
        ml_api.train_model(ml_api.TrainRequest(source=source), request, session, user)  # type: ignore[arg-type]
    except (ValueError, HTTPException) as exc:
        return _settings_page(request, session, user, error=_err(exc))
    return RedirectResponse("/ui/settings?saved=quality#quality", status_code=303)


# --------------------------------------------------------------------------------------------
# brand configuration editor + whitelist
# --------------------------------------------------------------------------------------------
def _facts(request: Request) -> dict:
    from brandwatch.about import project_facts

    return project_facts(request.app)


def _brand_error(
    request: Request, session: Session, user: User, brand_id: uuid.UUID, exc: Exception
) -> HTMLResponse:
    from brandwatch.api.ui import brand_context

    return _render(request, "brand_detail.html", user, error=_err(exc),
                   **brand_context(request, session, user, brand_id))  # fmt: skip


@router.post("/brands/{brand_id}/edit")
def brand_edit(
    brand_id: uuid.UUID,
    request: Request,
    session: Annotated[Session, Depends(get_session, scope="function")],
    user: Annotated[User | None, Depends(ui_writer)],
    name: Annotated[str, Form()] = "",
    domains: Annotated[str, Form()] = "",
    vertical: Annotated[str, Form()] = "",
    entry: Annotated[list[str], Form()] = [],  # noqa: B006 - one input per line of the official domains / app listings
):
    if user is None:
        return _login_redirect(request)
    domain_list = [d.strip() for d in [*entry, *domains.replace(",", "\n").splitlines()] if d.strip()]
    try:
        out = brands_api.update_brand(
            brand_id,
            brands_api.BrandPatch(name=name, vertical=vertical, domains=domain_list),
            session,
            user,
        )  # type: ignore[arg-type]
    except (ValueError, HTTPException) as exc:
        return _brand_error(request, session, user, brand_id, exc)
    flag = "domains" if out.get("domains_changed") else ("saved" if out.get("changed") else "same")
    return RedirectResponse(f"/ui/brands/{brand_id}?edited={flag}#edit", status_code=303)


@router.post("/brands/{brand_id}/profile")
async def brand_profile_save(
    brand_id: uuid.UUID,
    request: Request,
    session: Annotated[Session, Depends(get_session, scope="function")],
    user: Annotated[User | None, Depends(ui_writer)],
):
    """Brand profile form: kind, countries, ad keywords, official prices, authorised retailers."""
    if user is None:
        return _login_redirect(request)
    form = await request.form()
    try:
        body = profile_body(form, "retail" if form.get("kind") == "retail" else "service")
        out = brands_api.save_profile(brand_id, body, session, user)
    except (ValueError, HTTPException) as exc:
        return _brand_error(request, session, user, brand_id, exc)
    added = len(out.get("retailers_added") or [])
    return RedirectResponse(
        f"/ui/brands/{brand_id}?profile=saved&retailers={added or ''}#profile", status_code=303
    )


def profile_body(form: Any, kind: str, *, keep: dict[str, Any] | None = None) -> Any:
    """The brand-profile fields of a form (countries, ad keywords, official prices, retailers, the
    brand's own accounts) → ``BrandProfileBody``. ``keep`` supplies what the form does not carry."""
    split = lambda v: [x.strip() for x in str(v or "").replace(",", "\n").splitlines() if x.strip()]  # noqa: E731
    products = []
    names = form.getlist("product_name")
    pad = lambda xs: list(xs) + [""] * (len(names) - len(xs))  # noqa: E731 - every row has every column
    rows = zip(names, pad(form.getlist("product_price")), pad(form.getlist("product_currency")),
               pad(form.getlist("product_country")), pad(form.getlist("product_source")), strict=True)  # fmt: skip
    for name, price, cur, country, src in rows:
        if not str(name).strip() and not str(price).strip():
            continue  # an empty row
        try:
            products.append(brands_api.ProfileProduct(
                name=str(name).strip(), price=float(str(price).replace(",", ".")), currency=str(cur).strip().upper(),
                country=str(country).strip().upper(), source="ai" if src == "ai" else "analyst"))  # fmt: skip
        except (ValueError, TypeError) as exc:
            raise ValueError(
                f"product “{name}”: check the price, currency (3 letters) and country (2 letters) — {exc}"
            ) from exc
    keep = keep or {}
    return brands_api.BrandProfileBody(
        kind=kind,
        countries=[c.split()[0] for c in split(form.get("countries")) if c],
        ad_keywords=[x for x in str(form.get("ad_keywords") or "").splitlines() if x.strip()],
        products=products,
        retailers=split(form.get("retailers")),
        official_social=split(form.get("official_social")) if "official_social" in form else keep.get("official_social"),
        **{k: int(str(form.get(k))) for k in ("ads_per_search", "ad_searches_max", "shops_checked_max")
           if str(form.get(k) or "").strip().isdigit()},
    )


# ------------------------------------------------------------------------------------------
# Set-up before the first scan: the Google queries and (retail) the profile, approved together
# ------------------------------------------------------------------------------------------
def needs_setup(brand: dict[str, Any], honour_skip: bool = True) -> bool:
    """A brand whose first scan would skip Google (queries not approved) or search ads blind
    (a retail brand without countries). ``honour_skip``: an analyst who chose "start now without setting up" is not asked
    again (the brand page then shows the normal Start scan and a "finish set-up" link)."""
    if honour_skip and (brand.get("profile") or {}).get("setup_skipped"):
        return False
    cfg = brand.get("config") or {}
    search_on = "search" in ((cfg.get("detection") or {}).get("streams") or [])
    pending = search_on and not (brand.get("search_queries") or {}).get("approved")
    retail_blind = brand.get("kind") == "retail" and not (brand.get("profile") or {}).get("countries")
    ai = brand.get("ai_answers") or {}
    ai_pending = bool(ai.get("on")) and not (ai.get("prompts") or {}).get("approved")
    return bool(pending or retail_blind or ai_pending)


def _setup_context(request: Request, session: Session, user: User, brand_id: uuid.UUID, error: str | None = None) -> dict[str, Any]:
    from brandwatch import keys as keystore

    brand = brands_api.get_brand(brand_id, session, user)
    cfg = brand.get("config") or {}
    settings = request.app.state.settings
    return {"brand": brand, "search_on": "search" in ((cfg.get("detection") or {}).get("streams") or []),
            "retail": brand.get("kind") == "retail", "error": error, "active": "brands",
            # "Suggest with AI" needs a model: say so instead of a button that fails
            "ai_ready": keystore.provider_ready(session, user.workspace_id, settings, "openai")}  # fmt: skip


@router.get("/brands/{brand_id}/setup", response_class=HTMLResponse)
def brand_setup_page(
    brand_id: uuid.UUID,
    request: Request,
    session: Annotated[Session, Depends(get_session, scope="function")],
    user: Annotated[User | None, Depends(ui_writer)],
):
    if user is None:
        return _login_redirect(request)
    return _render(request, "brand_setup.html", user, **_setup_context(request, session, user, brand_id))


@router.post("/brands/{brand_id}/setup")
async def brand_setup_save(
    brand_id: uuid.UUID,
    request: Request,
    session: Annotated[Session, Depends(get_session, scope="function")],
    user: Annotated[User | None, Depends(ui_writer)],
):
    """Approve the queries and save the profile — then, for "Approve & start the scan", start it."""
    if user is None:
        return _login_redirect(request)
    form = await request.form()
    ctx = _setup_context(request, session, user, brand_id)
    brand = ctx["brand"]
    try:
        if ctx["retail"]:
            brands_api.save_profile(brand_id, profile_body(form, "retail", keep=brand.get("profile")), session, user)
        # the size of the scan: the brand's defaults (saved), so this scan and the automatic ones use them
        sizes = {k: int(str(form.get(k)).strip()) for k in ("max_candidates", "max_names_checked") if str(form.get(k) or "").strip().isdigit()}
        for key, label, top in (("max_candidates", "Max sites to visit", 5000), ("max_names_checked", "Max look-alike names to check", 100_000)):
            if key in sizes and not 1 <= sizes[key] <= top:
                raise ValueError(f"{label} must be between 1 and {top:,}")
        current = (brand.get("config") or {}).get("detection") or {}
        sizes = {k: v for k, v in sizes.items() if v != current.get(k)}
        if sizes:
            brands_api.patch_config(brand_id, brands_api.ConfigPatch(detection=sizes), session, user)
        if form.get("raise_cap"):  # "raise the workspace limit to my number": the size is kept, the limit follows it
            _admin_only(user)
            want = sizes.get("max_candidates") or int(current.get("max_candidates") or 0)
            if want:
                admin_api.patch_workspace(admin_api.WorkspacePatch(economic_limits={"max_candidate_count": want}), request, session, user)
            return RedirectResponse(f"/ui/brands/{brand_id}/setup?cap=raised#s-size", status_code=303)
        ai_texts = [str(q) for q in form.getlist("aiq") if str(q).strip()]
        if ai_texts:  # the AI-answers step: approved with the rest
            langs, topics = list(form.getlist("ailang")), list(form.getlist("aitopic"))
            rows = [{"text": t, "lang": langs[i] if i < len(langs) else "", "topic": topics[i] if i < len(topics) else ""} for i, t in enumerate(ai_texts)]
            brands_api.approve_ai_prompts(brand_id, brands_api.AiPromptsBody(prompts=rows), session, user)
        queries = [str(q) for q in form.getlist("q") if str(q).strip()]
        if ctx["search_on"]:
            if not queries:
                raise ValueError("add at least one Google query — or switch Google search off in the detection track")
            brands_api.approve_search_queries(brand_id, brands_api.SearchQueriesBody(queries=queries), session, user)
        if form.get("action") == "scan":
            out = brands_api.start_scan(brand_id, brands_api.ScanRequest(), request, session, user)
            return RedirectResponse(f"/ui/jobs/{out['job_id']}", status_code=303)
    except (ValueError, HTTPException) as exc:
        session.rollback()
        msg = exc.detail if isinstance(exc, HTTPException) else str(exc)
        return _render(request, "brand_setup.html", user, **_setup_context(request, session, user, brand_id, error=str(msg)))
    return RedirectResponse(f"/ui/brands/{brand_id}?setup=saved", status_code=303)


@router.post("/brands/{brand_id}/regions")
async def brand_region_create(
    brand_id: uuid.UUID,
    request: Request,
    session: Annotated[Session, Depends(get_session, scope="function")],
    user: Annotated[User | None, Depends(ui_writer)],
):
    """Add a country site as a regional campaign; the analyst lands on its set-up page."""
    if user is None:
        return _login_redirect(request)
    form = await request.form()
    split = lambda v: [x.strip() for x in str(v or "").replace(",", "\n").splitlines() if x.strip()]  # noqa: E731
    try:
        out = brands_api.create_region(
            brand_id,
            brands_api.RegionCreate(region=str(form.get("region") or "").strip(), domains=split(form.get("domains")),
                                    countries=split(form.get("countries")), search_lang=str(form.get("search_lang") or "").strip() or None),
            session, user,
        )  # fmt: skip
    except (ValueError, HTTPException) as exc:
        session.rollback()
        return _brand_error(request, session, user, brand_id, exc)
    return RedirectResponse(f"/ui/brands/{out['id']}/setup", status_code=303)


@router.post("/brands/{brand_id}/regions/sync")
def brand_region_sync(
    brand_id: uuid.UUID,
    request: Request,
    session: Annotated[Session, Depends(get_session, scope="function")],
    user: Annotated[User | None, Depends(ui_writer)],
):
    if user is None:
        return _login_redirect(request)
    try:
        brands_api.sync_region(brand_id, session, user)
    except (ValueError, HTTPException) as exc:
        session.rollback()
        return _brand_error(request, session, user, brand_id, exc)
    return RedirectResponse(f"/ui/brands/{brand_id}?region=synced#regions", status_code=303)


@router.post("/brands/{brand_id}/country-sites")
async def brand_country_site(
    brand_id: uuid.UUID,
    request: Request,
    session: Annotated[Session, Depends(get_session, scope="function")],
    user: Annotated[User | None, Depends(ui_writer)],
):
    """A country site found on the official homepage: region / another official domain / ignore."""
    if user is None:
        return _login_redirect(request)
    form = await request.form()
    try:
        out = brands_api.country_site_action(
            brand_id,
            brands_api.CountrySiteAction(
                domain=str(form.get("domain") or ""), action=str(form.get("action") or "ignore"),  # type: ignore[arg-type]
                region=str(form.get("region") or "").strip() or None,
                countries=[c for c in str(form.get("countries") or "").replace(",", " ").split() if c]),
            session, user,
        )  # fmt: skip
    except (ValueError, HTTPException) as exc:
        session.rollback()
        return _brand_error(request, session, user, brand_id, exc)
    if out["action"] == "region":
        return RedirectResponse(f"/ui/brands/{out['region_id']}/setup", status_code=303)
    return RedirectResponse(f"/ui/brands/{brand_id}?region={'added' if out['action'] == 'domain' else 'ignored'}#regions", status_code=303)


@router.post("/brands/{brand_id}/site-links")
async def brand_site_link(
    brand_id: uuid.UUID,
    request: Request,
    session: Annotated[Session, Depends(get_session, scope="function")],
    user: Annotated[User | None, Depends(ui_writer)],
):
    """A link found on the official homepage: an official domain / a whitelisted partner / our account / ignore."""
    if user is None:
        return _login_redirect(request)
    form = await request.form()
    try:
        out = brands_api.site_link_action(
            brand_id, brands_api.SiteLinkAction(key=str(form.get("key") or ""), action=str(form.get("action") or "ignore")),  # type: ignore[arg-type]
            session, user,
        )  # fmt: skip
    except (ValueError, HTTPException) as exc:
        session.rollback()
        return _brand_error(request, session, user, brand_id, exc)
    return RedirectResponse(f"/ui/brands/{brand_id}?links={out['action']}#sitelinks", status_code=303)


@router.post("/brands/{brand_id}/ai-answers")
async def brand_ai_answers_switch(
    brand_id: uuid.UUID,
    request: Request,
    session: Annotated[Session, Depends(get_session, scope="function")],
    user: Annotated[User | None, Depends(ui_writer)],
):
    """AI answers on / off for this brand (and, from the panel, which assistants are asked)."""
    if user is None:
        return _login_redirect(request)
    form = await request.form()
    patch: dict[str, Any] = {}
    if "on" in form:
        patch["ai_answers"] = str(form.get("on") or "") == "1"
    if "engines_form" in form:
        patch["ai_engines"] = [e for e in form.getlist("engines") if e in ("chatgpt", "gemini", "google_ai_mode")] or ["chatgpt"]
    for key, top in (("ai_prompts_max", 20), ("contacts_pages_max", 150)):
        raw = str(form.get(key) or "").strip()
        if raw.isdigit():
            patch[key] = max(1, min(top, int(raw)))
    try:
        brands_api.patch_config(brand_id, brands_api.ConfigPatch(detection=patch), session, user)
    except (ValueError, HTTPException) as exc:
        session.rollback()
        return _brand_error(request, session, user, brand_id, exc)
    flag = "on" if patch.get("ai_answers") else ("off" if "ai_answers" in patch else "saved")
    return RedirectResponse(f"/ui/brands/{brand_id}?ai={flag}#ai-answers", status_code=303)


@router.post("/brands/{brand_id}/ai-prompts")
async def brand_ai_prompts(
    brand_id: uuid.UUID,
    request: Request,
    session: Annotated[Session, Depends(get_session, scope="function")],
    user: Annotated[User | None, Depends(ui_writer)],
):
    """The questions asked to AI assistants: approve the list as edited, or let the AI propose new ones (not saved)."""
    if user is None:
        return _login_redirect(request)
    form = await request.form()
    try:
        if form.get("action") == "suggest":
            from brandwatch.api.ui import brand_context

            out = await brands_api.suggest_ai_prompts(brand_id, request, session, user)
            ctx = brand_context(request, session, user, brand_id)
            ctx["brand"]["ai_answers"]["prompts"]["proposal"] = out["prompts"]
            ctx["brand"]["ai_answers"]["suggested"] = True
            return _render(request, "brand_detail.html", user, **ctx)
        texts = [str(q) for q in form.getlist("q") if str(q).strip()]
        langs = list(form.getlist("lang"))
        topics = list(form.getlist("topic"))
        rows = [{"text": t, "lang": langs[i] if i < len(langs) else "", "topic": topics[i] if i < len(topics) else ""} for i, t in enumerate(texts)]
        brands_api.approve_ai_prompts(brand_id, brands_api.AiPromptsBody(prompts=rows), session, user)
    except (ValueError, HTTPException) as exc:
        session.rollback()
        return _brand_error(request, session, user, brand_id, exc)
    return RedirectResponse(f"/ui/brands/{brand_id}?ai=approved#ai-answers", status_code=303)


@router.post("/brands/{brand_id}/known-contacts")
async def brand_known_contact(
    brand_id: uuid.UUID,
    request: Request,
    session: Annotated[Session, Depends(get_session, scope="function")],
    user: Annotated[User | None, Depends(ui_writer)],
):
    """A contact the brand uses that its website does not show: never reported as wrong."""
    if user is None:
        return _login_redirect(request)
    form = await request.form()
    try:
        brands_api.known_contact(brand_id, brands_api.KnownContactBody(value=str(form.get("value") or "").strip() or "-",
                                                                        action=str(form.get("action") or "add"),  # type: ignore[arg-type]
                                                                        note=str(form.get("note") or "") or None), session, user)  # fmt: skip
    except (ValueError, HTTPException) as exc:
        session.rollback()
        return _brand_error(request, session, user, brand_id, exc)
    return RedirectResponse(f"/ui/brands/{brand_id}?ai=contact#ai-answers", status_code=303)


@router.post("/brands/{brand_id}/social")
async def brand_social_switch(
    brand_id: uuid.UUID,
    request: Request,
    session: Annotated[Session, Depends(get_session, scope="function")],
    user: Annotated[User | None, Depends(ui_writer)],
):
    """Social media scanning on / off for this brand, whatever its detection track."""
    if user is None:
        return _login_redirect(request)
    form = await request.form()
    on = str(form.get("on") or "") == "1"
    try:
        brands_api.patch_config(brand_id, brands_api.ConfigPatch(detection={"social_accounts": on}), session, user)
    except (ValueError, HTTPException) as exc:
        session.rollback()
        return _brand_error(request, session, user, brand_id, exc)
    return RedirectResponse(f"/ui/brands/{brand_id}?social={'on' if on else 'off'}#scan", status_code=303)


@router.post("/brands/{brand_id}/ads")
async def brand_ads_switch(
    brand_id: uuid.UUID,
    request: Request,
    session: Annotated[Session, Depends(get_session, scope="function")],
    user: Annotated[User | None, Depends(ui_writer)],
):
    """Phishing ads on / off for a brand nobody else sells (a resold brand's ads are always searched, for scam shops)."""
    if user is None:
        return _login_redirect(request)
    form = await request.form()
    on = str(form.get("on") or "") == "1"
    try:
        brands_api.patch_config(brand_id, brands_api.ConfigPatch(detection={"phishing_ads": on}), session, user)
    except (ValueError, HTTPException) as exc:
        session.rollback()
        return _brand_error(request, session, user, brand_id, exc)
    return RedirectResponse(f"/ui/brands/{brand_id}?ads={'on' if on else 'off'}#scan", status_code=303)


@router.post("/brands/{brand_id}/reach")
async def brand_reach_save(
    brand_id: uuid.UUID,
    request: Request,
    session: Annotated[Session, Depends(get_session, scope="function")],
    user: Annotated[User | None, Depends(ui_writer)],
):
    """How far to look on social media and in the ads: accounts checked per scan, the phishing-ads switch (a brand nobody
    else sells) and the ad numbers (detection/ad_settings.py, kept in the brand profile)."""
    if user is None:
        return _login_redirect(request)
    from brandwatch.db.models import Brand
    from brandwatch.detection import ad_settings

    form = await request.form()
    det: dict[str, Any] = {}
    if str(form.get("social_accounts_max") or "").strip().isdigit():
        det["social_accounts_max"] = max(1, min(50, int(str(form.get("social_accounts_max")))))
    if "phishing_ads_form" in form:
        det["phishing_ads"] = form.get("phishing_ads") == "on"
    try:
        if det:
            brands_api.patch_config(brand_id, brands_api.ConfigPatch(detection=det), session, user)
        nums = {k: int(str(form.get(k))) for k in ("ads_per_search", "ad_searches_max", "shops_checked_max") if str(form.get(k) or "").strip().isdigit()}
        if nums:
            row = session.get(Brand, brand_id)
            if row is None or row.workspace_id != user.workspace_id:
                raise HTTPException(404, "brand not found")
            clamped = ad_settings.settings({**(row.profile or {}), **nums})
            row.profile = {**(row.profile or {}), **{k: clamped[k] for k in nums}}
            session.commit()
    except (ValueError, HTTPException) as exc:
        session.rollback()
        return _brand_error(request, session, user, brand_id, exc)
    return RedirectResponse(f"/ui/brands/{brand_id}?reach=saved#reach", status_code=303)


@router.post("/brands/{brand_id}/schedule")
async def brand_schedule_save(
    brand_id: uuid.UUID,
    request: Request,
    session: Annotated[Session, Depends(get_session, scope="function")],
    user: Annotated[User | None, Depends(ui_writer)],
):
    """Automatic scans panel: on / off, frequency, preferred local hour, tasks."""
    if user is None:
        return _login_redirect(request)
    form = await request.form()
    hour = str(form.get("hour") or "")
    try:
        brands_api.save_schedule(
            brand_id,
            brands_api.ScheduleBody(
                enabled=form.get("enabled") == "on", every_hours=int(str(form.get("every_hours") or 24)),
                hour=None if hour in ("", "any") else int(hour), tz_offset=int(str(form.get("tz_offset") or 0)),
                tasks=[str(t) for t in form.getlist("tasks")],
            ),
            session, user,
        )  # fmt: skip
    except (ValueError, HTTPException) as exc:
        return _brand_error(request, session, user, brand_id, exc)
    return RedirectResponse(f"/ui/brands/{brand_id}?schedule=saved#schedule", status_code=303)


@router.post("/brands/{brand_id}/search-queries")
async def brand_search_queries_save(
    brand_id: uuid.UUID,
    request: Request,
    session: Annotated[Session, Depends(get_session, scope="function")],
    user: Annotated[User | None, Depends(ui_writer)],
):
    """Google queries panel: one input per query; saving approves the list."""
    if user is None:
        return _login_redirect(request)
    form = await request.form()
    try:
        brands_api.approve_search_queries(
            brand_id, brands_api.SearchQueriesBody(queries=[str(q) for q in form.getlist("q")]), session, user
        )  # fmt: skip
        if form.get("then") == "scan":  # the pop-up's "Approve & start scan"
            mc, mn = str(form.get("max_candidates") or ""), str(form.get("max_names") or "")
            out = brands_api.start_scan(
                brand_id,
                brands_api.ScanRequest(max_candidates=int(mc) if mc.strip().isdigit() else None,
                                       max_names=int(mn) if mn.strip().isdigit() else None,
                                       rebuild_baseline=form.get("rebuild_baseline") == "on"),
                request, session, user,
            )  # fmt: skip
            return RedirectResponse(f"/ui/jobs/{out['job_id']}", status_code=303)
    except (ValueError, HTTPException) as exc:
        return _brand_error(request, session, user, brand_id, exc)
    return RedirectResponse(f"/ui/brands/{brand_id}?queries=approved#queries", status_code=303)


@router.post("/brands/{brand_id}/config")
async def brand_config_save(
    brand_id: uuid.UUID,
    request: Request,
    session: Annotated[Session, Depends(get_session, scope="function")],
    user: Annotated[User | None, Depends(ui_writer)],
):
    if user is None:
        return _login_redirect(request)
    form = await request.form()
    take_write_lock(session)
    try:
        preset, detection, scoring, custom = brands_api.config_patch_from_form(form)
        # track mode: the chosen preset's profile replaces every detection knob;
        # custom mode: the preset is the base and the form's values are layered on top
        brands_api.patch_config(
            brand_id,
            brands_api.ConfigPatch(
                # in track mode the brand's own switches on the form (the countries it is searched in) still count
                preset=preset, detection=detection if custom else ({k: detection[k] for k in BRAND_SWITCHES if k in detection} or None),
                scoring=scoring or None
            ),
            session, user, apply_rescore=form.get("apply_rescore") == "on",
        )  # fmt: skip
        if form.get("then_scan"):
            session.commit()  # the job thread must see the new configuration
            out = brands_api.start_scan(brand_id, brands_api.ScanRequest(), request, session, user)
            return RedirectResponse(f"/ui/jobs/{out['job_id']}", status_code=303)
    except (ValueError, HTTPException) as exc:
        return _brand_error(request, session, user, brand_id, exc)
    return RedirectResponse(f"/ui/brands/{brand_id}#config", status_code=303)


@router.post("/brands/{brand_id}/delete")
def brand_delete(
    brand_id: uuid.UUID,
    request: Request,
    session: Annotated[Session, Depends(get_session, scope="function")],
    user: Annotated[User | None, Depends(ui_writer)],
):
    if user is None:
        return _login_redirect(request)
    try:
        brands_api.delete_brand(brand_id, request, session, user)
    except (ValueError, HTTPException) as exc:
        return _brand_error(request, session, user, brand_id, exc)
    return RedirectResponse("/ui/brands", status_code=303)


@router.post("/campaigns/{campaign_id}/delete")
def campaign_delete(
    campaign_id: uuid.UUID,
    request: Request,
    session: Annotated[Session, Depends(get_session, scope="function")],
    user: Annotated[User | None, Depends(ui_writer)],
):
    if user is None:
        return _login_redirect(request)
    try:
        campaigns_api.delete_campaign(campaign_id, session, user)
    except HTTPException:
        return RedirectResponse(f"/ui/campaigns/{campaign_id}", status_code=303)
    return RedirectResponse("/ui/campaigns", status_code=303)


@router.post("/brands/{brand_id}/whitelist")
def brand_whitelist_add(
    brand_id: uuid.UUID,
    request: Request,
    session: Annotated[Session, Depends(get_session, scope="function")],
    user: Annotated[User | None, Depends(ui_writer)],
    domain: Annotated[str, Form()],
    kind: Annotated[str, Form()] = "partner",
):
    if user is None:
        return _login_redirect(request)
    try:
        brands_api.add_whitelist(
            brand_id, brands_api.WhitelistAdd(domain=domain, kind=kind), session, user
        )  # type: ignore[arg-type]
    except (ValueError, HTTPException) as exc:
        return _brand_error(request, session, user, brand_id, exc)
    return RedirectResponse(f"/ui/brands/{brand_id}#whitelist", status_code=303)


@router.post("/brands/{brand_id}/whitelist/{domain}/delete")
def brand_whitelist_remove(
    brand_id: uuid.UUID,
    domain: str,
    request: Request,
    session: Annotated[Session, Depends(get_session, scope="function")],
    user: Annotated[User | None, Depends(ui_writer)],
):
    if user is None:
        return _login_redirect(request)
    brands_api.remove_whitelist(brand_id, domain, session, user)
    return RedirectResponse(f"/ui/brands/{brand_id}#whitelist", status_code=303)
