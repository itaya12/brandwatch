"""Server-rendered analyst UI (Phase 1 "analyst core loop", spec §17): Brands → run scan → Live
Console → Findings table → Explain Finding with side-by-side screenshots and the observation
timeline → confirm / dismiss. Jinja2 over the same service functions the JSON API uses; the
Next.js command-center UX (globe, animations) is layered on later, when the loop already works.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated, Any

import sqlalchemy as sa
from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session

from brandwatch.api import brands as brands_api
from brandwatch.api import campaigns as campaigns_api
from brandwatch.api import candidates as candidates_api
from brandwatch.api import dashboard as dashboard_api
from brandwatch.api import findings as findings_api
from brandwatch.api import reports as reports_api
from brandwatch.api import scans as scans_api
from brandwatch.api import ui_stats
from brandwatch.api.auth import (
    SESSION_COOKIE,
    audit,
    create_access_token,
    decode_token,
    verify_password,
)
from brandwatch.api.deps import get_session, get_settings_dep
from brandwatch.config.brand_config import (
    BRAND_SWITCHES,
    PRESET_INFO,
    PRESET_PROFILES,
    SIGNAL_GROUPS,
)
from brandwatch.config.settings import Settings
from brandwatch.db.base import take_write_lock
from brandwatch.db.enums import (
    AnalystVerdict,
    CandidateState,
    FindingState,
    Severity,
    TakedownState,
    UserRole,
)
from brandwatch.db.models import Brand, Candidate, Finding, ScanJob, User
from brandwatch.detection import regions as regions_mod
from brandwatch.detection.normalize import APP_STORES
from brandwatch.ui import markets as markets_ui

router = APIRouter(prefix="/ui", include_in_schema=False)
templates = Jinja2Templates(directory=str(Path(__file__).parent / "templates"))
templates.env.globals.update(
    {
        "Severity": [s.value for s in Severity],
        "FindingStates": [s.value for s in FindingState],
        "CandidateStates": [s.value for s in CandidateState],
        "Verdicts": [v.value for v in AnalystVerdict if v is not AnalystVerdict.PHISHING],
        "SIGNAL_GROUPS": SIGNAL_GROUPS,
        "TakedownStates": [s.value for s in TakedownState],
        "APP_STORE_HOSTS": sorted(APP_STORES),  # the "official domains" rows tell a store link from a domain
        # the search-market picker: every country with its default language, and the languages that can be ticked
        "MARKET_DATA": markets_ui.market_data(),
        "search_markets": markets_ui.markets_of,  # (detection) -> [{"country", "langs"}]: what the picker shows
        "search_pairs": markets_ui.pairs_of,  # (detection) -> [(country, lang)]: what a scan runs
    }
)
from brandwatch.api import labels as _labels  # noqa: E402
from brandwatch.api import palette as _palette  # noqa: E402

_labels.register(templates)  # one vocabulary for every screen
_palette.register(templates)  # one palette for every screen


def ui_user(
    request: Request,
    session: Annotated[Session, Depends(get_session, scope="function")],
    settings: Annotated[Settings, Depends(get_settings_dep)],
) -> User | None:
    token = request.cookies.get(SESSION_COOKIE)
    if not token:
        return None
    try:
        claims = decode_token(token, settings)
        user = session.get(User, uuid.UUID(str(claims.get("sub"))))
    except Exception:  # noqa: BLE001 - any bad cookie means "not logged in"
        return None
    return user if user is not None and user.is_active else None


def ui_writer(user: Annotated[User | None, Depends(ui_user)]) -> User | None:
    """POST routes of the UI: viewers have read-only access (spec §14 RBAC)."""
    if user is not None and user.role is UserRole.VIEWER:
        raise HTTPException(403, "viewers have read-only access")
    return user


def render_error(request: Request, status_code: int, message: str) -> HTMLResponse:
    """A UI error as a page (nav, plain message, ways back) — never a raw JSON body."""
    user = None
    try:
        factory = request.app.state.session_factory
        with factory() as session:
            user = ui_user(request, session, request.app.state.settings)
            if user is not None:
                session.expunge(user)
    except Exception:  # noqa: BLE001 - the error page must always render
        user = None
    titles = {400: "That request did not make sense", 401: "Please sign in", 403: "Not allowed",
              404: "Not found", 409: "Not possible right now", 422: "Some input was not valid"}  # fmt: skip
    resp = _render(request, "error.html", user, status_code=status_code,
                   title=titles.get(status_code, "Something went wrong"), message=message)  # fmt: skip
    resp.status_code = status_code
    return resp


def _render(request: Request, name: str, user: User | None, **ctx: Any) -> HTMLResponse:
    can_write = user is not None and user.role is not UserRole.VIEWER
    is_admin = user is not None and user.role is UserRole.ADMIN
    nav = nav_counts(request, user) if user is not None else {}
    return templates.TemplateResponse(
        request, name, {"user": user, "can_write": can_write, "is_admin": is_admin, "nav": nav, **ctx}
    )


_NAV_CACHE: dict[uuid.UUID, tuple[float, dict[str, int]]] = {}
NAV_TTL = 60.0  # seconds


def nav_counts(request: Request, user: User) -> dict[str, int]:
    """The numbers in the navigation bar: open findings, and confirmed sites whose takedown was not sent. One small query,
    cached for a minute per workspace; a page that follows an action (?flash=, ?bulk=) recounts."""
    import time

    from brandwatch.db.models import TakedownDraft

    now = time.monotonic()
    hit = _NAV_CACHE.get(user.workspace_id)
    fresh = not any(k in request.query_params for k in ("flash", "bulk", "saved"))
    if hit and fresh and now - hit[0] < NAV_TTL:
        return hit[1]
    factory = getattr(request.app.state, "session_factory", None)
    if factory is None:
        return {}
    with factory() as s:
        ws = s.scalars(sa.select(Brand.id).where(Brand.workspace_id == user.workspace_id)).all()
        if not ws:
            out = {"findings": 0, "takedowns": 0}
        else:
            awake = sa.or_(Finding.snoozed_until.is_(None), Finding.snoozed_until <= datetime.now(UTC))  # a snoozed finding does not wait yet
            open_n = s.scalar(sa.select(sa.func.count()).select_from(Finding).where(Finding.brand_id.in_(ws), Finding.state == FindingState.OPEN, awake)) or 0
            confirmed = s.scalars(sa.select(Finding.id).where(Finding.brand_id.in_(ws), Finding.state == FindingState.CONFIRMED, Finding.kind != "ai_answer")).all()
            sent = set(s.scalars(sa.select(TakedownDraft.finding_id).where(
                TakedownDraft.finding_id.in_(confirmed) if confirmed else sa.false(),
                TakedownDraft.state.notin_([TakedownState.DRAFT, TakedownState.REVIEW, TakedownState.APPROVED, TakedownState.REOPENED]))).all())  # fmt: skip
            out = {"findings": int(open_n), "takedowns": sum(1 for f in confirmed if f not in sent)}
    _NAV_CACHE[user.workspace_id] = (now, out)
    return out


def _uuid_or_none(value: str | None) -> uuid.UUID | None:
    """'' (the 'all' option of a filter) or garbage → no filter, never a 422."""
    try:
        return uuid.UUID(str(value)) if value else None
    except ValueError:
        return None


def _enum_or_none(enum_cls: Any, value: str | None) -> Any:
    try:
        return enum_cls(value) if value else None
    except ValueError:
        return None


def _login_redirect(request: Request) -> RedirectResponse:
    return RedirectResponse(f"/ui/login?next={request.url.path}", status_code=303)


# --------------------------------------------------------------------------------------------
# auth
# --------------------------------------------------------------------------------------------
def landing_for(session: Session, user: User) -> str:
    """Where a signed-in user starts: the brands page (with the getting-started checklist) until the
    workspace has a brand, the dashboard afterwards."""
    has_brand = session.scalar(
        sa.select(Brand.id).where(Brand.workspace_id == user.workspace_id).limit(1)
    )
    return "/ui/dashboard" if has_brand else "/ui/brands"


@router.get("/login", response_class=HTMLResponse)
def login_page(
    request: Request, session: Annotated[Session, Depends(get_session, scope="function")],
    user: Annotated[User | None, Depends(ui_user)], next: str = "",
):  # fmt: skip
    if user:
        return RedirectResponse(
            next if next.startswith("/ui/") else landing_for(session, user), status_code=303
        )
    return _render(request, "login.html", None, error=None, next=next,
                   demo_mode=request.app.state.settings.demo_mode)  # fmt: skip


@router.post("/login")
def login_submit(
    request: Request,
    session: Annotated[Session, Depends(get_session, scope="function")],
    settings: Annotated[Settings, Depends(get_settings_dep)],
    email: Annotated[str, Form()],
    password: Annotated[str, Form()],
    next: Annotated[str, Form()] = "",
):
    user = session.scalars(sa.select(User).where(User.email == email.strip())).first()
    ok = user is not None and verify_password(user.password_hash, password)
    if not ok or not user.is_active:
        if user is not None:
            audit(session, workspace_id=user.workspace_id, actor_type="analyst", actor_id=user.id,
                  action="user.login_failed", object_type="user", object_id=user.id)  # fmt: skip
        # a disabled account is told so, but only to someone who knows its password (no account probing)
        msg = ("This account is disabled. An admin turns it back on in Settings → Team." if ok
               else "Wrong username or password. Forgot it? An admin sets a new one in Settings → Team.")  # fmt: skip
        return _render(request, "login.html", None, error=msg, next=next,
                       demo_mode=request.app.state.settings.demo_mode)  # fmt: skip
    audit(session, workspace_id=user.workspace_id, actor_type="analyst", actor_id=user.id,
          action="user.login", object_type="user", object_id=user.id)  # fmt: skip
    from datetime import UTC, datetime

    user.record_login(datetime.now(UTC))
    token, expires_in = create_access_token(user, settings)
    target = next if next.startswith("/ui/") else landing_for(session, user)
    resp = RedirectResponse(target, status_code=303)
    resp.set_cookie(SESSION_COOKIE, token, max_age=expires_in, httponly=True, samesite="lax",
                    secure=settings.environment == "production")  # fmt: skip
    return resp


@router.get("/logout")
def logout():
    resp = RedirectResponse("/ui/login", status_code=303)
    resp.delete_cookie(SESSION_COOKIE)
    return resp


# --------------------------------------------------------------------------------------------
# brands
# --------------------------------------------------------------------------------------------
@router.get("/brands", response_class=HTMLResponse)
def brands_page(
    request: Request,
    session: Annotated[Session, Depends(get_session, scope="function")],
    user: Annotated[User | None, Depends(ui_user)],
):
    if user is None:
        return _login_redirect(request)
    brands = brands_api.list_brands(session, user)
    return _render(
        request,
        "brands.html",
        user,
        brands=brands,
        cards=ui_stats.brand_cards(session, user, brands),
        jobs=scans_api.list_jobs(session, user, limit=14),
        copy_sources=_copy_sources(session, brands),
        PRESETS=presets_view(),
        active="brands",
        **_add_form_ctx(request, session, user),
    )


def _add_form_ctx(request: Request, session: Session, user: User) -> dict[str, Any]:
    """What the add-brand form needs besides the tracks: the workspace's site cap (the Deep warning) and the
    country-code → markets map (the countries follow the main domain as it is typed)."""
    from brandwatch import tenancy
    from brandwatch.detection import markets as markets_mod

    cap = tenancy.workspace_limits(session, user.workspace_id, request.app.state.settings).max_candidate_count or 0
    return {"ws_cap": int(cap), "cc_markets": markets_mod.tld_markets()}


def _copy_sources(session: Session, brands: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """The detection parameters of each existing brand, so a new brand can start from them ("copy the parameters
    of ShopNova") instead of from a track's defaults."""
    from brandwatch import tenancy

    keys = ("streams", "tlds", "max_candidates", "max_names_checked", "search_queries_max", "search_geo", "search_lang", "search_markets", "watch_window_days",
            "watch_cadence_hours", "residential_probe", "residential_country", "cloaking_probes", "social_accounts",
            "ai_second_opinion", "auto_map_on_confirm", "auto_investigate_on_confirm")  # fmt: skip
    out = []
    for b in brands:
        cfg = tenancy.effective_brand_config(session, uuid.UUID(str(b["id"])))
        det = cfg.detection.model_dump()
        out.append({"id": str(b["id"]), "name": b["name"], "preset": cfg.preset,
                    "detection": {k: det.get(k) for k in keys}, "thresholds": dict(cfg.scoring.thresholds.model_dump())})  # fmt: skip
    return out


@router.post("/brands")
async def brands_create(
    request: Request,
    session: Annotated[Session, Depends(get_session, scope="function")],
    user: Annotated[User | None, Depends(ui_writer)],
):
    if user is None:
        return _login_redirect(request)
    form = await request.form()
    take_write_lock(session)  # an async handler: wait for a running scan's checkpoint instead of "database is locked"
    # one input per line ("entry"); the old single box ("domains": comma / newline separated) still works
    domain_list = [str(d).strip() for d in [*form.getlist("entry"), *str(form.get("domains") or "").replace(",", "\n").splitlines()] if str(d).strip()]
    try:
        # "Customise parameters" on the form: the visible parameters are saved on top of the chosen track
        preset, detection, scoring, custom = brands_api.config_patch_from_form(form, default_mode="preset")
        if form.get("markets_auto") == "1":  # the analyst did not touch the countries: the main domain decides (create_brand)
            for k in ("search_markets", "search_geo", "search_lang"):
                detection.pop(k, None)
        body = brands_api.BrandCreate(
            name=str(form.get("name") or ""),
            vertical=str(form.get("vertical") or "") or None,
            domains=domain_list,
            preset=preset or "basic",
            kind="retail" if form.get("kind") == "retail" else "service",
            # the track's profile, plus the brand's own switches (social / ads reach, AI answers) whatever the track
            detection=detection if custom else ({k: detection[k] for k in BRAND_SWITCHES if k in detection} or None),
            scoring=scoring if (custom and scoring) else None,
        )  # type: ignore[arg-type]
        out = brands_api.create_brand(body, session, user)
    except (ValueError, HTTPException) as exc:
        detail = getattr(exc, "detail", str(exc))
        listed = brands_api.list_brands(session, user)
        return _render(
            request,
            "brands.html",
            user,
            brands=listed,
            cards=ui_stats.brand_cards(session, user, listed),
            copy_sources=_copy_sources(session, listed),
            PRESETS=presets_view(),
            **_add_form_ctx(request, session, user),
            prefill={"name": str(form.get("name") or ""), "entries": domain_list or [""]},
            active="brands",
            error=str(detail),
        )
    # set up before the first scan: the Google queries, and for a brand other shops sell its countries
    # and official prices — approved once, so the scan never stops to ask
    from brandwatch.api.ui_settings import needs_setup

    reach = {k: int(str(form.get(k))) for k in ("ads_per_search", "ad_searches_max") if str(form.get(k) or "").strip().isdigit()}
    if reach:  # how far the ad hunt goes lives in the brand profile (detection/ad_settings.py)
        from brandwatch.detection import ad_settings

        row = session.get(Brand, uuid.UUID(out["id"]))
        clamped = ad_settings.settings({**(row.profile or {}), **reach})
        row.profile = {**(row.profile or {}), **{k: clamped[k] for k in reach}}
        session.commit()
    brand = brands_api.get_brand(uuid.UUID(out["id"]), session, user)
    to = f"/ui/brands/{out['id']}/setup" if needs_setup(brand) else f"/ui/brands/{out['id']}"
    return RedirectResponse(to, status_code=303)


def presets_view() -> dict[str, Any]:
    """The three detection tracks with the knobs each one sets (the track cards, and what a track's values fill in)."""
    return {k: {**PRESET_INFO[k], "detection": PRESET_PROFILES[k]} for k in PRESET_PROFILES}


def _needs_setup(brand: dict[str, Any]) -> bool:
    from brandwatch.api.ui_settings import needs_setup

    return needs_setup(brand)


def brand_context(
    request: Request, session: Session, user: User, brand_id: uuid.UUID
) -> dict[str, Any]:
    """Everything brand_detail.html needs — shared by the page and by every error re-render."""
    from brandwatch import keys as keystore_mod
    brand = brands_api.get_brand(brand_id, session, user)
    return {
        "brand": brand,
        "jobs": scans_api.list_jobs(session, user, brand_id=brand_id, limit=20),
        "findings": findings_api.list_findings(session, user, brand_id=brand_id, limit=10),
        "pulse": dashboard_api.dashboard(request, session, user, brand_id=brand_id),
        "PRESETS": presets_view(),
        "scheduler_on": bool(getattr(request.app.state.settings, "scheduler_enabled", False)),
        "setup_needed": _needs_setup(brand),
        "setup_pending": _needs_setup_ignoring_skip(brand),
        # social media is searched through SearchApi: in live mode it needs that key
        "social_ready": keystore_mod.provider_ready(session, user.workspace_id, request.app.state.settings, "searchapi"),
        "ready": part_readiness(request, session, user),
        "active": "brands",
    }


def part_readiness(request: Request, session: Session, user: User) -> dict[str, bool]:
    """Which parts of a scan can really run in this workspace: Google needs SerpApi or ScraperAPI, the AI second opinion
    and "Suggest with AI" need OpenAI, the residential probe needs a proxy and a residential budget (demo: all)."""
    from brandwatch import keys as keystore_mod
    from brandwatch import tenancy

    settings = request.app.state.settings
    ready = lambda p: keystore_mod.provider_ready(session, user.workspace_id, settings, p)  # noqa: E731
    proxy = tenancy.workspace_proxy_settings(session, user.workspace_id)
    gb = tenancy.workspace_limits(session, user.workspace_id, settings).max_residential_gb or 0
    return {"google": ready("serpapi") or ready("scraperapi"), "openai": ready("openai"), "searchapi": ready("searchapi"),
            "residential": bool(settings.demo_mode or (proxy.get("mode") not in (None, "off") and gb > 0)),
            "proxy": proxy.get("mode") not in (None, "off"), "residential_gb": gb > 0}  # fmt: skip


def _needs_setup_ignoring_skip(brand: dict[str, Any]) -> bool:
    from brandwatch.api.ui_settings import needs_setup

    return needs_setup(brand, honour_skip=False)


_WORLD_LAND = Path(__file__).parent / "assets" / "world-land-110m.json"


@router.get("/assets/world-land.json")
def world_land() -> Response:
    """Coastlines for the flat attack map on the dashboard (Natural Earth 1:110m, public domain),
    served by the app itself so the map works without any CDN."""
    return Response(_WORLD_LAND.read_bytes(), media_type="application/json",
                    headers={"Cache-Control": "public, max-age=86400"})  # fmt: skip


@router.get("/brands/{brand_id}", response_class=HTMLResponse)
def brand_page(
    brand_id: uuid.UUID, request: Request,
    session: Annotated[Session, Depends(get_session, scope="function")], user: Annotated[User | None, Depends(ui_user)],
    edited: str = "",
):  # fmt: skip
    if user is None:
        return _login_redirect(request)
    return _render(request, "brand_detail.html", user, edited=edited,
                   **brand_context(request, session, user, brand_id))  # fmt: skip


@router.post("/brands/{brand_id}/scan")
def brand_scan(
    brand_id: uuid.UUID, request: Request,
    session: Annotated[Session, Depends(get_session, scope="function")], user: Annotated[User | None, Depends(ui_writer)],
    max_candidates: Annotated[str, Form()] = "",
    max_names: Annotated[str, Form()] = "",
    rebuild_baseline: Annotated[str, Form()] = "",
    only: Annotated[str, Form()] = "",  # "scan now, only …": lookalike / search / social / ads
    skip_setup: Annotated[str, Form()] = "",  # "start now without setting up": not asked again
):  # fmt: skip
    if user is None:
        return _login_redirect(request)
    cap = int(max_candidates) if max_candidates.strip().isdigit() else None
    if skip_setup:
        row = session.get(Brand, brand_id)
        if row is not None and row.workspace_id == user.workspace_id:
            row.profile = {**(row.profile or {}), "setup_skipped": True}
            session.flush()
    try:
        out = brands_api.start_scan(
            brand_id,
            brands_api.ScanRequest(
                max_candidates=cap,
                max_names=int(max_names) if max_names.strip().isdigit() else None,
                rebuild_baseline=rebuild_baseline == "on",
                only=only if only in brands_api.ONLY_PARTS else None,  # type: ignore[arg-type]
            ),
            request,
            session,
            user,
        )
    except HTTPException as exc:
        from brandwatch.api.ui_settings import _brand_error

        session.rollback()
        return _brand_error(request, session, user, brand_id, exc)
    return RedirectResponse(f"/ui/jobs/{out['job_id']}", status_code=303)


@router.post("/brands/{brand_id}/scan-urls")
def brand_scan_urls(
    brand_id: uuid.UUID, request: Request,
    session: Annotated[Session, Depends(get_session, scope="function")], user: Annotated[User | None, Depends(ui_writer)],
    urls: Annotated[str, Form()] = "",
):  # fmt: skip
    if user is None:
        return _login_redirect(request)
    url_list = [u.strip() for u in urls.replace(",", "\n").splitlines() if u.strip()]
    if not url_list:
        return RedirectResponse(f"/ui/brands/{brand_id}", status_code=303)
    out = brands_api.start_url_scan(
        brand_id, brands_api.UrlScanRequest(urls=url_list), request, session, user
    )
    return RedirectResponse(f"/ui/jobs/{out['job_id']}", status_code=303)


@router.post("/brands/{brand_id}/baseline")
async def brand_baseline(
    brand_id: uuid.UUID, request: Request,
    session: Annotated[Session, Depends(get_session, scope="function")], user: Annotated[User | None, Depends(ui_writer)],
):  # fmt: skip
    if user is None:
        return _login_redirect(request)
    await brands_api.rebuild_baseline(brand_id, request, session, user)
    return RedirectResponse(f"/ui/brands/{brand_id}", status_code=303)


# --------------------------------------------------------------------------------------------
# jobs (Live Scan Console)
# --------------------------------------------------------------------------------------------
@router.post("/jobs/{job_id}/cancel")
def job_cancel(
    job_id: uuid.UUID, request: Request,
    session: Annotated[Session, Depends(get_session, scope="function")], user: Annotated[User | None, Depends(ui_writer)],
):  # fmt: skip
    if user is None:
        return _login_redirect(request)
    try:
        scans_api.cancel_job(job_id, session, user)
    except HTTPException:
        pass  # already finished: just show the console
    return RedirectResponse(f"/ui/jobs/{job_id}", status_code=303)


@router.get("/jobs/{job_id}", response_class=HTMLResponse)
def job_page(
    job_id: uuid.UUID, request: Request,
    session: Annotated[Session, Depends(get_session, scope="function")], user: Annotated[User | None, Depends(ui_user)],
):  # fmt: skip
    if user is None:
        return _login_redirect(request)
    job = scans_api.get_job(job_id, session, user)
    summary = None
    if job["state"] in ("done", "failed", "cancelled"):
        from brandwatch.db.models import ScanEventRecord

        ev = session.scalars(
            sa.select(ScanEventRecord)
            .where(ScanEventRecord.job_id == job_id, ScanEventRecord.stage == "summary")
            .order_by(ScanEventRecord.seq.desc())
            .limit(1)
        ).first()
        summary = dict(ev.data or {}) if ev else None
    from brandwatch.detection.runner import ISSUE_HELP

    return _render(
        request, "job.html", user, job=job, summary=summary, issue_help=ISSUE_HELP, active="scans"
    )


# --------------------------------------------------------------------------------------------
# findings / watchlist
# --------------------------------------------------------------------------------------------
@router.get("/findings", response_class=HTMLResponse)
def findings_page(
    request: Request,
    session: Annotated[Session, Depends(get_session, scope="function")],
    user: Annotated[User | None, Depends(ui_user)],
    brand_id: str = "",
    state: str | None = None,
    severity: str = "",
    kind: str = "",
    q: str = "",
    since: str = "",
    sort: str = "severity",
    page: int = 1,
    job_id: str = "",
    fmt: str = "",
):
    if user is None:
        return _login_redirect(request)
    kind = kind if kind in ("phishing", "shop", "social", "ai_answer") else ""
    # no state param at all → open findings (the work queue); state="" → the 'all' option; "snoozed" → the ones put aside
    snoozed = state == "snoozed"
    state = _enum_or_none(FindingState, "open" if state is None or snoozed else state)
    brand_id = _uuid_or_none(brand_id)
    job = _uuid_or_none(job_id)
    severity = _enum_or_none(Severity, severity)
    q = q.strip()[:120]
    since = since if since in findings_api.SINCE else ""
    sort = sort if sort in findings_api.SORTS else "severity"
    per_page = 50
    stmt = findings_api.findings_query(session, user, brand_id=brand_id, state=state, severity=severity, kind=kind or None,
                                       q=q, since=since, sort=sort, snoozed=snoozed, job_id=job)  # fmt: skip
    if fmt in ("csv", "json"):  # the same filters, every row (at most 10,000), as a file
        return _export(fmt, "findings", [findings_api.finding_row(session, f) for f in session.scalars(stmt.limit(10_000)).all()],
                       ["id", "hostname", "brand_id", "kind", "severity", "score", "confidence", "state", "surface", "created_at", "snoozed_until"])  # fmt: skip
    total = findings_api.count_findings(session, stmt)
    pages = max(1, -(-total // per_page))
    page = max(1, min(page, pages))
    rows = [findings_api.finding_row(session, f) for f in session.scalars(stmt.limit(per_page).offset((page - 1) * per_page)).all()]
    brands = brands_api.list_brands(session, user)
    stats = ui_stats.findings_stats(session, user, brand_id)
    # one chip per brand with how many findings it has under the same state / severity / kind: "all brands" or one brand in a click
    cq = (sa.select(Finding.brand_id, sa.func.count()).join(Brand, Brand.id == Finding.brand_id)
          .where(Brand.workspace_id == user.workspace_id).group_by(Finding.brand_id))  # fmt: skip
    if state:
        cq = cq.where(Finding.state == state)
    if severity:
        cq = cq.where(Finding.severity == severity)
    if kind:
        cq = cq.where(Finding.kind == kind)
    counts = {str(b): n for b, n in session.execute(cq).all()}
    brand_chips = [{"id": str(b["id"]), "name": b["name"], "count": sum(counts.get(str(i), 0) for i in regions_mod.with_regions(session, uuid.UUID(str(b["id"]))))}
                   for b in brands]  # fmt: skip
    filters = {"brand_id": str(brand_id) if brand_id else "", "state": "snoozed" if snoozed else (state.value if state else ""),
               "severity": severity.value if severity else "", "kind": kind, "q": q, "since": since, "sort": sort,
               "job_id": str(job) if job else ""}  # fmt: skip
    snoozed_n = findings_api.count_findings(session, findings_api.findings_query(session, user, brand_id=brand_id, state=FindingState.OPEN, snoozed=True))
    base_qs = "&".join(f"{k}={v}" for k, v in filters.items() if v or k == "state")  # the filters without the page
    return _render(request, "findings.html", user, findings=rows, brands=brands, stats=stats, active="findings",
                   brand_chips=brand_chips, brand_total=sum(counts.values()), filters=filters,
                   total=total, page=page, pages=pages, per_page=per_page, base_qs=base_qs,
                   SORTS=findings_api.SORTS, SINCE=findings_api.SINCE, last_visit=user.previous_login_at, snoozed_n=snoozed_n,
                   scan_job=scans_api.get_job(job, session, user) if job else None,
                   has_shops=any(r.get("kind") in ("shop", "social", "ai_answer") for r in rows) or bool(kind))  # fmt: skip


@router.post("/findings/bulk")
async def findings_bulk(
    request: Request, session: Annotated[Session, Depends(get_session, scope="function")], user: Annotated[User | None, Depends(ui_writer)],
):  # fmt: skip
    """The list's "Confirm phishing" / "Not phishing" for every ticked finding; back to the same list with a line that says what changed."""
    if user is None:
        return _login_redirect(request)
    from urllib.parse import quote

    form = await request.form()
    ids = [i for i in (_uuid_or_none(str(v)) for v in form.getlist("ids")) if i]
    action = str(form.get("action") or "")
    nxt = str(form.get("next") or "/ui/findings")
    if not nxt.startswith("/ui/findings") or "//" in nxt:  # back to the list only, never somewhere else
        nxt = "/ui/findings"
    if not ids or action not in ("confirm", "dismiss"):
        return RedirectResponse(nxt, status_code=303)
    take_write_lock(session)
    verdict = _enum_or_none(AnalystVerdict, str(form.get("verdict") or "")) if action == "dismiss" else None
    out = findings_api.bulk_verdict(session, user, findings_api.BulkVerdictRequest(
        ids=ids, action=action, reason=str(form.get("reason") or "")[:2000],
        verdict=verdict if verdict is not AnalystVerdict.PHISHING else None, whitelist=action == "dismiss" and form.get("whitelist") == "on"))  # fmt: skip
    note = f"{action}:{out['changed']}:{len(out['skipped'])}"
    return RedirectResponse(nxt + ("&" if "?" in nxt else "?") + "bulk=" + quote(note), status_code=303)


@router.get("/demo-shot/{host}")
def demo_shot(
    host: str, request: Request, user: Annotated[User | None, Depends(ui_user)]
) -> Response:
    """Demo mode only: the rendered picture of a recorded site (urlscan's "screenshot" in the demo)."""
    import re as _re

    from brandwatch.providers.mock import demo_screenshot
    from brandwatch.providers.mock.fixtures import default_store

    if (
        user is None
        or not request.app.state.settings.demo_mode
        or not _re.fullmatch(r"[a-z0-9.\-]{1,253}", host)
    ):
        raise HTTPException(404)
    sc = default_store().get(host)
    png = demo_screenshot(sc) if sc else None
    if not png:
        raise HTTPException(404)
    return Response(png, media_type="image/png", headers={"Cache-Control": "private, max-age=3600"})


@router.get("/findings/{finding_id}", response_class=HTMLResponse)
def finding_page(
    finding_id: uuid.UUID, request: Request,
    session: Annotated[Session, Depends(get_session, scope="function")], user: Annotated[User | None, Depends(ui_user)],
):  # fmt: skip
    if user is None:
        return _login_redirect(request)
    ctx = finding_context(session, user, finding_id)
    if _auto_investigate(request, session, user, ctx):
        ctx = finding_context(session, user, finding_id)  # the running job's bar
    return _render(request, "finding_detail.html", user, back=_back_path(request, f"/ui/findings/{finding_id}"), **ctx)


def _auto_investigate(request: Request, session: Session, user: User, ctx: dict[str, Any]) -> bool:
    """An open High / Critical site that was never investigated: start the site & network investigation now, so the
    tabs are full by the time the analyst reads the evidence (once per finding; demo mode, or when VirusTotal has a key)."""
    from brandwatch import keys as keystore
    from brandwatch.api import intel as intel_api

    f = ctx["d"]["finding"]
    if (user.role is UserRole.VIEWER or f["state"] != "open" or f["severity"] not in ("critical", "high")
            or f.get("kind") in ("social", "ai_answer") or ctx.get("intel_job") or ctx.get("has_intel")):  # fmt: skip
        return False
    settings = request.app.state.settings
    if not (settings.demo_mode or keystore.provider_ready(session, user.workspace_id, settings, "virustotal")):
        return False
    try:
        take_write_lock(session)  # a GET that writes: wait for a writing job's checkpoint instead of "database is locked"
        row = session.get(Finding, uuid.UUID(f["id"]))
        intel_api.start_intel_job(session, request, user, row, light=True, auto=True)
    except Exception:  # noqa: BLE001 - the page must open even when the queue is full or the lock never came
        session.rollback()
        return False
    return True


def _back_path(request: Request, own: str) -> str:
    """The page the analyst came from (the findings list, the Attack infrastructure page …), so a verdict can take them back to it
    instead of leaving them on the finding they just closed. Only this application's own pages; never the finding itself."""
    from urllib.parse import urlsplit

    ref = urlsplit(request.headers.get("referer") or "")
    if ref.netloc and ref.netloc != request.headers.get("host"):
        return ""
    path = ref.path + (f"?{ref.query}" if ref.query else "")
    return path if path.startswith("/ui/") and not path.startswith(own) and not path.startswith("/ui/login") else ""


def finding_context(session: Session, user: User, finding_id: uuid.UUID) -> dict[str, Any]:
    """Everything finding_detail.html needs — shared by the page and its error re-renders.
    One page per site: the finding and its Site & network investigation (read from the intel cache —
    nothing is fetched here; the page's Run / Refresh button starts the intel job)."""
    from brandwatch.api import intel as intel_api
    from brandwatch.detection import intel as intel_mod

    mj = campaigns_api.latest_map_job(session, finding_id)
    d = findings_api.get_finding(finding_id, session, user)
    host = d["candidate"]["hostname"]
    view = intel_mod.intel_view(
        session, user.workspace_id, host, url=d["candidate"]["canonical_url"]
    )
    ij = intel_api._latest_job(session, user.workspace_id, "finding_id", str(finding_id))
    from brandwatch.detection import takedown_channels as tc

    shop = (d.get("score") or {}).get("shop") or {}
    soc = (d.get("score") or {}).get("social") or {}
    ads = (d.get("score") or {}).get("ads") or []
    if d["finding"].get("kind") == "social" and soc:
        meta = {"pages": tc.social_targets(soc), "forms": tc.SOCIAL_FORMS, "social": True,
                "text": tc.social_report_text(d["brand"]["name"], soc, (d.get("score") or {}).get("summary"))}  # fmt: skip
    elif ads and d["finding"].get("kind") == "phishing":
        meta = {"pages": tc.meta_pages({"ads": ads}), "forms": tc.PHISHING_AD_FORMS, "phishing_ad": True, "meta_reason": "Scam or fraud",
                "text": tc.phishing_ad_report_text(d["brand"]["name"], d["candidate"]["canonical_url"], {"ads": ads},
                                                   (d.get("score") or {}).get("summary"))}  # fmt: skip
    else:
        lv = d["finding"].get("shop_level") or {}
        level = lv.get("level") or "suspicious_retailer"
        meta = {"pages": tc.meta_pages(shop), "forms": tc.META_FORMS, **_meta_level(level),
                "text": tc.meta_report_text(d["brand"]["name"], d["candidate"]["canonical_url"], shop,
                                            (d.get("score") or {}).get("summary"), level, lv.get("conclusion"))}  # fmt: skip
    from brandwatch.detection import shop_levels

    frow = session.get(Finding, finding_id)
    return {
        "d": d,
        "nb": findings_api.neighbours(session, user, frow) if frow else {"prev": None, "next": None, "open_count": 0},
        "notes": findings_api.list_notes(session, finding_id),
        "snoozed_until": frow.snoozed_until.isoformat() if frow is not None and frow.snoozed_until else None,
        "SNOOZE_DAYS": findings_api.SNOOZE_DAYS,
        "meta": meta,
        "shop_levels": shop_levels.LEVELS,
        "shop_proofs": shop_levels.PROOFS,
        "reports": reports_api.list_reports(finding_id, session, user),
        "takedowns": reports_api.list_finding_takedowns(finding_id, session, user),
        "map_job": {"id": str(mj.id), "state": mj.state.value} if mj else None,
        "v": view, "has_intel": view["fetched_at"] is not None, "mode": "finding",
        "intel_job": intel_api._job_out(ij), "intel_running": intel_api._running(ij),
        "active": "findings",
    }  # fmt: skip


@router.post("/findings/{finding_id}/verdict")
def finding_verdict(
    finding_id: uuid.UUID, request: Request,
    session: Annotated[Session, Depends(get_session, scope="function")], user: Annotated[User | None, Depends(ui_writer)],
    action: Annotated[str, Form()], reason: Annotated[str, Form()] = "",
    verdict: Annotated[str, Form()] = "legitimate", conclusion: Annotated[str, Form()] = "",
    proof: Annotated[str, Form()] = "", next: Annotated[str, Form()] = "", whitelist: Annotated[str, Form()] = "",
):  # fmt: skip
    if user is None:
        return _login_redirect(request)
    from urllib.parse import quote

    take_write_lock(session)  # a job may be writing (the auto-started investigation): wait for it, no "database is locked"
    f = session.get(Finding, finding_id)
    nb = findings_api.neighbours(session, user, f) if f else {"next": None}  # before the verdict moves it out of the queue
    host = session.get(Candidate, f.candidate_id).hostname if f else ""
    confirm = action in ("confirm", "confirm_draft")  # confirm_draft: confirm and open the takedown request in one press
    try:
        body = findings_api.VerdictRequest(
            reason=reason, verdict=AnalystVerdict(verdict) if action == "dismiss" else None,
            conclusion=(conclusion or None) if confirm else None,
            proof=(proof or None) if confirm and conclusion == "confirmed_counterfeit" else None,
            whitelist=action == "dismiss" and whitelist == "on",
        )  # fmt: skip
        if confirm:
            findings_api.confirm_finding(finding_id, body, request, session, user)
        else:
            findings_api.dismiss_finding(finding_id, body, session, user)
    except (ValueError, HTTPException) as exc:
        msg = exc.detail if isinstance(exc, HTTPException) else str(exc)
        return _render(request, "finding_detail.html", user, error=str(msg),
                       **finding_context(session, user, finding_id))  # fmt: skip
    flash = "flash=" + quote(f"{'confirmed' if confirm else 'dismissed'}:{host}:{finding_id}", safe=":")
    if action == "confirm_draft":
        try:
            out = reports_api.create_takedown(finding_id, session, user)
        except HTTPException as exc:  # a contact, not a site, or no draft possible: the finding page says why
            return RedirectResponse(f"/ui/findings/{finding_id}?{flash}&error={quote(str(exc.detail))}", status_code=303)
        return RedirectResponse(f"/ui/takedowns/{out['id']}?{flash}", status_code=303)
    if next.startswith("/ui/") and not next.startswith("/ui/findings"):  # came from somewhere else: back there
        return RedirectResponse(next + ("&" if "?" in next else "?") + flash, status_code=303)
    if next.startswith("/ui/findings"):  # the queue: straight on to the next open finding; the last one returns to the list
        if nb.get("next"):
            return RedirectResponse(f"/ui/findings/{nb['next']}?{flash}", status_code=303)
        lst = next if next.startswith("/ui/findings?") else "/ui/findings"
        return RedirectResponse(lst + ("&" if "?" in lst else "?") + flash, status_code=303)
    return RedirectResponse(f"/ui/findings/{finding_id}?{flash}", status_code=303)  # opened directly: stay, with the note


@router.post("/findings/{finding_id}/note")
def finding_note(
    finding_id: uuid.UUID, request: Request,
    session: Annotated[Session, Depends(get_session, scope="function")], user: Annotated[User | None, Depends(ui_writer)],
    text: Annotated[str, Form()] = "",
):  # fmt: skip
    if user is None:
        return _login_redirect(request)
    if text.strip():
        findings_api.add_note(finding_id, findings_api.NoteRequest(text=text[:4000]), session, user)
    return RedirectResponse(f"/ui/findings/{finding_id}?saved=note#notes", status_code=303)


@router.post("/findings/{finding_id}/snooze")
def finding_snooze(
    finding_id: uuid.UUID, request: Request,
    session: Annotated[Session, Depends(get_session, scope="function")], user: Annotated[User | None, Depends(ui_writer)],
    days: Annotated[int, Form()] = 7, reason: Annotated[str, Form()] = "", next: Annotated[str, Form()] = "",
):  # fmt: skip
    """Put an open finding aside for N days (0 = back in the queue now); from the queue, on to the next open one."""
    if user is None:
        return _login_redirect(request)
    from urllib.parse import quote

    f = session.get(Finding, finding_id)
    nb = findings_api.neighbours(session, user, f) if f else {"next": None}
    try:
        findings_api.snooze_finding(finding_id, findings_api.SnoozeRequest(days=max(0, min(days, 90)), reason=reason), session, user)
    except HTTPException as exc:
        return render_error(request, exc.status_code, str(exc.detail))
    if days and next.startswith("/ui/findings") and nb.get("next") and nb["next"] != str(finding_id):
        host = session.get(Candidate, f.candidate_id).hostname
        return RedirectResponse(f"/ui/findings/{nb['next']}?flash=" + quote(f"snoozed:{host}:{finding_id}", safe=":"), status_code=303)
    return RedirectResponse(f"/ui/findings/{finding_id}?saved={'snoozed' if days else 'woken'}", status_code=303)


def _export(fmt: str, name: str, rows: list[dict[str, Any]], cols: list[str]) -> Response:
    """A list page's rows as CSV (the chosen columns) or JSON (everything), with the page's filters."""
    import csv
    import io
    import json as _json

    if fmt == "json":
        return Response(_json.dumps(rows, ensure_ascii=False, default=str, indent=1), media_type="application/json",
                        headers={"Content-Disposition": f'attachment; filename="brandwatch-{name}.json"'})  # fmt: skip
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(cols)
    for r in rows:
        w.writerow(["" if r.get(c) is None else (r[c] if isinstance(r.get(c), (str, int, float)) else _json.dumps(r[c], ensure_ascii=False, default=str)) for c in cols])
    return Response("\ufeff" + buf.getvalue(), media_type="text/csv; charset=utf-8",
                    headers={"Content-Disposition": f'attachment; filename="brandwatch-{name}.csv"'})  # fmt: skip


@router.post("/findings/{finding_id}/reopen")
def finding_reopen(
    finding_id: uuid.UUID, request: Request,
    session: Annotated[Session, Depends(get_session, scope="function")], user: Annotated[User | None, Depends(ui_writer)],
    next: Annotated[str, Form()] = "",
):  # fmt: skip
    """Undo: the finding waits for a verdict again."""
    if user is None:
        return _login_redirect(request)
    from urllib.parse import quote

    take_write_lock(session)
    try:
        findings_api.reopen_finding(finding_id, session, user)
    except HTTPException as exc:
        return render_error(request, exc.status_code, str(exc.detail))
    host = session.get(Candidate, session.get(Finding, finding_id).candidate_id).hostname
    flash = "flash=" + quote(f"reopened:{host}:{finding_id}", safe=":")
    to = next if next.startswith("/ui/") else f"/ui/findings/{finding_id}"
    to = to.split("?flash=")[0].split("&flash=")[0]  # never stack two flashes
    return RedirectResponse(to + ("&" if "?" in to else "?") + flash, status_code=303)


@router.post("/findings/{finding_id}/conclusion")
def finding_conclusion(
    finding_id: uuid.UUID, request: Request,
    session: Annotated[Session, Depends(get_session, scope="function")], user: Annotated[User | None, Depends(ui_writer)],
    level: Annotated[str, Form()], reason: Annotated[str, Form()] = "", proof: Annotated[str, Form()] = "",
):  # fmt: skip
    """A confirmed shop's conclusion changes (e.g. after a test purchase)."""
    if user is None:
        return _login_redirect(request)
    try:
        body = findings_api.ConclusionRequest(
            level=level, reason=reason, proof=(proof or None) if level == "confirmed_counterfeit" else None
        )
        findings_api.update_conclusion(finding_id, body, session, user)
    except (ValueError, HTTPException) as exc:
        msg = exc.detail if isinstance(exc, HTTPException) else str(exc)
        return _render(request, "finding_detail.html", user, error=str(msg),
                       **finding_context(session, user, finding_id))  # fmt: skip
    return RedirectResponse(f"/ui/findings/{finding_id}?conclusion=saved", status_code=303)


@router.post("/findings/{finding_id}/authorized")
def finding_authorized(
    finding_id: uuid.UUID, request: Request,
    session: Annotated[Session, Depends(get_session, scope="function")], user: Annotated[User | None, Depends(ui_writer)],
):  # fmt: skip
    """A genuine retailer: whitelist its domain as an authorised retailer of the brand. The whitelist
    closes every open finding on the site (detection/protect.py) and the scans skip it from now on."""
    if user is None:
        return _login_redirect(request)
    f = findings_api._get_finding(session, user, finding_id)
    from brandwatch.db.models import Candidate

    cand = session.get(Candidate, f.candidate_id)
    try:
        brands_api.add_whitelist(
            f.brand_id,
            brands_api.WhitelistAdd(domain=cand.canonical_domain, kind="reseller"),
            session,
            user,
        )
    except HTTPException as exc:
        if exc.status_code != 409:  # already listed is fine: the finding is closed below either way
            raise
    from brandwatch.detection.protect import dismiss_protected

    dismiss_protected(session, f.brand_id)
    return RedirectResponse(f"/ui/findings/{finding_id}", status_code=303)


@router.post("/findings/{finding_id}/official-account")
def finding_official_account(
    finding_id: uuid.UUID, request: Request,
    session: Annotated[Session, Depends(get_session, scope="function")], user: Annotated[User | None, Depends(ui_writer)],
):  # fmt: skip
    """"This is our account": joins the brand's official social accounts and the finding closes."""
    if user is None:
        return _login_redirect(request)
    findings_api.official_account(finding_id, session, user)
    return RedirectResponse(f"/ui/findings/{finding_id}", status_code=303)


@router.post("/findings/{finding_id}/our-contact")
def finding_our_contact(
    finding_id: uuid.UUID, request: Request,
    session: Annotated[Session, Depends(get_session, scope="function")], user: Annotated[User | None, Depends(ui_writer)],
):  # fmt: skip
    """"This is our contact": the contact an AI gave joins the brand's known contacts and the finding closes."""
    if user is None:
        return _login_redirect(request)
    findings_api.our_contact(finding_id, session, user)
    return RedirectResponse(f"/ui/findings/{finding_id}", status_code=303)


@router.post("/findings/{finding_id}/report")
def finding_report(
    finding_id: uuid.UUID, request: Request,
    session: Annotated[Session, Depends(get_session, scope="function")], user: Annotated[User | None, Depends(ui_writer)],
):  # fmt: skip
    if user is None:
        return _login_redirect(request)
    reports_api.generate_report(finding_id, request, session, user)
    return RedirectResponse(f"/ui/findings/{finding_id}", status_code=303)


@router.post("/findings/{finding_id}/takedown")
def finding_takedown(
    finding_id: uuid.UUID, request: Request,
    session: Annotated[Session, Depends(get_session, scope="function")], user: Annotated[User | None, Depends(ui_writer)],
):  # fmt: skip
    if user is None:
        return _login_redirect(request)
    try:
        out = reports_api.create_takedown(finding_id, session, user)
    except HTTPException as exc:
        return _render(request, "finding_detail.html", user, error=str(exc.detail),
                       **finding_context(session, user, finding_id))  # fmt: skip
    return RedirectResponse(f"/ui/takedowns/{out['id']}", status_code=303)


@router.post("/campaigns/draft-takedowns")
async def campaigns_draft_takedowns(
    request: Request,
    session: Annotated[Session, Depends(get_session, scope="function")], user: Annotated[User | None, Depends(ui_writer)],
):  # fmt: skip
    """An operation card → "Draft takedowns for these N sites": one request per confirmed site that has none yet."""
    if user is None:
        return _login_redirect(request)
    form = await request.form()
    ids = [i for i in (_uuid_or_none(str(x)) for x in form.getlist("ids")) if i][:200]
    take_write_lock(session)
    done = skipped = 0
    for fid in ids:
        try:
            reports_api.create_takedown(fid, session, user)
            done += 1
        except HTTPException:
            skipped += 1
    return RedirectResponse(f"/ui/takedowns?state=unsent&bulk=drafted:{done}:{skipped}", status_code=303)


@router.get("/takedowns/{draft_id}", response_class=HTMLResponse)
def takedown_page(
    draft_id: uuid.UUID, request: Request,
    session: Annotated[Session, Depends(get_session, scope="function")], user: Annotated[User | None, Depends(ui_user)],
    error: str | None = None,
):  # fmt: skip
    if user is None:
        return _login_redirect(request)
    from brandwatch.db.models import TakedownDraft
    from brandwatch.detection import takedown_channels as tc

    draft = session.get(TakedownDraft, draft_id)
    t = reports_api.get_takedown(draft_id, session, user)
    ch = tc.ensure_channels(session, draft, persist=False)  # a GET never writes
    t["channels"] = ch
    url, host = tc.finding_url(session, draft)
    subject = tc.subject_for(draft, session)
    body = draft.body or ""
    res = ch.get("resolved") or {}
    reg, cdn = res.get("registrar") or {}, res.get("cdn") or {}
    mail = {
        "registrar": tc.mailto(reg.get("email"), subject, tc.body_for(body, reg.get("email"), reg.get("name"), draft.reference)),
        "cdn": tc.mailto(cdn.get("email"), subject, tc.body_for(body, cdn.get("email"), cdn.get("name"), draft.reference)),
        "hosting": {
            h["ip"]: tc.mailto(h.get("email"), subject, tc.body_for(body, h.get("email"), h.get("desk") or h.get("org"), draft.reference))
            for h in res.get("hosting") or []
        },
    }  # fmt: skip
    finding = session.get(Finding, draft.finding_id)
    brand = session.get(Brand, finding.brand_id) if finding else None
    shop = tc.shop_record_of(session, finding) if finding else {}
    soc = tc.social_record_of(session, finding) if finding and finding.kind == "social" else {}
    ad_rec = tc.ads_record_of(session, finding) if finding and finding.kind == "phishing" else {}
    if soc:
        meta = {"pages": tc.social_targets(soc), "forms": tc.SOCIAL_FORMS, "social": True,
                "text": tc.social_report_text(brand.name if brand else "", soc, None)}  # fmt: skip
    elif ad_rec:
        meta = {"pages": tc.meta_pages(ad_rec), "forms": tc.PHISHING_AD_FORMS, "phishing_ad": True, "meta_reason": "Scam or fraud",
                "text": tc.phishing_ad_report_text(brand.name if brand else "", url, ad_rec, None)}  # fmt: skip
    else:
        level, conclusion = tc.shop_level_of(session, finding) if finding else ("suspicious_retailer", None)
        meta = {"pages": tc.meta_pages(shop), "forms": tc.META_FORMS, **_meta_level(level),
                "text": tc.meta_report_text(brand.name if brand else "", url, shop, None, level, conclusion)}  # fmt: skip
    is_shop = bool(finding and finding.kind == "shop")
    shop_lvl = None
    if is_shop:
        from brandwatch.detection import shop_levels

        w = shop_levels.wording(meta["level"], brand.name if brand else "", finding.conclusion)
        shop_lvl = {**meta, "stale": bool(body) and w["subject"] not in body,
                    "editable": draft.state.value in ("draft", "review", "reopened")}  # fmt: skip
    return _render(request, "takedown.html", user, t=t, active="takedowns", error=error, mail=mail,
                   portals=tc.portal_links(url, host, subject, body), groups=tc.PORTAL_GROUPS,
                   brand_name=brand.name if brand else None, brand_id=str(brand.id) if brand else None,
                   site_url=url, meta=meta, is_shop=is_shop, shop_lvl=shop_lvl)  # fmt: skip


def _meta_level(level: str) -> dict[str, Any]:
    """What the Report-to-Meta box needs to word its steps for the shop's conclusion."""
    from brandwatch.detection import shop_levels

    w = shop_levels.wording(level, "", None)
    return {"level": level, "level_label": shop_levels.LEVELS[level]["label"], "meta_reason": w["meta_reason"]}


@router.post("/takedowns/{draft_id}/rewrite")
def takedown_rewrite(
    draft_id: uuid.UUID, request: Request,
    session: Annotated[Session, Depends(get_session, scope="function")], user: Annotated[User | None, Depends(ui_writer)],
):  # fmt: skip
    """Rewrite a shop's takedown letter for its current conclusion (after the analyst changed it).
    Only while the request is still editable; audited as an edit."""
    from brandwatch.db.models import TakedownDraft
    from brandwatch.detection import reports as reports_mod

    if user is None:
        return _login_redirect(request)
    draft = session.get(TakedownDraft, draft_id)
    reports_api.get_takedown(draft_id, session, user)  # workspace check
    finding = session.get(Finding, draft.finding_id)
    detail = findings_api.finding_detail(session, finding)
    body = reports_mod.takedown_body(detail, abuse_contact=draft.abuse_contact, registrar=draft.registrar)
    try:
        reports_mod.update_takedown_body(session, draft, actor=user, body=body)
    except ValueError as exc:
        return RedirectResponse(f"/ui/takedowns/{draft_id}?error={exc}", status_code=303)
    return RedirectResponse(f"/ui/takedowns/{draft_id}#request", status_code=303)


@router.post("/takedowns/{draft_id}/channel")
def takedown_channel(
    draft_id: uuid.UUID, request: Request,
    session: Annotated[Session, Depends(get_session, scope="function")], user: Annotated[User | None, Depends(ui_writer)],
    channel: Annotated[str, Form()], contact: Annotated[str, Form()] = "",
    mark: Annotated[str, Form()] = "save",
):  # fmt: skip
    """Save a channel's contact and/or record that the request was sent to it."""
    from brandwatch.db.models import TakedownDraft
    from brandwatch.detection import takedown_channels as tc

    if user is None:
        return _login_redirect(request)
    draft = session.get(TakedownDraft, draft_id)
    reports_api.get_takedown(draft_id, session, user)  # workspace check
    try:
        tc.record_channel(
            session, draft, actor=user, channel=channel, contact=contact, sent=mark == "sent"
        )
    except ValueError as exc:
        return RedirectResponse(f"/ui/takedowns/{draft_id}?error={exc}", status_code=303)
    return RedirectResponse(f"/ui/takedowns/{draft_id}#channels", status_code=303)


@router.post("/takedowns/{draft_id}/reported")
def takedown_reported(
    draft_id: uuid.UUID, request: Request,
    session: Annotated[Session, Depends(get_session, scope="function")], user: Annotated[User | None, Depends(ui_writer)],
    portal: Annotated[str, Form()],
    next: Annotated[str, Form()] = "",
):  # fmt: skip
    """Tick / untick a phishing report portal (or a Report-to-Meta row)."""
    from brandwatch.db.models import TakedownDraft
    from brandwatch.detection import takedown_channels as tc

    if user is None:
        return _login_redirect(request)
    draft = session.get(TakedownDraft, draft_id)
    reports_api.get_takedown(draft_id, session, user)  # workspace check
    try:
        ch = tc.toggle_report(session, draft, actor=user, portal=portal)
    except ValueError as exc:
        if request.headers.get("x-requested-with") == "fetch":
            return JSONResponse({"error": str(exc)}, status_code=400)
        return RedirectResponse(f"/ui/takedowns/{draft_id}?error={exc}", status_code=303)
    if request.headers.get("x-requested-with") == "fetch":  # the page swaps the button itself
        reports = ch.get("reports") or {}
        return JSONResponse({"portal": portal, "done": portal in reports, "at": (reports.get(portal) or {}).get("at"), "count": len(reports)})
    return RedirectResponse(
        f"/ui/takedowns/{draft_id}#{'meta' if next == 'meta' else 'report'}", status_code=303
    )


@router.post("/takedowns/{draft_id}/edit")
def takedown_edit(
    draft_id: uuid.UUID, request: Request,
    session: Annotated[Session, Depends(get_session, scope="function")], user: Annotated[User | None, Depends(ui_writer)],
    body: Annotated[str, Form()] = "", abuse_contact: Annotated[str, Form()] = "",
):  # fmt: skip
    if user is None:
        return _login_redirect(request)
    try:
        reports_api.edit_takedown(
            draft_id,
            reports_api.TakedownEdit(body=body, abuse_contact=abuse_contact),
            session,
            user,
        )
    except HTTPException as exc:
        return RedirectResponse(f"/ui/takedowns/{draft_id}?error={exc.detail}", status_code=303)
    return RedirectResponse(f"/ui/takedowns/{draft_id}", status_code=303)


@router.post("/takedowns/{draft_id}/transition")
def takedown_transition(
    draft_id: uuid.UUID, request: Request,
    session: Annotated[Session, Depends(get_session, scope="function")], user: Annotated[User | None, Depends(ui_writer)],
    to: Annotated[str, Form()], reason: Annotated[str, Form()] = "",
):  # fmt: skip
    if user is None:
        return _login_redirect(request)
    try:
        reports_api.transition_takedown(
            draft_id,
            reports_api.TakedownTransition(to=TakedownState(to), reason=reason),
            session,
            user,
        )
    except (HTTPException, ValueError) as exc:
        return RedirectResponse(
            f"/ui/takedowns/{draft_id}?error={getattr(exc, 'detail', exc)}", status_code=303
        )
    return RedirectResponse(f"/ui/takedowns/{draft_id}", status_code=303)


@router.get("/candidates/{candidate_id}", response_class=HTMLResponse)
def candidate_page(
    candidate_id: uuid.UUID, request: Request,
    session: Annotated[Session, Depends(get_session, scope="function")], user: Annotated[User | None, Depends(ui_user)],
):  # fmt: skip
    if user is None:
        return _login_redirect(request)
    d = candidates_api.get_candidate(candidate_id, session, user)
    return _render(request, "candidate_detail.html", user, d=d, active="candidates")


@router.post("/candidates/{candidate_id}/rescan")
async def candidate_rescan(
    candidate_id: uuid.UUID, request: Request,
    session: Annotated[Session, Depends(get_session, scope="function")], user: Annotated[User | None, Depends(ui_writer)],
):  # fmt: skip
    if user is None:
        return _login_redirect(request)
    form = await request.form()
    out = candidates_api.rescan_candidate(candidate_id, request, session, user)
    nxt = str(form.get("next") or "")
    if nxt.startswith("/ui/") and not nxt.startswith("/ui/jobs"):  # from the list: stay on it, with a note and the console link
        from urllib.parse import quote

        host = session.get(Candidate, candidate_id).hostname
        nxt = nxt.split("&flash=")[0].split("?flash=")[0]
        return RedirectResponse(nxt + ("&" if "?" in nxt else "?") + "flash=" + quote(f"rescan:{host}:{out['job_id']}", safe=":"), status_code=303)
    return RedirectResponse(f"/ui/jobs/{out['job_id']}", status_code=303)


@router.post("/candidates/{candidate_id}/dismiss")
def candidate_dismiss(
    candidate_id: uuid.UUID, request: Request,
    session: Annotated[Session, Depends(get_session, scope="function")], user: Annotated[User | None, Depends(ui_writer)],
    reason: Annotated[str, Form()] = "", whitelist: Annotated[str, Form()] = "",
    next: Annotated[str, Form()] = "/ui/candidates",
):  # fmt: skip
    """Watchlist → "Known legit": off the watchlist (+ whitelisted for the brand by default)."""
    if user is None:
        return _login_redirect(request)
    candidates_api.dismiss_candidate(
        candidate_id,
        candidates_api.DismissRequest(reason=reason, whitelist=whitelist == "on"),
        session,
        user,
    )  # type: ignore[arg-type]
    return RedirectResponse(next if next.startswith("/ui/") else "/ui/candidates", status_code=303)


@router.post("/findings/{finding_id}/investigate")
def finding_investigate(
    finding_id: uuid.UUID, request: Request,
    session: Annotated[Session, Depends(get_session, scope="function")], user: Annotated[User | None, Depends(ui_writer)],
):  # fmt: skip
    if user is None:
        return _login_redirect(request)
    try:
        out = campaigns_api.investigate_finding(finding_id, request, session, user)
    except HTTPException as exc:
        return _render(request, "finding_detail.html", user, error=str(exc.detail),
                       **finding_context(session, user, finding_id))  # fmt: skip
    return RedirectResponse(f"/ui/jobs/{out['job_id']}", status_code=303)


def _last_messages(session: Session, job_ids: list[uuid.UUID]) -> dict[uuid.UUID, str]:
    """What each of these jobs said last: the live progress shown in a row of the Attack infrastructure page."""
    from brandwatch.db.models import ScanEventRecord

    if not job_ids:
        return {}
    newest = (sa.select(ScanEventRecord.job_id, sa.func.max(ScanEventRecord.seq).label("m"))
              .where(ScanEventRecord.job_id.in_(job_ids)).group_by(ScanEventRecord.job_id).subquery())  # fmt: skip
    rows = session.execute(sa.select(ScanEventRecord.job_id, ScanEventRecord.message)
                           .join(newest, sa.and_(ScanEventRecord.job_id == newest.c.job_id, ScanEventRecord.seq == newest.c.m))).all()  # fmt: skip
    return {jid: str(msg)[:110] for jid, msg in rows}


def _map_batch(session: Session, user: User) -> dict[str, Any] | None:
    """The latest "MAP ALL" batch of the workspace: how far it is."""
    from brandwatch.db.models import ScanEventRecord

    job = session.scalars(sa.select(ScanJob).where(ScanJob.workspace_id == user.workspace_id, ScanJob.kind == "map_all")
                          .order_by(ScanJob.created_at.desc())).first()  # fmt: skip
    if job is None:
        return None
    ev = session.scalars(sa.select(ScanEventRecord).where(ScanEventRecord.job_id == job.id, ScanEventRecord.progress.is_not(None))
                         .order_by(ScanEventRecord.seq.desc()).limit(1)).first()  # fmt: skip
    prog = (ev.progress if ev else None) or {}
    ids = list((job.payload or {}).get("finding_ids", []))
    return {"id": str(job.id), "state": job.state.value, "total": int(prog.get("total") or len(ids)), "current": int(prog.get("current") or 0),
            "finding_ids": ids, "message": ev.message if ev else None}  # fmt: skip


@router.post("/campaigns/map-all")
def campaigns_map_all(
    request: Request, session: Annotated[Session, Depends(get_session, scope="function")], user: Annotated[User | None, Depends(ui_writer)],
    brand_id: Annotated[str, Form()] = "", remap: Annotated[str, Form()] = "",
):  # fmt: skip
    if user is None:
        return _login_redirect(request)
    bid = _uuid_or_none(brand_id)
    out = campaigns_api.map_all(request, session, user, campaigns_api.AllRequest(brand_id=bid, remap=remap == "on"))
    note = f"mapping:{out['count']}" if out["count"] else "mapping:0"
    return RedirectResponse(f"/ui/campaigns?{'brand_id=' + str(bid) + '&' if bid else ''}note={note}#confirmed", status_code=303)


@router.post("/campaigns/investigate-all")
def campaigns_investigate_all(
    request: Request, session: Annotated[Session, Depends(get_session, scope="function")], user: Annotated[User | None, Depends(ui_writer)],
    brand_id: Annotated[str, Form()] = "", remap: Annotated[str, Form()] = "",
):  # fmt: skip
    if user is None:
        return _login_redirect(request)
    bid = _uuid_or_none(brand_id)
    out = campaigns_api.investigate_all(request, session, user, campaigns_api.AllRequest(brand_id=bid, remap=remap == "on"))
    return RedirectResponse(f"/ui/campaigns?{'brand_id=' + str(bid) + '&' if bid else ''}note=investigating:{out['count']}#confirmed", status_code=303)


@router.post("/campaigns/reverse-search")
def campaigns_reverse_search(
    request: Request, session: Annotated[Session, Depends(get_session, scope="function")], user: Annotated[User | None, Depends(ui_writer)],
    kind: Annotated[str, Form()], value: Annotated[str, Form()], brand_id: Annotated[str, Form()] = "",
):  # fmt: skip
    if user is None:
        return _login_redirect(request)
    bid = _uuid_or_none(brand_id)
    campaigns_api.reverse_search(request, campaigns_api.ReverseRequest(kind=kind, value=value, brand_id=bid), session, user)
    return RedirectResponse(f"/ui/campaigns/all?{'brand_id=' + str(bid) if bid else ''}#groups", status_code=303)


@router.post("/campaigns/reassess-redirects")
def campaigns_reassess_redirects(
    request: Request, session: Annotated[Session, Depends(get_session, scope="function")], user: Annotated[User | None, Depends(ui_writer)], brand_id: Annotated[str, Form()] = "",
):  # fmt: skip
    if user is None:
        return _login_redirect(request)
    bid = _uuid_or_none(brand_id)
    out = campaigns_api.reassess_redirects(campaigns_api.ReassessRequest(brand_id=bid), session, user)
    return RedirectResponse(f"/ui/campaigns/all?{'brand_id=' + str(bid) + '&' if bid else ''}reassessed={out['count']}#groups", status_code=303)


@router.post("/campaigns/map-exclude")
def campaigns_map_exclude(
    session: Annotated[Session, Depends(get_session, scope="function")], request: Request, user: Annotated[User | None, Depends(ui_writer)],
    kind: Annotated[str, Form()], value: Annotated[str, Form()] = "", exclude: Annotated[str, Form()] = "1", brand_id: Annotated[str, Form()] = "",
    name: Annotated[str, Form()] = "",
):  # fmt: skip
    if user is None:
        return _login_redirect(request)
    from urllib.parse import quote

    bid = _uuid_or_none(brand_id)
    before = campaigns_api.all_map(session, user, bid)["stats"]
    campaigns_api.map_exclude(campaigns_api.ExcludeRequest(kind=kind, value=value or None, exclude=exclude == "1"), session, user)
    after = campaigns_api.all_map(session, user, bid)["stats"]  # analysed again, without (or with) it: say what changed
    label = quote((name or kind).replace(":", "-")[:60], safe="")
    note = f"{'out' if exclude == '1' else 'in'}:{before['groups']}:{after['groups']}:{before['linked_sites']}:{after['linked_sites']}:{label}"
    return RedirectResponse(f"/ui/campaigns/all?{'brand_id=' + str(bid) + '&' if bid else ''}re={note}#groups", status_code=303)


@router.get("/campaigns/operation-report", response_class=HTMLResponse)
def campaigns_operation_report(
    request: Request, session: Annotated[Session, Depends(get_session, scope="function")], user: Annotated[User | None, Depends(ui_user)],
    brand_id: str = "", group: int = 1, download: int = 0,
):  # fmt: skip
    """One operation of the all-sites map as a standalone HTML document: pretty, printable, with every table. ``download=1`` saves it as a file."""
    if user is None:
        return _login_redirect(request)
    import re as _re
    from datetime import UTC, datetime

    from brandwatch.detection import pattern as pattern_mod

    bid = _uuid_or_none(brand_id)
    data = campaigns_api.all_map(session, user, bid)
    op = next((g for g in data["operations"] if g["index"] == group), None)
    if op is None:
        raise HTTPException(404, "no such group")
    sites = {s["host"]: s for s in data["sites"]}
    days = sorted(({"date": d.isoformat(), "host": h} for h in op["sites"] if (d := pattern_mod._day(sites[h].get("registered"))) and d.year >= 1995), key=lambda x: x["date"])
    timeline = None
    if days:
        lo, hi = pattern_mod._day(days[0]["date"]), pattern_mod._day(days[-1]["date"])
        span = max((hi - lo).days, 1)
        for i, d in enumerate(days):
            when = pattern_mod._day(d["date"])
            d["x"] = round(((when - lo).days / span) * 94 + 3, 2)
            d["wave"] = any(j != i and abs((pattern_mod._day(days[j]["date"]) - when).days) <= 3 for j in range(len(days)))
        timeline = {"dots": days, "first": days[0]["date"], "last": days[-1]["date"]}
    brand = next((sites[h]["brand"] for h in op["sites"] if sites[h].get("brand")), None)
    resp = templates.TemplateResponse(request, "operation_report.html", {"g": op, "stats": data["stats"], "brand": brand, "timeline": timeline,
                                                                       "generated": datetime.now(UTC).strftime("%Y-%m-%d %H:%M UTC")})  # fmt: skip
    if download:
        slug = _re.sub(r"[^a-z0-9]+", "-", op["name"].lower()).strip("-")[:48] or "operation"
        resp.headers["Content-Disposition"] = f'attachment; filename="operation-{op["index"]}-{slug}.html"'
    return resp


@router.get("/campaigns/all", response_class=HTMLResponse)
def campaigns_all_page(
    request: Request, session: Annotated[Session, Depends(get_session, scope="function")], user: Annotated[User | None, Depends(ui_user)],
    brand_id: str = "",
):  # fmt: skip
    """Every confirmed site on one map: are they connected, and by what."""
    if user is None:
        return _login_redirect(request)
    bid = _uuid_or_none(brand_id)
    data = campaigns_api.all_map(session, user, bid)
    brands = brands_api.list_brands(session, user)
    # one chip per brand: its confirmed sites (with its country campaigns), the map shows only them when chosen
    per: dict[str, int] = {}
    for f in campaigns_api._confirmed(session, user, None):
        per[str(f.brand_id)] = per.get(str(f.brand_id), 0) + 1
    brand_chips = [{"id": str(b["id"]), "name": b["name"], "count": sum(per.get(str(i), 0) for i in regions_mod.with_regions(session, uuid.UUID(str(b["id"]))))}
                   for b in brands if not b.get("parent_id")]  # fmt: skip
    return _render(request, "campaigns_all.html", user, m=data, brands=brands, active="campaigns",
                   brand_id=str(bid) if bid else "", brand_chips=[c for c in brand_chips if c["count"]], brand_total=sum(per.values()))  # fmt: skip


@router.get("/campaigns", response_class=HTMLResponse)
def campaigns_page(
    request: Request, session: Annotated[Session, Depends(get_session, scope="function")], user: Annotated[User | None, Depends(ui_user)],
    brand_id: str = "",
):  # fmt: skip
    if user is None:
        return _login_redirect(request)
    brand_id = _uuid_or_none(brand_id)
    rows = campaigns_api.list_campaigns(session, user, brand_id=brand_id, limit=100)
    brands = brands_api.list_brands(session, user)
    return _render(
        request,
        "campaigns.html",
        user,
        campaigns=rows,
        stats=ui_stats.campaign_stats(session, rows),
        brands=brands,
        confirmed=(confirmed := confirmed_sites(session, user, brand_id, brands)),
        glance=ui_stats.confirmed_at_a_glance(session, user.workspace_id, confirmed),
        batch=_map_batch(session, user),
        todo={"map": sum(1 for x in confirmed if x["map_status"] in ("none", "failed")),
              "investigate": sum(1 for x in confirmed if not x["intel_job"] or x["intel_job"]["state"] in ("failed", "cancelled")),
              "active": sum(1 for x in confirmed if x["map_status"] == "mapping" or (x["intel_job"] and x["intel_job"]["state"] in ("queued", "running"))
                            or x["batch_position"])},  # fmt: skip
        active="campaigns",
    )


def confirmed_sites(
    session: Session, user: User, brand_id: uuid.UUID | None, brands: list[dict]
) -> list[dict[str, Any]]:
    """Every confirmed phishing site of the workspace with its takedown and infrastructure-map
    status — the backbone of the Takedowns page and of the Attack infrastructure page."""
    from brandwatch.db.models import Candidate, TakedownDraft
    from brandwatch.detection import reports as reports_svc

    q = (
        sa.select(Finding).join(Brand, Brand.id == Finding.brand_id)
        .where(Brand.workspace_id == user.workspace_id, Finding.state == FindingState.CONFIRMED, Finding.kind != "ai_answer")  # a contact is not a site
    )  # fmt: skip
    if brand_id:
        q = q.where(Finding.brand_id.in_(regions_mod.with_regions(session, brand_id)))
    findings = session.scalars(q.order_by(Finding.updated_at.desc())).all()
    ids = [f.id for f in findings]
    drafts: dict[uuid.UUID, Any] = {}
    for d in (session.scalars(sa.select(TakedownDraft).where(TakedownDraft.finding_id.in_(ids)).order_by(TakedownDraft.updated_at.asc())).all() if ids else []):  # fmt: skip
        drafts[d.finding_id] = d  # newest wins
    sids = [str(i) for i in ids]
    from brandwatch.db.models import Report

    intel_jobs = (
        session.scalars(
            sa.select(ScanJob).where(ScanJob.kind == "intel", ScanJob.workspace_id == user.workspace_id,
                                     ScanJob.payload["finding_id"].as_string().in_(sids)).order_by(ScanJob.created_at.desc())
        ).all() if ids else []
    )  # fmt: skip
    intel_of: dict[str, ScanJob] = {}
    for j in intel_jobs:
        intel_of.setdefault(str((j.payload or {}).get("finding_id")), j)
    package_of: dict[uuid.UUID, Any] = {}
    for r in (session.scalars(sa.select(Report).where(Report.finding_id.in_(ids), Report.kind == "evidence_package", Report.format == "html")
                              .order_by(Report.created_at.asc())).all() if ids else []):  # fmt: skip
        package_of[r.finding_id] = r  # newest wins
    batch = _map_batch(session, user)
    waiting = {fid: i for i, fid in enumerate(batch["finding_ids"], 1)} if batch and batch["state"] in ("queued", "running") else {}
    map_jobs = (
        session.scalars(
            sa.select(ScanJob)
            .where(
                ScanJob.kind == "investigate",
                ScanJob.workspace_id == user.workspace_id,
                ScanJob.payload["finding_id"].as_string().in_(sids),
            )
            .order_by(ScanJob.created_at.desc())
        ).all()
        if ids
        else []
    )
    job_of: dict[str, ScanJob] = {}
    for j in map_jobs:
        fid = (j.payload or {}).get("finding_id")
        if fid and fid not in job_of:
            job_of[fid] = j
    # when it was confirmed: the analyst's audit event (updated_at moves on every later change)
    from brandwatch.db.models import AuditEvent

    confirmed_at: dict[str, str] = {}
    audit_rows = (
        session.scalars(
            sa.select(AuditEvent)
            .where(AuditEvent.action == "finding.confirmed", AuditEvent.object_id.in_(ids))
            .order_by(AuditEvent.at.asc())
        ).all()
        if ids
        else []
    )
    for ev in audit_rows:
        confirmed_at[str(ev.object_id)] = ev.at.isoformat()
    bname = {b["id"]: b["name"] for b in brands}
    active = [j.id for j in (*job_of.values(), *intel_of.values()) if j.state.value in ("queued", "running")]
    last = _last_messages(session, active)
    out = []
    for f in findings:
        cand = session.get(Candidate, f.candidate_id)
        d = drafts.get(f.id)
        j = job_of.get(str(f.id))
        out.append({
            "id": str(f.id), "hostname": cand.hostname if cand else "?", "brand_id": str(f.brand_id),
            "brand_name": bname.get(str(f.brand_id)), "severity": f.severity.value,
            "confirmed_at": confirmed_at.get(str(f.id)) or (f.updated_at.isoformat() if f.updated_at else None),
            "takedown": reports_svc.takedown_out(d, session) if d else None,
            "takedown_state": d.state.value if d else "none",
            "campaign_id": str(f.campaign_id) if f.campaign_id else None,
            "map_job": {"id": str(j.id), "state": j.state.value, "last": last.get(j.id)} if j else None,
            "intel_job": ({"id": str(ij.id), "state": ij.state.value, "light": bool((ij.payload or {}).get("light")), "last": last.get(ij.id)}
                          if (ij := intel_of.get(str(f.id))) else None),
            "batch_position": waiting.get(str(f.id)),
            "package_url": f"/api/reports/{package_of[f.id].id}" if f.id in package_of else None,
            "map_status": "mapped" if f.campaign_id else ("mapping" if j and j.state.value in ("queued", "running") else ("failed" if j and j.state.value in ("failed", "cancelled") else "none")),
        })  # fmt: skip
    return out


@router.get("/campaigns/{campaign_id}", response_class=HTMLResponse)
def campaign_page(
    campaign_id: uuid.UUID, request: Request,
    session: Annotated[Session, Depends(get_session, scope="function")], user: Annotated[User | None, Depends(ui_user)],
):  # fmt: skip
    if user is None:
        return _login_redirect(request)
    c = campaigns_api.get_campaign(campaign_id, session, user)
    iocs = campaigns_api.list_iocs(
        session, user, campaign_id=campaign_id, format="json", limit=5000
    )
    brand = session.get(Brand, uuid.UUID(c["brand_id"]))
    job = session.scalars(
        sa.select(ScanJob).where(ScanJob.kind == "investigate", ScanJob.brand_id == brand.id)
        .order_by(ScanJob.created_at.desc()).limit(50)
    ).all() if brand else []  # fmt: skip
    seed_job = next((j for j in job if (j.payload or {}).get("campaign_id") == c["id"]), None)
    job_id = str(seed_job.id) if seed_job else None
    seed = None
    seed_fid = (
        _uuid_or_none(str((seed_job.payload or {}).get("finding_id") or "")) if seed_job else None
    )
    if seed_fid:
        from brandwatch.db.models import Candidate

        row = session.execute(
            sa.select(Finding.id, Candidate.hostname)
            .join(Candidate, Candidate.id == Finding.candidate_id)
            .where(Finding.id == seed_fid)
        ).first()
        seed = {"id": str(row[0]), "hostname": row[1]} if row else None
    return _render(request, "campaign_detail.html", user, c=c, iocs=iocs, active="campaigns",
                   brand_name=brand.name if brand else None, job_id=job_id, seed=seed)  # fmt: skip


@router.get("/candidates", response_class=HTMLResponse)
def candidates_page(
    request: Request,
    session: Annotated[Session, Depends(get_session, scope="function")],
    user: Annotated[User | None, Depends(ui_user)],
    brand_id: str = "",
    state: str = "",
    q: str = "",
    page: int = 1,
    fmt: str = "",
):
    if user is None:
        return _login_redirect(request)
    brand_id = _uuid_or_none(brand_id)
    state = _enum_or_none(CandidateState, state)
    q = q.strip()[:120]
    per_page = 50
    stmt = findings_api.candidates_query(session, user, brand_id=brand_id, state=state, q=q)
    if fmt in ("csv", "json"):
        rows = findings_api.list_candidates(session, user, brand_id=brand_id, state=state, q=q, limit=5000)
        for r in rows:
            r["found_by"] = ", ".join(sorted({s["stream"] for s in r.get("sources") or []}))
        return _export(fmt, "watchlist", rows, ["id", "hostname", "brand_name", "state", "surface", "priority", "found_by", "first_seen", "last_seen", "next_scan_at", "scan_count"])
    total = findings_api.count_findings(session, stmt)
    pages = max(1, -(-total // per_page))
    page = max(1, min(page, pages))
    rows = findings_api.list_candidates(session, user, brand_id=brand_id, state=state, q=q, limit=per_page, offset=(page - 1) * per_page)
    brands = brands_api.list_brands(session, user)
    stats = ui_stats.watchlist_stats(session, user, brand_id)

    # a chip per brand with how many domains it has under the same state: "all brands" or one brand in a click
    cq = (sa.select(Candidate.brand_id, sa.func.count()).join(Brand, Brand.id == Candidate.brand_id)
          .where(Brand.workspace_id == user.workspace_id).group_by(Candidate.brand_id))  # fmt: skip
    if state:
        cq = cq.where(Candidate.state == state)
    counts = {str(b): n for b, n in session.execute(cq).all()}
    brand_chips = [{"id": str(b["id"]), "name": b["name"], "count": sum(counts.get(str(i), 0) for i in regions_mod.with_regions(session, uuid.UUID(str(b["id"]))))}
                   for b in brands]  # fmt: skip
    filters = {"brand_id": str(brand_id) if brand_id else "", "state": state.value if state else "", "q": q}
    base_qs = "&".join(f"{k}={v}" for k, v in filters.items() if v)
    return _render(request, "candidates.html", user, candidates=rows, brands=brands, stats=stats, active="candidates",
                   brand_chips=brand_chips, brand_total=sum(counts.values()), filters=filters,
                   total=total, page=page, pages=pages, per_page=per_page, base_qs=base_qs)  # fmt: skip


@router.post("/candidates/bulk-dismiss")
async def candidates_bulk_dismiss(
    request: Request,
    session: Annotated[Session, Depends(get_session, scope="function")], user: Annotated[User | None, Depends(ui_writer)],
):  # fmt: skip
    """Watchlist → tick several domains → Known legit: each one off the watchlist and allowlisted for its brand."""
    if user is None:
        return _login_redirect(request)
    form = await request.form()
    ids = [i for i in (_uuid_or_none(str(x)) for x in form.getlist("ids")) if i][:500]
    nxt = str(form.get("next") or "/ui/candidates")
    if not nxt.startswith("/ui/"):
        nxt = "/ui/candidates"
    take_write_lock(session)
    done = skipped = 0
    for cid in ids:
        try:
            candidates_api.dismiss_candidate(
                cid, candidates_api.DismissRequest(reason=str(form.get("reason") or "known legitimate domain")[:2000],
                                                   whitelist=form.get("whitelist") != "off"), session, user)  # fmt: skip
            done += 1
        except HTTPException:
            skipped += 1
    nxt = nxt.split("&bulk=")[0].split("?bulk=")[0]
    return RedirectResponse(nxt + ("&" if "?" in nxt else "?") + f"bulk=legit:{done}:{skipped}", status_code=303)


@router.get("/how-it-works", response_class=HTMLResponse)
def how_it_works_page(
    request: Request, session: Annotated[Session, Depends(get_session, scope="function")],
    user: Annotated[User | None, Depends(ui_user)],
):  # fmt: skip
    """The product in two minutes: an animated six-chapter story on the workspace's own data, then
    the deep material folded underneath (pipeline, demo walkthrough, facts, under the hood, glossary)."""
    if user is None:
        return _login_redirect(request)
    from brandwatch.about import project_facts
    from brandwatch.api.deep_info import DEEP
    from brandwatch.demo.story import flow, story
    from brandwatch.demo.tour import tour_stops

    s = request.app.state.settings
    return _render(request, "how_it_works.html", user, facts=project_facts(request.app), deep=DEEP,
                   stops=tour_stops(session, user), story=story(session, user), flow=flow(session, user),
                   links={"case_study": s.case_study_url}, active="how")  # fmt: skip


_OG_IMAGE = Path(__file__).parent / "assets" / "og-how-it-works.png"


@router.get("/assets/og-how-it-works.png")
def og_image() -> Response:
    """The picture a chat app or LinkedIn shows next to a link to How it works (1200×630, rendered
    from the flow diagram by scripts/render_og_image.py)."""
    if not _OG_IMAGE.exists():
        raise HTTPException(status_code=404)
    return Response(_OG_IMAGE.read_bytes(), media_type="image/png",
                    headers={"Cache-Control": "public, max-age=86400"})  # fmt: skip


@router.get("/takedowns", response_class=HTMLResponse)
def takedowns_page(
    request: Request, session: Annotated[Session, Depends(get_session, scope="function")],
    user: Annotated[User | None, Depends(ui_user)],
    brand_id: str = "", state: str = "", fmt: str = "",
):  # fmt: skip
    """Every confirmed phishing site and whether a takedown was requested — and how far it got."""
    if user is None:
        return _login_redirect(request)
    brand_id = _uuid_or_none(brand_id)
    brands = brands_api.list_brands(session, user)
    sites = confirmed_sites(session, user, brand_id, brands)
    states = ["none", *[s.value for s in TakedownState]]
    counts = {st: sum(1 for x in sites if x["takedown_state"] == st) for st in states}
    unsent = {"draft", "review", "approved", "reopened"}  # a request exists but was not sent yet
    inflight = {"sent", "acknowledged", "in_progress"}  # sent, waiting for the host / registrar
    def by_state(xs: list[dict[str, Any]]) -> list[dict[str, Any]]:
        if state == "unsent":
            return [x for x in xs if x["takedown_state"] in unsent]
        if state == "inflight":
            return [x for x in xs if x["takedown_state"] in inflight]
        return [x for x in xs if not state or x["takedown_state"] == state]

    now = datetime.now(UTC)
    for x in sites:
        t = x.get("takedown")
        sent = t.get("sent_at") if t else None
        x["waiting_days"] = None
        if sent and x["takedown_state"] in inflight:
            x["waiting_days"] = max(0, (now - datetime.fromisoformat(sent).replace(tzinfo=UTC)).days)
    if state == "stale":  # sent, and nobody answered for a week: time to chase or try another channel
        rows = [x for x in sites if (x["waiting_days"] or 0) >= 7 and x["takedown_state"] in ("sent", "acknowledged")]
    else:
        rows = by_state(sites)
    counts["stale"] = sum(1 for x in sites if (x["waiting_days"] or 0) >= 7 and x["takedown_state"] in ("sent", "acknowledged"))
    if fmt in ("csv", "json"):
        flat = [{"hostname": x["hostname"], "brand_name": x["brand_name"], "severity": x["severity"], "confirmed_at": x["confirmed_at"],
                 "takedown_state": x["takedown_state"], "reference": (x["takedown"] or {}).get("reference"), "abuse_contact": (x["takedown"] or {}).get("abuse_contact"),
                 "sent_at": (x["takedown"] or {}).get("sent_at"), "waiting_days": x["waiting_days"], "reported_portals": (x["takedown"] or {}).get("reported_count"),
                 "map_status": x["map_status"], "finding_id": x["id"]} for x in rows]  # fmt: skip
        return _export(fmt, "takedowns", flat, list(flat[0]) if flat else ["hostname"])
    # a chip per brand with how many confirmed sites it has under the same takedown state: "all brands" or one brand in a click
    every = by_state(confirmed_sites(session, user, None, brands) if brand_id else sites)
    per = {}
    for x in every:
        per[str(x["brand_id"])] = per.get(str(x["brand_id"]), 0) + 1
    brand_chips = [{"id": str(b["id"]), "name": b["name"], "count": sum(per.get(str(i), 0) for i in regions_mod.with_regions(session, uuid.UUID(str(b["id"]))))}
                   for b in brands]  # fmt: skip
    return _render(request, "takedowns.html", user, sites=rows, counts=counts, brands=brands, total=len(sites),
                   brand_chips=brand_chips, brand_total=len(every),
                   filters={"brand_id": str(brand_id) if brand_id else "", "state": state if (state in states or state in ("unsent", "inflight", "stale")) else ""},
                   active="takedowns")  # fmt: skip


@router.get("/activity", response_class=HTMLResponse)
def activity_page(
    request: Request,
    session: Annotated[Session, Depends(get_session, scope="function")],
    user: Annotated[User | None, Depends(ui_user)],
):
    if user is None:
        return _login_redirect(request)
    f = _activity_filters(request)
    per_page = 300
    page = max(1, int(request.query_params.get("page") or 1) if str(request.query_params.get("page") or "1").isdigit() else 1)
    stats = ui_stats.activity_stats(session, user, limit=per_page, offset=(page - 1) * per_page, **f)
    users = session.scalars(sa.select(User.email).where(User.workspace_id == user.workspace_id).order_by(User.email)).all()
    qs = "&".join(f"{k}={v}" for k, v in f.items() if v)
    return _render(request, "activity.html", user, stats=stats, filters=f, page=page, per_page=per_page, users=users,
                   base_qs=qs, active="activity")  # fmt: skip


def _activity_filters(request: Request) -> dict[str, str]:
    """?actor= (an e-mail or "system") · ?category= (finding, takedown, brand …) · ?object_id= · ?since= / ?until= (YYYY-MM-DD)."""
    import re as _re

    q = request.query_params
    day = lambda v: v if _re.fullmatch(r"\d{4}-\d{2}-\d{2}", v or "") else ""  # noqa: E731
    return {"actor": str(q.get("actor") or "")[:320], "category": _re.sub(r"[^a-z_]", "", str(q.get("category") or ""))[:40],
            "object_id": str(_uuid_or_none(q.get("object_id")) or ""), "since": day(q.get("since")), "until": day(q.get("until"))}  # fmt: skip


@router.get("/activity.csv")
def activity_csv(
    request: Request, session: Annotated[Session, Depends(get_session, scope="function")],
    user: Annotated[User | None, Depends(ui_user)],
):  # fmt: skip
    """The activity log with the page's filters, as CSV (one row per event, nothing collapsed; at most 20,000 rows)."""
    if user is None:
        return _login_redirect(request)
    import csv
    import io
    import json as _json

    rows = ui_stats.activity_rows(session, user, limit=20_000, **_activity_filters(request))
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["at_utc", "actor", "actor_type", "action", "object_type", "object_id", "old", "new", "reason"])
    for r in rows:
        w.writerow([r["at"], r["actor"], r["actor_type"], r["action"], r["object_type"], r["object_id"] or "",
                    _json.dumps(r["old"], ensure_ascii=False) if r["old"] else "", _json.dumps(r["new"], ensure_ascii=False) if r["new"] else "", r["reason"] or ""])  # fmt: skip
    return Response("\ufeff" + buf.getvalue(), media_type="text/csv; charset=utf-8",
                    headers={"Content-Disposition": 'attachment; filename="brandwatch-activity.csv"'})  # fmt: skip


def jobs_for_nav(
    session: Session, user: User
) -> list[ScanJob]:  # pragma: no cover - helper for templates
    return session.scalars(
        sa.select(ScanJob)
        .join(Brand, Brand.id == ScanJob.brand_id)
        .where(Brand.workspace_id == user.workspace_id)
        .limit(5)
    ).all()


@router.get("/dashboard/sites-map")
def dashboard_sites_map(
    request: Request, session: Annotated[Session, Depends(get_session, scope="function")], user: Annotated[User | None, Depends(ui_user)],
    brand_id: str = "",
):  # fmt: skip
    """The map of every confirmed site for the dashboard, fetched after the page is shown (the analysis takes about half a
    second). JSON, not HTML, so the static demo keeps a copy of it."""
    if user is None:
        return JSONResponse({"html": "", "error": "signed out"}, status_code=401)
    bid = _uuid_or_none(brand_id)
    data = campaigns_api.all_map(session, user, bid)
    html = templates.get_template("_sites_map.html").render(
        request=request, user=user, m=data, brand_id=str(bid) if bid else "", can_write=user.role is not UserRole.VIEWER, embed=True,
    )  # fmt: skip
    st = data.get("stats") or {}
    return JSONResponse({"html": html, "sites": st.get("sites", 0), "groups": st.get("groups", 0), "alone": st.get("alone", 0)})


@router.get("/dashboard", response_class=HTMLResponse)
def dashboard_page(
    request: Request,
    session: Annotated[Session, Depends(get_session, scope="function")],
    user: Annotated[User | None, Depends(ui_user)],
    brand_id: str = "",
):
    if user is None:
        return _login_redirect(request)
    brand_id = _uuid_or_none(brand_id)
    data = dashboard_api.dashboard(request, session, user, brand_id=brand_id)
    brands = brands_api.list_brands(session, user)
    # a brand that was never scanned: the dashboard says so first, with the way to its first scan
    scanned = set(session.scalars(sa.select(ScanJob.brand_id).where(ScanJob.workspace_id == user.workspace_id, ScanJob.kind == "brand_scan").distinct()).all())
    unscanned = sorted((b for b in brands if uuid.UUID(str(b["id"])) not in scanned), key=lambda b: str(b.get("created_at") or ""), reverse=True)  # newest first
    # new since yesterday: the open Critical / High ones that arrived in the last 24 hours, each a link
    new_stmt = findings_api.findings_query(session, user, brand_id=brand_id, state=FindingState.OPEN, since="24h", sort="newest")
    new_24h = [findings_api.finding_row(session, f) for f in session.scalars(
        new_stmt.where(Finding.severity.in_([Severity.CRITICAL, Severity.HIGH])).limit(8)).all()]  # fmt: skip
    # the takedowns waiting on the analyst: not drafted / not sent, or sent a week ago with no answer — oldest first
    now = datetime.now(UTC)
    queue = []
    for x in confirmed_sites(session, user, brand_id, brands):
        t = x.get("takedown") or {}
        st = x["takedown_state"]
        sent = t.get("sent_at")
        days = (now - datetime.fromisoformat(sent).replace(tzinfo=UTC)).days if sent else None
        if st in ("none", "draft", "review", "approved", "reopened") or (st in ("sent", "acknowledged") and (days or 0) >= 7):
            since = x.get("confirmed_at") or ""
            queue.append({**x, "waiting_days": days, "why": "no request yet" if st == "none" else ("not sent yet" if days is None else f"no answer for {days} days"),
                          "since": since})  # fmt: skip
    queue.sort(key=lambda r: r["since"])
    # brands at a glance (all brands only) and the next watchlist re-checks
    from brandwatch.detection import schedule as sched_mod
    from brandwatch.detection.runner import load_brand_config

    brand_rows = []
    if not brand_id:
        brand_rows = ui_stats.brand_cards(session, user, brands)
        for r in brand_rows:
            row = session.get(Brand, uuid.UUID(str(r["id"])))
            sc = sched_mod.load(row, load_brand_config(session, row.id).detection) if row is not None else None
            r["schedule"] = sc.label if sc is not None and sc.enabled else None
    upcoming = ui_stats.watchlist_stats(session, user, brand_id)["upcoming"][:5]
    return _render(
        request, "dashboard.html", user, d=data, brands=brands, active="dashboard",
        selected_brand=str(brand_id) if brand_id else "", unscanned=unscanned, new_24h=new_24h,
        takedown_queue=queue[:6], takedown_queue_total=len(queue), brand_rows=brand_rows, upcoming=upcoming,
        scheduler_interval=request.app.state.settings.scheduler_interval_seconds,
    )  # fmt: skip


# --------------------------------------------------------------------------------------------
# global search
# --------------------------------------------------------------------------------------------
@router.get("/search", response_class=HTMLResponse)
def search_page(
    request: Request, session: Annotated[Session, Depends(get_session, scope="function")],
    user: Annotated[User | None, Depends(ui_user)], q: str = "",
):  # fmt: skip
    """One box for everything: a domain, an IP, a takedown reference or a brand name — findings (any state), the watchlist,
    the allowlist, takedowns, indicators on the infrastructure maps and brands."""
    if user is None:
        return _login_redirect(request)
    q = q.strip()[:120]
    return _render(request, "search.html", user, q=q, results=global_search(session, user, q) if len(q) >= 2 else None, active="")


def global_search(session: Session, user: User, q: str) -> dict[str, list[dict[str, Any]]]:
    from brandwatch.db.models import BrandDomain, Ioc, TakedownDraft

    like = f"%{q.lower()}%"
    brand_rows = session.scalars(sa.select(Brand).where(Brand.workspace_id == user.workspace_id)).all()
    bname = {b.id: b.name for b in brand_rows}
    ids = list(bname)
    if not ids:
        return {"findings": [], "watchlist": [], "allowlist": [], "takedowns": [], "indicators": [], "brands": []}
    findings = session.execute(
        sa.select(Finding, Candidate.hostname).join(Candidate, Candidate.id == Finding.candidate_id)
        .where(Finding.brand_id.in_(ids), sa.func.lower(Candidate.hostname).like(like)).order_by(Finding.created_at.desc()).limit(25)
    ).all()  # fmt: skip
    found_cands = {f.candidate_id for f, _ in findings}
    cands = session.scalars(
        sa.select(Candidate).where(Candidate.brand_id.in_(ids), sa.func.lower(Candidate.hostname).like(like)).order_by(Candidate.last_seen.desc()).limit(25)
    ).all()  # fmt: skip
    allow = session.scalars(sa.select(BrandDomain).where(BrandDomain.brand_id.in_(ids), sa.func.lower(BrandDomain.domain).like(like)).limit(25)).all()
    tds = session.execute(
        sa.select(TakedownDraft, Candidate.hostname).join(Finding, Finding.id == TakedownDraft.finding_id).join(Candidate, Candidate.id == Finding.candidate_id)
        .where(Finding.brand_id.in_(ids), sa.or_(sa.func.lower(Candidate.hostname).like(like), sa.cast(TakedownDraft.id, sa.String).like(like),
                                                 sa.func.lower(sa.func.coalesce(TakedownDraft.abuse_contact, "")).like(like)))
        .order_by(TakedownDraft.updated_at.desc()).limit(25)
    ).all()  # fmt: skip
    iocs = session.scalars(sa.select(Ioc).where(Ioc.workspace_id == user.workspace_id, sa.func.lower(Ioc.value).like(like)).limit(25)).all()

    return {
        "findings": [{"id": str(f.id), "host": h, "severity": f.severity.value, "state": f.state.value, "brand": bname.get(f.brand_id), "kind": f.kind}
                     for f, h in findings],
        "watchlist": [{"id": str(c.id), "host": c.hostname, "state": c.state.value, "brand": bname.get(c.brand_id)} for c in cands if c.id not in found_cands],
        "allowlist": [{"domain": d.domain, "kind": d.kind, "official": d.is_official, "brand": bname.get(d.brand_id), "brand_id": str(d.brand_id)} for d in allow],
        "takedowns": [{"id": str(t.id), "reference": t.reference, "host": h, "state": t.state.value}
                      for t, h in tds],
        "indicators": [{"type": getattr(i.type, "value", str(i.type)), "value": i.value, "campaign_id": str(i.campaign_id) if getattr(i, "campaign_id", None) else None}
                       for i in iocs],
        "brands": [{"id": str(b.id), "name": b.name} for b in brand_rows if q.lower() in b.name.lower()],
    }  # fmt: skip


# --------------------------------------------------------------------------------------------
# every scan of the workspace
# --------------------------------------------------------------------------------------------
JOB_KINDS = ("brand_scan", "url_scan", "investigate", "intel", "map_all")


@router.get("/scans", response_class=HTMLResponse)
def scans_page(
    request: Request, session: Annotated[Session, Depends(get_session, scope="function")],
    user: Annotated[User | None, Depends(ui_user)], brand_id: str = "", state: str = "", kind: str = "", page: int = 1,
):  # fmt: skip
    """Every scan, map and investigation of the workspace, newest first, with a Retry on the ones that failed."""
    if user is None:
        return _login_redirect(request)
    from brandwatch.db.enums import JobState

    bid = _uuid_or_none(brand_id)
    stmt = sa.select(ScanJob).where(ScanJob.workspace_id == user.workspace_id)
    if bid:
        stmt = stmt.where(ScanJob.brand_id.in_(regions_mod.with_regions(session, bid)))
    st = _enum_or_none(JobState, state)
    if st:
        stmt = stmt.where(ScanJob.state == st)
    if kind in JOB_KINDS:
        stmt = stmt.where(ScanJob.kind == kind)
    per_page = 50
    total = int(session.scalar(sa.select(sa.func.count()).select_from(stmt.subquery())) or 0)
    pages = max(1, -(-total // per_page))
    page = max(1, min(page, pages))
    jobs = session.scalars(stmt.order_by(ScanJob.created_at.desc()).limit(per_page).offset((page - 1) * per_page)).all()
    brands = brands_api.list_brands(session, user)
    bname = {str(b["id"]): b["name"] for b in brands}
    rows = [{**scans_api.job_out(session, j), "brand_name": bname.get(str(j.brand_id)),
             "payload": {k: (j.payload or {}).get(k) for k in ("only", "retry_of")}} for j in jobs]  # fmt: skip
    filters = {"brand_id": str(bid) if bid else "", "state": st.value if st else "", "kind": kind if kind in JOB_KINDS else ""}
    base_qs = "&".join(f"{k}={v}" for k, v in filters.items() if v)
    return _render(request, "scans.html", user, jobs=rows, brands=brands, filters=filters, total=total, page=page, pages=pages,
                   per_page=per_page, base_qs=base_qs, JOB_KINDS=JOB_KINDS, JOB_STATES=[s.value for s in JobState], active="scans")  # fmt: skip


@router.post("/jobs/{job_id}/retry")
def job_retry(
    job_id: uuid.UUID, request: Request,
    session: Annotated[Session, Depends(get_session, scope="function")], user: Annotated[User | None, Depends(ui_writer)],
):  # fmt: skip
    """Run a failed or stopped scan again: the same kind, brand and parameters, as a new job (the old one stays on record)."""
    if user is None:
        return _login_redirect(request)
    job = session.get(ScanJob, job_id)
    if job is None or job.workspace_id != user.workspace_id:
        raise HTTPException(404, "scan not found")
    if job.state.value not in ("failed", "cancelled"):
        return RedirectResponse(f"/ui/jobs/{job_id}", status_code=303)
    payload = {k: v for k, v in (job.payload or {}).items() if k not in ("batch",)}
    payload["requested_by"] = str(user.id)
    payload["retry_of"] = str(job.id)
    audit(session, workspace_id=user.workspace_id, actor_type="analyst", actor_id=user.id, action="scan.retried",
          object_type="scan_job", object_id=job.id, new={"kind": job.kind})  # fmt: skip
    session.commit()
    new_id = request.app.state.queue.enqueue(job.kind, payload, workspace_id=user.workspace_id, brand_id=job.brand_id)
    return RedirectResponse(f"/ui/jobs/{new_id}", status_code=303)


@router.get("", include_in_schema=False)
def ui_root(
    request: Request, session: Annotated[Session, Depends(get_session, scope="function")],
    user: Annotated[User | None, Depends(ui_user)],
) -> Response:  # fmt: skip
    if user is None:
        return _login_redirect(request)
    return RedirectResponse(landing_for(session, user), status_code=303)
