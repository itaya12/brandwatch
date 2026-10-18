"""Brands API (spec §14 "Brands" tab, Phase 1 subset): create a brand with its official domains,
build the attack-surface baseline, and launch scans."""

from __future__ import annotations

import uuid
from typing import Annotated, Any, Literal
from urllib.parse import urlsplit

import sqlalchemy as sa
from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from brandwatch import keys as keystore
from brandwatch import tenancy
from brandwatch.api.auth import (
    audit,
    current_user,
    require_admin,
    require_analyst,
)
from brandwatch.api.deps import get_session
from brandwatch.config.brand_config import (
    BRAND_SWITCHES,
    BrandConfig,
    detection_for_preset,
    is_custom_detection,
)
from brandwatch.db.base import immediate_writes
from brandwatch.db.enums import (
    DiscoverySource,
    FindingState,
    Surface,
    UserRole,
)
from brandwatch.db.maintenance import artifact_locations, purge_brand
from brandwatch.db.models import (
    ApiUsage,
    Brand,
    BrandDomain,
    BrandFingerprint,
    Config,
    Finding,
    ScanJob,
    User,
)
from brandwatch.db.types import utcnow
from brandwatch.detection import ai as ai_mod
from brandwatch.detection import baseline_health, rescore
from brandwatch.detection import regions as regions_mod
from brandwatch.detection import schedule as schedule_mod
from brandwatch.detection import search_queries as search_queries_mod
from brandwatch.detection.baseline import (
    build_baseline,
    latest_fetch,
    load_baseline,
    official_domains,
)
from brandwatch.detection.discovery import split_host
from brandwatch.detection.normalize import canonical_listing_url, is_app_store, normalize
from brandwatch.pipeline.stages import DiscoveryHit
from brandwatch.providers.registry import ProviderRegistry
from brandwatch.trace import trace_path

router = APIRouter(prefix="/api/brands", tags=["brands"])


class BrandCreate(BaseModel):
    name: str = Field(min_length=2, max_length=200)
    vertical: str | None = Field(default=None, max_length=64)
    domains: list[str] = Field(min_length=1, max_length=50)
    preset: Literal["basic", "standard", "enterprise"] = "basic"
    # "retail": other shops resell its products → scam shops advertising them are hunted on Meta ads
    kind: Literal["retail", "service"] = "service"
    # the track's parameters, changed from the start ("Customise parameters"): layered on top of ``preset`` like
    # PATCH /config does; omitted = the pure track
    detection: dict[str, Any] | None = None
    scoring: dict[str, Any] | None = None


class BrandPatch(BaseModel):
    """Edit a brand after creation. ``domains`` replaces the official-domain list (first = primary)."""

    name: str | None = Field(default=None, min_length=2, max_length=200)
    vertical: str | None = Field(default=None, max_length=64)
    domains: list[str] | None = Field(default=None, min_length=1, max_length=50)


ScanTask = Literal["dnstwist", "ct", "nrd", "search", "urlscan", "meta_ads", "social", "ai_answers", "contacts"]
# "scan now, only …": one part of the scan, by itself
ONLY_PARTS = {
    "lookalike": "look-alike sites",
    "search": "Google search",
    "social": "social media",
    "ads": "Facebook / Instagram ads",
    "ai": "AI answers",
    "contacts": "official contacts",
}
DOMAIN_STREAMS = ("dnstwist", "ct", "nrd", "urlscan")


def tasks_for_only(cfg: BrandConfig, only: str) -> list[str]:
    """The tasks of one part of the scan: look-alike sites use the brand's own domain streams (dnstwist at least)."""
    if only == "lookalike":
        return [x for x in cfg.detection.streams if x in DOMAIN_STREAMS] or ["dnstwist"]
    return {"search": ["search"], "social": ["social"], "ads": ["meta_ads"], "ai": ["ai_answers"], "contacts": ["contacts"]}[only]


class ScanRequest(BaseModel):
    max_candidates: int | None = Field(default=None, ge=1, le=5000)
    max_names: int | None = Field(default=None, ge=1, le=100_000)  # look-alike names checked in DNS
    rebuild_baseline: bool = False  # fingerprint the official site again before discovery
    tasks: list[ScanTask] | None = Field(default=None, min_length=1, max_length=9)  # only these parts (None: the whole track)
    only: Literal["lookalike", "search", "social", "ads", "ai", "contacts"] | None = None  # shorthand for tasks, by part


class UrlScanRequest(BaseModel):
    urls: list[str] = Field(min_length=1, max_length=200)


def _get_brand(session: Session, user: User, brand_id: uuid.UUID) -> Brand:
    brand = session.get(Brand, brand_id)
    if brand is None or brand.workspace_id != user.workspace_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "brand not found")
    return brand


def profile_view(brand: Brand) -> dict[str, Any]:
    """The brand's commerce profile with every key present (the column is null until first saved)."""
    from brandwatch.detection import ad_settings

    p = dict(brand.profile or {})
    return {
        **ad_settings.settings(p),  # ads_per_search, ad_searches_max, shops_checked_max
        "countries": list(p.get("countries") or []),
        "ad_keywords": list(p.get("ad_keywords") or []),
        "products": list(p.get("products") or []),
        "official_pages": list(p.get("official_pages") or []),
        "official_social": list(p.get("official_social") or []),
        "baseline_url": p.get("baseline_url"),  # another official page to fingerprint when the homepage blocks us
        "official_apps": list(p.get("official_apps") or []),  # app-store listings the analyst named as the brand's own
        "updated_at": p.get("updated_at"),
    }


def brand_summary(session: Session, brand: Brand) -> dict[str, Any]:
    fp_version = session.scalar(
        sa.select(sa.func.max(BrandFingerprint.version)).where(
            BrandFingerprint.brand_id == brand.id
        )
    )
    open_findings = session.scalar(
        sa.select(sa.func.count())
        .select_from(Finding)
        .where(Finding.brand_id == brand.id, Finding.state == FindingState.OPEN)
    )
    kids = regions_mod.regions_of(session, brand.id)
    parent = session.get(Brand, brand.parent_id) if brand.parent_id else None
    fetch = latest_fetch(session, brand.id)
    family_open = open_findings or 0
    for k in kids:
        family_open += session.scalar(
            sa.select(sa.func.count()).select_from(Finding).where(Finding.brand_id == k.id, Finding.state == FindingState.OPEN)
        ) or 0
    return {
        "id": str(brand.id),
        "name": brand.name,
        "vertical": brand.vertical,
        "kind": brand.kind or "service",
        "profile": profile_view(brand),
        "domains": official_domains(session, brand.id),
        "fingerprint_version": fp_version or 0,
        "open_findings": open_findings or 0,
        "created_at": brand.created_at.isoformat(),
        "parent_id": str(brand.parent_id) if brand.parent_id else None,
        "parent_name": parent.name if parent else None,
        "region": brand.region,
        "regions": [{"id": str(k.id), "name": k.name, "region": k.region, "domains": official_domains(session, k.id),
                     "countries": list((k.profile or {}).get("countries") or []),
                     "open_findings": session.scalar(sa.select(sa.func.count()).select_from(Finding).where(
                         Finding.brand_id == k.id, Finding.state == FindingState.OPEN)) or 0} for k in kids],
        "family_open_findings": family_open,
        "baseline_fetch": fetch,
        "baseline_blocked": bool(fetch and not fetch.get("ok", True)),
        "baseline_snapshot": bool(fetch and fetch.get("source") == "urlscan"),
    }


@router.delete("/{brand_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_brand(
    brand_id: uuid.UUID,
    request: Request,
    session: Annotated[Session, Depends(get_session, scope="function")],
    user: Annotated[User, Depends(require_admin)],
) -> Response:
    """Start over: delete the brand with every candidate, finding, campaign, scan and evidence
    row it produced (admin only; evidence immutability is suspended for this one transaction).
    Audit events are kept, and this action writes one more."""
    if user.role is not UserRole.ADMIN:  # also when called from the UI, which bypasses Depends
        raise HTTPException(status.HTTP_403_FORBIDDEN, "admin role required")
    brand = _get_brand(session, user, brand_id)
    kids = regions_mod.regions_of(session, brand.id)
    if kids:
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            f"{brand.name} has regional campaigns ({', '.join(k.region or k.name for k in kids)}): delete them first",
        )
    name, domains = brand.name, official_domains(session, brand.id)
    artifacts = artifact_locations(session, brand.id)
    job_ids = list(session.scalars(sa.select(ScanJob.id).where(ScanJob.brand_id == brand.id)))
    deleted = purge_brand(session, brand.id)
    traces = 0
    for jid in job_ids:  # the engineering trace files of the brand's scans
        tp = trace_path(request.app.state.settings.evidence_dir, jid)
        if tp.is_file():
            tp.unlink()
            traces += 1
    if traces:
        deleted["trace_files"] = traces
    store = getattr(request.app.state, "store", None)
    if store is not None and hasattr(store, "delete"):
        deleted["artifact_files"] = sum(1 for loc in artifacts if store.delete(loc))
    audit(
        session, workspace_id=user.workspace_id, actor_type="analyst", actor_id=user.id,
        action="brand.purged", object_type="brand", object_id=brand_id,
        old={"name": name, "domains": domains}, new={"deleted_rows": deleted},
    )  # fmt: skip
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.get("")
def list_brands(
    session: Annotated[Session, Depends(get_session, scope="function")],
    user: Annotated[User, Depends(current_user)],
) -> list[dict[str, Any]]:
    brands = list(session.scalars(
        sa.select(Brand).where(Brand.workspace_id == user.workspace_id).order_by(Brand.created_at)
    ).all())
    # a main brand's regions right after it (every selector and list shows the family together)
    kids: dict[uuid.UUID, list[Brand]] = {}
    for b in brands:
        if b.parent_id:
            kids.setdefault(b.parent_id, []).append(b)
    ids = {b.id for b in brands}
    ordered: list[Brand] = []
    for b in brands:
        if not b.parent_id or b.parent_id not in ids:
            ordered.append(b)
            ordered += kids.get(b.id, [])
    return [brand_summary(session, b) for b in ordered]


def split_entries(entries: list[str]) -> tuple[list[str], list[str]]:
    """The "official domains" lines of the add / edit form → ``(domains, app listings)``.

    Analysts paste what they have: the website, and also the app-store pages of the brand's apps. A listing must
    never become an official *domain* - that would whitelist the whole store (every fake "MetaMask" app on
    play.google.com would be dismissed as the brand's own) - so a link into an app store is kept as an official app
    listing (``profile.official_apps``, which the scan treats like the listings linked from the official site)."""
    domains: list[str] = []
    apps: list[str] = []
    for raw in entries:
        text = str(raw or "").strip()
        if not text:
            continue
        norm = normalize(DiscoveryHit(DiscoverySource.MANUAL, text, Surface.NAME))
        if norm is None:
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, f"invalid domain: {raw!r}")
        if is_app_store(norm.hostname):
            url = text if "://" in text else "https://" + text
            if not urlsplit(url).path.strip("/"):
                raise HTTPException(
                    status.HTTP_422_UNPROCESSABLE_CONTENT,
                    f"{norm.hostname} is an app store, not a domain of the brand: paste the link of the app's own page there",
                )
            listing = canonical_listing_url(url)
            if listing not in apps:
                apps.append(listing)
        elif norm.hostname not in domains:
            domains.append(norm.hostname)
    return domains, apps


@router.post("", status_code=status.HTTP_201_CREATED)
def create_brand(
    body: BrandCreate,
    session: Annotated[Session, Depends(get_session, scope="function")],
    user: Annotated[User, Depends(require_analyst)],
) -> dict[str, Any]:
    domains, apps = split_entries(body.domains)
    if not domains:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, "add at least one official domain (the brand's own website)")
    brand = Brand(
        workspace_id=user.workspace_id,
        name=body.name.strip(),
        vertical=body.vertical,
        kind=body.kind,
        profile={"official_apps": apps} if apps else None,
    )
    session.add(brand)
    session.flush()
    for i, d in enumerate(domains):
        session.add(
            BrandDomain(
                brand_id=brand.id,
                domain=d,
                is_official=True,
                kind="official" if i == 0 else "alias",
            )
        )
    cfg = BrandConfig.for_preset(body.preset)
    session.add(
        Config(
            brand_id=brand.id,
            preset=cfg.preset,
            detection=cfg.detection.model_dump(),
            economic_limits={},  # inherit the workspace budget until a brand override is set
            scoring=cfg.scoring.model_dump(mode="json"),
        )  # fmt: skip
    )
    audit(
        session, workspace_id=user.workspace_id, actor_type="analyst", actor_id=user.id,
        action="brand.created", object_type="brand", object_id=brand.id,
        new={"name": brand.name, "domains": domains, "official_apps": apps, "preset": body.preset, "kind": body.kind,
             "custom": bool(body.detection or body.scoring)},
    )  # fmt: skip
    session.flush()
    if body.detection or body.scoring:  # validated like any later change (unknown knobs and bad values are refused)
        patch_config(brand.id, ConfigPatch(preset=body.preset, detection=body.detection, scoring=body.scoring), session, user)
    return brand_summary(session, brand)


def config_patch_from_form(form: Any, default_mode: str = "custom") -> tuple[str | None, dict[str, Any], dict[str, Any], bool]:
    """The detection-track form (the brand page and the add-brand form) → ``(preset, detection, scoring, custom)``.
    ``custom`` False = the pure track: the preset's profile replaces every knob. Raises ValueError on a bad number."""
    weights: dict[str, int] = {}
    caps: dict[str, int] = {}
    thresholds: dict[str, int] = {}
    detection: dict[str, Any] = {}
    preset = str(form.get("preset") or "")
    preset = preset if preset in ("basic", "standard", "enterprise") else None
    custom = str(form.get("mode") or default_mode) == "custom"
    for k, v in form.multi_items():
        v = str(v).strip()
        if not v:
            continue
        if k.startswith("w_"):
            weights[k[2:]] = int(v)
        elif k.startswith("cap_"):
            caps[k[4:]] = int(v)
        elif k.startswith("t_"):
            thresholds[k[2:]] = int(v)
        elif k in ("watch_window_days", "watch_cadence_hours", "max_candidates", "max_names_checked", "scan_interval_hours", "search_queries_max"):
            detection[k] = int(v)
        elif k == "search_markets":  # the picker: [{"country": "us", "langs": ["en", "es"]}, …]
            from brandwatch.detection import markets as markets_mod

            detection["search_markets"] = markets_mod.normalize(v)
        elif k in ("tlds", "residential_probe", "search_geo", "search_lang", "residential_country"):
            detection[k] = v[:64]
    if "search_markets" in detection:  # the countries and the first language follow the markets
        from brandwatch.detection import markets as markets_mod

        if detection["search_markets"]:
            detection["search_geo"], detection["search_lang"] = markets_mod.legacy(detection["search_markets"])
    elif "search_geo" in detection or "search_lang" in detection:  # the two plain fields were edited: they are the truth now
        detection["search_markets"] = []
    if "search_queries" in form:  # an emptied box means "back to the AI-generated list"
        detection["search_queries"] = [q.strip() for q in str(form.get("search_queries") or "").splitlines() if q.strip()][:30]
    for flag in ("cloaking_probes", "social_accounts", "ai_second_opinion", "auto_map_on_confirm", "auto_investigate_on_confirm"):
        detection[flag] = form.get(flag) == "on"
    streams = [str(s) for s in form.getlist("streams")]
    if streams:
        detection["streams"] = streams
    if "reach_form" in form:  # "how far to look" on social media and in the ads: brand switches, kept whatever the track
        if str(form.get("social_accounts_max") or "").strip().isdigit():
            detection["social_accounts_max"] = max(1, min(50, int(str(form.get("social_accounts_max")))))
        detection["phishing_ads"] = form.get("phishing_ads") == "on"
    if "ai_answers_form" in form:  # the AI-answers block: a brand switch, kept whatever the track
        detection["ai_answers"] = form.get("ai_answers") == "on"
        engines = [e for e in form.getlist("ai_engines") if e in ("chatgpt", "gemini", "google_ai_mode")]
        detection["ai_engines"] = engines or ["chatgpt", "gemini", "google_ai_mode"]
    scoring: dict[str, Any] = {}
    if weights:
        scoring["weights"] = weights
    if caps:
        scoring["group_caps"] = caps
    if thresholds:
        scoring["thresholds"] = thresholds
    return preset, detection, scoring, custom


@router.patch("/{brand_id}")
def update_brand(
    brand_id: uuid.UUID,
    body: BrandPatch,
    session: Annotated[Session, Depends(get_session, scope="function")],
    user: Annotated[User, Depends(require_analyst)],
) -> dict[str, Any]:
    """Rename, change the vertical, or replace the official domains (whitelist rows are untouched)."""
    brand = _get_brand(session, user, brand_id)
    old = {
        "name": brand.name,
        "vertical": brand.vertical,
        "domains": official_domains(session, brand.id),
    }
    changed: dict[str, Any] = {}
    if body.name is not None and body.name.strip() != brand.name:
        brand.name = body.name.strip()
        changed["name"] = brand.name
    if body.vertical is not None and (body.vertical or None) != brand.vertical:
        brand.vertical = body.vertical or None
        changed["vertical"] = brand.vertical
    if body.domains is not None:
        wanted, apps = split_entries(body.domains)
        profile = dict(brand.profile or {})
        if apps != list(profile.get("official_apps") or []):  # the list is the whole truth: domains and app listings
            old["official_apps"] = list(profile.get("official_apps") or [])
            changed["official_apps"] = apps
            if apps:
                profile["official_apps"] = apps
            else:
                profile.pop("official_apps", None)
            brand.profile = profile or None
        if not wanted:
            raise HTTPException(
                status.HTTP_422_UNPROCESSABLE_CONTENT, "a brand needs at least one official domain"
            )
        rows = session.scalars(
            sa.select(BrandDomain).where(
                BrandDomain.brand_id == brand.id, BrandDomain.is_official.is_(True)
            )
        ).all()
        current = {r.domain.lower(): r for r in rows}
        for r in rows:
            if r.domain.lower() not in wanted:
                session.delete(r)
        for i, d in enumerate(wanted):
            row = current.get(d)
            if row is None:
                existing = session.scalars(
                    sa.select(BrandDomain).where(
                        BrandDomain.brand_id == brand.id, BrandDomain.domain == d
                    )
                ).first()
                if existing is not None:  # was on the whitelist → promote
                    existing.is_official, existing.kind = True, "official" if i == 0 else "alias"
                else:
                    session.add(
                        BrandDomain(
                            brand_id=brand.id,
                            domain=d,
                            is_official=True,
                            kind="official" if i == 0 else "alias",
                        )
                    )
            else:
                row.kind = "official" if i == 0 else "alias"
        if wanted != old["domains"]:
            changed["domains"] = wanted
    if changed:
        audit(session, workspace_id=user.workspace_id, actor_type="analyst", actor_id=user.id,
              action="brand.updated", object_type="brand", object_id=brand.id, old=old, new=changed)  # fmt: skip
    session.flush()
    from brandwatch.detection.protect import dismiss_protected

    dismiss_protected(session, brand.id)
    out = brand_summary(session, brand)
    out["changed"] = sorted(changed)
    out["domains_changed"] = "domains" in changed
    return out


def country_site_suggestions(session: Session, brand: Brand) -> list[dict[str, Any]]:
    """The brand's other country sites found on its official homepage (baseline ``country_sites``), minus
    the ones already in the family and the ones the analyst ignored."""
    fp = session.scalars(
        sa.select(BrandFingerprint).where(BrandFingerprint.brand_id == brand.id).order_by(BrandFingerprint.version.desc())
    ).first()
    if fp is None or brand.parent_id:  # a region is not the place to map further regions
        return []
    mine = {split_host(d).registrable for d in regions_mod.family_domains(session, brand.id)}
    ignored = {str(x).lower() for x in (brand.profile or {}).get("ignored_country_sites") or []}
    return [r for r in (fp.features or {}).get("country_sites") or []
            if r.get("domain") and r.get("country")  # an older fingerprint may hold brand-named domains without a country: not country sites
            and r["domain"] not in mine and r["domain"].lower() not in ignored]


# ------------------------------------------------------------------------------------------
# Regional campaigns of a global brand (detection/regions.py)
# ------------------------------------------------------------------------------------------
class RegionCreate(BaseModel):
    region: str = Field(min_length=2, max_length=60)
    domains: list[str] = Field(min_length=1, max_length=20)
    countries: list[str] = Field(default_factory=list, max_length=10)
    search_lang: str | None = Field(default=None, min_length=2, max_length=5)


def make_region(session: Session, user: User, parent: Brand, body: RegionCreate) -> Brand:
    """A child brand of ``parent``: its own domains, countries and language; the parent's settings copied once."""
    from brandwatch.detection.protect import dismiss_protected

    if parent.parent_id:
        raise HTTPException(status.HTTP_409_CONFLICT, "a regional campaign belongs to a main brand — add it there")
    domains: list[str] = []
    for raw in body.domains:
        norm = normalize(DiscoveryHit(DiscoverySource.MANUAL, raw, Surface.NAME))
        if norm is None:
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, f"invalid domain: {raw!r}")
        if norm.hostname not in domains:
            domains.append(norm.hostname)
    countries = [c for c in dict.fromkeys(ai_mod.clean_country(x) for x in body.countries) if c]
    countries = countries or [c for c in [regions_mod.guess_country(domains[0])] if c]
    if not countries:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, "name the country (ISO code) of this region")
    if any(r.region and r.region.lower() == body.region.strip().lower() for r in regions_mod.regions_of(session, parent.id)):
        raise HTTPException(status.HTTP_409_CONFLICT, f"{parent.name} already has a region called “{body.region.strip()}”")
    # a domain the main brand held as an alias moves to the region (one owner per domain)
    moved = list(session.scalars(sa.select(BrandDomain).where(
        BrandDomain.brand_id == parent.id, BrandDomain.is_official.is_(True), BrandDomain.kind != "official",
        BrandDomain.domain.in_(domains))).all())  # fmt: skip
    for row in moved:
        session.delete(row)
    taken = [d for d in domains if d in regions_mod.family_domains(session, parent.id) and d not in {m.domain for m in moved}]
    if taken:
        raise HTTPException(status.HTTP_409_CONFLICT, f"{', '.join(taken)} already belongs to this brand family")
    kind = parent.kind or "service"
    child = Brand(workspace_id=parent.workspace_id, name=regions_mod.region_name(parent, body.region.strip()),
                  vertical=parent.vertical, kind=kind, parent_id=parent.id, region=body.region.strip()[:64])  # fmt: skip
    child.profile = regions_mod.inherit(parent, None, countries)
    session.add(child)
    session.flush()
    for i, d in enumerate(domains):
        session.add(BrandDomain(brand_id=child.id, domain=d, is_official=True, kind="official" if i == 0 else "alias"))
    pcfg = tenancy.effective_brand_config(session, parent.id)
    det = pcfg.detection.model_dump()
    det["search_geo"] = ",".join(c.lower() for c in countries)
    det["search_lang"] = (body.search_lang or regions_mod.COUNTRY_LANG.get(countries[0], "en")).lower()
    det["search_markets"] = []  # a region searches in its own countries, in its own language
    det["search_queries"] = []  # the region approves its own, in its own language
    prow = session.scalars(sa.select(Config).where(Config.brand_id == parent.id)).first()
    session.add(Config(brand_id=child.id, preset=pcfg.preset, detection=det,
                       economic_limits=dict(prow.economic_limits or {}) if prow else {},
                       scoring=pcfg.scoring.model_dump(mode="json")))  # fmt: skip
    audit(session, workspace_id=user.workspace_id, actor_type="analyst", actor_id=user.id,
          action="brand.region_created", object_type="brand", object_id=child.id,
          new={"parent": str(parent.id), "region": child.region, "domains": domains, "countries": countries,
               "moved_from_parent": [m.domain for m in moved]})  # fmt: skip
    session.flush()
    dismiss_protected(session, parent.id)  # the new site is now protected in every campaign of the family
    return child


@router.post("/{brand_id}/regions", status_code=status.HTTP_201_CREATED)
def create_region(
    brand_id: uuid.UUID, body: RegionCreate,
    session: Annotated[Session, Depends(get_session, scope="function")], user: Annotated[User, Depends(require_analyst)],
) -> dict[str, Any]:  # fmt: skip
    """A regional campaign of this (main) brand: ``The North Face · Israel`` with thenorthface.co.il."""
    parent = _get_brand(session, user, brand_id)
    return brand_summary(session, make_region(session, user, parent, body))


@router.post("/{brand_id}/regions/sync")
def sync_region(
    brand_id: uuid.UUID,
    session: Annotated[Session, Depends(get_session, scope="function")], user: Annotated[User, Depends(require_analyst)],
) -> dict[str, Any]:  # fmt: skip
    """"Update from the main brand": re-copy the main brand's track, scoring, keywords and ad reach into
    this region. Its own domains, countries, language, approved queries and prices are never touched."""
    child = _get_brand(session, user, brand_id)
    if not child.parent_id:
        raise HTTPException(status.HTTP_409_CONFLICT, "only a regional campaign can be updated from its main brand")
    parent = session.get(Brand, child.parent_id)
    pcfg = tenancy.effective_brand_config(session, parent.id)
    crow = session.scalars(sa.select(Config).where(Config.brand_id == child.id)).first()
    prow = session.scalars(sa.select(Config).where(Config.brand_id == parent.id)).first()
    old_det = dict(crow.detection or {})
    det = pcfg.detection.model_dump()
    for k in ("search_geo", "search_lang", "search_queries", "residential_country"):
        det[k] = old_det.get(k, det.get(k))
    crow.preset, crow.detection = pcfg.preset, det
    crow.scoring = pcfg.scoring.model_dump(mode="json")
    crow.economic_limits = dict(prow.economic_limits or {}) if prow else {}
    prof = dict(child.profile or {})
    for k in regions_mod.INHERITED_PROFILE_KEYS:
        if k in (parent.profile or {}):
            prof[k] = (parent.profile or {})[k]
    child.profile = prof
    child.kind, child.vertical = parent.kind, parent.vertical
    audit(session, workspace_id=user.workspace_id, actor_type="analyst", actor_id=user.id,
          action="brand.region_synced", object_type="brand", object_id=child.id,
          new={"from": str(parent.id), "preset": pcfg.preset})  # fmt: skip
    session.flush()
    return brand_summary(session, child)


class CountrySiteAction(BaseModel):
    domain: str = Field(min_length=3, max_length=253)
    action: Literal["region", "domain", "ignore"]
    region: str | None = Field(default=None, max_length=60)
    countries: list[str] = Field(default_factory=list, max_length=10)


@router.post("/{brand_id}/country-sites")
def country_site_action(
    brand_id: uuid.UUID, body: CountrySiteAction,
    session: Annotated[Session, Depends(get_session, scope="function")], user: Annotated[User, Depends(require_analyst)],
) -> dict[str, Any]:  # fmt: skip
    """What to do with a country site found on the official homepage: make it a regional campaign, add it as
    another official domain of this brand, or ignore it. Nothing is added unless the analyst says so."""
    from brandwatch.detection.protect import dismiss_protected

    brand = _get_brand(session, user, brand_id)
    found = {r["domain"]: r for r in country_site_suggestions(session, brand)}
    dom = body.domain.strip().lower()
    if dom not in found:
        raise HTTPException(status.HTTP_404_NOT_FOUND, f"{dom} is not among the country sites found on the official site")
    row = found[dom]
    if body.action == "ignore":
        prof = dict(brand.profile or {})
        prof["ignored_country_sites"] = sorted({*(prof.get("ignored_country_sites") or []), dom})
        brand.profile = prof
        audit(session, workspace_id=user.workspace_id, actor_type="analyst", actor_id=user.id,
              action="brand.country_site_ignored", object_type="brand", object_id=brand.id, new={"domain": dom})  # fmt: skip
        session.flush()
        return {"action": "ignore", "domain": dom}
    if body.action == "domain":
        norm = normalize(DiscoveryHit(DiscoverySource.MANUAL, dom, Surface.NAME))
        if norm is None:
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, f"invalid domain: {dom!r}")
        session.add(BrandDomain(brand_id=brand.id, domain=norm.hostname, is_official=True, kind="alias"))
        audit(session, workspace_id=user.workspace_id, actor_type="analyst", actor_id=user.id,
              action="brand.country_site_added", object_type="brand", object_id=brand.id, new={"domain": dom})  # fmt: skip
        session.flush()
        dismiss_protected(session, brand.id)
        return {"action": "domain", "domain": dom}
    region = (body.region or row.get("region") or row.get("country") or "").strip()
    if not region:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, "name the region (e.g. Israel)")
    child = make_region(session, user, brand, RegionCreate(region=region, domains=[dom],
                        countries=body.countries or ([row["country"]] if row.get("country") else [])))  # fmt: skip
    return {"action": "region", "domain": dom, "region_id": str(child.id)}


# ------------------------------------------------------------------------------------ links on the official homepage
def _latest_fingerprint(session: Session, brand: Brand) -> BrandFingerprint | None:
    return session.scalars(
        sa.select(BrandFingerprint).where(BrandFingerprint.brand_id == brand.id).order_by(BrandFingerprint.version.desc())
    ).first()


def site_links(session: Session, brand: Brand) -> dict[str, Any]:
    """Every link from the official homepage to another site (baseline ``external_links``), each with its
    status: ``ours`` (already an official domain, a whitelisted partner, a known account or app), ``new``
    (waiting for a decision) — the ignored ones are left out and counted."""
    from brandwatch.detection.social import official_handles

    fp = _latest_fingerprint(session, brand)
    feats = (fp.features or {}) if fp else {}
    rows = list(feats.get("external_links") or [])
    if fp is None:
        return {"fingerprinted": False, "rows": [], "ignored": 0, "new": 0, "by_kind": {}}
    prof = brand.profile or {}
    ignored = {str(x) for x in prof.get("ignored_links") or []}
    family = {d.lower() for d in regions_mod.family_domains(session, brand.id)}
    family_reg = {split_host(d).registrable for d in family}
    partners = {d.domain.lower(): d.kind for d in session.scalars(
        sa.select(BrandDomain).where(BrandDomain.brand_id == brand.id, BrandDomain.is_official.is_(False))).all()}  # fmt: skip
    accounts = official_handles(prof, feats.get("official_social") or [])
    apps = {canonical_listing_url(str(a)).lower() for a in [*(feats.get("official_apps") or []), *(prof.get("official_apps") or [])]}
    out: list[dict[str, Any]] = []
    hidden = 0
    for r in rows:
        if r.get("key") in ignored:
            hidden += 1
            continue
        row = dict(r)
        status_, why = "new", ""
        if r["kind"] == "social":
            if f"{r['platform']}:{r['handle']}".lower() in accounts:
                status_, why = "ours", "a known account of the brand"
        elif r["kind"] == "app":
            if canonical_listing_url(r["url"]).lower() in apps:
                status_, why = "ours", "a known app of the brand"
        else:
            dom = (r.get("domain") or "").lower()
            if dom in family or dom in family_reg:
                status_, why = "ours", "an official domain of the brand"
            elif dom in partners:
                status_, why = "ours", f"whitelisted ({partners[dom]})"
        row["status"], row["status_why"] = status_, why
        out.append(row)
    by_kind: dict[str, int] = {}
    for r in out:
        by_kind[r["kind"]] = by_kind.get(r["kind"], 0) + 1
    return {"fingerprinted": True, "rows": out, "ignored": hidden, "new": sum(1 for r in out if r["status"] == "new"), "by_kind": by_kind}


class SiteLinkAction(BaseModel):
    key: str = Field(min_length=3, max_length=400)
    action: Literal["official", "partner", "ours", "ignore"]


@router.post("/{brand_id}/site-links")
def site_link_action(
    brand_id: uuid.UUID, body: SiteLinkAction,
    session: Annotated[Session, Depends(get_session, scope="function")], user: Annotated[User, Depends(require_analyst)],
) -> dict[str, Any]:  # fmt: skip
    """What to do with a link found on the official homepage: another official domain of the brand, a
    whitelisted partner, the brand's own social account, or ignore it. Nothing is added unless the analyst says so."""
    from brandwatch.detection.protect import dismiss_protected

    brand = _get_brand(session, user, brand_id)
    found = {r["key"]: r for r in site_links(session, brand)["rows"]}
    row = found.get(body.key)
    if row is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "that link is not among the links found on the official site")
    prof = dict(brand.profile or {})
    if body.action == "ignore":
        prof["ignored_links"] = sorted({*(prof.get("ignored_links") or []), body.key})
        brand.profile = prof
    elif body.action == "ours":
        if row["kind"] != "social":
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, "only a social account can be marked as the brand's own account")
        prof["official_social"] = sorted({*(prof.get("official_social") or []), f"{row['platform']}:{row['handle']}".lower()})
        brand.profile = prof
    else:
        if row["kind"] not in ("official_site", "other", "country_site"):
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, "only a website can be added as a domain")
        norm = normalize(DiscoveryHit(DiscoverySource.MANUAL, row["domain"], Surface.NAME))
        if norm is None:
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, f"invalid domain: {row['domain']!r}")
        if session.scalars(sa.select(BrandDomain).where(BrandDomain.brand_id == brand.id, BrandDomain.domain == norm.hostname)).first():
            raise HTTPException(status.HTTP_409_CONFLICT, "domain already listed for this brand")
        official = body.action == "official"
        session.add(BrandDomain(brand_id=brand.id, domain=norm.hostname, is_official=official, kind="alias" if official else "partner"))
    audit(session, workspace_id=user.workspace_id, actor_type="analyst", actor_id=user.id, action=f"brand.site_link_{body.action}",
          object_type="brand", object_id=brand.id, new={"key": body.key, "kind": row["kind"]})  # fmt: skip
    session.flush()
    if body.action in ("official", "partner"):
        dismiss_protected(session, brand.id)
    return {"action": body.action, "key": body.key}


@router.get("/{brand_id}")
def get_brand(
    brand_id: uuid.UUID,
    session: Annotated[Session, Depends(get_session, scope="function")],
    user: Annotated[User, Depends(current_user)],
) -> dict[str, Any]:
    brand = _get_brand(session, user, brand_id)
    out = brand_summary(session, brand)
    base = load_baseline(session, brand)
    out["baseline"] = (
        None
        if base is None
        else {
            "version": base.version,
            "brand_key": base.brand_key,
            "favicon_mmh3": base.favicon_mmh3,
            "favicon_phash": base.favicon_phash,
            "screenshot_phash": base.screenshot_phash,
            "keywords": list(base.keywords),
            "search_queries": list(base.search_queries),
            "auth_pages": list(base.auth_pages),
            "login_screenshot_phash": base.login_screenshot_phash,
            "has_login_form": base.has_login_form,
            "fetch": base.fetch,
        }
    )
    out["baseline_fixes"] = [{"id": i, "title": t, "detail": d} for i, t, d in baseline_health.FIXES]
    cfg = tenancy.effective_brand_config(session, brand.id)
    out["config"] = cfg.model_dump(mode="json")
    out["config_custom"] = is_custom_detection(cfg.preset, cfg.detection)
    out["search_queries"] = search_queries_mod.query_state(brand, cfg.detection, base).as_dict()
    out["schedule"] = schedule_view(session, brand, cfg, out["search_queries"])
    out["scoring_version"] = cfg.scoring.version
    out["country_sites"] = country_site_suggestions(session, brand)
    out["site_links"] = site_links(session, brand)
    out["ai_answers"] = ai_answers_view(session, brand, cfg)
    out["whitelist"] = [
        {"domain": d.domain, "kind": d.kind}
        for d in session.scalars(
            sa.select(BrandDomain)
            .where(BrandDomain.brand_id == brand.id, BrandDomain.is_official.is_(False))
            .order_by(BrandDomain.domain)
        ).all()
    ]
    return out


# ------------------------------------------------------------------------------------------
# Phase 6: configuration editor (scoring weights / thresholds / detection knobs), live re-score
# preview, apply, and the false-positive whitelist.
# ------------------------------------------------------------------------------------------
class ConfigPatch(BaseModel):
    preset: Literal["basic", "standard", "enterprise"] | None = None
    detection: dict[str, Any] | None = None
    scoring: dict[str, Any] | None = None
    economic_limits: dict[str, Any] | None = None


class WhitelistAdd(BaseModel):
    domain: str = Field(min_length=3, max_length=253)
    kind: Literal["partner", "subsidiary", "cdn", "reseller"] = "partner"


def _candidate_config(
    session: Session, brand: Brand, body: ConfigPatch
) -> tuple[BrandConfig, dict[str, Any]]:
    """Merge the patch into the stored config and validate it (BrandConfig forbids unknown keys,
    so a brand config can never carry a security limit)."""
    row = session.scalars(sa.select(Config).where(Config.brand_id == brand.id)).first()
    stored = {
        "preset": row.preset if row else "basic",
        "detection": dict(row.detection or {}) if row else {},
        "scoring": dict(row.scoring or {}) if row else {},
        "economic_limits": dict(row.economic_limits or {}) if row else {},
    }
    if body.preset:
        stored["preset"] = body.preset
        # choosing a track resets detection to its profile; an explicit detection patch
        # (custom mode) is then layered on top
        kept = {k: stored["detection"][k] for k in BRAND_SWITCHES if k in stored["detection"]}  # social on / off is the brand's
        stored["detection"] = {**detection_for_preset(body.preset).model_dump(), **kept}
    for part in ("detection", "scoring", "economic_limits"):
        patch = getattr(body, part)
        if patch:
            stored[part] = {**stored[part], **patch}
    if body.detection and ("search_geo" in body.detection or "search_lang" in body.detection) and "search_markets" not in body.detection:
        stored["detection"]["search_markets"] = []  # the plain fields were set by hand: they replace any markets
    elif body.detection and body.detection.get("search_markets"):
        from brandwatch.detection import markets as markets_mod

        mk = markets_mod.normalize(body.detection["search_markets"])
        stored["detection"]["search_markets"] = mk
        if mk and "search_geo" not in body.detection:
            stored["detection"]["search_geo"], stored["detection"]["search_lang"] = markets_mod.legacy(mk)
    stored["scoring"].pop("version", None)
    try:
        cfg = BrandConfig.model_validate(
            {
                **stored,
                "economic_limits": {
                    **tenancy.workspace_limits(session, brand.workspace_id).model_dump(),
                    **stored["economic_limits"],
                },
            }
        )
    except ValueError as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, str(exc)) from exc
    cfg.scoring.version = rescore.version_for(cfg.scoring)
    stored["scoring"] = cfg.scoring.model_dump(mode="json")
    return cfg, stored


@router.post("/{brand_id}/config/preview")
def preview_config(
    brand_id: uuid.UUID,
    body: ConfigPatch,
    session: Annotated[Session, Depends(get_session, scope="function")],
    user: Annotated[User, Depends(require_analyst)],
) -> dict[str, Any]:
    brand = _get_brand(session, user, brand_id)
    cfg, _ = _candidate_config(session, brand, body)
    return rescore.preview(session, brand.id, cfg.scoring)


@router.patch("/{brand_id}/config")
def patch_config(
    brand_id: uuid.UUID,
    body: ConfigPatch,
    session: Annotated[Session, Depends(get_session, scope="function")],
    user: Annotated[User, Depends(require_analyst)],
    apply_rescore: bool = False,
) -> dict[str, Any]:
    brand = _get_brand(session, user, brand_id)
    cfg, stored = _candidate_config(session, brand, body)
    row = session.scalars(sa.select(Config).where(Config.brand_id == brand.id)).first()
    old = None
    if row is None:
        row = Config(brand_id=brand.id)
        session.add(row)
    else:
        old = {"preset": row.preset, "scoring_version": (row.scoring or {}).get("version")}
    row.preset, row.detection, row.scoring, row.economic_limits = (
        stored["preset"], stored["detection"], stored["scoring"], stored["economic_limits"],
    )  # fmt: skip
    rescore.ensure_version_row(session, cfg.scoring)
    rescored = rescore.apply(session, brand.id, cfg.scoring, actor=user) if apply_rescore else 0
    audit(
        session, workspace_id=user.workspace_id, actor_type="analyst", actor_id=user.id,
        action="brand.config_updated", object_type="brand", object_id=brand.id, old=old,
        new={"preset": row.preset, "scoring_version": cfg.scoring.version, "rescored": rescored,
             "changed": [k for k in ("preset", "detection", "scoring", "economic_limits") if getattr(body, k)]},
    )  # fmt: skip
    return {
        "config": cfg.model_dump(mode="json"),
        "scoring_version": cfg.scoring.version,
        "rescored": rescored,
    }


@router.post("/{brand_id}/rescore")
def rescore_brand(
    brand_id: uuid.UUID,
    session: Annotated[Session, Depends(get_session, scope="function")],
    user: Annotated[User, Depends(require_analyst)],
) -> dict[str, Any]:
    brand = _get_brand(session, user, brand_id)
    cfg = tenancy.effective_brand_config(session, brand.id)
    n = rescore.apply(session, brand.id, cfg.scoring, actor=user)
    return {"rescored": n, "scoring_version": cfg.scoring.version}


@router.post("/{brand_id}/whitelist", status_code=status.HTTP_201_CREATED)
def add_whitelist(
    brand_id: uuid.UUID,
    body: WhitelistAdd,
    session: Annotated[Session, Depends(get_session, scope="function")],
    user: Annotated[User, Depends(require_analyst)],
) -> dict[str, Any]:
    brand = _get_brand(session, user, brand_id)
    norm = normalize(DiscoveryHit(DiscoverySource.MANUAL, body.domain, Surface.NAME))
    if norm is None:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_CONTENT, f"invalid domain: {body.domain!r}"
        )
    if session.scalars(
        sa.select(BrandDomain).where(
            BrandDomain.brand_id == brand.id, BrandDomain.domain == norm.hostname
        )
    ).first():
        raise HTTPException(status.HTTP_409_CONFLICT, "domain already listed for this brand")
    session.add(
        BrandDomain(brand_id=brand.id, domain=norm.hostname, is_official=False, kind=body.kind)
    )
    audit(session, workspace_id=user.workspace_id, actor_type="analyst", actor_id=user.id, action="brand.whitelist_added",
          object_type="brand", object_id=brand.id, new={"domain": norm.hostname, "kind": body.kind})  # fmt: skip
    session.flush()
    from brandwatch.detection.protect import dismiss_protected

    dismiss_protected(session, brand.id)
    return {"domain": norm.hostname, "kind": body.kind}


@router.delete("/{brand_id}/whitelist/{domain}", status_code=status.HTTP_204_NO_CONTENT)
def remove_whitelist(
    brand_id: uuid.UUID,
    domain: str,
    session: Annotated[Session, Depends(get_session, scope="function")],
    user: Annotated[User, Depends(require_analyst)],
) -> None:
    brand = _get_brand(session, user, brand_id)
    row = session.scalars(
        sa.select(BrandDomain).where(
            BrandDomain.brand_id == brand.id,
            BrandDomain.domain == domain.lower(),
            BrandDomain.is_official.is_(False),
        )
    ).first()
    if row is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "not on the whitelist")
    session.delete(row)
    audit(session, workspace_id=user.workspace_id, actor_type="analyst", actor_id=user.id, action="brand.whitelist_removed",
          object_type="brand", object_id=brand.id, old={"domain": row.domain, "kind": row.kind})  # fmt: skip


# ------------------------------------------------------------------------------------------
# Commerce profile: is this brand resold by other shops, in which countries, which ad keywords,
# what do the products cost officially, which retailers are authorised. The AI suggests; the
# analyst saves. Authorised retailers become whitelist rows of kind "reseller".
# ------------------------------------------------------------------------------------------
class ProfileProduct(BaseModel):
    name: str = Field(min_length=2, max_length=80)
    price: float = Field(gt=0, lt=100_000)
    currency: str = Field(pattern=r"^[A-Z]{3}$")
    country: str = Field(pattern=r"^[A-Z]{2}$")
    source: Literal["ai", "analyst"] = "analyst"


class BrandProfileBody(BaseModel):
    kind: Literal["retail", "service"]
    countries: list[str] = Field(default_factory=list, max_length=30)
    ad_keywords: list[str] = Field(default_factory=list, max_length=12)
    products: list[ProfileProduct] = Field(default_factory=list, max_length=60)
    retailers: list[str] = Field(
        default_factory=list, max_length=30
    )  # domains → reseller whitelist
    official_social: list[str] | None = Field(default=None, max_length=30)  # the brand's own accounts
    # how far the ad hunt goes (detection/ad_settings.py); None keeps what is saved
    ads_per_search: int | None = Field(default=None, ge=10, le=300)
    ad_searches_max: int | None = Field(default=None, ge=1, le=20)
    shops_checked_max: int | None = Field(default=None, ge=0, le=60)


class ProfileSuggestBody(BaseModel):
    countries: list[str] = Field(default_factory=list, max_length=30)
    current_keywords: list[str] = Field(default_factory=list, max_length=40)  # to say which are too generic


@router.post("/{brand_id}/profile/suggest")
async def suggest_profile(
    brand_id: uuid.UUID, body: ProfileSuggestBody, request: Request,
    session: Annotated[Session, Depends(get_session, scope="function")], user: Annotated[User, Depends(require_analyst)],
) -> dict[str, Any]:  # fmt: skip
    """The AI's suggestion for the commerce profile. Nothing is saved."""
    from brandwatch.detection import ai as ai_mod

    brand = _get_brand(session, user, brand_id)
    countries = (
        [c for c in (ai_mod.clean_country(x) for x in body.countries) if c]
        or profile_view(brand)["countries"]
        or ["US"]
    )
    settings = request.app.state.settings
    providers = ProviderRegistry(
        settings, key_overrides=keystore.load_keys(session, user.workspace_id, settings)
    )
    domains = official_domains(session, brand.id)
    out = await ai_mod.commerce_profile(
        providers,
        brand_name=brand.search_name,
        domain=domains[0] if domains else None,
        countries=countries,
    )
    if out is None:
        issue = next(iter(providers.drain_issues()), None)
        return {"available": False, "countries": countries,
                "reason": (issue.get("message") if isinstance(issue, dict) else None)
                or "no AI model is configured (Settings → API keys → OpenAI)"}  # fmt: skip
    models = out.get("model_lines") or []
    generic = [k for k in body.current_keywords if k.strip() and not ai_mod.brand_specific(k, brand.search_name, models)]
    return {"available": True, "countries": countries, **out, "generic_current": generic}


@router.put("/{brand_id}/profile")
def save_profile(
    brand_id: uuid.UUID, body: BrandProfileBody,
    session: Annotated[Session, Depends(get_session, scope="function")], user: Annotated[User, Depends(require_analyst)],
) -> dict[str, Any]:  # fmt: skip
    from brandwatch.db.types import utcnow
    from brandwatch.detection import ai as ai_mod
    from brandwatch.detection.protect import dismiss_protected

    brand = _get_brand(session, user, brand_id)
    old = {"kind": brand.kind, **profile_view(brand)}
    countries: list[str] = []
    for c in body.countries:
        cc = ai_mod.clean_country(c)
        if cc is None:
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, f"not a country code: {c!r}")
        if cc not in countries:
            countries.append(cc)
    keywords: list[str] = []
    for k in body.ad_keywords:
        t = ai_mod.clean_term(k)
        if t and t not in keywords:
            keywords.append(t)
    profile = dict(brand.profile or {})
    profile.update({
        "countries": countries, "ad_keywords": keywords,
        "products": [p.model_dump() for p in body.products], "updated_at": utcnow().isoformat(),
    })  # fmt: skip
    for k in ("ads_per_search", "ad_searches_max", "shops_checked_max"):
        if getattr(body, k) is not None:
            profile[k] = getattr(body, k)
    if body.official_social is not None:  # "facebook:<handle>" / "instagram:<user>" from URLs or handles
        from brandwatch.detection.social import official_handles

        profile["official_social"] = sorted(official_handles({"official_social": body.official_social}))
    brand.kind, brand.profile = body.kind, profile
    official = set(official_domains(session, brand.id))
    listed = set(
        session.scalars(sa.select(BrandDomain.domain).where(BrandDomain.brand_id == brand.id)).all()
    )
    added: list[str] = []
    for raw in body.retailers:
        dom = ai_mod.clean_domain(raw)  # "https://www.shop.com/x" → "shop.com"
        norm = normalize(DiscoveryHit(DiscoverySource.MANUAL, dom, Surface.NAME)) if dom else None
        if norm is None or norm.hostname in official or norm.hostname in listed:
            continue
        session.add(
            BrandDomain(brand_id=brand.id, domain=norm.hostname, is_official=False, kind="reseller")
        )
        listed.add(norm.hostname)
        added.append(norm.hostname)
    audit(session, workspace_id=user.workspace_id, actor_type="analyst", actor_id=user.id, action="brand.profile_updated",
          object_type="brand", object_id=brand.id, old=old,
          new={"kind": body.kind, "countries": countries, "ad_keywords": keywords, "products": len(body.products), "retailers_added": added})  # fmt: skip
    session.flush()
    if added:
        dismiss_protected(session, brand.id)
    return {**brand_summary(session, brand), "retailers_added": added}


# ------------------------------------------------------------------------------------------
# Google search queries: the AI proposes (from the fingerprint, or on demand), an analyst approves.
# Google search runs only with an approved list — every scan and the scheduled one use it.
# ------------------------------------------------------------------------------------------
class SearchQueriesBody(BaseModel):
    queries: list[str] = Field(default_factory=list, max_length=60)


@router.post("/{brand_id}/search-queries/suggest")
async def suggest_search_queries(
    brand_id: uuid.UUID, request: Request,
    session: Annotated[Session, Depends(get_session, scope="function")], user: Annotated[User, Depends(require_analyst)],
) -> dict[str, Any]:  # fmt: skip
    """A fresh AI proposal for the brand's Google queries. Nothing is saved."""
    from brandwatch.detection import ai as ai_mod

    brand = _get_brand(session, user, brand_id)
    base = load_baseline(session, brand)
    fp = session.scalars(
        sa.select(BrandFingerprint)
        .where(BrandFingerprint.brand_id == brand.id)
        .order_by(BrandFingerprint.version.desc())
    ).first()
    title = ((fp.features or {}).get("title") if fp is not None else None) or "-"
    domains = official_domains(session, brand.id)
    text = (
        f"Official site: {domains[0] if domains else '-'}\nTitle: {title}\n"
        f"Words on the site: {', '.join(base.keywords) if base else '-'}"
    )
    settings = request.app.state.settings
    providers = ProviderRegistry(
        settings, key_overrides=keystore.load_keys(session, user.workspace_id, settings)
    )
    out = await ai_mod.brand_profile(providers, brand_name=brand.search_name, homepage_text=text, kind=brand.kind)
    if out is None:
        issue = next(iter(providers.drain_issues()), None)
        return {"available": False,
                "reason": (issue.get("message") if isinstance(issue, dict) else None)
                or "no AI model is configured (Settings → API keys → OpenAI)"}  # fmt: skip
    return {"available": True, "queries": out["search_queries"], "vertical": out.get("vertical"),
            "model": out.get("model")}  # fmt: skip


@router.put("/{brand_id}/search-queries")
def approve_search_queries(
    brand_id: uuid.UUID, body: SearchQueriesBody,
    session: Annotated[Session, Depends(get_session, scope="function")], user: Annotated[User, Depends(require_analyst)],
) -> dict[str, Any]:  # fmt: skip
    """Approve the brand's Google queries (edited or as proposed). From now on every scan and the
    scheduled scan search Google with exactly this list."""
    brand = _get_brand(session, user, brand_id)
    queries = search_queries_mod.clean_queries(body.queries)
    if not queries:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_CONTENT,
            "approve at least one query — to stop Google search, switch the “search” stream off in the detection track",
        )
    base = load_baseline(session, brand)
    old = search_queries_mod.approve(
        brand, queries, by=user.email, baseline_version=base.version if base else 0
    )
    audit(session, workspace_id=user.workspace_id, actor_type="analyst", actor_id=user.id,
          action="brand.search_queries_approved", object_type="brand", object_id=brand.id,
          old={"approved": old.get("approved")}, new={"approved": queries})  # fmt: skip
    session.flush()
    cfg = tenancy.effective_brand_config(session, brand.id)
    return {"search_queries": search_queries_mod.query_state(brand, cfg.detection, base).as_dict()}


# ------------------------------------------------------------------------------------------
# AI answers: the approved prompts and the brand's official contacts (detection/ai_answers.py).
# ------------------------------------------------------------------------------------------
def ai_answers_view(session: Session, brand: Brand, cfg: Any) -> dict[str, Any]:
    """What the brand page shows: the switch, the prompts (approved or proposed), the official contacts and a cost line."""
    from brandwatch.detection import ai_answers as ai_answers_mod
    from brandwatch.detection import ai_prompts
    from brandwatch.detection import contacts as contacts_mod

    det = cfg.detection
    st = ai_prompts.prompt_state(brand, det)
    prof = brand.profile or {}
    saved = dict(prof.get("contacts") or {})
    engines = [e for e in det.ai_engines if e in ai_answers_mod.ENGINE_LABEL]
    asks = min(len(st.prompts), det.ai_prompts_max) * max(1, len(engines))
    return {
        "on": det.ai_answers, "engines": engines, "engine_labels": ai_answers_mod.ENGINE_LABEL,
        "prompts": st.as_dict(), "topics": ai_prompts.TOPICS,
        "contacts": {k: saved.get(k) or [] for k in contacts_mod.KINDS}, "contacts_at": saved.get("at"),
        "contacts_pages": saved.get("crawled") or 0, "contacts_read": bool(saved.get("at")),
        "known_contacts": list(prof.get("known_contacts") or []), "kind_labels": contacts_mod.KIND_LABEL,
        "requests": asks, "cost": round(asks * 0.004 + min(asks, ai_answers_mod.MAX_SUSPECTS * 3) * 0.004, 2),
        "max_prompts": det.ai_prompts_max, "pages_max": det.contacts_pages_max,
    }  # fmt: skip


class AiPromptsBody(BaseModel):
    prompts: list[dict[str, str] | str] = Field(default_factory=list, max_length=40)


@router.post("/{brand_id}/ai-prompts/suggest")
async def suggest_ai_prompts(
    brand_id: uuid.UUID, request: Request,
    session: Annotated[Session, Depends(get_session, scope="function")], user: Annotated[User, Depends(require_analyst)],
) -> dict[str, Any]:  # fmt: skip
    """The AI writes the questions a real user would ask about the brand, from its approved Google queries. Nothing is saved."""
    from brandwatch.detection import ai_prompts

    brand = _get_brand(session, user, brand_id)
    cfg = tenancy.effective_brand_config(session, brand.id)
    base = load_baseline(session, brand)
    qs = search_queries_mod.query_state(brand, cfg.detection, base)
    settings = request.app.state.settings
    providers = ProviderRegistry(settings, key_overrides=keystore.load_keys(session, user.workspace_id, settings))
    rows = await ai_prompts.suggest(providers, brand_name=brand.search_name, detection=cfg.detection, queries=qs.queries,
                                    keywords=list(base.keywords) if base else [])  # fmt: skip
    return {"prompts": rows}


@router.put("/{brand_id}/ai-prompts")
def approve_ai_prompts(
    brand_id: uuid.UUID, body: AiPromptsBody,
    session: Annotated[Session, Depends(get_session, scope="function")], user: Annotated[User, Depends(require_analyst)],
) -> dict[str, Any]:  # fmt: skip
    """Approve the questions asked to AI assistants (edited or as proposed); every run after that asks exactly these."""
    from brandwatch.detection import ai_prompts

    brand = _get_brand(session, user, brand_id)
    prompts = ai_prompts.clean(body.prompts)
    if not prompts:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT,
                            "approve at least one question — to stop asking AI assistants, switch AI answers off")  # fmt: skip
    old = ai_prompts.approve(brand, prompts, by=user.email)
    audit(session, workspace_id=user.workspace_id, actor_type="analyst", actor_id=user.id, action="brand.ai_prompts_approved",
          object_type="brand", object_id=brand.id, old={"approved": old.get("approved")}, new={"approved": prompts})  # fmt: skip
    session.flush()
    cfg = tenancy.effective_brand_config(session, brand.id)
    return {"ai_answers": ai_answers_view(session, brand, cfg)}


class KnownContactBody(BaseModel):
    value: str = Field(min_length=3, max_length=200)
    action: Literal["add", "remove"] = "add"
    note: str | None = Field(default=None, max_length=200)


@router.post("/{brand_id}/known-contacts")
def known_contact(
    brand_id: uuid.UUID, body: KnownContactBody,
    session: Annotated[Session, Depends(get_session, scope="function")], user: Annotated[User, Depends(require_analyst)],
) -> dict[str, Any]:  # fmt: skip
    """A contact the brand uses but its website does not show (an SMS sender, an app-only line): never reported."""
    from brandwatch.detection import contacts as contacts_mod

    brand = _get_brand(session, user, brand_id)
    value = " ".join(body.value.split())
    cfg = tenancy.effective_brand_config(session, brand.id)
    cc = contacts_mod.dial_code([*((brand.profile or {}).get("countries") or []), *[g for g in cfg.detection.search_geo.split(",") if g]])
    if body.action == "add" and not contacts_mod.known_set(None, [value], cc=cc):
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, f"“{value}” is not a phone number, short code or e-mail address")
    prof = dict(brand.profile or {})
    rows = [r for r in prof.get("known_contacts") or [] if (r.get("value") if isinstance(r, dict) else r) != value]
    if body.action == "add":
        rows.append({"value": value, "note": body.note or "", "by": user.email, "at": utcnow().isoformat()})
    prof["known_contacts"] = rows
    brand.profile = prof
    audit(session, workspace_id=user.workspace_id, actor_type="analyst", actor_id=user.id, action=f"brand.known_contact_{body.action}",
          object_type="brand", object_id=brand.id, new={"value": value})  # fmt: skip
    session.flush()
    return {"known_contacts": rows}


# ------------------------------------------------------------------------------------------
# Automatic scans: on / off, how often, at what time, which tasks (detection/schedule.py).
# ------------------------------------------------------------------------------------------
def schedule_view(session: Session, brand: Brand, cfg: Any, queries: dict[str, Any]) -> dict[str, Any]:
    out = schedule_mod.view(session, brand, cfg.detection)
    sc = schedule_mod.load(brand, cfg.detection)
    p = profile_view(brand)
    retail = (brand.kind or "service") == "retail"
    geos = [g for g in cfg.detection.search_geo.split(",") if g.strip()] or ["us"]
    from brandwatch.detection import ad_settings

    reach = ad_settings.cost(brand.profile, keywords=len(p["ad_keywords"] or [brand.search_name]), countries=len(p["countries"] or geos))
    ad_queries = reach["requests"]
    from brandwatch.detection import ai_prompts

    ai_st = ai_prompts.prompt_state(brand, cfg.detection)
    out["cost"] = schedule_mod.cost_estimate(
        sc, approved_queries=len(queries["queries"]) if queries.get("approved") else 0,
        search_max=cfg.detection.search_queries_max, geos=len(geos), retail=retail, ad_queries=ad_queries,
        shops_checked=reach["shops_checked_max"], social_accounts=cfg.detection.social_accounts_max,
        ai_requests=min(len(ai_st.prompts), cfg.detection.ai_prompts_max) * len(cfg.detection.ai_engines) if ai_st.approved else 0,
    )  # fmt: skip
    out["retail"] = retail
    out["search_approved"] = bool(queries.get("approved"))
    out["tasks_info"] = schedule_mod.TASKS
    out["frequencies"] = schedule_mod.FREQUENCIES
    return out


class ScheduleBody(BaseModel):
    enabled: bool = False
    every_hours: int = Field(default=24, ge=1, le=720)
    hour: int | None = Field(default=3, ge=0, le=23)
    tz_offset: int = Field(default=0, ge=-840, le=840)
    tasks: list[str] = Field(default_factory=list, max_length=20)


@router.put("/{brand_id}/schedule")
def save_schedule(
    brand_id: uuid.UUID, body: ScheduleBody,
    session: Annotated[Session, Depends(get_session, scope="function")], user: Annotated[User, Depends(require_analyst)],
) -> dict[str, Any]:  # fmt: skip
    """Switch automatic scans on or off and choose how often, when, and what they do."""
    from brandwatch.db.types import utcnow

    brand = _get_brand(session, user, brand_id)
    old = dict(brand.schedule or {})
    new = schedule_mod.clean(body.model_dump())
    if body.enabled and not new["tasks"]:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, "choose at least one task for the automatic scans")
    keep_clock = old.get("updated_at") if old.get("enabled") and new["enabled"] else None  # re-saving keeps the rhythm
    brand.schedule = {**new, "updated_at": keep_clock or utcnow().isoformat(), "updated_by": user.email}
    audit(session, workspace_id=user.workspace_id, actor_type="analyst", actor_id=user.id, action="brand.schedule_updated",
          object_type="brand", object_id=brand.id, old=old or None, new=new)  # fmt: skip
    session.flush()
    cfg = tenancy.effective_brand_config(session, brand.id)
    base = load_baseline(session, brand)
    return {"schedule": schedule_view(session, brand, cfg, search_queries_mod.query_state(brand, cfg.detection, base).as_dict())}


class BaselineActionBody(BaseModel):
    """How to reach the official site: through which IP, and which page of the brand to look at."""

    # "snapshot": skip the live site and fingerprint from a public urlscan.io snapshot of it
    via: Literal["datacenter", "residential", "snapshot"] = "datacenter"
    url: str | None = Field(default=None, max_length=300)  # another official page; "" goes back to the homepage
    # with via="snapshot": the urlscan.io scan to use, as a result link or a bare id (default: the newest public one)
    urlscan: str | None = Field(default=None, max_length=300)


async def _baseline_providers(
    request: Request, session: Session, user: User, brand: Brand, via: str
) -> ProviderRegistry:
    """A registry for fetching the official site. ``via="residential"`` only when the workspace has a residential
    proxy switched on and a residential budget left - BrandWatch never reaches for it silently."""
    registry, reason = await _residential_registry(request, session, user, brand)
    if via == "residential" and reason:
        raise HTTPException(status.HTTP_409_CONFLICT, reason)
    return registry


async def _residential_registry(
    request: Request, session: Session, user: User, brand: Brand
) -> tuple[ProviderRegistry, str | None]:
    """A registry that can also fetch through the residential proxy, and why it cannot (None: it can).
    Without a budget and a proxy the registry is a plain one - the paid proxy is never reached for silently."""
    from brandwatch import proxy as proxy_mod
    from brandwatch.detection import cloaking

    settings = request.app.state.settings
    keys = keystore.load_keys(session, user.workspace_id, settings)
    cfg = tenancy.effective_brand_config(session, brand.id)
    limit = cfg.economic_limits.max_residential_gb
    reason = cloaking.residential_gate(session, user.workspace_id, settings, limit, True)  # the budget first
    if reason:
        return ProviderRegistry(settings, key_overrides=keys), reason
    if settings.demo_mode:  # a recorded residential view, as in the scan's own residential probe
        return ProviderRegistry(settings, key_overrides=keys), None
    proxy_cfg = await tenancy.resolve_proxy(session, user.workspace_id, settings)
    if not proxy_cfg.enabled:
        return ProviderRegistry(settings, key_overrides=keys), "no residential proxy is switched on - Settings → Residential proxy"
    country = cfg.detection.residential_country or proxy_mod.country_for(cfg.detection.search_geo, cfg.detection.search_lang)
    return ProviderRegistry(settings, key_overrides=keys, residential_proxy=proxy_cfg.url(country)), None


def _record_residential(session: Session, user: User, settings: Any) -> None:
    from decimal import Decimal

    from brandwatch.detection import cloaking

    session.add(ApiUsage(
        workspace_id=user.workspace_id, provider="residential", calls=1,
        cost_usd=Decimal("0") if settings.demo_mode
        else Decimal(str(round(cloaking.RESIDENTIAL_GB_PER_FETCH * cloaking.RESIDENTIAL_USD_PER_GB, 4))),
    ))  # fmt: skip
    session.flush()


def _official_page(session: Session, user: User, brand: Brand, raw: str) -> str:
    """Validate "another official page of this brand". Its domain becomes an official domain of the brand
    (and so of its family's whitelist) - the analyst is vouching for it by naming it."""
    from brandwatch.detection.protect import dismiss_protected

    url = raw.strip()
    if "://" not in url:
        url = "https://" + url
    dom = ai_mod.clean_domain(url)
    norm = normalize(DiscoveryHit(DiscoverySource.MANUAL, dom, Surface.NAME)) if dom else None
    if norm is None or not url.lower().startswith(("http://", "https://")):
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, f"not a web address: {raw!r}")
    if norm.hostname not in set(official_domains(session, brand.id)):
        session.add(BrandDomain(brand_id=brand.id, domain=norm.hostname, is_official=True, kind="official"))
        audit(session, workspace_id=user.workspace_id, actor_type="analyst", actor_id=user.id,
              action="brand.domain_added", object_type="brand", object_id=brand.id,
              new={"domain": norm.hostname, "reason": "another official page to fingerprint"})  # fmt: skip
        session.flush()
        dismiss_protected(session, brand.id)
    return url


def _urlscan_scan_id(raw: str | None) -> str | None:
    """A urlscan.io result link (https://urlscan.io/result/<id>/) or a bare scan id → the id."""
    import re

    if not raw or not raw.strip():
        return None
    text = raw.strip()
    m = re.search(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}|mock-snap-[a-z0-9.-]+", text, re.I)
    if not m or not (text.lower() == m.group(0).lower() or "urlscan.io" in text.lower()):
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, f"not a urlscan.io scan link or id: {raw!r}")
    return m.group(0).lower()


@router.post("/{brand_id}/baseline/check")
async def check_baseline(
    brand_id: uuid.UUID, request: Request,
    session: Annotated[Session, Depends(get_session, scope="function")], user: Annotated[User, Depends(current_user)],
    body: BaselineActionBody | None = None,
) -> dict[str, Any]:  # fmt: skip
    """Does the official site let BrandWatch in? One fetch, nothing is saved: the answer ({ok, kind, status,
    reason, vendor}) and what can be done about it. Used before the first scan and after each fix."""
    brand = _get_brand(session, user, brand_id)
    body = body or BaselineActionBody()
    domains = official_domains(session, brand.id)
    home = (brand.profile or {}).get("home_domain")
    home = home if home in domains else (domains or [""])[0]
    url = body.url or (brand.profile or {}).get("baseline_url") or f"https://{home}/"
    if "://" not in url:
        url = "https://" + url
    if ai_mod.clean_domain(url) is None:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, f"not a web address: {url!r}")
    if body.via == "snapshot":
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, "a snapshot is not a check of the live site")
    providers = await _baseline_providers(request, session, user, brand, body.via)
    res = await providers.browser().fetch(url, profile=body.via)
    if body.via == "residential":
        _record_residential(session, user, request.app.state.settings)
    health = baseline_health.from_fetch(res)
    ladder: list[dict[str, Any]] = []
    snapshot: dict[str, Any] | None = None
    if not health["ok"]:
        # what a scan / rebuild would do next, laid out: so "blocked" is never the end of the story
        from urllib.parse import urlsplit

        from brandwatch.detection.snapshot import urlscan_snapshot as _urlscan_snapshot

        host = urlsplit(url).hostname or home
        ladder.append({"step": "the live site " + ("through the residential proxy" if body.via == "residential" else "from a data-centre IP"),
                       "ok": False, "text": health["reason"]})  # fmt: skip
        if body.via == "datacenter":
            _reg, off = await _residential_registry(request, session, user, brand)
            ladder.append({"step": "residential proxy", "ok": None,
                           "text": (f"not available: {off}" if off else "available — a scan or a rebuild tries it automatically after a block")})  # fmt: skip
        snap, why = await _urlscan_snapshot(providers, [host, home], peek=True)
        if snap:
            snapshot = {k: snap.get(k) for k in ("scan_id", "url", "time", "title", "screenshot_url", "result_url", "has_key")}
        ladder.append({"step": "urlscan.io snapshot", "ok": bool(snap), "snapshot": snapshot,
                       "text": (f"a public scan of {snap.get('url')} from {str(snap.get('time') or '')[:10]} exists"
                                + ("" if snap.get("has_key") else " — screenshot, colours and title (page text and favicon need a urlscan API key)")) if snap
                       else f"none found: {why}"})  # fmt: skip
    return {**health, "url": url, "via": body.via, "ladder": ladder, "snapshot": snapshot,
            "fixes": [{"id": i, "title": t, "detail": d} for i, t, d in baseline_health.FIXES] if not health["ok"] else []}  # fmt: skip


@router.post("/{brand_id}/baseline")
async def rebuild_baseline(
    brand_id: uuid.UUID,
    request: Request,
    session: Annotated[Session, Depends(get_session, scope="function")],
    user: Annotated[User, Depends(require_analyst)],
    body: BaselineActionBody | None = None,
) -> dict[str, Any]:
    brand = _get_brand(session, user, brand_id)
    body = body or BaselineActionBody()
    settings = request.app.state.settings
    if body.url is not None:  # remembered: scheduled scans rebuild from the same page
        profile = dict(brand.profile or {})
        if body.url.strip():
            # the homepage stays "the homepage" once a second official domain is added (the list is alphabetical)
            profile.setdefault("home_domain", (official_domains(session, brand.id) or [None])[0])
            profile["baseline_url"] = _official_page(session, user, brand, body.url)
        else:
            profile.pop("baseline_url", None)
        brand.profile = profile
        session.flush()
    if body.via == "datacenter":  # the plain rebuild escalates like a scan does, when the budget and the proxy allow it
        providers, resid_off = await _residential_registry(request, session, user, brand)
        report = await build_baseline(session, brand, providers, request.app.state.store, via="datacenter",
                                      escalate=resid_off is None, residential_off=resid_off)  # fmt: skip
    else:
        providers = ProviderRegistry(settings, key_overrides=keystore.load_keys(session, user.workspace_id, settings)) \
            if body.via == "snapshot" else await _baseline_providers(request, session, user, brand, body.via)
        report = await build_baseline(session, brand, providers, request.app.state.store, via=body.via,
                                      urlscan_id=_urlscan_scan_id(body.urlscan) if body.via == "snapshot" else None)  # fmt: skip
    audit(
        session, workspace_id=user.workspace_id, actor_type="analyst", actor_id=user.id,
        action="brand.baseline_built", object_type="brand", object_id=brand.id,
        new={"version": report.version, "unavailable": report.unavailable, "via": body.via,
             "fetch": {k: report.fetch.get(k) for k in ("ok", "kind", "status", "vendor", "url")}},
    )  # fmt: skip
    return {
        "fingerprint_id": str(report.fingerprint_id),
        "version": report.version,
        "fetched_url": report.fetched_url,
        "favicon_mmh3": report.favicon_mmh3,
        "screenshot_phash": report.screenshot_phash,
        "keywords": report.keywords,
        "unavailable": report.unavailable,
        "fetch": report.fetch,
    }


def _baseline_artifact(request: Request, session: Session, brand: Brand, which: str) -> Response:
    fp = session.scalars(
        sa.select(BrandFingerprint)
        .where(BrandFingerprint.brand_id == brand.id)
        .order_by(BrandFingerprint.version.desc())
    ).first()
    location = None
    if fp is not None:
        if which == "favicon":
            location = fp.logo_path
        else:
            location = ((fp.screenshots or {}).get("home") or {}).get("artifact")
    store = request.app.state.store
    if not location or not store.exists(location):
        raise HTTPException(status.HTTP_404_NOT_FOUND, f"no baseline {which}")
    return Response(content=store.get(location), media_type="image/png")


@router.get("/{brand_id}/baseline/screenshot")
def baseline_screenshot(
    brand_id: uuid.UUID, request: Request,
    session: Annotated[Session, Depends(get_session, scope="function")], user: Annotated[User, Depends(current_user)],
) -> Response:  # fmt: skip
    return _baseline_artifact(request, session, _get_brand(session, user, brand_id), "screenshot")


@router.get("/{brand_id}/baseline/favicon")
def baseline_favicon(
    brand_id: uuid.UUID, request: Request,
    session: Annotated[Session, Depends(get_session, scope="function")], user: Annotated[User, Depends(current_user)],
) -> Response:  # fmt: skip
    return _baseline_artifact(request, session, _get_brand(session, user, brand_id), "favicon")


@router.post("/{brand_id}/scan", status_code=status.HTTP_202_ACCEPTED)
def start_scan(
    brand_id: uuid.UUID,
    body: ScanRequest,
    request: Request,
    session: Annotated[Session, Depends(get_session, scope="function")],
    user: Annotated[User, Depends(require_analyst)],
) -> dict[str, Any]:
    brand = _get_brand(session, user, brand_id)
    if not official_domains(session, brand.id):
        raise HTTPException(status.HTTP_409_CONFLICT, "brand has no official domain")
    tasks = list(body.tasks) if body.tasks else None
    if body.only:
        cfg = tenancy.effective_brand_config(session, brand.id)
        tasks = tasks_for_only(cfg, body.only)
        if body.only == "search":
            qs = search_queries_mod.query_state(brand, cfg.detection, load_baseline(session, brand))
            if not qs.approved:
                raise HTTPException(status.HTTP_409_CONFLICT, "Google search runs only with approved queries — approve them first (brand page → Google queries)")
        from brandwatch import keys as keystore_mod

        searchapi_ok = keystore_mod.provider_ready(session, user.workspace_id, request.app.state.settings, "searchapi")
        if body.only in ("social", "ads") and not searchapi_ok:
            raise HTTPException(status.HTTP_409_CONFLICT, ("Social media" if body.only == "social" else "Facebook / Instagram ads") + " need a SearchApi key — add it in Settings → API keys")
        if body.only == "ai":
            from brandwatch.detection import ai_prompts

            if not ai_prompts.prompt_state(brand, cfg.detection).approved:
                raise HTTPException(status.HTTP_409_CONFLICT, "AI answers run only with approved questions — approve them first (brand page → AI answers)")
            if not searchapi_ok:
                raise HTTPException(status.HTTP_409_CONFLICT, "AI answers need a SearchApi key — add it in Settings → API keys")
    session.commit()  # release our write lock before the job thread starts writing
    payload: dict[str, Any] = {
        "max_candidates": body.max_candidates,
        "max_names": body.max_names,
        "rebuild_baseline": body.rebuild_baseline,
        "requested_by": str(user.id),
    }
    if tasks is not None:
        payload["tasks"] = tasks
        payload["only"] = ONLY_PARTS.get(body.only or "", "") or ", ".join(tasks)
    job_id = request.app.state.queue.enqueue(
        "brand_scan",
        payload,
        workspace_id=user.workspace_id,
        brand_id=brand.id,
    )
    _audit_scan_started(session, user, job_id, {"kind": "brand_scan", "brand": brand.name})
    return {"job_id": str(job_id), "kind": "brand_scan"}


@router.post("/{brand_id}/scan-urls", status_code=status.HTTP_202_ACCEPTED)
def start_url_scan(
    brand_id: uuid.UUID,
    body: UrlScanRequest,
    request: Request,
    session: Annotated[Session, Depends(get_session, scope="function")],
    user: Annotated[User, Depends(require_analyst)],
) -> dict[str, Any]:
    brand = _get_brand(session, user, brand_id)
    session.commit()  # release our write lock before the job thread starts writing
    job_id = request.app.state.queue.enqueue(
        "url_scan",
        {"urls": body.urls, "requested_by": str(user.id)},
        workspace_id=user.workspace_id,
        brand_id=brand.id,
    )
    _audit_scan_started(
        session, user, job_id, {"kind": "url_scan", "brand": brand.name, "urls": len(body.urls)}
    )
    return {"job_id": str(job_id), "kind": "url_scan"}


def _audit_scan_started(
    session: Session, user: User, job_id: uuid.UUID, new: dict[str, Any]
) -> None:
    """Audit row for a started scan, pointing at the job (so Activity links to its console). Written
    after enqueue: take the write lock up front, the job thread may already be writing."""
    with immediate_writes():
        session.connection()
    audit(session, workspace_id=user.workspace_id, actor_type="analyst", actor_id=user.id,
          action="scan.started", object_type="scan_job", object_id=job_id, new=new)  # fmt: skip
