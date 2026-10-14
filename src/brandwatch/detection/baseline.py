"""Brand Attack-Surface Baseline (spec §11), Phase 1 subset.

Onboarding fetches the official homepage through the provider layer and records what every
detection is measured against: favicon hashes (mmh3 + pHash), homepage screenshot pHash,
keywords from title/headings, whether the real site has a login form. Stored as a versioned
``brand_fingerprints`` row; ``BrandBaseline`` is the in-memory view the analysis stage uses.
LLM-derived keywords/lures (spec §11) arrive with the LLM provider in Phase 5.
"""

from __future__ import annotations

import base64
import re
import uuid
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlsplit

import sqlalchemy as sa
from sqlalchemy.orm import Session

from brandwatch.db.models import Brand, BrandDomain, BrandFingerprint
from brandwatch.db.types import utcnow
from brandwatch.detection import baseline_health, dom, images
from brandwatch.detection.ai import default_search_queries, fit_queries, shopping_first
from brandwatch.detection.discovery import split_host
from brandwatch.detection.html import (
    app_store_links,
    auth_links,
    extract_features,
    is_bot_challenge,
    title_keywords,
)
from brandwatch.detection.regions import country_sites
from brandwatch.detection.snapshot import urlscan_snapshot as _urlscan_snapshot
from brandwatch.detection.social import social_links
from brandwatch.evidence.store import EvidenceStore
from brandwatch.providers.registry import ProviderRegistry


@dataclass(frozen=True, slots=True)
class BrandBaseline:
    brand_id: uuid.UUID
    brand_key: str  # "shopnova"
    official_domains: tuple[str, ...]
    favicon_mmh3: int | None
    favicon_phash: str | None
    screenshot_phash: str | None
    screenshot_dhash: str | None = None
    palette: tuple[str, ...] = ()
    login_signature: tuple[str, ...] = ()
    whitelist_domains: tuple[str, ...] = ()
    keywords: tuple[str, ...] = ()
    has_login_form: bool = False
    auth_pages: tuple[dict, ...] = ()  # login / sign-up pages linked from the homepage
    login_screenshot_phash: str | None = None  # the official login or sign-up page
    login_screenshot_dhash: str | None = None
    official_apps: tuple[str, ...] = ()  # app-store listings linked from the official site
    search_queries: tuple[str, ...] = ()  # Google queries impersonators target (AI or default)
    version: int = 0
    vertical: str | None = None  # the AI's words for the business ("footwear and apparel")
    official_social: tuple[str, ...] = ()  # "facebook:<handle>" / "instagram:<user>" linked from the site
    # how the fetch of the official site went (baseline_health.assess + url / via / at); None for old baselines
    fetch: dict[str, Any] | None = None

    @property
    def registrable_domains(self) -> tuple[str, ...]:
        return tuple(sorted({split_host(d).registrable for d in self.official_domains}))


MIN_KEY_LEN = 4  # "on" (on.com) is inside every second word; it cannot find look-alikes


def brand_key_for(brand: Brand, session: Session | None = None) -> str:
    """The token lookalikes are measured against: the second-level label of the primary official
    domain ("shopnova" for shopnova.com), falling back to the normalised display name. The display
    name is free text ("ShopNova EU", "Acme Corp") and must not drive detection — except when the
    domain label is too short to search for: on.com's "on" appears in "phone", "london", "online",
    so a brand named "On Cloud" is searched as "oncloud" (the label must be part of the name)."""
    name_key = re.sub(r"[^a-z0-9]", "", _sname(brand).lower())
    if session is not None:
        domains = session.scalars(
            sa.select(BrandDomain.domain)
            .where(BrandDomain.brand_id == brand.id, BrandDomain.is_official.is_(True))
            .order_by(sa.case((BrandDomain.kind == "official", 0), else_=1), BrandDomain.domain)
        ).all()
        for d in domains:
            sld = split_host(d).sld
            if sld:
                key = re.sub(r"[^a-z0-9]", "", sld.lower())
                if len(key) < MIN_KEY_LEN and len(name_key) >= MIN_KEY_LEN and name_key.startswith(key):
                    return name_key
                return key
    return name_key


def _sname(brand: Any) -> str:
    """The brand's own name for searching (a region "ShopNova · Israel" searches for "ShopNova")."""
    return getattr(brand, "search_name", None) or brand.name


def official_domains(session: Session, brand_id: uuid.UUID) -> list[str]:
    """The brand's own domains (permuted by discovery, fetched for the baseline)."""
    return list(
        session.scalars(
            sa.select(BrandDomain.domain)
            .where(BrandDomain.brand_id == brand_id, BrandDomain.is_official.is_(True))
            .order_by(sa.case((BrandDomain.kind == "official", 0), else_=1), BrandDomain.domain)
        ).all()
    )


def whitelist_domains(session: Session, brand_id: uuid.UUID) -> list[str]:
    """Everything the pre-filter must drop: official domains + partners / subsidiaries / CDNs — of the
    brand *and of its whole family* (a global brand's regions: thenorthface.co.il is never a suspect of
    thenorthface.com's campaign, and the other way round)."""
    from brandwatch.detection.regions import family_domains

    return family_domains(session, brand_id)


def _fit_saved_queries(llm: dict, brand: Brand, key: str) -> list[str]:
    """The saved Google queries, cleaned with today's rules: no "wallet" / "bonus" for a brand that
    is not crypto, banking or betting, and shopping queries first for a brand whose products shops
    resell — so a baseline saved before those rules does not need a rebuild."""
    queries = fit_queries(
        list(llm.get("search_queries") or []), vertical=llm.get("vertical"), kind=brand.kind
    ) or default_search_queries(_sname(brand), key, brand.kind)
    if (brand.kind or "service") == "retail":
        queries = shopping_first(queries, _sname(brand), key)
    return queries


def latest_fetch(session: Session, brand_id: uuid.UUID) -> dict[str, Any] | None:
    """How the fetch of the official site went when the newest fingerprint was built (None: no fingerprint,
    or one built before BrandWatch recorded it)."""
    fp = session.scalars(
        sa.select(BrandFingerprint).where(BrandFingerprint.brand_id == brand_id).order_by(BrandFingerprint.version.desc())
    ).first()
    return ((fp.features or {}).get("fetch") or None) if fp else None


def load_baseline(session: Session, brand: Brand) -> BrandBaseline | None:
    fp = session.scalars(
        sa.select(BrandFingerprint)
        .where(BrandFingerprint.brand_id == brand.id)
        .order_by(BrandFingerprint.version.desc())
    ).first()
    if fp is None:
        return None
    shots = fp.screenshots or {}
    home = shots.get("home", {}) if isinstance(shots, dict) else {}
    return BrandBaseline(
        brand_id=brand.id,
        brand_key=brand_key_for(brand, session),
        official_domains=tuple(official_domains(session, brand.id)),
        whitelist_domains=tuple(whitelist_domains(session, brand.id)),
        favicon_mmh3=fp.favicon_mmh3,
        favicon_phash=fp.favicon_phash,
        screenshot_phash=home.get("phash"),
        screenshot_dhash=home.get("dhash"),
        login_screenshot_phash=(shots.get("login") or {}).get("phash")
        if isinstance(shots, dict)
        else None,
        login_screenshot_dhash=(shots.get("login") or {}).get("dhash")
        if isinstance(shots, dict)
        else None,
        auth_pages=tuple((fp.features or {}).get("auth_pages", [])),
        palette=tuple((fp.colors or {}).get("palette", [])) if isinstance(fp.colors, dict) else (),
        login_signature=tuple((fp.features or {}).get("login_signature", [])),
        # listings linked from the official site, plus the ones the analyst named when adding / editing the brand
        official_apps=tuple(dict.fromkeys([*(fp.features or {}).get("official_apps", []), *((brand.profile or {}).get("official_apps") or [])])),
        search_queries=tuple(
            _fit_saved_queries(fp.llm_analysis or {}, brand, brand_key_for(brand, session))
        ),
        vertical=(fp.llm_analysis or {}).get("vertical") or None,
        official_social=tuple((fp.features or {}).get("official_social", [])),
        fetch=(fp.features or {}).get("fetch") or None,
        keywords=tuple((fp.keywords or {}).get("terms", []))
        if isinstance(fp.keywords, dict)
        else (),
        has_login_form=bool((fp.features or {}).get("has_login_form")),
        version=fp.version,
    )


@dataclass(slots=True)
class BaselineReport:
    fingerprint_id: uuid.UUID
    version: int
    fetched_url: str
    favicon_mmh3: int | None
    screenshot_phash: str | None
    keywords: list[str]
    unavailable: list[str] = field(default_factory=list)
    fetch: dict[str, Any] = field(default_factory=dict)


async def build_baseline(
    session: Session,
    brand: Brand,
    providers: ProviderRegistry,
    store: EvidenceStore,
    narrate: Callable[[str, str, list[dict], str | None], None] | None = None,
    *,
    via: str = "datacenter",
    url_override: str | None = None,
    escalate: bool = False,
    residential_off: str | None = None,
    snapshot: bool = True,
    urlscan_id: str | None = None,
) -> BaselineReport:
    """``narrate(title, detail, items, image)`` is called after each sub-step (live console).

    ``via`` is the browser profile for the fetch ("residential" = through the workspace's residential proxy;
    "snapshot" = learn from the urlscan.io snapshot, of the scan ``urlscan_id`` when the analyst pasted a
    urlscan.io link, else the newest public one — the site is still asked ONCE, from a data-centre IP, for its real
    status and its favicon file, and is never learned from); ``url_override`` fingerprints another
    official page (default: the brand's ``profile.baseline_url``, else the primary domain's homepage).

    When the site does not let BrandWatch in (403, a bot check …) the block page is *never* learned from, and
    the answer is escalated in the open, every step narrated: the data-centre IP is refused → (``escalate``: the
    caller says the residential proxy is switched on and has budget; otherwise ``residential_off`` says why not)
    the same page through the residential proxy
    → (``snapshot``) a public urlscan.io snapshot of the homepage: its screenshot and colours, its title, and
    with a urlscan key its DOM and favicon. Whatever worked is recorded in ``features.fetch``."""

    def say(
        title: str, detail: str = "", items: list[dict] | None = None, image: str | None = None
    ) -> None:
        if narrate is not None:
            narrate(title, detail, items or [], image)

    domains = official_domains(session, brand.id)
    if not domains:
        raise ValueError("brand has no official domain; add one before onboarding")
    home = (brand.profile or {}).get("home_domain")  # remembered when another official page was named
    primary = home if home in domains else domains[0]
    url = url_override or (brand.profile or {}).get("baseline_url") or f"https://{primary}/"
    key = brand_key_for(brand, session)

    host = urlsplit(url).hostname or primary
    attempts: list[dict[str, Any]] = []

    async def attempt(profile: str) -> tuple[Any, dict[str, Any]]:
        res = await providers.browser().fetch(url, profile=profile)
        h = baseline_health.from_fetch(res)
        attempts.append({"via": profile, "ok": h["ok"], "kind": h["kind"], "status": h["status"], "vendor": h["vendor"]})
        if profile == "residential":
            _count_residential(session, brand, providers)
        return res, h

    page: Any = None  # the last live answer
    forced = via == "snapshot"
    live_via = "datacenter" if forced else via
    if forced:
        say("Using the urlscan.io snapshot" + (f" (scan {urlscan_id})" if urlscan_id else ""),
            "chosen by the analyst — the page is learned from the snapshot; the site is asked once, only for its "
            "real status and its favicon file")  # fmt: skip
        page, health = await attempt("datacenter")
        if health["ok"]:
            say(f"The official site answers (HTTP {health['status']})", "the snapshot is still used, as chosen")
        else:
            say(f"Got HTTP {health['status']} from {host}" if health["status"] else f"{host} did not let BrandWatch in",
                f"{health['reason']}.")  # fmt: skip
    else:
        say(f"Opening the official site {url}" + (" through the residential proxy" if via == "residential" else ""),
            "sandboxed Chromium: HTML, screenshot and favicon")  # fmt: skip
        page, health = await attempt(via)
        if health["ok"]:
            say(f"Official site loaded: HTTP {page.data.get('status')}",
                f"title “{(page.data.get('title') or '')[:80]}” · {len(page.data.get('html') or ''):,} characters of HTML")
        elif page.ok and page.data:
            say(f"Got HTTP {health['status']} from {host}" if health["status"] else f"{host} did not let BrandWatch in",
                f"{health['reason']}. The block page is not used as the fingerprint.")  # fmt: skip
        else:
            say(f"{host} could not be loaded", str(page.error or "unavailable"))
        if not health["ok"] and escalate and via == "datacenter":
            say("Retrying through the residential proxy",
                "a home IP address instead of a data-centre one — the usual way past an IP-based block "
                "(BrandWatch does not solve CAPTCHAs or disguise itself)")  # fmt: skip
            try:
                page2, health2 = await attempt("residential")
            except Exception as exc:  # noqa: BLE001 - a missing / failing proxy must never break onboarding
                say("The residential proxy could not be used", str(exc)[:160])
            else:
                if health2["ok"]:
                    page, health, live_via = page2, health2, "residential"
                    say(f"The residential proxy got in: HTTP {health2['status']}",
                        f"{host} answers a residential IP — the fingerprint is built from the live site")  # fmt: skip
                else:
                    say(f"The residential proxy was refused too: {health2['reason']}",
                        "the protection also blocks home IPs from this proxy pool")  # fmt: skip
        elif not health["ok"] and via == "datacenter" and residential_off:
            say("The residential proxy was not tried", residential_off)

    snap: dict[str, Any] | None = None
    if (not health["ok"] or forced) and snapshot:
        say("Asking urlscan.io for a public snapshot of the official site",
            "someone else's browser already saw the real page: its screenshot, colours and title are enough "
            "to compare look-alikes with")  # fmt: skip
        snap, why = await _urlscan_snapshot(providers, [host, primary], urlscan_id)
        if snap:
            say(f"Found a urlscan.io snapshot of {snap.get('url')} from {str(snap.get('time') or '')[:10]}",
                "the screenshot" + (", the page's DOM" if snap.get("html") else "")
                + (" and the favicon" if snap.get("favicon_png") else "")
                + (" — the page text, login form and favicon need a urlscan API key" if not snap.get("html") else ""),
                image=None)  # fmt: skip
        else:
            say("urlscan.io has no usable snapshot of this site",
                f"{why}. Fingerprint another official page, paste the link of a urlscan.io scan, or try again later")  # fmt: skip

    # what the fingerprint is learned from: the live site, else the snapshot, else nothing (never a block page)
    d: dict[str, Any] | None = None
    source = "none"
    if health["ok"] and not forced and page is not None and page.ok and page.data:
        d, source = page.data, "site"
    elif snap:
        title = str(snap.get("title") or "")
        d = {"html": snap.get("html") or (f"<html><head><title>{_html_escape(title)}</title></head><body></body></html>" if title else ""),
             "screenshot_png": snap["screenshot_png"], "favicon_png": snap.get("favicon_png"), "dom": None}  # fmt: skip
        source = "urlscan"
    # a protection that refuses the page often still serves the icon file (thenorthface.com: /favicon.ico → 200)
    blocked_icon = page.data.get("favicon_png") if (page is not None and page.ok and page.data and source != "site") else None
    if source == "urlscan" and d is not None and not d.get("favicon_png"):
        icon_bytes = blocked_icon  # the live attempt brought it: the site serves its icon file even when it blocks the page
        if icon_bytes:
            d["favicon_png"] = snap["favicon_png"] = icon_bytes  # type: ignore[index]
            snap["favicon_from"] = "site"  # type: ignore[index]
    unavailable: list[str] = []
    html = ""
    favicon_mmh3 = favicon_phash = None
    screenshot_phash = None
    screenshot_dhash = None
    colors: list[str] = []
    screenshots: dict = {}
    logo_path = None
    if d is not None or blocked_icon:
        html = (d.get("html") or "") if d else ""
        icon = (d.get("favicon_png") if d else None) or blocked_icon
        if icon:
            favicon_mmh3 = images.favicon_mmh3(icon)  # of the file as the site serves it
            picture = icon
            if images.is_svg(icon):  # many brands serve only favicon.svg: draw it, so it can be shown and compared
                picture = await images.rasterize_svg(icon)
            favicon_uri = ("data:image/png;base64," + base64.b64encode(picture).decode()) if picture else None
            say("Favicon fingerprint", f"mmh3 hash {favicon_mmh3} (the same hash Shodan indexes) — a phishing kit "
                "that copies the icon matches it exactly" + (" · an SVG icon" if images.is_svg(icon) else ""),
                image=favicon_uri)  # fmt: skip
            try:
                favicon_phash = images.phash_hex(picture) if picture else None
            except Exception:  # noqa: BLE001
                favicon_phash = None
            if picture:
                logo_path = store.put(picture, content_type="image/png", suffix=".png").location
        else:
            unavailable.append("favicon")
        shot = d.get("screenshot_png") if d else None
        if shot:
            screenshot_phash = images.phash_hex(shot)
            screenshot_dhash = images.dhash_hex(shot)
            colors = dom.palette_to_hex(dom.palette(shot))
            say("Screenshot fingerprint + colour palette",
                f"pHash {screenshot_phash} · dHash {screenshot_dhash} — candidates are compared with this "
                f"picture; {len(colors)} dominant colours extracted",
                [{"label": c, "tag": "colour", "color": c} for c in colors])  # fmt: skip
            art = store.put(shot, content_type="image/png", suffix=".png")
            screenshots["home"] = {
                "phash": screenshot_phash,
                "dhash": screenshot_dhash,
                "artifact": art.location,
                "url": url,
            }
        else:
            unavailable.append("screenshot")
    else:
        unavailable += ["http", "favicon", "screenshot"]
    if not health["ok"]:
        unavailable.append("homepage_blocked")
    if source == "urlscan":
        unavailable.append("snapshot")
        if not snap.get("html"):
            unavailable.append("page_text")
    if d is None and "http" not in unavailable:
        unavailable.append("http")

    if html and source == "site" and (bool(d.get("bot_challenge")) or is_bot_challenge(None, html)):
        unavailable.append(
            "homepage_bot_protected"
        )  # keywords / screenshot are the gate's, not the brand's
    features = extract_features(html, url, [key]) if html else None
    login_signature = (
        dom.login_form_signature(d.get("dom") or html) if (d is not None and html) else []
    )

    # --- the login / sign-up pages: most brands keep the forms off the homepage -------------
    auth_pages: list[dict] = []
    regs = {split_host(dmn).registrable for dmn in domains}
    for link in (auth_links(html, url, regs) if (html and health["ok"]) else [])[:3]:  # a snapshot cannot follow links
        entry: dict = {"kind": link["kind"], "url": link["url"], "ok": False, "has_password": False}
        try:
            ap = await providers.browser().fetch(link["url"], profile=live_via)
            if live_via == "residential":
                _count_residential(session, brand, providers)
        except Exception as exc:  # noqa: BLE001 - an auth page must never break onboarding
            entry["error"] = str(exc)[:120]
            auth_pages.append(entry)
            continue
        if ap.ok and ap.data:
            ahtml = ap.data.get("html") or ""
            afe = extract_features(ahtml, link["url"], [key])
            gated = bool(ap.data.get("bot_challenge")) or is_bot_challenge(afe.title, ahtml)
            entry.update(ok=True, has_password=bool(afe.credential_form), title=afe.title,
                         final_url=ap.data.get("final_url"), bot_challenge=gated)  # fmt: skip
            if gated:
                unavailable.append(f"{link['kind']}_page_bot_protected")
            if afe.credential_form and not login_signature:
                login_signature = dom.login_form_signature(ap.data.get("dom") or ahtml)
            shot = ap.data.get("screenshot_png")
            if shot and "login" not in screenshots and not gated:
                art = store.put(shot, content_type="image/png", suffix=".png")
                screenshots["login"] = {
                    "phash": images.phash_hex(shot), "dhash": images.dhash_hex(shot),
                    "artifact": art.location, "url": link["url"], "kind": link["kind"],
                }  # fmt: skip
        else:
            entry["error"] = ap.error
        auth_pages.append(entry)
    say(f"Login / sign-up pages: {len(auth_pages)} followed",
        "links whose text or path says login / sign up / register / account",
        [{"label": a.get("url", ""), "tag": a.get("kind", "") + (" · password form" if a.get("has_password") else "")
          + (" · bot protection" if a.get("bot_challenge") else "")} for a in auth_pages])  # fmt: skip
    has_login_form = bool(features and features.credential_form) or any(
        a.get("has_password") for a in auth_pages
    )
    terms = [key, *(t for t in title_keywords(html) if t != key)] if html else [key]
    say("Keywords from the page", f"brand token “{key}” + words of the <title> and <h1>/<h2> headings",
        [{"label": t, "tag": "keyword"} for t in terms[:12]])  # fmt: skip
    terms += [
        w for w in re.split(r"[^a-z0-9]+", _sname(brand).lower()) if len(w) > 3 and w not in terms
    ]

    llm_profile = None
    try:
        from brandwatch.detection import ai as ai_mod

        features_text = features.text_excerpt if features else ""
        llm_profile = await ai_mod.brand_profile(
            providers, brand_name=_sname(brand), homepage_text=features_text, kind=brand.kind
        )
    except Exception:  # noqa: BLE001 - onboarding never fails on the advisory LLM step
        llm_profile = None
    if llm_profile:
        say("AI brand profile", "the AI read the homepage text and returned brand words, lure phrases and the Google "
            "queries impersonators target (exact prompt and answer in the detailed trace)",
            [{"label": k, "tag": "AI keyword"} for k in llm_profile.get("keywords", [])[:6]]
            + [{"label": q, "tag": "search query"} for q in (llm_profile.get("search_queries") or [])[:8]])  # fmt: skip
    else:
        say(
            "AI brand profile skipped",
            "no LLM configured or it did not answer — default search queries are used",
        )
    if llm_profile:
        for kw in llm_profile.get("keywords", []):
            if kw not in terms and len(terms) < 20:
                terms.append(kw)

    version = (
        session.scalar(
            sa.select(sa.func.coalesce(sa.func.max(BrandFingerprint.version), 0)).where(
                BrandFingerprint.brand_id == brand.id
            )
        )
        or 0
    ) + 1
    fp = BrandFingerprint(
        brand_id=brand.id,
        version=version,
        favicon_mmh3=favicon_mmh3,
        favicon_phash=favicon_phash,
        logo_path=logo_path,
        screenshots=screenshots,
        keywords={"terms": terms, "source": "title_headings_v1"},
        features={
            "has_login_form": has_login_form,
            "auth_pages": auth_pages,
            "has_payment_form": bool(features and features.payment_form),
            "title": features.title if features else None,
            "unavailable": unavailable,
            "login_signature": login_signature,
            "official_apps": app_store_links(html, url) if html else [],
            "official_social": social_links(html) if html else [],
            # the brand's other country sites, linked from the official homepage (suggested to the analyst)
            "country_sites": country_sites(html, url, key, set(domains)) if html else [],
            "fetch": {**health, "url": url, "via": live_via, "at": utcnow().isoformat(), **_fetch_extra(attempts, source, snap)},
        },
        colors={"palette": colors},
        languages={"detected": ["en"]},
        llm_analysis=llm_profile,
    )
    session.add(fp)
    session.flush()
    return BaselineReport(
        fingerprint_id=fp.id,
        version=version,
        fetched_url=url,
        favicon_mmh3=favicon_mmh3,
        screenshot_phash=screenshot_phash,
        keywords=terms,
        unavailable=unavailable,
        fetch={**health, "url": url, "via": live_via, **_fetch_extra(attempts, source, snap)},
    )


def _html_escape(text: str) -> str:
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def _fetch_extra(attempts: list[dict[str, Any]], source: str, snap: dict[str, Any] | None) -> dict[str, Any]:
    """What was tried, and where the fingerprint came from ("site" = the live official site, "urlscan" = a
    public snapshot of it, "none" = nothing could be learned)."""
    out: dict[str, Any] = {"attempts": attempts, "source": source}
    if source == "urlscan" and snap:
        out["snapshot"] = {"scan_id": snap.get("scan_id"), "url": snap.get("url"), "time": snap.get("time"),
                           "has_dom": bool(snap.get("html")), "has_favicon": bool(snap.get("favicon_png")),
                           "favicon_from": snap.get("favicon_from") or ("urlscan" if snap.get("favicon_png") else None)}  # fmt: skip
    return out


def _count_residential(session: Session, brand: Brand, providers: ProviderRegistry) -> None:
    """A residential fetch is metered like the scan's own residential probe (about 2 MB, $0.016)."""
    from decimal import Decimal

    from brandwatch.db.models import ApiUsage
    from brandwatch.detection import cloaking

    demo = bool(getattr(providers.settings, "demo_mode", False))
    session.add(ApiUsage(
        workspace_id=brand.workspace_id, provider="residential", calls=1,
        cost_usd=Decimal("0") if demo else Decimal(str(round(cloaking.RESIDENTIAL_GB_PER_FETCH * cloaking.RESIDENTIAL_USD_PER_GB, 4))),
    ))  # fmt: skip
