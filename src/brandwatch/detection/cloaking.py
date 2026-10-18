"""Cloaking / anti-bot detection (spec §8 "Cloaking", §3 Analysis Tier 3–4), Phase 5.

Kits serve a benign page to scanners and the phishing page only to victims. We look at the same
URL through several *profiles* and compare what comes back:

    Tier 3 (cheap, datacenter):
        bot        crawler User-Agent            → benign while a real browser sees a login form
                                                   = ``cloaking_ua_based``  (captcha page = ``bot_blocking``)
        param      ``?email=victim@example.com``  → login form appears only with the parameter
                                                   = ``parameter_gating``
        referer    ``Referer: google.com``         → login form appears only when "coming from search"
                                                   = ``referer_gating``
    Tier 4 (gated, $/GB):
        residential  residential/mobile proxy      → login form appears only to a residential IP
                                                   = ``cloaking_ip_based`` (the strongest tell)

Tier 3 runs when the candidate is brand-related, has a credential form, or scores ≥ Medium.
Tier 4 runs only when cloaking is *suspected* (a probe diverged, or the cheap fetch shows a thin,
brand-less "maintenance" page on a brand-lookalike host) or the preliminary risk is ≥ Medium —
and only within the residential budget. A probe that reveals the real page hands its capture to
the analysis stage, so the finding is scored on what a victim actually sees.

Every probe is an immutable HTTP evidence row (``source_type = "probe"``) whose response meta
records whether it diverged from the datacenter view. Residential proxies are used to *look*
(evidence collection) — never to interact with or attack a target.
"""

from __future__ import annotations

import hashlib
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

import sqlalchemy as sa

from brandwatch.db.enums import DiscoverySource, EvidenceType, ScannerProfile, Severity
from brandwatch.db.models import (
    ApiUsage,
    Candidate,
    HtmlSnapshot,
    HttpResponse,
    Observation,
    Screenshot,
)
from brandwatch.detection import dom, images
from brandwatch.detection.baseline_health import vendor_of
from brandwatch.detection.discovery import split_host
from brandwatch.detection.enrichment import CollectedEvidence, _new_evidence
from brandwatch.detection.html import (
    CHALLENGE_MAX_TEXT,
    HtmlFeatures,
    extract_features,
    is_bot_challenge,
    visible_text,
)
from brandwatch.detection.sources import _looks_related
from brandwatch.evidence.store import EvidenceStore
from brandwatch.pipeline.stages import LivenessResult, PipelineContext

PROBE_EMAIL = "victim@example.com"
RESIDENTIAL_GB_PER_FETCH = 0.002  # ~2 MB per rendered page
RESIDENTIAL_USD_PER_GB = 8.0
THIN_PAGE_CHARS = 300
CHALLENGE_MARKERS = (
    "captcha",
    "verify you are human",
    "are you a robot",
    "checking your browser",
    "cf-challenge",
    "please enable javascript and cookies",
)
_SEV = [Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
# headers that differ between any two visits without meaning anything
_VOLATILE_HEADERS = frozenset({"cookie", "content-length", "if-none-match", "if-modified-since"})
# what a person's browser sends and the sandboxed one may not: the first thing many bot checks look at
BROWSER_HEADERS = ("accept-language", "sec-ch-ua", "sec-fetch-site", "sec-fetch-mode", "sec-fetch-dest")


def is_challenge_page(title: str | None, html: str | None) -> bool:
    """A gate, not a site: Cloudflare's "Just a moment…", a CAPTCHA wall, "verify you are human". The word "captcha" inside
    the scripts of an ordinary page (the error text of its login form) is not one: the first version of this check took
    it for one, and rated ordinary sites "blocks bots" and "diverged"."""
    if is_bot_challenge(title, html):
        return True
    text = visible_text(html)
    return len(text) <= CHALLENGE_MAX_TEXT and any(m in f"{title or ''} {text}".lower() for m in CHALLENGE_MARKERS)


@dataclass(slots=True)
class ProbeOutcome:
    name: str
    profile: str
    url: str
    ok: bool
    status: int | None = None
    content_sha256: str | None = None
    phishy: bool = False
    challenge: bool = False
    diverged: bool = False
    error: str | None = None
    evidence_id: uuid.UUID | None = None
    page: dict[str, Any] | None = None
    features: HtmlFeatures | None = None
    challenge_info: dict[str, Any] | None = None  # who was challenged, what the page said, the screenshot's evidence id

    def summary(self) -> dict[str, Any]:
        return {
            "probe": self.name, "profile": self.profile, "ok": self.ok, "status": self.status,
            "credential_form": self.phishy, "challenge": self.challenge, "diverged": self.diverged,
            "sha256": (self.content_sha256 or "")[:12] or None, "error": self.error,
        }  # fmt: skip


@dataclass(slots=True)
class CloakingResult:
    probes: list[ProbeOutcome] = field(default_factory=list)
    signals: dict[str, str] = field(default_factory=dict)
    suspected: bool = False
    revealed_by: str | None = None
    residential: str = "not_needed"  # not_needed | used | skipped:<reason>

    def summary(self) -> dict[str, Any]:
        return {
            "probes": [p.summary() for p in self.probes],
            "signals": dict(self.signals),
            "suspected": self.suspected,
            "revealed_by": self.revealed_by,
            "residential": self.residential,
        }


# --------------------------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------------------------
def with_probe_param(url: str) -> str:
    parts = urlsplit(url)
    query = [(k, v) for k, v in parse_qsl(parts.query, keep_blank_values=True) if k != "email"]
    query.append(("email", PROBE_EMAIL))
    return urlunsplit((parts.scheme, parts.netloc, parts.path or "/", urlencode(query), ""))


def is_phishy(features: HtmlFeatures | None) -> bool:
    return bool(
        features
        and (features.credential_form or features.payment_form or features.seed_phrase_field)
    )


def looks_hidden(col: CollectedEvidence, brand_key: str) -> bool:
    """Brand-lookalike host serving a thin, brand-less page with no forms (the classic decoy)."""
    f = col.features
    if f is None or is_phishy(f) or not _looks_related(col.host, brand_key):
        return False
    return (
        (f.is_parked or len(f.text_excerpt) < THIN_PAGE_CHARS)
        and not f.brand_keywords
        and not f.forms
    )


def should_probe(col: CollectedEvidence, brand_key: str, prelim: Severity) -> bool:
    if not col.liveness.alive or col.features is None or col.security_warning:  # a verdict was already made
        return False
    return _looks_related(col.host, brand_key) or is_phishy(col.features) or _SEV.index(prelim) >= 1


def residential_gb_today(session, workspace_id: uuid.UUID) -> float:
    since = datetime.now(UTC) - timedelta(days=1)
    calls = session.scalar(
        sa.select(sa.func.coalesce(sa.func.sum(ApiUsage.calls), 0)).where(
            ApiUsage.workspace_id == workspace_id,
            ApiUsage.provider == "residential",
            ApiUsage.at >= since,
        )
    )
    return float(calls or 0) * RESIDENTIAL_GB_PER_FETCH


def residential_gate(
    session, workspace_id: uuid.UUID, settings, limit_gb: float, proxy_enabled: bool
) -> str | None:
    """None when a residential fetch may go ahead; otherwise why not. The budget is checked before the proxy:
    the default budget is 0 GB, so the paid proxy is never used until somebody sets one. Demo: a recorded view."""
    if settings.demo_mode:
        return None
    if limit_gb <= 0:
        return "the residential budget is 0 GB - raise it under Settings → Workspace & budget"
    used = residential_gb_today(session, workspace_id)
    if used + RESIDENTIAL_GB_PER_FETCH > limit_gb:
        return f"the residential budget is used up today ({used:.3f}/{limit_gb} GB)"
    if not proxy_enabled:
        return "no residential proxy is switched on - Settings → Residential proxy"
    return None


def residential_allowance(ctx: PipelineContext) -> tuple[bool, str]:
    det = ctx.config.detection
    if det.residential_probe == "off":
        return False, "disabled for this brand"
    if ctx.settings.demo_mode:
        return True, "demo mode (recorded residential view)"
    extra = getattr(ctx, "extra", None) or {}
    if not (extra.get("proxy_enabled") or ctx.settings.residential_proxy_url):
        kind = {"mobile": "mobile", "both": "residential or mobile"}.get(str(extra.get("proxy_kind")), "residential")
        return False, f"no {kind} proxy configured (Settings → Proxy)"
    limit = ctx.config.economic_limits.max_residential_gb
    used = residential_gb_today(ctx.session, ctx.workspace_id)
    if limit <= 0 or used + RESIDENTIAL_GB_PER_FETCH > limit:
        return False, f"residential budget exhausted ({used:.3f}/{limit} GB)"
    return True, "within budget"


# --------------------------------------------------------------------------------------------
# probing
# --------------------------------------------------------------------------------------------
async def _probe(
    ctx: PipelineContext, cand: Candidate, col: CollectedEvidence, name: str, profile: str, url: str,
    keywords: list[str], dc_phishy: bool, store: EvidenceStore,
) -> ProbeOutcome:  # fmt: skip
    res = await ctx.providers.browser().fetch(url, profile=profile)
    if not res.ok or not res.data:
        return ProbeOutcome(name, profile, url, ok=False, error=res.error or "unavailable")
    d = res.data
    html = d.get("dom") or d.get("html") or ""
    feats = extract_features(html, d.get("final_url") or url, keywords)
    sha = hashlib.sha256(html.encode("utf-8", errors="replace")).hexdigest()
    phishy = is_phishy(feats)
    title = d.get("title") or (feats.title if feats else None)
    challenge = is_challenge_page(title, html)
    diverged = (sha != col.content_sha256) and (phishy != dc_phishy or challenge)
    # what this visit really sent: the evidence says who was asking, which is what a bot check is decided on
    profile_row = {"profile": profile, "probe": name, "url": url, "user_agent": d.get("user_agent"),
                   "headers": d.get("request_headers") or None}  # fmt: skip
    ev = _new_evidence(
        ctx.session, cand, EvidenceType.HTTP, source=res.provider, source_type="probe",
        parent=col.evidence_ids.get("http"),
        request_profile=profile_row,
        response_meta={"probe": name, "status": d.get("status"), "content_sha256": sha,
                       "credential_form": phishy, "challenge": challenge, "diverged": diverged},
        content_sha256=sha,
    )  # fmt: skip
    ctx.session.add(
        HttpResponse(
            evidence_id=ev.id,
            status=d.get("status"),
            headers={"content-type": d.get("content_type")},
            ip=d.get("ip"),
            redirect_chain=d.get("redirect_chain", []),
            size_bytes=len(html),
        )  # fmt: skip
    )
    ctx.session.flush()
    col.evidence_ids[f"probe:{name}"] = ev.id
    info = _keep_challenge(ctx, cand, col, store, name, res.provider, profile_row, d, ev.id, title, html) if challenge else None
    return ProbeOutcome(
        name, profile, url, ok=True, status=d.get("status"), content_sha256=sha, phishy=phishy,
        challenge=challenge, diverged=diverged, evidence_id=ev.id, page=d, features=feats, challenge_info=info,
    )  # fmt: skip


def _keep_challenge(
    ctx: PipelineContext, cand: Candidate, col: CollectedEvidence, store: EvidenceStore, name: str, provider: str,
    profile_row: dict[str, Any], d: dict[str, Any], parent: uuid.UUID, title: str | None, html: str,
) -> dict[str, Any]:  # fmt: skip
    """The bot check the probe was shown, kept as evidence: a picture of it and its HTML (what the page said, who
    served it), linked to the visit that got it. The picture is not the site's: it is never used as the suspect's
    screenshot (``source_type = challenge_screenshot``)."""
    shot = d.get("screenshot_png")
    shot_id: uuid.UUID | None = None
    if shot:
        art = store.put(shot, content_type="image/png", suffix=".png")
        w, h = images.image_size(shot)
        ev_shot = _new_evidence(
            ctx.session, cand, EvidenceType.SCREENSHOT, source=provider, source_type="challenge_screenshot", parent=parent,
            request_profile=profile_row, content_sha256=art.sha256, artifact_location=art.location,
            response_meta={"probe": name, "challenge": True, "title": title, "status": d.get("status")},
        )  # fmt: skip
        ctx.session.add(Screenshot(evidence_id=ev_shot.id, width=w, height=h, phash=images.phash_hex(shot), path=art.location))
        col.evidence_ids[f"challenge:{name}"] = ev_shot.id
        shot_id = ev_shot.id
    page = store.put(html.encode("utf-8", errors="replace"), content_type="text/html", suffix=".html")
    ev_html = _new_evidence(
        ctx.session, cand, EvidenceType.HTML, source=provider, source_type="challenge", parent=parent,
        request_profile=profile_row, content_sha256=page.sha256, artifact_location=page.location,
        response_meta={"probe": name, "challenge": True, "title": title},
    )  # fmt: skip
    col.evidence_ids[f"challenge_html:{name}"] = ev_html.id
    ctx.session.flush()
    return {
        "probe": name, "profile": profile_row["profile"], "user_agent": profile_row.get("user_agent"),
        "headers": profile_row.get("headers") or {}, "status": d.get("status"), "title": (title or "")[:120] or None,
        "vendor": vendor_of(title, html), "said": visible_text(html)[:240],
        "screenshot_evidence_id": str(shot_id) if shot_id else None,
    }  # fmt: skip


def _short_ua(ua: str | None) -> str:
    return (ua or "an unknown browser")[:90]


def challenge_report(bot: ProbeOutcome, col: CollectedEvidence) -> dict[str, Any]:
    """Which visitor was shown the bot check, and why that one: the crawler probe against the ordinary browser visit
    of the same scan (same IP; they differ in what they sent)."""
    info = dict(bot.challenge_info or {})
    base_title = col.features.title if col.features else None
    base_challenged = is_challenge_page(base_title, col.html)
    sent, base_sent = info.get("headers") or {}, col.fetch_headers or {}
    diffs = [{"header": k, "crawler": sent.get(k), "browser": base_sent.get(k)}
             for k in sorted(set(sent) | set(base_sent))
             if k not in _VOLATILE_HEADERS and sent.get(k) != base_sent.get(k)]  # fmt: skip
    ua, base_ua = info.get("user_agent"), col.fetch_user_agent
    on = f" ({info['vendor']})" if info.get("vendor") else ""
    missing = [h for h in BROWSER_HEADERS if sent and h not in sent]
    if base_challenged:
        why = ("The ordinary browser visit from the same IP address was shown a bot check too, so it is not the crawler's User-Agent "
               "that sets this off: the site (or the network in front of it) challenges automated browsers coming from a data-centre address.")  # fmt: skip
    elif [x["header"] for x in diffs] in (["user-agent"], []):
        why = (f"The two visits came from the same data-centre IP address and sent the same headers except the User-Agent. The crawler "
               f"sent “{_short_ua(ua)}” — it announces itself as a bot — and only it was challenged; the browser-like visit "
               f"(“{_short_ua(base_ua)}”) was given the page. So the site tells crawlers apart by their User-Agent.")  # fmt: skip
    else:
        names = ", ".join(x["header"] for x in diffs[:6])
        why = (f"The crawler visit and the browser-like visit came from the same IP address but differ in: {names}. Only the crawler was "
               f"challenged, so the site is judging what the visitor sends: its User-Agent (“{_short_ua(ua)}”) and headers.")  # fmt: skip
    if missing:
        why += (f" A person's browser also sends {', '.join(missing)}; this visit did not"
                + (" (nor did the browser-like one, so that is not what set the two apart — but it is what many bot checks look at first)."
                   if not [m for m in missing if m in base_sent] else "."))  # fmt: skip
    return {
        **info,
        "not_sent": missing,
        "visitor": "BrandWatch crawler probe" if bot.name == "bot" else f"BrandWatch “{bot.name}” probe",
        "ip": "data-centre IP (the same one as the browser-like visit)",
        "compared": {"profile": col.fetch_profile or "datacenter", "user_agent": base_ua, "status": col.http_status,
                     "title": (base_title or "")[:120] or None, "challenged": base_challenged},
        "differences": diffs[:12],
        "why": why,
        "summary": (f"the crawler (User-Agent “{_short_ua(ua)}”) was shown a bot check{on}, HTTP {info.get('status')}; "
                    + ("the browser-like visit was shown one too" if base_challenged else "the browser-like visit was not")),  # fmt: skip
    }



def _adopt(
    ctx: PipelineContext,
    cand: Candidate,
    col: CollectedEvidence,
    store: EvidenceStore,
    outcome: ProbeOutcome,
) -> None:
    """The probe saw what a victim sees: analyse that capture instead of the decoy."""
    session = ctx.session
    d = outcome.page or {}
    html = d.get("dom") or d.get("html") or ""
    body = html.encode("utf-8", errors="replace")
    profile = {"profile": outcome.profile, "probe": outcome.name, "url": outcome.url}
    art = store.put(body, content_type="text/html", suffix=".html")
    ev_html = _new_evidence(
        session, cand, EvidenceType.HTML, source=f"probe:{outcome.name}", source_type="html",
        parent=outcome.evidence_id, request_profile=profile, content_sha256=art.sha256, artifact_location=art.location,
        response_meta={"title": outcome.features.title if outcome.features else None, "forms": len(outcome.features.forms) if outcome.features else 0,
                       "parked": False, "probe": outcome.name, "revealed": True},
    )  # fmt: skip
    feats = outcome.features
    login_sig = dom.login_form_signature(html)
    session.add(
        HtmlSnapshot(
            evidence_id=ev_html.id,
            dom_hash=art.sha256,
            title=feats.title if feats else None,
            meta={
                "credential_form": is_phishy(feats),
                "payment_form": bool(feats and feats.payment_form),
                "lure_terms": feats.lure_terms if feats else [],
                "brand_keywords": feats.brand_keywords if feats else [],
                "login_signature": login_sig,
                "tracking_ids": feats.tracking_ids if feats else [],
                "revealed_by": outcome.name,
            },
            path=art.location,
        )  # fmt: skip
    )
    if "html" in col.evidence_ids:
        col.evidence_ids["html:decoy"] = col.evidence_ids["html"]
    col.evidence_ids["html"] = ev_html.id
    col.html = html
    col.features = feats
    col.login_signature = login_sig
    col.tracking_ids = list(feats.tracking_ids) if feats else []

    shot = d.get("screenshot_png")
    if shot:
        sart = store.put(shot, content_type="image/png", suffix=".png")
        phash, dhash = images.phash_hex(shot), images.dhash_hex(shot)
        pal = dom.palette_to_hex(dom.palette(shot))
        w, h = images.image_size(shot)
        ev_shot = _new_evidence(
            session, cand, EvidenceType.SCREENSHOT, source=f"probe:{outcome.name}", source_type="screenshot",
            parent=outcome.evidence_id, request_profile=profile, content_sha256=sart.sha256, artifact_location=sart.location,
            response_meta={"phash": phash, "dhash": dhash, "palette": pal, "probe": outcome.name, "revealed": True},
        )  # fmt: skip
        session.add(
            Screenshot(evidence_id=ev_shot.id, width=w, height=h, phash=phash, path=sart.location)
        )
        if "screenshot" in col.evidence_ids:
            col.evidence_ids["screenshot:decoy"] = col.evidence_ids["screenshot"]
        col.evidence_ids["screenshot"] = ev_shot.id
        col.screenshot_png, col.screenshot_phash, col.screenshot_dhash, col.palette = (
            shot,
            phash,
            dhash,
            pal,
        )
        col.unavailable = [u for u in col.unavailable if u != "screenshot"]

    icon = d.get("favicon_png")
    if icon:
        fart = store.put(icon, content_type="image/png", suffix=".png")
        mmh3 = images.favicon_mmh3(icon)
        try:
            fph = images.phash_hex(icon)
        except Exception:  # noqa: BLE001
            fph = None
        ev_icon = _new_evidence(
            session, cand, EvidenceType.FAVICON, source=f"probe:{outcome.name}", source_type="favicon",
            parent=outcome.evidence_id, request_profile=profile, content_sha256=fart.sha256, artifact_location=fart.location,
            response_meta={"mmh3": mmh3, "phash": fph, "probe": outcome.name, "revealed": True},
        )  # fmt: skip
        if "favicon" in col.evidence_ids:
            col.evidence_ids["favicon:decoy"] = col.evidence_ids["favicon"]
        col.evidence_ids["favicon"] = ev_icon.id
        col.favicon_png, col.favicon_mmh3, col.favicon_phash = icon, mmh3, fph
        col.unavailable = [u for u in col.unavailable if u != "favicon"]

    col.liveness = LivenessResult(
        alive=True, http_status=outcome.status, content_present=True, parked=False
    )
    if outcome.name.startswith(("residential", "mobile-network")):
        mobile_net = outcome.name.startswith("mobile-network") or ctx.extra.get("proxy_kind") == "mobile"
        session.add(
            Observation(
                candidate_id=cand.id,
                source=cand.sources[0].source if cand.sources else DiscoverySource.MANUAL,
                scanner_profile=ScannerProfile.MOBILE if mobile_net else ScannerProfile.RESIDENTIAL,
                state_at_time=cand.state,
                content_hash=outcome.content_sha256,
                screenshot_evidence_id=col.evidence_ids.get("screenshot"),
                http_status=outcome.status,
                changed=True,
            )
        )
    session.flush()


async def probe(
    ctx: PipelineContext,
    cand: Candidate,
    col: CollectedEvidence,
    store: EvidenceStore,
    *,
    brand_key: str,
    keywords: list[str],
    prelim: Severity,
) -> CloakingResult:
    result = CloakingResult()
    dc_phishy = is_phishy(col.features)
    base_url = cand.canonical_url

    # ---- Tier 3: cheap datacenter probes ---------------------------------------------------
    devices = str(ctx.extra.get("devices") or "desktop")  # Settings → Proxy: desktop, a phone, or both
    tier3 = [("bot", "bot", base_url), ("param", "datacenter", with_probe_param(base_url)), ("referer", "referer", base_url)]
    if devices in ("mobile", "both"):
        tier3.append(("mobile", "mobile", base_url))  # kits that target phones show the lure to a mobile browser only
    for name, profile, url in tier3:
        result.probes.append(await _probe(ctx, cand, col, name, profile, url, keywords, dc_phishy, store))

    by = {p.name: p for p in result.probes}
    bot, param, ref = by["bot"], by["param"], by["referer"]
    mob = by.get("mobile")
    if dc_phishy and bot.ok and not bot.phishy and bot.content_sha256 != col.content_sha256:
        result.signals["cloaking_ua_based"] = (
            "a crawler User-Agent gets a benign page; a real browser gets the credential form"
        )
    if bot.ok and bot.challenge:
        col.challenge = challenge_report(bot, col)
        result.signals["bot_blocking"] = col.challenge["summary"]
    revealed: ProbeOutcome | None = None
    if not dc_phishy and param.ok and param.phishy:
        result.signals["parameter_gating"] = (
            f"login form appears only with ?email={PROBE_EMAIL} (victim link parameter)"
        )
        revealed = param
    if not dc_phishy and ref.ok and ref.phishy:
        result.signals["referer_gating"] = (
            "login form appears only when the visit comes from a search referer"
        )
        revealed = revealed or ref
    if not dc_phishy and mob is not None and mob.ok and mob.phishy:
        result.signals["device_gating"] = "the login form appears only to a mobile phone: a desktop browser is shown a harmless page"
        revealed = revealed or mob

    result.suspected = (
        bool(revealed) or any(p.diverged for p in result.probes) or looks_hidden(col, brand_key)
    )

    # ---- Tier 4: residential (gated, budgeted) ----------------------------------------------
    want_residential = result.suspected or _SEV.index(prelim) >= 1
    if want_residential and not (dc_phishy and result.signals):
        allowed, why = residential_allowance(ctx)
        if not allowed:
            result.residential = f"skipped:{why}"
            if result.suspected and not revealed:
                col.unavailable.append(
                    "residential"
                )  # confidence penalty: the victim view is unknown
        else:
            # one visit per proxy (residential, mobile network or both) and per device (desktop, phone or both)
            nets = list(ctx.extra.get("proxy_nets") or []) or [
                ("mobile-network" if ctx.extra.get("proxy_kind") == "mobile" else "residential", "residential")]
            if ctx.settings.demo_mode and ctx.extra.get("proxy_kind") == "both":
                nets = [("residential", "residential"), ("mobile-network", "carrier")]  # recorded: both answer
            runs = []
            for net, prefix in nets:
                base = "residential" if prefix == "residential" else "mobile-network"
                if devices in ("desktop", "both"):
                    runs.append((base, prefix, "desktop", net))
                if devices in ("mobile", "both"):
                    runs.append((f"{base}-mobile" if prefix == "residential" else "mobile-network-phone", f"{prefix}+mobile", "phone", net))
            done: list[tuple[ProbeOutcome, str, str]] = []
            for name, profile, label, net in runs:
                res = await _probe(ctx, cand, col, name, profile, base_url, keywords, dc_phishy, store)
                result.probes.append(res)
                ctx.session.add(
                    ApiUsage(
                        workspace_id=ctx.workspace_id,
                        provider="residential",
                        job_id=ctx.job_id,
                        calls=1,
                        cost_usd=Decimal("0")
                        if ctx.settings.demo_mode
                        else Decimal(str(round(RESIDENTIAL_GB_PER_FETCH * RESIDENTIAL_USD_PER_GB, 4))),
                    )  # fmt: skip
                )
                done.append((res, label, net))
            result.residential = "used" if any(r.ok for r, _, _ in done) else f"skipped:{done[0][0].error}"
            for res, label, net in done:
                if res.ok and res.phishy and not dc_phishy:
                    # only an IP-based decision if the parameter / referer / phone probes did not already explain it
                    explained = (param.ok and param.phishy) or (ref.ok and ref.phishy) or (mob is not None and mob.ok and mob.phishy)
                    if not explained:
                        result.signals["cloaking_ip_based"] = (
                            f"datacenter IPs get a decoy page; a {net} IP gets the phishing page" + (" (seen as a phone)" if label == "phone" else "")
                        )
                    revealed = revealed or res
            if not any(r.ok for r, _, _ in done) and result.suspected and not revealed:
                col.unavailable.append("residential")

    if revealed is not None:
        _adopt(ctx, cand, col, store, revealed)
        result.revealed_by = revealed.name
    col.cloaking_signals = dict(result.signals)
    col.cloaking_summary = result.summary()
    col.cloaking_suspected = (
        result.suspected and not result.revealed_by and result.residential != "used"
    )
    return result


def brand_key_from(host: str) -> str:  # pragma: no cover - convenience for scripts
    return split_host(host).sld
