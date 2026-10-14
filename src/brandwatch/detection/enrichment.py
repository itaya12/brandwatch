"""Enrichment (spec §3 stage 5): collect immutable evidence for one candidate.

Sub-ops through the provider layer: DNS → page fetch (HTML + screenshot + favicon via the
``browser`` chain) → WHOIS → reputation. Each provider failure degrades *that* evidence to
"unavailable" (recorded in ``CollectedEvidence.unavailable``) — never "clean" — and the item
continues. Every artifact goes to the evidence store; every observation becomes an immutable
``evidence`` row with provenance and a parent link (dns → http → html/screenshot/favicon).
"""

from __future__ import annotations

import hashlib
import ipaddress
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

import sqlalchemy as sa
from sqlalchemy.orm import Session

from brandwatch import __version__
from brandwatch.db.enums import (
    CandidateState,
    DiscoverySource,
    EvidenceType,
    ProviderStatus,
    ScannerProfile,
)
from brandwatch.db.models import (
    Candidate,
    DnsObservation,
    Evidence,
    HtmlSnapshot,
    HttpResponse,
    IpAddress,
    Observation,
    ReputationObservation,
    Screenshot,
    SslObservation,
    WhoisObservation,
)
from brandwatch.db.types import utcnow
from brandwatch.detection import baseline_health, dom, images
from brandwatch.detection.discovery import split_host
from brandwatch.detection.html import (
    HtmlFeatures,
    clickfix_lure,
    extract_features,
    security_warning,
)
from brandwatch.detection.snapshot import urlscan_picture, urlscan_snapshot
from brandwatch.evidence.store import EvidenceStore
from brandwatch.pipeline.stages import LivenessResult, PipelineContext
from brandwatch.providers.base import ProviderResult

COLLECTOR = "brandwatch.enrichment"


@dataclass(slots=True)
class CollectedEvidence:
    candidate_id: uuid.UUID
    url: str
    host: str
    registrable: str
    dns_records: list[str] | None = None  # None → unresolved (dead) or unavailable
    http_status: int | None = None
    final_url: str | None = None
    html: str | None = None
    content_sha256: str | None = None
    features: HtmlFeatures | None = None
    screenshot_png: bytes | None = None
    screenshot_phash: str | None = None
    screenshot_dhash: str | None = None
    palette: list[str] = field(default_factory=list)
    login_signature: list[str] = field(default_factory=list)
    dom_html: str | None = None
    favicon_png: bytes | None = None
    favicon_mmh3: int | None = None
    favicon_phash: str | None = None
    whois_age_days: int | None = None
    whois_registrar: str | None = None
    reputation: dict[str, ProviderStatus] = field(default_factory=dict)  # provider → status
    reputation_counts: dict[str, tuple[int | None, int | None]] = field(default_factory=dict)
    unavailable: list[str] = field(
        default_factory=list
    )  # dns/http/screenshot/favicon/whois/reputation
    evidence_ids: dict[str, uuid.UUID] = field(default_factory=dict)
    observation_id: uuid.UUID | None = None
    liveness: LivenessResult = LivenessResult(False, None, False, False)
    provider_notes: dict[str, str] = field(default_factory=dict)
    triggers: list[str] = field(default_factory=list)  # trigger names fired this run (spec §6)
    # the site refuses automated visitors (HTTP 403 / a bot check): {kind, status, vendor, reason}; its page is then
    # NOT the site, and ``snapshot`` says where the screenshot / title came from instead (urlscan.io)
    scanner_block: dict[str, Any] | None = None
    snapshot: dict[str, Any] | None = None
    # the ordinary visit's request: the baseline a crawler probe's request is compared with
    fetch_profile: str | None = None
    fetch_user_agent: str | None = None
    fetch_headers: dict[str, str] = field(default_factory=dict)
    # a crawler probe was shown a bot check: {visitor, user_agent, headers, status, vendor, why, compared, screenshot_evidence_id}
    challenge: dict[str, Any] | None = None
    # a flagged look-alike redirected its visitors here: {host, severity}
    redirected_from: dict[str, Any] | None = None
    # the page tries to make the visitor run a command (ClickFix) or is a fake Cloudflare check: {kind, reason, indicators}
    clickfix: dict[str, Any] | None = None
    # the picture is one flat colour (a gate that had not forwarded yet): it says nothing, so it is not used; ``no_picture``
    # says where the page leads instead when urlscan.io has no picture of it either
    screenshot_blank: bool = False
    no_picture: dict[str, Any] | None = None
    redirect_chain: list[str] = field(default_factory=list)  # every address the visit was sent away from (HTTP, meta refresh, script)
    # a security product (Cloudflare, an antivirus, a DNS filter) answered with its own "this site is phishing" page: a
    # verdict somebody else already made. {vendor, reason}. The site behind it is not opened any further.
    security_warning: dict[str, Any] | None = None
    reputation_detail: dict[str, dict[str, Any]] = field(default_factory=dict)  # provider -> {threats, phishing_engines}
    cloaking_suspected: bool = False  # Phase 5 multi-probe
    cloaking_signals: dict[str, str] = field(default_factory=dict)
    cloaking_summary: dict[str, Any] = field(default_factory=dict)
    ip: str | None = None
    tls_fingerprint: str | None = None
    tracking_ids: list[str] = field(default_factory=list)
    infra_links: dict[str, str] = field(
        default_factory=dict
    )  # signal → detail (runner fills from campaigns)

    @property
    def evidence_refs(self) -> tuple[uuid.UUID, ...]:
        return tuple(self.evidence_ids.values())


def _provider_short(name: str) -> str:
    return name.split(":", 1)[1] if name.startswith("mock:") else name


def _new_evidence(
    session: Session,
    cand: Candidate,
    etype: EvidenceType,
    *,
    source: str,
    source_type: str,
    parent: uuid.UUID | None = None,
    request_profile: dict[str, Any] | None = None,
    response_meta: dict[str, Any] | None = None,
    content_sha256: str | None = None,
    artifact_location: str | None = None,
    trust_level: str = "collected",
) -> Evidence:
    ev = Evidence(
        candidate_id=cand.id,
        type=etype,
        source=source,
        source_type=source_type,
        collector=COLLECTOR,
        collector_version=__version__,
        parser_version="1",
        request_profile=request_profile,
        response_meta=response_meta,
        content_sha256=content_sha256,
        artifact_location=artifact_location,
        trust_level=trust_level,
        parent_evidence_id=parent,
    )
    session.add(ev)
    session.flush()
    return ev


async def _is_registered(host: str) -> bool | None:
    """True if the name has NS / A records, False if NXDOMAIN, None if no usable answer."""
    import asyncio

    from brandwatch.detection import dnslookup

    return await asyncio.to_thread(dnslookup.registered, host)


async def enrich(
    ctx: PipelineContext,
    cand: Candidate,
    store: EvidenceStore,
    *,
    brand_keywords: list[str],
    profile: ScannerProfile = ScannerProfile.DATACENTER,
) -> CollectedEvidence:
    session = ctx.session
    host = cand.hostname
    col = CollectedEvidence(
        candidate_id=cand.id,
        url=cand.canonical_url,
        host=host,
        registrable=split_host(host).registrable,
    )
    req_profile = {"profile": profile.value, "collector": COLLECTOR}

    # --- DNS --------------------------------------------------------------------------------
    dns = await ctx.providers.dns().resolve(host, "A")
    dns_parent: uuid.UUID | None = None
    if dns.ok:
        col.dns_records = list(dns.data.get("records", [])) if dns.data else []
        ev = _new_evidence(
            session, cand, EvidenceType.DNS, source=dns.provider, source_type="dns",
            request_profile=req_profile, response_meta={"status": dns.status.value},
        )  # fmt: skip
        session.add(
            DnsObservation(evidence_id=ev.id, records={"A": col.dns_records}, resolver=dns.provider)
        )
        col.evidence_ids["dns"] = ev.id
        dns_parent = ev.id
    else:
        col.unavailable.append("dns")
        col.provider_notes["dns"] = dns.error or "unavailable"

    alive = bool(col.dns_records)
    if not alive:
        # no A record → there is no web server to fetch; do not call the browser (that only
        # produces "did not resolve" / timeout noise). The name may still be registered
        # (NS only) — a parked / reserved look-alike worth keeping on the watchlist.
        # only consult real DNS in live mode; demo/golden uses the recorded mock resolver
        registered = None if ctx.settings.demo_mode else await _is_registered(host)
        if "dns" in col.unavailable and registered is not False:
            col.unavailable.remove("dns")  # not an error: the domain simply serves no A record
            col.provider_notes["dns"] = (
                "registered but no A record (not hosting a website)" if registered
                else "no A record"
            )  # fmt: skip
        col.liveness = LivenessResult(
            alive=False,
            http_status=None,
            content_present=False,
            parked=bool(registered),  # parked = registered but no site
        )
        _record_observation(session, cand, col, changed=False)
        return col

    # --- page (HTML + screenshot + favicon) ---------------------------------------------------
    # A security product's phishing warning is a verdict somebody already made: when a plain HTTP request is enough to
    # see it (the site is served by Cloudflare, which is where most of them come from), no browser is launched at all.
    # An analyst's "Rescan" is a full check: it looks at the site behind the warning too.
    full_check = bool(ctx.extra.get("full_check"))
    page: ProviderResult | None = None
    if not full_check and (ctx.settings.demo_mode or _on_cloudflare(col.dns_records)):
        try:
            peeked = await ctx.providers.browser().peek(cand.canonical_url)
        except Exception:  # noqa: BLE001 - a failed peek only means the browser looks, as before
            peeked = None
        if peeked is not None and peeked.ok and peeked.data and security_warning(peeked.data.get("title"), peeked.data.get("html")):
            page = peeked
    if page is None:
        page = await ctx.providers.browser().fetch(cand.canonical_url, profile="datacenter-proceed" if full_check else profile.value)
    http_parent: uuid.UUID | None = dns_parent
    cfw: dict[str, Any] | None = None
    if page.ok and page.data:
        d = page.data
        col.http_status = d.get("status")
        col.final_url = d.get("final_url") or cand.canonical_url
        col.redirect_chain = [str(u) for u in (d.get("redirect_chain") or [])]
        col.fetch_profile, col.fetch_user_agent = profile.value, d.get("user_agent")
        col.fetch_headers = dict(d.get("request_headers") or {})
        col.html = d.get("html") or ""
        body = col.html.encode("utf-8", errors="replace")
        col.content_sha256 = hashlib.sha256(body).hexdigest()
        ev_http = _new_evidence(
            session, cand, EvidenceType.HTTP, source=page.provider, source_type="http",
            parent=dns_parent,
            request_profile={**req_profile, "user_agent": d.get("user_agent"), "headers": d.get("request_headers") or None},
            response_meta={"status": col.http_status, "final_url": col.final_url,
                           "content_type": d.get("content_type"), "redirect_chain": d.get("redirect_chain", [])},
            content_sha256=col.content_sha256,
        )  # fmt: skip
        session.add(
            HttpResponse(
                evidence_id=ev_http.id,
                status=col.http_status,
                headers={"content-type": d.get("content_type")},
                ip=d.get("ip"),
                redirect_chain=d.get("redirect_chain", []),
                size_bytes=len(body),
            )  # fmt: skip
        )
        col.evidence_ids["http"] = ev_http.id
        http_parent = ev_http.id

        col.features = extract_features(col.html, col.final_url, brand_keywords)
        col.clickfix = clickfix_lure(col.features.title, col.html, col.host)
        cfw = d.get("cloudflare_warning") or None
        if cfw:
            # Cloudflare showed its "Suspected Phishing" warning: a verdict (signal) and evidence; when the
            # browser proceeded past it, the page analysed below is the site behind the warning
            col.features.cloudflare_phish_warning = True
            warn = str(cfw.get("interstitial_html") or "").encode("utf-8", errors="replace")
            if warn:
                wart = store.put(warn, content_type="text/html", suffix=".html")
                _new_evidence(
                    session, cand, EvidenceType.HTML, source=page.provider, source_type="interstitial",
                    parent=http_parent, request_profile=req_profile, content_sha256=wart.sha256,
                    artifact_location=wart.location,
                    response_meta={"title": cfw.get("title"), "cloudflare_phishing_warning": True,
                                   "proceeded": bool(cfw.get("proceeded")), "error": cfw.get("error")},
                )  # fmt: skip
        col.dom_html = d.get("dom") or None
        col.ip = d.get("ip") or (col.dns_records[0] if col.dns_records else None)
        col.tls_fingerprint = d.get("tls_fingerprint_sha256")
        col.tracking_ids = list(col.features.tracking_ids)
        col.login_signature = dom.login_form_signature(col.dom_html or col.html)
        if col.html:
            art = store.put(body, content_type="text/html", suffix=".html")
            ev_html = _new_evidence(
                session, cand, EvidenceType.HTML, source=page.provider, source_type="html",
                parent=http_parent, request_profile=req_profile, content_sha256=art.sha256,
                artifact_location=art.location,
                response_meta={
                    "title": col.features.title,
                    "forms": len(col.features.forms),
                    "parked": col.features.is_parked,
                },
            )  # fmt: skip
            session.add(
                HtmlSnapshot(
                    evidence_id=ev_html.id,
                    dom_hash=art.sha256,
                    title=col.features.title,
                    meta={
                        "credential_form": col.features.credential_form,
                        "payment_form": col.features.payment_form,
                        "lure_terms": col.features.lure_terms,
                        "brand_keywords": col.features.brand_keywords,
                        "login_signature": col.login_signature,
                        "rendered_dom": col.dom_html is not None,
                        "tracking_ids": col.tracking_ids,
                    },
                    path=art.location,
                )  # fmt: skip
            )
            col.evidence_ids["html"] = ev_html.id

        shot = d.get("screenshot_png")
        if shot:
            col.screenshot_png = shot
            col.screenshot_phash = images.phash_hex(shot)
            col.screenshot_dhash = images.dhash_hex(shot)
            col.palette = dom.palette_to_hex(dom.palette(shot))
            col.screenshot_blank = images.is_blank(shot)
            art = store.put(shot, content_type="image/png", suffix=".png")
            w, h = images.image_size(shot)
            ev_shot = _new_evidence(
                session, cand, EvidenceType.SCREENSHOT, source=page.provider, source_type="screenshot",
                parent=http_parent, request_profile=req_profile, content_sha256=art.sha256,
                artifact_location=art.location,
                response_meta={"phash": col.screenshot_phash, "dhash": col.screenshot_dhash, "palette": col.palette,
                               **({"blank": True} if col.screenshot_blank else {})},
            )  # fmt: skip
            session.add(
                Screenshot(
                    evidence_id=ev_shot.id,
                    width=w,
                    height=h,
                    phash=col.screenshot_phash,
                    path=art.location,
                )
            )
            col.evidence_ids["screenshot"] = ev_shot.id
        else:
            col.unavailable.append("screenshot")
            col.provider_notes["screenshot"] = f"{page.provider} captured no screenshot"

        icon = d.get("favicon_png")
        if icon:
            col.favicon_png = icon
            col.favicon_mmh3 = images.favicon_mmh3(icon)
            try:
                col.favicon_phash = images.phash_hex(icon)
            except Exception:  # noqa: BLE001 - undecodable icon: keep mmh3 only
                col.favicon_phash = None
            art = store.put(icon, content_type="image/png", suffix=".png")
            ev_icon = _new_evidence(
                session, cand, EvidenceType.FAVICON, source=page.provider, source_type="favicon",
                parent=http_parent, request_profile=req_profile, content_sha256=art.sha256,
                artifact_location=art.location,
                response_meta={"mmh3": col.favicon_mmh3, "phash": col.favicon_phash},
            )  # fmt: skip
            col.evidence_ids["favicon"] = ev_icon.id
        else:
            col.unavailable.append("favicon")

        warn = security_warning(col.features.title, col.html) if col.html else None
        if cfw and not warn:
            warn = {"vendor": "Cloudflare", "reason": "its \u201cSuspected Phishing\u201d warning is shown instead of the site"}
        if warn:  # the verdict page: a short warning, never a site to be studied (no snapshot, no cloaking probes)
            col.security_warning = warn
            col.features.is_parked = False
            col.unavailable = [u for u in col.unavailable if u not in ("screenshot", "favicon")]

        # the site refuses automated visitors: what we hold is its block page, not the site
        health = baseline_health.from_fetch(page)
        if not health["ok"] and health["kind"] in ("blocked", "challenge") and not col.security_warning:
            col.scanner_block = {**{k: health.get(k) for k in ("kind", "status", "vendor", "reason")},
                                 "profile": profile.value, "user_agent": d.get("user_agent"), "headers": dict(d.get("request_headers") or {})}
            col.unavailable.append("live_page")
            await _use_snapshot(ctx, cand, col, store, brand_keywords, req_profile, http_parent)
        elif col.screenshot_blank and not col.security_warning and not col.clickfix:
            await _use_snapshot(ctx, cand, col, store, brand_keywords, req_profile, http_parent, reason="blank")
    else:
        col.unavailable += ["http", "screenshot", "favicon"]
        col.provider_notes["http"] = page.error or "unavailable"

    if col.tls_fingerprint:
        ev_ssl = _new_evidence(
            session, cand, EvidenceType.SSL, source=page.provider, source_type="tls",
            parent=http_parent, request_profile=req_profile,
            response_meta={"fingerprint_sha256": col.tls_fingerprint},
        )  # fmt: skip
        session.add(
            SslObservation(
                evidence_id=ev_ssl.id, fingerprint_sha256=col.tls_fingerprint, issuer=None
            )
        )
        col.evidence_ids["ssl"] = ev_ssl.id

    if col.ip:
        await geolocate_ip(ctx, col.ip)

    # --- WHOIS --------------------------------------------------------------------------------
    who = await ctx.providers.whois().lookup(col.registrable)
    if who.ok and who.data:
        col.whois_age_days = who.data.get("age_days")
        col.whois_registrar = who.data.get("registrar")
        registered = who.data.get("registered_at")
        ev_who = _new_evidence(
            session, cand, EvidenceType.WHOIS, source=who.provider, source_type="whois",
            request_profile=req_profile, response_meta={"status": who.status.value},
        )  # fmt: skip
        session.add(
            WhoisObservation(
                evidence_id=ev_who.id,
                registered_at=datetime.fromisoformat(registered).date() if registered else None,
                registrar=col.whois_registrar,
                registrant=who.data.get("registrant"),
                raw=who.raw if isinstance(who.raw, dict) else None,
                age_days=col.whois_age_days,
            )  # fmt: skip
        )
        col.evidence_ids["whois"] = ev_who.id
    else:
        col.unavailable.append("whois")
        col.provider_notes["whois"] = who.error or "unavailable"

    # --- Reputation (every provider in the chain is asked; UNKNOWN is never 'clean') -----------
    rep_chain = ctx.providers.reputation()
    any_ok = False
    for rp in rep_chain.providers:
        rep: ProviderResult = await rp.lookup_domain(host)
        short = _provider_short(rep.provider)
        if rep.ok and isinstance(rep.data, dict):
            col.reputation_detail[short] = {k: rep.data[k] for k in ("threats", "phishing_engines") if rep.data.get(k)}
        if not rep.ok:
            col.provider_notes[f"reputation:{short}"] = rep.error or "unavailable"
            continue
        any_ok = True
        col.reputation[short] = rep.status
        data = rep.data or {}
        if "positives" in data:
            try:
                col.reputation_counts[short] = (
                    int(data["positives"]),
                    int(data.get("total") or 0) or None,
                )
            except (TypeError, ValueError):
                pass
        ev_rep = _new_evidence(
            session, cand, EvidenceType.REPUTATION, source=rep.provider, source_type="reputation",
            request_profile=req_profile, response_meta={"status": rep.status.value},
        )  # fmt: skip
        session.add(
            ReputationObservation(
                evidence_id=ev_rep.id,
                provider=short,
                status=rep.status,
                verdict=str((rep.data or {}).get("positives", "")),
                raw=rep.raw if isinstance(rep.raw, dict) else None,
            )  # fmt: skip
        )
        col.evidence_ids[f"reputation:{short}"] = ev_rep.id
    if not any_ok:
        col.unavailable.append("reputation")

    # --- liveness + observation -----------------------------------------------------------------
    content_present = bool(col.html and col.features and not col.features.is_parked)
    parked = bool(col.features and col.features.is_parked)
    col.liveness = LivenessResult(
        alive=alive, http_status=col.http_status, content_present=content_present, parked=parked
    )
    changed = col.content_sha256 is not None and col.content_sha256 != cand.content_hash
    _record_observation(session, cand, col, changed=changed)
    return col


# Cloudflare's published address ranges (https://www.cloudflare.com/ips/): a site resolving into them is served by Cloudflare
_CLOUDFLARE_NETS = tuple(ipaddress.ip_network(n) for n in (
    "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22", "141.101.64.0/18", "108.162.192.0/18",
    "190.93.240.0/20", "188.114.96.0/20", "197.234.240.0/22", "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
    "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
    "2400:cb00::/32", "2606:4700::/32", "2803:f800::/32", "2405:b500::/32", "2405:8100::/32", "2a06:98c0::/29", "2c0f:f248::/32"))  # fmt: skip


def _on_cloudflare(records: list[str] | None) -> bool:
    for r in records or []:
        try:
            ip = ipaddress.ip_address(str(r))
        except ValueError:
            continue
        if any(ip in net for net in _CLOUDFLARE_NETS if net.version == ip.version):
            return True
    return False


MAX_SNAPSHOTS_PER_SCAN = 25  # urlscan.io is rate limited; a scan meets a handful of protected sites, not hundreds


def _no_picture(col: CollectedEvidence, why: str) -> None:
    """A blank page and nobody's picture of it: do not keep a white rectangle as the suspect's screenshot. Say where the page
    leads instead (the finding page shows the chain), and count the picture as missing."""
    col.no_picture = {"reason": "blank", "why": why, "final_url": col.final_url, "chain": list(col.redirect_chain),
                      "status": col.http_status}  # fmt: skip
    if col.evidence_ids.get("screenshot"):
        col.evidence_ids["screenshot_blank"] = col.evidence_ids.pop("screenshot")  # kept as evidence, no longer shown or compared
    col.screenshot_png = col.screenshot_phash = col.screenshot_dhash = None
    col.palette = []
    if "screenshot" not in col.unavailable:
        col.unavailable.append("screenshot")


async def _use_snapshot(
    ctx: PipelineContext, cand: Candidate, col: CollectedEvidence, store: EvidenceStore,
    brand_keywords: list[str] | None, req_profile: dict[str, Any] | None, http_parent: uuid.UUID | None,
    *, reason: str = "blocked",
) -> None:
    """The suspect refused the scan. If urlscan.io has a public scan of its homepage, use its screenshot and title
    (and, with a urlscan key, its DOM) instead of the block page: they feed the same visual and content signals as a
    live fetch, are stored as evidence of their own (source "urlscan", trust "third_party", the scan id and date) and
    are shown as a snapshot, never as what BrandWatch saw. Nothing here may fail the candidate."""
    session = ctx.session
    blank = reason == "blank"
    used = int(ctx.extra.get("snapshots_used", 0))
    if used >= MAX_SNAPSHOTS_PER_SCAN:
        col.provider_notes["snapshot"] = f"not asked: {MAX_SNAPSHOTS_PER_SCAN} urlscan.io lookups were already made in this scan"
        if blank:
            _no_picture(col, col.provider_notes["snapshot"])
        return
    ctx.extra["snapshots_used"] = used + 1
    finder = urlscan_picture if blank else urlscan_snapshot
    snap, why = await finder(ctx.providers, [col.host])
    if not snap:
        col.provider_notes["snapshot"] = f"urlscan.io has nothing to show: {why}"
        if blank:
            _no_picture(col, f"urlscan.io has no picture of it either: {why}")
        return
    shot = snap["screenshot_png"]
    try:
        phash, dhash = images.phash_hex(shot), images.dhash_hex(shot)
        palette = dom.palette_to_hex(dom.palette(shot))
        width, height = images.image_size(shot)
    except Exception as exc:  # noqa: BLE001 - an unreadable picture is no snapshot
        col.provider_notes["snapshot"] = f"urlscan.io screenshot unreadable: {type(exc).__name__}"
        if blank:
            _no_picture(col, col.provider_notes["snapshot"])
        return
    when = str(snap.get("time") or "")
    meta = {"scan_id": snap.get("scan_id"), "url": snap.get("url"), "time": when, "result_url": snap.get("result_url"),
            "has_dom": bool(snap.get("html")) and not blank, "title": snap.get("title"), "reason": reason,
            "reached": snap.get("reached"), "via": snap.get("via")}  # fmt: skip
    col.snapshot = meta
    col.provider_notes["snapshot"] = (
        f"urlscan.io picture of {snap.get('url')} from {when[:10]}: BrandWatch's own screenshot of the page was blank"
        if blank else f"urlscan.io snapshot of {snap.get('url')} from {when[:10]}: the live site answered "
                      f"HTTP {col.scanner_block.get('status') if col.scanner_block else '—'}")  # fmt: skip
    if blank and col.evidence_ids.get("screenshot"):
        col.evidence_ids["screenshot_blank"] = col.evidence_ids.pop("screenshot")  # the white one stays as evidence only
    col.screenshot_blank = False
    col.screenshot_png, col.screenshot_phash, col.screenshot_dhash, col.palette = shot, phash, dhash, palette
    art = store.put(shot, content_type="image/png", suffix=".png")
    ev_shot = _new_evidence(
        session, cand, EvidenceType.SCREENSHOT, source="urlscan", source_type="urlscan_snapshot",
        parent=http_parent, request_profile=req_profile, content_sha256=art.sha256,
        artifact_location=art.location, trust_level="third_party",
        response_meta={"phash": phash, "dhash": dhash, "palette": palette, "snapshot": meta},
    )  # fmt: skip
    session.add(Screenshot(evidence_id=ev_shot.id, width=width, height=height, phash=phash, path=art.location))
    col.evidence_ids["screenshot"] = ev_shot.id  # the picture shown and compared is the snapshot's, not the block page's
    col.unavailable = [u for u in col.unavailable if u != "screenshot"]

    title = str(snap.get("title") or "")
    html = snap.get("html") or (f"<html><head><title>{_esc(title)}</title></head><body></body></html>" if title else "")
    if html and not blank:  # a blank page keeps its own HTML (the gate's); only the picture comes from urlscan.io
        col.html, col.dom_html = html, snap.get("html") or None
        col.features = extract_features(html, col.final_url or cand.canonical_url, brand_keywords)
        col.features.is_parked = False  # a picture of a real page exists: this is not a parked domain
        col.tracking_ids = list(col.features.tracking_ids)
        col.login_signature = dom.login_form_signature(col.dom_html) if col.dom_html else []
        if col.dom_html:
            body = col.dom_html.encode("utf-8", errors="replace")
            hart = store.put(body, content_type="text/html", suffix=".html")
            ev_html = _new_evidence(
                session, cand, EvidenceType.HTML, source="urlscan", source_type="urlscan_dom",
                parent=http_parent, request_profile=req_profile, content_sha256=hart.sha256,
                artifact_location=hart.location, trust_level="third_party",
                response_meta={"title": col.features.title, "forms": len(col.features.forms), "snapshot": meta},
            )  # fmt: skip
            session.add(HtmlSnapshot(
                evidence_id=ev_html.id, dom_hash=hart.sha256, title=col.features.title,
                meta={"credential_form": col.features.credential_form, "payment_form": col.features.payment_form,
                      "lure_terms": col.features.lure_terms, "brand_keywords": col.features.brand_keywords,
                      "login_signature": col.login_signature, "rendered_dom": True, "snapshot": True},
                path=hart.location,
            ))  # fmt: skip
            col.evidence_ids["html"] = ev_html.id


def _esc(text: str) -> str:
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def _record_observation(
    session: Session, cand: Candidate, col: CollectedEvidence, *, changed: bool
) -> None:
    obs = Observation(
        candidate_id=cand.id,
        source=DiscoverySource.MANUAL if not cand.sources else cand.sources[0].source,
        scanner_profile=ScannerProfile.DATACENTER,
        state_at_time=cand.state,
        content_hash=col.content_sha256,
        screenshot_evidence_id=col.evidence_ids.get("screenshot"),
        http_status=col.http_status,
        changed=changed,
    )
    session.add(obs)
    session.flush()
    col.observation_id = obs.id
    cand.last_seen = utcnow()
    cand.scan_count = (cand.scan_count or 0) + 1
    if col.content_sha256:
        cand.content_hash = col.content_sha256


def schedule_next_scan(cand: Candidate, *, hours: int) -> None:
    cand.next_scan_at = datetime.now(UTC) + timedelta(hours=hours)


def dismiss_dead(cand: Candidate) -> None:
    cand.state = CandidateState.DISMISSED
    cand.next_scan_at = None


async def geolocate_ip(ctx: PipelineContext, ip: str) -> IpAddress | None:
    """Upsert ``ip_addresses`` with geolocation (dashboard globe / attribution). Best effort."""
    session = ctx.session
    row = session.scalars(sa.select(IpAddress).where(IpAddress.ip == ip)).first()
    if row is None:
        row = IpAddress(ip=ip)
        session.add(row)
        session.flush()
    row.last_seen = utcnow()
    if row.lat is None:
        try:
            geo = await ctx.providers.geo().locate(ip)
        except Exception:  # noqa: BLE001 - geo is cosmetic; never fail the scan on it
            geo = None
        if geo is not None and geo.ok and geo.data and geo.data.get("lat") is not None:
            row.country = geo.data.get("country")
            row.city = geo.data.get("city")
            row.lat = float(geo.data["lat"])
            row.lon = float(geo.data["lon"])
            row.org = geo.data.get("org")
            row.geo_source = geo.provider
    session.flush()
    return row
