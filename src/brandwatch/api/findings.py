"""Findings, Explain Finding, evidence, watchlist (spec §14 Findings / Watchlist tabs).

The detail payload is the analyst's 5-second answer: what happened / how bad / why / what
evidence / what do I do — fired signals with plain-language details, group caps, bonuses and
penalties, confidence breakdown, evidence with roles and artifacts, side-by-side screenshots,
the observation timeline and the score history.
"""

from __future__ import annotations

import mimetypes
import re
import uuid
from typing import Annotated, Any
from urllib.parse import urlsplit

import sqlalchemy as sa
from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from brandwatch.api.auth import current_user, require_analyst
from brandwatch.api.deps import get_session
from brandwatch.config.brand_config import SIGNAL_GROUPS
from brandwatch.db.enums import (
    AnalystVerdict,
    CandidateState,
    EvidenceType,
    FindingState,
    ProviderStatus,
    Severity,
)
from brandwatch.db.models import (
    Brand,
    BrandFingerprint,
    Candidate,
    CandidateSource,
    Evidence,
    Finding,
    FindingEvidence,
    Observation,
    ReputationObservation,
    RiskScore,
    Screenshot,
    User,
)
from brandwatch.detection import finding as finding_stage
from brandwatch.detection import images
from brandwatch.detection import regions as regions_mod

router = APIRouter(prefix="/api", tags=["findings"])

_SEV_RANK = sa.case(
    (Finding.severity == Severity.CRITICAL, 4),
    (Finding.severity == Severity.HIGH, 3),
    (Finding.severity == Severity.MEDIUM, 2),
    else_=1,
)


class VerdictRequest(BaseModel):
    reason: str = Field(default="", max_length=2000)
    verdict: AnalystVerdict | None = None
    # dismiss only: also allowlist the registrable domain for the brand, so no scan flags it (or a subdomain) again
    whitelist: bool = False
    # suspicious shops only: how sure — suspicious_retailer | likely_counterfeit | confirmed_counterfeit
    # (default: BrandWatch's own reading of the evidence); ``proof`` is required for confirmed_counterfeit
    conclusion: str | None = Field(default=None, pattern="^(suspicious_retailer|likely_counterfeit|confirmed_counterfeit)$")
    proof: str | None = Field(default=None, pattern="^(test_purchase|brand_inspection|platform_confirmation|customer_evidence)$")


class ConclusionRequest(BaseModel):
    level: str = Field(pattern="^(suspicious_retailer|likely_counterfeit|confirmed_counterfeit)$")
    proof: str | None = Field(default=None, pattern="^(test_purchase|brand_inspection|platform_confirmation|customer_evidence)$")
    reason: str = Field(default="", max_length=2000)


def shop_level_view(f: Finding) -> dict[str, Any] | None:
    """A shop finding's conclusion as the UI shows it: the effective level (the analyst's, else
    BrandWatch's), BrandWatch's own reading with its reasons, and the analyst's record."""
    from brandwatch.detection import shop_levels

    if (f.kind or "phishing") != "shop":
        return None
    cur = f.current_score
    rec = dict(((cur.groups or {}).get("_breakdown") or {}).get("shop") or {}) if cur else {}
    system = rec.get("level") if isinstance(rec.get("level"), dict) else {"level": "suspicious_retailer", "because": [], "next": []}
    level = shop_levels.effective_level(f.conclusion, rec)
    return {"level": level, **shop_levels.LEVELS[level], "system": system,
            "system_label": shop_levels.LEVELS.get(system.get("level"), {}).get("label"),
            "conclusion": f.conclusion, "proof_label": shop_levels.PROOFS.get(str((f.conclusion or {}).get("proof")))}  # fmt: skip


def _iso(dt) -> str | None:
    return dt.isoformat() if dt else None


def _artifact_url(ev: Evidence) -> str | None:
    return f"/api/evidence/{ev.id}/artifact" if ev.artifact_location else None


# The reputation feeds shown on a finding, each with a lookup page that works without an account
# (checked in a real browser). URLhaus lists malware only and its browse page sits behind a
# captcha, so it appears only when it actually lists the host, without a link. urlscan lives on the
# intel page (its own tab), not here.
INTEL_LINKS: dict[str, tuple[str, str | None]] = {
    "virustotal": ("VirusTotal", "https://www.virustotal.com/gui/domain/{host}"),
    "safebrowsing": ("Google Safe Browsing", "https://transparencyreport.google.com/safe-browsing/search?url={host}&hl=en"),
    "urlhaus": ("URLhaus", None),
}  # fmt: skip
ONLY_WHEN_LISTED = {"urlhaus"}


SB_THREATS = {"SOCIAL_ENGINEERING": "phishing / social engineering", "MALWARE": "malware",
              "UNWANTED_SOFTWARE": "unwanted software", "POTENTIALLY_HARMFUL_APPLICATION": "harmful app"}  # fmt: skip


def _vt_counts(obs: ReputationObservation) -> tuple[int | None, int | None]:
    """(engines flagging it, engines total) from the VirusTotal v3 payload, else the verdict."""
    raw = obs.raw if isinstance(obs.raw, dict) else {}
    stats = (((raw.get("data") or {}).get("attributes") or {}).get("last_analysis_stats")) or {}
    if stats:
        flagged = int(stats.get("malicious", 0)) + int(stats.get("suspicious", 0))
        return flagged, sum(int(v) for v in stats.values() if isinstance(v, int | float))
    try:
        return int(obs.verdict), None
    except (TypeError, ValueError):
        return None, None


def threat_intel(session: Session, cand: Candidate) -> list[dict[str, Any]]:
    """What the reputation feeds say about the host, with a link to each feed's own page —
    VirusTotal first. Feeds that were not consulted still get their link (open it by hand)."""
    host = cand.hostname
    latest: dict[str, ReputationObservation] = {}
    rows = session.execute(
        sa.select(ReputationObservation)
        .join(Evidence, Evidence.id == ReputationObservation.evidence_id)
        .where(Evidence.candidate_id == cand.id)
        .order_by(Evidence.observed_at.desc())
    ).scalars()
    for obs in rows:
        latest.setdefault(obs.provider, obs)
    out: list[dict[str, Any]] = []
    for provider, (label, tmpl) in INTEL_LINKS.items():
        obs = latest.get(provider)
        if provider in ONLY_WHEN_LISTED and (
            obs is None or obs.status is not ProviderStatus.POSITIVE
        ):
            continue
        entry: dict[str, Any] = {
            "provider": provider, "label": label, "url": tmpl.format(host=host) if tmpl else None,
            "checked": obs is not None, "status": obs.status.value if obs else None,
            "positives": None, "total": None, "summary": "not checked in this scan — look it up",
        }  # fmt: skip
        if obs is not None:
            pos, total = _vt_counts(obs) if provider == "virustotal" else (None, None)
            if provider == "urlhaus":
                urls = (obs.raw or {}).get("urls") if isinstance(obs.raw, dict) else None
                pos = (
                    len(urls)
                    if isinstance(urls, list)
                    else (1 if obs.status is ProviderStatus.POSITIVE else 0)
                )
            if pos is None:
                try:
                    pos = int(obs.verdict)
                except (TypeError, ValueError):
                    pos = None
            entry.update(positives=pos, total=total)
            if provider == "virustotal":
                if pos:
                    entry["summary"] = (
                        f"{pos} of {total} engines flag it" if total else f"{pos} engine(s) flag it"
                    )
                elif obs.status is ProviderStatus.UNKNOWN:
                    entry["summary"] = "not in VirusTotal yet (unknown ≠ clean)"
                else:
                    entry["summary"] = (
                        f"not flagged by any of {total} engines" if total else "not flagged"
                    )
            elif provider == "urlhaus":
                entry["summary"] = f"{pos} malicious URL(s) listed" if pos else "not listed"
            elif provider == "safebrowsing":
                raw = obs.raw if isinstance(obs.raw, dict) else {}
                kinds = sorted(
                    {
                        SB_THREATS.get(m.get("threatType"), str(m.get("threatType")).lower())
                        for m in raw.get("matches") or []
                    }
                )
                entry["summary"] = (f"Google warns users: {', '.join(kinds)}" if obs.status is ProviderStatus.POSITIVE
                                    else "not on Google's list yet — browsers do not warn")  # fmt: skip
            else:
                entry["summary"] = {"positive": "flagged", "negative": "not flagged"}.get(
                    obs.status.value, "unknown"
                )
        out.append(entry)
    return out


def unicode_host(host: str) -> str:
    """xn--shopnov-8fg.com → shopnovа.com (the homoglyph the victim actually sees)."""
    if "xn--" not in host:
        return host
    try:
        return host.encode("ascii").decode("idna")
    except UnicodeError:
        return host


def signal_items(ordered: list[tuple[str, Any]], details: dict[str, Any]) -> list[dict[str, Any]]:
    from brandwatch.api.labels import signal_help, signal_label

    return [
        {"id": k, "label": signal_label(k), "points": v, "group": SIGNAL_GROUPS.get(k, ""),
         "evidence": str(details.get(k) or signal_help(k))}
        for k, v in ordered
    ]  # fmt: skip


def _snooze_iso(f: Finding) -> str | None:
    return f.snoozed_until.isoformat() if getattr(f, "snoozed_until", None) else None


def finding_row(session: Session, f: Finding) -> dict[str, Any]:
    cand = session.get(Candidate, f.candidate_id)
    cur = f.current_score
    sources = session.scalars(
        sa.select(CandidateSource.source).where(CandidateSource.candidate_id == cand.id)
    ).all()
    shot = session.scalars(
        sa.select(Evidence)
        .join(FindingEvidence, FindingEvidence.evidence_id == Evidence.id)
        .where(FindingEvidence.finding_id == f.id, Evidence.type == EvidenceType.SCREENSHOT)
        .order_by(Evidence.observed_at.desc())
    ).first()
    details = (cur.signals or {}).get("_details", {}) if cur else {}
    sig_pts = {k: v for k, v in (cur.signals or {}).items() if not k.startswith("_")} if cur else {}
    ordered = sorted(sig_pts.items(), key=lambda kv: (-float(kv[1] or 0), kv[0]))  # decisive first
    return {
        "id": str(f.id),
        "brand_id": str(f.brand_id),
        "candidate_id": str(f.candidate_id),
        "hostname": cand.hostname,
        "host_display": unicode_host(cand.hostname),
        "is_idn": "xn--" in cand.hostname,
        "signal_items": signal_items(ordered, details),
        "cloaked": any(SIGNAL_GROUPS.get(k) == "evasion" for k in sig_pts),
        "canonical_url": cand.canonical_url,
        "surface": cand.surface.value,
        "sources": [s.value for s in sources],
        "state": f.state.value,
        "severity": f.severity.value,
        "score": cur.score if cur else None,
        "confidence": float(f.confidence) if f.confidence is not None else None,
        "signals": [k for k, _ in ordered],
        "age_days": details.get("age_days"),
        "created_at": _iso(f.created_at),
        "snoozed_until": _snooze_iso(f),
        "updated_at": _iso(f.updated_at),
        "thumbnail_url": _artifact_url(shot) if shot else None,
        "preview_note": None if shot else _no_picture_note(cur.signals if cur else None),
        "analyst_verdict": f.analyst_verdict.value if f.analyst_verdict else None,
        "kind": f.kind or "phishing",
        "shop_level": shop_level_view(f),
        "vt": next(t for t in threat_intel(session, cand) if t["provider"] == "virustotal"),
    }



def _no_picture_note(signals: dict | None) -> str:
    """Why a finding has no screenshot, in a few words, for the list."""
    sig = signals or {}
    if sig.get("_security_warning"):
        return f"{(sig['_security_warning'] or {}).get('vendor') or 'A security service'} shows its phishing warning instead of the site"
    if sig.get("_scanner_block"):
        return "the site refuses automated visitors"
    if sig.get("_no_picture"):
        return "the page is blank"
    if sig.get("_challenge"):
        return "a bot check was shown"
    return "no screenshot (the page did not load)"

SORTS: dict[str, str] = {"severity": "severity, then score", "score": "score", "newest": "newest first", "oldest": "oldest first",
                          "confidence": "confidence"}  # fmt: skip
SINCE: dict[str, str] = {"24h": "last 24 hours", "7d": "last 7 days", "visit": "since my last visit"}
SNOOZE_DAYS = (1, 3, 7, 14, 30)


def findings_query(
    session: Session, user: User, *, brand_id: uuid.UUID | None = None, state: FindingState | None = None,
    severity: Severity | None = None, kind: str | None = None, q: str = "", since: str = "", sort: str = "severity",
    snoozed: bool = False, job_id: uuid.UUID | None = None,
) -> Any:
    """The findings of the workspace, filtered and ordered: the queue the analyst works through. ``q`` is a
    host-name fragment, ``since`` one of SINCE (``visit`` = the user's previous sign-in), ``sort`` one of SORTS."""
    from datetime import UTC, datetime, timedelta

    stmt = (
        sa.select(Finding)
        .join(Brand, Brand.id == Finding.brand_id)
        .join(Candidate, Candidate.id == Finding.candidate_id)
        .outerjoin(RiskScore, sa.and_(RiskScore.finding_id == Finding.id, RiskScore.is_current.is_(True)))
        .where(Brand.workspace_id == user.workspace_id)
    )  # fmt: skip
    if brand_id:
        stmt = stmt.where(Finding.brand_id.in_(regions_mod.with_regions(session, brand_id)))
    if state:
        stmt = stmt.where(Finding.state == state)
    if severity:
        stmt = stmt.where(Finding.severity == severity)
    if kind:
        stmt = stmt.where(Finding.kind == kind)
    if q:
        stmt = stmt.where(Candidate.hostname.ilike(f"%{q.strip().lower()}%"))
    # snoozed: out of the open queue until the date passes; the "snoozed" view shows only them
    now = datetime.now(UTC)
    if snoozed:
        stmt = stmt.where(Finding.snoozed_until.is_not(None), Finding.snoozed_until > now)
    elif state is FindingState.OPEN:
        stmt = stmt.where(sa.or_(Finding.snoozed_until.is_(None), Finding.snoozed_until <= now))
    if job_id:  # what one scan found or re-scored: a score written while it ran
        from brandwatch.db.models import ScanJob

        job = session.get(ScanJob, job_id)
        if job is None or job.workspace_id != user.workspace_id:
            return stmt.where(sa.false())
        start, end = job.started_at or job.created_at, job.finished_at or now
        stmt = stmt.where(Finding.id.in_(sa.select(RiskScore.finding_id).where(RiskScore.created_at >= start, RiskScore.created_at <= end)))
    if since == "24h":
        stmt = stmt.where(Finding.created_at >= datetime.now(UTC) - timedelta(days=1))
    elif since == "7d":
        stmt = stmt.where(Finding.created_at >= datetime.now(UTC) - timedelta(days=7))
    elif since == "visit" and user.previous_login_at is not None:
        stmt = stmt.where(Finding.created_at >= user.previous_login_at)
    order = {
        "score": (RiskScore.score.desc().nulls_last(), _SEV_RANK.desc(), Finding.created_at.desc()),
        "newest": (Finding.created_at.desc(),),
        "oldest": (Finding.created_at.asc(),),
        "confidence": (Finding.confidence.desc().nulls_last(), _SEV_RANK.desc()),
    }.get(sort, (_SEV_RANK.desc(), RiskScore.score.desc().nulls_last(), Finding.created_at.desc()))
    return stmt.order_by(*order)


def count_findings(session: Session, stmt: Any) -> int:
    return int(session.scalar(sa.select(sa.func.count()).select_from(stmt.order_by(None).subquery())) or 0)


@router.get("/findings")
def list_findings(
    session: Annotated[Session, Depends(get_session, scope="function")],
    user: Annotated[User, Depends(current_user)],
    brand_id: uuid.UUID | None = None,
    state: FindingState | None = None,
    severity: Severity | None = None,
    kind: Annotated[str | None, Query(pattern="^(phishing|shop|social|ai_answer)$")] = None,  # None when called directly
    limit: int = Query(default=200, ge=1, le=1000),
    offset: Annotated[int, Query(ge=0)] = 0,  # plain defaults: the page calls this function directly
    q: Annotated[str, Query(max_length=120)] = "",
    since: Annotated[str, Query(pattern="^(|24h|7d|visit)$")] = "",
    sort: Annotated[str, Query(pattern="^(severity|score|newest|oldest|confidence)$")] = "severity",
) -> list[dict[str, Any]]:
    stmt = findings_query(session, user, brand_id=brand_id, state=state, severity=severity, kind=kind, q=q, since=since, sort=sort)
    return [finding_row(session, f) for f in session.scalars(stmt.limit(limit).offset(offset)).all()]


def neighbours(session: Session, user: User, finding: Finding) -> dict[str, str | None]:
    """The open finding before and after this one in the queue's default order (severity, score, newest) — for the
    previous / next links and for "open the next one after a verdict"; same brand family as the finding."""
    rows = session.scalars(findings_query(session, user, brand_id=finding.brand_id, state=FindingState.OPEN)).all()
    ids = [f.id for f in rows]
    if finding.id not in ids:  # the finding is no longer open: the next one is the first open one
        return {"prev": None, "next": str(ids[0]) if ids else None, "open_count": len(ids)}
    i = ids.index(finding.id)
    return {"prev": str(ids[i - 1]) if i > 0 else None, "next": str(ids[i + 1]) if i + 1 < len(ids) else None, "open_count": len(ids)}


def _get_finding(session: Session, user: User, finding_id: uuid.UUID) -> Finding:
    f = session.get(Finding, finding_id)
    if f is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "finding not found")
    brand = session.get(Brand, f.brand_id)
    if brand is None or brand.workspace_id != user.workspace_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "finding not found")
    return f


def _trace_job(session: Session, f: Finding, cur: Any) -> str | None:
    """The scan that produced the current score (newest scan of the brand started before it)."""
    from brandwatch.db.models import ScanJob

    if cur is None:
        return None
    job = session.scalars(
        sa.select(ScanJob)
        .where(ScanJob.brand_id == f.brand_id, ScanJob.kind.in_(["brand_scan", "url_scan"]),
               ScanJob.created_at <= cur.created_at)
        .order_by(ScanJob.created_at.desc())
        .limit(1)
    ).first()  # fmt: skip
    return str(job.id) if job else None


def _redirect_links(session: Session, cand: Candidate, came_from: dict[str, Any] | None) -> dict[str, Any]:
    """The redirect, both ways: the flagged look-alike that sends its visitors to this site, and where this site sends its
    own (with the finding of that address, when it has one)."""
    from brandwatch.detection.discovery import split_host

    out: dict[str, Any] = {"from": None, "to": None, "chain": []}
    if came_from and came_from.get("finding_id"):
        out["from"] = {"host": came_from.get("host"), "severity": str(came_from.get("severity") or "high"),
                       "finding_id": came_from["finding_id"]}  # fmt: skip
    ev = session.scalars(
        sa.select(Evidence)
        .where(Evidence.candidate_id == cand.id, Evidence.type == EvidenceType.HTTP, Evidence.source_type == "http")
        .order_by(Evidence.observed_at.desc())
    ).first()  # fmt: skip
    final = str((ev.response_meta or {}).get("final_url") or "") if ev else ""
    out["chain"] = [str(u) for u in ((ev.response_meta or {}).get("redirect_chain") or [])] if ev else []
    host = (urlsplit(final).hostname or "").lower().rstrip(".") if "://" in final else ""
    if host and split_host(host).registrable != split_host(cand.hostname).registrable:
        reg = split_host(host).registrable
        target = session.scalars(
            sa.select(Candidate).where(Candidate.brand_id == cand.brand_id, Candidate.hostname.in_([host, reg]))
        ).first()
        tf = session.scalars(sa.select(Finding).where(Finding.candidate_id == target.id)).first() if target else None
        out["to"] = {"host": host, "url": final, "finding_id": str(tf.id) if tf else None,
                     "severity": tf.severity.value if tf else None}  # fmt: skip
    return out


def _confirmed_twin(session: Session, f: Finding) -> dict[str, Any] | None:
    """An OPEN finding whose site already has a CONFIRMED finding (data from before
    one-finding-per-site): the page links to the confirmed one instead of asking for a verdict."""
    if f.state is not FindingState.OPEN:
        return None
    twin = session.scalars(
        sa.select(Finding)
        .where(Finding.candidate_id == f.candidate_id, Finding.state == FindingState.CONFIRMED, Finding.id != f.id)
        .order_by(Finding.updated_at.desc())
    ).first()  # fmt: skip
    if twin is None:
        return None
    return {"id": str(twin.id), "confirmed_at": _iso(twin.updated_at)}


_AGE_RE = re.compile(r"registered (\d+) day")


def explain_shop_sentence(shop: dict[str, Any], brand: str, host: str) -> str:
    """A suspicious shop in two or three plain sentences, from the shop record."""
    facts, why = shop.get("facts") or {}, shop.get("why") or {}
    tld = host.rsplit(".", 1)[-1]
    lang = {"he": "Hebrew", "en": "English", "es": "Spanish", "fr": "French", "de": "German", "ar": "Arabic",
            "ru": "Russian", "it": "Italian", "pt": "Portuguese", "nl": "Dutch", "pl": "Polish", "tr": "Turkish"}.get(facts.get("lang") or "", "")  # fmt: skip
    pages = sorted({a.get("page_name") for a in shop.get("ads") or [] if a.get("page_name")})
    first = f"A .{tld} shop" + (
        f" in {lang}" if lang and "shop_tld_language_mismatch" in why else ""
    )
    named = " — a page named after the brand that is not the brand's own" if "shop_ad_page_uses_brand" in why else ""
    first += (f" advertising {brand} products on Facebook / Instagram (page “{pages[0]}”{named})" if pages
              else f" selling {brand} products")  # fmt: skip
    price = shop.get("price") or {}
    if "shop_price_far_below_official" in why and price.get("offer") and price.get("reference"):
        o, r = price["offer"], price["reference"]
        first += (f" at {o['unit']:.0f} {o['currency']} per item — {price['ratio']:.0%} of the official "
                  f"{r['price']:.0f} {r['currency']}")  # fmt: skip
    out = [first + "."]
    contact = []
    if "shop_free_email_only" in why and facts.get("free_emails"):
        contact.append(
            f"its only e-mail is {facts['free_emails'][0].split('@')[1].split('.')[0].title()} ({facts['free_emails'][0]})"
        )
    elif "shop_chat_or_phone_only" in why:
        contact.append("it can only be reached on WhatsApp or by phone")
    if "shop_no_policy_pages" in why:
        contact.append("it has no privacy policy, terms or returns page")
    reg = shop.get("registry") or {}
    if "shop_company_not_in_registry" in why:
        contact.append(
            f"company number {reg.get('number')} does not exist in {reg.get('registry') or 'the registry'}"
        )
    elif "shop_company_dissolved" in why:
        contact.append(f"the company it names is dissolved ({reg.get('registry')})")
    elif "shop_no_company_details" in why:
        contact.append("it names no company at all")
    if contact:
        s = ", ".join(contact[:-1]) + (" and " if len(contact) > 1 else "") + contact[-1]
        out.append(s[0].upper() + s[1:] + ".")
    extra = []
    if "shop_brand_catalog" in why:
        m = re.search(r"lists (\d+) of", why["shop_brand_catalog"])
        extra.append(f"its menu is built around {m.group(1) if m else 'several'} {brand} product lines")
    if "shop_deep_discounts" in why:
        extra.append("it marks items down by half or more from an invented regular price")
    if extra:
        s2 = " and ".join(extra)
        out.append(s2[0].upper() + s2[1:] + ".")
    if "shop_reviews_warn" in why:
        out.append("Search results about it mention scams or replica products.")
    elif "shop_no_web_presence" in why:
        out.append("Google knows nothing about the business outside the shop itself.")
    for k in ("shop_new_domain", "shop_young_domain"):
        m = re.search(r"(\d+) day", why.get(k) or "")
        if m:
            out.insert(0, f"Registered {m.group(1)} days ago.")
            break
    return " ".join(out)


def explain_ai_sentence(rec: dict[str, Any], brand: str) -> str:
    """One plain sentence about an AI-answer finding: who said what, and what the pages say."""
    from brandwatch.detection.ai_answers import ENGINE_LABEL
    from brandwatch.detection.contacts import KIND_LABEL

    who = ", ".join(ENGINE_LABEL.get(e, e) for e in rec.get("engines") or []) or "An AI assistant"
    what = KIND_LABEL.get(rec.get("kind"), "contact")
    v = rec.get("verdict")
    if v == "url_not_official":
        return f"{who} sends users who ask about {brand} to {rec.get('display')}, which is not one of {brand}'s sites."
    hosts = list(dict.fromkeys([c["host"] for c in rec.get("checks") or [] if c.get("found") and not c.get("official")]
                               + [h["host"] for h in rec.get("hunt") or [] if not h.get("official")]))  # fmt: skip
    if v == "offsite":
        return (f"{who} gives {rec.get('display')} as {brand}'s {what}. No page of {brand} publishes it; "
                f"{', '.join(hosts[:3])} does — callers reach whoever runs that page.")
    took_back = any(fu.get("retracted") for fu in rec.get("followups") or [])
    return (f"{who} gives {rec.get('display')} as {brand}'s {what}, but no page publishes it"
            + (" — asked for the proof, it took it back" if took_back else "") + ". A made-up contact can be claimed by a scammer.")


def explain_social_sentence(rec: dict[str, Any], brand: str) -> str:
    """A fake social account in two or three plain sentences, from its record."""
    why = rec.get("why") or {}
    kind = "Facebook page" if rec.get("platform") == "facebook" else "Instagram account"
    first = f"A {kind} named “{rec.get('name') or rec.get('handle')}”"
    facts = []
    m = re.search(r"(\d+) day", why.get("social_new_account") or "")
    if m:
        facts.append(f"created {m.group(1)} days ago")
    if "social_renamed" in why:
        facts.append("renamed since")
    m = re.search(r"run from ([A-Z, ]+?) —", why.get("social_admins_abroad") or "")
    if m:
        facts.append(f"run from {m.group(1).strip()}")
    out = [first + (", " + ", ".join(facts) if facts else "") + "."]
    acts = []
    if "social_logo_match" in why:
        acts.append(f"uses the {brand} logo")
    if "social_claims_official" in why:
        acts.append(f"presents itself as {brand}'s own account")
    m = re.search(r"sends people to (\S+)", why.get("social_links_off_brand") or "")
    if m:
        acts.append(f"sends people to {m.group(1)}")
    if "social_scam_lures" in why:
        acts.append("asks for payments, card or order details")
    if acts:
        s = ", ".join(acts[:-1]) + (" and " if len(acts) > 1 else "") + acts[-1]
        out.append("It " + s + ".")
    ai = rec.get("ai") or {}
    if ai.get("summary") and ai.get("verdict") not in (None, "unclear"):
        out.append(f"The AI read its content: {ai['summary']}")
    return " ".join(out)


def explain_sentence(signals: dict[str, Any], details: dict[str, Any], brand: str) -> str:
    """Two plain sentences an interviewer can read without knowing any signal name."""
    has = signals.__contains__
    out: list[str] = []
    m = _AGE_RE.search(str(details.get("age_lt_7d") or details.get("age_lt_30d") or ""))
    if m:
        days = int(m.group(1))
        out.append(f"Registered {days} day{'s' if days != 1 else ''} ago.")
    acts: list[str] = []
    if has("brand_tld_swap"):
        acts.append(f"uses the {brand} name on another top-level domain")
    elif has("homoglyph_idn"):
        acts.append(f"spells {brand} with look-alike characters")
    elif has("levenshtein_le_2"):
        acts.append(f"is one or two typos away from {brand}")
    elif has("brand_exact_in_domain") or has("combosquat") or has("brand_in_subdomain"):
        acts.append(f"puts the {brand} name in its address")
    copied = [w for w, sigs in (("favicon", ("favicon_exact",)), ("homepage", ("screenshot_similarity_ge_90", "looks_like_brand_ge_85")),
                                ("logo", ("logo_detected",)), ("login form", ("login_dom_similarity",))) if any(has(s) for s in sigs)]  # fmt: skip
    if copied:
        acts.append(
            f"copies {brand}'s {' and '.join(copied[:2]) if len(copied) <= 2 else ', '.join(copied[:-1]) + ' and ' + copied[-1]}"
        )
    asks = [w for w, sig in (("a password", "credential_form"), ("card details", "payment_form"),
                             ("a wallet seed phrase", "seed_phrase_field")) if has(sig)]  # fmt: skip
    if asks:
        acts.append("asks for " + " and ".join(asks))
    if has("external_form_action"):
        acts.append("sends what you type to another server")
    if acts:
        s = ", ".join(acts[:-1]) + (" and " if len(acts) > 1 else "") + acts[-1]
        out.append(s[0].upper() + s[1:] + ".")
    if has("cloaking_ip_based") or has("cloaking_ua_based"):
        out.append(
            "It hides from security scanners: the real page only appears to a normal visitor (home IP / browser)."
        )
    elif has("parameter_gating") or has("referer_gating"):
        out.append(
            "It only opens for visitors arriving from the phishing link, so a plain scanner sees nothing."
        )
    if has("linked_to_known_campaign") or has("cohosted_with_known_phish"):
        out.append("It shares infrastructure with phishing BrandWatch already mapped.")
    if has("cloudflare_phishing_warning"):
        out.append("Cloudflare, which serves the site, already blocks it with its own “Suspected Phishing” warning"
                   + (", and VirusTotal engines flag it." if has("vt_flagged") else "."))  # fmt: skip
    elif has("vt_flagged") and not acts:
        out.append("Security vendors on VirusTotal flag it as malicious.")
    return " ".join(out) or "Only weak evidence so far: see the signals below."


def finding_detail(session: Session, f: Finding) -> dict[str, Any]:
    cand = session.get(Candidate, f.candidate_id)
    brand = session.get(Brand, f.brand_id)
    cur = f.current_score
    signals_raw = dict(cur.signals or {}) if cur else {}
    groups_raw = dict(cur.groups or {}) if cur else {}
    details = signals_raw.pop("_details", {})
    unavailable = signals_raw.pop("_unavailable", [])
    fp_flags = signals_raw.pop("_fp_flags", [])
    scanner_block = signals_raw.pop("_scanner_block", None)
    snapshot = signals_raw.pop("_snapshot", None)
    security_warning = signals_raw.pop("_security_warning", None)
    challenge = signals_raw.pop("_challenge", None)
    redirected_from = signals_raw.pop("_redirected_from", None)
    clickfix = signals_raw.pop("_clickfix", None)
    no_picture = signals_raw.pop("_no_picture", None)
    breakdown = groups_raw.pop("_breakdown", {})
    group_detail = breakdown.get("group_detail", {})

    from brandwatch.detection.ai_answers import AI_GROUPS
    from brandwatch.detection.merchant import SHOP_GROUPS
    from brandwatch.detection.social import SOCIAL_GROUPS

    signals = sorted(
        (
            {
                "name": k,
                "group": SIGNAL_GROUPS.get(k) or SHOP_GROUPS.get(k) or SOCIAL_GROUPS.get(k) or AI_GROUPS.get(k, "?"),
                "points": v,
                "detail": details.get(k, ""),
            }
            for k, v in signals_raw.items()
        ),
        key=lambda s: (-s["points"], s["name"]),
    )
    groups = [
        {
            "name": g,
            "total": gd.get("total", 0),
            "cap": gd.get("cap", 0),
            "capped": gd.get("capped", 0),
            "counted": min(gd.get("total", 0) or 0, gd.get("cap", 0) or 0)
            if gd.get("cap")
            else gd.get("total", 0),
        }
        for g, gd in group_detail.items()
    ] or [{"name": g, "total": v, "cap": None, "capped": v} for g, v in groups_raw.items()]

    links = session.execute(
        sa.select(FindingEvidence.role, Evidence)
        .join(Evidence, Evidence.id == FindingEvidence.evidence_id)
        .where(FindingEvidence.finding_id == f.id)
        .order_by(Evidence.observed_at)
    ).all()
    evidence = []
    suspect_shot: Evidence | None = None
    suspect_phash: str | None = None
    scanner_shot: Evidence | None = None  # what a datacenter scanner was shown (cloaked kits)
    for role, ev in links:
        meta = dict(ev.response_meta or {})
        if ev.type is EvidenceType.SCREENSHOT and ev.source_type != "challenge_screenshot" and not meta.get("blank"):  # a bot check, or a white page, is not the site
            if (ev.request_profile or {}).get("profile") == "datacenter":
                scanner_shot = ev
            suspect_shot = ev
            sc = session.get(Screenshot, ev.id)
            suspect_phash = sc.phash if sc else meta.get("phash")
        evidence.append(
            {
                "id": str(ev.id),
                "type": ev.type.value,
                "role": role.value,
                "observed_at": _iso(ev.observed_at),
                "source": ev.source,
                "source_type": ev.source_type,
                "collector": f"{ev.collector}@{ev.collector_version}",
                "sha256": ev.content_sha256,
                "artifact_url": _artifact_url(ev),
                "parent_id": str(ev.parent_evidence_id) if ev.parent_evidence_id else None,
                "meta": meta,
            }
        )

    fp = session.scalars(
        sa.select(BrandFingerprint)
        .where(BrandFingerprint.brand_id == brand.id)
        .order_by(BrandFingerprint.version.desc())
    ).first()
    baseline_phash = ((fp.screenshots or {}).get("home") or {}).get("phash") if fp else None
    similarity = (
        round(images.similarity(suspect_phash, baseline_phash) * 100)
        if suspect_phash and baseline_phash
        else None
    )

    observations = session.scalars(
        sa.select(Observation)
        .where(Observation.candidate_id == cand.id)
        .order_by(Observation.observed_at)
    ).all()
    history = session.scalars(
        sa.select(RiskScore).where(RiskScore.finding_id == f.id).order_by(RiskScore.created_at)
    ).all()
    sources = session.scalars(
        sa.select(CandidateSource).where(CandidateSource.candidate_id == cand.id)
    ).all()

    return {
        "finding": {
            "id": str(f.id),
            "state": f.state.value,
            "severity": f.severity.value,
            "confidence": float(f.confidence) if f.confidence is not None else None,
            "analyst_verdict": f.analyst_verdict.value if f.analyst_verdict else None,
            "kind": f.kind or "phishing",
            "shop_level": shop_level_view(f),
            "created_at": _iso(f.created_at),
            "updated_at": _iso(f.updated_at),
        },
        "candidate": {
            "id": str(cand.id),
            "hostname": cand.hostname,
            "host_display": unicode_host(cand.hostname),
            "canonical_url": cand.canonical_url,
            "canonical_domain": cand.canonical_domain,
            "surface": cand.surface.value,
            "state": cand.state.value,
            "first_seen": _iso(cand.first_seen),
            "last_seen": _iso(cand.last_seen),
            "next_scan_at": _iso(cand.next_scan_at),
            "scan_count": cand.scan_count,
            "sources": [
                {
                    "source": s.source.value,
                    "pattern": s.matched_pattern,
                    "found_at": _iso(s.found_at),
                }
                for s in sources
            ],
        },
        "brand": {"id": str(brand.id), "name": brand.name},
        "score": None
        if cur is None
        else {
            "score": cur.score,
            "raw": cur.raw_score,
            "raw_max": breakdown.get("raw_max"),
            "severity": cur.severity.value,
            "confidence": float(cur.confidence),
            "scoring_version": cur.scoring_version,
            "created_at": _iso(cur.created_at),
            "signals": signals,
            "summary": explain_shop_sentence(breakdown["shop"], brand.name, cand.hostname)
            if f.kind == "shop" and breakdown.get("shop")
            else explain_social_sentence(breakdown["social"], brand.name)
            if f.kind == "social" and breakdown.get("social")
            else explain_ai_sentence(breakdown["ai_answer"], brand.name)
            if f.kind == "ai_answer" and breakdown.get("ai_answer")
            else explain_sentence(
                signals_raw, details if isinstance(details, dict) else {}, brand.name
            ),
            "shop": breakdown.get("shop"),
            "ads": breakdown.get("ads"),  # a phishing site's own ads (a brand nobody else sells)
            "social": breakdown.get("social"),
            "ai_answer": breakdown.get("ai_answer"),
            "phishing": breakdown.get("phishing"),
            "cloaked": any(SIGNAL_GROUPS.get(k) == "evasion" for k in signals_raw),
            "age_days": int(m.group(1))
            if (
                m := _AGE_RE.search(
                    str((details or {}).get("age_lt_7d") or (details or {}).get("age_lt_30d") or "")
                )
            )
            else None,
            "trace_job_id": _trace_job(session, f, cur),
            "groups": groups,
            "bonuses": breakdown.get("bonuses", []),
            "penalties": breakdown.get("penalties", []),
            "rules_fired": breakdown.get("combination_rules_fired", []),
            "thresholds": breakdown.get("thresholds"),
            "confidence_breakdown": breakdown.get("confidence", {}),
            "unavailable": unavailable,
            "fp_flags": fp_flags,
            "not_evaluated_groups": details.get("not_evaluated_groups", [])
            if isinstance(details, dict)
            else [],
            "reputation": details.get("reputation", {}) if isinstance(details, dict) else {},
            "provider_notes": details.get("provider_notes", {})
            if isinstance(details, dict)
            else {},
            "ai": breakdown.get("ai"),
            "ml": breakdown.get("ml"),
            "cloaking": breakdown.get("cloaking"),
            "scanner_block": scanner_block,
            "snapshot": snapshot,
            "security_warning": security_warning,
            "clickfix": clickfix,
            "no_picture": no_picture,
            "challenge": {**challenge, "screenshot_url": f"/api/evidence/{challenge['screenshot_evidence_id']}/artifact"
                          if challenge.get("screenshot_evidence_id") else None} if challenge else None,
        },
        "threat_intel": threat_intel(session, cand),
        "evidence": evidence,
        "screenshots": {
            "suspect_url": _artifact_url(suspect_shot) if suspect_shot else None,
            "scanner_url": _artifact_url(scanner_shot)
            if scanner_shot is not None
            and suspect_shot is not None
            and scanner_shot.id != suspect_shot.id
            and (suspect_shot.request_profile or {}).get("profile") != "datacenter"
            else None,
            "baseline_url": f"/api/brands/{brand.id}/baseline/screenshot"
            if baseline_phash
            else None,
            "similarity_pct": similarity,
        },
        "observations": [
            {
                "observed_at": _iso(o.observed_at),
                "http_status": o.http_status,
                "content_hash": o.content_hash,
                "changed": o.changed,
                "state_at_time": o.state_at_time.value,
                "scanner_profile": o.scanner_profile.value,
                "screenshot_url": f"/api/evidence/{o.screenshot_evidence_id}/artifact"
                if o.screenshot_evidence_id
                else None,
            }
            for o in observations
        ],
        "campaign_id": str(f.campaign_id) if f.campaign_id else None,
        "confirmed_twin": _confirmed_twin(session, f),
        "redirect": _redirect_links(session, cand, redirected_from),
        "score_history": [
            {
                "created_at": _iso(r.created_at),
                "score": r.score,
                "severity": r.severity.value,
                "confidence": float(r.confidence),
                "scoring_version": r.scoring_version,
                "is_current": r.is_current,
            }
            for r in history
        ],  # fmt: skip
    }


@router.get("/findings/{finding_id}")
def get_finding(
    finding_id: uuid.UUID,
    session: Annotated[Session, Depends(get_session, scope="function")],
    user: Annotated[User, Depends(current_user)],
) -> dict[str, Any]:
    return finding_detail(session, _get_finding(session, user, finding_id))


@router.post("/findings/{finding_id}/confirm")
def confirm_finding(
    finding_id: uuid.UUID,
    body: VerdictRequest,
    request: Request,
    session: Annotated[Session, Depends(get_session, scope="function")],
    user: Annotated[User, Depends(require_analyst)],
) -> dict[str, Any]:
    f = _get_finding(session, user, finding_id)
    if f.state is not FindingState.OPEN:
        raise HTTPException(status.HTTP_409_CONFLICT, f"finding is already {f.state.value}")
    try:
        finding_stage.confirm(session, f, user, reason=body.reason, conclusion=body.conclusion, proof=body.proof)
    except ValueError as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, str(exc)) from exc
    out = finding_row(session, f)
    out["map_job_id"] = None
    out["intel_job_id"] = None
    # the brand decides whether a confirmation also maps the attacker's infrastructure right away, and investigates the site
    # and its network (the quick lookup) and builds the evidence package: the confirmed site is complete without opening it
    from brandwatch.api.campaigns import start_map_job
    from brandwatch.api.intel import start_intel_job
    from brandwatch.detection.runner import load_brand_config

    det = load_brand_config(session, f.brand_id).detection
    plans: list[tuple[str, dict[str, Any]]] = []
    if (f.kind or "phishing") == "ai_answer":  # a contact, not a site: there is no server to map or investigate
        return out
    if det.auto_map_on_confirm:
        plans.append(("map_job_id", start_map_job(session, request, user, f, auto=True, defer=True)))
    if det.auto_investigate_on_confirm:
        plans.append(("intel_job_id", start_intel_job(session, request, user, f, light=True, package=True, auto=True, defer=True)))
    if plans:
        session.commit()  # everything the request writes, once; the jobs are started after it (they write at once)
        for key, plan in plans:
            out[key] = (plan["defer"]() if "defer" in plan else plan)["job_id"]
    return out


@router.post("/findings/{finding_id}/conclusion")
def update_conclusion(
    finding_id: uuid.UUID,
    body: ConclusionRequest,
    session: Annotated[Session, Depends(get_session, scope="function")],
    user: Annotated[User, Depends(require_analyst)],
) -> dict[str, Any]:
    """Change a confirmed shop's conclusion (e.g. to "confirmed counterfeit" after a test purchase).
    The takedown subject follows at once; a drafted letter can be rewritten from the takedown page."""
    f = _get_finding(session, user, finding_id)
    if (f.kind or "phishing") != "shop" or f.state is not FindingState.CONFIRMED:
        raise HTTPException(status.HTTP_409_CONFLICT, "only a confirmed suspicious-shop finding has a conclusion to change")
    try:
        finding_stage.set_conclusion(session, f, user, level=body.level, proof=body.proof, reason=body.reason)
    except ValueError as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, str(exc)) from exc
    return finding_row(session, f)


@router.post("/findings/{finding_id}/official-account")
def official_account(
    finding_id: uuid.UUID,
    session: Annotated[Session, Depends(get_session, scope="function")],
    user: Annotated[User, Depends(require_analyst)],
) -> dict[str, Any]:
    """"This is our account": the Facebook page / Instagram profile (and its linked account) join
    the brand's official accounts, the finding closes, and the next scans skip them."""
    from brandwatch.db.models import AuditEvent
    from brandwatch.detection.takedown_channels import social_record_of

    f = _get_finding(session, user, finding_id)
    rec = social_record_of(session, f)
    if (f.kind or "phishing") != "social" or not rec:
        raise HTTPException(status.HTTP_409_CONFLICT, "only a social-account finding can be marked as the brand's own account")
    brand = session.get(Brand, f.brand_id)
    keys = [f"{rec['platform']}:{str(rec['handle']).lower()}"]
    if (rec.get("ig") or {}).get("username") and rec["platform"] == "facebook":
        keys.append(f"instagram:{str(rec['ig']['username']).lower()}")
    profile = dict(brand.profile or {})
    have = list(profile.get("official_social") or [])
    profile["official_social"] = have + [k for k in keys if k not in have]
    brand.profile = profile
    session.add(AuditEvent(workspace_id=user.workspace_id, actor_type="analyst", actor_id=user.id,
                           action="brand.official_account_added", object_type="brand", object_id=brand.id,
                           old_value={"official_social": have}, new_value={"official_social": profile["official_social"]},
                           reason=f"marked from finding {f.id}"))  # fmt: skip
    if f.state is FindingState.OPEN:
        finding_stage.dismiss(session, f, user, reason="the brand's own account", verdict=AnalystVerdict.LEGITIMATE)
    session.flush()
    return {"official_social": profile["official_social"], "state": f.state.value}


@router.post("/findings/{finding_id}/our-contact")
def our_contact(
    finding_id: uuid.UUID,
    session: Annotated[Session, Depends(get_session, scope="function")],
    user: Annotated[User, Depends(require_analyst)],
) -> dict[str, Any]:
    """"This is our contact": the phone / e-mail an AI gave is the brand's after all (an SMS line, a new number the site
    does not show yet). It joins the brand's known contacts, the finding closes, and later runs never raise it again."""
    from brandwatch.db.models import AuditEvent
    from brandwatch.db.types import utcnow
    from brandwatch.detection.ai_answers import ai_record_of

    f = _get_finding(session, user, finding_id)
    rec = ai_record_of(f)
    if (f.kind or "phishing") != "ai_answer" or not rec:
        raise HTTPException(status.HTTP_409_CONFLICT, "only an AI-answer finding can be marked as the brand's own contact")
    if rec.get("kind") == "url":
        raise HTTPException(status.HTTP_409_CONFLICT, "a web address is made official on the brand page (Links on the official site / Edit brand)")
    brand = session.get(Brand, f.brand_id)
    profile = dict(brand.profile or {})
    have = list(profile.get("known_contacts") or [])
    if not any((r.get("value") if isinstance(r, dict) else r) == rec["display"] for r in have):
        have.append({"value": rec["display"], "note": f"marked from an AI-answer finding {f.id}", "by": user.email, "at": _iso(utcnow())})
    profile["known_contacts"] = have
    brand.profile = profile
    session.add(AuditEvent(workspace_id=user.workspace_id, actor_type="analyst", actor_id=user.id,
                           action="brand.known_contact_add", object_type="brand", object_id=brand.id,
                           new_value={"value": rec["display"]}, reason=f"marked from finding {f.id}"))  # fmt: skip
    if f.state is FindingState.OPEN:
        finding_stage.dismiss(session, f, user, reason="the brand's own contact", verdict=AnalystVerdict.LEGITIMATE)
    session.flush()
    return {"known_contacts": have, "state": f.state.value}


class BulkVerdictRequest(BaseModel):
    ids: list[uuid.UUID] = Field(min_length=1, max_length=500)
    action: str = Field(pattern="^(confirm|dismiss)$")
    reason: str = Field(default="", max_length=2000)
    verdict: AnalystVerdict | None = None  # dismiss: legitimate by default
    whitelist: bool = False  # dismiss: also allowlist each finding's registrable domain


def allowlist_domain(session: Session, finding: Finding) -> str | None:
    """Allowlist the finding's registrable domain for its brand (kind ``known_legit``), as the watchlist's
    "Known legit" does; returns the domain added, or None when it was already there / is official."""
    from brandwatch.db.models import BrandDomain
    from brandwatch.detection.normalize import protected_root

    cand = session.get(Candidate, finding.candidate_id)
    if cand is None:
        return None
    reg = protected_root(cand.hostname)
    existing = session.scalars(sa.select(BrandDomain).where(BrandDomain.brand_id == finding.brand_id, BrandDomain.domain == reg)).first()
    if existing is not None:
        return None
    session.add(BrandDomain(brand_id=finding.brand_id, domain=reg, is_official=False, kind="known_legit"))
    return reg


def bulk_verdict(session: Session, user: User, body: BulkVerdictRequest) -> dict[str, Any]:
    """One verdict for many findings at once (the analyst ticked them in the list). Only open findings change; a confirmation here starts
    no mapping or investigation per site (that would be dozens of jobs at once): MAP ALL and INVESTIGATE ALL do that, one after the other."""
    done: list[str] = []
    skipped: list[dict[str, str]] = []
    for fid in dict.fromkeys(body.ids):
        try:
            f = _get_finding(session, user, fid)
        except HTTPException:
            skipped.append({"id": str(fid), "why": "not found"})
            continue
        host = session.get(Candidate, f.candidate_id).hostname
        if f.state is not FindingState.OPEN:
            skipped.append({"id": str(fid), "host": host, "why": f"already {f.state.value}"})
            continue
        try:
            if body.action == "confirm":
                finding_stage.confirm(session, f, user, reason=body.reason or "confirmed in bulk from the findings list")
            else:
                finding_stage.dismiss(session, f, user, reason=body.reason or "dismissed in bulk from the findings list",
                                      verdict=body.verdict or AnalystVerdict.LEGITIMATE)  # fmt: skip
                if body.whitelist:
                    allowlist_domain(session, f)
        except ValueError as exc:
            skipped.append({"id": str(fid), "host": host, "why": str(exc)})
            continue
        done.append(host)
    session.flush()
    return {"action": body.action, "changed": len(done), "hosts": done, "skipped": skipped}


class SnoozeRequest(BaseModel):
    days: int = Field(ge=0, le=90)  # 0 = wake it now
    reason: str = Field(default="", max_length=2000)


@router.post("/findings/{finding_id}/snooze")
def snooze_finding(
    finding_id: uuid.UUID, body: SnoozeRequest,
    session: Annotated[Session, Depends(get_session, scope="function")], user: Annotated[User, Depends(require_analyst)],
) -> dict[str, Any]:  # fmt: skip
    """Out of the open queue for N days ("waiting for the registrar", "parked: look again next week"); 0 wakes it now."""
    from datetime import UTC, datetime, timedelta

    from brandwatch.api.auth import audit

    f = _get_finding(session, user, finding_id)
    if f.state is not FindingState.OPEN:
        raise HTTPException(status.HTTP_409_CONFLICT, "only an open finding can be snoozed")
    old = f.snoozed_until
    f.snoozed_until = (datetime.now(UTC) + timedelta(days=body.days)) if body.days else None
    audit(session, workspace_id=user.workspace_id, actor_type="analyst", actor_id=user.id,
          action="finding.snoozed" if body.days else "finding.woken", object_type="finding", object_id=f.id,
          old={"snoozed_until": old.isoformat() if old else None}, new={"snoozed_until": f.snoozed_until.isoformat() if f.snoozed_until else None},
          reason=body.reason or None)  # fmt: skip
    session.flush()
    return {"id": str(f.id), "snoozed_until": f.snoozed_until.isoformat() if f.snoozed_until else None}


class NoteRequest(BaseModel):
    text: str = Field(min_length=1, max_length=4000)


@router.post("/findings/{finding_id}/notes", status_code=status.HTTP_201_CREATED)
def add_note(
    finding_id: uuid.UUID, body: NoteRequest,
    session: Annotated[Session, Depends(get_session, scope="function")], user: Annotated[User, Depends(require_analyst)],
) -> dict[str, Any]:  # fmt: skip
    """A working note on a finding (kept, never edited; also in Activity)."""
    from brandwatch.api.auth import audit
    from brandwatch.db.models import FindingNote

    f = _get_finding(session, user, finding_id)
    note = FindingNote(finding_id=f.id, author_id=user.id, text=body.text.strip())
    session.add(note)
    session.flush()
    audit(session, workspace_id=user.workspace_id, actor_type="analyst", actor_id=user.id, action="finding.note_added",
          object_type="finding", object_id=f.id, new={"note": note.text[:300]})  # fmt: skip
    return {"id": str(note.id), "text": note.text, "created_at": note.created_at.isoformat() if note.created_at else None}


def list_notes(session: Session, finding_id: uuid.UUID) -> list[dict[str, Any]]:
    from brandwatch.db.models import FindingNote

    emails = dict(session.execute(sa.select(User.id, User.email)).all())
    return [{"id": str(n.id), "text": n.text, "by": emails.get(n.author_id) or "—", "at": n.created_at.isoformat() if n.created_at else None}
            for n in session.scalars(sa.select(FindingNote).where(FindingNote.finding_id == finding_id).order_by(FindingNote.created_at.desc())).all()]  # fmt: skip


@router.post("/findings/{finding_id}/reopen")
def reopen_finding(
    finding_id: uuid.UUID,
    session: Annotated[Session, Depends(get_session, scope="function")],
    user: Annotated[User, Depends(require_analyst)],
    body: VerdictRequest | None = None,
) -> dict[str, Any]:
    """Undo a verdict: the finding waits for a verdict again (audited; the old verdict stays in the log)."""
    f = _get_finding(session, user, finding_id)
    try:
        finding_stage.reopen(session, f, user, reason=(body.reason if body else ""))
    except ValueError as exc:
        raise HTTPException(status.HTTP_409_CONFLICT, str(exc)) from exc
    return finding_row(session, f)


@router.post("/findings/bulk")
def bulk_verdict_api(
    body: BulkVerdictRequest,
    session: Annotated[Session, Depends(get_session, scope="function")],
    user: Annotated[User, Depends(require_analyst)],
) -> dict[str, Any]:
    return bulk_verdict(session, user, body)


@router.post("/findings/{finding_id}/dismiss")
def dismiss_finding(
    finding_id: uuid.UUID,
    body: VerdictRequest,
    session: Annotated[Session, Depends(get_session, scope="function")],
    user: Annotated[User, Depends(require_analyst)],
) -> dict[str, Any]:
    f = _get_finding(session, user, finding_id)
    try:
        finding_stage.dismiss(
            session, f, user, reason=body.reason, verdict=body.verdict or AnalystVerdict.LEGITIMATE
        )
    except ValueError as exc:
        raise HTTPException(status.HTTP_409_CONFLICT, str(exc)) from exc
    out = finding_row(session, f)
    out["whitelisted"] = allowlist_domain(session, f) if body.whitelist else None
    return out


def candidates_query(session: Session, user: User, *, brand_id: uuid.UUID | None = None, state: CandidateState | None = None,
                     q: str = "") -> Any:  # fmt: skip
    """The watchlist of the workspace, highest priority first; ``q`` is a host-name fragment."""
    stmt = sa.select(Candidate).join(Brand, Brand.id == Candidate.brand_id).where(Brand.workspace_id == user.workspace_id)
    if brand_id:
        stmt = stmt.where(Candidate.brand_id.in_(regions_mod.with_regions(session, brand_id)))
    if state:
        stmt = stmt.where(Candidate.state == state)
    if q.strip():
        stmt = stmt.where(Candidate.hostname.ilike(f"%{q.strip().lower()}%"))
    return stmt.order_by(Candidate.priority.desc(), Candidate.last_seen.desc())


@router.get("/candidates")
def list_candidates(
    session: Annotated[Session, Depends(get_session, scope="function")],
    user: Annotated[User, Depends(current_user)],
    brand_id: uuid.UUID | None = None,
    state: CandidateState | None = None,
    limit: Annotated[int, Query(ge=1, le=5000)] = 500,
    offset: Annotated[int, Query(ge=0)] = 0,
    q: Annotated[str, Query(max_length=120)] = "",
) -> list[dict[str, Any]]:
    rows = session.scalars(candidates_query(session, user, brand_id=brand_id, state=state, q=q).limit(limit).offset(offset)).all()
    from brandwatch.detection.protect import is_protected, protected_set

    _prot: dict[uuid.UUID, set[str]] = {}
    rows = [
        c for c in rows
        if not is_protected(c.hostname, _prot.setdefault(c.brand_id, protected_set(session, c.brand_id)))
    ]  # fmt: skip
    brand_names = {b.id: b.name for b in session.scalars(sa.select(Brand).where(Brand.workspace_id == user.workspace_id)).all()}  # fmt: skip
    # the newest finding per candidate (open first), so the watchlist can link to it
    fmap: dict[uuid.UUID, Finding] = {}
    if rows:
        for f in session.scalars(
            sa.select(Finding)
            .where(Finding.candidate_id.in_([c.id for c in rows]))
            .order_by(Finding.created_at.desc())
        ).all():
            cur = fmap.get(f.candidate_id)
            if cur is None or (f.state is FindingState.OPEN and cur.state is not FindingState.OPEN):
                fmap[f.candidate_id] = f
    return [
        {
            "id": str(c.id),
            "brand_id": str(c.brand_id),
            "brand_name": brand_names.get(c.brand_id),
            "finding": (
                {
                    "id": str(fmap[c.id].id),
                    "severity": fmap[c.id].severity.value,
                    "state": fmap[c.id].state.value,
                }
                if c.id in fmap
                else None
            ),
            "hostname": c.hostname,
            "host_display": unicode_host(c.hostname),
            "is_idn": "xn--" in c.hostname,
            "canonical_url": c.canonical_url,
            "surface": c.surface.value,
            "state": c.state.value,
            "priority": c.priority,
            "first_seen": _iso(c.first_seen),
            "last_seen": _iso(c.last_seen),
            "next_scan_at": _iso(c.next_scan_at),
            "scan_count": c.scan_count,
            "content_hash": c.content_hash,
            # why it is on the watchlist: the streams that found it and what they matched
            "sources": [{"stream": src.source.value, "pattern": src.matched_pattern} for src in c.sources],
        }
        for c in rows
    ]


@router.get("/evidence/{evidence_id}/artifact")
def get_artifact(
    evidence_id: uuid.UUID,
    request: Request,
    session: Annotated[Session, Depends(get_session, scope="function")],
    user: Annotated[User, Depends(current_user)],
) -> Response:
    ev = session.get(Evidence, evidence_id)
    if ev is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "evidence not found")
    cand = session.get(Candidate, ev.candidate_id)
    brand = session.get(Brand, cand.brand_id) if cand else None
    if brand is None or brand.workspace_id != user.workspace_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "evidence not found")
    store = request.app.state.store
    if not ev.artifact_location or not store.exists(ev.artifact_location):
        raise HTTPException(status.HTTP_404_NOT_FOUND, "no artifact for this evidence")
    media, _ = mimetypes.guess_type(ev.artifact_location)
    content = store.get(ev.artifact_location)
    headers = {"Content-Disposition": f'inline; filename="{ev.content_sha256 or ev.id}"'}
    if (media or "").startswith("text/html"):
        media = "text/plain; charset=utf-8"  # never render attacker HTML inside the console
    return Response(
        content=content, media_type=media or "application/octet-stream", headers=headers
    )
