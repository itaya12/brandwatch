"""Dashboard API (spec §14 tab 1, §12 metrics): one payload that answers "what is the system
doing for this brand right now" — KPIs, severity/score distributions, scans per day, discovery
source effectiveness, pipeline stage statistics, provider/budget status, recent criticals,
analyst metrics (precision / FP rate / MTTD / MTTC) and the geo points for the globe."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from typing import Annotated, Any

import sqlalchemy as sa
from fastapi import APIRouter, Depends, Query, Request
from sqlalchemy.orm import Session

from brandwatch import tenancy
from brandwatch.api.auth import current_user
from brandwatch.api.deps import get_session
from brandwatch.db.enums import CandidateState, FindingState, Severity, TakedownState
from brandwatch.db.models import (
    AnalystLabel,
    ApiUsage,
    Brand,
    BrandDomain,
    Campaign,
    Candidate,
    CandidateSource,
    DnsObservation,
    Evidence,
    Finding,
    Ioc,
    IpAddress,
    RiskScore,
    ScanEventRecord,
    ScanJob,
    ScanStage,
    TakedownDraft,
    User,
    WhoisObservation,
)
from brandwatch.detection import hosting
from brandwatch.detection import regions as regions_mod

router = APIRouter(prefix="/api/dashboard", tags=["dashboard"])


def _day(dt: datetime) -> str:
    return dt.date().isoformat()


_HOME_CACHE: dict[str, dict[str, Any] | None] = {}


def _brand_home(session: Session, request: Request, brand_ids: list[uuid.UUID], points: list[dict[str, Any]]) -> dict[str, Any] | None:
    """Without HOME_LABEL / HOME_LAT / HOME_LON the globe had no starting point and drew no arcs (live mode). The brand's own site is
    a fair one: the first official domain of the brand with the most attacks, resolved and geolocated once (cached in the process)."""
    import asyncio
    import socket

    from brandwatch.db.models import BrandDomain

    if not points or not brand_ids:
        return None
    row = session.execute(
        sa.select(BrandDomain.domain, Brand.name).join(Brand, Brand.id == BrandDomain.brand_id)
        .where(BrandDomain.brand_id.in_(brand_ids), BrandDomain.is_official.is_(True)).order_by(Brand.created_at, BrandDomain.domain)
    ).first()
    if row is None:
        return None
    domain, brand = row
    if domain in _HOME_CACHE:
        return _HOME_CACHE[domain]
    home = None
    try:
        ip = next(i[4][0] for i in socket.getaddrinfo(domain, 443, socket.AF_INET, socket.SOCK_STREAM))
        geo = asyncio.run(request.app.state.providers.geo().locate(ip))
        d = geo.data or {}
        if geo.ok and d.get("lat") is not None and not hosting.is_cdn(d.get("org"), ip):  # a CDN edge is where the asker is: not a home
            home = {"label": f"{brand} · {d.get('city') or d.get('country') or domain}", "lat": float(d["lat"]), "lon": float(d["lon"])}
    except Exception:  # noqa: BLE001 - no home point is not an error: the globe just has no arcs
        home = None
    if home is not None:  # a failure is not cached: the next load tries again
        _HOME_CACHE[domain] = home
    return home


def _aware(dt: datetime | None) -> datetime | None:
    if dt is None:
        return None
    return dt if dt.tzinfo is not None else dt.replace(tzinfo=UTC)


def _count(session: Session, stmt) -> int:
    return int(session.scalar(sa.select(sa.func.count()).select_from(stmt.subquery())) or 0)


def dashboard(
    request: Request,
    session: Session,
    user: User,
    *,
    brand_id: uuid.UUID | None = None,
) -> dict[str, Any]:
    now = datetime.now(UTC)
    since_day = now - timedelta(days=1)
    since_14 = now - timedelta(days=14)
    ws = user.workspace_id

    brands_q = sa.select(Brand).where(Brand.workspace_id == ws)
    if brand_id:
        brands_q = brands_q.where(Brand.id.in_(regions_mod.with_regions(session, brand_id)))
    brands = session.scalars(brands_q).all()
    brand_ids = [b.id for b in brands]
    if not brand_ids:
        brand_ids = [uuid.uuid4()]  # matches nothing

    cand_q = sa.select(Candidate).where(Candidate.brand_id.in_(brand_ids))
    find_q = sa.select(Finding).where(Finding.brand_id.in_(brand_ids))
    # scans only: infrastructure-mapping and intel jobs are not scans
    jobs_q = sa.select(ScanJob).where(
        ScanJob.workspace_id == ws, ScanJob.kind.in_(["brand_scan", "url_scan"])
    )
    if brand_id:
        jobs_q = jobs_q.where(ScanJob.brand_id.in_(regions_mod.with_regions(session, brand_id)))

    # ---- KPIs ------------------------------------------------------------------------------
    open_sev = dict(
        session.execute(
            sa.select(Finding.severity, sa.func.count())
            .where(Finding.brand_id.in_(brand_ids), Finding.state == FindingState.OPEN)
            .group_by(Finding.severity)
        ).all()
    )
    cand_states = dict(
        session.execute(
            sa.select(Candidate.state, sa.func.count())
            .where(Candidate.brand_id.in_(brand_ids))
            .group_by(Candidate.state)
        ).all()
    )
    find_states = dict(
        session.execute(
            sa.select(Finding.state, sa.func.count())
            .where(Finding.brand_id.in_(brand_ids))
            .group_by(Finding.state)
        ).all()
    )
    evidence_total = _count(
        session,
        sa.select(Evidence.id)
        .join(Candidate, Candidate.id == Evidence.candidate_id)
        .where(Candidate.brand_id.in_(brand_ids)),
    )
    screenshots = _count(
        session,
        sa.select(Evidence.id)
        .join(Candidate, Candidate.id == Evidence.candidate_id)
        .where(Candidate.brand_id.in_(brand_ids), Evidence.type == "screenshot"),
    )
    jobs_total = _count(session, jobs_q)
    jobs_today = _count(session, jobs_q.where(ScanJob.created_at >= since_day))
    cands_scanned_today = _count(session, cand_q.where(Candidate.last_seen >= since_day))
    usage_today = session.execute(
        sa.select(
            sa.func.coalesce(sa.func.sum(ApiUsage.calls), 0),
            sa.func.coalesce(sa.func.sum(ApiUsage.cost_usd), 0),
        ).where(ApiUsage.workspace_id == ws, ApiUsage.at >= since_day)
    ).one()
    campaigns = _count(session, sa.select(Campaign.id).where(Campaign.brand_id.in_(brand_ids)))
    iocs = _count(session, sa.select(Ioc.id).where(Ioc.workspace_id == ws))
    takedowns_open = _count(
        session,
        sa.select(TakedownDraft.id)
        .join(Finding, Finding.id == TakedownDraft.finding_id)
        .where(
            Finding.brand_id.in_(brand_ids),
            TakedownDraft.state.notin_([TakedownState.RESOLVED, TakedownState.REJECTED]),
        ),
    )
    confirmed_ids = session.scalars(
        sa.select(Finding.id).where(Finding.brand_id.in_(brand_ids), Finding.state == FindingState.CONFIRMED)
    ).all()  # fmt: skip
    with_takedown = set(session.scalars(
        sa.select(TakedownDraft.finding_id).where(TakedownDraft.finding_id.in_(confirmed_ids))
    ).all()) if confirmed_ids else set()  # fmt: skip
    confirmed_unmapped = _count(
        session,
        sa.select(Finding.id).where(
            Finding.brand_id.in_(brand_ids), Finding.state == FindingState.CONFIRMED,
            Finding.campaign_id.is_(None),
        ),
    ) if confirmed_ids else 0  # fmt: skip
    takedowns_draft = _count(
        session,
        sa.select(TakedownDraft.id)
        .join(Finding, Finding.id == TakedownDraft.finding_id)
        .where(Finding.brand_id.in_(brand_ids),
               TakedownDraft.state.in_([TakedownState.DRAFT, TakedownState.REVIEW, TakedownState.APPROVED, TakedownState.REOPENED])),
    )  # fmt: skip
    # legacy data: an open twin of an already-confirmed site is not "awaiting verdict"
    confirmed_cands = sa.select(Finding.candidate_id).where(
        Finding.brand_id.in_(brand_ids), Finding.state == FindingState.CONFIRMED
    )
    legacy_twins = _count(
        session,
        sa.select(Finding.id).where(
            Finding.brand_id.in_(brand_ids), Finding.state == FindingState.OPEN,
            Finding.candidate_id.in_(confirmed_cands),
        ),
    )  # fmt: skip
    from brandwatch.db.models import BrandFingerprint

    baselines = _count(
        session,
        sa.select(sa.func.distinct(BrandFingerprint.brand_id)).where(
            BrandFingerprint.brand_id.in_(brand_ids)
        ),
    )
    takedowns_total = _count(
        session,
        sa.select(TakedownDraft.id).join(Finding, Finding.id == TakedownDraft.finding_id).where(Finding.brand_id.in_(brand_ids)),
    )  # fmt: skip
    takedowns_sent = _count(
        session,
        sa.select(TakedownDraft.id).join(Finding, Finding.id == TakedownDraft.finding_id)
        .where(Finding.brand_id.in_(brand_ids), TakedownDraft.state.in_(
            [TakedownState.SENT, TakedownState.ACKNOWLEDGED, TakedownState.IN_PROGRESS, TakedownState.RESOLVED])),
    )  # fmt: skip
    kpis = {
        "baselines": baselines,
        "takedowns_total": takedowns_total,
        "takedowns_sent": takedowns_sent,
        "confirmed_no_takedown": len([i for i in confirmed_ids if i not in with_takedown]),
        "confirmed_unmapped": confirmed_unmapped,
        "takedowns_draft": takedowns_draft,
        "brands": len(brands),
        "official_domains": _count(
            session, sa.select(BrandDomain.id).where(BrandDomain.brand_id.in_(brand_ids))
        ),
        "candidates_total": sum(cand_states.values()),
        "candidates_watching": cand_states.get(CandidateState.WATCHING, 0)
        + cand_states.get(CandidateState.LONG_WATCH, 0),
        "candidates_flagged": cand_states.get(CandidateState.FLAGGED, 0),
        "candidates_dismissed": cand_states.get(CandidateState.DISMISSED, 0),
        "findings_open": max(0, find_states.get(FindingState.OPEN, 0) - legacy_twins),
        "findings_confirmed": find_states.get(FindingState.CONFIRMED, 0),
        "findings_dismissed": find_states.get(FindingState.DISMISSED, 0),
        "critical_open": open_sev.get(Severity.CRITICAL, 0),
        "high_open": open_sev.get(Severity.HIGH, 0),
        "evidence_rows": evidence_total,
        "screenshots": screenshots,
        "scans_total": jobs_total,
        "scans_today": jobs_today,
        "candidates_scanned_today": cands_scanned_today,
        "api_calls_today": int(usage_today[0]),
        "cost_today_usd": float(usage_today[1]),
        "campaigns": campaigns,
        "iocs": iocs,
        "takedowns_open": takedowns_open,
    }

    # ---- distributions ---------------------------------------------------------------------
    scores = session.scalars(
        sa.select(RiskScore.score)
        .join(Finding, Finding.id == RiskScore.finding_id)
        .where(Finding.brand_id.in_(brand_ids), RiskScore.is_current.is_(True))
    ).all()
    histogram = [0] * 10
    for sc in scores:
        histogram[min(9, max(0, int(sc) // 10))] += 1
    severity_distribution = {s.value: int(open_sev.get(s, 0)) for s in Severity}

    # ---- per day (14 days) -----------------------------------------------------------------
    days = [(now - timedelta(days=i)).date().isoformat() for i in range(13, -1, -1)]
    jobs_rows = session.scalars(jobs_q.where(ScanJob.created_at >= since_14)).all()
    per_day_jobs = {d: 0 for d in days}
    for j in jobs_rows:
        d = _day(_aware(j.created_at))
        if d in per_day_jobs:
            per_day_jobs[d] += 1
    finds_rows = session.scalars(find_q.where(Finding.created_at >= since_14)).all()
    per_day_findings = {d: 0 for d in days}
    for f in finds_rows:
        d = _day(_aware(f.created_at))
        if d in per_day_findings:
            per_day_findings[d] += 1
    stage_rows = session.execute(
        sa.select(
            ScanStage.name,
            sa.func.count(),
            sa.func.coalesce(sa.func.sum(ScanStage.hits), 0),
            sa.func.coalesce(sa.func.avg(ScanStage.elapsed_ms), 0),
            sa.func.coalesce(sa.func.sum(ScanStage.api_calls), 0),
        )
        .join(ScanJob, ScanJob.id == ScanStage.job_id)
        .where(ScanJob.id.in_(sa.select(jobs_q.subquery().c.id)))
        .group_by(ScanStage.name)
    ).all()
    stage_order = ["baseline", "discovery", "normalize_dedup_prefilter", "enrichment_analysis_scoring",
                   "investigation", "intel", "noop"]  # the order the pipeline runs in  # fmt: skip
    pipeline = sorted(
        (
            {"stage": n, "runs": int(c), "hits": int(h), "avg_ms": int(a or 0), "api_calls": int(k)}
            for n, c, h, a, k in stage_rows
        ),
        key=lambda p: (
            stage_order.index(p["stage"]) if p["stage"] in stage_order else len(stage_order)
        ),
    )

    # ---- discovery source effectiveness -------------------------------------------------------
    src_cands = dict(
        session.execute(
            sa.select(CandidateSource.source, sa.func.count())
            .join(Candidate, Candidate.id == CandidateSource.candidate_id)
            .where(Candidate.brand_id.in_(brand_ids))
            .group_by(CandidateSource.source)
        ).all()
    )
    src_finds = dict(
        session.execute(
            sa.select(CandidateSource.source, sa.func.count(sa.distinct(Finding.id)))
            .join(Candidate, Candidate.id == CandidateSource.candidate_id)
            .join(Finding, Finding.candidate_id == Candidate.id)
            .where(Candidate.brand_id.in_(brand_ids))
            .group_by(CandidateSource.source)
        ).all()
    )
    source_effectiveness = sorted(
        (
            {"source": s.value, "candidates": int(c), "findings": int(src_finds.get(s, 0))}
            for s, c in src_cands.items()
        ),
        key=lambda r: (-r["findings"], -r["candidates"]),
    )

    # ---- recent criticals -------------------------------------------------------------------------
    recent = session.execute(
        sa.select(Finding, Candidate.hostname, RiskScore.score, RiskScore.signals)
        .join(Candidate, Candidate.id == Finding.candidate_id)
        .outerjoin(
            RiskScore, sa.and_(RiskScore.finding_id == Finding.id, RiskScore.is_current.is_(True))
        )
        .where(
            Finding.brand_id.in_(brand_ids),
            Finding.state == FindingState.OPEN,  # what waits for a verdict, not what was already judged
            Finding.severity == Severity.CRITICAL,
        )
        .order_by(Finding.created_at.desc())
        .limit(8)
    ).all()
    from brandwatch.api.findings import signal_items, unicode_host
    from brandwatch.config.brand_config import SIGNAL_GROUPS

    def _sig(sigs: dict | None) -> tuple[list[dict], bool]:
        pts = {k: v for k, v in (sigs or {}).items() if not k.startswith("_")}
        ordered = sorted(pts.items(), key=lambda kv: (-float(kv[1] or 0), kv[0]))
        return signal_items(ordered[:3], (sigs or {}).get("_details", {})), any(
            SIGNAL_GROUPS.get(k) == "evasion" for k in pts
        )

    showcase = _showcase(session, brand_ids, {b.id: b.name for b in brands})

    recent_criticals = []
    for f, host, score, sigs in recent:
        items, cloaked = _sig(sigs)
        recent_criticals.append({
            "id": str(f.id), "hostname": host, "host_display": unicode_host(host), "is_idn": "xn--" in host,
            "severity": f.severity.value, "score": score, "confidence": float(f.confidence or 0),
            "state": f.state.value, "created_at": _aware(f.created_at).isoformat(),
            "signal_items": items, "cloaked": cloaked,
        })  # fmt: skip

    # ---- analyst metrics (spec §12) ----------------------------------------------------------------
    labels = session.execute(
        sa.select(AnalystLabel.label, Finding.severity)
        .join(Finding, Finding.id == AnalystLabel.finding_id)
        .where(Finding.brand_id.in_(brand_ids))
    ).all()
    tp = sum(1 for lab, sev in labels if lab == "phishing")
    fp = sum(
        1 for lab, sev in labels if lab != "phishing" and sev in (Severity.HIGH, Severity.CRITICAL)
    )
    precision = round(tp / (tp + fp), 2) if (tp + fp) else None
    fp_rate = round(fp / len(labels), 2) if labels else None
    # MTTD = finding.created_at - domain registration; MTTC = confirm - finding.created_at
    mttd_hours: list[float] = []
    for f, _host, _score, _sigs in recent:
        who = session.execute(
            sa.select(WhoisObservation.registered_at)
            .join(Evidence, Evidence.id == WhoisObservation.evidence_id)
            .where(Evidence.candidate_id == f.candidate_id)
            .order_by(Evidence.observed_at.desc())
        ).scalar()
        if who:
            delta = _aware(f.created_at) - datetime(who.year, who.month, who.day, tzinfo=UTC)
            mttd_hours.append(max(0.0, delta.total_seconds() / 3600))
    confirm_rows = session.execute(
        sa.select(Finding.created_at, AnalystLabel.at)
        .join(AnalystLabel, AnalystLabel.finding_id == Finding.id)
        .where(Finding.brand_id.in_(brand_ids), AnalystLabel.label == "phishing")
    ).all()
    mttc = [
        max(0.0, (_aware(at) - _aware(created)).total_seconds() / 3600)
        for created, at in confirm_rows
    ]
    metrics = {
        "labels": len(labels), "precision": precision, "fp_rate": fp_rate,
        "mttd_hours": round(sum(mttd_hours) / len(mttd_hours), 1) if mttd_hours else None,
        "mttc_hours": round(sum(mttc) / len(mttc), 2) if mttc else None,
    }  # fmt: skip

    # ---- geo for the globe ----------------------------------------------------------------------
    points: list[dict[str, Any]] = []
    ip_rows = session.execute(
        sa.select(Finding, Candidate.hostname, DnsObservation.records, RiskScore.score)
        .join(Candidate, Candidate.id == Finding.candidate_id)
        .join(Evidence, Evidence.candidate_id == Candidate.id)
        .join(DnsObservation, DnsObservation.evidence_id == Evidence.id)
        .outerjoin(
            RiskScore, sa.and_(RiskScore.finding_id == Finding.id, RiskScore.is_current.is_(True))
        )
        .where(Finding.brand_id.in_(brand_ids), Finding.state != FindingState.DISMISSED)
        .order_by(Finding.created_at.desc())
    ).all()
    seen_hosts: set[str] = set()
    cdn_hidden = 0
    for f, host, records, score in ip_rows:
        if host in seen_hosts:
            continue
        ips = (records or {}).get("A") or []
        if not ips:
            continue
        geo = None
        edge = False
        for ip in ips:  # the first address that is a server, not a CDN edge
            g = session.scalars(sa.select(IpAddress).where(IpAddress.ip == ip)).first()
            if g is None or g.lat is None:
                continue
            if hosting.is_cdn(g.org, ip):
                edge = True
                continue
            geo = g
            break
        if geo is None:
            if edge:  # only edges: where the site really is cannot be known, and the edge's place is wherever the scan ran
                seen_hosts.add(host)
                cdn_hidden += 1
            continue
        seen_hosts.add(host)
        points.append({"hostname": host, "ip": ips[0], "lat": geo.lat, "lon": geo.lon, "city": geo.city, "country": geo.country, "org": geo.org,
                       "severity": f.severity.value, "score": score, "state": f.state.value, "finding_id": str(f.id),
                       "kind": f.kind or "phishing"})  # fmt: skip
    settings = request.app.state.settings
    home = None
    if settings.home_label and settings.home_lat is not None and settings.home_lon is not None:
        home = {"label": settings.home_label, "lat": settings.home_lat, "lon": settings.home_lon}
    elif settings.demo_mode:  # the fictional demo brand's head office
        home = {"label": "ShopNova HQ · Austin", "lat": 30.2672, "lon": -97.7431}
    else:  # live, nothing configured: the arcs start where the brand's own site is hosted (its official domain, geolocated)
        home = _brand_home(session, request, brand_ids, points)
    geo_payload = {"home": home, "points": points, "cdn_hidden": cdn_hidden,
                   "countries": sorted({p["country"] for p in points if p["country"]})}  # fmt: skip

    # ---- system --------------------------------------------------------------------------------------
    app = request.app
    scheduler = getattr(app.state, "scheduler", None)
    limits = tenancy.workspace_limits(session, ws, settings)
    system = {
        "demo_mode": settings.demo_mode,
        "providers": app.state.providers.describe(),
        "queue_backend": type(app.state.queue).__name__,
        "scheduler": "running" if scheduler is not None and scheduler._thread else "stopped",
        "notify_channels": [n.name for n in app.state.notifier.notifiers] if getattr(app.state, "notifier", None) else [],
        "budget": {
            "max_daily_spend": limits.max_daily_spend, "spent_today": kpis["cost_today_usd"],
            "max_api_calls": limits.max_api_calls, "api_calls_today": kpis["api_calls_today"],
            "max_residential_gb": limits.max_residential_gb,
        },
    }  # fmt: skip

    return {
        "generated_at": now.isoformat(),
        "brand": None
        if not brand_id or not brands
        else {"id": str(brands[0].id), "name": brands[0].name},
        "brands": [{"id": str(b.id), "name": b.name} for b in brands],
        "kpis": kpis,
        "severity_distribution": severity_distribution,
        "score_histogram": histogram,
        "scans_per_day": [
            {"date": d, "jobs": per_day_jobs[d], "findings": per_day_findings[d]} for d in days
        ],
        "pipeline": pipeline,
        "source_effectiveness": source_effectiveness,
        "recent_criticals": recent_criticals,
        "showcase": showcase,
        # the headline names the brand when there is exactly one in scope
        "hero_brand": brands[0].name if len(brands) == 1 else None,
        "watchlist": {s.value: int(cand_states.get(s, 0)) for s in CandidateState},
        "metrics": metrics,
        "geo": geo_payload,
        "system": system,
    }


def _showcase(session: Session, brand_ids: list, names: dict) -> list[dict[str, Any]]:
    """'Caught in the act': the most telling fakes, each with its screenshot next to the real site's.
    Critical first, then confirmed, cloaked and highest score; only findings that have a screenshot."""
    import re

    from brandwatch.api.findings import explain_sentence, unicode_host
    from brandwatch.config.brand_config import SIGNAL_GROUPS
    from brandwatch.db.enums import EvidenceType
    from brandwatch.db.models import BrandFingerprint, FindingEvidence

    rows = session.execute(
        sa.select(Finding, Candidate.hostname, RiskScore.score, RiskScore.signals)
        .join(Candidate, Candidate.id == Finding.candidate_id)
        .join(RiskScore, sa.and_(RiskScore.finding_id == Finding.id, RiskScore.is_current.is_(True)))
        .where(Finding.brand_id.in_(brand_ids), Finding.severity.in_([Severity.CRITICAL, Severity.HIGH]),
               Finding.state.in_([FindingState.OPEN, FindingState.CONFIRMED]))
    ).all()  # fmt: skip
    with_baseline = set(
        session.scalars(
            sa.select(BrandFingerprint.brand_id).where(BrandFingerprint.brand_id.in_(brand_ids))
        ).all()
    )

    def rank(row):
        f, _host, score, sigs = row
        cloaked = any(
            SIGNAL_GROUPS.get(k) == "evasion" for k in (sigs or {}) if not k.startswith("_")
        )
        return (
            f.severity is not Severity.CRITICAL,
            f.state is not FindingState.CONFIRMED,
            not cloaked,
            -(score or 0),
        )

    out: list[dict[str, Any]] = []
    for f, host, score, sigs in sorted(rows, key=rank):
        shot = session.scalars(
            sa.select(Evidence).join(FindingEvidence, FindingEvidence.evidence_id == Evidence.id)
            .where(FindingEvidence.finding_id == f.id, Evidence.type == EvidenceType.SCREENSHOT)
            .order_by(Evidence.observed_at.desc())
        ).first()  # fmt: skip
        if shot is None or not shot.artifact_location:
            continue
        sigs = sigs or {}
        details = sigs.get("_details", {}) or {}
        pts = {k: v for k, v in sigs.items() if not k.startswith("_")}
        m = re.search(r"(\d+)% similar", str(details.get("screenshot_similarity_ge_90") or ""))
        out.append({
            "id": str(f.id), "hostname": host, "host_display": unicode_host(host), "is_idn": "xn--" in host,
            "severity": f.severity.value, "state": f.state.value, "score": score,
            "cloaked": any(SIGNAL_GROUPS.get(k) == "evasion" for k in pts),
            "summary": explain_sentence(pts, details, names.get(f.brand_id, "the brand")),
            "suspect_url": f"/api/evidence/{shot.id}/artifact",
            "baseline_url": f"/api/brands/{f.brand_id}/baseline/screenshot" if f.brand_id in with_baseline else None,
            "similarity": int(m.group(1)) if m else None, "brand": names.get(f.brand_id),
        })  # fmt: skip
        if len(out) == 3:
            break
    return out


@router.get("")
def get_dashboard(
    request: Request,
    session: Annotated[Session, Depends(get_session, scope="function")],
    user: Annotated[User, Depends(current_user)],
    brand_id: uuid.UUID | None = None,
) -> dict[str, Any]:
    return dashboard(request, session, user, brand_id=brand_id)


@router.get("/feed")
def live_feed(
    session: Annotated[Session, Depends(get_session, scope="function")],
    user: Annotated[User, Depends(current_user)],
    brand_id: uuid.UUID | None = None,
    limit: int = Query(default=40, ge=1, le=200),
) -> list[dict[str, Any]]:
    """Latest scan events across all jobs of the workspace — the dashboard's live ticker."""
    q = (
        sa.select(ScanEventRecord, ScanJob.kind, Brand.name)
        .join(ScanJob, ScanJob.id == ScanEventRecord.job_id)
        .outerjoin(Brand, Brand.id == ScanJob.brand_id)
        .where(ScanJob.workspace_id == user.workspace_id)
    )
    if brand_id:
        q = q.where(ScanJob.brand_id.in_(regions_mod.with_regions(session, brand_id)))
    rows = session.execute(
        q.order_by(ScanEventRecord.at.desc(), ScanEventRecord.seq.desc()).limit(limit)
    ).all()
    return [
        {"at": _aware(e.at).isoformat(), "job_id": str(e.job_id), "kind": kind, "brand": brand, "stage": e.stage, "step": e.step,
         "status": e.status, "level": e.level, "message": e.message, "data": e.data}
        for e, kind, brand in rows
    ]  # fmt: skip
