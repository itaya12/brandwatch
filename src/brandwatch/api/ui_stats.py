"""Aggregates behind the analyst UI's statistics panels (Findings, Brands, Watchlist, Campaigns,
Activity). Every query is scoped to the caller's workspace; nothing here writes."""

from __future__ import annotations

import uuid
from collections import Counter
from datetime import UTC, datetime, timedelta
from typing import Any

import sqlalchemy as sa
from sqlalchemy.orm import Session

from brandwatch.config.brand_config import SIGNAL_GROUPS
from brandwatch.db.enums import CandidateState, FindingState, Severity
from brandwatch.db.models import (
    AuditEvent,
    Brand,
    BrandFingerprint,
    Campaign,
    Candidate,
    CandidateSource,
    Finding,
    Ioc,
    Observation,
    RiskScore,
    ScanJob,
    User,
)
from brandwatch.detection import regions as regions_mod
from brandwatch.detection.ai_answers import AI_GROUPS
from brandwatch.detection.merchant import SHOP_GROUPS
from brandwatch.detection.social import SOCIAL_GROUPS

ALL_GROUPS = {**AI_GROUPS, **SOCIAL_GROUPS, **SHOP_GROUPS, **SIGNAL_GROUPS}  # phishing + shop + social + AI-answer signals
SEV_COLORS = {"critical": "#FF4D4D", "high": "#FF9F1C", "medium": "#F5C518", "low": "#2ECC71"}
STATE_COLORS = {
    "new": "#8A97A8", "watching": "#35C7F2", "analyzing": "#5FE3FF", "flagged": "#FF4D4D",
    "long_watch": "#2386a6", "dismissed": "#3a4658",
}  # fmt: skip
# Charts use one hue: severity colors are reserved for danger, everything else is the accent.
ACCENT = "#35C7F2"
RAMP = (
    "#5FE3FF",
    "#35C7F2",
    "#2386a6",
    "#1a5f78",
    "#8A97A8",
    "#3a4658",
)  # accent shades for multi-part charts
GROUP_COLORS = dict.fromkeys(
    ("identity", "visual", "behavior", "infrastructure", "reputation", "freshness", "evasion"),
    ACCENT,
)
CATEGORY_COLORS: dict[str, str] = {}  # activity categories are neutral (see activity.html)
# the few events that deserve a color in the activity log
EVENT_TONES = {"finding.confirmed": "crit", "takedown.sent": "ok", "takedown.resolved": "ok"}


def _aware(dt: datetime | None) -> datetime | None:
    if dt is None:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=UTC)


def _days(n: int = 14) -> list[str]:
    now = datetime.now(UTC)
    return [(now - timedelta(days=i)).date().isoformat() for i in range(n - 1, -1, -1)]


def _per_day(stamps: list[datetime | None], n: int = 14) -> list[int]:
    days = _days(n)
    idx = {d: i for i, d in enumerate(days)}
    out = [0] * n
    for s in stamps:
        s = _aware(s)
        if s is not None and (i := idx.get(s.date().isoformat())) is not None:
            out[i] += 1
    return out


def _brand_ids(session: Session, user: User, brand_id: uuid.UUID | None) -> list[uuid.UUID]:
    q = sa.select(Brand.id).where(Brand.workspace_id == user.workspace_id)
    if brand_id:
        q = q.where(Brand.id.in_(regions_mod.with_regions(session, brand_id)))
    return list(session.scalars(q).all()) or [uuid.uuid4()]


def segments(
    counter: dict[str, int], colors: dict[str, str], order: list[str] | None = None
) -> list[dict[str, Any]]:
    keys = order or sorted(counter, key=lambda k: -counter[k])
    from brandwatch.api.labels import GROUP_LABELS, STREAM_LABELS, SURFACE_LABELS

    def human(k: str) -> str:  # one vocabulary on charts too
        if k in GROUP_LABELS:
            return GROUP_LABELS[k][0]
        return STREAM_LABELS.get(k) or SURFACE_LABELS.get(k) or k.replace("_", " ")

    return [
        {
            "label": human(k),
            "key": k,
            "value": int(counter.get(k, 0)),
            "color": colors.get(k, "#8A97A8"),
        }
        for k in keys
        if counter.get(k, 0)
    ]


# ------------------------------------------------------------------------------------------ findings
def _signal_label(sig: str) -> str:
    from brandwatch.api.labels import signal_label

    return signal_label(sig)


def findings_stats(session: Session, user: User, brand_id: uuid.UUID | None) -> dict[str, Any]:
    ids = _brand_ids(session, user, brand_id)
    rows = session.execute(
        sa.select(Finding, RiskScore.score, RiskScore.signals, Candidate.surface)
        .join(Candidate, Candidate.id == Finding.candidate_id)
        .outerjoin(
            RiskScore, sa.and_(RiskScore.finding_id == Finding.id, RiskScore.is_current.is_(True))
        )
        .where(Finding.brand_id.in_(ids))
    ).all()
    now = datetime.now(UTC)
    by_state: Counter = Counter()
    open_sev: Counter = Counter()
    hist = [0] * 10
    signals: Counter = Counter()
    groups: Counter = Counter()
    surfaces: Counter = Counter()
    conf: list[float] = []
    stamps: list[datetime] = []
    new_24h = 0
    for f, score, sig, surface in rows:
        by_state[f.state.value] += 1
        stamps.append(f.created_at)
        if _aware(f.created_at) >= now - timedelta(days=1):
            new_24h += 1
        if f.state is FindingState.DISMISSED:
            continue
        if f.state is FindingState.OPEN:
            open_sev[f.severity.value] += 1
        if score is not None:
            hist[min(9, max(0, int(score) // 10))] += 1
        if f.confidence is not None:
            conf.append(float(f.confidence))
        surfaces[surface.value] += 1
        for name in sig or {}:
            if not name.startswith("_"):
                signals[name] += 1
                groups[ALL_GROUPS.get(name, "?")] += 1
    top = signals.most_common(10)
    mx = top[0][1] if top else 1
    return {
        "total": len(rows),
        "by_state": dict(by_state),
        "open_sev": {s.value: open_sev.get(s.value, 0) for s in reversed(list(Severity))},
        "open_total": by_state.get("open", 0),
        "sev_segments": segments(open_sev, SEV_COLORS, ["critical", "high", "medium", "low"]),
        "group_segments": segments(groups, GROUP_COLORS),
        "surface_segments": segments(
            surfaces,
            {"name": RAMP[1], "subdomain": RAMP[2], "path": RAMP[3], "content": RAMP[4]},
        ),
        "histogram": hist,
        "hist_max": max(hist) or 1,
        "top_signals": [
            {
                "name": n,
                "label": _signal_label(n),
                "count": c,
                "pct": round(c / mx * 100),
                "color": GROUP_COLORS.get(ALL_GROUPS.get(n, ""), "#8A97A8"),
            }
            for n, c in top
        ],
        "avg_confidence": round(sum(conf) / len(conf)) if conf else 0,
        "new_24h": new_24h,
        "per_day": _per_day(stamps),
    }


# ------------------------------------------------------------------------------------------ brands
def brand_cards(session: Session, user: User, brands: list[dict[str, Any]]) -> list[dict[str, Any]]:
    out = []
    now = datetime.now(UTC)
    for b in brands:
        bid = uuid.UUID(b["id"])
        sev = dict(
            session.execute(
                sa.select(Finding.severity, sa.func.count())
                .where(Finding.brand_id == bid, Finding.state == FindingState.OPEN)
                .group_by(Finding.severity)
            ).all()
        )
        states = dict(
            session.execute(
                sa.select(Candidate.state, sa.func.count())
                .where(Candidate.brand_id == bid)
                .group_by(Candidate.state)
            ).all()
        )
        confirmed = (
            session.scalar(
                sa.select(sa.func.count())
                .select_from(Finding)
                .where(Finding.brand_id == bid, Finding.state == FindingState.CONFIRMED)
            )
            or 0
        )
        campaigns = (
            session.scalar(
                sa.select(sa.func.count()).select_from(Campaign).where(Campaign.brand_id == bid)
            )
            or 0
        )
        jobs = session.scalars(
            sa.select(ScanJob).where(ScanJob.brand_id == bid).order_by(ScanJob.created_at.desc())
        ).all()
        created = session.scalars(
            sa.select(Finding.created_at).where(Finding.brand_id == bid)
        ).all()
        has_fp = (
            session.scalar(
                sa.select(sa.func.count())
                .select_from(BrandFingerprint)
                .where(BrandFingerprint.brand_id == bid)
            )
            or 0
        )
        last = jobs[0] if jobs else None
        sevmap = {s.value: int(sev.get(s, 0)) for s in Severity}
        open_total = sum(sevmap.values())
        out.append({
            **b,
            "sev": sevmap,
            "sev_pct": {k: (round(v / open_total * 100) if open_total else 0) for k, v in sevmap.items()},
            "candidates": sum(states.values()),
            "watching": int(states.get(CandidateState.WATCHING, 0) + states.get(CandidateState.LONG_WATCH, 0)),
            "confirmed": int(confirmed),
            "campaigns": int(campaigns),
            "scans": len(jobs),
            "scans_today": sum(1 for j in jobs if _aware(j.created_at) >= now - timedelta(days=1)),
            "running": any(j.state.value in ("queued", "running") for j in jobs[:5]),
            "last_scan": _aware(last.created_at).isoformat() if last else None,
            "last_job_id": str(last.id) if last else None,
            "per_day": _per_day(list(created)),
            "has_baseline": bool(has_fp),
            "threat": "critical" if sevmap["critical"] else ("high" if sevmap["high"] else ("medium" if sevmap["medium"] else "low")),
        })  # fmt: skip
    return out


# ------------------------------------------------------------------------------------------ watchlist
def watchlist_stats(session: Session, user: User, brand_id: uuid.UUID | None) -> dict[str, Any]:
    ids = _brand_ids(session, user, brand_id)
    cands = session.execute(
        sa.select(Candidate.id, Candidate.hostname, Candidate.state, Candidate.surface, Candidate.priority,
                  Candidate.first_seen, Candidate.next_scan_at, Candidate.scan_count).where(Candidate.brand_id.in_(ids))
    ).all()  # fmt: skip
    now = datetime.now(UTC)
    states = Counter(c.state.value for c in cands)
    surfaces = Counter(c.surface.value for c in cands)
    prio = Counter(
        "20+"
        if c.priority >= 20
        else ("10–19" if c.priority >= 10 else ("1–9" if c.priority > 0 else "0"))
        for c in cands
    )
    upcoming = sorted(
        ({"id": str(c.id), "hostname": c.hostname, "state": c.state.value, "at": _aware(c.next_scan_at).isoformat(), "priority": c.priority}
         for c in cands if c.next_scan_at is not None and _aware(c.next_scan_at) <= now + timedelta(days=2)
         and c.state.value in ("watching", "long_watch", "flagged")),
        key=lambda r: r["at"],
    )[:8]  # fmt: skip
    sources = Counter(
        s.value for s in session.scalars(
            sa.select(CandidateSource.source).join(Candidate, Candidate.id == CandidateSource.candidate_id).where(Candidate.brand_id.in_(ids))
        ).all()
    )  # fmt: skip
    changed_24h = session.scalar(
        sa.select(sa.func.count()).select_from(Observation).join(Candidate, Candidate.id == Observation.candidate_id)
        .where(Candidate.brand_id.in_(ids), Observation.changed.is_(True), Observation.observed_at >= now - timedelta(days=1))
    ) or 0  # fmt: skip
    total = len(cands) or 1
    order = ["new", "watching", "analyzing", "flagged", "long_watch", "dismissed"]
    return {
        "total": len(cands),
        "states": {s: int(states.get(s, 0)) for s in order},
        "state_pct": {s: round(states.get(s, 0) / total * 100, 1) for s in order},
        "state_colors": STATE_COLORS,
        "surface_segments": segments(
            surfaces,
            {"name": RAMP[1], "subdomain": RAMP[2], "path": RAMP[3], "content": RAMP[4]},
        ),
        "source_segments": segments(
            sources,
            {
                "ct": RAMP[0],
                "dnstwist": RAMP[1],
                "manual": RAMP[2],
                "urlscan": RAMP[3],
                "serpapi": RAMP[4],
                "nrd": RAMP[5],
            },
        ),  # fmt: skip
        "priority": {k: int(prio.get(k, 0)) for k in ("0", "1–9", "10–19", "20+")},
        "priority_max": max(prio.values() or [1]),
        "upcoming": upcoming,
        "discovered_per_day": _per_day([c.first_seen for c in cands]),
        "scans_total": sum(c.scan_count or 0 for c in cands),
        "changed_24h": int(changed_24h),
    }


# ------------------------------------------------------------------------------------------ campaigns
def confirmed_at_a_glance(session: Session, workspace_id: uuid.UUID, confirmed: list[dict[str, Any]]) -> dict[str, Any]:
    """Everyone at once: for every confirmed site, what its investigation found (from the cache, no lookups), rolled up by what
    they share. The servers that more than one site sits on, the registrars, the name servers: the shape of the operation
    without opening the sites one by one. A site whose investigation is not done yet is listed as such."""
    from brandwatch.db.models import ScanJob
    from brandwatch.detection import intel as intel_mod

    servers: dict[str, dict[str, Any]] = {}
    registrars: dict[str, list[str]] = {}
    nameservers: dict[str, list[str]] = {}
    pending: list[dict[str, str]] = []
    for x in confirmed:
        host = x["hostname"]
        v = intel_mod.intel_view(session, workspace_id, host)
        if v.get("fetched_at") is None:
            job = session.scalars(
                sa.select(ScanJob).where(ScanJob.workspace_id == workspace_id, ScanJob.kind == "intel")
                .order_by(ScanJob.created_at.desc()).limit(40)
            ).all()
            mine = next((j for j in job if str((j.payload or {}).get("finding_id")) == x["id"]), None)
            state = mine.state.value if mine else "not investigated"
            pending.append({"host": host, "id": x["id"], "state": state})
            continue
        for ip in v.get("ips") or []:
            row = servers.setdefault(ip["ip"], {"ip": ip["ip"], "country": ip.get("country_name"), "country_code": ip.get("country"), "asn": ip.get("asn"),
                                                "owner": ip.get("as_owner"), "shared": bool(ip.get("shared")), "sites": [],
                                                "abuse": (ip.get("abuse") or {}).get("abuse_score"), "detections": ip.get("positives")})  # fmt: skip
            if host not in row["sites"]:
                row["sites"].append(host)
        if v.get("registrar"):
            registrars.setdefault(str(v["registrar"]), []).append(host)
        for rec in (v.get("dns") or {}).get("records") or []:
            if rec.get("type") == "NS" and rec.get("value"):
                nameservers.setdefault(str(rec["value"]).lower().rstrip("."), []).append(host)
    shared = sorted(servers.values(), key=lambda r: (-len(r["sites"]), r["ip"]))
    return {
        "sites": len(confirmed), "investigated": len(confirmed) - len(pending), "pending": pending,
        "servers": shared, "multi_site_servers": sum(1 for r in shared if len(r["sites"]) > 1 and not r["shared"]),
        "registrars": sorted(({"name": k, "sites": sorted(set(h))} for k, h in registrars.items()), key=lambda r: (-len(r["sites"]), r["name"])),
        "nameservers": sorted(({"name": k, "sites": sorted(set(h))} for k, h in nameservers.items()), key=lambda r: (-len(r["sites"]), r["name"]))[:12],
    }  # fmt: skip


def campaign_stats(session: Session, rows: list[dict[str, Any]]) -> dict[str, Any]:
    servers: set[str] = set()
    other: set[str] = set()
    for r in rows:
        servers |= set((r.get("actor_profile") or {}).get("servers") or [])
        other |= set((r.get("actor_profile") or {}).get("other_brands_hit") or [])
        r["iocs"] = int(
            session.scalar(
                sa.select(sa.func.count())
                .select_from(Ioc)
                .where(Ioc.campaign_id == uuid.UUID(r["id"]))
            )
            or 0
        )
        st = r["stats"]
        r["included_pct"] = round(st["included"] / st["nodes"] * 100) if st["nodes"] else 0
    return {
        "campaigns": len(rows),
        "nodes": sum(r["stats"]["nodes"] for r in rows),
        "included": sum(r["stats"]["included"] for r in rows),
        "excluded": sum(r["stats"]["excluded"] for r in rows),
        "edges": sum(r["stats"]["edges"] for r in rows),
        "findings": sum(len(r["findings"]) for r in rows),
        "iocs": sum(r["iocs"] for r in rows),
        "servers": sorted(servers),
        "other_brands": sorted(other),
    }


# ------------------------------------------------------------------------------------------ activity
def _object_names(session: Session, events: list[Any]) -> dict[Any, str]:
    """Hostnames / brand names / references instead of id prefixes (one query per type)."""
    from brandwatch.api.labels import JOB_LABELS
    from brandwatch.db.models import Campaign, ScanJob, TakedownDraft

    ids: dict[str, set] = {}
    for e in events:
        if e.object_id:
            ids.setdefault(e.object_type, set()).add(e.object_id)
    out: dict[Any, str] = {}
    if ids.get("scan_job"):
        for jid, kind in session.execute(
            sa.select(ScanJob.id, ScanJob.kind).where(ScanJob.id.in_(ids["scan_job"]))
        ).all():
            out[jid] = f"{JOB_LABELS.get(kind, kind)} {str(jid)[:8]}"
    if ids.get("finding"):
        for fid, host in session.execute(sa.select(Finding.id, Candidate.hostname).join(Candidate, Candidate.id == Finding.candidate_id)
                                          .where(Finding.id.in_(ids["finding"]))).all():  # fmt: skip
            out[fid] = host
    if ids.get("candidate"):
        for cid, host in session.execute(
            sa.select(Candidate.id, Candidate.hostname).where(Candidate.id.in_(ids["candidate"]))
        ).all():
            out[cid] = host
    if ids.get("brand"):
        for bid, name in session.execute(
            sa.select(Brand.id, Brand.name).where(Brand.id.in_(ids["brand"]))
        ).all():
            out[bid] = name
    if ids.get("campaign"):
        for cid, name in session.execute(
            sa.select(Campaign.id, Campaign.name).where(Campaign.id.in_(ids["campaign"]))
        ).all():
            out[cid] = name
    if ids.get("takedown_draft"):
        for tid, ref in session.execute(
            sa.select(TakedownDraft.id, TakedownDraft.reference).where(
                TakedownDraft.id.in_(ids["takedown_draft"])
            )
        ).all():
            out[tid] = ref or str(tid)[:8]
    return out


def activity_stats(session: Session, user: User, limit: int = 300) -> dict[str, Any]:
    events = session.scalars(
        sa.select(AuditEvent)
        .where(AuditEvent.workspace_id == user.workspace_id)
        .order_by(AuditEvent.at.desc())
        .limit(limit)
    ).all()
    emails = dict(
        session.execute(
            sa.select(User.id, User.email).where(User.workspace_id == user.workspace_id)
        ).all()
    )
    now = datetime.now(UTC)
    names = _object_names(session, events)
    cats: Counter = Counter()
    actors: Counter = Counter()
    rows = []
    for e in events:
        cat = e.action.split(".", 1)[0]
        cats[cat] += 1
        who = emails.get(e.actor_id) if e.actor_id else None
        actors[who or e.actor_type] += 1
        prev = rows[-1] if rows else None
        # consecutive repeats (logins, re-scores of the same kind) collapse into one row "×N"
        if (
            prev is not None
            and prev["action"] == e.action
            and prev["actor"] == (who or e.actor_type)
            and not e.reason
            and not prev["reason"]
            and (e.action.startswith("user.login") or not (e.old_value or e.new_value))
        ):
            prev["count"] += 1
            prev["first_at"] = _aware(e.at).isoformat()
            continue
        rows.append({
            "count": 1, "first_at": None, "notable": not e.action.startswith("user.login"), "tone": EVENT_TONES.get(e.action),
            "object_name": names.get(e.object_id) if e.object_id else None,
            "at": _aware(e.at).isoformat(), "action": e.action, "category": cat, "color": CATEGORY_COLORS.get(cat, "#8A97A8"),
            "verb": e.action.split(".", 1)[1] if "." in e.action else e.action,
            "actor": who or e.actor_type, "actor_type": e.actor_type,
            "initials": (who or e.actor_type)[:2].upper(), "object_type": e.object_type,
            "object_id": str(e.object_id) if e.object_id else None, "old": e.old_value, "new": e.new_value, "reason": e.reason,
        })  # fmt: skip
    top_actors = actors.most_common(6)
    amx = top_actors[0][1] if top_actors else 1
    return {
        "events": rows,
        "total": len(rows),
        "analyst": sum(1 for r in rows if r["actor_type"] == "analyst"),
        "system": sum(1 for r in rows if r["actor_type"] == "system"),
        "logins_24h": sum(
            1
            for r in rows
            if r["action"] == "user.login"
            and datetime.fromisoformat(r["at"]) >= now - timedelta(days=1)
        ),
        "verdicts": sum(
            1 for r in rows if r["action"] in ("finding.confirmed", "finding.dismissed")
        ),
        "category_segments": segments(cats, CATEGORY_COLORS),
        "categories": sorted(cats),
        "category_colors": CATEGORY_COLORS,
        "per_day": _per_day([datetime.fromisoformat(r["at"]) for r in rows]),
        "top_actors": [{"name": n, "count": c, "pct": round(c / amx * 100)} for n, c in top_actors],
    }
