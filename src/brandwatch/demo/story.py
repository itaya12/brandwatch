"""The How-it-works story: one real object per chapter, read from the workspace's own data.

Six chapters — learn the real site, find look-alikes, visit like a victim, score, map the attacker,
take it down — each animated on the page with what BrandWatch actually recorded (the brand's
fingerprint, its candidates, a cloaked kit's screenshots, its signals, the infrastructure graph and
the takedown). A workspace with nothing yet gets a clearly labelled illustration instead, so the
page always tells the story. Read-only: nothing here writes or calls a provider.
"""

from __future__ import annotations

import math
from typing import Any

import sqlalchemy as sa
from sqlalchemy.orm import Session

from brandwatch.db.enums import FindingState
from brandwatch.db.models import (
    Brand,
    BrandFingerprint,
    Campaign,
    Candidate,
    CandidateSource,
    Finding,
    RiskScore,
    TakedownDraft,
    User,
)

MAX_GRAPH_NODES = 14
MAX_SIGNALS = 7

# Shown only when the workspace has no data for a chapter (an empty live workspace).
EXAMPLE: dict[str, Any] = {
    "brand": {"name": "ShopNova", "domain": "shopnova.com", "palette": ["#2b6cb0", "#f6ad55", "#1a202c", "#e2e8f0"],
              "keywords": ["shopnova", "shop", "orders", "deals"], "queries": ["shopnova login", "shopnova support", "shopnova app"],
              "favicon_mmh3": -1189322473, "login_form": True, "screenshot": None},
    "candidates": [
        {"host": "shopn0va.com", "streams": ["Typo permutation"], "flag": "critical"},
        {"host": "shopnova-login.com", "streams": ["Certificate logs"], "flag": "high"},
        {"host": "secure-shopnova.com", "streams": ["New domains"], "flag": "high"},
        {"host": "shopnova-support.net", "streams": ["Google results"], "flag": "medium"},
        {"host": "shoqnova.com", "streams": ["Typo permutation"], "flag": None},
        {"host": "shopnova.co", "streams": ["Typo permutation"], "flag": None},
    ],
    "signals": [
        {"label": "Brand name inside the domain", "group": "Identity", "points": 12},
        {"label": "Same favicon as the brand", "group": "Visual", "points": 14},
        {"label": "Homepage looks ≥ 90% the same", "group": "Visual", "points": 12},
        {"label": "Asks for a password", "group": "Behaviour", "points": 10},
        {"label": "Domain registered < 7 days ago", "group": "Freshness", "points": 8},
        {"label": "Shows scanners a different page", "group": "Evasion", "points": 14},
    ],
}  # fmt: skip


def _brand(session: Session, user: User) -> Brand | None:
    return session.scalars(
        sa.select(Brand).where(Brand.workspace_id == user.workspace_id)
        .order_by((Brand.name == "ShopNova").desc(), Brand.created_at)
    ).first()  # fmt: skip


def _fingerprint(session: Session, brand: Brand) -> dict[str, Any]:
    from brandwatch.detection.baseline import brand_key_for, official_domains

    fp = session.scalars(
        sa.select(BrandFingerprint).where(BrandFingerprint.brand_id == brand.id)
        .order_by(BrandFingerprint.version.desc())
    ).first()  # fmt: skip
    domains = official_domains(session, brand.id)
    out = {"name": brand.name, "id": str(brand.id), "key": brand_key_for(brand, session),
           "domain": domains[0] if domains else None, "illustrative": fp is None}  # fmt: skip
    if fp is None:
        return {**EXAMPLE["brand"], **{k: v for k, v in out.items() if v}, "illustrative": True}
    llm = fp.llm_analysis or {}
    feats = fp.features or {}
    out.update({
        "version": fp.version,
        "favicon_mmh3": fp.favicon_mmh3,
        "palette": list(((fp.colors or {}).get("palette") or [])[:6]),
        "keywords": list(((fp.keywords or {}).get("terms") or [])[:6]),
        "queries": _queries(session, brand)[:3],
        "lures": list((llm.get("lures") or [])[:2]),
        "login_form": bool(feats.get("has_login_form")),
        "login_fields": [x for x in feats.get("login_signature") or [] if x.startswith("input")],
        "auth_pages": len(feats.get("auth_pages") or []),
        "screenshot": f"/api/brands/{brand.id}/baseline/screenshot" if (fp.screenshots or {}).get("home") else None,
        "favicon": f"/api/brands/{brand.id}/baseline/favicon" if fp.favicon_mmh3 is not None else None,
    })  # fmt: skip
    return out


def _queries(session: Session, brand: Brand) -> list[str]:
    """The Google queries scans really use: the approved list, else the (cleaned) AI proposal."""
    from brandwatch import tenancy
    from brandwatch.detection.baseline import load_baseline
    from brandwatch.detection.search_queries import query_state

    cfg = tenancy.effective_brand_config(session, brand.id)
    return query_state(brand, cfg.detection, load_baseline(session, brand)).queries


def _candidates(session: Session, brand: Brand) -> dict[str, Any]:
    from brandwatch.api.findings import unicode_host
    from brandwatch.api.labels import stream_label

    total = (
        session.scalar(sa.select(sa.func.count(Candidate.id)).where(Candidate.brand_id == brand.id))
        or 0
    )
    by_stream = dict(session.execute(
        sa.select(CandidateSource.source, sa.func.count(sa.distinct(CandidateSource.candidate_id)))
        .join(Candidate, Candidate.id == CandidateSource.candidate_id)
        .where(Candidate.brand_id == brand.id).group_by(CandidateSource.source)
    ).all())  # fmt: skip
    if not total:
        return {"total": 0, "streams": [], "rows": EXAMPLE["candidates"], "illustrative": True}
    # the most telling rows first: sites that became findings, then the rest by most recent
    sev = dict(session.execute(
        sa.select(Finding.candidate_id, Finding.severity).where(Finding.brand_id == brand.id,
                                                                Finding.state != FindingState.DISMISSED)
    ).all())  # fmt: skip
    cands = session.scalars(
        sa.select(Candidate).where(Candidate.brand_id == brand.id).order_by(Candidate.first_seen.desc()).limit(300)
    ).all()  # fmt: skip
    srcs: dict[Any, set[str]] = {}
    for cid, src in session.execute(
        sa.select(CandidateSource.candidate_id, CandidateSource.source)
        .where(CandidateSource.candidate_id.in_([c.id for c in cands]))
    ).all():  # fmt: skip
        srcs.setdefault(cid, set()).add(getattr(src, "value", str(src)))
    manual = "manual"

    def streams_of(
        c,
    ):  # the discovery stream that found it; "analyst URL scan" only when nothing else did
        found = srcs.get(c.id, set())
        return sorted(stream_label(x) for x in (found - {manual} or found))

    def lookalike(c):  # rows a visitor reads as "a copy of the brand", not unrelated test URLs
        from rapidfuzz.distance import Levenshtein

        from brandwatch.detection.discovery import split_host

        sld = split_host(c.hostname).sld or ""
        key = brand_key or ""
        return bool(key) and (
            key in sld or Levenshtein.distance(sld, key) <= 2 or c.hostname.startswith("xn--")
        )

    from brandwatch.detection.baseline import brand_key_for

    brand_key = brand_key_for(brand, session)
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    seen: set[str] = set()
    pool = []
    for c in cands:  # one row per host, look-alikes only
        if c.hostname not in seen and lookalike(c):
            seen.add(c.hostname)
            pool.append(c)

    def rank(c):  # found by a discovery stream first, then by severity
        return (
            not (srcs.get(c.id, set()) - {manual}),
            order.get(getattr(sev.get(c.id), "value", ""), 9),
        )

    flagged = sorted((c for c in pool if c.id in sev), key=rank)
    watched = sorted((c for c in pool if c.id not in sev), key=rank)
    picked = flagged[:5] + watched[:3]
    picked += [c for c in flagged[5:] + watched[3:]][: 8 - len(picked)]
    rows = [{"host": unicode_host(c.hostname), "streams": streams_of(c),
             "flag": getattr(sev.get(c.id), "value", None)} for c in picked]  # fmt: skip
    streams = sorted(((stream_label(s), n) for s, n in by_stream.items()), key=lambda x: -x[1])
    return {"total": total, "streams": streams, "rows": rows, "illustrative": False}


def _pick_finding(session: Session, brand: Brand) -> Finding | None:
    """A cloaked kit whose scanner view was captured (the best story), else any cloaked kit, else the
    highest-scoring open / confirmed finding."""
    rows = session.execute(
        sa.select(Finding, RiskScore.signals)
        .join(RiskScore, sa.and_(RiskScore.finding_id == Finding.id, RiskScore.is_current.is_(True)))
        .where(Finding.brand_id == brand.id, Finding.state != FindingState.DISMISSED)
        .order_by(RiskScore.score.desc())
    ).all()  # fmt: skip
    cloaked = [f for f, sigs in rows if any(k.startswith("cloaking_") for k in (sigs or {}))]
    if cloaked:
        from brandwatch.api.findings import finding_detail

        both = next(
            (
                f
                for f in cloaked[:6]
                if finding_detail(session, f)["screenshots"].get("scanner_url")
            ),
            None,
        )
        return both or cloaked[0]
    return rows[0][0] if rows else None


def _finding(session: Session, f: Finding | None) -> dict[str, Any] | None:
    if f is None:
        return None
    from brandwatch.api.findings import finding_detail, unicode_host
    from brandwatch.api.labels import group_label, signal_label

    d = finding_detail(session, f)
    s = d["score"] or {}
    sigs = sorted(s.get("signals") or [], key=lambda x: -x["points"])
    th = s.get("thresholds") or {}
    cl = s.get("cloaking") or {}
    return {
        "id": str(f.id), "host": unicode_host(d["candidate"]["hostname"]), "url": f"/ui/findings/{f.id}",
        "severity": s.get("severity"), "score": s.get("score"), "confidence": round(s.get("confidence") or 0),
        "summary": s.get("summary"), "age_days": s.get("age_days"), "cloaked": bool(s.get("cloaked")),
        "revealed_by": cl.get("revealed_by"),
        "signals": [{"label": signal_label(x["name"]), "group": group_label(x["group"]), "points": int(x["points"]),
                     "detail": x.get("detail") or ""} for x in sigs[:MAX_SIGNALS]],
        "more_signals": max(0, len(sigs) - MAX_SIGNALS),
        "groups_fired": len({x["group"] for x in sigs}),
        "thresholds": {"medium": th.get("medium", 30), "high": th.get("high", 55), "critical": th.get("critical", 75)},
        "rule": (s.get("rules_fired") or [{}])[0].get("rule"),
        "shots": d["screenshots"],
    }  # fmt: skip


def _layout(
    ids: list[str], seed: str, links: list[tuple[str, str]], w: float = 520, h: float = 340
) -> dict[str, tuple[float, float]]:
    """Radial tree: the seed in the centre, each depth on its own ring, every subtree in an angular
    wedge as wide as its number of leaves — no overlaps, same picture every time."""
    kids: dict[str, list[str]] = {n: [] for n in ids}
    for a, b in links:
        kids[a].append(b)
    depth = {seed: 0}
    for n in ids:  # ids are in BFS order
        for k in kids[n]:
            depth[k] = depth[n] + 1
    leaves: dict[str, int] = {}

    def count(n: str) -> int:
        leaves[n] = sum(count(k) for k in kids[n]) or 1
        return leaves[n]

    count(seed)
    deepest = max(depth.values()) or 1
    rx, ry = (w / 2 - 44) / deepest, (h / 2 - 26) / deepest
    pos = {seed: (w / 2, h / 2)}

    def place(n: str, lo: float, hi: float) -> None:
        start = lo
        for k in kids[n]:
            span = (hi - lo) * leaves[k] / leaves[n]
            a = start + span / 2
            pos[k] = (w / 2 + rx * depth[k] * math.cos(a), h / 2 + ry * depth[k] * math.sin(a))
            place(k, start, start + span)
            start += span

    place(seed, -math.pi / 2, 3 * math.pi / 2)
    return pos


def _graph(session: Session, brand: Brand) -> dict[str, Any] | None:
    """A readable slice of the latest attack-infrastructure map, laid out in rings around the seed."""
    from brandwatch.detection.investigation import EDGE_LABELS, campaign_out

    camp = session.scalars(
        sa.select(Campaign).where(Campaign.brand_id == brand.id).order_by(Campaign.created_at.desc())
    ).first()  # fmt: skip
    if camp is None:
        return None
    c = campaign_out(session, camp)
    nodes = {n["id"]: n for n in c["nodes"]}
    adj: dict[str, list[tuple[str, str]]] = {}
    for e in c["edges"]:
        adj.setdefault(e["source"], []).append((e["target"], e["type"]))
        adj.setdefault(e["target"], []).append((e["source"], e["type"]))
    # the map starts from the confirmed site it was built from: the best-connected confirmed domain
    hubs = [
        n["id"] for n in c["nodes"] if n["type"] == "domain" and n["included"] and n["id"] in adj
    ]
    confirmed = [h for h in hubs if (nodes[h].get("finding") or {}).get("state") == "confirmed"]
    seed = max(confirmed or hubs or list(adj), key=lambda k: len(adj[k]), default=None)
    if seed is None:
        return None
    # BFS: the seed, its neighbours, then a few of theirs — included nodes first
    keep, level, parent = [seed], {seed: 0}, {}
    frontier = [seed]
    while frontier and len(keep) < MAX_GRAPH_NODES:
        nxt = []
        for nid in frontier:
            neigh = sorted(
                adj.get(nid, []),
                key=lambda t: (not nodes[t[0]]["included"], nodes[t[0]]["type"] != "domain"),
            )
            cap = 6 if nid == seed else 3
            for other, etype in neigh[:cap]:
                if other in level or len(keep) >= MAX_GRAPH_NODES:
                    continue
                level[other], parent[other] = level[nid] + 1, (nid, etype)
                keep.append(other)
                nxt.append(other)
        frontier = nxt
    # one dropped node, so the page can show that noise is triaged out with a reason
    dropped = next(
        (
            n
            for n in c["nodes"]
            if not n["included"] and n["triage_reason"] and n["id"] not in level
        ),
        None,
    )
    if dropped and len(keep) < MAX_GRAPH_NODES + 1:
        anchor = next((t for t, _ in adj.get(dropped["id"], []) if t in level), seed)
        level[dropped["id"]], parent[dropped["id"]] = level[anchor] + 1, (anchor, "passive_dns")
        keep.append(dropped["id"])
    pos = _layout(keep, seed, [(parent[n][0], n) for n in keep if n in parent])
    out_nodes = []
    for i, nid in enumerate(keep):
        n = nodes[nid]
        x, y = pos[nid]
        out_nodes.append({
            "x": round(x, 1), "y": round(y, 1), "i": i,
            "type": n["type"], "value": n["value"] if len(n["value"]) <= 26 else n["value"][:24] + "…",
            "included": n["included"], "reason": n["triage_reason"], "seed": nid == seed,
            "flag": (n.get("finding") or {}).get("severity"),
        })  # fmt: skip
    idx = {nid: i for i, nid in enumerate(keep)}
    out_edges = [{"a": idx[parent[nid][0]], "b": idx[nid], "label": EDGE_LABELS.get(parent[nid][1], parent[nid][1]), "i": idx[nid]}
                 for nid in keep if nid in parent]  # fmt: skip
    return {"id": c["id"], "url": f"/ui/campaigns/{c['id']}", "nodes": out_nodes, "edges": out_edges, "illustrative": False,
            "stats": c["stats"], "findings": len(c["findings"]), "dropped_reason": dropped["triage_reason"].split(";")[0] if dropped else None}  # fmt: skip


def _takedown(session: Session, brand: Brand) -> dict[str, Any] | None:
    from brandwatch.detection import takedown_channels as tc

    draft = session.scalars(
        sa.select(TakedownDraft).join(Finding, Finding.id == TakedownDraft.finding_id)
        .where(Finding.brand_id == brand.id).order_by(TakedownDraft.updated_at.desc())
    ).first()  # fmt: skip
    if draft is None:
        return None
    res = (
        tc.ensure_channels(session, draft, persist=False).get("resolved") or {}
    )  # a GET never writes
    reg, cdn, hosting = res.get("registrar") or {}, res.get("cdn") or {}, res.get("hosting") or []
    cand = session.get(Candidate, session.get(Finding, draft.finding_id).candidate_id)
    body = [ln.strip() for ln in (draft.body or "").splitlines()
            if ln.strip() and not ln.lower().startswith(("to:", "subject:"))][:5]  # fmt: skip
    return {
        "url": f"/ui/takedowns/{draft.id}", "reference": draft.reference, "state": draft.state.value,
        "host": cand.hostname if cand else None, "subject": tc.subject_for(draft, session), "body": body,
        "channels": [
            {"k": "Registrar", "who": reg.get("name") or draft.registrar or "registrar", "to": reg.get("email") or draft.abuse_contact},
            {"k": "Hosting", "who": (hosting[0].get("org") or hosting[0].get("desk") or hosting[0].get("ip")) if hosting else "hosting provider",
             "to": hosting[0].get("email") if hosting else None},
            {"k": "CDN", "who": cdn.get("name") or "CDN / DNS provider", "to": cdn.get("email")},
        ],
    }  # fmt: skip


def _example_graph(brand_name: str) -> dict[str, Any]:
    """The illustration used before any attack infrastructure was mapped."""
    k = brand_name.lower().replace(" ", "")
    spec = [  # id, type, label, included, parent, edge
        ("s", "domain", f"{k}-login.com", True, None, None),
        ("ip1", "ip", "203.0.113.66", True, "s", "passive_dns"), ("cert", "certificate", "TLS certificate", True, "s", "cert"),
        ("trk", "tracking_id", "UA-424242-1", True, "s", "tracking_id"), ("reg", "registrant", "same registrant", True, "s", "reverse_whois"),
        ("d1", "domain", f"secure-{k}.com", True, "ip1", "passive_dns"), ("d2", "domain", f"{k}-verify.net", True, "ip1", "passive_dns"),
        ("d3", "domain", "bakery-menu.example", False, "ip1", "passive_dns"), ("d4", "domain", f"{k}-refund.net", True, "cert", "cert"),
        ("d5", "domain", f"{k}-support.com", True, "trk", "tracking_id"), ("d6", "domain", f"my-{k}.co", True, "reg", "reverse_whois"),
    ]  # fmt: skip
    from brandwatch.detection.investigation import EDGE_LABELS

    ids = [x[0] for x in spec]
    pos = _layout(ids, "s", [(x[4], x[0]) for x in spec if x[4]])
    nodes = [{"x": round(pos[i][0], 1), "y": round(pos[i][1], 1), "i": n, "type": t, "value": v, "included": inc,
              "reason": None if inc else "co-hosted neighbour without link signals (reverse-IP noise)", "seed": i == "s",
              "flag": "critical" if t == "domain" and inc else None} for n, (i, t, v, inc, _p, _e) in enumerate(spec)]  # fmt: skip
    idx = {x[0]: n for n, x in enumerate(spec)}
    edges = [
        {"a": idx[x[4]], "b": idx[x[0]], "label": EDGE_LABELS.get(x[5], x[5]), "i": idx[x[0]]}
        for x in spec
        if x[4]
    ]
    return {"id": None, "url": None, "nodes": nodes, "edges": edges, "stats": {"nodes": 11, "included": 10, "excluded": 1, "edges": 10},
            "findings": 6, "dropped_reason": "co-hosted neighbour without link signals (reverse-IP noise)", "illustrative": True}  # fmt: skip


def story(session: Session, user: User) -> dict[str, Any]:
    from brandwatch.detection.takedown_channels import PORTAL_GROUPS, REPORT_PORTALS

    portals = [{"name": p["name"], "group": p["group"]} for p in REPORT_PORTALS]
    groups = [
        {"key": k, "label": (v if isinstance(v, str) else v[0])} for k, v in PORTAL_GROUPS.items()
    ]
    brand = _brand(session, user)
    if brand is None:
        return {"brand": {**EXAMPLE["brand"], "illustrative": True},
                "candidates": {"total": 0, "streams": [], "rows": EXAMPLE["candidates"], "illustrative": True},
                "finding": None, "graph": _example_graph(EXAMPLE["brand"]["name"]), "takedown": None,
                "portals": portals, "portal_groups": groups, "example": EXAMPLE}  # fmt: skip
    f = _pick_finding(session, brand)
    fd = _finding(session, f)
    return {
        "brand": _fingerprint(session, brand),
        "candidates": _candidates(session, brand),
        "finding": fd,
        "graph": _graph(session, brand) or _example_graph(brand.name),
        "takedown": _takedown(session, brand),
        "portals": portals, "portal_groups": groups, "example": EXAMPLE,
    }  # fmt: skip



# ------------------------------------------------------------------------------ the flow diagram
def flow(session: Session, user: User) -> dict[str, int]:
    """The live numbers on the How-it-works flow diagram, for the whole workspace."""
    from brandwatch.db.enums import TakedownState

    ws = user.workspace_id
    brands = sa.select(Brand.id).where(Brand.workspace_id == ws)

    def count(q: Any) -> int:
        return int(session.scalar(q) or 0)

    findings = sa.select(sa.func.count()).select_from(Finding).where(Finding.brand_id.in_(brands))
    sent = (TakedownState.SENT, TakedownState.ACKNOWLEDGED, TakedownState.IN_PROGRESS, TakedownState.RESOLVED)
    return {
        "lookalikes": count(sa.select(sa.func.count()).select_from(Candidate).where(Candidate.brand_id.in_(brands),
                                                                                     Candidate.canonical_domain != "ai-answer")),
        "findings": count(findings),
        "confirmed": count(findings.where(Finding.state == FindingState.CONFIRMED)),
        "social": count(findings.where(Finding.kind == "social")),
        "ai": count(findings.where(Finding.kind == "ai_answer")),
        "networks": count(sa.select(sa.func.count()).select_from(Campaign).where(Campaign.brand_id.in_(brands))),
        "takedowns": count(sa.select(sa.func.count()).select_from(TakedownDraft).join(Finding, Finding.id == TakedownDraft.finding_id)
                           .where(Finding.brand_id.in_(brands), TakedownDraft.state.in_(sent))),
        "drafted": count(sa.select(sa.func.count()).select_from(TakedownDraft).join(Finding, Finding.id == TakedownDraft.finding_id)
                         .where(Finding.brand_id.in_(brands))),
    }  # fmt: skip


def by_numbers(session: Session, user: User) -> dict[str, Any]:
    """"By the numbers" on How it works: per discovery source, how many domains it brought, how many became suspects
    (a finding) and how many an analyst confirmed; then the takedowns. A domain found by two sources counts in both."""
    from brandwatch.api.labels import source_badges
    from brandwatch.db.enums import TakedownState
    from brandwatch.db.models import CandidateSource, TakedownDraft

    brands = sa.select(Brand.id).where(Brand.workspace_id == user.workspace_id)
    per: dict[str, dict[str, Any]] = {}

    def add(rows: Any, key: str) -> None:
        for src, n in rows:
            b = source_badges([src])[0]
            row = per.setdefault(b["g"], {"g": b["g"], "label": b["label"], "glyph": str(b["glyph"]), "examined": 0, "suspects": 0, "confirmed": 0})
            row[key] += int(n)

    base = sa.select(CandidateSource.source, sa.func.count(sa.distinct(Candidate.id))).join(Candidate, Candidate.id == CandidateSource.candidate_id)
    add(session.execute(base.where(Candidate.brand_id.in_(brands)).group_by(CandidateSource.source)).all(), "examined")
    fbase = (
        sa.select(CandidateSource.source, sa.func.count(sa.distinct(Finding.id)))
        .join(Candidate, Candidate.id == CandidateSource.candidate_id)
        .join(Finding, Finding.candidate_id == Candidate.id)
        .where(Candidate.brand_id.in_(brands))
    )
    add(session.execute(fbase.group_by(CandidateSource.source)).all(), "suspects")
    add(session.execute(fbase.where(Finding.state == FindingState.CONFIRMED).group_by(CandidateSource.source)).all(), "confirmed")
    sources = sorted((r for r in per.values() if r["examined"]), key=lambda r: (-r["confirmed"], -r["suspects"], -r["examined"]))
    f = flow(session, user)
    resolved = int(
        session.scalar(
            sa.select(sa.func.count()).select_from(TakedownDraft).join(Finding, Finding.id == TakedownDraft.finding_id)
            .where(Finding.brand_id.in_(brands), TakedownDraft.state == TakedownState.RESOLVED)
        ) or 0
    )  # fmt: skip
    return {
        "sources": sources,
        "totals": {"examined": f["lookalikes"], "suspects": f["findings"], "confirmed": f["confirmed"], "networks": f["networks"],
                   "drafted": f["drafted"], "sent": f["takedowns"], "resolved": resolved},
    }  # fmt: skip


def one_case(session: Session, user: User) -> dict[str, Any] | None:
    """"One real case": the life of one confirmed site, from its registration to the takedown, with the real times.
    The case that went furthest is chosen (a takedown sent, a map of the attacker, a draft, the highest score)."""
    from brandwatch.api.labels import source_badges
    from brandwatch.db.models import (
        AuditEvent,
        Campaign,
        CandidateSource,
        Evidence,
        Observation,
        TakedownDraft,
        WhoisObservation,
    )

    brands = sa.select(Brand.id).where(Brand.workspace_id == user.workspace_id)
    rows = session.execute(
        sa.select(Finding, Candidate).join(Candidate, Candidate.id == Finding.candidate_id)
        .where(Finding.brand_id.in_(brands), Finding.state == FindingState.CONFIRMED, Finding.kind != "ai_answer")
    ).all()  # fmt: skip
    if not rows:
        return None
    ids = [f.id for f, _ in rows]
    drafts = {d.finding_id: d for d in session.scalars(sa.select(TakedownDraft).where(TakedownDraft.finding_id.in_(ids)).order_by(TakedownDraft.created_at)).all()}

    def rank(fc: Any) -> tuple:
        fi = fc[0]
        d = drafts.get(fi.id)
        sc = fi.current_score
        return (1 if d and d.sent_at else 0, 1 if fi.campaign_id else 0, 1 if d else 0, float(sc.score) if sc else 0.0)

    f, c = max(rows, key=rank)
    brand = session.get(Brand, f.brand_id)
    bname = brand.name if brand else "the brand"
    steps: list[dict[str, Any]] = []
    reg = session.scalar(
        sa.select(WhoisObservation.registered_at).join(Evidence, Evidence.id == WhoisObservation.evidence_id)
        .where(Evidence.candidate_id == c.id, WhoisObservation.registered_at.is_not(None)).order_by(Evidence.observed_at).limit(1)
    )  # fmt: skip
    if reg:
        steps.append({"k": "registered", "at": f"{reg.isoformat()}T00:00:00+00:00", "day_only": True, "title": "The domain is bought",
                      "text": f"{c.hostname} is registered, a name that carries {bname}."})  # fmt: skip
    srcs = session.scalars(sa.select(CandidateSource.source).where(CandidateSource.candidate_id == c.id)).all()
    badges = source_badges(list(srcs), limit=4)
    steps.append({"k": "found", "at": c.first_seen.isoformat(), "title": "BrandWatch finds it",
                  "text": "Found by " + (", ".join(b["label"] for b in badges) or "a scan") + ".",
                  "icons": [{"g": b["g"], "glyph": str(b["glyph"]), "label": b["label"]} for b in badges]})  # fmt: skip
    visits = int(session.scalar(sa.select(sa.func.count()).select_from(Observation).where(Observation.candidate_id == c.id)) or 0)
    sc = f.current_score
    parts = [f"Risk {int(sc.score)}/100" if sc else "Scored", f.severity.value]
    if sc and sc.signals:
        parts.append(f"{len(sc.signals)} signals")
    if visits:
        parts.append(f"{visits} visit{'s' if visits != 1 else ''}")
    steps.append({"k": "scored", "at": f.created_at.isoformat(), "title": "Visited like a victim, scored", "text": " · ".join(parts),
                  "score": int(sc.score) if sc else None, "severity": f.severity.value})  # fmt: skip
    conf = session.scalar(sa.select(AuditEvent.at).where(AuditEvent.action == "finding.confirmed", AuditEvent.object_id == f.id).order_by(AuditEvent.at).limit(1))
    steps.append({"k": "confirmed", "at": (conf or f.updated_at).isoformat(), "title": "An analyst confirms it",
                  "text": "Confirmed as phishing: a person decided, with the evidence in front of them."})  # fmt: skip
    if f.campaign_id:
        camp = session.get(Campaign, f.campaign_id)
        sisters = int(session.scalar(sa.select(sa.func.count()).select_from(Finding).where(Finding.campaign_id == f.campaign_id)) or 0)
        if camp:
            steps.append({"k": "mapped", "at": camp.created_at.isoformat(), "title": "The attacker is mapped", "href": f"/ui/campaigns/{camp.id}",
                          "text": f"Its servers, certificates and owners are followed: {sisters} confirmed site{'s' if sisters != 1 else ''} on the same map."})  # fmt: skip
    d = drafts.get(f.id)
    if d:
        steps.append({"k": "drafted", "at": d.created_at.isoformat(), "title": "The takedown is drafted", "href": f"/ui/takedowns/{d.id}",
                      "text": f"Request {d.reference or ''} to {d.registrar or 'the registrar'}, with the evidence attached."})  # fmt: skip
        if d.sent_at:
            steps.append({"k": "sent", "at": d.sent_at.isoformat(), "title": "Sent to the people who can pull it", "href": f"/ui/takedowns/{d.id}",
                          "text": f"Sent to {d.abuse_contact or 'the abuse contact'}."})  # fmt: skip
        if d.resolved_at:
            steps.append({"k": "resolved", "at": d.resolved_at.isoformat(), "title": "Taken down", "text": "The site is gone."})
    for s in steps:  # SQLite returns naive datetimes: they are UTC
        if "+" not in s["at"][10:] and not s["at"].endswith("Z"):
            s["at"] += "+00:00"
    steps.sort(key=lambda s: s["at"])
    return {"host": c.hostname, "brand": bname, "finding_id": str(f.id), "steps": steps}
