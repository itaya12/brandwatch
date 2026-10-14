"""A look-alike that ends on the brand's own site is not a phishing page, and is still not harmless.

A typo domain whose visitors end up on the real site looked like "the brand's own defensive registration". Often it is not: the
link on the way carries an *affiliate id* (the commission of everything the visitor buys goes to a stranger), or it goes through a
*third-party redirect host* (a short link, a traffic broker) that can send the visitor anywhere tomorrow. This module reads the
chain of a visit and says which of the three it is; ``analysis`` uses it for new scans and ``reassess`` for the findings that are
already saved (from the stored evidence, without touching the network).
"""

from __future__ import annotations

import re
import uuid
from dataclasses import dataclass, field
from urllib.parse import parse_qsl, urlsplit

import sqlalchemy as sa
from sqlalchemy.orm import Session

from brandwatch.config.brand_config import ScoringConfig
from brandwatch.db.enums import EvidenceType, FindingState
from brandwatch.db.models import AuditEvent, Brand, Candidate, Evidence, Finding, RiskScore, User
from brandwatch.detection import scoring
from brandwatch.detection.discovery import split_host
from brandwatch.pipeline.stages import AnalysisResult

# the query parameters of a link to the brand's OWN site that name who gets the commission (?atid=70321, ?ref=partner7, ?aff_id=…)
AFFILIATE = re.compile(r"^(atid|aff\w*|a_aid|aid|pid|partner\w*|ref|refid|ref_id|referr?al\w*|clickref|irclickid|ranmid|tid|cid|sid)$", re.I)
# what a visit that ends on the brand's own site no longer deserves: the page content is the real site's, not a copy
COPIED_FROM_REAL_SITE = ("looks_like_brand_ge_85", "brand_tld_swap", "title_claims_brand")


def on(host: str, domains: set[str]) -> bool:
    host = host.lower().rstrip(".")
    return any(host == d or host.endswith("." + d) for d in domains)


def registrable(host: str) -> str:
    reg = split_host(host).registrable
    return reg if reg and "." in reg else host  # a name with a suffix nobody knows (.example, an internal name) stays whole


def host_of(url: str) -> str:
    return (urlsplit(url).hostname or "").lower()


def affiliate_ids(hops: list[str], own: set[str], site: str) -> list[str]:
    """The affiliate parameters of every link to the brand's own site in a redirect chain: the visitor reaches the real shop, and the
    commission of whatever the visitor buys goes to the owner of the id."""
    out: list[str] = []
    for hop in hops:
        parts = urlsplit(hop)
        host = (parts.hostname or "").lower()
        if not host or host == site or not on(host, own):
            continue
        for k, v in parse_qsl(parts.query):
            if AFFILIATE.match(k) and len(v) >= 3 and site not in v.lower() and f"{k.lower()}={v}" not in out:
                out.append(f"{k.lower()}={v}")
    return out


@dataclass(slots=True)
class RedirectFacts:
    ends_on_brand: bool = False
    affiliate: list[str] = field(default_factory=list)
    via: list[str] = field(default_factory=list)  # third-party hosts the visit went through on the way
    landing: str | None = None


def facts(site: str, chain: list[str], final_url: str | None, own: set[str], *, saved: bool = False) -> RedirectFacts:
    """``chain``: the addresses the visit was sent away from; ``final_url``: where it ended. ``saved``: evidence stored before the fetcher
    reported where the page really ended (it used to name the first document, not the last): then the last address of the chain is
    the landing page if it is the brand's."""
    urls = [*(u for u in chain if u), *([final_url] if final_url else [])]
    land = host_of(final_url) if final_url else ""
    if saved and chain and not on(land, own) and on(host_of(chain[-1]), own):
        land = host_of(chain[-1])
    out = RedirectFacts(landing=land or None)
    if not land or not on(land, own) or on(site, own):
        return out
    out.ends_on_brand = True
    out.affiliate = affiliate_ids(urls, own, site)
    mine = registrable(site)
    for u in urls:
        h = host_of(u)
        reg = registrable(h) if h else ""
        if h and not on(h, own) and reg != mine and reg not in out.via:
            out.via.append(reg)
    return out


# ------------------------------------------------------------------------------------------ the findings that are already saved
def _own_domains(session: Session, brand_id: uuid.UUID) -> set[str]:
    from brandwatch.detection.baseline import whitelist_domains

    return {d.lower() for d in whitelist_domains(session, brand_id)}


def reassess(session: Session, brand_id: uuid.UUID, cfg: ScoringConfig, *, actor: User | None) -> list[dict[str, str]]:
    """Look again, from the stored evidence only, at the open findings whose visit ended on the brand's own site: take away the signals that
    only came from that page being the real one (a 100% look-alike of the brand, the brand's title), and add what the chain shows (an affiliate
    id, a third-party redirect host). The finding gets a new score row (history kept); nothing is fetched."""
    brand = session.get(Brand, brand_id)
    own = _own_domains(session, brand_id)
    out: list[dict[str, str]] = []
    rows = session.execute(
        sa.select(Finding, RiskScore, Candidate)
        .join(RiskScore, sa.and_(RiskScore.finding_id == Finding.id, RiskScore.is_current.is_(True)))
        .join(Candidate, Candidate.id == Finding.candidate_id)
        .where(Finding.brand_id == brand_id, Finding.state != FindingState.DISMISSED, sa.or_(Finding.kind == "phishing", Finding.kind.is_(None)))
    ).all()
    for f, rs, cand in rows:
        chain: list[str] = []
        final = None
        for ev in session.scalars(sa.select(Evidence).where(Evidence.candidate_id == cand.id, Evidence.type == EvidenceType.HTTP, Evidence.source_type == "http")
                                  .order_by(Evidence.observed_at.desc())).all():  # fmt: skip
            meta = ev.response_meta or {}
            chain = [str(u) for u in (meta.get("redirect_chain") or [])]
            final = meta.get("final_url")
            break
        rf = facts(cand.hostname, chain, final, own, saved=True)
        if not rf.ends_on_brand:
            continue
        sig = dict(rs.signals or {})
        details = dict(sig.get("_details", {}))
        names = [k for k in sig if not k.startswith("_") and cfg.weights.get(k, 0) > 0 and k not in COPIED_FROM_REAL_SITE]
        fp = [x for x in sig.get("_fp_flags", []) if x != "redirects_to_official"] + ["redirects_to_official"]  # the page captured is the real site's: its look is not counted
        if rf.affiliate:
            names.append("affiliate_redirect")
            details["affiliate_redirect"] = f"the visit ends on the brand's own site after a link with {', '.join(rf.affiliate)}: the commission goes to the owner of that id"
        if rf.via:
            names.append("redirect_via_third_party")
            details["redirect_via_third_party"] = f"the visit goes through {', '.join(rf.via)} on its way to the brand's own site: the destination can be changed at any time"
        details["redirects_to_official"] = (f"ends on the brand's own site ({rf.landing}), so the page is the real one and its look is not counted"
                                            + (" — an affiliate id or a third-party redirect host in the chain is still rated" if rf.affiliate or rf.via else " — likely the brand's own registration"))
        unavailable = tuple(sig.get("_unavailable", []))
        an = AnalysisResult(
            signals={n: float(cfg.weights[n]) for n in dict.fromkeys(names) if cfg.weights.get(n, 0) > 0}, evidence_refs=(), unavailable=unavailable, fp_flags=tuple(fp),
            details={"signals": details, "screenshot_captured": "screenshot" not in unavailable, "html_captured": "http" not in unavailable, "whois_age_days": None if "whois" in unavailable else 0,
                     "reputation_positives": sum(1 for n in names if n in ("vt_flagged", "urlhaus_listed", "phishtank_listed", "safe_browsing", "known_phishing"))},
        )  # fmt: skip
        new = scoring.score(an, cfg)
        if new.severity == rs.severity and set(new.signals) == {k for k in sig if not k.startswith("_")}:
            continue
        old_breakdown = dict((rs.groups or {}).get("_breakdown", {}))
        breakdown = {**new.breakdown, **{k: old_breakdown[k] for k in ("ai", "ml", "cloaking") if k in old_breakdown}, "rescored_from": rs.scoring_version,
                     "reassessed": "the visit ends on the brand's own site"}  # fmt: skip
        session.execute(sa.update(RiskScore).where(RiskScore.id == rs.id).values(is_current=False))
        session.add(RiskScore(
            finding_id=f.id, is_current=True, score=new.score, raw_score=new.raw, severity=new.severity, confidence=rs.confidence, scoring_version=cfg.version,
            signals={**new.signals, "_details": details, "_unavailable": list(unavailable), "_fp_flags": list(fp),
                     **{k: sig[k] for k in ("_scanner_block", "_snapshot", "_security_warning", "_challenge", "_redirected_from", "_clickfix", "_no_picture") if sig.get(k)}},
            groups={**new.groups, "_breakdown": breakdown},
        ))  # fmt: skip
        old_sev = f.severity
        f.severity = new.severity
        session.add(AuditEvent(workspace_id=brand.workspace_id, actor_type="analyst" if actor else "system", actor_id=actor.id if actor else None, action="finding.reassessed",
                               object_type="finding", object_id=f.id, old_value={"score": rs.score, "severity": old_sev.value, "version": rs.scoring_version},
                               new_value={"score": new.score, "severity": new.severity.value, "version": cfg.version},
                               reason="the visit ends on the brand's own site" + (f" with {', '.join(rf.affiliate)}" if rf.affiliate else "") + (f" via {', '.join(rf.via)}" if rf.via else "")))  # fmt: skip
        out.append({"hostname": cand.hostname, "before": old_sev.value, "after": new.severity.value, "affiliate": ", ".join(rf.affiliate), "via": ", ".join(rf.via)})
    session.flush()
    return out
