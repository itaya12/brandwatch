"""Finding stage (spec §3 stage 8) + analyst verdicts.

* Score ≥ ``finding_min_severity`` → create/update the candidate's open Finding, append a
  ``risk_scores`` row (flipping the previous ``is_current``), link evidence with roles, and flag
  the candidate. Below the threshold → the candidate goes to the watchlist (no Finding).
* ``confirm`` / ``dismiss`` are the analyst-only transitions; both write ``analyst_labels`` and
  ``audit_events``. System code never calls them.
"""

from __future__ import annotations

import uuid
from decimal import Decimal
from typing import Any

import sqlalchemy as sa
from sqlalchemy.orm import Session

from brandwatch.config.brand_config import ScoringConfig
from brandwatch.db.enums import (
    AnalystVerdict,
    CandidateState,
    EvidenceRole,
    EvidenceType,
    FindingState,
    ProviderStatus,
    Severity,
)
from brandwatch.db.models import (
    AnalystLabel,
    AuditEvent,
    Candidate,
    Evidence,
    Finding,
    FindingEvidence,
    RiskScore,
    User,
)
from brandwatch.db.types import utcnow
from brandwatch.detection.enrichment import CollectedEvidence, schedule_next_scan
from brandwatch.pipeline.stages import AnalysisResult, FindingResult, RiskResult

_SEVERITY_ORDER = [Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]

# evidence type → the signals it is primary evidence for
_PRIMARY_FOR: dict[EvidenceType, tuple[str, ...]] = {
    EvidenceType.FAVICON: ("favicon_exact", "favicon_phash_near"),
    EvidenceType.SCREENSHOT: ("screenshot_similarity_ge_90", "looks_like_brand_ge_85", "login_dom_similarity"),
    EvidenceType.HTML: (
        "credential_form", "payment_form", "seed_phrase_field", "brand_keywords_in_content",
        "lure_language", "external_form_action", "password_prefill",
        # suspicious shops: read from the page itself
        "shop_no_policy_pages", "shop_free_email_only", "shop_chat_or_phone_only", "shop_no_company_details",
        "shop_multibuy_bait", "shop_price_far_below_official", "shop_tld_language_mismatch",
        "shop_brand_catalog", "shop_deep_discounts",
    ),
    EvidenceType.WHOIS: ("age_lt_7d", "age_lt_30d", "shop_new_domain", "shop_young_domain"),
    EvidenceType.REPUTATION: ("vt_flagged", "urlhaus_listed", "phishtank_listed", "safe_browsing"),
}  # fmt: skip


def _audit(session: Session, workspace_id: uuid.UUID, **kw: Any) -> None:
    session.add(AuditEvent(workspace_id=workspace_id, **kw))
    session.flush()


def evidence_role(ev: Evidence, analysis: AnalysisResult, col: CollectedEvidence) -> EvidenceRole:
    primary_signals = _PRIMARY_FOR.get(ev.type, ())
    meta = ev.response_meta or {}
    if meta.get("diverged") or meta.get("revealed"):
        return EvidenceRole.PRIMARY
    if any(s in analysis.signals for s in primary_signals):
        return EvidenceRole.PRIMARY
    if ev.type is EvidenceType.REPUTATION:
        meta = ev.response_meta or {}
        if meta.get("status") == ProviderStatus.NEGATIVE.value:
            return EvidenceRole.CONTRADICTING
        return EvidenceRole.CONTEXT
    if ev.type is EvidenceType.WHOIS and "age_gt_2y" in analysis.fp_flags:
        return EvidenceRole.CONTRADICTING
    if ev.type in (EvidenceType.DNS, EvidenceType.HTTP):
        return EvidenceRole.SUPPORTING
    return EvidenceRole.CONTEXT


def record(
    session: Session,
    *,
    workspace_id: uuid.UUID,
    cand: Candidate,
    col: CollectedEvidence,
    analysis: AnalysisResult,
    risk: RiskResult,
    cfg: ScoringConfig,
    watch_cadence_hours: int,
    kind: str = "phishing",
) -> FindingResult:
    below = _SEVERITY_ORDER.index(risk.severity) < _SEVERITY_ORDER.index(cfg.finding_min_severity)
    if below:
        cand.state = CandidateState.WATCHING
        schedule_next_scan(cand, hours=watch_cadence_hours)
        return FindingResult(finding_id=None, state=None, created=False, disposition="watch")

    # One finding per site: a re-scan updates the site's newest open *or confirmed* finding (its
    # score history grows) instead of opening a second one the analyst would have to judge again.
    # A dismissed finding stays closed; if the site scores again later it gets a fresh finding.
    finding = session.scalars(
        sa.select(Finding)
        .where(
            Finding.candidate_id == cand.id,
            Finding.state.in_([FindingState.OPEN, FindingState.CONFIRMED]),
        )
        .order_by((Finding.state == FindingState.CONFIRMED).desc(), Finding.created_at.desc())
    ).first()
    created = finding is None
    old_state = (
        {"severity": finding.severity.value, "confidence": float(finding.confidence or 0)}
        if finding
        else None
    )
    if finding is None:
        finding = Finding(
            candidate_id=cand.id,
            brand_id=cand.brand_id,
            state=FindingState.OPEN,
            severity=risk.severity,
            confidence=Decimal(str(round(risk.confidence, 2))),
            kind=kind,
        )
        session.add(finding)
        session.flush()
    else:
        finding.severity = risk.severity
        finding.confidence = Decimal(str(round(risk.confidence, 2)))
        finding.kind = kind  # a scam shop that grows a login form becomes a phishing finding

    # the ads found for this site before stay with it, joined with any found now
    prev = session.scalars(sa.select(RiskScore).where(RiskScore.finding_id == finding.id, RiskScore.is_current.is_(True))).first()
    old_ads = (((prev.groups or {}).get("_breakdown") or {}).get("ads") or []) if prev else []
    if old_ads:
        merged = {str(a.get("ad_id")): a for a in old_ads}
        merged.update({str(a.get("ad_id")): a for a in risk.breakdown.get("ads") or []})
        risk.breakdown["ads"] = list(merged.values())
    # append-only scoring history: flip the previous current row, insert the new one
    session.execute(
        sa.update(RiskScore)
        .where(RiskScore.finding_id == finding.id, RiskScore.is_current.is_(True))
        .values(is_current=False)
    )
    session.add(
        RiskScore(
            finding_id=finding.id,
            is_current=True,
            score=risk.score,
            raw_score=risk.raw,
            severity=risk.severity,
            confidence=Decimal(str(round(risk.confidence, 2))),
            scoring_version=risk.scoring_version,
            signals={
                **risk.signals,
                "_details": analysis.details.get("signals", {}),
                "_unavailable": list(analysis.unavailable),
                "_fp_flags": list(analysis.fp_flags),
                # the site refused the scan: its refusal, and the urlscan.io snapshot its picture came from
                **{k: analysis.details[n] for k, n in (("_scanner_block", "scanner_block"), ("_snapshot", "snapshot"),
                                                       ("_security_warning", "security_warning"), ("_challenge", "challenge"),
                                                       ("_redirected_from", "redirected_from"), ("_clickfix", "clickfix"),
                                                       ("_no_picture", "no_picture"))
                   if analysis.details.get(n)},
            },
            groups={**risk.groups, "_breakdown": risk.breakdown},
        )  # fmt: skip
    )

    # link every evidence row of this run with a role (idempotent)
    linked = set(
        session.scalars(
            sa.select(FindingEvidence.evidence_id).where(FindingEvidence.finding_id == finding.id)
        ).all()
    )
    for ev_id in col.evidence_refs:
        if ev_id in linked:
            continue
        ev = session.get(Evidence, ev_id)
        if ev is None:
            continue
        session.add(
            FindingEvidence(
                finding_id=finding.id, evidence_id=ev.id, role=evidence_role(ev, analysis, col)
            )
        )
    session.flush()

    cand.state = CandidateState.FLAGGED
    schedule_next_scan(cand, hours=watch_cadence_hours)
    _audit(
        session, workspace_id,
        actor_type="system", actor_id=None,
        action="finding.created" if created else "finding.rescored",
        object_type="finding", object_id=finding.id,
        old_value=old_state,
        new_value={"severity": risk.severity.value, "score": risk.score, "confidence": risk.confidence,
                   "scoring_version": risk.scoring_version},
        reason=(f"{len(risk.signals)} signals fired; rules: "
                f"{[r['rule'] for r in risk.breakdown.get('combination_rules_fired', [])]}"
                + ("; already confirmed by an analyst — score history appended" if finding.state is FindingState.CONFIRMED else "")),
    )  # fmt: skip
    return FindingResult(
        finding_id=finding.id, state=finding.state, created=created, disposition="finding"
    )


# --------------------------------------------------------------------------------------------
# Analyst-only transitions (spec §2 state machine)
# --------------------------------------------------------------------------------------------
def _analyst_transition(
    session: Session,
    finding: Finding,
    analyst: User,
    *,
    to: FindingState,
    verdict: AnalystVerdict,
    reason: str,
    conclusion: dict[str, Any] | None = None,
) -> Finding:
    if finding.state is not FindingState.OPEN:
        raise ValueError(f"finding is already {finding.state.value}")
    old = finding.state
    finding.state = to
    finding.analyst_verdict = verdict
    finding.updated_at = utcnow()
    if conclusion is not None:
        finding.conclusion = conclusion
    session.add(
        AnalystLabel(
            finding_id=finding.id, label=(conclusion or {}).get("level") or verdict.value, reason=reason,
            analyst_id=analyst.id,
        )
    )  # fmt: skip
    new = {"state": to.value, "verdict": verdict.value}
    if conclusion is not None:
        new["conclusion"] = {k: conclusion.get(k) for k in ("level", "proof", "system_level")}
    _audit(
        session, analyst.workspace_id,
        actor_type="analyst", actor_id=analyst.id,
        action=f"finding.{to.value}", object_type="finding", object_id=finding.id,
        old_value={"state": old.value}, new_value=new, reason=reason,
    )  # fmt: skip
    session.flush()
    return finding


def _shop_conclusion(
    finding: Finding, analyst: User, level: str | None, proof: str | None, reason: str
) -> dict[str, Any]:
    """A shop finding's conclusion, validated: BrandWatch's own reading is the default; confirming
    counterfeits needs the proof (detection/shop_levels.py)."""
    from brandwatch.detection import shop_levels

    cur = finding.current_score
    rec = dict(((cur.groups or {}).get("_breakdown") or {}).get("shop") or {}) if cur else {}
    system = shop_levels.effective_level(None, rec)
    level = level or system
    shop_levels.validate(level, proof, reason, system)
    return shop_levels.record(level, proof, reason, system, analyst.email, utcnow().isoformat())


def confirm(
    session: Session,
    finding: Finding,
    analyst: User,
    reason: str = "",
    *,
    conclusion: str | None = None,
    proof: str | None = None,
) -> Finding:
    """Confirm a finding. A suspicious shop is confirmed *at a conclusion* — suspicious shop, likely
    counterfeit seller or confirmed counterfeit — which decides what the takedown letter may claim."""
    concl = None
    if (finding.kind or "phishing") == "shop":
        concl = _shop_conclusion(finding, analyst, conclusion, proof, reason)
    elif conclusion:
        raise ValueError("a conclusion level only applies to suspicious-shop findings")
    return _analyst_transition(
        session,
        finding,
        analyst,
        to=FindingState.CONFIRMED,
        verdict=AnalystVerdict.PHISHING,
        reason=reason,
        conclusion=concl,
    )


def set_conclusion(
    session: Session, finding: Finding, analyst: User, *, level: str, proof: str | None, reason: str
) -> Finding:
    """Change a confirmed shop's conclusion — typically up to "confirmed counterfeit" after a test
    purchase. Audited, and kept as a training label."""
    if (finding.kind or "phishing") != "shop":
        raise ValueError("a conclusion level only applies to suspicious-shop findings")
    if finding.state is not FindingState.CONFIRMED:
        raise ValueError("confirm the shop first; the conclusion can then be changed")
    old = dict(finding.conclusion or {})
    finding.conclusion = _shop_conclusion(finding, analyst, level, proof, reason)
    finding.updated_at = utcnow()
    session.add(AnalystLabel(finding_id=finding.id, label=level, reason=reason, analyst_id=analyst.id))
    _audit(
        session, analyst.workspace_id,
        actor_type="analyst", actor_id=analyst.id,
        action="finding.conclusion_updated", object_type="finding", object_id=finding.id,
        old_value={"level": old.get("level"), "proof": old.get("proof")},
        new_value={"level": level, "proof": finding.conclusion.get("proof")}, reason=reason,
    )  # fmt: skip
    session.flush()
    return finding


def reopen(session: Session, finding: Finding, analyst: User, reason: str = "") -> Finding:
    """Undo a verdict: the finding is open again and waits for a verdict; the domain goes back on the
    watchlist as flagged. The old verdict stays in the audit log and in the training labels (the new
    verdict, when it comes, is a later label)."""
    if finding.state is FindingState.OPEN:
        raise ValueError("the finding is already open")
    old = finding.state
    finding.state = FindingState.OPEN
    finding.analyst_verdict = None
    finding.updated_at = utcnow()
    cand = session.get(Candidate, finding.candidate_id)
    if cand is not None and cand.state is CandidateState.DISMISSED:
        cand.state = CandidateState.FLAGGED
    _audit(
        session, analyst.workspace_id,
        actor_type="analyst", actor_id=analyst.id,
        action="finding.reopened", object_type="finding", object_id=finding.id,
        old_value={"state": old.value}, new_value={"state": "open"}, reason=reason or "verdict undone",
    )  # fmt: skip
    session.flush()
    return finding


def dismiss(
    session: Session,
    finding: Finding,
    analyst: User,
    reason: str = "",
    verdict: AnalystVerdict = AnalystVerdict.LEGITIMATE,
) -> Finding:
    if verdict is AnalystVerdict.PHISHING:
        raise ValueError("dismiss cannot carry the 'phishing' verdict")
    result = _analyst_transition(
        session, finding, analyst, to=FindingState.DISMISSED, verdict=verdict, reason=reason
    )
    cand = session.get(Candidate, finding.candidate_id)
    if cand is not None:
        cand.state = CandidateState.DISMISSED
        cand.next_scan_at = None
    return result
