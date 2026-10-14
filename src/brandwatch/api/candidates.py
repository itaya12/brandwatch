"""Candidate evidence timeline (spec §14 Watchlist detail, Phase 2) and single-candidate rescan."""

from __future__ import annotations

import uuid
from typing import Annotated, Any

import sqlalchemy as sa
from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from brandwatch.api.auth import audit, current_user, require_analyst
from brandwatch.api.deps import get_session
from brandwatch.db.enums import CandidateState
from brandwatch.db.models import (
    Brand,
    BrandDomain,
    Candidate,
    CandidateSource,
    Evidence,
    Finding,
    Observation,
    RiskScore,
    User,
)

router = APIRouter(prefix="/api/candidates", tags=["candidates"])


def _iso(dt) -> str | None:
    return dt.isoformat() if dt else None


def _get_candidate(session: Session, user: User, candidate_id: uuid.UUID) -> Candidate:
    c = session.get(Candidate, candidate_id)
    brand = session.get(Brand, c.brand_id) if c else None
    if c is None or brand is None or brand.workspace_id != user.workspace_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "candidate not found")
    return c


def candidate_timeline(session: Session, c: Candidate) -> dict[str, Any]:
    brand = session.get(Brand, c.brand_id)
    sources = session.scalars(
        sa.select(CandidateSource).where(CandidateSource.candidate_id == c.id)
    ).all()
    observations = session.scalars(
        sa.select(Observation)
        .where(Observation.candidate_id == c.id)
        .order_by(Observation.observed_at)
    ).all()
    evidence = session.scalars(
        sa.select(Evidence).where(Evidence.candidate_id == c.id).order_by(Evidence.observed_at)
    ).all()
    findings = session.scalars(
        sa.select(Finding).where(Finding.candidate_id == c.id).order_by(Finding.created_at)
    ).all()

    # Attach evidence to the observation it belongs to (same scan run ≈ nearest preceding observation
    # window): evidence observed between observation[i-1] and observation[i] belongs to i.
    bounds = [o.observed_at for o in observations]
    buckets: dict[int, list[Evidence]] = {i: [] for i in range(len(observations))}
    for ev in evidence:
        idx = next((i for i, t in enumerate(bounds) if ev.observed_at <= t), len(bounds) - 1)
        if idx >= 0:
            buckets[idx].append(ev)

    prev_hash: str | None = None
    timeline: list[dict[str, Any]] = []
    for i, o in enumerate(observations):
        evs = buckets.get(i, [])
        timeline.append(
            {
                "observed_at": _iso(o.observed_at),
                "http_status": o.http_status,
                "state_at_time": o.state_at_time.value,
                "scanner_profile": o.scanner_profile.value,
                "content_hash": o.content_hash,
                "changed": o.changed,
                "hash_changed_since_previous": bool(
                    prev_hash and o.content_hash and prev_hash != o.content_hash
                ),
                "screenshot_url": f"/api/evidence/{o.screenshot_evidence_id}/artifact"
                if o.screenshot_evidence_id
                else None,
                "evidence": [
                    {
                        "id": str(e.id),
                        "type": e.type.value,
                        "source": e.source,
                        "sha256": e.content_sha256,
                        "artifact_url": f"/api/evidence/{e.id}/artifact"
                        if e.artifact_location
                        else None,
                        "meta": e.response_meta or {},
                    }
                    for e in evs
                ],
            }
        )
        prev_hash = o.content_hash or prev_hash

    scores = []
    for f in findings:
        for r in session.scalars(
            sa.select(RiskScore).where(RiskScore.finding_id == f.id).order_by(RiskScore.created_at)
        ).all():
            scores.append({"finding_id": str(f.id), "created_at": _iso(r.created_at), "score": r.score,
                           "severity": r.severity.value, "confidence": float(r.confidence), "is_current": r.is_current})  # fmt: skip

    return {
        "candidate": {
            "id": str(c.id),
            "brand_id": str(c.brand_id),
            "brand_name": brand.name,
            "hostname": c.hostname,
            "canonical_url": c.canonical_url,
            "canonical_domain": c.canonical_domain,
            "surface": c.surface.value,
            "state": c.state.value,
            "priority": c.priority,
            "first_seen": _iso(c.first_seen),
            "last_seen": _iso(c.last_seen),
            "next_scan_at": _iso(c.next_scan_at),
            "scan_count": c.scan_count,
            "content_hash": c.content_hash,
        },
        "sources": [
            {"source": s.source.value, "pattern": s.matched_pattern, "found_at": _iso(s.found_at)}
            for s in sources
        ],
        "timeline": timeline,
        "findings": [
            {
                "id": str(f.id),
                "state": f.state.value,
                "severity": f.severity.value,
                "confidence": float(f.confidence or 0),
                "created_at": _iso(f.created_at),
            }
            for f in findings
        ],  # fmt: skip
        "score_history": scores,
        "evidence_count": len(evidence),
    }


@router.get("/{candidate_id}")
def get_candidate(
    candidate_id: uuid.UUID,
    session: Annotated[Session, Depends(get_session, scope="function")],
    user: Annotated[User, Depends(current_user)],
) -> dict[str, Any]:
    return candidate_timeline(session, _get_candidate(session, user, candidate_id))


class DismissRequest(BaseModel):
    reason: str = Field(default="", max_length=500)
    whitelist: bool = True  # also whitelist the registrable domain for this brand


@router.post("/{candidate_id}/dismiss")
def dismiss_candidate(
    candidate_id: uuid.UUID,
    body: DismissRequest,
    session: Annotated[Session, Depends(get_session, scope="function")],
    user: Annotated[User, Depends(require_analyst)],
) -> dict[str, Any]:
    """Analyst: "I know this domain, it is legitimate". Takes the domain off the watchlist, dismisses
    its open findings and — by default — whitelists its registrable domain for the brand so no scan
    re-adds it or any of its subdomains."""
    from brandwatch.db.enums import AnalystVerdict, FindingState
    from brandwatch.detection import finding as finding_svc
    from brandwatch.detection.normalize import protected_root

    c = _get_candidate(session, user, candidate_id)
    reg = protected_root(c.hostname)  # on shared hosting (github.io, pages.dev …) only this site
    whitelisted: str | None = None
    if body.whitelist:
        existing = session.scalars(
            sa.select(BrandDomain).where(
                BrandDomain.brand_id == c.brand_id, BrandDomain.domain == reg
            )
        ).first()
        if existing is None:
            session.add(
                BrandDomain(brand_id=c.brand_id, domain=reg, is_official=False, kind="known_legit")
            )
            whitelisted = reg
        elif not existing.is_official:
            whitelisted = existing.domain
    targets = [c]
    if body.whitelist:  # every sibling under the same registrable domain goes too
        siblings = session.scalars(
            sa.select(Candidate).where(
                Candidate.brand_id == c.brand_id, Candidate.state != CandidateState.DISMISSED
            )
        ).all()
        targets += [
            s
            for s in siblings
            if s.id != c.id and (s.hostname == reg or s.hostname.endswith("." + reg))
        ]
    dismissed, findings_closed = [], 0
    for cand in targets:
        for f in session.scalars(
            sa.select(Finding).where(
                Finding.candidate_id == cand.id, Finding.state == FindingState.OPEN
            )
        ).all():
            finding_svc.dismiss(
                session,
                f,
                user,
                body.reason or "known legitimate domain",
                AnalystVerdict.LEGITIMATE,
            )
            findings_closed += 1
        cand.state = CandidateState.DISMISSED
        cand.next_scan_at = None
        dismissed.append(cand.hostname)
    audit(session, workspace_id=user.workspace_id, actor_type="analyst", actor_id=user.id,
          action="candidate.dismissed", object_type="candidate", object_id=c.id,
          new={"hosts": dismissed, "whitelisted": whitelisted, "findings_closed": findings_closed}, reason=body.reason or None)  # fmt: skip
    session.flush()
    return {"dismissed": dismissed, "whitelisted": whitelisted, "findings_closed": findings_closed}


@router.post("/{candidate_id}/rescan", status_code=status.HTTP_202_ACCEPTED)
def rescan_candidate(
    candidate_id: uuid.UUID,
    request: Request,
    session: Annotated[Session, Depends(get_session, scope="function")],
    user: Annotated[User, Depends(require_analyst)],
) -> dict[str, Any]:
    c = _get_candidate(session, user, candidate_id)
    if c.state is CandidateState.DISMISSED:
        c.state = CandidateState.WATCHING  # an analyst asked to look again
    audit(
        session, workspace_id=user.workspace_id, actor_type="analyst", actor_id=user.id,
        action="candidate.rescan_requested", object_type="candidate", object_id=c.id,
        new={"url": c.canonical_url},
    )  # fmt: skip
    session.commit()
    job_id = request.app.state.queue.enqueue(
        # an analyst's rescan is a full check: it also looks behind a security product's phishing warning
        "url_scan", {"urls": [c.canonical_url], "requested_by": str(user.id), "candidate_id": str(c.id), "full_check": True},
        workspace_id=user.workspace_id, brand_id=c.brand_id,
    )  # fmt: skip
    return {"job_id": str(job_id), "kind": "url_scan"}
