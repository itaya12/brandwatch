"""Re-scoring under a new scoring configuration (spec §5 "live re-score preview", §2 versioned
scores), Phase 6.

Scores are reproducible from the fired signals + the scoring version, so a new weight set can be
previewed against every open finding *without* touching evidence: the fired signal names, the
false-positive flags and the unavailable-evidence list are re-weighted with the candidate config.
``apply`` appends a new ``risk_scores`` row per finding (history preserved, ``is_current`` flipped)
under a new ``scoring_version`` whose weights/thresholds/rules are snapshotted in
``risk_score_versions`` so old and new scores both stay interpretable.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from decimal import Decimal
from typing import Any

import sqlalchemy as sa
from sqlalchemy.orm import Session

from brandwatch.config.brand_config import SCORING_VERSION, SIGNAL_GROUPS, ScoringConfig
from brandwatch.db.enums import FindingState
from brandwatch.db.models import (
    AuditEvent,
    Brand,
    Candidate,
    Finding,
    RiskScore,
    RiskScoreVersion,
    User,
)
from brandwatch.detection import scoring
from brandwatch.pipeline.stages import AnalysisResult

REPUTATION_SIGNALS = ("vt_flagged", "urlhaus_listed", "phishtank_listed", "safe_browsing", "known_phishing")


def version_for(cfg: ScoringConfig) -> str:
    """Content-addressed version: same weights/thresholds/rules ⇒ same version string."""
    body = cfg.model_dump(mode="json", exclude={"version"})
    digest = hashlib.sha256(json.dumps(body, sort_keys=True).encode()).hexdigest()[:8]
    return f"{SCORING_VERSION}-{digest}"


def ensure_version_row(session: Session, cfg: ScoringConfig) -> str:
    if not session.scalars(
        sa.select(RiskScoreVersion).where(RiskScoreVersion.version == cfg.version)
    ).first():
        session.add(
            RiskScoreVersion(
                version=cfg.version,
                weights=dict(cfg.weights),
                thresholds=cfg.thresholds.model_dump(),
                combination_rules=[r.model_dump(mode="json") for r in cfg.combination_rules],
            )
        )
        session.flush()
    return cfg.version


def analysis_from_score(rs: RiskScore, cfg: ScoringConfig) -> AnalysisResult:
    sig = dict(rs.signals or {})
    names = [k for k in sig if not k.startswith("_") and k in SIGNAL_GROUPS]
    unavailable = tuple(sig.get("_unavailable", []))
    details: dict[str, Any] = {
        "signals": sig.get("_details", {}),
        "screenshot_captured": "screenshot" not in unavailable,
        "html_captured": "http" not in unavailable,
        "whois_age_days": None if "whois" in unavailable else 0,
        "reputation_positives": sum(1 for n in names if n in REPUTATION_SIGNALS),
    }
    return AnalysisResult(
        signals={n: float(cfg.weights.get(n, 0)) for n in names if cfg.weights.get(n, 0) > 0},
        evidence_refs=(),
        unavailable=unavailable,
        fp_flags=tuple(sig.get("_fp_flags", [])),
        details=details,
    )


def _open_findings(session: Session, brand_id: uuid.UUID) -> list[tuple[Finding, RiskScore, str]]:
    rows = session.execute(
        sa.select(Finding, RiskScore, Candidate.hostname)
        .join(
            RiskScore, sa.and_(RiskScore.finding_id == Finding.id, RiskScore.is_current.is_(True))
        )
        .join(Candidate, Candidate.id == Finding.candidate_id)
        .where(
            Finding.brand_id == brand_id,
            Finding.state != FindingState.DISMISSED,
            # shop and social findings are scored by code-defined, versioned scores
            # (detection/merchant.py, detection/social.py) — a phishing config never re-weights them
            sa.or_(Finding.kind == "phishing", Finding.kind.is_(None)),
        )
        .order_by(RiskScore.score.desc())
    ).all()
    return [(f, rs, host) for f, rs, host in rows]


def preview(session: Session, brand_id: uuid.UUID, cfg: ScoringConfig) -> dict[str, Any]:
    out = []
    changed = 0
    for f, rs, host in _open_findings(session, brand_id):
        new = scoring.score(analysis_from_score(rs, cfg), cfg)
        moved = new.severity.value != rs.severity.value
        changed += moved
        out.append(
            {"finding_id": str(f.id), "hostname": host, "state": f.state.value,
             "before": {"score": rs.score, "severity": rs.severity.value, "version": rs.scoring_version},
             "after": {"score": new.score, "severity": new.severity.value, "version": cfg.version},
             "severity_changed": moved, "delta": new.score - rs.score}
        )  # fmt: skip
    return {"version": cfg.version, "findings": out, "severity_changes": changed, "total": len(out)}


def apply(session: Session, brand_id: uuid.UUID, cfg: ScoringConfig, *, actor: User | None) -> int:
    ensure_version_row(session, cfg)
    brand = session.get(Brand, brand_id)
    n = 0
    for f, rs, _host in _open_findings(session, brand_id):
        if rs.scoring_version == cfg.version:
            continue
        an = analysis_from_score(rs, cfg)
        new = scoring.score(an, cfg)
        old_breakdown = dict((rs.groups or {}).get("_breakdown", {}))
        breakdown = {
            **new.breakdown,
            **{k: old_breakdown[k] for k in ("ai", "ml", "cloaking") if k in old_breakdown},
        }
        breakdown["rescored_from"] = rs.scoring_version
        session.execute(sa.update(RiskScore).where(RiskScore.id == rs.id).values(is_current=False))
        session.add(
            RiskScore(
                finding_id=f.id,
                is_current=True,
                score=new.score,
                raw_score=new.raw,
                severity=new.severity,
                confidence=rs.confidence,
                scoring_version=cfg.version,
                signals={
                    **new.signals,
                    "_details": (rs.signals or {}).get("_details", {}),
                    "_unavailable": list(an.unavailable),
                    "_fp_flags": list(an.fp_flags),
                    **{k: (rs.signals or {})[k] for k in ("_scanner_block", "_snapshot", "_security_warning", "_challenge", "_redirected_from", "_clickfix", "_no_picture") if (rs.signals or {}).get(k)},
                },
                groups={**new.groups, "_breakdown": breakdown},
            )  # fmt: skip
        )
        old_sev = f.severity
        f.severity = new.severity
        session.add(
            AuditEvent(
                workspace_id=brand.workspace_id,
                actor_type="analyst" if actor else "system",
                actor_id=actor.id if actor else None,
                action="finding.rescored",
                object_type="finding",
                object_id=f.id,
                old_value={
                    "score": rs.score,
                    "severity": old_sev.value,
                    "version": rs.scoring_version,
                },
                new_value={
                    "score": new.score,
                    "severity": new.severity.value,
                    "version": cfg.version,
                },
                reason="scoring configuration changed",
            )  # fmt: skip
        )
        n += 1
    session.flush()
    return n


def _confidence(
    value: Any,
) -> Decimal:  # pragma: no cover - helper kept for symmetry with finding stage
    return Decimal(str(round(float(value), 2)))
