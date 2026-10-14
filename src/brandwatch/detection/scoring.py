"""Risk & Confidence engine (spec §5). Pure and deterministic: the same AnalysisResult and the
same ScoringConfig always yield the same RiskResult, so a score is reproducible from evidence
plus ``scoring_version``.

    raw   = Σ min(group_total, group_cap) + high-confidence bonuses − FP penalties
    score = round(raw / Σ caps × 100)
    severity = thresholds(score), then floored by combination rules

Confidence is a separate axis — how sure we are this is genuinely impersonation — built from
breadth of evidence, hard confirmers, evidence completeness, provider agreement and penalties for
unavailable or weak evidence.
"""

from __future__ import annotations

from typing import Any

from brandwatch.config.brand_config import SIGNAL_GROUPS, ScoringConfig
from brandwatch.db.enums import Severity
from brandwatch.pipeline.stages import AnalysisResult, RiskResult

_SEVERITY_ORDER = [Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]

HARD_CONFIRMERS: tuple[str, ...] = (
    "favicon_exact",
    "cloaking_ip_based",
    "linked_to_known_campaign",
    "vt_flagged",
    "cloudflare_phishing_warning",
    "known_phishing",
    "clickfix_lure",
    "urlhaus_listed",
    "phishtank_listed",
    "safe_browsing",
)


def _max_severity(a: Severity, b: Severity) -> Severity:
    return a if _SEVERITY_ORDER.index(a) >= _SEVERITY_ORDER.index(b) else b


def group_totals(signals: dict[str, float], cfg: ScoringConfig) -> dict[str, dict[str, float]]:
    """{group: {"total": Σ points, "cap": cap, "capped": min(total, cap)}}"""
    out = {g: {"total": 0.0, "cap": float(cap), "capped": 0.0} for g, cap in cfg.group_caps.items()}
    for name, points in signals.items():
        group = SIGNAL_GROUPS.get(name)
        if group is None or points <= 0:
            continue
        out[group]["total"] += float(points)
    for g in out.values():
        g["capped"] = min(g["total"], g["cap"])
    return out


def compute_confidence(
    analysis: AnalysisResult, groups: dict[str, dict[str, float]]
) -> tuple[float, dict[str, Any]]:
    fired_groups = [g for g, v in groups.items() if v["total"] > 0]
    breadth = {0: 0, 1: 20, 2: 35, 3: 50, 4: 60}.get(len(fired_groups), 70)

    confirmers = [s for s in HARD_CONFIRMERS if s in analysis.signals]
    confirmer_points = min(30, 15 * len(confirmers))

    completeness = 0
    unavailable = set(analysis.unavailable)
    if "screenshot" not in unavailable and analysis.details.get("screenshot_captured"):
        completeness += 5
    if "whois" not in unavailable and analysis.details.get("whois_age_days") is not None:
        completeness += 5
    if "http" not in unavailable and analysis.details.get("html_captured"):
        completeness += 5

    agreement = 5 if int(analysis.details.get("reputation_positives", 0)) >= 2 else 0

    unavailable_penalty = min(24, 8 * len(unavailable))
    weak_penalty = 0
    if len(fired_groups) == 1 and groups[fired_groups[0]]["total"] < 10:
        weak_penalty = 15

    value = (
        breadth + confirmer_points + completeness + agreement - unavailable_penalty - weak_penalty
    )
    value = float(max(0, min(100, value)))
    return value, {
        "breadth": breadth,
        "groups_fired": fired_groups,
        "hard_confirmers": confirmers,
        "hard_confirmer_points": confirmer_points,
        "evidence_completeness": completeness,
        "provider_agreement": agreement,
        "unavailable_penalty": -unavailable_penalty,
        "unavailable": sorted(unavailable),
        "single_weak_signal_penalty": -weak_penalty,
    }


def score(analysis: AnalysisResult, cfg: ScoringConfig) -> RiskResult:
    signals = {k: float(v) for k, v in analysis.signals.items() if v > 0}
    groups = group_totals(signals, cfg)
    base = sum(g["capped"] for g in groups.values())

    bonuses: list[dict[str, Any]] = []
    bonus_total = 0
    for cluster in cfg.high_confidence_clusters:
        if all(s in signals for s in cluster):
            bonuses.append({"cluster": list(cluster), "points": cfg.high_confidence_bonus})
            bonus_total += cfg.high_confidence_bonus
    bonus_total = min(bonus_total, cfg.high_confidence_bonus_cap)

    penalties: list[dict[str, Any]] = []
    penalty_total = 0
    for flag in analysis.fp_flags:
        pts = cfg.fp_penalties.get(flag, 0)
        if pts:
            penalties.append({"flag": flag, "points": -pts})
            penalty_total += pts

    raw_max = cfg.raw_max
    raw = int(round(max(0.0, min(float(raw_max), base + bonus_total - penalty_total))))
    normalized = int(round(raw / raw_max * 100)) if raw_max else 0
    severity = cfg.thresholds.severity_for(normalized)

    rules_fired: list[dict[str, Any]] = []
    for rule in cfg.combination_rules:
        if all(s in signals for s in rule.signals_all):
            rules_fired.append({"rule": rule.name, "min_severity": rule.min_severity.value})
            severity = _max_severity(severity, rule.min_severity)
    if rules_fired:  # keep the number consistent with the floored severity
        floor = {
            Severity.MEDIUM: cfg.thresholds.medium, Severity.HIGH: cfg.thresholds.high,
            Severity.CRITICAL: cfg.thresholds.critical,
        }.get(severity, 0)  # fmt: skip
        normalized = max(normalized, floor)

    confidence, confidence_breakdown = compute_confidence(analysis, groups)

    return RiskResult(
        raw=raw,
        score=normalized,
        severity=severity,
        confidence=confidence,
        signals=signals,
        groups={g: v["capped"] for g, v in groups.items()},
        scoring_version=cfg.version,
        breakdown={
            "group_detail": groups,
            "base": base,
            "bonuses": bonuses,
            "bonus_total": bonus_total,
            "penalties": penalties,
            "penalty_total": -penalty_total,
            "raw_max": raw_max,
            "thresholds": cfg.thresholds.model_dump(),
            "combination_rules_fired": rules_fired,
            "confidence": confidence_breakdown,
            "signal_details": analysis.details.get("signals", {}),
        },
    )
