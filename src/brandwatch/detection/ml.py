"""Phishing classifier trained on analyst labels (spec §5 "Manual weights now; the analyst_labels
dataset later trains an ML classifier — AI as augmentation, never source of truth", §2 feedback
loop), Phase 5.

* Features: presence of each catalogue signal + false-positive flags + which evidence was
  unavailable, taken from ``candidates.last_analysis`` (written by every scan, Finding or not, so
  the model also learns from the low-scoring legit pages that never became findings).
* Labels: analyst verdicts on findings (``phishing`` → 1, ``legitimate`` → 0; ``suspicious`` is
  skipped). In demo mode the recorded golden labels can bootstrap a model (``source="golden"``).
* Model: L2-regularised logistic regression in numpy (no scipy / sklearn dependency), evaluated
  with deterministic k-fold cross-validation before it is stored as a versioned ``rule_versions``
  row (``kind = "ml_model"``) — so every probability shown is reproducible from its version.

The probability is displayed next to the deterministic score; it never changes the score.
"""

from __future__ import annotations

import math
import uuid
from datetime import UTC, datetime
from typing import Any

import numpy as np
import sqlalchemy as sa
from sqlalchemy.orm import Session

from brandwatch.config.brand_config import SIGNAL_GROUPS
from brandwatch.db.enums import AnalystVerdict
from brandwatch.db.models import Brand, Candidate, Finding, RuleVersion

FEATURES: tuple[str, ...] = (
    *sorted(SIGNAL_GROUPS),
    "fp:age_gt_2y",
    "unavailable:screenshot",
    "unavailable:whois",
    "unavailable:reputation",
    "unavailable:residential",
)
MIN_SAMPLES = 8
KIND = "ml_model"


def vectorize(record: dict[str, Any]) -> np.ndarray:
    on = set(record.get("signals", []))
    on |= {f"fp:{f}" for f in record.get("fp_flags", [])}
    on |= {f"unavailable:{u}" for u in record.get("unavailable", [])}
    return np.array([1.0 if f in on else 0.0 for f in FEATURES], dtype=np.float64)


def _sigmoid(z: np.ndarray) -> np.ndarray:
    return 1.0 / (1.0 + np.exp(-np.clip(z, -30, 30)))


def fit(
    X: np.ndarray, y: np.ndarray, *, l2: float = 0.05, lr: float = 0.5, iters: int = 1500
) -> tuple[np.ndarray, float]:
    n, d = X.shape
    w = np.zeros(d)
    b = 0.0
    pos = max(1.0, float(y.sum()))
    neg = max(1.0, float(n - y.sum()))
    sample_w = np.where(y == 1, n / (2 * pos), n / (2 * neg))  # class balance
    for _ in range(iters):
        p = _sigmoid(X @ w + b)
        g = (p - y) * sample_w
        w -= lr * ((X.T @ g) / n + l2 * w)
        b -= lr * float(g.mean())
    return w, b


def cross_validate(X: np.ndarray, y: np.ndarray, k: int = 5) -> dict[str, float]:
    n = len(y)
    k = max(2, min(k, n))
    idx = np.arange(n)
    preds = np.zeros(n)
    for fold in range(k):
        test = idx[idx % k == fold]
        train = idx[idx % k != fold]
        if len(set(y[train].tolist())) < 2:
            preds[test] = y[train].mean()
            continue
        w, b = fit(X[train], y[train])
        preds[test] = _sigmoid(X[test] @ w + b)
    yhat = (preds >= 0.5).astype(float)
    tp = float(((yhat == 1) & (y == 1)).sum())
    fp = float(((yhat == 1) & (y == 0)).sum())
    fn = float(((yhat == 0) & (y == 1)).sum())
    acc = float((yhat == y).mean())
    return {
        "accuracy": round(acc, 3),
        "precision": round(tp / (tp + fp), 3) if tp + fp else 0.0,
        "recall": round(tp / (tp + fn), 3) if tp + fn else 0.0,
        "folds": k,
    }


def _golden_label(host: str) -> int | None:
    from brandwatch.providers.mock.fixtures import default_store

    sc = default_store().get(host)
    if sc is None:
        return None
    return 1 if sc.is_phishing else 0


def training_set(
    session: Session,
    workspace_id: uuid.UUID,
    *,
    source: str = "analyst",
    brand_id: uuid.UUID | None = None,
):
    q = (
        sa.select(Candidate)
        .join(Brand, Brand.id == Candidate.brand_id)
        .where(Brand.workspace_id == workspace_id, Candidate.last_analysis.is_not(None))
    )
    if brand_id:
        q = q.where(Candidate.brand_id == brand_id)
    rows: list[tuple[np.ndarray, int, str]] = []
    for cand in session.scalars(q).all():
        label: int | None = None
        if source in ("golden", "both"):
            label = _golden_label(cand.hostname)
        if source in ("analyst", "both"):
            verdict = session.scalars(
                sa.select(Finding.analyst_verdict)
                .where(
                    Finding.candidate_id == cand.id,
                    Finding.analyst_verdict.is_not(None),
                    # a confirmed scam shop / fake account is not a phishing label for this model
                    sa.or_(Finding.kind == "phishing", Finding.kind.is_(None)),
                )
                .order_by(Finding.created_at.desc())
            ).first()
            if verdict is AnalystVerdict.PHISHING:
                label = 1
            elif verdict is AnalystVerdict.LEGITIMATE:
                label = 0
        if label is not None:
            rows.append((vectorize(cand.last_analysis), label, cand.hostname))
    return rows


def train(
    session: Session,
    workspace_id: uuid.UUID,
    *,
    source: str = "analyst",
    brand_id: uuid.UUID | None = None,
) -> RuleVersion:
    if source not in ("analyst", "golden", "both"):
        raise ValueError("source must be analyst | golden | both")
    rows = training_set(session, workspace_id, source=source, brand_id=brand_id)
    if len(rows) < MIN_SAMPLES:
        raise ValueError(f"need at least {MIN_SAMPLES} labelled candidates, have {len(rows)}")
    X = np.stack([r[0] for r in rows])
    y = np.array([r[1] for r in rows], dtype=np.float64)
    if len(set(y.tolist())) < 2:
        raise ValueError("need both phishing and legitimate labels to train")
    metrics = cross_validate(X, y)
    w, b = fit(X, y)
    ranked = sorted(zip(FEATURES, w.tolist(), strict=True), key=lambda t: -abs(t[1]))
    n_prev = (
        session.scalar(
            sa.select(sa.func.count()).select_from(RuleVersion).where(RuleVersion.kind == KIND)
        )
        or 0
    )
    version = f"ml-{str(workspace_id)[:8]}-{n_prev + 1}"
    row = RuleVersion(
        kind=KIND,
        version=version,
        payload={
            "workspace_id": str(workspace_id),
            "brand_id": str(brand_id) if brand_id else None,
            "features": list(FEATURES),
            "weights": [round(x, 6) for x in w.tolist()],
            "bias": round(float(b), 6),
            "n_samples": len(rows),
            "positives": int(y.sum()),
            "source": source,
            "metrics": metrics,
            "top_features": [{"feature": f, "weight": round(v, 3)} for f, v in ranked[:10]],
            "trained_at": datetime.now(UTC).isoformat(),
            "algorithm": "logistic_regression_l2_numpy",
        },
    )
    session.add(row)
    session.flush()
    return row


def latest_model(session: Session, workspace_id: uuid.UUID) -> dict[str, Any] | None:
    rows = session.scalars(
        sa.select(RuleVersion)
        .where(RuleVersion.kind == KIND)
        .order_by(RuleVersion.created_at.desc())
    ).all()
    for r in rows:
        if (r.payload or {}).get("workspace_id") == str(workspace_id):
            return {"version": r.version, **r.payload}
    return None


def predict(model: dict[str, Any], record: dict[str, Any]) -> float:
    feats = model["features"]
    on = set(record.get("signals", []))
    on |= {f"fp:{f}" for f in record.get("fp_flags", [])}
    on |= {f"unavailable:{u}" for u in record.get("unavailable", [])}
    z = model["bias"] + sum(wt for f, wt in zip(feats, model["weights"], strict=True) if f in on)
    return round(1.0 / (1.0 + math.exp(-max(-30.0, min(30.0, z)))), 4)
