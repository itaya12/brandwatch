"""Facts about this project, computed from the code — never typed by hand.

The How-it-works page, Settings and ``GET /health`` show numbers an interviewer asks for (how many
signals, tests, providers, immutable tables …). They are read from the live objects, so they cannot
drift from the code the way a README does.
"""

from __future__ import annotations

import re
import time
from pathlib import Path
from typing import Any

from brandwatch import __version__

ROOT = Path(__file__).resolve().parents[2]
# the regression gate the golden suite enforces (tests/test_golden.py) and what it last measured
GOLDEN_GATE = {"precision": 0.90, "recall": 0.90, "fp_rate": 0.05}
GOLDEN_LAST_MEASURED = {"precision": 1.00, "recall": 1.00, "fp_rate": 0.00}

_cache: dict[str, Any] = {}


def _tests() -> dict[str, int] | None:
    tests = ROOT / "tests"
    if not tests.is_dir():
        return None
    files = sorted(tests.glob("test_*.py"))
    funcs = sum(
        len(re.findall(r"^\s*(?:async\s+)?def test_", f.read_text(encoding="utf-8"), re.M))
        for f in files
    )
    return {"files": len(files), "functions": funcs}


def _ci_jobs() -> list[str]:
    ci = ROOT / ".github" / "workflows" / "ci.yml"
    if not ci.is_file():
        return []
    text = ci.read_text(encoding="utf-8").split("jobs:", 1)[-1]
    return re.findall(r"^  ([a-z0-9_-]+):\s*$", text, re.M)


def project_facts(app: Any | None = None, *, max_age: float = 300.0) -> dict[str, Any]:
    """Everything the 'About this project' tiles show. Cached for ``max_age`` seconds."""
    if _cache and time.monotonic() - _cache.get("_at", 0) < max_age:
        return _with_app(dict(_cache["facts"]), app)
    from brandwatch.config.brand_config import SIGNAL_GROUPS, BrandConfig
    from brandwatch.config.settings import DEFAULT_PROVIDER_ROUTES
    from brandwatch.db.models import IMMUTABLE_TABLES
    from brandwatch.detection.rescore import version_for
    from brandwatch.providers.mock.fixtures import default_store
    from brandwatch.security.limits import SYSTEM_LIMITS

    cfg = BrandConfig()
    labels: dict[str, int] = {}
    for sc in default_store().all():
        labels[sc.label] = labels.get(sc.label, 0) + 1
    providers = sorted(
        {p for r in DEFAULT_PROVIDER_ROUTES.values() for p in [r.primary, *r.fallback]}
    )
    facts: dict[str, Any] = {
        "version": __version__,
        "signals": len(SIGNAL_GROUPS),
        "signal_groups": len(set(SIGNAL_GROUPS.values())),
        "group_caps": dict(cfg.scoring.group_caps),
        "thresholds": {
            "medium": cfg.scoring.thresholds.medium,
            "high": cfg.scoring.thresholds.high,
            "critical": cfg.scoring.thresholds.critical,
        },  # fmt: skip
        "combination_rules": len(cfg.scoring.combination_rules),
        "fp_penalties": len(getattr(cfg.scoring, "fp_penalties", {}) or {}),
        "scoring_version": version_for(cfg.scoring),
        "provider_kinds": len(DEFAULT_PROVIDER_ROUTES),
        "providers": len(providers),
        "provider_routes": {
            k: [r.primary, *r.fallback] for k, r in DEFAULT_PROVIDER_ROUTES.items()
        },
        "golden": {"total": sum(labels.values()), **labels},
        "golden_gate": GOLDEN_GATE,
        "golden_measured": GOLDEN_LAST_MEASURED,
        "immutable_tables": list(IMMUTABLE_TABLES),
        "limits": {
            "blocked_networks": len(SYSTEM_LIMITS.BLOCKED_NETWORKS),
            "max_redirects": SYSTEM_LIMITS.MAX_REDIRECTS,
            "max_response_mb": round(SYSTEM_LIMITS.MAX_RESPONSE_SIZE / 1024 / 1024, 1),
            "fetch_timeout_s": SYSTEM_LIMITS.FETCH_TIMEOUT,
            "pivot_depth": SYSTEM_LIMITS.MAX_BFS_DEPTH,
            "pivot_nodes": SYSTEM_LIMITS.MAX_PIVOT_NODES,
            "pivot_edges": SYSTEM_LIMITS.MAX_PIVOT_EDGES,
        },
        "migrations": len(list((ROOT / "migrations" / "versions").glob("[0-9]*.py"))) or None,
        "tests": _tests(),
        "ci_jobs": _ci_jobs(),
    }
    _cache.update(facts=facts, _at=time.monotonic())
    return _with_app(dict(facts), app)


def _with_app(facts: dict[str, Any], app: Any | None) -> dict[str, Any]:
    """Per-app parts (API operations, job kinds, queue) — computed per call, never cached."""
    if app is not None:
        try:
            paths = app.openapi().get("paths", {})
            facts["api_operations"] = sum(
                1
                for ops in paths.values()
                for m in ops
                if m in ("get", "post", "put", "patch", "delete")
            )
        except Exception:  # noqa: BLE001 - facts are best effort
            facts["api_operations"] = None
        queue = getattr(app.state, "queue", None)
        facts["job_kinds"] = sorted(getattr(queue, "handlers", {}) or [])
        facts["queue_backend"] = type(queue).__name__ if queue is not None else None
    return facts
