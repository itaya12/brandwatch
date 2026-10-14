"""Golden-dataset evaluation (spec §18): precision / recall / FP rate / FN rate over the recorded
scenarios, run through the real pipeline in demo mode. Every scoring change must keep this green.

Decision rule under test: a *Finding with severity ≥ High* is a phishing call. Medium findings are
"suspicious" (analyst triage), Low → watchlist.
"""

from __future__ import annotations

import pytest
import sqlalchemy as sa
from tests.conftest import make_brand, make_workspace

import brandwatch.db.models as m
from brandwatch.config.settings import Settings
from brandwatch.db.enums import Severity
from brandwatch.detection.discovery import manual_hits
from brandwatch.detection.runner import run_scan
from brandwatch.providers.mock.fixtures import LABELS, default_store

MIN_PRECISION = 0.90
MIN_RECALL = 0.90
MAX_FP_RATE = 0.05


def _is_phish_call(outcome) -> bool:
    return outcome.disposition == "finding" and outcome.severity in (
        Severity.HIGH,
        Severity.CRITICAL,
    )


@pytest.fixture(scope="module")
def golden_run(engine, tmp_path_factory):
    """Run the whole golden set once per module (≈40 scenarios) and share the outcomes."""
    import asyncio

    from brandwatch.db.base import make_session_factory

    store = default_store()
    scenarios = [s for s in store.all() if "OFFICIAL" not in s.notes]
    settings = Settings(
        _env_file=None, demo_mode=True, evidence_dir=str(tmp_path_factory.mktemp("ev"))
    )
    with make_session_factory(engine)() as session:
        ws = make_workspace(session, "golden")
        brand = make_brand(session, ws, "ShopNova")
        session.add(m.BrandDomain(brand_id=brand.id, domain="shopnova.com"))
        job = m.ScanJob(workspace_id=ws.id, brand_id=brand.id, kind="url_scan")
        session.add(job)
        session.flush()
        summary = asyncio.run(
            run_scan(
                session, job.id, settings=settings, hits=manual_hits([s.url for s in scenarios])
            )
        )
        session.commit()
        by_host = {o.host: o for o in summary.outcomes}
        return {"scenarios": scenarios, "by_host": by_host, "summary": summary}


def test_every_scenario_was_processed_without_errors(golden_run):
    by_host, scenarios = golden_run["by_host"], golden_run["scenarios"]
    missing = [s.host for s in scenarios if s.host not in by_host]
    assert missing == []
    assert golden_run["summary"].errors == 0, [
        o.error for o in golden_run["summary"].outcomes if o.error
    ]


def test_golden_metrics(golden_run):
    by_host, scenarios = golden_run["by_host"], golden_run["scenarios"]
    tp = fp = fn = tn = 0
    rows: list[str] = []
    per_class_fp: dict[str, list[str]] = {label: [] for label in LABELS}
    for s in scenarios:
        o = by_host[s.host]
        call = _is_phish_call(o)
        if s.is_phishing and call:
            tp += 1
        elif s.is_phishing and not call:
            fn += 1
        elif not s.is_phishing and call:
            fp += 1
            per_class_fp[s.label].append(s.host)
        else:
            tn += 1
        rows.append(
            f"{s.label:24s} {s.host:32s} {o.disposition:9s} "
            f"{(o.severity.value if o.severity else '-'):8s} score={o.score if o.score is not None else '-':>3} "
            f"conf={f'{o.confidence:.0f}' if o.confidence is not None else '-':>3}  {'PHISH' if call else '-'}"
        )
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    fp_rate = fp / (fp + tn) if fp + tn else 0.0
    fn_rate = fn / (tp + fn) if tp + fn else 0.0
    report = "\n".join(
        [
            "",
            f"golden dataset: {len(scenarios)} scenarios | TP={tp} FP={fp} FN={fn} TN={tn}",
            f"precision={precision:.2f} recall={recall:.2f} fp_rate={fp_rate:.2f} fn_rate={fn_rate:.2f}",
            f"false positives by class: { {k: v for k, v in per_class_fp.items() if v} }",
            *rows,
        ]
    )
    print(report)
    assert precision >= MIN_PRECISION, report
    assert recall >= MIN_RECALL, report
    assert fp_rate <= MAX_FP_RATE, report


def test_brand_related_legit_sites_never_become_findings_above_medium(golden_run):
    """Where the real FP problem lives (spec §18): partners / fans / status pages."""
    by_host = golden_run["by_host"]
    for s in default_store().by_label("brand_related_legit"):
        o = by_host[s.host]
        assert not _is_phish_call(o), (s.host, o.severity, o.signals)


def test_parked_typo_goes_to_watchlist_not_finding(golden_run):
    o = golden_run["by_host"]["shopnovaa.com"]
    assert o.disposition == "watch"


def test_unknown_reputation_is_never_treated_as_clean(golden_run, engine):
    from brandwatch.db.base import make_session_factory

    with make_session_factory(engine)() as s:
        verdicts = s.scalars(
            sa.select(m.ReputationObservation.status).where(
                m.ReputationObservation.provider == "virustotal"
            )
        ).all()
    assert verdicts and all(v.value in ("positive", "negative", "unknown") for v in verdicts)
    assert any(v.value == "unknown" for v in verdicts)
