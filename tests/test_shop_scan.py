"""Suspicious shops end to end in demo mode: a retail brand's scan finds the shops advertised on
Meta, checks them, and turns the scams into "shop" findings — while the genuine retailer, the
brand's own site and every phishing scenario keep their old verdicts."""

from __future__ import annotations

import asyncio

import pytest
import sqlalchemy as sa
from tests.conftest import make_brand, make_workspace

import brandwatch.db.models as m
from brandwatch.config.settings import Settings
from brandwatch.db.enums import DiscoverySource, Severity
from brandwatch.detection import merchant
from brandwatch.detection.discovery import manual_hits
from brandwatch.detection.runner import run_scan
from brandwatch.detection.sources import clean_ad_link
from brandwatch.providers.mock.fixtures import default_store

PROFILE = {
    "countries": ["IL", "US"],
    "ad_keywords": ["shopnova runner"],
    "products": [
        {
            "name": "ShopNova Runner",
            "price": 799,
            "currency": "ILS",
            "country": "IL",
            "source": "analyst",
        },
        {
            "name": "ShopNova Runner",
            "price": 150,
            "currency": "USD",
            "country": "US",
            "source": "analyst",
        },
    ],
}
SCAMS = ("onestyle-shopping.com", "footstyle-il.com", "runnerhub-sale.com")


def _scan(engine, tmp_path, *, kind: str, hits=None):
    from brandwatch.db.base import make_session_factory

    settings = Settings(_env_file=None, demo_mode=True, evidence_dir=str(tmp_path / "ev"))
    with make_session_factory(engine)() as session:
        ws = make_workspace(session, f"shops-{kind}")
        brand = make_brand(session, ws, "ShopNova")
        brand.kind, brand.profile = kind, PROFILE
        session.add(m.BrandDomain(brand_id=brand.id, domain="shopnova.com"))
        job = m.ScanJob(
            workspace_id=ws.id, brand_id=brand.id, kind="brand_scan" if hits is None else "url_scan"
        )
        session.add(job)
        session.flush()
        summary = asyncio.run(
            run_scan(session, job.id, settings=settings, hits=hits, max_candidates=60)
        )
        session.commit()
        findings = {
            c.hostname: f
            for f, c in session.execute(
                sa.select(m.Finding, m.Candidate).join(m.Candidate, m.Candidate.id == m.Finding.candidate_id)
                .where(m.Finding.brand_id == brand.id)
            ).all()
        }  # fmt: skip
        sources = {
            c.hostname: {s.source for s in c.sources}
            for c in session.scalars(
                sa.select(m.Candidate).where(m.Candidate.brand_id == brand.id)
            ).all()
        }
        records = {
            h: (f.current_score.groups or {}).get("_breakdown", {})
            for h, f in findings.items()
            if f.current_score
        }
        return summary, findings, sources, records


@pytest.fixture(scope="module")
def retail_scan(engine, tmp_path_factory):
    return _scan(engine, tmp_path_factory.mktemp("retail"), kind="retail")


def test_meta_ads_stream_finds_the_advertised_shops(retail_scan):
    summary, findings, sources, records = retail_scan
    for host in (*SCAMS, "sportzone-il.co.il"):
        assert DiscoverySource.META_ADS in sources.get(host, set()), host
    step = next(s for s in summary.steps if s["title"].startswith("Searched Meta ads"))
    assert "shop(s) to check" in step["detail"]


def test_scam_shops_become_shop_findings_with_every_ad(retail_scan):
    _summary, findings, _sources, records = retail_scan
    for host in SCAMS:
        f = findings[host]
        assert f.kind == "shop" and f.severity in (Severity.HIGH, Severity.CRITICAL), (
            host,
            f.kind,
            f.severity,
        )
        assert f.current_score.scoring_version == merchant.SHOP_SCORING_VERSION
    one = records["onestyle-shopping.com"]["shop"]
    assert one["registry"]["status"] == "not_found" and one["web"]["warnings"]
    assert len(one["ads"]) == 2 and one["ads"][0]["library_url"].startswith(
        "https://www.facebook.com/ads/library/?id="
    )
    assert (
        one["price"]["ratio"]
        and one["price"]["ratio"] <= 0.5
        and one["ai"]["verdict"] == "likely_scam"
    )
    signals = findings["onestyle-shopping.com"].current_score.signals
    for sig in ("shop_company_not_in_registry", "shop_price_far_below_official", "shop_free_email_only",
                "shop_no_policy_pages", "shop_reviews_warn", "shop_new_domain", "shop_multibuy_bait"):  # fmt: skip
        assert sig in signals, sig
    assert records["onestyle-shopping.com"]["phishing"]["severity"] in (
        "low",
        "medium",
    )  # kept beside it


def test_genuine_retailer_is_not_a_shop_finding(retail_scan):
    _summary, findings, _sources, _records = retail_scan
    f = findings.get("sportzone-il.co.il")
    assert f is None or f.kind != "shop" or f.severity is Severity.LOW


def test_service_brand_never_runs_shop_checks(engine, tmp_path):
    store = default_store()
    urls = [store.get(h).url for h in SCAMS]
    summary, findings, sources, records = _scan(
        engine, tmp_path, kind="service", hits=manual_hits(urls)
    )
    assert all(f.kind == "phishing" for f in findings.values())
    assert all("shop" not in r for r in records.values())
    assert not any(s["title"].startswith("Searched Meta ads") for s in summary.steps)


def test_clean_ad_link_unwraps_and_strips_tracking():
    wrapped = "https://l.facebook.com/l.php?u=https%3A%2F%2Fshop.example%2Fp%2Fon%3Futm_source%3Dfb%26size%3D42%26fbclid%3DX&h=AT0"
    assert clean_ad_link(wrapped) == "https://shop.example/p/on?size=42"
    assert clean_ad_link("https://SHOP.example/?gclid=1") == "https://shop.example/"
