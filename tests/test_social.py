"""Fake social accounts: Facebook pages and Instagram profiles that pose as the brand.

The demo world (``demo/social.json``) has, for the fictional ShopNova: its own verified page and
Instagram account, a fake "ShopNova Support" page (new, renamed, run from abroad, the brand's logo,
"send us your card" and a link to a phishing site) with a linked "refund" Instagram, a fake
"ShopNova Israel | Official" giveaway profile linking to a scam shop, a self-declared fan club and a
bakery that only shares half the name.
"""

from __future__ import annotations

import asyncio
from datetime import date

import pytest
import sqlalchemy as sa
from tests.conftest import make_brand, make_workspace

import brandwatch.db.models as m
from brandwatch.config.settings import Settings
from brandwatch.db.enums import DiscoverySource, Severity
from brandwatch.detection import relevance, social
from brandwatch.detection.runner import run_scan
from brandwatch.events.emitter import replay

PROFILE = {"countries": ["IL", "US"], "official_social": ["https://www.facebook.com/shopnova", "instagram:shopnova"]}


# ------------------------------------------------------------------------------------ units
@pytest.mark.parametrize(("url", "want"), [
    ("https://www.instagram.com/shopnova.israel.official/", ("instagram", "shopnova.israel.official")),
    ("https://www.instagram.com/p/CxAbC123/", None),
    ("https://www.facebook.com/shopnova.support.help", ("facebook", "shopnova.support.help")),
    ("https://www.facebook.com/profile.php?id=100094400000001", ("facebook", "100094400000001")),
    ("https://www.facebook.com/people/Shop-Nova/100094400000002/", ("facebook", "100094400000002")),
    ("https://www.facebook.com/groups/shopnovafans/", None),
    ("https://example.com/shopnova", None),
])  # fmt: skip
def test_parse_profile_url(url, want):
    assert social.parse_profile_url(url) == want


def test_official_accounts_from_profile_and_website():
    html = '<footer><a href="https://www.facebook.com/shopnova">fb</a><a href="https://instagram.com/shopnova/">ig</a></footer>'
    learned = social.social_links(html)
    assert learned == ["facebook:shopnova", "instagram:shopnova"]
    assert social.official_handles({"official_social": ["https://www.facebook.com/ShopNova"]}, learned) == {
        "facebook:shopnova", "instagram:shopnova",
    }  # fmt: skip


def _terms():
    return relevance.brand_terms("ShopNova", "shopnova", official_domains=["shopnova.com"])


def test_signals_for_a_fake_support_page():
    acc = social.Account("facebook", "shopnova.support.help", "ShopNova Support", "https://www.facebook.com/shopnova.support.help",
                         page={"page_id": "1", "likes": 212, "verified": False},
                         info={"about": "Official ShopNova customer care. Message us your order number and the card you paid with. https://shopnova-refund.net/",
                               "created": "2026-09-23", "name_changes": [{"at": "2026-10-02"}], "admin_countries": {"VN": 2}})  # fmt: skip
    acc.avatar_phash = "f" * 16
    fired, pen = social.account_signals(acc, terms=_terms(), brand_name="ShopNova", brand_key="shopnova",
                                        official_domains={"shopnova.com"}, countries=["IL", "US"], logo_phash="f" * 16,
                                        today=date(2026, 10, 11))  # fmt: skip
    for sig in ("social_claims_official", "social_logo_match", "social_links_off_brand", "social_scam_lures",
                "social_new_account", "social_renamed", "social_admins_abroad", "social_small_audience"):  # fmt: skip
        assert sig in fired, sig
    assert "shopnova-refund.net" in fired["social_links_off_brand"] and not pen
    s = social.score_social(fired, pen, thresholds={"medium": 25, "high": 50, "critical": 75}, checks=3, unavailable=[])
    assert s["severity"] is Severity.CRITICAL


def test_fan_page_and_verified_page_are_penalised():
    fan = social.Account("facebook", "shopnovarunners", "ShopNova Runners Club", "u",
                         info={"about": "Unofficial fan group. Not affiliated with ShopNova.", "created": "2023-01-01"},
                         page={"likes": 4800})  # fmt: skip
    fired, pen = social.account_signals(fan, terms=_terms(), brand_name="ShopNova", brand_key="shopnova", official_domains=set(),
                                        countries=["US"], logo_phash=None, today=date(2026, 10, 11))  # fmt: skip
    assert "social_says_unofficial" in pen and "social_claims_official" not in fired
    real = social.Account("facebook", "shopnova", "ShopNova", "u", page={"verified": True, "likes": 182400})
    _f, pen2 = social.account_signals(real, terms=_terms(), brand_name="ShopNova", brand_key="shopnova", official_domains=set(),
                                      countries=["US"], logo_phash=None)  # fmt: skip
    assert "social_verified" in pen2


# ------------------------------------------------------------------------------------ end to end (demo)
def _scan(engine, tmp_path, profile=PROFILE):
    from brandwatch.db.base import make_session_factory

    settings = Settings(_env_file=None, demo_mode=True, evidence_dir=str(tmp_path / "ev"))
    with make_session_factory(engine)() as session:
        ws = make_workspace(session, "social")
        brand = make_brand(session, ws, "ShopNova")
        brand.profile = profile
        session.add(m.BrandDomain(brand_id=brand.id, domain="shopnova.com"))
        session.add(m.Config(brand_id=brand.id, preset="basic", detection={"streams": ["ct"], "max_candidates": 40},
                             economic_limits={}, scoring={}))  # fmt: skip
        job = m.ScanJob(workspace_id=ws.id, brand_id=brand.id, kind="brand_scan")
        session.add(job)
        session.flush()
        summary = asyncio.run(run_scan(session, job.id, settings=settings, max_candidates=40))
        session.commit()
        rows = session.execute(
            sa.select(m.Finding, m.Candidate).join(m.Candidate, m.Candidate.id == m.Finding.candidate_id).where(m.Finding.brand_id == brand.id)
        ).all()  # fmt: skip
        findings = {c.hostname: (f, social.social_record_of(f)) for f, c in rows}
        cands = {c.hostname: c for c in session.scalars(sa.select(m.Candidate).where(m.Candidate.brand_id == brand.id)).all()}
        events = replay(session, job.id)
        sources = {c.hostname: {s.source for s in c.sources} for c in cands.values()}
        return summary, findings, cands, events, sources


@pytest.fixture(scope="module")
def social_scan(engine, tmp_path_factory):
    return _scan(engine, tmp_path_factory.mktemp("social"))


def test_fake_accounts_become_social_findings(social_scan):
    _summary, findings, _cands, _events, _sources = social_scan
    page = findings["facebook.com/shopnova.support.help"]
    giveaway = findings["instagram.com/shopnova.israel.official"]
    for f, rec in (page, giveaway):
        assert f.kind == "social" and f.severity in (Severity.HIGH, Severity.CRITICAL), (f.kind, f.severity)
        assert rec["ai"]["verdict"] == "impersonation" and rec["scoring_version"].startswith("social-v1-")
    rec = page[1]
    assert rec["ig"]["username"] == "shopnova_refunds"  # the linked Instagram account was read too
    assert {"social_logo_match", "social_renamed", "social_links_off_brand"} <= set(page[0].current_score.signals)


def test_official_fan_and_unrelated_accounts_are_not_findings(social_scan):
    _summary, findings, cands, events, _sources = social_scan
    assert "facebook.com/shopnova" not in findings and "facebook.com/shopnova" not in cands  # the brand's own page
    assert "facebook.com/novashopbakery" not in cands  # only shares half the name
    fan = cands.get("facebook.com/shopnovarunners")
    assert fan is not None and "facebook.com/shopnovarunners" not in findings  # watched, not raised
    assert fan.next_scan_at is None  # never queued for the website re-scan
    done = next(e for e in events if e.step == "social" and e.stage == "discovery" and e.status == "done")
    assert "fake" in done.message


def test_links_from_fake_accounts_go_to_the_website_checks(social_scan):
    _summary, _findings, _cands, _events, sources = social_scan
    assert sources.get("shopnova-refund.net")  # also found by certificate logs: that stream keeps it
    assert DiscoverySource.SOCIAL in sources.get("onestyle-shopping.com", set())  # only the fake account led here


def test_social_finding_page_and_report_to_meta(engine, tmp_path):
    from fastapi.testclient import TestClient
    from tests.test_demo_story import _api, _app, _ui

    app = _app(engine, tmp_path)
    with TestClient(app):
        c = _api(app)
        b = c.post("/api/brands", json={"name": "ShopNova", "domains": ["shopnova.com"]}).json()
        c.put(f"/api/brands/{b['id']}/search-queries", json={"queries": ["shopnova login"]})
        job = c.post(f"/api/brands/{b['id']}/scan", json={"max_candidates": 10}).json()["job_id"]
        for _ in range(240):
            if c.get(f"/api/jobs/{job}").json()["state"] in ("done", "failed"):
                break
            asyncio.run(asyncio.sleep(0.25))
        rows = c.get("/api/findings", params={"brand_id": b["id"], "kind": "social"}).json()
        hosts = {r["hostname"] for r in rows}
        assert "facebook.com/shopnova.support.help" in hosts
        fid = next(r["id"] for r in rows if r["hostname"] == "facebook.com/shopnova.support.help")
        page = _ui(app).get(f"/ui/findings/{fid}").text
        assert "Social account" in page and "Report to Meta" in page and "ShopNova Support" in page
        # "this is our account": whitelisted, the finding closes, the next scan skips it
        r = c.post(f"/api/findings/{fid}/official-account")
        assert r.status_code == 200
        got = c.get(f"/api/brands/{b['id']}").json()
        assert "facebook:shopnova.support.help" in got["profile"]["official_social"]
        assert c.get(f"/api/findings/{fid}").json()["finding"]["state"] == "dismissed"


def test_avatar_fetch_only_from_meta_image_hosts():
    assert asyncio.run(social._avatar("http://169.254.169.254/latest/meta-data", False)) is None
    assert asyncio.run(social._avatar("https://evil.example/x.png", False)) is None
    assert asyncio.run(social._avatar("demo:icons/_brand.png", False)) is None  # demo assets only in demo mode
    assert asyncio.run(social._avatar("demo:../../../../etc/passwd", True)) is None
    assert asyncio.run(social._avatar("demo:icons/_brand.png", True))

