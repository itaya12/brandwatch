"""How far the Facebook / Instagram ad hunt goes, per brand: ads per search (paging through the Ad
Library), searches per scan, and the shops checked in full — saved in the brand profile, with the
cost per scan shown before anything is spent."""

from __future__ import annotations

import asyncio
import uuid

import sqlalchemy as sa
from fastapi.testclient import TestClient
from tests.conftest import make_brand, make_workspace
from tests.test_demo_story import _api, _app, _ui

import brandwatch.db.models as m
from brandwatch.config.settings import Settings
from brandwatch.db.enums import ProviderStatus
from brandwatch.detection import ad_settings, sources
from brandwatch.providers.base import ProviderResult


class _Ads:
    """An Ad Library with 95 ads for every search, 30 a page."""

    def __init__(self):
        self.calls: list[tuple[str, str, str | None]] = []

    async def meta_ads(self, query, country, active_status="active", next_page_token=None):
        self.calls.append((query, country, next_page_token))
        start = int(next_page_token or 0)
        ads = [{"ad_id": f"{country}{i}", "page_name": f"Page {i}", "text": f"{query} sale {i}",
                "link_url": f"https://shop{i}.example/p", "library_url": f"https://www.facebook.com/ads/library/?id={i}"}
               for i in range(start, min(start + 30, 95))]  # fmt: skip
        nxt = str(start + 30) if start + 30 < 95 else None
        return ProviderResult("t", ProviderStatus.POSITIVE, {"ads": ads, "total": 95, "next_page_token": nxt})


class _P:
    def __init__(self):
        self.a = _Ads()

    def ads(self):
        return self.a


def test_ads_per_search_pages_through_the_library():
    p = _P()
    r = asyncio.run(sources.stream_meta_ads(p, ["on cloud"], ["US"], set(), ads_per_search=60))
    assert [c[2] for c in p.a.calls] == [None, "30"]  # two pages for 60 ads
    assert len(r.seen) == 60 and r.api_calls == 2 and r.ad_totals == {"on cloud|US": 95}
    p = _P()
    r = asyncio.run(sources.stream_meta_ads(p, ["on cloud"], ["US"], set(), ads_per_search=200))
    assert len(p.a.calls) == 4 and len(r.seen) == 95  # stops when Meta has no more pages
    p = _P()
    r = asyncio.run(sources.stream_meta_ads(p, ["a", "b"], ["US", "IL"], set(), ads_per_search=30, max_queries=3))
    assert len({(q, c) for q, c, _t in p.a.calls}) == 3  # searches per scan caps keywords × countries


def test_settings_and_cost():
    assert ad_settings.settings(None) == {"ads_per_search": 30, "ad_searches_max": 6, "shops_checked_max": 15}
    assert ad_settings.settings({"ads_per_search": 9999, "ad_searches_max": 0})["ads_per_search"] == 300
    c = ad_settings.cost({"ads_per_search": 100, "ad_searches_max": 6, "shops_checked_max": 20}, keywords=2, countries=2)
    assert c["searches"] == 4 and c["requests"] == 16 and c["ads_max"] == 400  # 100 ads = 4 pages
    assert abs(c["ads_usd"] - 0.064) < 1e-9 and abs(c["shops_usd"] - 0.42) < 1e-9


def test_the_profile_saves_the_numbers_and_the_scan_uses_them(engine, tmp_path):
    app = _app(engine, tmp_path)
    with TestClient(app):
        c, ui = _api(app), _ui(app)
        b = c.post("/api/brands", json={"name": f"ShopNova {uuid.uuid4().hex[:4]}", "domains": ["shopnova.com"],
                                        "kind": "retail"}).json()  # fmt: skip
        assert c.get(f"/api/brands/{b['id']}").json()["profile"]["ads_per_search"] == 30
        page = ui.get(f"/ui/brands/{b['id']}").text
        assert 'name="ads_per_search"' in page and "Shops checked in full" in page
        r = ui.post(f"/ui/brands/{b['id']}/profile", data={
            "kind": "retail", "countries": "IL", "ad_keywords": "shopnova runner",
            "ads_per_search": "100", "ad_searches_max": "4", "shops_checked_max": "1"}, follow_redirects=False)  # fmt: skip
        assert r.status_code == 303
        prof = c.get(f"/api/brands/{b['id']}").json()["profile"]
        assert (prof["ads_per_search"], prof["ad_searches_max"], prof["shops_checked_max"]) == (100, 4, 1)
        assert c.put(f"/api/brands/{b['id']}/profile", json={"kind": "retail", "ad_searches_max": 99}).status_code == 422
        setup = ui.get(f"/ui/brands/{b['id']}/setup").text
        assert 'value="100" selected' in setup


def test_only_the_set_number_of_shops_get_the_paid_checks(engine, tmp_path):
    from tests.test_shop_scan import PROFILE

    from brandwatch.db.base import make_session_factory
    from brandwatch.detection.runner import run_scan

    settings = Settings(_env_file=None, demo_mode=True, evidence_dir=str(tmp_path / "ev"))
    with make_session_factory(engine)() as s:
        ws = make_workspace(s, f"reach-{uuid.uuid4().hex[:6]}")
        brand = make_brand(s, ws, "ShopNova")
        brand.kind, brand.profile = "retail", {**PROFILE, "shops_checked_max": 2}
        s.add(m.BrandDomain(brand_id=brand.id, domain="shopnova.com"))
        job = m.ScanJob(workspace_id=ws.id, brand_id=brand.id, kind="brand_scan")
        s.add(job)
        s.flush()
        asyncio.run(run_scan(s, job.id, settings=settings, max_candidates=60))
        s.commit()
        runs = s.scalars(sa.select(m.ScanEventRecord).where(m.ScanEventRecord.job_id == job.id, m.ScanEventRecord.stage == "shop",
                                                      m.ScanEventRecord.status == "running")).all()  # fmt: skip
        assert len(runs) == 2  # "Shop checks for …: company registry, Google, reviews, AI" — only two shops


# ------------------------------------------------------------------------------------ brand-only keywords
def test_keywords_must_point_to_the_brand_alone():
    from brandwatch.detection.ai import brand_specific

    models = ["nuptse", "denali"]
    for ok in ("the north face", "north face", "tnf", "nuptse jacket", "the north face mountain jacket"):
        assert brand_specific(ok, "The North Face", models), ok
    for generic in ("mountain jacket", "hiking boots", "thermal fleece", "face mask", "north"):
        assert not brand_specific(generic, "The North Face", models), generic


def test_the_ai_suggestion_leaves_out_generic_keywords(engine, tmp_path):
    app = _app(engine, tmp_path)
    with TestClient(app):
        c = _api(app)
        b = c.post("/api/brands", json={"name": f"ShopNova {uuid.uuid4().hex[:4]}", "domains": ["shopnova.com"],
                                        "kind": "retail"}).json()  # fmt: skip
        s = c.post(f"/api/brands/{b['id']}/profile/suggest", json={"countries": ["US"]}).json()
        assert s["available"] and "trail running shoes" in s["dropped_keywords"]  # the mock slipped it in
        assert "running shoes" not in s["model_lines"]  # a "model line" made of category words is not one
        assert all("shopnova" in k.replace(" ", "") for k in s["ad_keywords"]), s["ad_keywords"]
        assert s["ad_keywords"][0] == b["name"].lower()  # the brand's name always leads
        s2 = c.post(f"/api/brands/{b['id']}/profile/suggest",
                    json={"countries": ["US"], "current_keywords": ["mountain jacket", b["name"].lower() + " runner"]}).json()  # fmt: skip
        assert s2["generic_current"] == ["mountain jacket"]  # the form removes it; the brand's own one stays
        page = _ui(app).get(f"/ui/brands/{b['id']}/setup").text
        assert "never “mountain jacket”" in page and "Left out as too generic" in page


def test_generic_words_never_make_an_ad_about_the_brand():
    from brandwatch.detection import relevance as r

    t = r.brand_terms("The North Face", "thenorthface", ad_keywords=["the north face", "mountain jacket"],
                      products=["hiking boots"])  # fmt: skip
    assert "mountain jacket" not in t.phrases and "hiking boots" not in t.products
    assert r.ad_relevance({"text": "North Face Nuptse 50% off", "page_name": "Deals"}, t)[0] == "yes"
    assert r.ad_relevance({"text": "Best mountain jacket sale", "page_name": "Columbia"}, t)[0] == "no"
    on = r.brand_terms("on cloud", "oncloud", ad_keywords=["on cloud"])
    assert r.ad_relevance({"text": "cloud storage on cloud nine", "page_name": "x"}, on)[0] == "maybe"  # still asks


def test_the_setup_buttons_are_not_clipped(engine, tmp_path):
    app = _app(engine, tmp_path)
    with TestClient(app):
        c = _api(app)
        b = c.post("/api/brands", json={"name": f"ShopNova {uuid.uuid4().hex[:4]}", "domains": ["shopnova.com"],
                                        "kind": "retail", "preset": "enterprise"}).json()  # fmt: skip
        page = _ui(app).get(f"/ui/brands/{b['id']}/setup").text
        assert 'class="setup-actions"' in page and 'class="bar"' not in page  # the global .bar is an 8px meter
