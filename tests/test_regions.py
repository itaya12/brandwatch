"""Regional campaigns of a global brand: a main brand and one child per country site.

The family protects each other (thenorthface.co.il is never a suspect of thenorthface.com's campaign), a
region copies the main brand's settings once and has its own domains / countries / language / queries,
country sites are suggested from the official homepage and added only when the analyst chooses, and one
suspect becomes one finding per family.
"""

from __future__ import annotations

import asyncio
import uuid

import sqlalchemy as sa
from fastapi.testclient import TestClient
from tests.conftest import make_brand, make_workspace
from tests.test_demo_story import _api, _app, _ui

import brandwatch.db.models as m
from brandwatch.config.settings import Settings
from brandwatch.detection import regions
from brandwatch.detection.discovery import manual_hits
from brandwatch.detection.runner import run_scan

HOME = """<html><head><title>The North Face</title>
<link rel="alternate" hreflang="en-US" href="https://www.thenorthface.com/">
<link rel="alternate" hreflang="he-IL" href="https://www.thenorthface.co.il/">
<link rel="alternate" hreflang="de-DE" href="https://www.thenorthface.de/">
</head><body><a href="https://www.thenorthface.fr/">France</a> <a href="https://twitter.com/thenorthface">tw</a>
<a href="https://www.google.com/">g</a> <a href="https://shop.thenorthface.com/x">own subdomain</a></body></html>"""


def _brand_with_region(session, name="ShopNova", main="shopnova.com", region="Israel", site="shopnova.co.il"):
    ws = make_workspace(session, f"fam-{uuid.uuid4().hex[:6]}")
    parent = make_brand(session, ws, name)
    session.add(m.BrandDomain(brand_id=parent.id, domain=main, is_official=True, kind="official"))
    child = m.Brand(workspace_id=ws.id, name=f"{name} · {region}", kind="service", parent_id=parent.id, region=region)
    session.add(child)
    session.flush()
    session.add(m.BrandDomain(brand_id=child.id, domain=site, is_official=True, kind="official"))
    session.flush()
    return ws, parent, child


# ------------------------------------------------------------------------------------ the family
def test_the_family_protects_each_other(session):
    _ws, parent, child = _brand_with_region(session)
    from brandwatch.detection.baseline import whitelist_domains

    assert regions.family_ids(session, parent.id) == regions.family_ids(session, child.id)
    assert set(regions.family_ids(session, child.id)) == {parent.id, child.id}
    for bid in (parent.id, child.id):  # either campaign protects both sites
        assert {"shopnova.com", "shopnova.co.il"} <= set(whitelist_domains(session, bid))
    assert regions.with_regions(session, parent.id) == [parent.id, child.id]
    assert regions.with_regions(session, child.id) == [child.id]  # a region covers itself only


def test_a_country_site_is_not_a_finding_of_the_main_brand(engine, tmp_path):
    """Without the family, thenorthface.co.il is "the brand on another TLD" with the brand's title: HIGH."""
    from brandwatch.db.base import make_session_factory

    settings = Settings(_env_file=None, demo_mode=True, evidence_dir=str(tmp_path / "ev"))
    with make_session_factory(engine)() as s:
        ws = make_workspace(s, f"fam2-{uuid.uuid4().hex[:6]}")
        main = make_brand(s, ws, "ShopNova")
        s.add(m.BrandDomain(brand_id=main.id, domain="shopnova.com"))
        job = m.ScanJob(workspace_id=ws.id, brand_id=main.id, kind="url_scan")
        s.add(job)
        s.flush()
        asyncio.run(run_scan(s, job.id, settings=settings, hits=manual_hits(["https://shopnova.co.il/"])))
        s.commit()
        assert s.scalars(sa.select(m.Finding).where(m.Finding.brand_id == main.id)).all(), "alone, the Israeli site is flagged"
        # now it is a region of the family: neither campaign flags it
        child = m.Brand(workspace_id=ws.id, name="ShopNova · Israel", kind="service", parent_id=main.id, region="Israel")
        s.add(child)
        s.flush()
        s.add(m.BrandDomain(brand_id=child.id, domain="shopnova.co.il", is_official=True, kind="official"))
        s.flush()
        from brandwatch.detection.protect import dismiss_protected

        for bid in regions.family_ids(s, main.id):
            dismiss_protected(s, bid)
        s.commit()
        opened = s.scalars(sa.select(m.Finding).where(m.Finding.brand_id == main.id, m.Finding.state == "open")).all()
        assert opened == []  # the earlier finding closed: it is the brand's own site


def test_one_suspect_one_finding_per_family(engine, tmp_path):
    from brandwatch.db.base import make_session_factory

    settings = Settings(_env_file=None, demo_mode=True, evidence_dir=str(tmp_path / "ev"))
    with make_session_factory(engine)() as s:
        ws, parent, child = _brand_with_region(s, site="shopnova-il.com")
        for b in (parent, child):
            s.add(m.Config(brand_id=b.id, preset="basic", detection={"streams": ["dnstwist"], "max_candidates": 20},
                           economic_limits={}, scoring={}))  # fmt: skip
        s.commit()
        url = "https://shopn0va.com/"  # a recorded phishing site both campaigns could find
        for brand in (parent, child):
            job = m.ScanJob(workspace_id=ws.id, brand_id=brand.id, kind="url_scan")
            s.add(job)
            s.flush()
            summary = asyncio.run(run_scan(s, job.id, settings=settings, hits=manual_hits([url])))
            s.commit()
            if brand is child:
                assert any("already tracked by another regional campaign" in st["title"] for st in summary.steps)
        n = s.scalar(sa.select(sa.func.count()).select_from(m.Finding).join(m.Candidate, m.Candidate.id == m.Finding.candidate_id)
                     .where(m.Candidate.canonical_domain == "shopn0va.com", m.Finding.brand_id.in_([parent.id, child.id])))  # fmt: skip
        assert n == 1


# ------------------------------------------------------------------------------------ country sites
def test_country_sites_are_read_from_the_official_homepage():
    found = regions.country_sites(HOME, "https://www.thenorthface.com/", "thenorthface", {"thenorthface.com"})
    by = {r["domain"]: r for r in found}
    assert set(by) == {"thenorthface.co.il", "thenorthface.de", "thenorthface.fr"}  # not twitter, google, its own subdomain
    assert by["thenorthface.co.il"]["country"] == "IL" and by["thenorthface.co.il"]["hreflang"] == "he-IL"
    assert by["thenorthface.co.il"]["region"] == "Israel" and by["thenorthface.fr"]["country"] == "FR"  # from the ccTLD
    assert regions.country_sites("", "https://x.com/", "thenorthface", set()) == []
    assert regions.country_sites(HOME, "https://x.com/", "", set()) == []


# ------------------------------------------------------------------------------------ the API and pages
def _main(c, name="ShopNova", preset="standard"):
    return c.post("/api/brands", json={"name": f"{name} {uuid.uuid4().hex[:4]}", "domains": ["shopnova.com"], "preset": preset,
                                       "kind": "retail"}).json()  # fmt: skip


def test_create_a_region_copies_the_main_brand_once(engine, tmp_path):
    app = _app(engine, tmp_path)
    with TestClient(app):
        c = _api(app)
        main = _main(c)
        c.put(f"/api/brands/{main['id']}/profile", json={
            "kind": "retail", "countries": ["US", "IL"], "ad_keywords": ["shopnova runner"], "ads_per_search": 60,
            "products": [{"name": "ShopNova Runner", "price": 150, "currency": "USD", "country": "US"},
                         {"name": "ShopNova Runner", "price": 799, "currency": "ILS", "country": "IL"}]})  # fmt: skip
        r = c.post(f"/api/brands/{main['id']}/regions", json={"region": "Israel", "domains": ["shopnova.co.il"]})
        assert r.status_code == 201
        child = r.json()
        assert child["parent_id"] == main["id"] and child["region"] == "Israel" and child["name"].endswith("· Israel")
        got = c.get(f"/api/brands/{child['id']}").json()
        assert got["domains"] == ["shopnova.co.il"] and got["kind"] == "retail"
        assert got["profile"]["countries"] == ["IL"] and got["profile"]["ads_per_search"] == 60
        assert [p["currency"] for p in got["profile"]["products"]] == ["ILS"]  # only the region's prices
        assert got["config"]["preset"] == "standard" and got["config"]["detection"]["search_geo"] == "il"
        assert got["config"]["detection"]["search_lang"] == "he"  # from the country
        assert got["search_queries"]["approved"] is False  # the region approves its own, in its language
        assert got["schedule"]["enabled"] is False
        parent = c.get(f"/api/brands/{main['id']}").json()
        assert [r["region"] for r in parent["regions"]] == ["Israel"] and parent["family_open_findings"] == 0
        # a region belongs to a main brand; the same region name twice is refused
        assert c.post(f"/api/brands/{child['id']}/regions", json={"region": "Xyz", "domains": ["x.de"]}).status_code == 409
        assert c.post(f"/api/brands/{main['id']}/regions", json={"region": "israel", "domains": ["other.co.il"]}).status_code == 409
        assert c.post(f"/api/brands/{main['id']}/regions", json={"region": "Mars", "domains": ["shopnova.co.il"]}).status_code == 409
        assert c.post(f"/api/brands/{main['id']}/regions", json={"region": "Nowhere", "domains": ["shopnova.example"]}).status_code == 422
        # a domain the main brand held as an alias moves to the region
        c.patch(f"/api/brands/{main['id']}", json={"domains": ["shopnova.com", "shopnova.de"]})
        assert c.post(f"/api/brands/{main['id']}/regions", json={"region": "Germany", "domains": ["shopnova.de"]}).status_code == 201
        assert c.get(f"/api/brands/{main['id']}").json()["domains"] == ["shopnova.com"]


def test_update_from_the_main_brand_keeps_what_is_the_regions_own(engine, tmp_path):
    app = _app(engine, tmp_path)
    with TestClient(app):
        c = _api(app)
        main = _main(c)
        child = c.post(f"/api/brands/{main['id']}/regions", json={"region": "Israel", "domains": ["shopnova.co.il"],
                                                                  "countries": ["IL"]}).json()  # fmt: skip
        c.put(f"/api/brands/{child['id']}/search-queries", json={"queries": ["שופנובה נעליים"]})
        c.patch(f"/api/brands/{main['id']}/config", json={"preset": "enterprise"})
        c.put(f"/api/brands/{main['id']}/profile", json={"kind": "retail", "ad_keywords": ["shopnova outlet"], "ad_searches_max": 9})
        r = c.post(f"/api/brands/{child['id']}/regions/sync")
        assert r.status_code == 200
        got = c.get(f"/api/brands/{child['id']}").json()
        assert got["config"]["preset"] == "enterprise" and got["profile"]["ad_keywords"] == ["shopnova outlet"]
        assert got["profile"]["ad_searches_max"] == 9
        assert got["config"]["detection"]["search_geo"] == "il" and got["profile"]["countries"] == ["IL"]  # its own
        assert got["search_queries"]["queries"] == ["שופנובה נעליים"] and got["domains"] == ["shopnova.co.il"]
        assert c.post(f"/api/brands/{main['id']}/regions/sync").status_code == 409  # a main brand has nothing to sync from


def test_a_main_brand_with_regions_cannot_be_deleted(engine, tmp_path):
    app = _app(engine, tmp_path)
    with TestClient(app):
        c = _api(app)
        main = _main(c)
        child = c.post(f"/api/brands/{main['id']}/regions", json={"region": "Israel", "domains": ["shopnova.co.il"]}).json()
        r = c.delete(f"/api/brands/{main['id']}")
        assert r.status_code == 409 and "delete them first" in r.json()["detail"]
        assert c.delete(f"/api/brands/{child['id']}").status_code == 204
        assert c.delete(f"/api/brands/{main['id']}").status_code == 204  # no regions left


def test_filters_follow_the_family(engine, tmp_path):
    from brandwatch.db.base import make_session_factory

    app = _app(engine, tmp_path)
    with TestClient(app):
        c = _api(app)
        main = _main(c)
        child = c.post(f"/api/brands/{main['id']}/regions", json={"region": "Israel", "domains": ["shopnova.co.il"]}).json()
        with make_session_factory(engine)() as s:
            for bid, host in ((main["id"], "fake-a.com"), (child["id"], "fake-b.co.il")):
                cand = m.Candidate(brand_id=uuid.UUID(bid), canonical_domain=host, canonical_url=f"https://{host}/", hostname=host,
                                   surface="name")  # fmt: skip
                s.add(cand)
                s.flush()
                s.add(m.Finding(candidate_id=cand.id, brand_id=uuid.UUID(bid), severity="high"))
            s.commit()
        by_main = {r["hostname"] for r in c.get("/api/findings", params={"brand_id": main["id"]}).json()}
        by_child = {r["hostname"] for r in c.get("/api/findings", params={"brand_id": child["id"]}).json()}
        assert by_main == {"fake-a.com", "fake-b.co.il"} and by_child == {"fake-b.co.il"}  # the main brand covers its regions
        assert c.get(f"/api/brands/{main['id']}").json()["family_open_findings"] == 2
        brands = [b["name"] for b in c.get("/api/brands").json()]
        assert brands.index(child["name"]) == brands.index(main["name"]) + 1  # right after its main brand


def test_country_sites_suggested_added_and_ignored(engine, tmp_path):
    from brandwatch.db.base import make_session_factory

    app = _app(engine, tmp_path)
    with TestClient(app):
        c, ui = _api(app), _ui(app)
        main = _main(c, preset="enterprise")  # a track that searches Google: the region must approve its own queries
        with make_session_factory(engine)() as s:
            s.add(m.BrandFingerprint(brand_id=uuid.UUID(main["id"]), version=1, features={"country_sites": [
                {"domain": "shopnova.co.il", "hreflang": "he-IL", "country": "IL", "region": "Israel"},
                {"domain": "shopnova.de", "hreflang": "de-DE", "country": "DE", "region": "Germany"},
                {"domain": "shopnova.fr", "hreflang": None, "country": "FR", "region": "France"}]}))
            s.commit()
        got = c.get(f"/api/brands/{main['id']}").json()["country_sites"]
        assert {r["domain"] for r in got} == {"shopnova.co.il", "shopnova.de", "shopnova.fr"}
        page = ui.get(f"/ui/brands/{main['id']}").text
        for needle in ("Country sites found on shopnova.com", "Add as a region", "Add as an official domain", "Ignore"):
            assert needle in page, needle
        # nothing happens until the analyst chooses
        r = ui.post(f"/ui/brands/{main['id']}/country-sites", data={"domain": "shopnova.co.il", "action": "region",
                                                                     "region": "Israel", "countries": "IL"}, follow_redirects=False)  # fmt: skip
        assert r.status_code == 303 and r.headers["location"].endswith("/setup")  # the new region's set-up page
        r = ui.post(f"/ui/brands/{main['id']}/country-sites", data={"domain": "shopnova.de", "action": "domain"}, follow_redirects=False)
        assert r.status_code == 303 and "region=added" in r.headers["location"]
        r = ui.post(f"/ui/brands/{main['id']}/country-sites", data={"domain": "shopnova.fr", "action": "ignore"}, follow_redirects=False)
        assert r.status_code == 303
        assert c.get(f"/api/brands/{main['id']}").json()["country_sites"] == []  # all three decided
        assert "shopnova.de" in c.get(f"/api/brands/{main['id']}").json()["domains"]
        assert c.post(f"/api/brands/{main['id']}/country-sites", json={"domain": "nope.com", "action": "ignore"}).status_code == 404
        # the regional panel, on the region's page
        child = c.get(f"/api/brands/{main['id']}").json()["regions"][0]
        rp = ui.get(f"/ui/brands/{child['id']}").text
        assert "Regional campaign" in rp and "Update from" in rp
        assert "Set up &amp; start the scan" in rp  # its own queries still wait for approval
        lst = ui.get("/ui/brands").text
        assert "regional campaign of" in lst and "1 region: Israel" in lst


def test_the_baseline_stores_country_sites(engine, tmp_path):
    """build_baseline reads the official homepage it already fetched: ShopNova's recorded site links shopnova.co.il."""
    from brandwatch.db.base import make_session_factory

    app = _app(engine, tmp_path)
    with TestClient(app):
        c = _api(app)
        main = _main(c)
        job = c.post(f"/api/brands/{main['id']}/baseline").json()
        assert job.get("version") or job.get("fingerprint_id")
        sites = c.get(f"/api/brands/{main['id']}").json()["country_sites"]
        assert [s["domain"] for s in sites] == ["shopnova.co.il"] and sites[0]["country"] == "IL"
    with make_session_factory(engine)() as s:
        assert s.scalar(sa.select(sa.func.count()).select_from(m.BrandFingerprint)) >= 1


def test_a_region_searches_for_the_brands_own_name(engine, tmp_path):
    """"ShopNova · Israel" is the display name; its Google queries / ads / social search use "ShopNova"."""
    app = _app(engine, tmp_path)
    with TestClient(app):
        c = _api(app)
        main = _main(c, preset="enterprise")
        child = c.post(f"/api/brands/{main['id']}/regions", json={"region": "Israel", "domains": ["shopnova.co.il"]}).json()
        queries = c.get(f"/api/brands/{child['id']}").json()["search_queries"]["proposal"]
        assert queries and not any("israel" in q.lower() for q in queries), queries  # not "shopnoavisrael"
        assert all("shopnova" in q.replace(" ", "") for q in queries[:2]), queries
    from brandwatch.db.models import Brand

    b = Brand(name="The North Face · Israel", parent_id=uuid.uuid4(), region="Israel")
    assert b.search_name == "The North Face"
    assert Brand(name="On · Israel").search_name == "On · Israel"  # not a region: the name is the name
