"""Suspicious shops (phase 1): the brand's commerce profile, the Meta-ads stream, the shop checks and
the "Suspicious shop" finding kind."""

import uuid

from fastapi.testclient import TestClient
from tests.test_demo_story import _api, _app

from brandwatch.detection import ai


def _brand(c, *, kind="retail", name=None):
    return c.post(
        "/api/brands",
        json={
            "name": name or f"ShopNova {uuid.uuid4().hex[:4]}",
            "domains": ["shopnova.com"],
            "kind": kind,
        },
    ).json()


def test_commerce_profile_suggest_and_save(engine, tmp_path):
    app = _app(engine, tmp_path)
    with TestClient(app):
        c = _api(app)
        b = _brand(c)
        assert b["kind"] == "retail" and b["profile"]["countries"] == []

        sug = c.post(
            f"/api/brands/{b['id']}/profile/suggest", json={"countries": ["il", "uk"]}
        ).json()
        assert sug["available"] and sug["countries"] == ["IL", "GB"] and sug["resold_by_retailers"]
        assert {p["country"] for p in sug["products"]} == {"IL", "GB"} and sug["products"][0][
            "source"
        ] == "ai"
        assert sug["authorized_retailers"][0]["domain"].endswith("-partners.com")

        saved = c.put(f"/api/brands/{b['id']}/profile", json={
            "kind": "retail", "countries": ["IL", "il", "US"], "ad_keywords": ["On Cloud", "on cloud", "און קלאוד"],
            "products": [{"name": "Cloud 6", "price": 699, "currency": "ILS", "country": "IL", "source": "ai"}],
            "retailers": ["https://www.footlocker.co.il/", "shopnova.com"],  # the official domain is never a retailer
        }).json()  # fmt: skip
        assert saved["profile"]["countries"] == ["IL", "US"]
        assert saved["profile"]["ad_keywords"] == [
            "on cloud",
            "און קלאוד",
        ]  # any script, de-duplicated
        assert saved["retailers_added"] == ["footlocker.co.il"]
        wl = c.get(f"/api/brands/{b['id']}").json()["whitelist"]
        assert any(w["domain"] == "footlocker.co.il" and w["kind"] == "reseller" for w in wl)
        # saving again does not duplicate the retailer
        again = c.put(
            f"/api/brands/{b['id']}/profile",
            json={"kind": "retail", "retailers": ["footlocker.co.il"]},
        ).json()
        assert again["retailers_added"] == []

        assert (
            c.put(
                f"/api/brands/{b['id']}/profile", json={"kind": "retail", "countries": ["Israel"]}
            ).status_code
            == 422
        )
        assert c.put(f"/api/brands/{b['id']}/profile", json={"kind": "shop"}).status_code == 422


def test_service_brand_suggestion_says_not_resold(engine, tmp_path):
    app = _app(engine, tmp_path)
    with TestClient(app):
        c = _api(app)
        b = _brand(c, kind="service", name=f"Quantix {uuid.uuid4().hex[:4]}")
        sug = c.post(f"/api/brands/{b['id']}/profile/suggest", json={}).json()
        assert sug["available"] and not sug["resold_by_retailers"] and sug["products"] == []


def test_ai_cleaners():
    assert ai.clean_country("uk") == "GB" and ai.clean_country("ISR") is None
    assert ai.clean_domain("https://www.Foot-Locker.co.il/store") == "foot-locker.co.il"
    assert ai.clean_domain("not a domain") is None
    assert ai.clean_term("  On   Cloud ") == "on cloud" and ai.clean_term("x") is None


def _retail_brand_scanned(app, c):
    from tests.test_demo_story import _ui  # noqa: F401  (same helpers module)

    b = _brand(c)
    c.put(f"/api/brands/{b['id']}/profile", json={
        "kind": "retail", "countries": ["IL", "US"], "ad_keywords": ["shopnova runner"],
        "products": [{"name": "ShopNova Runner", "price": 799, "currency": "ILS", "country": "IL"},
                     {"name": "ShopNova Runner", "price": 150, "currency": "USD", "country": "US"}],
    })  # fmt: skip
    job = c.post(f"/api/brands/{b['id']}/scan", json={"max_candidates": 40}).json()["job_id"]
    app.state.queue.wait(uuid.UUID(job), timeout=240)
    rows = {r["hostname"]: r for r in c.get("/api/findings", params={"brand_id": b["id"]}).json()}
    return b, rows


def test_shop_finding_page_report_to_meta_and_takedown(engine, tmp_path):
    from tests.test_demo_story import _ui

    from brandwatch.db.base import make_session_factory
    from brandwatch.db.models import AuditEvent, BrandDomain, Finding

    app = _app(engine, tmp_path)
    with TestClient(app):
        c = _api(app)
        b, rows = _retail_brand_scanned(app, c)
        shops = {h for h, r in rows.items() if r["kind"] == "shop"}
        assert {"onestyle-shopping.com", "footstyle-il.com"} <= shops
        only = c.get("/api/findings", params={"brand_id": b["id"], "kind": "shop"}).json()
        assert {r["hostname"] for r in only} == shops

        fid = rows["onestyle-shopping.com"]["id"]
        ui = _ui(app)
        page = ui.get(f"/ui/findings/{fid}").text
        for needle in ("likely counterfeit seller", 'data-tab="shop"', "Shop checks", "Company number not in the registry",
                       "Report to Meta", "Report this ad", "https://www.facebook.com/ads/library/?id=",
                       "Confirm at this conclusion", "BrandWatch’s reading", "Authorised retailer",
                       "help/contact/trademarkform"):  # fmt: skip
            assert needle in page, needle
        assert "does not exist in" in c.get(f"/api/findings/{fid}").json()["score"]["summary"]

        # takedown: the scam-shop letter and Report to Meta with tracking (own ads only)
        assert c.post(f"/api/findings/{fid}/confirm", json={"reason": "replica shop"}).status_code == 200
        assert "confirmed · likely fake" in ui.get(f"/ui/findings/{fid}").text  # BrandWatch's reading by default
        tid = c.post(f"/api/findings/{fid}/takedown").json()["id"]
        t = c.get(f"/api/takedowns/{tid}").json()
        assert (
            "Shop likely selling counterfeit" in t["body"]
            and "is likely selling counterfeit goods" in t["body"]
            and "facebook.com/ads/library" in t["body"]
        )
        tpage = ui.get(f"/ui/takedowns/{tid}").text
        assert "Report to Meta" in tpage and "Mark reported" in tpage
        detail = c.get(f"/api/findings/{fid}").json()
        ad_id = detail["score"]["shop"]["ads"][0]["ad_id"]
        r = ui.post(
            f"/ui/takedowns/{tid}/reported",
            data={"portal": f"meta_ad:{ad_id}", "next": "meta"},
            follow_redirects=False,
        )
        assert r.status_code == 303 and r.headers["location"].endswith("#meta")
        assert f"meta_ad:{ad_id}" in c.get(f"/api/takedowns/{tid}").json()["channels"]["reports"]
        bad = ui.post(
            f"/ui/takedowns/{tid}/reported", data={"portal": "meta_ad:999"}, follow_redirects=False
        )
        assert "error=" in bad.headers["location"]  # someone else's ad is not reportable from here

        # a genuine retailer: one click whitelists it as a reseller and closes the finding
        fid2 = rows["footstyle-il.com"]["id"]
        assert ui.post(f"/ui/findings/{fid2}/authorized", follow_redirects=False).status_code == 303
        with make_session_factory(engine)() as s:
            assert s.get(Finding, uuid.UUID(fid2)).state.value == "dismissed"
            assert (
                s.query(BrandDomain)
                .filter_by(brand_id=uuid.UUID(b["id"]), domain="footstyle-il.com", kind="reseller")
                .count()
                == 1
            )
            assert s.query(AuditEvent).filter_by(action="takedown.reported").count() >= 1
        assert "shop · likely fake" in ui.get("/ui/findings?kind=shop&state=").text


def test_brand_profile_form_saves(engine, tmp_path):
    from tests.test_demo_story import _ui

    app = _app(engine, tmp_path)
    with TestClient(app):
        c = _api(app)
        b = _brand(c, kind="service")
        ui = _ui(app)
        page = ui.get(f"/ui/brands/{b['id']}").text
        assert 'id="profile"' in page and "Suggest with AI" in page
        r = ui.post(f"/ui/brands/{b['id']}/profile", data={
            "kind": "retail", "countries": "IL, us", "ad_keywords": "shopnova runner\nshopnova sale",
            "product_name": ["ShopNova Runner", ""], "product_price": ["799", ""], "product_currency": ["ils", ""],
            "product_country": ["il", ""], "product_source": ["analyst", "analyst"], "retailers": "sportzone-il.co.il",
        }, follow_redirects=False)  # fmt: skip
        assert r.status_code == 303 and "profile=saved" in r.headers["location"]
        got = c.get(f"/api/brands/{b['id']}").json()
        assert got["kind"] == "retail" and got["profile"]["countries"] == ["IL", "US"]
        assert got["profile"]["products"] == [
            {
                "name": "ShopNova Runner",
                "price": 799.0,
                "currency": "ILS",
                "country": "IL",
                "source": "analyst",
            }
        ]
        assert any(
            w["domain"] == "sportzone-il.co.il" and w["kind"] == "reseller"
            for w in got["whitelist"]
        )
        bad = ui.post(f"/ui/brands/{b['id']}/profile", data={"kind": "retail", "product_name": ["X"], "product_price": ["abc"],
                                                               "product_currency": ["ILS"], "product_country": ["IL"]})  # fmt: skip
        assert bad.status_code == 200 and "check the price" in bad.text
