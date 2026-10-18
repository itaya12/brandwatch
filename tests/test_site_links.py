"""Links on the official homepage, the social-media switch of a brand, and "scan now, only one part"."""

from __future__ import annotations

import uuid

from fastapi.testclient import TestClient
from tests.test_demo_story import _api, _app, _ui

from brandwatch.detection.site_links import external_links

PAGE = """<link rel=alternate hreflang=he-il href="https://shopnova.co.il/">
<a href="https://www.facebook.com/shopnova">fb</a><a href="https://x.com/shopnova">X</a><a href="https://twitter.com/intent/tweet?u=1">share</a>
<a href="https://www.youtube.com/@ShopNova">yt</a><a href="https://www.linkedin.com/company/shopnova/">li</a><a href="https://wa.me/972501234567">wa</a>
<a href="https://shopnova.de/">DE</a><a href="https://shopnova-help.com/x">Help</a><a href="https://shopnova.zendesk.com/hc">Support</a>
<a href="https://apps.apple.com/app/shopnova/id123">iOS</a><a href="https://www.visa.com">Visa</a><a href="https://www.visa.com/x">Visa again</a>
<a href="/about">about</a><a href="https://www.shopnova.com/x">own</a>"""


def test_every_external_link_of_the_homepage_is_sorted_into_what_it_is():
    rows = {r["key"]: r for r in external_links(PAGE, "https://www.shopnova.com/", "shopnova", {"shopnova.com"})}
    kinds = {k: r["kind"] for k, r in rows.items()}
    assert kinds["site:shopnova.co.il"] == "country_site" and rows["site:shopnova.co.il"]["country"] == "IL"
    assert kinds["site:shopnova.de"] == "country_site" and rows["site:shopnova.de"]["region"] == "Germany"
    assert kinds["site:shopnova-help.com"] == "official_site"
    assert kinds["site:shopnova.zendesk.com"] == "official_site" and "zendesk.com" in rows["site:shopnova.zendesk.com"]["why"]
    assert {k for k, v in kinds.items() if v == "social"} == {
        "social:facebook:shopnova", "social:x:shopnova", "social:youtube:@shopnova", "social:linkedin:company/shopnova", "social:whatsapp:972501234567"}  # fmt: skip
    assert kinds["app:https://apps.apple.com/app/shopnova/id123"] == "app"
    assert kinds["site:visa.com"] == "other" and rows["site:visa.com"]["count"] == 2  # one row per domain, counted
    assert not any("shopnova.com" == r["domain"] for r in rows.values())  # never the brand's own site
    assert not any("intent" in r["url"] for r in rows.values())  # a share button is not an account
    order = [r["kind"] for r in rows.values()]
    assert order == sorted(order, key=["country_site", "official_site", "social", "app", "other"].index)


def _brand(c):
    b = c.post("/api/brands", json={"name": f"Links {uuid.uuid4().hex[:4]}", "domains": ["shopnova.com"]}).json()
    assert c.post(f"/api/brands/{b['id']}/baseline").status_code == 200
    return b


def test_the_brand_page_lists_the_links_and_the_analyst_decides_each(engine, tmp_path):
    app = _app(engine, tmp_path)
    with TestClient(app):
        c, ui = _api(app), _ui(app)
        b = _brand(c)
        links = {r["key"]: r for r in c.get(f"/api/brands/{b['id']}").json()["site_links"]["rows"]}
        assert links["social:facebook:shopnova"]["status"] == "ours"  # the homepage's own icons are learned as the brand's accounts
        assert links["social:x:shopnova"]["status"] == "new" and links["site:shopnova.zendesk.com"]["kind"] == "official_site"
        assert links["site:stripe.com"]["kind"] == "other"
        assert links["app:https://apps.apple.com/us/app/shopnova/id1600000001"]["status"] == "ours"  # an app it links to is its own
        page = ui.get(f"/ui/brands/{b['id']}").text
        assert 'id="sitelinks"' in page and "Links on the official site" in page and "This is our account" in page
        # X is ours; the business site is another official domain; Stripe is a partner; YouTube is ignored
        for key, action in (("social:x:shopnova", "ours"), ("site:shopnova-business.com", "official"), ("site:stripe.com", "partner"),
                            ("social:youtube:@shopnova", "ignore")):  # fmt: skip
            r = ui.post(f"/ui/brands/{b['id']}/site-links", data={"key": key, "action": action}, follow_redirects=False)
            assert r.status_code == 303 and r.headers["location"].endswith(f"?links={action}#sitelinks")
        after = c.get(f"/api/brands/{b['id']}").json()
        rows = {r["key"]: r for r in after["site_links"]["rows"]}
        assert rows["social:x:shopnova"]["status"] == "ours" and "x:shopnova" in after["profile"]["official_social"]
        assert rows["site:shopnova-business.com"]["status"] == "ours" and "shopnova-business.com" in after["domains"]
        assert rows["site:stripe.com"]["status"] == "ours" and {"domain": "stripe.com", "kind": "partner"} in after["whitelist"]
        assert "social:youtube:@shopnova" not in rows and after["site_links"]["ignored"] == 1
        assert c.post(f"/api/brands/{b['id']}/site-links", json={"key": "site:nowhere.example", "action": "official"}).status_code == 404
        assert c.post(f"/api/brands/{b['id']}/site-links", json={"key": "site:shopnova.zendesk.com", "action": "ours"}).status_code == 422


def test_social_media_is_a_switch_of_the_brand_not_of_its_track(engine, tmp_path):
    app = _app(engine, tmp_path)
    with TestClient(app):
        c, ui = _api(app), _ui(app)
        b = _brand(c)
        page = ui.get(f"/ui/brands/{b['id']}").text
        assert 'action="/ui/brands/' in page and "social media on · turn off" in page
        r = ui.post(f"/ui/brands/{b['id']}/social", data={"on": "0"}, follow_redirects=False)
        assert r.status_code == 303 and r.headers["location"].endswith("?social=off#scan")
        got = c.get(f"/api/brands/{b['id']}").json()
        assert got["config"]["detection"]["social_accounts"] is False and got["config_custom"] is False  # still the plain track
        c.patch(f"/api/brands/{b['id']}/config", json={"preset": "standard"})  # another track keeps the brand's choice
        assert c.get(f"/api/brands/{b['id']}").json()["config"]["detection"]["social_accounts"] is False
        assert "social media off · turn on" in ui.get(f"/ui/brands/{b['id']}?social=off").text
        ui.post(f"/ui/brands/{b['id']}/social", data={"on": "1"})
        assert c.get(f"/api/brands/{b['id']}").json()["config"]["detection"]["social_accounts"] is True


def _payload(engine, job_id):
    from brandwatch.db.base import make_session_factory
    from brandwatch.db.models import ScanJob

    with make_session_factory(engine)() as s:
        return dict(s.get(ScanJob, job_id).payload or {})


def test_scan_now_only_one_part(engine, tmp_path):
    app = _app(engine, tmp_path)
    with TestClient(app):
        c, ui = _api(app), _ui(app)
        b = _brand(c)
        page = ui.get(f"/ui/brands/{b['id']}").text
        assert "only one part" in page and 'value="lookalike"' in page and 'value="social"' in page
        assert "approve the queries first" in page  # Google only after its queries are approved
        r = c.post(f"/api/brands/{b['id']}/scan", json={"only": "social"})
        assert r.status_code == 202
        job = uuid.UUID(r.json()["job_id"])
        app.state.queue.wait(job, timeout=120)
        assert _payload(engine, job)["tasks"] == ["social"] and _payload(engine, job)["only"] == "social media"
        events = c.get(f"/api/jobs/{job}/events").json()["events"]
        done = next(e for e in events if e.get("stage") == "summary" and (e.get("data") or {}).get("steps") is not None)
        titles = [st["title"] for st in done["data"]["steps"]]
        assert "Scan of one part · social media" in titles, titles
        assert not any(t.startswith("Automatic scan") for t in titles)  # said as what it is: started by hand, one part
        assert c.post(f"/api/brands/{b['id']}/scan", json={"only": "search"}).status_code == 409
        assert c.post(f"/api/brands/{b['id']}/scan", json={"only": "ads"}).status_code == 409  # not a retail brand
        refused = ui.post(f"/ui/brands/{b['id']}/scan", data={"only": "search"})
        assert refused.status_code == 200 and "approved queries" in refused.text  # said on the brand page, not an error page
        r = ui.post(f"/ui/brands/{b['id']}/scan", data={"only": "lookalike"}, follow_redirects=False)
        assert r.status_code == 303 and r.headers["location"].startswith("/ui/jobs/")
        lk = uuid.UUID(r.headers["location"].rsplit("/", 1)[-1])
        app.state.queue.wait(lk, timeout=120)
        assert _payload(engine, lk)["tasks"] == ["dnstwist", "ct"]  # the brand's own domain streams, nothing else
