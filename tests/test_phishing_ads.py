"""Phishing ads for a brand nobody else sells (a bank, a payment app).

A retail brand's Facebook / Instagram ads were always searched, for scam shops. Any other brand could not tick the task at
all, yet impostors advertise banks and payment apps too ("your account is limited — verify now"), and the site behind such an
ad often has no brand name in its domain, so no look-alike stream finds it. With the brand's "phishing ads" switch (or the
task in an automatic scan, or "scan now, only ads") the ads that use the brand's name are read; a site they send people to that
is not the brand's gets the ordinary phishing checks, and the finding keeps its ads to report them to Meta.

Recorded world (demo/networks): VaultPay runs a genuine ad; two impostor ads send people to account-review-center.com.
"""

from __future__ import annotations

import re
import uuid
from types import SimpleNamespace

from fastapi.testclient import TestClient
from tests.test_demo_story import _api, _app, _ui

from brandwatch.detection import schedule as schedule_mod


def _vaultpay(c):
    b = c.post("/api/brands", json={"name": "VaultPay", "domains": ["vaultpay.com", "www.vaultpay.com"], "preset": "standard"}).json()
    c.patch(f"/api/brands/{b['id']}/config", json={"detection": {"auto_map_on_confirm": False, "auto_investigate_on_confirm": False}})
    return b


def test_scan_only_ads_finds_the_site_behind_a_phishing_ad_and_keeps_its_ads(engine, tmp_path):
    app = _app(engine, tmp_path)
    with TestClient(app):
        c, ui = _api(app), _ui(app)
        b = _vaultpay(c)
        assert b.get("kind", "service") != "retail"
        r = c.post(f"/api/brands/{b['id']}/scan", json={"only": "ads"})
        assert r.status_code < 300, r.text  # used to be 409: "ads are searched for a retail brand"
        app.state.queue.wait(uuid.UUID(r.json()["job_id"]), timeout=180)
        rows = c.get("/api/findings", params={"brand_id": b["id"], "limit": 50}).json()
        hosts = {f["hostname"]: f for f in rows}
        assert "account-review-center.com" in hosts, list(hosts)  # no brand name in the domain: only the ads lead here
        assert "vaultpay.com" not in hosts  # the brand's own ad is left alone
        f = hosts["account-review-center.com"]
        assert f["kind"] == "phishing" and f["severity"] in ("high", "critical")
        d = c.get(f"/api/findings/{f['id']}").json()
        ads = d["score"]["ads"]
        assert {a["page_name"] for a in ads} == {"VaultPay Account Services", "Vault Pay Help Desk"}
        assert all(a["library_url"].startswith("https://www.facebook.com/ads/library/") for a in ads)
        page = ui.get(f"/ui/findings/{f['id']}").text
        assert 'data-tab="ads"' in page and "Advertised on Facebook / Instagram" in page and "Report this ad" in page
        assert "It is advertised:" in page and "a phishing site that is not VaultPay" in page.replace("&#39;", "'")
        assert "Counterfeit report form" not in page  # an impostor ad is not about fake goods
        # the ads can be ticked as reported on the takedown record, like a shop's
        assert c.post(f"/api/findings/{f['id']}/confirm", json={"reason": "phishing ad"}).status_code < 300
        t = ui.post(f"/ui/findings/{f['id']}/takedown", follow_redirects=False)
        draft = t.headers["location"].rstrip("/").split("/")[-1].split("?")[0]
        ad_id = ads[0]["ad_id"]
        done = ui.post(f"/ui/takedowns/{draft}/reported", data={"portal": f"meta_ad:{ad_id}", "next": "meta"}, follow_redirects=False)
        assert done.status_code == 303 and "error" not in done.headers["location"]
        assert "Reported ✓" in ui.get(f"/ui/takedowns/{draft}").text


def test_the_switch_the_schedule_and_the_profile_are_open_to_a_brand_nobody_else_sells(engine, tmp_path):
    app = _app(engine, tmp_path)
    with TestClient(app):
        c, ui = _api(app), _ui(app)
        b = _vaultpay(c)
        page = ui.get(f"/ui/brands/{b['id']}").text
        assert "phishing ads off · turn on" in page and 'value="ads"' in page  # the switch and "scan only ads"
        sched = re.search(r'<input type="checkbox" name="tasks" value="meta_ads"[^>]*>', page).group(0)
        assert "disabled" not in sched  # it used to be greyed out for anything but a retail brand
        prof = page[page.index('id="pform"'):]
        assert prof.index('name="ad_keywords"') < prof.index('class="retail-only"')  # keywords and countries for every brand
        r = ui.post(f"/ui/brands/{b['id']}/ads", data={"on": "1"}, follow_redirects=False)
        assert r.status_code == 303 and "ads=on" in r.headers["location"]
        det = c.get(f"/api/brands/{b['id']}").json()["config"]["detection"]
        assert det["phishing_ads"] is True and c.get(f"/api/brands/{b['id']}").json()["config"]["preset"] == "standard"  # not "custom"
        assert "phishing ads on · turn off" in ui.get(f"/ui/brands/{b['id']}").text


def test_a_hebrew_ad_keyword_ties_a_hebrew_ad_to_the_brand():
    # "בנק הפועלים" has no Latin letters: it used to be dropped as too short, so a Hebrew-only impostor ad never counted
    from brandwatch.detection import relevance

    terms = relevance.brand_terms("Bank Hapoalim", "bankhapoalim", ad_keywords=["בנק הפועלים"], official_domains=["bankhapoalim.co.il"])
    assert "בנק הפועלים" in terms.phrases
    ad = {"text": "בנק הפועלים: החשבון שלך הוגבל. אמתו את הפרטים עוד היום", "page_name": "שירות לקוחות", "landing_url": "https://secure-verify-il.com/"}
    assert relevance.ad_relevance(ad, terms)[0] == "yes"
    other = {"text": "מבצע על נעלי ריצה לכל המשפחה", "page_name": "חנות", "landing_url": "https://shoes.example/"}
    assert relevance.ad_relevance(other, terms)[0] == "no"
    # a Latin phrase with a short word still needs the brand's context ("on cloud" may mean anything)
    assert relevance.standalone_phrase("on cloud") is False and relevance.standalone_phrase("north face") is True


def test_default_tasks_and_cost_follow_the_switch():
    off, on = SimpleNamespace(streams=["dnstwist"], social_accounts=False), SimpleNamespace(streams=["dnstwist"], social_accounts=False, phishing_ads=True)
    assert "meta_ads" not in schedule_mod.default_tasks(off, retail=False)
    assert "meta_ads" in schedule_mod.default_tasks(on, retail=False) and "meta_ads" in schedule_mod.default_tasks(off, retail=True)
    s = schedule_mod.Schedule(enabled=True, tasks=["meta_ads"])
    service = schedule_mod.cost_estimate(s, approved_queries=0, search_max=0, geos=1, retail=False, ad_queries=6)
    retail = schedule_mod.cost_estimate(s, approved_queries=0, search_max=0, geos=1, retail=True, ad_queries=6)
    assert service["lines"] == [{"task": "Facebook / Instagram ads", "usd": 0.024}]  # the ad pages only: no shop checks
    assert retail["per_run"] > service["per_run"]
