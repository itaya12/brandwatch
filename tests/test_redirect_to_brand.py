"""A look-alike that ends on the brand's own site is not a phishing page, and is still not harmless.

A real-world case: 8 typo domains of a crypto-trading brand forward every visitor to the real site with the same affiliate id (``?atid=70321``) through a
short-link host. They were rated Critical because the page captured was the real site's own ("looks 100% like the brand"). They steal nothing from
the visitor; the abuse is the commission, and a redirect host that can send visitors anywhere tomorrow. Now: the signals that came from the page
being the real one are not counted, an affiliate id is Medium, a third-party redirect host is High, a plain redirect home stays "likely the
brand's own", and the findings that are already saved can be looked at again from the stored evidence (nothing is fetched).
"""

from __future__ import annotations

import uuid

from fastapi.testclient import TestClient
from tests.test_demo_story import _api, _app, _ui
from tests.test_redirect_and_challenge import _scan, _Scenarios

from brandwatch.detection import redirects
from brandwatch.providers.mock.fixtures import default_store

OWN = {"shopnova.com"}


def test_the_chain_of_a_visit_says_whether_it_ends_home_with_an_affiliate_id_or_through_another_host():
    f = redirects.facts("shopn0va.com", ["https://shopn0va.com/", "https://trackz.example/Sc9m2v", "https://www.shopnova.com/?atid=70321"], "https://www.shopnova.com/", OWN)
    assert f.ends_on_brand and f.affiliate == ["atid=70321"] and f.via == ["trackz.example"] and f.landing == "www.shopnova.com"
    plain = redirects.facts("shopn0va.com", ["https://shopn0va.com/"], "https://www.shopnova.com/", OWN)
    assert plain.ends_on_brand and plain.affiliate == [] and plain.via == []  # the brand's own defensive registration, as before
    assert not redirects.facts("shopn0va.com", ["https://shopn0va.com/"], "https://elsewhere.example/", OWN).ends_on_brand
    assert not redirects.facts("www.shopnova.com", [], "https://www.shopnova.com/", OWN).ends_on_brand  # the brand's own site is not a suspect
    only_utm = redirects.facts("shopn0va.com", [], "https://www.shopnova.com/?utm_source=x&lang=en", OWN)
    assert only_utm.ends_on_brand and only_utm.affiliate == []  # tracking noise is not an affiliate id
    # saved evidence: the fetcher used to name the first document as the end of the visit; the last address of the chain is where it really ended
    old = redirects.facts("shopn0va.com", ["https://shopn0va.com/", "https://www.shopnova.com/?atid=70321", "https://www.shopnova.com/"], "https://trackz.example/Sc9m2v", OWN, saved=True)
    assert old.ends_on_brand and old.affiliate == ["atid=70321"] and old.via == ["trackz.example"]
    assert not redirects.facts("shopn0va.com", ["https://shopn0va.com/", "https://www.shopnova.com/"], "https://trackz.example/Sc9m2v", OWN).ends_on_brand  # not said to be saved: believed


REAL_PAGE = "<html><head><title>ShopNova</title></head><body><h1>Welcome to ShopNova</h1><p>Shoes and more.</p></body></html>"  # what the visitor really sees: the brand's own page, no form


def _fresh(*hops):
    return {"hops": list(hops), "final_url": "https://www.shopnova.com/", "html": REAL_PAGE}, {}


def test_a_scan_rates_a_look_alike_that_ends_home_by_what_the_chain_shows(engine, tmp_path):
    ha, ea = _fresh("https://trackz.example/aB1", "https://www.shopnova.com/?atid=777")  # affiliate id, through a redirect host
    hb, eb = _fresh()  # straight home
    hc, ec = _fresh("https://short.example/x")  # through a redirect host, no affiliate id
    hd, ed = _fresh("https://www.shopnova.com/?atid=555")  # an affiliate id, no other host
    with _Scenarios(("shopnova-rdr-a.com", "shopn0va.com", ha, ea), ("shopnova-rdr-b.com", "shopn0va.com", hb, eb), ("shopnova-rdr-c.com", "shopn0va.com", hc, ec),
                    ("shopnova-rdr-d.com", "shopn0va.com", hd, ed)):  # fmt: skip
        _s, _e, out, _ids = _scan(engine, tmp_path, [f"https://shopnova-rdr-{x}.com/" for x in "abcd"])
    a, b, c, d = (out[f"shopnova-rdr-{x}.com"] for x in "abcd")
    assert {"affiliate_redirect", "redirect_via_third_party"} <= set(a["signals"]) and a["severity"] in ("high", "critical")
    assert "looks_like_brand_ge_85" not in a["signals"] and "brand_tld_swap" not in a["signals"]  # the page is the real site's, not a copy of it
    assert "redirects_to_official" in a["signals"]["_fp_flags"] and "ends on the brand's own site" in a["signals"]["_details"]["affiliate_redirect"]
    assert "still rated" in a["signals"]["_details"]["redirects_to_official"] and "likely the brand's own" in b["signals"]["_details"]["redirects_to_official"]
    assert "affiliate_redirect" not in b["signals"] and "redirect_via_third_party" not in b["signals"] and "redirects_to_official" in b["signals"]["_fp_flags"]
    assert "redirect_via_third_party" in c["signals"] and "affiliate_redirect" not in c["signals"] and c["severity"] in ("high", "critical")
    assert "affiliate_redirect" in d["signals"] and "redirect_via_third_party" not in d["signals"] and d["severity"] in ("medium", "high", "critical")


def test_saved_findings_are_looked_at_again_from_the_stored_evidence_without_fetching_anything(engine, tmp_path):
    # the evidence the fetcher used to store: the chain ends on the brand, but "final_url" names the redirect host
    http = {"hops": ["https://www.shopnova.com/?atid=424242", "https://www.shopnova.com/"], "final_url": "https://trackz.example/q1", "html": REAL_PAGE}
    with _Scenarios(("shopnova-old-a.com", "shopn0va.com", http, {}), ("shopnova-old-b.com", "shopn0va.com", http, {})), TestClient(_app(engine, tmp_path)) as client:
        app = client.app
        c, ui = _api(app), _ui(app)
        brand = c.post("/api/brands", json={"name": f"Old {uuid.uuid4().hex[:4]}", "domains": ["shopnova.com"]}).json()
        c.patch(f"/api/brands/{brand['id']}/config", json={"detection": {"auto_map_on_confirm": False, "auto_investigate_on_confirm": False}})
        job = c.post(f"/api/brands/{brand['id']}/scan-urls", json={"urls": ["https://shopnova-old-a.com/", "https://shopnova-old-b.com/"]}).json()["job_id"]
        app.state.queue.wait(uuid.UUID(job), timeout=120)
        findings = c.get("/api/findings", params={"brand_id": brand["id"]}).json()
        for f in findings:
            c.post(f"/api/findings/{f['id']}/confirm", json={"reason": "x"})
        before = {f["id"]: c.get(f"/api/findings/{f['id']}").json()["finding"]["severity"] for f in findings}
        page = ui.get("/ui/campaigns/all", params={"brand_id": brand["id"]}).text
        assert "end on the brand's own site" in page and "Re-assess them from the saved evidence" in page and "no scan, no provider call" in page
        r = c.post("/api/campaigns/reassess-redirects", json={"brand_id": brand["id"]})
        assert r.status_code == 200 and r.json()["count"] == len(findings) == 2
        row = r.json()["changed"][0]
        assert row["affiliate"] == "atid=424242" and row["via"] == "trackz.example" and row["after"] == "high" and row["before"] in ("critical", "high", "medium")
        for f in findings:
            d = c.get(f"/api/findings/{f['id']}").json()
            assert d["finding"]["severity"] == "high" and d["finding"]["state"] == "confirmed"  # still confirmed, rated for what it is
            names = {s["name"] for s in d["score"]["signals"]}
            assert {"affiliate_redirect", "redirect_via_third_party"} <= names and not names & set(redirects.COPIED_FROM_REAL_SITE)  # what the real page caused is not counted
            assert [h["severity"] for h in d["score_history"]][0] == before[f["id"]] or len(d["score_history"]) >= 2  # the old rating stays in the history
        assert c.post("/api/campaigns/reassess-redirects", json={"brand_id": brand["id"]}).json()["count"] == 0  # nothing left to change
        again = ui.post("/ui/campaigns/reassess-redirects", data={"brand_id": brand["id"]}, follow_redirects=False)
        assert again.status_code == 303 and "reassessed=0" in again.headers["location"]
        page = ui.get("/ui/campaigns/all", params={"brand_id": brand["id"], "reassessed": 2}).text
        assert "Re-assessed from the saved evidence." in page and "rated for that already" in page
        data = c.get("/api/campaigns/all-map", params={"brand_id": brand["id"]}).json()
        assert data["stats"]["ends_on_brand"] == 2 and data["stats"]["ends_on_brand_unrated"] == 0
        op = data["operations"][0] if data["operations"] else None
        assert op is None or op["behaviour"]["key"] in ("affiliate_fraud", "credential_phishing")
    assert default_store().get("shopnova-old-a.com") is None  # the scenarios are taken out again


def test_the_new_signals_and_rules_are_part_of_the_scoring_catalogue():
    from brandwatch.config.brand_config import SCORING_VERSION, ScoringConfig

    cfg = ScoringConfig()
    assert SCORING_VERSION == "v7" and cfg.weights["affiliate_redirect"] == 25 and cfg.weights["redirect_via_third_party"] == 20
    rules = {r.name: r.min_severity.value for r in cfg.combination_rules}
    assert rules["affiliate_redirect_verdict"] == "medium" and rules["redirect_service_verdict"] == "high"
    old = ScoringConfig.model_validate({"version": "v6", "weights": {"credential_form": 20}, "combination_rules": []})
    assert old.weights["affiliate_redirect"] == 25 and any(r.name == "redirect_service_verdict" for r in old.combination_rules) and old.version.endswith("+c7")  # a saved v6 brand gets them
