"""The demo story "one attack group, two brands": CoinPilot's typo domains forward to the real site with one affiliate id through one redirect host,
VaultPay's phishing kits sit on one of the same servers with the same certificate and registrant. The map shows ONE operation with two brands.
"""

from __future__ import annotations

import uuid

from fastapi.testclient import TestClient
from tests.test_demo_story import _api, _app, _ui

from brandwatch.providers.mock.fixtures import default_store

COIN = [f"https://{h}/" for h in ("coinpilott.io", "coinpllot.io", "coinplot.io", "koinpilot.io", "cooinpilot.io", "coin-pilot.io", "coinpilot-bot.io")]
VAULT = [f"https://{h}/" for h in ("vaultpay-login.com", "vaultpay-secure.net", "vault-pay.co", "vaultpay-verify.com")]


def test_the_network_scenarios_answer_like_any_other_but_are_not_part_of_the_golden_dataset():
    store = default_store()
    assert store.get("coinpilott.io").infra["ip"] == "192.0.2.77" and store.get("vaultpay-login.com").infra["cert_fp"] == "0badc0de" * 8
    hosts = {s.host for s in store.all()}
    assert "coinpilott.io" not in hosts and "vaultpay.com" not in hosts  # not listed: the metrics, the classifier and the label counts do not move
    assert not any(s.brand in ("coinpilot", "vaultpay") for s in store.by_label("phishing"))
    assert {s.host for s in store.by_ip("192.0.2.77")} >= {"coinpilott.io", "vaultpay-login.com"}  # but they are found by server and certificate
    assert {s.host for s in store.by_cert("0badc0de" * 8)} >= {"coin-pilot.io", "vaultpay-secure.net"}
    assert store.get("go-linkz.click") is None


def test_two_brands_run_by_the_same_group_are_one_operation_on_the_map(engine, tmp_path):
    app = _app(engine, tmp_path)
    with TestClient(app):
        c, ui = _api(app), _ui(app)
        ids = {}
        for name, domains, urls in (("CoinPilot", ["coinpilot.io", "www.coinpilot.io"], COIN), ("VaultPay", ["vaultpay.com", "www.vaultpay.com"], VAULT)):
            b = c.post("/api/brands", json={"name": name, "domains": domains, "preset": "standard"}).json()
            ids[name] = b["id"]
            c.patch(f"/api/brands/{b['id']}/config", json={"detection": {"auto_map_on_confirm": False, "auto_investigate_on_confirm": False}})
            app.state.queue.wait(uuid.UUID(c.post(f"/api/brands/{b['id']}/scan-urls", json={"urls": urls}).json()["job_id"]), timeout=180)
            rows = c.get("/api/findings", params={"brand_id": b["id"], "state": "open", "limit": 200}).json()
            assert len(rows) == len(urls), [r["hostname"] for r in rows]
            for f in rows:
                assert c.post(f"/api/findings/{f['id']}/confirm", json={"reason": "demo story"}).status_code < 300
        for bid in ids.values():
            r = c.post("/api/campaigns/map-all", json={"brand_id": bid}).json()
            if r.get("job_id"):
                app.state.queue.wait(uuid.UUID(r["job_id"]), timeout=300)
            for jid in c.post("/api/campaigns/investigate-all", json={"brand_id": bid}).json().get("job_ids", []):
                app.state.queue.wait(uuid.UUID(jid), timeout=300)
        data = c.get("/api/campaigns/all-map").json()
        by_site = {}
        for g in data["operations"]:
            for h in g["sites"]:
                by_site[h] = g["index"]
        coin = {u.split("//")[1].rstrip("/") for u in COIN}
        vault = {u.split("//")[1].rstrip("/") for u in VAULT}
        one = {by_site.get(h) for h in coin | vault}
        assert len(one) == 1 and None not in one, by_site  # all eleven are in ONE group
        op = next(g for g in data["operations"] if g["index"] in one)
        extra_sites = set(op["sites"]) - coin - vault
        crossing = [(p["a"], p["b"], p["conf"], p["kinds"]) for p in data["views"]["pairs"] if (p["a"] in extra_sites) != (p["b"] in extra_sites) and {p["a"], p["b"]} & (coin | vault)]
        assert not extra_sites, crossing[:8]
        assert op["size"] == 11 and {b["name"]: b["count"] for b in op["brands"]} == {"CoinPilot": 7, "VaultPay": 4}
        assert op["story"].startswith("One group of attackers, 2 brands: CoinPilot ×7, VaultPay ×4. It does more than one thing: ")
        assert {x["key"]: x["count"] for x in op["mix"]} == {"affiliate_fraud": 7, "credential_phishing": 4}
        assert op["name"] == "Affiliate fraud + Phishing kit · 2 brands" and "Because" not in op["story"]
        kinds = {lk["kind"] for lk in op["links"] if lk["level"] == "solid"}
        assert {"registrant", "certificate"} <= kinds, kinds  # the ties that cross brands
        assert any(lk["kind"] == "affiliate_id" and lk["value"] == "atid=51803" and len(lk["sites"]) == 7 for lk in op["links"])
        assert any(lk["kind"] == "redirector" and lk["value"] == "go-linkz.click" for lk in op["links"])
        assert data["stats"]["brands"] >= 2 and data["stats"]["cross_brand_groups"] >= 1
        assert "spans 2 brands" in data["headline"] or "It spans 2 brands" in data["headline"] or "brands (" in data["headline"]
        # the typo domains end on the real site: not phishing pages, rated for the affiliate id and the redirect host
        sev = {s["host"]: s["severity"] for s in data["sites"]}
        assert all(sev[h] in ("medium", "high", "critical") for h in coin)
        sigs = {s["host"]: set(s["signals"]) for s in data["sites"]}
        assert all({"affiliate_redirect", "redirect_via_third_party"} <= sigs[h] for h in coin), {h: sigs[h] for h in coin}
        assert all("looks_like_brand_ge_85" not in sigs[h] for h in coin)
        page = ui.get("/ui/campaigns/all").text
        assert "2 brands" in page and "brand <b>CoinPilot</b>" in page.replace("&nbsp;", " ") or "CoinPilot" in page
        # the findings page: one click for a brand or for all of them, and every row says which brand it is about
        fp = ui.get("/ui/findings", params={"state": ""}).text
        assert "All brands" in fp and "CoinPilot" in fp and "VaultPay" in fp and 'id="filters"' in fp
        one_brand = ui.get("/ui/findings", params={"state": "", "brand_id": ids["VaultPay"]}).text
        assert "vaultpay-login.com" in one_brand and "coinpilott.io" not in one_brand
        # all brands: the list pages (50 a page) and the suite's database holds many findings, so search for each
        everyone = [ui.get("/ui/findings", params={"state": "", "brand_id": "", "q": q}).text for q in ("vaultpay-login", "coinpilott")]
        assert "vaultpay-login.com" in everyone[0] and "coinpilott.io" in everyone[1]
