"""A confirmation does the rest: it investigates the site and its network (the quick lookup) and builds the evidence package, and the
VirusTotal quota is shared by every investigation that runs at once, so ten confirmations queue instead of each spending the minute.

Also: a page that looks at least 85% like the brand's site is Critical.
"""

from __future__ import annotations

import asyncio
import json
import time
import uuid

from fastapi.testclient import TestClient
from tests.test_demo_story import _api, _app, _ui

from brandwatch.detection import intel as intel_mod


def _scan_one(c, app, host, name):
    brand = c.post("/api/brands", json={"name": f"{name} {uuid.uuid4().hex[:4]}", "domains": ["shopnova.com"]}).json()
    job = c.post(f"/api/brands/{brand['id']}/scan-urls", json={"urls": [f"https://{host}/"]}).json()["job_id"]
    app.state.queue.wait(uuid.UUID(job), timeout=120)
    return brand, c.get("/api/findings", params={"brand_id": brand["id"]}).json()[0]


def test_confirming_investigates_the_site_and_builds_the_evidence_package(engine, tmp_path):
    app = _app(engine, tmp_path)
    with TestClient(app):
        c, ui = _api(app), _ui(app)
        _brand, f = _scan_one(c, app, "shopn0va.com", "Auto")
        r = c.post(f"/api/findings/{f['id']}/confirm", json={"reason": "cloned login"})
        assert r.status_code == 200
        out = r.json()
        assert out["intel_job_id"] and out["map_job_id"]  # both follow a confirmation, by default
        app.state.queue.wait(uuid.UUID(out["intel_job_id"]), timeout=180)
        job = c.get(f"/api/jobs/{out['intel_job_id']}").json()
        assert job["state"] == "done"
        said = [e["message"] for e in c.get(f"/api/jobs/{out['intel_job_id']}/events").json()["events"]]
        assert any(m.startswith("Evidence package ready for shopn0va.com") for m in said), said
        # the quick investigation: the relations that place the site in a network, not the files that talked to it
        assert any("VirusTotal resolutions for shopn0va.com" in m for m in said) and any("VirusTotal subdomains for shopn0va.com" in m for m in said)
        assert not any("VirusTotal communicating files for shopn0va.com" in m or "VirusTotal referrer files" in m for m in said)
        assert not any("historical ssl certificates for shopn0va.com" in m for m in said)
        reports = c.get(f"/api/findings/{f['id']}/reports").json()
        assert {x["format"] for x in reports} == {"html", "json"}
        doc = json.loads(c.get(next(x["url"] for x in reports if x["format"] == "json")).text)
        inv = doc["investigation"]
        assert inv["registrar"] and inv["servers"] and inv["servers"][0]["ip"] == "203.0.113.66" and inv["detections"]["total"]
        page = c.get(next(x["url"] for x in reports if x["format"] == "html")).text
        assert "Investigation: the site and its network" in page and "203.0.113.66" in page
        # the finding page says it was a quick one and leaves the full lookup to the analyst
        iv = c.get(f"/api/findings/{f['id']}/intel").json()
        assert iv["job"]["light"] is True and iv["job"]["package"] is True
        assert ui.get(f"/ui/findings/{f['id']}").status_code == 200


def test_the_analysts_own_investigate_is_the_full_one_and_makes_no_package(engine, tmp_path):
    app = _app(engine, tmp_path)
    with TestClient(app):
        c = _api(app)
        _brand, f = _scan_one(c, app, "shopn0va.com", "Manual")
        r = c.post(f"/api/findings/{f['id']}/intel")
        app.state.queue.wait(uuid.UUID(r.json()["job_id"]), timeout=180)
        said = [e["message"] for e in c.get(f"/api/jobs/{r.json()['job_id']}/events").json()["events"]]
        assert any("VirusTotal communicating files for shopn0va.com" in m for m in said)  # all the relations
        assert not any(m.startswith("Evidence package ready") for m in said)
        assert c.get(f"/api/findings/{f['id']}/reports").json() == []


def test_the_brand_can_switch_the_automatic_investigation_off(engine, tmp_path):
    app = _app(engine, tmp_path)
    with TestClient(app):
        c = _api(app)
        brand, f = _scan_one(c, app, "shopn0va.com", "Off")
        assert c.patch(f"/api/brands/{brand['id']}/config", json={"detection": {"auto_investigate_on_confirm": False}}).status_code == 200
        out = c.post(f"/api/findings/{f['id']}/confirm", json={"reason": "x"}).json()
        assert out["intel_job_id"] is None and out["map_job_id"]


def test_a_confirmation_joins_an_investigation_that_is_already_running(engine, tmp_path):
    from brandwatch.api.intel import start_intel_job  # noqa: F401 - the one way to start it

    app = _app(engine, tmp_path)
    with TestClient(app):
        c = _api(app)
        _brand, f = _scan_one(c, app, "shopn0va.com", "Join")
        first = c.post(f"/api/findings/{f['id']}/intel").json()
        out = c.post(f"/api/findings/{f['id']}/confirm", json={"reason": "x"}).json()
        app.state.queue.wait(uuid.UUID(first["job_id"]), timeout=180)
        if out["intel_job_id"] == first["job_id"]:  # it was still running: it gets the package step too
            assert any(x["format"] == "json" for x in c.get(f"/api/findings/{f['id']}/reports").json())
        else:  # it had already finished: the confirmation started its own
            app.state.queue.wait(uuid.UUID(out["intel_job_id"]), timeout=180)
            assert any(x["format"] == "json" for x in c.get(f"/api/findings/{f['id']}/reports").json())


# ------------------------------------------------------------------------------------------ the shared quota
def test_every_investigation_shares_one_virustotal_quota():
    assert intel_mod.shared_pacer(4) is intel_mod.shared_pacer(4) and intel_mod.shared_pacer(4) is not intel_mod.shared_pacer(500)

    slept: list[float] = []

    async def fake_sleep(d):
        slept.append(d)

    async def burst():
        p = intel_mod._Pacer(4, sleep=fake_sleep)
        # three investigations asking at once: 12 requests in the same instant. 4 go at once, 4 at +60 s, 4 at +120 s
        await asyncio.gather(*[p.wait() for _ in range(12)])
        return sorted(slept)

    got = asyncio.run(burst())
    assert len(got) == 8 and 59.5 < got[0] <= 60.5 and 119.5 < got[-1] <= 121  # none spends a minute's requests twice


def test_time_spent_waiting_for_the_shared_quota_is_not_the_jobs_own_time():
    # a job queued behind nine others must not run out of its 10 minutes before it has done anything
    class Fake(intel_mod.Collector):
        def __init__(self):
            self.t0 = time.monotonic()
            self.api_calls = 0

    c = Fake()
    c.t0 -= 590  # almost out of its own time
    assert c._budget_left()
    c.t0 -= 20
    assert not c._budget_left()


def test_everyone_confirmed_is_one_map_on_the_attack_infrastructure_page(engine, tmp_path):
    app = _app(engine, tmp_path)
    with TestClient(app):
        c, ui = _api(app), _ui(app)
        brand = c.post("/api/brands", json={"name": f"Glance {uuid.uuid4().hex[:4]}", "domains": ["shopnova.com"]}).json()
        job = c.post(f"/api/brands/{brand['id']}/scan-urls", json={"urls": ["https://shopn0va.com/", "https://shopnova-login.com/"]}).json()["job_id"]
        app.state.queue.wait(uuid.UUID(job), timeout=120)
        findings = c.get("/api/findings", params={"brand_id": brand["id"]}).json()
        assert len(findings) == 2
        jobs = [c.post(f"/api/findings/{f['id']}/confirm", json={"reason": "cloned"}).json() for f in findings]
        for j in jobs:  # nothing else to press: both investigations and both packages follow the confirmations
            app.state.queue.wait(uuid.UUID(j["intel_job_id"]), timeout=180)
            app.state.queue.wait(uuid.UUID(j["map_job_id"]), timeout=180)
        page = ui.get("/ui/campaigns", params={"brand_id": brand["id"]}).text
        assert 'id="glance"' in page and "2 of 2 confirmed sites investigated" in page
        assert "203.0.113.66" in page  # both sites sit on it
        assert page.count("quick → open") == 2 and page.count("open ↗") >= 2  # the investigation and the package of each
        g = __import__("brandwatch.api.ui_stats", fromlist=["x"])
        from brandwatch.db.base import make_session_factory
        from brandwatch.db.models import User

        with make_session_factory(engine)() as s:
            ws = s.query(User).filter(User.email == "admin@test.local").first().workspace_id
            confirmed = [{"id": f["id"], "hostname": h} for f, h in zip(findings, ("shopn0va.com", "shopnova-login.com"), strict=True)]
            got = g.confirmed_at_a_glance(s, ws, confirmed)
        top = got["servers"][0]
        assert top["ip"] == "203.0.113.66" and sorted(top["sites"]) == ["shopn0va.com", "shopnova-login.com"] and got["multi_site_servers"] >= 1
        assert got["pending"] == [] and got["registrars"]


# ------------------------------------------------------------------------------------------ "Looks like" 85% -> very high
def _look(sim_bits_changed: int, *, blank_ev=False, redirected_home=False):
    """Analysis of a page whose screenshot differs from the brand's by ``sim_bits_changed`` of 64 pHash/dHash bits."""
    from brandwatch.config.brand_config import BrandConfig
    from brandwatch.detection.analysis import analyze
    from brandwatch.detection.baseline import BrandBaseline
    from brandwatch.detection.enrichment import CollectedEvidence

    ref = "f0f0f0f0f0f0f0f0"
    flip = (1 << sim_bits_changed) - 1
    mine = f"{int(ref, 16) ^ flip:016x}"
    base = BrandBaseline(brand_id=uuid.uuid4(), brand_key="acme", version=1, official_domains=("acme.com",), favicon_mmh3=None, favicon_phash=None,
                         screenshot_phash=ref, screenshot_dhash=ref, palette=(), keywords=("acme",))  # fmt: skip
    ev = CollectedEvidence(candidate_id=uuid.uuid4(), url="https://plain-widgets.example/", host="plain-widgets.example", registrable="plain-widgets.example",
                           screenshot_phash=None if blank_ev else mine, screenshot_dhash=None if blank_ev else mine,
                           final_url="https://www.acme.com/" if redirected_home else None)  # fmt: skip
    return analyze(ev, base, BrandConfig.for_preset("standard").scoring)


def test_a_page_that_looks_at_least_85_percent_like_the_brand_is_critical():
    from brandwatch.config.brand_config import BrandConfig
    from brandwatch.db.enums import Severity
    from brandwatch.detection.scoring import score

    cfg = BrandConfig.for_preset("standard").scoring
    for bits in (0, 4, 9):  # 100%, 94%, 86% of the bits agree
        an = _look(bits)
        assert "looks_like_brand_ge_85" in an.signals, bits
        risk = score(an, cfg)
        assert risk.severity is Severity.CRITICAL and "looks_like_brand_verdict" in [r["rule"] for r in risk.breakdown["combination_rules_fired"]]
        assert "very high" in an.details["signals"]["looks_like_brand_ge_85"]
    for bits in (12, 20, 32):  # 81% and below: a resemblance, not a copy
        assert "looks_like_brand_ge_85" not in _look(bits).signals, bits
    assert "looks_like_brand_ge_85" not in _look(0, blank_ev=True).signals  # no picture (or a blank one, which is dropped) is no evidence
    assert "looks_like_brand_ge_85" not in _look(0, redirected_home=True).signals  # a visit that ends on the brand's own site is the brand's own registration


def test_the_finding_page_number_and_the_rule_agree(engine, tmp_path):
    app = _app(engine, tmp_path)
    with TestClient(app):
        c = _api(app)
        brand = c.post("/api/brands", json={"name": f"Look {uuid.uuid4().hex[:4]}", "domains": ["shopnova.com"]}).json()
        job = c.post(f"/api/brands/{brand['id']}/scan-urls", json={"urls": ["https://shopnova-support-center.com/", "https://shopnova-login.com/"]}).json()["job_id"]
        app.state.queue.wait(uuid.UUID(job), timeout=120)
        by = {(f.get("hostname") or f.get("host")): f for f in c.get("/api/findings", params={"brand_id": brand["id"]}).json()}
        clone = c.get(f"/api/findings/{by['shopnova-login.com']['id']}").json()
        other = c.get(f"/api/findings/{by['shopnova-support-center.com']['id']}").json()
        assert clone["screenshots"]["similarity_pct"] >= 85 and clone["finding"]["severity"] == "critical"
        assert other["screenshots"]["similarity_pct"] < 85 and other["finding"]["severity"] != "critical"
