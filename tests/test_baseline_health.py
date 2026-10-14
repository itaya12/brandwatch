"""The official site does not answer 2xx (thenorthface.com: HTTP 403 "Access Denied").

BrandWatch compares every suspect with the brand's own site. When that site refuses the scanner, the page it
sent is a block page: it must not become the fingerprint (screenshot, colours, keywords "access" / "denied"),
the analyst must be told in the scan console / on the brand / before the first scan, and the legitimate fixes
(another IP, another official page) must work.
"""

from __future__ import annotations

import asyncio
import uuid

import pytest
import sqlalchemy as sa
from fastapi.testclient import TestClient
from tests.conftest import make_brand, make_workspace
from tests.test_demo_story import _api, _app

import brandwatch.db.models as m
from brandwatch.config.settings import Settings
from brandwatch.detection import baseline_health
from brandwatch.detection.discovery import manual_hits
from brandwatch.detection.runner import run_scan

AKAMAI = (
    "<HTML><HEAD><TITLE>Access Denied</TITLE></HEAD><BODY><H1>Access Denied</H1>You don't have permission to "
    "access this page.<P>Reference&#32;#18.4f2e1b8.1760000000.1a2b3c "
    "<P>https://errors.edgesuite.net/18.4f2e1b8.1760000000.1a2b3c</P></BODY></HTML>"
)


# ------------------------------------------------------------------------------------ the classifier
def test_a_403_access_denied_page_is_a_block_and_names_the_vendor():
    h = baseline_health.assess(status=403, title="Access Denied", html=AKAMAI)
    assert h["ok"] is False and h["kind"] == "blocked" and h["status"] == 403
    assert h["vendor"] == "Akamai" and "403" in h["reason"] and "Akamai" in h["reason"]


@pytest.mark.parametrize(
    "status,kind",
    [(401, "blocked"), (429, "blocked"), (451, "blocked"), (404, "not_found"), (410, "not_found"),
     (500, "server_error"), (503, "server_error"), (418, "blocked")],
)  # fmt: skip
def test_every_non_2xx_status_is_a_problem_with_its_own_kind(status, kind):
    h = baseline_health.assess(status=status, title="x", html="<html></html>")
    assert h["ok"] is False and h["kind"] == kind and str(status) in h["reason"]


def test_a_200_that_says_access_denied_is_a_soft_block():
    h = baseline_health.assess(status=200, title="Access Denied", html=AKAMAI)
    assert h["ok"] is False and h["kind"] == "blocked" and "200" in h["reason"]


def test_a_bot_check_page_is_a_challenge_even_with_a_200():
    h = baseline_health.assess(status=200, title="Just a moment...", html="<html>cdn-cgi/challenge</html>", bot_challenge=True)
    assert h["ok"] is False and h["kind"] == "challenge" and h["vendor"] == "Cloudflare"


def test_no_answer_at_all_is_unreachable():
    h = baseline_health.assess(status=None, error="connection failed: peakline.com unreachable")
    assert h["ok"] is False and h["kind"] == "unreachable" and "unreachable" in h["reason"]


def test_a_normal_page_is_fine():
    h = baseline_health.assess(status=200, title="Peakline — Gear", html="<html><body>hello</body></html>")
    assert h == {"status": 200, "vendor": None, "title": "Peakline — Gear", "ok": True, "kind": "ok", "reason": "HTTP 200"}


# ------------------------------------------------------------------------------------ the baseline
def _brand(c, name="Peakline", domain="peakline.com"):
    return c.post("/api/brands", json={"name": f"{name} {uuid.uuid4().hex[:4]}", "domains": [domain], "preset": "standard",
                                       "kind": "retail"}).json()  # fmt: skip


def test_a_block_page_is_not_learned_from(engine, tmp_path):
    """ironvale.com refuses data-centre AND residential IPs and urlscan.io never scanned it: nothing can be learned."""
    app = _app(engine, tmp_path)
    with TestClient(app):
        c = _api(app)
        b = _brand(c, "Ironvale", "ironvale.com")
        r = c.post(f"/api/brands/{b['id']}/baseline").json()
        assert r["fetch"]["ok"] is False and r["fetch"]["kind"] == "blocked" and r["fetch"]["status"] == 403
        assert r["fetch"]["vendor"] == "Akamai" and r["fetch"]["via"] == "datacenter"
        assert [a["via"] for a in r["fetch"]["attempts"]] == ["datacenter", "residential"]  # it tried the proxy too
        assert r["fetch"]["source"] == "none" and "homepage_blocked" in r["unavailable"]
        assert r["screenshot_phash"] is None  # no picture of "Access Denied"
        assert not {"access", "denied"} & set(r["keywords"]), r["keywords"]  # the words of the error page
        assert r["colors"] == [] if "colors" in r else True
        got = c.get(f"/api/brands/{b['id']}").json()
        assert got["baseline_blocked"] is True and got["baseline_fetch"]["reason"].startswith("HTTP 403")
        assert got["baseline"]["fetch"]["kind"] == "blocked" and got["baseline"]["screenshot_phash"] is None
        assert [f["id"] for f in got["baseline_fixes"]] == ["residential", "other_page", "snapshot", "retry"]
        listed = next(x for x in c.get("/api/brands").json() if x["id"] == b["id"])
        assert listed["baseline_blocked"] is True


def test_a_healthy_site_is_marked_ok(engine, tmp_path):
    app = _app(engine, tmp_path)
    with TestClient(app):
        c = _api(app)
        b = _brand(c, "ShopNova", "shopnova.com")
        r = c.post(f"/api/brands/{b['id']}/baseline").json()
        assert r["fetch"]["ok"] is True and r["fetch"]["status"] == 200 and "homepage_blocked" not in r["unavailable"]
        got = c.get(f"/api/brands/{b['id']}").json()
        assert got["baseline_blocked"] is False and got["baseline"]["screenshot_phash"]


def test_an_old_baseline_without_the_record_counts_as_fine(session):
    from brandwatch.detection.baseline import latest_fetch

    ws = make_workspace(session, f"old-{uuid.uuid4().hex[:6]}")
    brand = make_brand(session, ws, "Old")
    session.add(m.BrandFingerprint(brand_id=brand.id, version=1, features={"keywords": ["old"]}))
    session.flush()
    assert latest_fetch(session, brand.id) is None


# ------------------------------------------------------------------------------------ the fixes
def test_check_only_looks_and_saves_nothing(engine, tmp_path):
    app = _app(engine, tmp_path)
    with TestClient(app):
        c = _api(app)
        b = _brand(c)
        r = c.post(f"/api/brands/{b['id']}/baseline/check", json={}).json()
        assert r["ok"] is False and r["kind"] == "blocked" and r["via"] == "datacenter" and r["fixes"]
        assert c.get(f"/api/brands/{b['id']}").json()["baseline"] is None  # nothing was fingerprinted
        ok = c.post(f"/api/brands/{b['id']}/baseline/check", json={"via": "residential"}).json()
        assert ok["ok"] is True and ok["via"] == "residential" and ok["fixes"] == []


def test_a_plain_rebuild_escalates_to_the_residential_proxy_on_its_own(engine, tmp_path):
    """peakline.com refuses a data-centre IP but not a home one: the rebuild retries by itself, in the open."""
    app = _app(engine, tmp_path)
    with TestClient(app) as tc:
        c = _api(app)
        b = _brand(c)
        r = c.post(f"/api/brands/{b['id']}/baseline").json()  # no "via": the same thing a scan does
        f = r["fetch"]
        assert f["ok"] is True and f["via"] == "residential" and f["source"] == "site"
        assert [(a["via"], a["ok"], a["status"]) for a in f["attempts"]] == [("datacenter", False, 403), ("residential", True, 200)]
        assert r["screenshot_phash"] and "peakline" in r["keywords"] and "homepage_blocked" not in r["unavailable"]
        r = c.post(f"/api/brands/{b['id']}/baseline", json={"via": "residential"}).json()
        assert r["fetch"]["ok"] is True and r["fetch"]["via"] == "residential" and r["version"] == 2
        assert r["screenshot_phash"] and "peakline" in r["keywords"] and "homepage_blocked" not in r["unavailable"]
        with tc.app.state.session_factory() as s:  # the residential fetches were counted against the budget
            calls = s.scalar(sa.select(sa.func.sum(m.ApiUsage.calls)).where(m.ApiUsage.provider == "residential"))
            assert calls and calls >= 1


def test_fingerprint_from_another_official_page_and_remember_it(engine, tmp_path):
    app = _app(engine, tmp_path)
    with TestClient(app):
        c = _api(app)
        b = _brand(c, "Ironvale", "ironvale.com")  # blocks everything, and urlscan.io never saw it
        r = c.post(f"/api/brands/{b['id']}/baseline", json={"url": "https://peakline.co.il/"}).json()
        assert r["fetch"]["ok"] is True and r["fetch"]["url"] == "https://peakline.co.il/"
        got = c.get(f"/api/brands/{b['id']}").json()
        assert got["profile"]["baseline_url"] == "https://peakline.co.il/"
        assert "peakline.co.il" in got["domains"]  # naming it vouches for it: it is an official domain now
        assert got["baseline_blocked"] is False
        # the next rebuild (a scheduled scan too) keeps using that page
        again = c.post(f"/api/brands/{b['id']}/baseline").json()
        assert again["fetch"]["url"] == "https://peakline.co.il/"
        # an empty address goes back to the homepage
        back = c.post(f"/api/brands/{b['id']}/baseline", json={"url": ""}).json()
        assert back["fetch"]["url"] == "https://ironvale.com/" and back["fetch"]["ok"] is False
        assert c.get(f"/api/brands/{b['id']}").json()["profile"]["baseline_url"] is None


def test_a_page_that_is_not_a_web_address_is_refused(engine, tmp_path):
    app = _app(engine, tmp_path)
    with TestClient(app):
        c = _api(app)
        b = _brand(c)
        assert c.post(f"/api/brands/{b['id']}/baseline", json={"url": "javascript:alert(1)"}).status_code == 422
        assert c.post(f"/api/brands/{b['id']}/baseline", json={"url": "not a url"}).status_code == 422


def test_residential_needs_a_budget_and_a_proxy_in_live_mode(engine, tmp_path):
    """Nothing is fetched until both are set - BrandWatch never reaches for the paid proxy on its own."""
    live = Settings(_env_file=None, demo_mode=False, evidence_dir=str(tmp_path / "ev2"), bootstrap_admin_email="admin",
                    bootstrap_admin_password="admin", secret_key="unit-test-secret-0123456789abcdef")  # fmt: skip
    from brandwatch.api.main import create_app

    app = create_app(settings=live, engine=engine)
    with TestClient(app):
        c = _api(app)
        b = _brand(c)
        r = c.post(f"/api/brands/{b['id']}/baseline/check", json={"via": "residential"})
        assert r.status_code == 409 and "budget" in r.json()["detail"]  # the default budget is 0 GB
        assert c.post(f"/api/brands/{b['id']}/baseline", json={"via": "residential"}).status_code == 409
        c.patch("/api/admin/workspace", json={"economic_limits": {"max_residential_gb": 1}})
        r2 = c.post(f"/api/brands/{b['id']}/baseline/check", json={"via": "residential"})
        assert r2.status_code == 409 and "proxy" in r2.json()["detail"]
        assert c.get(f"/api/brands/{b['id']}").json()["baseline"] is None


# ------------------------------------------------------------------------------------ the scan
def test_a_scan_says_so_when_the_official_site_blocks(engine, tmp_path):
    from brandwatch.db.base import make_session_factory

    settings = Settings(_env_file=None, demo_mode=True, evidence_dir=str(tmp_path / "ev"))
    with make_session_factory(engine)() as s:
        ws = make_workspace(s, f"blk-{uuid.uuid4().hex[:6]}")
        brand = make_brand(s, ws, "Ironvale")
        s.add(m.BrandDomain(brand_id=brand.id, domain="ironvale.com", is_official=True, kind="official"))
        job = m.ScanJob(workspace_id=ws.id, brand_id=brand.id, kind="url_scan")
        s.add(job)
        s.flush()
        summary = asyncio.run(run_scan(s, job.id, settings=settings, hits=manual_hits(["https://ironvale-outlet.com/"])))
        s.commit()
        alerts = [e for e in s.scalars(sa.select(m.ScanEventRecord).where(m.ScanEventRecord.job_id == job.id)).all()
                  if (e.data or {}).get("alert", {}).get("kind") == "baseline"]  # fmt: skip
        assert len(alerts) == 1 and alerts[0].level == "warn"
        a = alerts[0].data["alert"]
        assert "HTTP 403" in a["title"] and "Akamai" in a["title"] and a["settings_url"] == f"/ui/brands/{brand.id}#baseline"
        assert "residential" in a["fix"] and "NOT used as the fingerprint" in a["fix"]
        assert any(st["title"] == "The official site blocked BrandWatch — visual comparison is off" for st in summary.steps)
        # a second scan reuses the baseline - and still says it, so the problem is not forgotten
        job2 = m.ScanJob(workspace_id=ws.id, brand_id=brand.id, kind="url_scan")
        s.add(job2)
        s.flush()
        summary2 = asyncio.run(run_scan(s, job2.id, settings=settings, hits=manual_hits(["https://ironvale-outlet.com/"])))
        s.commit()
        assert any(st["title"].startswith("The official site blocked BrandWatch") for st in summary2.steps)


def test_a_healthy_official_site_raises_no_alert(engine, tmp_path):
    from brandwatch.db.base import make_session_factory

    settings = Settings(_env_file=None, demo_mode=True, evidence_dir=str(tmp_path / "ev"))
    with make_session_factory(engine)() as s:
        ws = make_workspace(s, f"okk-{uuid.uuid4().hex[:6]}")
        brand = make_brand(s, ws, "ShopNova")
        s.add(m.BrandDomain(brand_id=brand.id, domain="shopnova.com", is_official=True, kind="official"))
        job = m.ScanJob(workspace_id=ws.id, brand_id=brand.id, kind="url_scan")
        s.add(job)
        s.flush()
        summary = asyncio.run(run_scan(s, job.id, settings=settings, hits=manual_hits(["https://shopnovaa.com/"])))
        s.commit()
        events = s.scalars(sa.select(m.ScanEventRecord).where(m.ScanEventRecord.job_id == job.id)).all()
        assert not [e for e in events if (e.data or {}).get("alert", {}).get("kind") == "baseline"]
        assert not any("blocked BrandWatch" in st["title"] for st in summary.steps)


# ------------------------------------------------------------------------------------ the pages
def test_the_pages_tell_the_analyst_and_offer_the_fixes(engine, tmp_path):
    from tests.test_demo_story import _ui

    app = _app(engine, tmp_path)
    with TestClient(app):
        c, ui = _api(app), _ui(app)
        b = _brand(c, "Ironvale", "ironvale.com")
        setup = ui.get(f"/ui/brands/{b['id']}/setup").text  # before the first scan: checked when the page opens
        assert 'id="siteacc"' in setup and 'data-auto="1"' in setup and "Check through residential" in setup
        c.post(f"/api/brands/{b['id']}/baseline")
        page = ui.get(f"/ui/brands/{b['id']}").text
        assert "did not let BrandWatch in" in page and "HTTP 403" in page and 'data-auto="0"' in page
        assert "Fingerprint another official page" in page and "residential proxy" in page
        assert "official site blocks BrandWatch" in ui.get("/ui/brands").text
        # a healthy brand shows none of it
        ok = _brand(c, "ShopNova", "shopnova.com")
        c.post(f"/api/brands/{ok['id']}/baseline")
        assert "did not let BrandWatch in" not in ui.get(f"/ui/brands/{ok['id']}").text.split('id="siteacc"')[0]


# ------------------------------------------------------------------------------------ the escalation, in the open
def _run_scan(engine, tmp_path, name, domain):
    from brandwatch.db.base import make_session_factory

    settings = Settings(_env_file=None, demo_mode=True, evidence_dir=str(tmp_path / f"ev-{domain}"))
    with make_session_factory(engine)() as s:
        ws = make_workspace(s, f"esc-{uuid.uuid4().hex[:6]}")
        brand = make_brand(s, ws, name)
        s.add(m.BrandDomain(brand_id=brand.id, domain=domain, is_official=True, kind="official"))
        job = m.ScanJob(workspace_id=ws.id, brand_id=brand.id, kind="url_scan")
        s.add(job)
        s.flush()
        summary = asyncio.run(run_scan(s, job.id, settings=settings, hits=manual_hits([f"https://{name.lower()}-outlet.com/"])))
        s.commit()
        events = s.scalars(sa.select(m.ScanEventRecord).where(m.ScanEventRecord.job_id == job.id).order_by(m.ScanEventRecord.seq)).all()
        usage = s.scalar(sa.select(sa.func.count()).select_from(m.ApiUsage).where(m.ApiUsage.workspace_id == ws.id, m.ApiUsage.provider == "residential"))
        return summary, events, usage


def test_a_scan_says_got_403_then_retries_through_the_proxy_and_gets_in(engine, tmp_path):
    summary, events, usage = _run_scan(engine, tmp_path, "Peakline", "peakline.com")
    said = [e.message for e in events if e.stage == "baseline"]
    assert any(x.startswith("Got HTTP 403 from peakline.com") and "Akamai" in x for x in said), said  # "I got a 403"
    assert any("Retrying through the residential proxy" in x for x in said)
    assert any(x.startswith("The residential proxy got in: HTTP 200") for x in said)
    assert not [e for e in events if (e.data or {}).get("alert", {}).get("kind") == "baseline"]  # solved: nothing to alert
    assert not any("blocked BrandWatch" in st["title"] for st in summary.steps)
    assert any(st["title"] == "The official site refused a data-centre IP — the residential proxy got in" for st in summary.steps)
    assert usage >= 1  # the proxy fetch is metered like the cloaking probe's


def test_when_every_ip_is_refused_the_fingerprint_comes_from_a_urlscan_snapshot(engine, tmp_path):
    summary, events, _usage = _run_scan(engine, tmp_path, "Trailmark", "trailmark.com")
    said = [e.message for e in events if e.stage == "baseline"]
    assert any(x.startswith("Got HTTP 403 from trailmark.com") for x in said)
    assert any("residential proxy was refused too" in x for x in said)
    assert any("Asking urlscan.io for a public snapshot" in x for x in said)
    assert any(x.startswith("Found a urlscan.io snapshot of https://trailmark.com/") for x in said)
    alert = next(e.data["alert"] for e in events if (e.data or {}).get("alert", {}).get("kind") == "baseline")
    assert "snapshot" in alert["title"] and "HTTP 403 (Akamai)" in alert["title"] and "((" not in alert["title"]
    assert "NOT used" not in alert["fix"] and "cannot be followed from a snapshot" in alert["fix"]
    assert "datacenter: HTTP 403 → residential: HTTP 403" in alert["fix"]
    step = next(st for st in summary.steps if st["title"].startswith("The official site blocked BrandWatch"))
    assert "urlscan.io snapshot" in step["title"]


def test_the_snapshot_gives_a_real_fingerprint_not_the_block_page(engine, tmp_path):
    app = _app(engine, tmp_path)
    with TestClient(app):
        c = _api(app)
        b = _brand(c, "Trailmark", "trailmark.com")
        r = c.post(f"/api/brands/{b['id']}/baseline").json()
        f = r["fetch"]
        assert f["ok"] is False and f["source"] == "urlscan" and f["snapshot"]["url"] == "https://trailmark.com/"
        assert f["snapshot"]["has_dom"] is True and f["snapshot"]["has_favicon"] is True
        assert {"homepage_blocked", "snapshot"} <= set(r["unavailable"])
        assert r["screenshot_phash"] and not {"access", "denied"} & set(r["keywords"]) and "trailmark" in r["keywords"]
        got = c.get(f"/api/brands/{b['id']}").json()
        assert got["baseline_blocked"] is True and got["baseline"]["screenshot_phash"] and got["baseline"]["favicon_mmh3"]
        assert got["baseline"]["auth_pages"] == []  # a snapshot cannot follow the login link


def test_the_analyst_can_choose_the_snapshot_and_keep_the_reason(engine, tmp_path):
    app = _app(engine, tmp_path)
    with TestClient(app):
        c = _api(app)
        b = _brand(c)  # peakline.com: the live site answers a residential IP, but the analyst asks for the snapshot
        r = c.post(f"/api/brands/{b['id']}/baseline", json={"via": "snapshot"}).json()
        assert r["fetch"]["source"] == "urlscan" and r["fetch"]["ok"] is False and r["screenshot_phash"]
        assert [a["via"] for a in r["fetch"]["attempts"]] == ["datacenter"]  # asked once; never the proxy
        assert c.post(f"/api/brands/{b['id']}/baseline/check", json={"via": "snapshot"}).status_code == 422
        nothing = _brand(c, "Ironvale", "ironvale.com")  # urlscan.io never saw it
        r2 = c.post(f"/api/brands/{nothing['id']}/baseline", json={"via": "snapshot"}).json()
        assert r2["fetch"]["source"] == "none" and r2["screenshot_phash"] is None


# ------------------------------------------------------------------------------------ the gate, with stub providers
class _Browser:
    def __init__(self, log):
        self.log = log

    async def fetch(self, url, profile="datacenter"):
        from brandwatch.providers.base import ProviderResult, ProviderStatus

        self.log.append(profile)
        return ProviderResult(provider="stub", status=ProviderStatus.POSITIVE, raw={}, cost_usd=0.0,
                              data={"status": 403, "title": "Access Denied", "html": AKAMAI, "screenshot_png": None, "favicon_png": None})  # fmt: skip


class _Urlscan:
    async def snapshot(self, domain, scan_id=None, peek=False):
        from brandwatch.providers.base import ProviderResult

        return ProviderResult.failure("stub", "urlscan: not reachable")


class _Providers:
    def __init__(self):
        self.log = []
        self.settings = Settings(_env_file=None, demo_mode=False)

    def browser(self):
        return _Browser(self.log)

    def urlscan(self):
        return _Urlscan()

    def llm(self):
        raise RuntimeError("no llm in this test")


def _stub_baseline(session, tmp_path, **kw):
    from brandwatch.detection.baseline import build_baseline
    from brandwatch.evidence.store import LocalEvidenceStore

    ws = make_workspace(session, f"stub-{uuid.uuid4().hex[:6]}")
    brand = make_brand(session, ws, "Stubbed")
    session.add(m.BrandDomain(brand_id=brand.id, domain="stubbed.com", is_official=True, kind="official"))
    session.flush()
    said, providers = [], _Providers()
    report = asyncio.run(build_baseline(session, brand, providers, LocalEvidenceStore(str(tmp_path / "ev")),
                                        narrate=lambda t, d, i, img: said.append((t, d)), **kw))  # fmt: skip
    return report, providers.log, said


def test_without_a_budget_or_proxy_the_paid_proxy_is_never_touched_and_the_analyst_is_told_why(session, tmp_path):
    report, fetched, said = _stub_baseline(session, tmp_path, escalate=False, residential_off="the residential budget is 0 GB")
    assert fetched == ["datacenter"]  # one fetch, no residential
    assert any(t == "The residential proxy was not tried" and "0 GB" in d for t, d in said), said
    assert any(t.startswith("Got HTTP 403 from stubbed.com") for t, _d in said)
    assert any(t == "urlscan.io has no usable snapshot of this site" for t, _d in said)  # the snapshot step ran and said so
    assert report.fetch["source"] == "none" and report.screenshot_phash is None


def test_with_a_budget_and_proxy_it_retries_once_then_falls_back(session, tmp_path):
    report, fetched, said = _stub_baseline(session, tmp_path, escalate=True)
    assert fetched == ["datacenter", "residential"]
    assert any(t.startswith("The residential proxy was refused too") for t, _d in said)
    assert [a["via"] for a in report.fetch["attempts"]] == ["datacenter", "residential"]


def test_the_snapshot_step_can_be_switched_off(session, tmp_path):
    _report, _fetched, said = _stub_baseline(session, tmp_path, escalate=False, snapshot=False)
    assert not any("urlscan" in t for t, _d in said)


def test_the_residential_gate_checks_the_budget_before_the_proxy(session):
    from brandwatch.detection import cloaking

    ws = make_workspace(session, f"gate-{uuid.uuid4().hex[:6]}")
    live = Settings(_env_file=None, demo_mode=False)
    demo = Settings(_env_file=None, demo_mode=True)
    assert cloaking.residential_gate(session, ws.id, demo, 0, False) is None  # demo: a recorded view
    assert "0 GB" in cloaking.residential_gate(session, ws.id, live, 0, True)
    assert "proxy" in cloaking.residential_gate(session, ws.id, live, 1, False)
    assert cloaking.residential_gate(session, ws.id, live, 1, True) is None
    session.add(m.ApiUsage(workspace_id=ws.id, provider="residential", calls=500, cost_usd=0))
    session.flush()
    assert "used up" in cloaking.residential_gate(session, ws.id, live, 1, True)


# ------------------------------------------------------------------------------------ urlscan.io, over a fake network
def _item(uuid_, domain, url, when, status="200", visibility="public", mime="text/html"):
    return {"task": {"uuid": uuid_, "domain": domain, "url": url, "time": when, "visibility": visibility},
            "page": {"status": status, "mimeType": mime, "title": f"Title of {uuid_}", "domain": domain, "url": url}}  # fmt: skip


def test_pick_snapshot_wants_the_newest_public_homepage_that_answered_200():
    from brandwatch.providers.impl.clients import pick_snapshot

    items = [
        _item("deep", "www.nf.com", "https://www.nf.com/jackets/x", "2026-10-12T09:00:00Z"),  # not the homepage
        _item("old", "www.nf.com", "https://www.nf.com/", "2026-09-01T09:00:00Z"),
        _item("new", "nf.com", "https://nf.com/", "2026-10-10T09:00:00Z"),
        _item("private", "www.nf.com", "https://www.nf.com/", "2026-10-11T09:00:00Z", visibility="private"),
        _item("blocked", "www.nf.com", "https://www.nf.com/", "2026-10-11T10:00:00Z", status="403"),
        _item("json", "www.nf.com", "https://www.nf.com/", "2026-10-11T11:00:00Z", mime="application/json"),
        _item("other", "click.nf.com", "https://click.nf.com/", "2026-10-12T10:00:00Z"),  # a mail-tracking subdomain
    ]
    assert pick_snapshot(items, "nf.com")["task"]["uuid"] == "new"
    assert pick_snapshot(items, "www.nf.com")["task"]["uuid"] == "new"  # www. or not, the same site
    assert pick_snapshot(items[:1] + items[3:], "nf.com") is None


def test_favicon_hash_is_taken_from_the_response_the_page_declares():
    from brandwatch.providers.impl.clients import favicon_response_hash

    result = {"data": {"requests": [
        {"response": {"hash": "aaa", "response": {"url": "https://nf.com/app.js", "mimeType": "application/javascript"}}},
        {"response": {"hash": "bbb", "response": {"url": "https://nf.com/other.ico", "mimeType": "image/x-icon"}}},
        {"response": {"hash": "ccc", "response": {"url": "https://nf.com/favicon-32.png", "mimeType": "image/png"}}},
    ]}}  # fmt: skip
    html = '<html><head><link rel="icon" href="/favicon-32.png"></head></html>'
    assert favicon_response_hash(result, html) == "ccc"
    assert favicon_response_hash(result, None) == "bbb"  # the first icon-looking response
    assert favicon_response_hash({}, html) is None


def _urlscan_client(key, calls):
    import httpx

    from brandwatch.providers.impl.clients import UrlscanClient

    def handler(req: httpx.Request) -> httpx.Response:
        calls.append(str(req.url))
        u = req.url.path
        if u == "/api/v1/search/":
            return httpx.Response(200, json={"results": [_item("snap-1", "www.nf.com", "https://www.nf.com/", "2026-10-12T07:00:00Z")]})
        if u == "/screenshots/snap-1.png":
            return httpx.Response(200, content=b"\x89PNG-fake", headers={"content-type": "image/png"})
        if not req.headers.get("API-Key"):  # urlscan serves the DOM and results to logged-in callers only
            return httpx.Response(403, json={"warning": "You're not logged in!"})
        if u == "/dom/snap-1/":
            return httpx.Response(200, text='<html><head><title>NF</title><link rel="icon" href="/f.ico"></head></html>')
        if u == "/api/v1/result/snap-1/":
            return httpx.Response(200, json={"data": {"requests": [{"response": {"hash": "h1", "response": {"url": "https://www.nf.com/f.ico", "mimeType": "image/x-icon"}}}]}})
        if u == "/responses/h1/":
            return httpx.Response(200, content=b"ICON-BYTES")
        return httpx.Response(404)

    return UrlscanClient(api_key=key, client=httpx.AsyncClient(transport=httpx.MockTransport(handler)))


def test_urlscan_snapshot_without_a_key_gives_the_picture_and_the_title():
    calls: list[str] = []
    res = asyncio.run(_urlscan_client(None, calls).snapshot("nf.com"))
    assert res.ok and res.data["scan_id"] == "snap-1" and res.data["screenshot_png"] == b"\x89PNG-fake"
    assert res.data["title"] == "Title of snap-1" and res.data["html"] is None and res.data["favicon_png"] is None
    assert not any("/dom/" in c or "/result/" in c for c in calls)  # not even asked: they need a key


def test_urlscan_snapshot_with_a_key_adds_the_dom_and_the_favicon():
    res = asyncio.run(_urlscan_client("k", []).snapshot("www.nf.com"))
    assert res.ok and "<title>NF</title>" in res.data["html"] and res.data["favicon_png"] == b"ICON-BYTES"


def test_urlscan_snapshot_with_nothing_to_show_is_not_an_error():
    import httpx

    from brandwatch.providers.impl.clients import UrlscanClient

    empty = UrlscanClient(client=httpx.AsyncClient(transport=httpx.MockTransport(lambda r: httpx.Response(200, json={"results": []}))))
    res = asyncio.run(empty.snapshot("never-scanned.com"))
    assert not res.data.get("screenshot_png") and res.data["note"].startswith("no public scan")


# ------------------------------------------------------------------------------------ "check" shows what happens next
def test_a_check_lays_out_the_ladder_and_shows_the_snapshot_that_exists(engine, tmp_path):
    app = _app(engine, tmp_path)
    with TestClient(app):
        c = _api(app)
        b = _brand(c, "Trailmark", "trailmark.com")
        r = c.post(f"/api/brands/{b['id']}/baseline/check", json={}).json()
        assert r["ok"] is False and [x["step"] for x in r["ladder"]] == ["the live site from a data-centre IP", "residential proxy", "urlscan.io snapshot"]
        assert r["ladder"][0]["ok"] is False and "HTTP 403" in r["ladder"][0]["text"]
        assert r["ladder"][1]["ok"] is None and "available" in r["ladder"][1]["text"]  # demo: the proxy is a recorded view
        snap = r["ladder"][2]
        assert snap["ok"] is True and "a public scan of https://trailmark.com/" in snap["text"]
        assert r["snapshot"]["screenshot_url"] and r["snapshot"]["scan_id"] == "mock-snap-trailmark.com"
        # nothing was downloaded or saved by looking
        assert c.get(f"/api/brands/{b['id']}").json()["baseline"] is None


def test_a_check_says_why_urlscan_has_nothing(engine, tmp_path):
    app = _app(engine, tmp_path)
    with TestClient(app):
        c = _api(app)
        b = _brand(c, "Ironvale", "ironvale.com")
        r = c.post(f"/api/brands/{b['id']}/baseline/check", json={}).json()
        step = r["ladder"][2]
        assert step["ok"] is False and step["text"].startswith("none found: no public scan") and r["snapshot"] is None
        # through the residential proxy the ladder has no residential rung (it is the thing just tried)
        r2 = c.post(f"/api/brands/{b['id']}/baseline/check", json={"via": "residential"}).json()
        assert [x["step"] for x in r2["ladder"]] == ["the live site through the residential proxy", "urlscan.io snapshot"]
        ok = c.post(f"/api/brands/{_brand(c)['id']}/baseline/check", json={}).json()  # peakline answers a data-centre IP? no, it blocks it
        assert ok["ok"] is False


def test_choosing_the_snapshot_still_asks_the_site_once_for_its_real_status(engine, tmp_path):
    app = _app(engine, tmp_path)
    with TestClient(app):
        c = _api(app)
        b = _brand(c)  # peakline.com refuses a data-centre IP
        f = c.post(f"/api/brands/{b['id']}/baseline", json={"via": "snapshot"}).json()["fetch"]
        assert f["source"] == "urlscan" and f["ok"] is False and f["status"] == 403 and f["vendor"] == "Akamai"
        assert [a["via"] for a in f["attempts"]] == ["datacenter"]  # one look, no proxy: the analyst chose the snapshot
        got = c.get(f"/api/brands/{b['id']}").json()
        assert got["baseline_blocked"] is True and got["baseline_snapshot"] is True
        # when the live site answers, the analyst's choice is still honoured - and nothing is called a block
        ok = _brand(c, "ShopNova", "shopnova.com")
        f2 = c.post(f"/api/brands/{ok['id']}/baseline", json={"via": "snapshot"}).json()["fetch"]
        assert f2["source"] == "urlscan" and f2["ok"] is True and f2["status"] == 200
        got2 = c.get(f"/api/brands/{ok['id']}").json()
        assert got2["baseline_blocked"] is False and got2["baseline_snapshot"] is True


def test_a_scan_on_a_snapshot_that_was_chosen_while_the_site_answers_has_no_alert(engine, tmp_path):
    from brandwatch.db.base import make_session_factory

    settings = Settings(_env_file=None, demo_mode=True, evidence_dir=str(tmp_path / "ev-snap"))
    app = _app(engine, tmp_path)
    with TestClient(app):
        c = _api(app)
        b = _brand(c, "ShopNova", "shopnova.com")
        c.post(f"/api/brands/{b['id']}/baseline", json={"via": "snapshot"})
        with make_session_factory(engine)() as s:
            job = m.ScanJob(workspace_id=s.get(m.Brand, uuid.UUID(b["id"])).workspace_id, brand_id=uuid.UUID(b["id"]), kind="url_scan")
            s.add(job)
            s.flush()
            summary = asyncio.run(run_scan(s, job.id, settings=settings, hits=manual_hits(["https://shopnova-outlet.com/"])))
            s.commit()
            events = s.scalars(sa.select(m.ScanEventRecord).where(m.ScanEventRecord.job_id == job.id)).all()
            assert not [e for e in events if (e.data or {}).get("alert", {}).get("kind") == "baseline"]
            assert any(st["title"].startswith("Fingerprint taken from a urlscan.io snapshot (chosen by the analyst)") for st in summary.steps)


def test_the_analyst_can_paste_the_link_of_the_urlscan_scan(engine, tmp_path):
    app = _app(engine, tmp_path)
    with TestClient(app):
        c = _api(app)
        b = _brand(c, "Trailmark", "trailmark.com")
        link = "https://urlscan.io/result/mock-snap-trailmark.com/"
        r = c.post(f"/api/brands/{b['id']}/baseline", json={"via": "snapshot", "urlscan": link}).json()
        assert r["fetch"]["source"] == "urlscan" and r["fetch"]["snapshot"]["scan_id"] == "mock-snap-trailmark.com" and r["screenshot_phash"]
        # a scan urlscan.io does not list is said so, and nothing wrong is learned
        gone = c.post(f"/api/brands/{b['id']}/baseline", json={"via": "snapshot", "urlscan": "https://urlscan.io/result/mock-snap-nowhere.example/"}).json()
        assert gone["fetch"]["source"] == "none" and gone["screenshot_phash"] is None
        for bad in ("hello", "https://example.com/result/mock-snap-trailmark.com/", "01a12ef3-ac95-73af-9298-9e8979761c7e-x@evil"):
            r2 = c.post(f"/api/brands/{b['id']}/baseline", json={"via": "snapshot", "urlscan": bad})
            assert r2.status_code == 422, bad
        real = "01a12ef3-ac95-73af-9298-9e8979761c7e"
        assert c.post(f"/api/brands/{b['id']}/baseline", json={"via": "snapshot", "urlscan": real}).status_code == 200  # a bare id is fine


def test_a_snapshot_that_fails_says_why_instead_of_being_silent(session, tmp_path):
    class Boom(_Urlscan):
        async def snapshot(self, domain, scan_id=None, peek=False):
            raise RuntimeError("HTTP 429 rate limited")

    from brandwatch.detection.baseline import _urlscan_snapshot

    class P:
        def urlscan(self):
            return Boom()

    snap, why = asyncio.run(_urlscan_snapshot(P(), ["www.nf.com", "nf.com"]))
    assert snap is None and "RuntimeError" in why and "429" in why
    snap2, why2 = asyncio.run(_urlscan_snapshot(_Providers(), ["nf.com"]))  # the stub answers "not reachable"
    assert snap2 is None and "not reachable" in why2


def test_the_stub_report_names_the_reason_in_the_console(session, tmp_path):
    _report, _fetched, said = _stub_baseline(session, tmp_path, escalate=False)
    t, detail = next((t, d) for t, d in said if t == "urlscan.io has no usable snapshot of this site")
    assert "not reachable" in detail and "paste the link of a urlscan.io scan" in detail


# ------------------------------------------------------------------------------------ the client: scan id, peek, private scans
def test_urlscan_snapshot_peek_downloads_nothing_and_a_pasted_scan_is_looked_up_by_id():
    import httpx

    from brandwatch.providers.impl.clients import UrlscanClient

    seen: list[str] = []

    def handler(req: httpx.Request) -> httpx.Response:
        seen.append(req.url.path + "?" + str(req.url.params.get("q") or ""))
        if req.url.path == "/api/v1/search/":
            q = req.url.params.get("q") or ""
            if q.startswith("task.uuid:"):
                return httpx.Response(200, json={"results": [_item("pasted-1", "other.nf.com", "https://other.nf.com/help", "2026-10-01T00:00:00Z", status="404")]})
            return httpx.Response(200, json={"results": [_item("snap-1", "www.nf.com", "https://www.nf.com/", "2026-10-12T07:00:00Z")]})
        return httpx.Response(200, content=b"PNG")

    client = UrlscanClient(client=httpx.AsyncClient(transport=httpx.MockTransport(handler)))
    peek = asyncio.run(client.snapshot("nf.com", peek=True))
    assert peek.data["scan_id"] == "snap-1" and peek.data["screenshot_url"].endswith("/screenshots/snap-1.png") and "screenshot_png" not in peek.data
    assert not any("screenshots" in x for x in seen)  # looking is free: no 600 KB picture
    pasted = asyncio.run(client.snapshot("nf.com", scan_id="pasted-1"))
    assert pasted.data["scan_id"] == "pasted-1" and pasted.data["screenshot_png"] == b"PNG"  # the analyst's choice: any page, any status
    assert any(x.startswith("/api/v1/search/?task.uuid:pasted-1") for x in seen)


def test_a_private_scan_is_read_with_the_owners_key():
    import httpx

    from brandwatch.providers.impl.clients import UrlscanClient

    def handler(req: httpx.Request) -> httpx.Response:
        if req.url.path == "/api/v1/search/":
            return httpx.Response(200, json={"results": []})  # private: not in the public search
        if req.url.path == "/api/v1/result/priv-1/":
            return httpx.Response(200, json={"task": {"uuid": "priv-1", "url": "https://www.nf.com/", "time": "2026-10-12T00:00:00Z"}, "page": {"title": "NF", "domain": "www.nf.com"}, "data": {"requests": []}})
        if req.url.path == "/dom/priv-1/":
            return httpx.Response(200, text="<html><head><title>NF</title></head></html>")
        return httpx.Response(200, content=b"PNG")

    mk = lambda key: UrlscanClient(api_key=key, client=httpx.AsyncClient(transport=httpx.MockTransport(handler)))  # noqa: E731
    got = asyncio.run(mk("k").snapshot("nf.com", scan_id="priv-1"))
    assert got.data["scan_id"] == "priv-1" and got.data["title"] == "NF" and got.data["html"].startswith("<html>")
    nope = asyncio.run(mk(None).snapshot("nf.com", scan_id="priv-1"))
    assert "does not list that scan" in nope.data["note"] and not nope.data.get("screenshot_png")


# ------------------------------------------------------------------------------------ SVG favicons
SVG = b'<?xml version="1.0"?><svg xmlns="http://www.w3.org/2000/svg" width="32" height="32"><rect width="32" height="32" fill="#c00"/><circle cx="16" cy="16" r="9" fill="#fff"/></svg>'


def test_svg_is_recognised_and_drawn_to_a_png():
    from brandwatch.detection import images

    assert images.is_svg(SVG) and images.is_svg(b"  <svg viewBox='0 0 1 1'></svg>") and not images.is_svg(b"\x89PNG\r\n") and not images.is_svg(None)
    png = asyncio.run(images.rasterize_svg(SVG))
    if png is None:
        pytest.skip("no sandboxed Chromium in this environment")
    assert png.startswith(b"\x89PNG") and images.image_size(png) == (64, 64)
    assert images.phash_hex(png)


def test_a_snapshot_whose_favicon_is_an_svg_still_gives_a_favicon_fingerprint(session, tmp_path):
    from brandwatch.detection import images

    if asyncio.run(images.rasterize_svg(SVG)) is None:
        pytest.skip("no sandboxed Chromium in this environment")

    class Svg(_Urlscan):
        async def snapshot(self, domain, scan_id=None, peek=False):
            from brandwatch.providers.base import ProviderResult, ProviderStatus

            shot = images_png()
            return ProviderResult(provider="stub", status=ProviderStatus.POSITIVE, raw={}, cost_usd=0.0, data={
                "scan_id": "s1", "url": "https://stubbed.com/", "time": "2026-10-12T00:00:00Z", "title": "Stubbed",
                "screenshot_png": shot, "html": None, "favicon_png": SVG})  # fmt: skip

    def images_png():
        import io

        from PIL import Image

        buf = io.BytesIO()
        Image.new("RGB", (64, 64), (200, 30, 30)).save(buf, "PNG")
        return buf.getvalue()

    class P(_Providers):
        def urlscan(self):
            return Svg()

    from brandwatch.detection.baseline import build_baseline
    from brandwatch.evidence.store import LocalEvidenceStore

    ws = make_workspace(session, f"svg-{uuid.uuid4().hex[:6]}")
    brand = make_brand(session, ws, "Stubbed")
    session.add(m.BrandDomain(brand_id=brand.id, domain="stubbed.com", is_official=True, kind="official"))
    session.flush()
    report = asyncio.run(build_baseline(session, brand, P(), LocalEvidenceStore(str(tmp_path / "ev")), escalate=False))
    fp = session.scalars(sa.select(m.BrandFingerprint).where(m.BrandFingerprint.brand_id == brand.id)).first()
    assert report.fetch["source"] == "urlscan" and "favicon" not in (fp.features or {}).get("unavailable", [])
    assert fp.favicon_mmh3 == images.favicon_mmh3(SVG) and fp.favicon_phash and fp.logo_path  # the file's hash, and a picture to compare


# ------------------------------------------------------------------------------------ the favicon the blocked page still gives
class _BlockedWithIcon(_Browser):
    """thenorthface.com: the page is a 403 "Access Denied", but the icon file is served."""

    async def fetch(self, url, profile="datacenter"):
        from brandwatch.providers.base import ProviderResult, ProviderStatus

        self.log.append(profile)
        return ProviderResult(provider="stub", status=ProviderStatus.POSITIVE, raw={}, cost_usd=0.0,
                              data={"status": 403, "title": "Access Denied", "html": AKAMAI, "screenshot_png": None, "favicon_png": ICO})  # fmt: skip


class _SnapNoIcon(_Urlscan):
    async def snapshot(self, domain, scan_id=None, peek=False):
        import io

        from PIL import Image

        from brandwatch.providers.base import ProviderResult, ProviderStatus

        buf = io.BytesIO()
        Image.new("RGB", (64, 64), (30, 90, 200)).save(buf, "PNG")
        return ProviderResult(provider="stub", status=ProviderStatus.POSITIVE, raw={}, cost_usd=0.0, data={
            "scan_id": "s1", "url": "https://stubbed.com/", "time": "2026-10-12T00:00:00Z", "title": "Stubbed Gear",
            "screenshot_png": buf.getvalue(), "html": None, "favicon_png": None})  # fmt: skip


def _png(color):
    import io

    from PIL import Image

    buf = io.BytesIO()
    Image.new("RGB", (32, 32), color).save(buf, "PNG")
    return buf.getvalue()


ICO = _png((200, 30, 30))


def test_the_favicon_comes_from_the_blocked_attempt_when_urlscan_did_not_keep_it(session, tmp_path):
    from brandwatch.detection import images
    from brandwatch.detection.baseline import build_baseline
    from brandwatch.evidence.store import LocalEvidenceStore

    class P(_Providers):
        def browser(self):
            return _BlockedWithIcon(self.log)

        def urlscan(self):
            return _SnapNoIcon()

    ws = make_workspace(session, f"ico-{uuid.uuid4().hex[:6]}")
    brand = make_brand(session, ws, "Stubbed")
    session.add(m.BrandDomain(brand_id=brand.id, domain="stubbed.com", is_official=True, kind="official"))
    session.flush()
    report = asyncio.run(build_baseline(session, brand, P(), LocalEvidenceStore(str(tmp_path / "ev")), escalate=False))
    fp = session.scalars(sa.select(m.BrandFingerprint).where(m.BrandFingerprint.brand_id == brand.id)).first()
    assert report.fetch["source"] == "urlscan" and report.fetch["snapshot"]["has_favicon"] is True
    assert report.fetch["snapshot"]["favicon_from"] == "site"
    assert fp.favicon_mmh3 == images.favicon_mmh3(ICO) and fp.favicon_phash and fp.logo_path
    assert "favicon" not in (fp.features or {}).get("unavailable", [])
    assert report.screenshot_phash and "stubbed" in report.keywords  # the picture and the title still come from the snapshot
