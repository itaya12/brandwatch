"""The dashboard is an operations view: scan data only (the explanations live in How it works), the attack map full width
with the numbers on it, the takedowns waiting on the analyst, the brands at a glance, the scans running now and a
one-line status bar."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

import sqlalchemy as sa
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session
from tests.test_demo_story import _api, _app, _ui
from tests.test_findings_bulk import _brand
from tests.test_pages_js import BROKEN, chromium  # noqa: F401 (the shared browser)

from brandwatch.db.enums import JobState
from brandwatch.db.models import Brand, ScanJob, TakedownDraft

PROSE = ("Nothing is sent automatically", "What the system does", "Finds the fake", "Press <b>START SCAN</b>", "Budget meter")


def test_the_dashboard_has_no_explanations_only_the_numbers(engine, tmp_path):
    app = _app(engine, tmp_path)
    with TestClient(app):
        c, ui = _api(app), _ui(app)
        brand, _rows = _brand(c, app)
        page = ui.get("/ui/dashboard").text
        for prose in PROSE:
            assert prose not in page, prose
        # the map comes first, its numbers on it, then the queues, the brands, the charts, and the status bar last
        order = ['id="geo"', 'class="map-kpis"', 'id="new-24h"', 'id="takedown-queue"', 'id="brands"', 'id="live"', 'id="status-bar"']
        at = [page.index(x) for x in order]
        assert at == sorted(at), order
        assert f'href="/ui/brands/{brand["id"]}"' in page.split('id="brands"')[1].split('id="live"')[0]
        bar = page.split('id="status-bar"')[1]
        assert 'data-k="cost_today_usd"' in bar and 'data-k="api_calls_today"' in bar and "scheduler" in bar
        # one brand selected: no brands panel
        one = ui.get("/ui/dashboard", params={"brand_id": brand["id"]}).text
        assert 'id="brands"' not in one and 'id="geo"' in one


def test_a_request_sent_a_week_ago_with_no_answer_waits_on_the_dashboard(engine, tmp_path):
    app = _app(engine, tmp_path)
    with TestClient(app):
        c, ui = _api(app), _ui(app)
        brand, rows = _brand(c, app)
        fid = rows["shopn0va.com"]["id"]
        c.post(f"/api/findings/{fid}/confirm", json={"reason": "cloned login"})
        tid = c.post(f"/api/findings/{fid}/takedown").json()["id"]
        before = ui.get("/ui/dashboard", params={"brand_id": brand["id"]}).text
        assert "shopn0va.com" in before.split('id="takedown-queue"')[1][:6000] and "not sent yet" in before
        ui.post(f"/ui/takedowns/{tid}/channel", data={"channel": "registrar", "contact": "abuse@registrar.example", "mark": "sent"}, follow_redirects=False)
        d = c.get("/api/dashboard", params={"brand_id": brand["id"]}).json()
        assert d["kpis"]["takedowns_stale"] == 0
        with engine.begin() as conn:
            conn.execute(sa.update(TakedownDraft).where(TakedownDraft.id == uuid.UUID(tid)).values(sent_at=datetime.now(UTC) - timedelta(days=9)))
        d = c.get("/api/dashboard", params={"brand_id": brand["id"]}).json()
        assert d["kpis"]["takedowns_stale"] == 1 and d["last_scan_at"]
        page = ui.get("/ui/dashboard", params={"brand_id": brand["id"]}).text
        queue = page.split('id="takedown-queue"')[1][:6000]
        assert "shopn0va.com" in queue and "no answer for 9 days" in queue
        assert 'data-k="takedowns_stale"' in page.split('id="action-required"')[1][:4000]


def test_the_scans_running_now_are_listed(engine, tmp_path):
    app = _app(engine, tmp_path)
    with TestClient(app):
        c, ui = _api(app), _ui(app)
        brand = c.post("/api/brands", json={"name": f"Running {uuid.uuid4().hex[:4]}", "domains": ["running.example"], "preset": "basic"}).json()
        with Session(engine) as s:
            ws = s.get(Brand, uuid.UUID(brand["id"])).workspace_id
            job = ScanJob(workspace_id=ws, brand_id=uuid.UUID(brand["id"]), kind="brand_scan", state=JobState.RUNNING)
            s.add(job)
            s.commit()
            jid = job.id
        try:
            d = c.get("/api/dashboard", params={"brand_id": brand["id"]}).json()
            assert [j["id"] for j in d["running_jobs"]] == [str(jid)] and d["kpis"]["running"] == 1
            page = ui.get("/ui/dashboard", params={"brand_id": brand["id"]}).text
            assert f'href="/ui/jobs/{jid}"' in page.split('id="runs"')[1][:2000]
        finally:
            with engine.begin() as conn:
                conn.execute(sa.delete(ScanJob).where(ScanJob.id == jid))


def test_the_dashboard_map_is_the_all_confirmed_sites_view(engine, tmp_path):
    """The globe is gone: the dashboard shows every confirmed site on one map, with the same five views and group filter as
    Attack infrastructure, fetched after the page (JSON, so the static demo keeps a copy), without the help text."""
    app = _app(engine, tmp_path)
    with TestClient(app):
        c, ui = _api(app), _ui(app)
        brand, rows = _brand(c, app)
        for h in ("shopn0va.com", "shopnova-login.com"):
            c.post(f"/api/findings/{rows[h]['id']}/confirm", json={"reason": "cloned login"})
        r = ui.get("/ui/dashboard/sites-map", params={"brand_id": brand["id"]})
        assert r.status_code == 200
        d = r.json()
        html = d["html"]
        assert d["sites"] >= 2 and 'id="vsw"' in html and 'id="graph"' in html
        for v in ("graph", "connections", "matrix", "flow", "timeline"):
            assert f'data-v="{v}"' in html, v
        assert 'id="t-common"' in html and "reset view" in html and "full analysis" in html
        assert "armWheel: true" in html and "Big dot with a name" not in html  # the page keeps its wheel; no help text
        full = ui.get("/ui/campaigns/all", params={"brand_id": brand["id"]}).text
        assert 'id="vsw"' in full and "armWheel: false" in full and "Big dot with a name" in full and 'class="gcard"' in full
        assert TestClient(app).get("/ui/dashboard/sites-map").status_code == 401


def test_the_map_fills_a_phone_without_sideways_scroll(engine, tmp_path, chromium):  # noqa: F811
    app = _app(engine, tmp_path)
    with TestClient(app):
        c, ui = _api(app), _ui(app)
        _brand(c, app)
        html = ui.get("/ui/dashboard").text
    ctx = chromium.new_context(viewport={"width": 390, "height": 844}, is_mobile=True)
    page = ctx.new_page()
    errors: list[str] = []
    page.on("pageerror", lambda e: errors.append(str(e)))
    page.set_content(html, wait_until="domcontentloaded")
    page.wait_for_timeout(300)
    assert page.evaluate("document.documentElement.scrollWidth - innerWidth") <= 1
    h = page.evaluate("document.querySelector('#sites-map .sm-skel').getBoundingClientRect().height")
    assert 360 <= h <= 440, h  # the room the map will take, held while it loads
    assert page.evaluate("getComputedStyle(document.querySelector('.map-kpis')).position") == "static"
    ctx.close()
    assert [e for e in errors if BROKEN.search(e)] == []


def test_the_charts_play_when_seen_and_the_how_it_works_steps_fit_a_phone(engine, tmp_path):
    app = _app(engine, tmp_path)
    with TestClient(app):
        c, ui = _api(app), _ui(app)
        _brand(c, app)
        dash = ui.get("/ui/dashboard").text
        charts = dash.split('class="charts"')[1].split('id="showcase"')[0]
        assert charts.count("data-dw=") >= 4 and "data-dh=" in charts and "width:" not in charts.split("<i ")[1][:80]
        assert "@keyframes barsweep" in dash and "@keyframes histscan" in dash and "IntersectionObserver" in dash and "prefers-reduced-motion" in dash
        how = ui.get("/ui/how-it-works").text
        rail = how.split('id="rail"')[1].split("</nav>")[0]
        assert rail.count('<span class="k"> · ') == 6 and 'aria-label="Step 1: ' in rail
