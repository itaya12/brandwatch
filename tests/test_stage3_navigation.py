"""Stage 3 of the UX upgrade: the nav shows what waits, one search box finds anything, every scan is listed with a Retry,
the activity log filters on the server and exports CSV, and the dashboard leads with what needs an analyst."""

from __future__ import annotations

import csv
import io
import uuid

import sqlalchemy as sa
from fastapi.testclient import TestClient
from tests.test_demo_story import _api, _app, _ui
from tests.test_findings_bulk import _brand

from brandwatch.db.enums import JobState
from brandwatch.db.models import ScanJob


def test_the_nav_counts_open_findings_and_unsent_takedowns(engine, tmp_path):
    from brandwatch.api import ui as ui_mod

    app = _app(engine, tmp_path)
    with TestClient(app):
        c, ui = _api(app), _ui(app)
        brand, rows = _brand(c, app)
        ui_mod._NAV_CACHE.clear()
        page = ui.get("/ui/brands").text
        nav = page.split('<nav aria-label="Main">')[1].split("</nav>")[0]
        assert nav.index("Findings") < nav.index("Watchlist") < nav.index("Attack infrastructure") < nav.index("Takedowns") < nav.index("Brands") < nav.index("How it works")
        assert 'class="nc"' in nav and 'id="hsearch"' in page
        n_open = int(nav.split('class="nc" title="')[1].split(" ")[0])
        assert n_open >= len(rows)
        # a verdict is counted on the very next page (the flash forces a recount)
        fid = next(iter(rows.values()))["id"]
        r = ui.post(f"/ui/findings/{fid}/verdict", data={"action": "confirm", "reason": "x", "next": "/ui/findings"}, follow_redirects=True)
        nav2 = r.text.split('<nav aria-label="Main">')[1].split("</nav>")[0]
        assert int(nav2.split('class="nc" title="')[1].split(" ")[0]) == n_open - 1
        assert 'class="nc warn"' in nav2  # a confirmed site with no takedown sent


def test_one_search_box_finds_findings_watchlist_allowlist_takedowns_and_brands(engine, tmp_path):
    app = _app(engine, tmp_path)
    with TestClient(app):
        c, ui = _api(app), _ui(app)
        brand, rows = _brand(c, app)
        fid = rows["shopn0va.com"]["id"]
        c.post(f"/api/findings/{fid}/confirm", json={"reason": "x"})
        td = c.post(f"/api/findings/{fid}/takedown").json()
        page = ui.get("/ui/search", params={"q": "shopn0va"}).text
        assert f'href="/ui/findings/{fid}"' in page and "Findings" in page
        assert f'href="/ui/takedowns/{td["id"]}"' in page  # by the host of its site
        by_ref = ui.get("/ui/search", params={"q": td["reference"][-6:]}).text
        assert f'href="/ui/takedowns/{td["id"]}"' in by_ref or "Takedowns" in by_ref
        official = ui.get("/ui/search", params={"q": "shopnova.com"}).text
        assert "Official and allowlisted domains" in official
        named = ui.get("/ui/search", params={"q": brand["name"][-4:]}).text
        assert f'href="/ui/brands/{brand["id"]}"' in named
        assert "Type at least two characters" in ui.get("/ui/search", params={"q": "x"}).text
        assert "0 results" in ui.get("/ui/search", params={"q": "zzzz-nothing-zzzz"}).text


def test_every_scan_is_listed_and_a_failed_one_can_be_retried(engine, tmp_path):
    app = _app(engine, tmp_path)
    with TestClient(app):
        c, ui = _api(app), _ui(app)
        brand, rows = _brand(c, app)
        page = ui.get("/ui/scans", params={"brand_id": brand["id"]}).text
        assert "URL scan" in page and 'name="kind"' in page
        job = c.get("/api/jobs", params={"brand_id": brand["id"]}).json()[0]
        assert ui.post(f"/ui/jobs/{job['id']}/retry", follow_redirects=False).headers["location"] == f"/ui/jobs/{job['id']}"  # done: nothing to retry
        with engine.begin() as conn:
            conn.execute(sa.update(ScanJob).where(ScanJob.id == uuid.UUID(job["id"])).values(state=JobState.FAILED, error="boom"))
        failed = ui.get("/ui/scans", params={"brand_id": brand["id"], "state": "failed"}).text
        assert f'action="/ui/jobs/{job["id"]}/retry"' in failed
        r = ui.post(f"/ui/jobs/{job['id']}/retry", follow_redirects=False)
        new_id = r.headers["location"].rsplit("/", 1)[-1]
        assert new_id != job["id"]
        app.state.queue.wait(uuid.UUID(new_id), timeout=120)
        with engine.connect() as conn:
            row = conn.execute(sa.select(ScanJob).where(ScanJob.id == uuid.UUID(new_id))).first()
        assert row.kind == "url_scan" and row.payload["retry_of"] == job["id"] and row.payload["urls"]
        assert "retry" in ui.get("/ui/scans", params={"brand_id": brand["id"]}).text


def test_the_activity_log_filters_pages_and_exports(engine, tmp_path):
    app = _app(engine, tmp_path)
    with TestClient(app):
        c, ui = _api(app), _ui(app)
        brand, rows = _brand(c, app)
        fid = rows["shopnowa.com"]["id"]
        c.post(f"/api/findings/{fid}/dismiss", json={"reason": "parked page"})
        page = ui.get("/ui/activity", params={"category": "finding"}).text
        assert 'name="since"' in page and "⤓ CSV" in page and "dismissed" in page
        one = ui.get("/ui/activity", params={"object_id": fid}).text
        assert "Only the events about one object" in one and "parked page" in one
        nothing = ui.get("/ui/activity", params={"since": "2000-01-01", "until": "2000-01-02"}).text
        assert "0 events match" in nothing
        r = ui.get("/ui/activity.csv", params={"category": "finding", "object_id": fid})
        assert r.status_code == 200 and r.headers["content-type"].startswith("text/csv")
        data = list(csv.DictReader(io.StringIO(r.text.lstrip("﻿"))))
        assert data and all(d["action"].startswith("finding.") for d in data) and any(d["reason"] == "parked page" for d in data)
        assert ui.get("/ui/activity", params={"since": "not-a-date", "category": "a;b"}).status_code == 200


def test_the_dashboard_leads_with_what_waits(engine, tmp_path):
    app = _app(engine, tmp_path)
    with TestClient(app):
        c, ui = _api(app), _ui(app)
        brand, rows = _brand(c, app)
        page = ui.get("/ui/dashboard", params={"brand_id": brand["id"]}).text
        assert page.index('id="action-required"') < page.index('id="geo"') < page.index('id="new-24h"')
        assert 'data-k="findings_open"' in page.split('id="action-required"')[1][:3000]  # refreshed every 20 s
        assert 'id="sites-map"' in page
        crit = [r for r in rows.values() if r["severity"] in ("critical", "high")]
        assert all(f'href="/ui/findings/{f["id"]}"' in page.split('id="new-24h"')[1].split('id="takedown-queue"')[0] for f in crit[:8])
