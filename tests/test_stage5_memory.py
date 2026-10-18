"""Stage 5 of the UX upgrade: working memory for one analyst — notes on a finding, snooze until a date, the lists as
CSV / JSON with their filters, and the scan console's links to what the scan found and a Retry."""

from __future__ import annotations

import csv
import io
import uuid
from datetime import UTC, datetime, timedelta

import sqlalchemy as sa
from fastapi.testclient import TestClient
from tests.test_demo_story import _api, _app, _ui
from tests.test_findings_bulk import _brand

from brandwatch.db.models import AuditEvent, Finding


def test_a_note_is_kept_with_the_finding_and_in_activity(engine, tmp_path):
    app = _app(engine, tmp_path)
    with TestClient(app):
        c, ui = _api(app), _ui(app)
        brand, rows = _brand(c, app)
        fid = rows["shopnowa.com"]["id"]
        r = ui.post(f"/ui/findings/{fid}/note", data={"text": "asked the registrar · שאלתי את הרשם"}, follow_redirects=False)
        assert r.status_code == 303 and r.headers["location"].endswith("?saved=note#notes")
        page = ui.get(f"/ui/findings/{fid}").text
        assert 'id="notes"' in page and "asked the registrar · שאלתי את הרשם" in page and "Note added" in ui.get(r.headers["location"]).text
        assert c.post(f"/api/findings/{fid}/notes", json={"text": ""}).status_code == 422
        with engine.connect() as conn:
            assert "finding.note_added" in conn.execute(sa.select(AuditEvent.action).where(AuditEvent.object_id == uuid.UUID(fid))).scalars().all()


def test_a_snoozed_finding_leaves_the_queue_and_comes_back_by_itself(engine, tmp_path):
    from brandwatch.api import ui as ui_mod

    app = _app(engine, tmp_path)
    with TestClient(app):
        c, ui = _api(app), _ui(app)
        brand, rows = _brand(c, app)
        fid = rows["shopnowa.com"]["id"]
        q = lambda **p: [f["id"] for f in c.get("/api/findings", params={"brand_id": brand["id"], "state": "open", **p}).json()]  # noqa: E731
        assert fid in q()
        r = ui.post(f"/ui/findings/{fid}/snooze", data={"days": "7", "reason": "parked", "next": "/ui/findings"}, follow_redirects=False)
        assert r.status_code == 303 and "flash=snoozed:shopnowa.com:" in r.headers["location"]  # on to the next open one
        assert fid not in q()
        page = ui.get("/ui/findings", params={"brand_id": brand["id"], "state": "snoozed"}).text
        assert "shopnowa.com" in page.split('id="ftable"')[1] and ">snoozed<" in page
        ui_mod._NAV_CACHE.clear()
        assert "Snoozed until" in ui.get(f"/ui/findings/{fid}").text
        # the date passes: it is back in the queue, and the digest says so
        with engine.begin() as conn:
            conn.execute(sa.update(Finding).where(Finding.id == uuid.UUID(fid)).values(snoozed_until=datetime.now(UTC) - timedelta(hours=1)))
        assert fid in q()
        svc = app.state.notifier
        from sqlalchemy.orm import Session

        ws = c.get("/api/auth/me").json()["workspace_id"]
        from brandwatch import tenancy

        with Session(engine) as s:
            # another test may have muted the digest of this (shared) workspace: on, for every brand
            tenancy.set_workspace_notify(s, uuid.UUID(ws), min_severity="high", channels=None, brands_off=[], digest=True)
            svc.daily_digest(s, uuid.UUID(ws))
            s.commit()
        digest = [m for m in svc.log_outbox if m.subject.startswith("[BrandWatch] daily digest")][-1]
        assert "Back from snooze today: " in digest.body
        # snooze, then wake it by hand; a closed finding cannot be snoozed
        c.post(f"/api/findings/{fid}/snooze", json={"days": 3})
        assert fid not in q()
        assert c.post(f"/api/findings/{fid}/snooze", json={"days": 0}).json()["snoozed_until"] is None and fid in q()
        c.post(f"/api/findings/{fid}/dismiss", json={"reason": "x"})
        assert c.post(f"/api/findings/{fid}/snooze", json={"days": 3}).status_code == 409


def test_the_lists_download_with_their_filters(engine, tmp_path):
    app = _app(engine, tmp_path)
    with TestClient(app):
        c, ui = _api(app), _ui(app)
        brand, rows = _brand(c, app)
        r = ui.get("/ui/findings", params={"brand_id": brand["id"], "state": "open", "q": "login", "fmt": "csv"})
        assert r.headers["content-type"].startswith("text/csv") and "brandwatch-findings.csv" in r.headers["content-disposition"]
        data = list(csv.DictReader(io.StringIO(r.text.lstrip("﻿"))))
        assert [d["hostname"] for d in data] == ["shopnova-login.com"]
        js = ui.get("/ui/findings", params={"brand_id": brand["id"], "state": "open", "fmt": "json"}).json()
        assert len(js) == len(rows) and {"hostname", "severity", "signals"} & set(js[0])
        wl = ui.get("/ui/candidates", params={"brand_id": brand["id"], "fmt": "csv"})
        assert "found_by" in wl.text.splitlines()[0] and "shopn0va.com" in wl.text
        fid = rows["shopn0va.com"]["id"]
        c.post(f"/api/findings/{fid}/confirm", json={"reason": "x"})
        td = ui.get("/ui/takedowns", params={"brand_id": brand["id"], "fmt": "json"}).json()
        assert any(x["hostname"] == "shopn0va.com" and x["takedown_state"] == "none" for x in td)
        page = ui.get("/ui/findings", params={"brand_id": brand["id"], "state": "open"}).text
        assert "&fmt=csv" in page and "&fmt=json" in page


def test_the_console_links_to_what_the_scan_found_and_retries_a_failed_one(engine, tmp_path):
    from brandwatch.db.enums import JobState
    from brandwatch.db.models import ScanJob

    app = _app(engine, tmp_path)
    with TestClient(app):
        c, ui = _api(app), _ui(app)
        brand, rows = _brand(c, app)
        job = c.get("/api/jobs", params={"brand_id": brand["id"]}).json()[0]
        page = ui.get(f"/ui/jobs/{job['id']}").text
        assert f'href="/ui/findings?state=&job_id={job["id"]}"' in page
        found = ui.get("/ui/findings", params={"state": "", "job_id": job["id"]}).text
        assert "Only what one scan found or re-scored" in found and all(h in found for h in rows)
        other = c.post(f"/api/brands/{brand['id']}/scan-urls", json={"urls": ["https://shopnova-verify.com/"]}).json()["job_id"]
        app.state.queue.wait(uuid.UUID(other), timeout=120)
        later = ui.get("/ui/findings", params={"state": "", "job_id": other}).text.split('id="ftable"')
        assert len(later) == 1 or "shopnowa.com" not in later[1]  # only that scan's
        with engine.begin() as conn:
            conn.execute(sa.update(ScanJob).where(ScanJob.id == uuid.UUID(other)).values(state=JobState.FAILED))
        assert f'action="/ui/jobs/{other}/retry"' in ui.get(f"/ui/jobs/{other}").text
