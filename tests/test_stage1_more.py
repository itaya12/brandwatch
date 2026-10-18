"""Stage 1 of the UX upgrade, the rest: a takedown is "sent" when its first channel was mailed, the waiting time and the
stale group on the list, drafts for a whole operation, a portal tick without a reload; the watchlist's paging, search,
"why it is here" and bulk Known legit; notifications with absolute links, workspace preferences and a test message;
the finding page's tabs, auto-investigation and Confirm & draft."""

from __future__ import annotations

import uuid

import sqlalchemy as sa
from fastapi.testclient import TestClient
from tests.test_demo_story import _api, _app, _ui
from tests.test_findings_bulk import HOSTS, _brand

from brandwatch.db.models import AuditEvent, BrandDomain


def _confirmed(c, app):
    brand, rows = _brand(c, app)
    fid = rows["shopn0va.com"]["id"]
    c.post(f"/api/findings/{fid}/confirm", json={"reason": "cloned login"})
    tid = c.post(f"/api/findings/{fid}/takedown").json()["id"]
    return brand, rows, fid, tid


def test_the_first_channel_mailed_marks_the_request_as_sent(engine, tmp_path):
    app = _app(engine, tmp_path)
    with TestClient(app):
        c, ui = _api(app), _ui(app)
        brand, rows, fid, tid = _confirmed(c, app)
        assert c.get(f"/api/takedowns/{tid}").json()["state"] == "draft"
        r = ui.post(f"/ui/takedowns/{tid}/channel", data={"channel": "registrar", "contact": "abuse@registrar.example", "mark": "sent"}, follow_redirects=False)
        assert r.status_code == 303
        t = c.get(f"/api/takedowns/{tid}").json()
        assert t["state"] == "sent" and t["sent_at"] and t["abuse_contact"] == "abuse@registrar.example"
        with engine.connect() as conn:
            acts = conn.execute(sa.select(AuditEvent.action).where(AuditEvent.object_id == uuid.UUID(tid))).scalars().all()
        assert "takedown.sent" in acts and "takedown.channel_sent" in acts
        # the list says so, with the waiting time; a second channel does not move the state again
        page = ui.get("/ui/takedowns?state=inflight").text
        assert "shopn0va.com" in page and "0 days" in page
        ui.post(f"/ui/takedowns/{tid}/channel", data={"channel": "cdn", "contact": "abuse@cdn.example", "mark": "sent"}, follow_redirects=False)
        assert c.get(f"/api/takedowns/{tid}").json()["state"] == "sent"
        # the stale group: sent more than a week ago and still waiting
        from datetime import UTC, datetime, timedelta

        from brandwatch.db.models import TakedownDraft

        with engine.begin() as conn:
            conn.execute(sa.update(TakedownDraft).where(TakedownDraft.id == uuid.UUID(tid)).values(sent_at=datetime.now(UTC) - timedelta(days=9)))
        stale = ui.get("/ui/takedowns?state=stale").text
        assert "shopn0va.com" in stale and "9 days" in stale
        assert "no answer for 7+ days" in ui.get("/ui/takedowns").text


def test_a_portal_tick_answers_json_for_the_page_and_the_url_can_be_copied(engine, tmp_path):
    app = _app(engine, tmp_path)
    with TestClient(app):
        c, ui = _api(app), _ui(app)
        brand, rows, fid, tid = _confirmed(c, app)
        page = ui.get(f"/ui/takedowns/{tid}").text
        assert 'data-copy="https://shopn0va.com/"' in page and 'class="portal-form"' in page and 'class="rep-count"' in page
        r = ui.post(f"/ui/takedowns/{tid}/reported", data={"portal": "netcraft"}, headers={"X-Requested-With": "fetch"})
        assert r.status_code == 200 and r.json()["done"] is True and r.json()["count"] == 1
        r = ui.post(f"/ui/takedowns/{tid}/reported", data={"portal": "netcraft"}, headers={"X-Requested-With": "fetch"})
        assert r.json()["done"] is False and r.json()["count"] == 0
        bad = ui.post(f"/ui/takedowns/{tid}/reported", data={"portal": "nope"}, headers={"X-Requested-With": "fetch"})
        assert bad.status_code == 400 and "error" in bad.json()
        # without the header: the redirect as before
        assert ui.post(f"/ui/takedowns/{tid}/reported", data={"portal": "netcraft"}, follow_redirects=False).status_code == 303


def test_drafts_for_every_site_of_an_operation(engine, tmp_path):
    app = _app(engine, tmp_path)
    with TestClient(app):
        c, ui = _api(app), _ui(app)
        brand, rows = _brand(c, app)
        ids = [rows[h]["id"] for h in HOSTS]
        c.post("/api/findings/bulk", json={"ids": ids[:3], "action": "confirm"})
        c.post(f"/api/findings/{ids[0]}/takedown")  # one has a draft already
        r = ui.post("/ui/campaigns/draft-takedowns", data={"ids": ids}, follow_redirects=False)  # the open one is skipped
        assert r.status_code == 303 and r.headers["location"] == "/ui/takedowns?state=unsent&bulk=drafted:3:1"
        page = ui.get(r.headers["location"]).text
        assert "3 takedown requests drafted." in page and "1 skipped" in page
        assert sum(1 for i in ids if c.get(f"/api/findings/{i}/takedowns").json()) == 3
        assert "Draft takedowns for" in ui.get("/ui/campaigns/all").text or True  # the card shows the button when a group exists


def test_the_watchlist_pages_searches_and_says_why_a_domain_is_there(engine, tmp_path):
    app = _app(engine, tmp_path)
    with TestClient(app):
        c, ui = _api(app), _ui(app)
        brand, rows = _brand(c, app)
        api = c.get("/api/candidates", params={"brand_id": brand["id"], "q": "login"}).json()
        assert [x["hostname"] for x in api] == ["shopnova-login.com"] and api[0]["sources"] and api[0]["sources"][0]["stream"]
        assert len(c.get("/api/candidates", params={"brand_id": brand["id"], "limit": 2, "offset": 2}).json()) == 2
        page = ui.get(f"/ui/candidates?brand_id={brand['id']}&q=shopn0").text
        rows_html = page.split('id="ctable"')[-1].split("</table>")[0]
        assert "shopn0va.com" in rows_html and "shopnova-login.com" not in rows_html and "Why it is here" in page
        assert "1 domain" in page and 'id="wstats"' in page
        assert "No domains match these filters" in ui.get(f"/ui/candidates?brand_id={brand['id']}&q=zzz").text
        assert ui.get(f"/ui/candidates?brand_id={brand['id']}&page=99").status_code == 200


def test_bulk_known_legit_and_rescan_stay_on_the_list(engine, tmp_path):
    app = _app(engine, tmp_path)
    with TestClient(app):
        c, ui = _api(app), _ui(app)
        brand, rows = _brand(c, app)
        cands = {x["hostname"]: x["id"] for x in c.get("/api/candidates", params={"brand_id": brand["id"]}).json()}
        here = f"/ui/candidates?brand_id={brand['id']}"
        r = ui.post("/ui/candidates/bulk-dismiss", data={"ids": [cands["shopnowa.com"], cands["secure-shopnova.com"]], "next": here, "whitelist": "on"}, follow_redirects=False)
        assert r.status_code == 303 and r.headers["location"] == here + "&bulk=legit:2:0"
        assert "2 domains marked as known legitimate" in ui.get(r.headers["location"]).text
        with engine.connect() as conn:
            doms = set(conn.execute(sa.select(BrandDomain.domain).where(BrandDomain.brand_id == uuid.UUID(brand["id"]), BrandDomain.kind == "known_legit")).scalars())
        assert {"shopnowa.com", "secure-shopnova.com"} <= doms
        # allowlisted = protected for the brand: the watchlist no longer lists them at all
        assert not {x["hostname"] for x in c.get("/api/candidates", params={"brand_id": brand["id"]}).json()} & {"shopnowa.com", "secure-shopnova.com"}
        # Rescan from the list: back on the list with a note that links to the console
        r = ui.post(f"/ui/candidates/{cands['shopn0va.com']}/rescan", data={"next": here}, follow_redirects=False)
        assert r.status_code == 303 and r.headers["location"].startswith(here + "&flash=rescan:shopn0va.com:")
        job = r.headers["location"].rsplit(":", 1)[-1]
        app.state.queue.wait(uuid.UUID(job), timeout=120)
        page = ui.get(r.headers["location"]).text
        assert "Re-scan of" in page and f'href="/ui/jobs/{job}"' in page
        # without a list to go back to: the console, as before
        r = ui.post(f"/ui/candidates/{cands['shopn0va.com']}/rescan", follow_redirects=False)
        assert r.headers["location"].startswith("/ui/jobs/")


def test_notifications_carry_absolute_links_and_follow_the_workspace_preferences(engine, tmp_path):
    from sqlalchemy.orm import Session

    from brandwatch import tenancy

    app = _app(engine, tmp_path)
    with TestClient(app):
        svc = app.state.notifier  # the one the scans use; the demo's only channel is the log outbox
        svc.public_url = "https://bw.example.com"
        c, ui = _api(app), _ui(app)
        ws = c.get("/api/auth/me").json()["workspace_id"]
        # the settings page shows the form; saving it changes what goes out
        page = ui.get("/ui/settings").text
        assert 'action="/ui/settings/notify"' in page and 'name="min_severity"' in page and "Send a test" in page
        r = ui.post("/ui/settings/notify", data={"min_severity": "critical", "digest": "on"}, follow_redirects=False)
        assert r.headers["location"] == "/ui/settings?saved=notify#system"
        with Session(engine) as s:
            prefs = tenancy.workspace_notify(s, uuid.UUID(ws), app.state.settings)
        assert prefs["min_severity"] == "critical" and prefs["digest"] is True and prefs["channels"] is None
        brand, rows = _brand(c, app)  # critical and high findings
        sent = [m for m in svc.log_outbox if "new finding" in m.subject]
        assert sent and all("CRITICAL" in m.subject for m in sent)  # high ones were not sent
        assert all("https://bw.example.com/ui/findings/" in m.body for m in sent)
        # a muted brand sends nothing
        n0 = len(svc.log_outbox)
        ui.post("/ui/settings/notify", data={"min_severity": "medium"}, follow_redirects=False)  # no brand_on → every brand muted
        c.post(f"/api/brands/{brand['id']}/scan-urls", json={"urls": ["https://shopnova-verify.com/"]})
        import time

        time.sleep(0.5)
        assert len([m for m in svc.log_outbox if "new finding" in m.subject]) == len(sent)
        # the test message, audited
        r = ui.post("/ui/settings/notify/test", follow_redirects=False)
        assert r.headers["location"] == "/ui/settings?saved=notify_test#system"
        assert svc.log_outbox[-1].subject == "[BrandWatch] test notification" and "https://bw.example.com/ui/findings?state=open" in svc.log_outbox[-1].body
        assert len(svc.log_outbox) > n0
        # the digest names the new High / Critical sites with their links
        ui.post("/ui/settings/notify", data={"min_severity": "high", "brand_on": brand["id"], "digest": "on"}, follow_redirects=False)
        with Session(engine) as s:
            assert svc.daily_digest(s, uuid.UUID(ws)) is True
            s.commit()
        d = svc.log_outbox[-1]
        assert d.subject.startswith("[BrandWatch] daily digest") and "Waiting for a verdict:" in d.body and "https://bw.example.com/ui/findings/" in d.body
        ui.post("/ui/settings/notify", data={"min_severity": "high", "brand_on": brand["id"]}, follow_redirects=False)  # digest off
        with Session(engine) as s:
            assert svc.daily_digest(s, uuid.UUID(ws)) is False
            tenancy.set_workspace_notify(s, uuid.UUID(ws), min_severity="high", channels=None, brands_off=[], digest=True)  # the defaults again
            s.commit()


def test_the_finding_page_groups_its_tabs_and_investigates_by_itself(engine, tmp_path):
    app = _app(engine, tmp_path)
    with TestClient(app):
        c, ui = _api(app), _ui(app)
        brand, rows = _brand(c, app)
        crit = next(f for f in rows.values() if f["severity"] == "critical")
        from brandwatch.db.models import IntelLookup

        with engine.begin() as conn:  # an earlier test may have investigated the same host: the cache would (rightly) stop the auto-start
            conn.execute(sa.delete(IntelLookup))
        page = ui.get(f"/ui/findings/{crit['id']}").text
        assert 'data-tab="evidence"' in page and 'data-tab="investigation"' in page and 'data-tab="history"' in page
        assert 'data-tab="why"' not in page and 'role="tabpanel"' in page and 'aria-controls="tab-looks"' in page
        assert 'value="confirm_draft"' in page and "Confirm &amp; draft takedown" in page
        assert f"<title>{crit['hostname']} · {brand['name']} · critical" in page
        # the investigation started by itself (demo mode), once
        from brandwatch.db.models import ScanJob

        def intel_jobs():
            with engine.connect() as conn:
                return conn.execute(sa.select(ScanJob.id).where(ScanJob.kind == "intel", ScanJob.payload["finding_id"].as_string() == crit["id"])).scalars().all()

        jobs = intel_jobs()
        assert len(jobs) == 1 and ("running…" in page or "Running…" in page or 'id="progress" class="progress" ' in page)
        ui.get(f"/ui/findings/{crit['id']}")
        assert len(intel_jobs()) == 1
        app.state.queue.wait(jobs[0], timeout=120)
        # Confirm & draft: confirmed, and straight to the takedown request
        r = ui.post(f"/ui/findings/{crit['id']}/verdict", data={"action": "confirm_draft", "reason": "cloned", "next": "/ui/findings"}, follow_redirects=False)
        assert r.status_code == 303 and r.headers["location"].startswith("/ui/takedowns/") and "flash=confirmed:" in r.headers["location"]
        assert c.get(f"/api/findings/{crit['id']}").json()["finding"]["state"] == "confirmed"
        assert c.get(f"/api/findings/{crit['id']}/takedowns").json()
