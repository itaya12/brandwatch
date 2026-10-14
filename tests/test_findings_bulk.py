"""The findings list: a verdict on many findings at once (tick, then Confirm phishing / Not phishing), and screenshots next to every site
as a view the analyst switches on (off by default)."""

from __future__ import annotations

import uuid

from fastapi.testclient import TestClient
from tests.test_demo_story import _api, _app, _ui

HOSTS = ("shopn0va.com", "shopnova-login.com", "shopnowa.com", "secure-shopnova.com")


def _brand(c, app):
    brand = c.post("/api/brands", json={"name": f"Bulk {uuid.uuid4().hex[:4]}", "domains": ["shopnova.com"]}).json()
    c.patch(f"/api/brands/{brand['id']}/config", json={"detection": {"auto_map_on_confirm": False, "auto_investigate_on_confirm": False}})
    job = c.post(f"/api/brands/{brand['id']}/scan-urls", json={"urls": [f"https://{h}/" for h in HOSTS]}).json()["job_id"]
    app.state.queue.wait(uuid.UUID(job), timeout=120)
    rows = {f["hostname"]: f for f in c.get("/api/findings", params={"brand_id": brand["id"], "state": "open"}).json()}
    return brand, rows


def test_one_verdict_for_many_findings_through_the_api(engine, tmp_path):
    app = _app(engine, tmp_path)
    with TestClient(app):
        c = _api(app)
        brand, rows = _brand(c, app)
        ids = [rows[h]["id"] for h in ("shopn0va.com", "shopnova-login.com")]
        r = c.post("/api/findings/bulk", json={"ids": ids, "action": "confirm", "reason": "same kit"}).json()
        assert r["changed"] == 2 and sorted(r["hosts"]) == ["shopn0va.com", "shopnova-login.com"] and r["skipped"] == []
        assert {c.get(f"/api/findings/{i}").json()["finding"]["state"] for i in ids} == {"confirmed"}
        again = c.post("/api/findings/bulk", json={"ids": [ids[0], rows["shopnowa.com"]["id"]], "action": "dismiss"}).json()
        assert again["changed"] == 1 and again["hosts"] == ["shopnowa.com"] and again["skipped"][0]["why"] == "already confirmed"  # a decided one is left alone
        assert c.get(f"/api/findings/{rows['shopnowa.com']['id']}").json()["finding"]["state"] == "dismissed"
        assert c.post("/api/findings/bulk", json={"ids": ids, "action": "delete"}).status_code == 422
        assert c.post("/api/findings/bulk", json={"ids": [], "action": "confirm"}).status_code == 422
        none = c.post("/api/findings/bulk", json={"ids": [str(uuid.uuid4())], "action": "confirm"}).json()
        assert none["changed"] == 0 and none["skipped"][0]["why"] == "not found"


def test_the_list_sends_the_ticked_rows_and_comes_back_with_what_changed(engine, tmp_path):
    app = _app(engine, tmp_path)
    with TestClient(app):
        c, ui = _api(app), _ui(app)
        brand, rows = _brand(c, app)
        back = f"/ui/findings?brand_id={brand['id']}&state=open"
        page = ui.get(back).text
        assert 'id="bulkform"' in page and 'class="sel"' in page and "✓ Confirm phishing" in page and "✕ Not phishing" in page
        assert 'id="t-shots"' in page and "show screenshots" in page and 'class="shotcol"' in page
        r = ui.post("/ui/findings/bulk", data={"ids": [rows["shopn0va.com"]["id"], rows["secure-shopnova.com"]["id"]], "action": "confirm", "next": back},
                    follow_redirects=False)  # fmt: skip
        assert r.status_code == 303 and r.headers["location"].startswith(back + "&bulk=confirm%3A2%3A0")
        shown = ui.get(r.headers["location"]).text
        assert "2 findings confirmed as phishing." in shown and "MAP ALL" in shown
        assert "shopn0va.com" not in shown.split('id="ftable"')[-1]  # no longer open: off the list
        foreign = ui.post("/ui/findings/bulk", data={"ids": [rows["shopnowa.com"]["id"]], "action": "dismiss", "next": "https://evil.example/"}, follow_redirects=False)
        assert foreign.headers["location"].startswith("/ui/findings?bulk=dismiss%3A1")  # back to the list, never elsewhere


def test_screenshots_are_a_view_that_is_off_until_switched_on_and_the_bar_counts_the_ticks(engine, tmp_path):
    import pytest

    sync = pytest.importorskip("playwright.sync_api")
    app = _app(engine, tmp_path)
    with TestClient(app):
        c, ui = _api(app), _ui(app)
        brand, rows = _brand(c, app)
        html = ui.get(f"/ui/findings?brand_id={brand['id']}&state=open").text
    with sync.sync_playwright() as pw:
        try:
            b = pw.chromium.launch()
        except Exception as exc:  # noqa: BLE001
            pytest.skip(f"no sandboxed Chromium here: {exc}")
        page = b.new_page(viewport={"width": 1400, "height": 900})
        errors: list[str] = []
        page.on("pageerror", lambda e: errors.append(str(e)))
        page.set_content(html, wait_until="domcontentloaded")
        page.wait_for_timeout(200)
        assert page.evaluate("document.getElementById('ftable').classList.contains('shots')") is False
        assert page.evaluate("getComputedStyle(document.querySelector('td.shotcol')).display") == "none"
        assert page.evaluate("document.querySelectorAll('img.bigshot[src]').length") == 0  # nothing is downloaded while the view is off
        page.check("#t-shots")
        assert page.evaluate("getComputedStyle(document.querySelector('td.shotcol')).display") != "none"
        assert page.evaluate("document.querySelectorAll('img.bigshot[src]').length") + page.evaluate("document.querySelectorAll('.noshot').length") == len(rows)
        assert page.evaluate("document.getElementById('bulkform').hidden") is True
        page.check("#selall")
        assert page.evaluate("document.getElementById('bulkform').hidden") is False and page.inner_text("#bulkn") == f"{len(rows)} selected"
        page.click("#bulkclear")
        assert page.evaluate("document.getElementById('bulkform').hidden") is True
        b.close()
    assert errors == [], errors
