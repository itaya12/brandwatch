"""The pages' inline scripts must at least parse and start.

A string-matching test cannot see a broken script: a ``confirm('… track's …')`` with an unescaped apostrophe made
the whole brand-page script (the Customise toggle, the track cards) silently dead while every HTML assertion
passed. These tests load the rendered pages into the sandboxed Chromium and fail on any script error.
"""

from __future__ import annotations

import re
import uuid

import pytest
from fastapi.testclient import TestClient
from tests.test_demo_story import _api, _app, _ui

# what a broken script looks like; a failed fetch to a server that is not there is not one
BROKEN = re.compile(r"SyntaxError|Unexpected|missing \)|Invalid or unexpected|is not defined|is not a function|Cannot read|Cannot set", re.I)


@pytest.fixture(scope="module")
def chromium():
    sync = pytest.importorskip("playwright.sync_api")
    pw = sync.sync_playwright().start()
    try:
        browser = pw.chromium.launch()
    except Exception as exc:  # noqa: BLE001
        pw.stop()
        pytest.skip(f"no sandboxed Chromium here: {exc}")
    yield browser
    browser.close()
    pw.stop()


def _script_errors(browser, html: str) -> list[str]:
    page = browser.new_page()
    errors: list[str] = []
    page.on("pageerror", lambda e: errors.append(str(e)))
    try:
        page.set_content(html, wait_until="domcontentloaded")
        page.wait_for_timeout(300)
    finally:
        page.close()
    return [e for e in errors if BROKEN.search(e)]


def test_the_brand_pages_scripts_run(engine, tmp_path, chromium):
    app = _app(engine, tmp_path)
    with TestClient(app):
        c, ui = _api(app), _ui(app)
        name = f"Js {uuid.uuid4().hex[:5]}"
        made = c.post("/api/brands", json={"name": name, "domains": ["ironvale.com"], "preset": "standard", "kind": "retail",
                                           "detection": {"max_candidates": 321}}).json()
        c.post(f"/api/brands/{made['id']}/baseline")  # blocked everywhere: the site-access panel has something to show
        c.put("/api/admin/api-keys/whoisxml", json={"key": "k" * 24})  # the Settings page gets Test buttons for stored keys
        pages = {
            "settings (keys with Test buttons)": ui.get("/ui/settings").text,
            "brands list + add form": ui.get("/ui/brands").text,
            "brand page (custom parameters, blocked site)": ui.get(f"/ui/brands/{made['id']}").text,
            "set-up page": ui.get(f"/ui/brands/{made['id']}/setup").text,
        }
        try:
            for label, html in pages.items():
                assert "<script" in html, label
                assert _script_errors(chromium, html) == [], f"script error on the {label}"
        finally:  # the database is shared with the other tests, some of which count the stored keys
            c.delete("/api/admin/api-keys/whoisxml")


def test_the_confirm_messages_of_the_brand_page_are_valid_javascript(engine, tmp_path, chromium):
    """The exact bug: the brand page with custom parameters must define its handlers (the track cards and the toggle)."""
    app = _app(engine, tmp_path)
    with TestClient(app):
        c, ui = _api(app), _ui(app)
        made = c.post("/api/brands", json={"name": f"Js {uuid.uuid4().hex[:5]}", "domains": ["shopnova.com"], "preset": "basic",
                                           "detection": {"max_candidates": 321}}).json()
        html = ui.get(f"/ui/brands/{made['id']}").text
        page = chromium.new_page()
        errors: list[str] = []
        page.on("pageerror", lambda e: errors.append(str(e)))
        native: list[str] = []
        page.on("dialog", lambda d: (native.append(d.message), d.dismiss()))  # the browser's own box must never show
        page.set_content(html, wait_until="domcontentloaded")
        page.wait_for_timeout(300)
        assert [e for e in errors if BROKEN.search(e)] == []

        def asked() -> str:  # the interface's own dialog: read the question, then Cancel to keep the analyst's values
            assert page.evaluate("document.getElementById('bw-modal').hidden") is False
            text = page.inner_text("#bw-dlg-t") + "\n" + page.inner_text(".bw-dlg-m")
            page.click(".bw-cancel")
            return text

        page.click('#btabs [data-pane="setup"]')  # the track lives in the "Scan setup" tab
        page.click("#customBtn")  # custom is on for this brand: switching it off must ask first
        first = asked()
        assert "Switch off custom parameters?" in first and "track's own profile" in first
        assert page.input_value("input[name=max_candidates]") == "321"  # Cancel kept the custom value
        page.click(".track-card.enterprise")
        second = asked()
        assert "Replace your custom parameters with the" in second and "track's values" in second
        assert page.input_value("input[name=max_candidates]") == "321"  # still the analyst's value
        assert native == []
        page.close()


def test_the_add_form_fills_the_scan_size_from_the_track(engine, tmp_path, chromium):
    app = _app(engine, tmp_path)
    with TestClient(app):
        html = _ui(app).get("/ui/brands").text
    page = chromium.new_page()
    errors: list[str] = []
    page.on("pageerror", lambda e: errors.append(str(e)))
    page.set_content(html, wait_until="domcontentloaded")
    page.click("#nb-btn")
    page.select_option("#add select[name=preset]", "enterprise")
    assert page.input_value("#add input[name=max_candidates]") == "1500" and page.input_value("#add input[name=max_names_checked]") == "20000"
    page.select_option("#add select[name=preset]", "basic")
    assert page.input_value("#add input[name=max_candidates]") == "150" and page.input_value("#add input[name=max_names_checked]") == "1000"
    assert [e for e in errors if BROKEN.search(e)] == []
    page.close()


def test_the_console_card_follows_a_running_intel_job(engine, tmp_path, chromium):
    # a site-intel job sends plain event lines, not "NOW" cards: the card said "Waiting for a worker …" for the whole
    # 5 minutes of the first live run, while the job was really waiting for VirusTotal's 4 requests a minute
    import json

    from brandwatch.db.base import make_session_factory
    from brandwatch.db.enums import JobState
    from brandwatch.db.models import Brand, ScanJob

    app = _app(engine, tmp_path)
    with TestClient(app):
        c, ui = _api(app), _ui(app)
        made = c.post("/api/brands", json={"name": f"Intel card {uuid.uuid4().hex[:5]}", "domains": ["ironvale.com"]}).json()
        with make_session_factory(engine)() as s:
            brand = s.get(Brand, uuid.UUID(made["id"]))
            job = ScanJob(workspace_id=brand.workspace_id, brand_id=brand.id, kind="intel", state=JobState.RUNNING, payload={})
            s.add(job)
            s.commit()
            job_id = str(job.id)
        html = ui.get(f"/ui/jobs/{job_id}").text
        assert "Waiting for a worker" in html  # what the page says until the first event arrives

    def ev(seq, step, message, status="running", stage="intel"):
        return {"seq": seq, "ts": "2026-10-13T06:51:43", "stage": stage, "step": step, "status": status, "level": "info",
                "message": message, "data": None, "progress": None, "counts": {}}

    events = [ev(1, "domain", "VirusTotal report for shop.example: detections …"),
              ev(2, "relations", "VirusTotal communicating files for shop.example …"),
              ev(3, "quota", "waiting 51s for VirusTotal quota (public API: 4 requests/min) …")]
    page = chromium.new_page()
    errors: list[str] = []
    page.on("pageerror", lambda e: errors.append(str(e)))
    base = "http://console.test"
    page.route(f"{base}/ui/jobs/{job_id}", lambda r: r.fulfill(status=200, content_type="text/html", body=html))
    page.route(f"{base}/api/jobs/{job_id}/events/stream**", lambda r: r.abort())  # the page falls back to polling
    page.route(f"{base}/api/jobs/{job_id}/events?**", lambda r: r.fulfill(
        status=200, content_type="application/json", body=json.dumps({"events": events, "state": "running"})))
    try:
        page.goto(f"{base}/ui/jobs/{job_id}")
        page.wait_for_function("document.getElementById('now-title').textContent !== 'Waiting for a worker …'", timeout=8000)
        assert page.inner_text("#now-title") == "Waiting for the VirusTotal quota"
        detail = page.inner_text("#now-detail")
        assert "waiting 51s" in detail and "carries on by itself" in detail
        assert page.inner_text("#now-pos").startswith("3 / 3")  # the earlier lines are in the history behind the arrows
    finally:
        page.close()
    assert [e for e in errors if BROKEN.search(e)] == []
