"""Every question the interface asks is its own dialog, never the browser's confirm() / prompt() box; and the watchlist and the takedowns filter by brand."""

from __future__ import annotations

import re
import uuid
from pathlib import Path

from fastapi.testclient import TestClient
from tests.test_demo_story import _api, _app, _ui

TEMPLATES = Path(__file__).resolve().parents[1] / "src" / "brandwatch" / "api" / "templates"


def test_no_page_uses_the_browsers_own_dialogs():
    native = re.compile(r"(?<![\w.])(confirm|alert|prompt)\(")
    hits = []
    for p in TEMPLATES.glob("*.html"):
        for i, line in enumerate(p.read_text(encoding="utf-8").splitlines(), 1):
            if native.search(line) and "bwConfirm" not in line and "bwAlert" not in line and "bwDialog" not in line and "/*" not in line:
                hits.append(f"{p.name}:{i}")
    assert hits == [], hits
    base = (TEMPLATES / "base.html").read_text(encoding="utf-8")
    assert 'id="bw-modal"' in base and "window.bwConfirm" in base and "data-confirm" in base


def _seed(c, app):
    brand = c.post("/api/brands", json={"name": f"Dlg {uuid.uuid4().hex[:4]}", "domains": ["shopnova.com"]}).json()
    c.patch(f"/api/brands/{brand['id']}/config", json={"detection": {"auto_map_on_confirm": False, "auto_investigate_on_confirm": False}})
    job = c.post(f"/api/brands/{brand['id']}/scan-urls", json={"urls": ["https://shopn0va.com/", "https://shopnowa.com/"]}).json()["job_id"]
    app.state.queue.wait(uuid.UUID(job), timeout=120)
    return brand


def test_the_takedowns_page_filters_by_brand_with_a_chip_per_brand(engine, tmp_path):
    app = _app(engine, tmp_path)
    with TestClient(app):
        c, ui = _api(app), _ui(app)
        brand = _seed(c, app)
        other = c.post("/api/brands", json={"name": f"Other {uuid.uuid4().hex[:4]}", "domains": ["othershop.example"]}).json()
        ids = [f["id"] for f in c.get("/api/findings", params={"brand_id": brand["id"], "state": "open"}).json()]
        assert c.post("/api/findings/bulk", json={"ids": ids, "action": "confirm"}).json()["changed"] == len(ids) > 0
        every = ui.get("/ui/takedowns").text
        assert "All brands <b>" in every and f"{brand['name']} <b>{len(ids)}</b>" in every and f"{other['name']} <b>0</b>" in every
        assert every.count('onchange="this.form.submit()"') == 2
        none = ui.get(f"/ui/takedowns?brand_id={other['id']}").text
        assert "shopn0va.com" not in none and "shopn0va.com" in every
        total = re.search(r"All brands <b>(\d+)</b>", every).group(1)
        assert int(total) >= len(ids) and f"All brands <b>{total}</b>" in none  # the chips keep counting every brand while one is picked


def test_the_bulk_verdict_and_the_brand_delete_ask_in_the_interfaces_own_dialog(engine, tmp_path):
    import pytest

    sync = pytest.importorskip("playwright.sync_api")
    app = _app(engine, tmp_path)
    with TestClient(app):
        c, ui = _api(app), _ui(app)
        brand = _seed(c, app)
        c.post("/api/brands", json={"name": f"Other {uuid.uuid4().hex[:4]}", "domains": ["othershop.example"]})  # the chips show from two brands on
        findings = ui.get(f"/ui/findings?brand_id={brand['id']}&state=open").text
        brand_page = ui.get(f"/ui/brands/{brand['id']}").text
        watch = ui.get("/ui/candidates").text
    assert "All brands" in watch and 'onchange="this.form.submit()"' in watch and brand["name"] in watch
    with sync.sync_playwright() as pw:
        try:
            b = pw.chromium.launch()
        except Exception as exc:  # noqa: BLE001
            pytest.skip(f"no sandboxed Chromium here: {exc}")
        page = b.new_page(viewport={"width": 1300, "height": 900})
        native: list[str] = []
        page.on("dialog", lambda d: (native.append(d.message), d.dismiss()))
        errors: list[str] = []
        page.on("pageerror", lambda e: errors.append(str(e)))
        page.set_content(findings, wait_until="domcontentloaded")
        page.evaluate("window.__sent = []; HTMLFormElement.prototype.requestSubmit = function(btn){ window.__sent.push(btn ? btn.value : null); }; null;")
        page.check(".sel >> nth=0")
        page.click("button[value=confirm]")
        assert page.evaluate("document.getElementById('bw-modal').hidden") is False
        assert "Confirm 1 finding(s) as phishing?" in page.inner_text(".bw-dlg-m") and page.inner_text("#bw-dlg-t") == "Confirm phishing"
        page.click(".bw-cancel")
        assert page.evaluate("document.getElementById('bw-modal').hidden") is True and page.evaluate("window.__sent") == []
        page.click("button[value=dismiss]")
        assert page.evaluate("document.querySelector('.bw-dlg').classList.contains('danger')") is True
        page.click(".bw-ok")
        assert page.evaluate("window.__sent") == ["dismiss"]  # the same button submits, after the answer
        page.keyboard.press("Escape")
        # the brand delete: the name must be typed in the dialog
        page.set_content(brand_page, wait_until="domcontentloaded")
        page.evaluate("window.__sent = []; HTMLFormElement.prototype.requestSubmit = function(btn){ window.__sent.push('delete'); }; null;")
        page.click('#btabs [data-pane="brand"]')  # "Start over" lives in the "Brand & site" tab
        page.click("form[action$='/delete'] button.danger")
        assert page.evaluate("document.getElementById('bw-modal').hidden") is False and page.is_visible(".bw-dlg-in")
        page.fill(".bw-dlg-in", "wrong name")
        page.click(".bw-ok")
        assert "That is not it" in page.inner_text(".bw-dlg-err") and page.evaluate("window.__sent") == []
        page.fill(".bw-dlg-in", brand["name"])
        page.click(".bw-ok")
        assert page.evaluate("window.__sent") == ["delete"]
        b.close()
    assert native == [], native  # not one browser box
    assert errors == [], errors
