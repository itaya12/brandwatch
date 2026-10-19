"""Stage 4 of the UX upgrade: Hebrew brand names keep their own direction, no page scrolls sideways on a 390-pixel phone,
the wide tables become cards there, the verdict is a few Tab presses away, the dialog keeps the focus, and the
glossary explains every word the pages use."""

from __future__ import annotations

import re
import uuid

import pytest
from fastapi.testclient import TestClient
from tests.test_demo_story import _api, _app, _ui
from tests.test_findings_bulk import _brand
from tests.test_pages_js import BROKEN, chromium  # noqa: F401 (the shared browser)

HEBREW = "דואר ישראל"


def test_a_hebrew_brand_name_keeps_its_direction(engine, tmp_path):
    app = _app(engine, tmp_path)
    with TestClient(app):
        c, ui = _api(app), _ui(app)
        b = c.post("/api/brands", json={"name": f"{HEBREW} {uuid.uuid4().hex[:3]}", "domains": ["israelpost.co.il"], "preset": "basic"}).json()
        page = ui.get(f"/ui/brands/{b['id']}").text
        assert re.search(r'<h1><bdi dir="auto">' + HEBREW, page)
        assert f"<bdi>{b['name']}</bdi>" in page  # the breadcrumb
        assert "unicode-bidi:plaintext" in page  # paragraphs that may be Hebrew take their own direction
        listed = ui.get("/ui/brands").text
        assert f'<div class="name" dir="auto">{b["name"]}</div>' in listed
        assert c.get(f"/api/brands/{b['id']}").json()["config"]["detection"]["search_geo"] == "il"  # .co.il: searched in Israel


def test_no_page_scrolls_sideways_on_a_phone_and_the_tables_become_cards(engine, tmp_path, chromium):  # noqa: F811
    app = _app(engine, tmp_path)
    with TestClient(app):
        c, ui = _api(app), _ui(app)
        brand, rows = _brand(c, app)
        fid = rows["shopn0va.com"]["id"]
        c.post(f"/api/findings/{fid}/confirm", json={"reason": "x"})
        tid = c.post(f"/api/findings/{fid}/takedown").json()["id"]
        pages = {name: ui.get(path).text for name, path in {
            "dashboard": "/ui/dashboard", "findings": "/ui/findings", "finding": f"/ui/findings/{rows['shopnova-login.com']['id']}",
            "watchlist": "/ui/candidates", "takedowns": "/ui/takedowns", "takedown": f"/ui/takedowns/{tid}", "brands": "/ui/brands",
            "brand": f"/ui/brands/{brand['id']}", "settings": "/ui/settings", "activity": "/ui/activity", "scans": "/ui/scans",
            "search": "/ui/search?q=shop", "campaigns": "/ui/campaigns", "how": "/ui/how-it-works"}.items()}  # fmt: skip
        login = TestClient(app).get("/ui/login").text
    pages["login"] = login
    ctx = chromium.new_context(viewport={"width": 390, "height": 844}, is_mobile=True)
    wide: dict[str, int] = {}
    errors: list[str] = []
    for name, html in pages.items():
        page = ctx.new_page()
        page.on("pageerror", lambda e, n=name: errors.append(f"{n}: {e}"))
        page.set_content(html, wait_until="domcontentloaded")
        page.wait_for_timeout(250)
        over = page.evaluate("document.documentElement.scrollWidth - innerWidth")
        if over > 1:
            wide[name] = over
        if name in ("findings", "watchlist", "takedowns", "scans"):
            shown = page.evaluate("[...document.querySelectorAll('table.rwd')].map(t => getComputedStyle(t.querySelector('tr')).display)")
            labelled = page.evaluate("document.querySelectorAll('table.rwd td[data-label]').length")
            assert shown and all(d in ("block", "grid") for d in shown) and labelled > 0, name  # one card per row, each cell labelled
        page.close()
    ctx.close()
    assert wide == {}, f"pages wider than a 390 px phone: {wide}"
    assert [e for e in errors if BROKEN.search(e)] == []


def test_the_verdict_is_a_few_tab_presses_away(engine, tmp_path, chromium):  # noqa: F811
    app = _app(engine, tmp_path)
    with TestClient(app):
        c, ui = _api(app), _ui(app)
        brand, rows = _brand(c, app)
        html = ui.get(f"/ui/findings/{rows['shopnova-login.com']['id']}").text
    page = chromium.new_page(viewport={"width": 1440, "height": 900})
    page.set_content(html, wait_until="domcontentloaded")
    for key in ("Tab", "Tab"):  # Skip to content, Skip to the verdict
        page.keyboard.press(key)
    assert page.evaluate("document.activeElement.textContent") == "Skip to the verdict"
    page.keyboard.press("Enter")
    presses = 3
    for _ in range(12):
        page.keyboard.press("Tab")
        presses += 1
        if page.evaluate("document.activeElement.value") == "confirm":
            break
    assert page.evaluate("document.activeElement.value") == "confirm" and presses < 15, presses
    page.close()


def test_the_dialog_keeps_the_focus(engine, tmp_path, chromium):  # noqa: F811
    app = _app(engine, tmp_path)
    with TestClient(app):
        html = _ui(app).get("/ui/brands").text
    page = chromium.new_page()
    page.set_content(html, wait_until="domcontentloaded")
    page.evaluate("void window.bwConfirm('test?')")  # not awaited: it waits for an answer
    page.wait_for_timeout(50)
    seen = set()
    for _ in range(5):
        page.keyboard.press("Tab")
        seen.add(page.evaluate("document.activeElement.closest('#bw-modal') ? 'in' : 'out'"))
    assert seen == {"in"}
    page.close()


def test_the_glossary_has_the_words_the_pages_use():
    from brandwatch.api.labels import GLOSSARY, term

    keys = {g[0] for g in GLOSSARY}
    assert {"stream", "dnstwist", "ct", "nrd", "urlscan", "residential", "stix", "golden", "tld-set", "vertical", "kind", "tracks"} <= keys
    assert "help" in str(term("tracks"))


@pytest.mark.parametrize("path", ["/ui/findings", "/ui/candidates", "/ui/takedowns", "/ui/activity", "/ui/scans"])
def test_the_filters_are_labelled(engine, tmp_path, path):
    app = _app(engine, tmp_path)
    with TestClient(app):
        html = _ui(app).get(path).text
    form = html.split("<form method=\"get\"")[1].split("</form>")[0] if "<form method=\"get\"" in html else ""
    for sel_id in re.findall(r'<select id="([^"]+)"', form):
        assert f'for="{sel_id}"' in form, (path, sel_id)
