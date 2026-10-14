"""The official domains, one per line - and app-store links kept as the brand's official apps.

Pasting the brand's website together with its App Store / Google Play / Chrome Web Store pages used to add
``apps.apple.com``, ``play.google.com`` and ``chromewebstore.google.com`` as official *domains*: the whole stores were
whitelisted, and every fake wallet app listed there would have been dismissed as the brand's own. Now a link into an
app store is an official app listing (the scan treats it like the listings linked from the official site), a bare
store host is refused, and the form has one input per line.
"""

from __future__ import annotations

import uuid

import pytest
from fastapi.testclient import TestClient
from tests.test_demo_story import _api, _app, _ui

APPLE = "https://apps.apple.com/us/app/metamask-trade-crypto/id1438144202"
CHROME = "https://chromewebstore.google.com/detail/metamask/nkbihfbeogaeaoehlefnkodbefgpgknn"
PLAY = "https://play.google.com/store/apps/details?id=io.metamask&hl=en"
NAME = lambda: f"MM {uuid.uuid4().hex[:6]}"  # noqa: E731


def _create(c, entries, **extra):
    return c.post("/api/brands", json={"name": NAME(), "domains": entries, "preset": "basic", **extra})


def test_store_links_become_official_apps_not_domains(engine, tmp_path):
    app = _app(engine, tmp_path)
    with TestClient(app):
        c = _api(app)
        r = _create(c, ["metamask.io", "www.metamask.io", APPLE, CHROME, PLAY])
        assert r.status_code == 201, r.text
        got = c.get(f"/api/brands/{r.json()['id']}").json()
        assert got["domains"] == ["metamask.io", "www.metamask.io"]  # the stores are NOT whitelisted
        apps = got["profile"]["official_apps"]
        assert apps == ["apps.apple.com/us/app/metamask-trade-crypto/id1438144202",
                        "chromewebstore.google.com/detail/metamask/nkbihfbeogaeaoehlefnkodbefgpgknn",
                        "play.google.com/store/apps/details?id=io.metamask"]  # canonical: no scheme, no tracking query
        # and no store host sits on the brand's protected list
        assert not {"apps.apple.com", "play.google.com", "chromewebstore.google.com"} & set(got["whitelist"] and [w["domain"] for w in got["whitelist"]])


def test_a_bare_store_host_or_only_apps_is_refused_with_a_reason(engine, tmp_path):
    app = _app(engine, tmp_path)
    with TestClient(app):
        c = _api(app)
        r = _create(c, ["metamask.io", "play.google.com"])
        assert r.status_code == 422 and "is an app store, not a domain of the brand" in r.json()["detail"]
        r = _create(c, [APPLE])
        assert r.status_code == 422 and "at least one official domain" in r.json()["detail"]
        assert _create(c, ["metamask.io", "not a domain"]).status_code == 422


def test_editing_replaces_the_whole_list_apps_included(engine, tmp_path):
    app = _app(engine, tmp_path)
    with TestClient(app):
        c = _api(app)
        b = _create(c, ["metamask.io", APPLE]).json()
        assert c.get(f"/api/brands/{b['id']}").json()["profile"]["official_apps"]
        r = c.patch(f"/api/brands/{b['id']}", json={"domains": ["metamask.io", CHROME]})
        assert r.status_code == 200
        got = c.get(f"/api/brands/{b['id']}").json()
        assert got["profile"]["official_apps"] == ["chromewebstore.google.com/detail/metamask/nkbihfbeogaeaoehlefnkodbefgpgknn"]
        c.patch(f"/api/brands/{b['id']}", json={"domains": ["metamask.io"]})  # the list is the whole truth: none left
        assert c.get(f"/api/brands/{b['id']}").json()["profile"]["official_apps"] == []
        assert c.patch(f"/api/brands/{b['id']}", json={"domains": [APPLE]}).status_code == 422  # a brand keeps a domain


def test_the_form_posts_one_entry_per_line_and_the_old_box_still_works(engine, tmp_path):
    app = _app(engine, tmp_path)
    with TestClient(app):
        c, ui = _api(app), _ui(app)
        name = NAME()
        r = ui.post("/ui/brands", data={"name": name, "entry": ["metamask.io", "", "metamask.app", APPLE, CHROME], "preset": "basic"}, follow_redirects=False)
        assert r.status_code == 303
        b = next(x for x in c.get("/api/brands").json() if x["name"] == name)
        got = c.get(f"/api/brands/{b['id']}").json()
        assert got["domains"] == ["metamask.app", "metamask.io"] or got["domains"] == ["metamask.io", "metamask.app"]
        assert len(got["profile"]["official_apps"]) == 2
        old = NAME()
        assert ui.post("/ui/brands", data={"name": old, "domains": "legacy.example, www.legacy.example", "preset": "basic"}, follow_redirects=False).status_code == 303
        assert next(x for x in c.get("/api/brands").json() if x["name"] == old)["domains"] == ["legacy.example", "www.legacy.example"]
        # the edit form too: rows in, rows out
        b2 = next(x for x in c.get("/api/brands").json() if x["name"] == old)
        r = ui.post(f"/ui/brands/{b2['id']}/edit", data={"name": old, "vertical": "", "entry": ["legacy.example", PLAY]}, follow_redirects=False)
        assert r.status_code == 303
        assert c.get(f"/api/brands/{b2['id']}").json()["profile"]["official_apps"] == ["play.google.com/store/apps/details?id=io.metamask"]


def test_a_refused_form_keeps_what_was_typed(engine, tmp_path):
    app = _app(engine, tmp_path)
    with TestClient(app):
        ui = _ui(app)
        name = NAME()
        r = ui.post("/ui/brands", data={"name": name, "entry": ["metamask.io", "play.google.com"], "preset": "basic"}, follow_redirects=False)
        assert r.status_code == 200 and "is an app store, not a domain of the brand" in r.text
        assert f'value="{name}"' in r.text and 'value="metamask.io"' in r.text and 'value="play.google.com"' in r.text  # nothing to retype


def test_the_brands_own_listing_is_not_flagged_but_a_fake_one_is(engine, tmp_path):
    """The point of naming the apps: the official listing is recognised by the scan, a look-alike listing is not."""
    from brandwatch.detection.analysis import _is_official_app

    official = ("play.google.com/store/apps/details?id=io.metamask",)
    assert _is_official_app("https://play.google.com/store/apps/details?id=io.metamask&hl=de&gl=US", official)  # tracking query ignored
    assert not _is_official_app("https://play.google.com/store/apps/details?id=io.metamask.wallet.free", official)
    assert not _is_official_app("https://apps.apple.com/us/app/metamask-trade-crypto/id999", official)


def test_the_baseline_carries_the_analysts_official_apps(session):
    from tests.conftest import make_brand, make_workspace

    import brandwatch.db.models as m
    from brandwatch.detection.baseline import load_baseline

    ws = make_workspace(session, f"apps-{uuid.uuid4().hex[:6]}")
    brand = make_brand(session, ws, "MetaMask")
    brand.profile = {"official_apps": ["play.google.com/store/apps/details?id=io.metamask"]}
    session.add(m.BrandFingerprint(brand_id=brand.id, version=1, features={"official_apps": ["apps.apple.com/us/app/x/id1"]}))
    session.flush()
    base = load_baseline(session, brand)
    assert base.official_apps == ("apps.apple.com/us/app/x/id1", "play.google.com/store/apps/details?id=io.metamask")  # the site's, then the analyst's


# ------------------------------------------------------------------------------------------ the component, in a real browser
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


def test_pasting_a_list_makes_one_row_per_line_and_marks_the_apps(engine, tmp_path, chromium):
    app = _app(engine, tmp_path)
    with TestClient(app):
        html = _ui(app).get("/ui/brands").text
    page = chromium.new_page()
    errors: list[str] = []
    page.on("pageerror", lambda e: errors.append(str(e)))
    page.set_content(html, wait_until="domcontentloaded")
    pasted = f"metamask.io, metamask.app\n{APPLE}\n{CHROME}\nhttps://play.google.com/"
    page.evaluate("""(text) => {
      const inp = document.querySelector('#add .drow input'); inp.focus();
      const dt = new DataTransfer(); dt.setData('text', text);
      inp.dispatchEvent(new ClipboardEvent('paste', {clipboardData: dt, bubbles: true, cancelable: true}));
    }""", pasted)
    rows = page.locator("#add .drow")
    assert rows.count() == 5
    assert [t.strip() for t in page.locator("#add .drow .dk").all_text_contents()] == ["primary", "domain", "official app", "official app", "paste the app link"]
    assert [i.input_value() for i in page.locator("#add .drow input").all()][:2] == ["metamask.io", "metamask.app"]
    # Enter adds a line (and does not submit); the last line can be removed
    page.locator("#add .drow input").first.press("Enter")
    assert rows.count() == 6
    page.locator("#add .drow .ddel").last.click()
    assert rows.count() == 5
    page.locator("#add .dadd").click()
    assert rows.count() == 6
    assert errors == []
    page.close()
