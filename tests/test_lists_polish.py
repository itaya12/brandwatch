"""Where a finding came from at a glance (one tile per source: Google, ChatGPT, Facebook …), a watchlist that fits a laptop
screen (first / last / next / scans in one Seen column, the brand under the domain), and map tabs that read as buttons."""

from __future__ import annotations

from fastapi.testclient import TestClient
from tests.test_demo_story import _api, _app, _ui
from tests.test_findings_bulk import _brand
from tests.test_pages_js import BROKEN, chromium  # noqa: F401 (the shared browser)

from brandwatch.api import labels


def test_one_tile_per_kind_of_source():
    got = labels.source_badges(["serpapi", "serper", "ct", "crtsh", "ai_answer"])
    assert [b["g"] for b in got] == ["google", "cert", "ai"]  # four APIs are one source to a reader; at most three tiles
    assert got[0]["label"] == "Google" and got[0]["glyph"] == "G" and "Google search" in got[0]["title"]
    assert labels.source_badges([{"stream": "manual", "pattern": "pivot: shares cert"}])[0]["g"] == "pivot"
    assert labels.source_badges([{"stream": "manual", "pattern": None}])[0]["label"] == "Analyst scan"
    assert labels.source_badges([{"stream": "social"}, {"stream": "meta_ads"}], limit=5)[1]["g"] == "meta_ads"
    assert labels.source_badges([]) == []


def test_the_lists_show_where_each_site_was_found_and_the_watchlist_fits(engine, tmp_path):
    app = _app(engine, tmp_path)
    with TestClient(app):
        c, ui = _api(app), _ui(app)
        _brand(c, app)
        findings = ui.get("/ui/findings").text
        assert 'class="srcic s-' in findings and 'class="hrow"' in findings
        assert "· found by " not in findings  # the tiles and a short name replaced the sentence
        watch = ui.get("/ui/candidates").text
        head = watch.split('id="ctable"')[1].split("</thead>")[0]
        assert "<th>Seen</th>" in head and "First seen" not in head and "Last seen" not in head and "<th>Brand</th>" not in head
        assert 'class="seen ts-short"' in watch and "<span>scans</span>" in watch and 'class="srcic s-' in watch
        dash = ui.get("/ui/dashboard").text
        tabs = dash.split('class="geotabs"')[1].split("</div>")[0]
        assert tabs.count('class="ic"><svg') == 2 and "where the fakes are hosted" in tabs and 'id="infra-n"' in tabs
        base = ui.get("/ui/brands").text
        assert "fmtShort" in base  # a narrow date column leaves this year's year out


def test_the_four_map_views_become_cards_and_lists_on_a_phone(engine, tmp_path, chromium):  # noqa: F811
    """At 390 px Connections, Matrix, Flow and Timeline are cards and lists (no shrunken drawing, no sideways scroll); a
    long list shows its first cards and a Show all button. On a wide screen the drawings stay."""
    app = _app(engine, tmp_path)
    with TestClient(app):
        c, ui = _api(app), _ui(app)
        brand, rows = _brand(c, app)
        for h in ("shopn0va.com", "shopnova-login.com", "shopnova-refund.net"):
            if h in rows:
                c.post(f"/api/findings/{rows[h]['id']}/confirm", json={"reason": "cloned login"})
        html = ui.get("/ui/campaigns/all", params={"brand_id": brand["id"]}).text
    errors: list[str] = []
    for width, phone in ((390, True), (1280, False)):
        ctx = chromium.new_context(viewport={"width": width, "height": 844}, is_mobile=phone)
        page = ctx.new_page()
        page.on("pageerror", lambda e: errors.append(str(e)))
        page.set_content(html, wait_until="domcontentloaded")
        page.wait_for_timeout(300)
        for v in ("connections", "matrix", "flow", "timeline"):
            if not page.evaluate(f"!!document.querySelector('#vsw button[data-v={v}]')"):
                continue
            page.evaluate(f"document.querySelector('#vsw button[data-v={v}]').click()")
            page.wait_for_timeout(150)
            has_list = page.evaluate(f"!!document.querySelector('#view-{v} .mv') || !!document.querySelector('#view-{v} p.muted')")
            has_svg = page.evaluate(f"!!document.querySelector('#view-{v} .vbox svg')")
            assert (has_list and not has_svg) if phone else not page.evaluate(f"!!document.querySelector('#view-{v} .mv')"), (width, v)
            assert page.evaluate("document.documentElement.scrollWidth - innerWidth") <= 1, (width, v)
        ctx.close()
    assert [e for e in errors if BROKEN.search(e)] == []


def test_every_page_plays_its_charts_when_seen_and_keeps_them_alive(engine, tmp_path, chromium):  # noqa: F811
    app = _app(engine, tmp_path)
    with TestClient(app):
        c, ui = _api(app), _ui(app)
        _brand(c, app)
        html = ui.get("/ui/brands").text
    assert "BW_whenSeen" in html and "@keyframes bw-sweep" in html and ".bw-run" in html and "@keyframes bw-scan" in html
    ctx = chromium.new_context(viewport={"width": 1280, "height": 700})
    page = ctx.new_page()
    errors: list[str] = []
    page.on("pageerror", lambda e: errors.append(str(e)))
    page.set_content(html, wait_until="domcontentloaded")
    page.wait_for_timeout(600)
    # bars on screen have played and are lit; a line chart on screen has its travelling pulse
    seen = page.evaluate("[...document.querySelectorAll('[data-w]')].filter(e => { const r = e.getBoundingClientRect(); return r.top < innerHeight && r.bottom > 0 && e.getClientRects().length; })")
    assert page.evaluate("[...document.querySelectorAll('[data-w]')].filter(e => { const r = e.getBoundingClientRect(); return r.top < innerHeight && r.bottom > 0 && e.getClientRects().length && !e.classList.contains('lit'); }).length") == 0, seen
    assert page.evaluate("document.querySelectorAll('svg.spark[data-spark]').length") == page.evaluate("document.querySelectorAll('.bw-run').length")
    ctx.close()
    assert [e for e in errors if BROKEN.search(e)] == []


def test_the_review_fixes_hold_across_the_app(engine, tmp_path, chromium):  # noqa: F811
    """The UX review: titles alike, trails that start at the active section, "About this page", a section bar and a way back
    up on long pages, a search button on the phone bar, sliding number tiles, a verdict bar on a phone, the How it works
    label style kept off the sidebar, and one call to action on a brand page."""
    app = _app(engine, tmp_path)
    with TestClient(app):
        c, ui = _api(app), _ui(app)
        brand, rows = _brand(c, app)
        fid = rows["shopnova-login.com"]["id"]
        settings = ui.get("/ui/settings").text
        assert "<h1>SETTINGS " in settings
        finding = ui.get(f"/ui/findings/{fid}").text
        trail = finding.split('aria-label="Breadcrumb"')[1].split("</nav>")[0]
        assert trail.index('href="/ui/findings"') < trail.index(brand["name"])  # Findings first, as the sidebar shows
        assert finding.index('id="tab-ai"') < finding.index('id="notes"') if 'id="tab-ai"' in finding else finding.index('id="tab-timeline"') < finding.index('id="notes"')
        assert 'id="vbar"' in finding
        how = ui.get("/ui/how-it-works").text
        assert "main .lbl{" in how and "\n  .lbl{font" not in how
        brand_page = ui.get(f"/ui/brands/{brand['id']}").text
        assert "main form button.primary:not([name=action])" in brand_page
        watch = ui.get("/ui/candidates").text
    assert 'class="tsearch"' in watch
    errors: list[str] = []
    ctx = chromium.new_context(viewport={"width": 390, "height": 844}, is_mobile=True)
    page = ctx.new_page()
    page.on("pageerror", lambda e: errors.append(str(e)))
    page.set_content(watch, wait_until="domcontentloaded")
    page.wait_for_timeout(300)
    assert page.evaluate("getComputedStyle(document.querySelector('main .kpis')).display") == "flex"  # one sliding row
    assert page.evaluate("!!document.querySelector('details.about .intro')")  # the explanation folds under About this page
    assert page.evaluate("!!document.getElementById('totop')")
    assert page.evaluate("getComputedStyle(document.querySelector('header.topbar .tsearch')).display") != "none"
    # the subtitle's leading dot is its own span, hidden when the subtitle sits under the title
    assert page.evaluate("getComputedStyle(document.querySelector('main h1 .hsep')).display") == "none"
    ctx.close()
    assert [e for e in errors if BROKEN.search(e)] == []


def test_the_infrastructure_settings_and_add_brand_sections_are_short_and_clear(engine, tmp_path):
    app = _app(engine, tmp_path)
    with TestClient(app):
        c, ui = _api(app), _ui(app)
        _brand(c, app)
        camp = ui.get("/ui/campaigns").text
        assert 'id="maps"' in camp and 'class="mtiles"' in camp and 'class="ccard"' not in camp
        settings = ui.get("/ui/settings").text
        keys = settings.split('id="keys"')[1].split("</section>")[0]
        assert 'class="kchips"' in keys and '<details class="kr" id="key-virustotal"' in keys and "Add key" in keys
        assert "Each key gets its own random 32-byte data key" not in keys  # the long security text is a "?" tip now
        brands = ui.get("/ui/brands").text
        add = brands.split('id="add"')[1]
        assert add.count('class="stp"') == 3 and 'id="as-name"' in add and 'id="nb-go"' in add
