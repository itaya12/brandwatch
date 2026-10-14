"""Interview-demo layer (tiers 2-3): one vocabulary, self-explaining pages, How it works, facts
computed from the code, visible resilience, presenter-safe activity."""

import uuid

from fastapi.testclient import TestClient

from brandwatch.about import project_facts
from brandwatch.api import labels
from brandwatch.api.findings import explain_sentence, unicode_host
from brandwatch.api.main import create_app
from brandwatch.config.brand_config import SIGNAL_GROUPS
from brandwatch.config.settings import Settings

ADMIN = {"email": "admin@test.local", "password": "test-admin-password"}


def _app(engine, tmp_path):
    settings = Settings(_env_file=None, demo_mode=True, evidence_dir=str(tmp_path / "ev"), bootstrap_admin_email=ADMIN["email"],
                        bootstrap_admin_password=ADMIN["password"], secret_key="unit-test-secret-0123456789abcdef")  # fmt: skip
    return create_app(settings=settings, engine=engine)


def _api(app):
    c = TestClient(app)
    c.headers["Authorization"] = (
        "Bearer " + c.post("/api/auth/login", json=ADMIN).json()["access_token"]
    )
    return c


def _ui(app):
    ui = TestClient(app)
    ui.post("/ui/login", data={**ADMIN, "next": "/ui/findings"}, follow_redirects=False)
    return ui


def _nested_links(html: str) -> list:
    """<a> inside <a> is invalid: the browser closes the outer link early and the card falls apart."""
    from html.parser import HTMLParser

    class P(HTMLParser):
        depth, bad = 0, []

        def handle_starttag(self, tag, attrs):
            if tag == "a":
                if self.depth:
                    self.bad.append(dict(attrs).get("href"))
                self.depth += 1

        def handle_endtag(self, tag):
            if tag == "a" and self.depth:
                self.depth -= 1

    p = P()
    p.bad = []
    p.feed(html)
    return p.bad


def _brand_with_scan(app, c, urls=None):
    b = c.post(
        "/api/brands", json={"name": f"Story {uuid.uuid4().hex[:4]}", "domains": ["shopnova.com"]}
    ).json()
    if urls:
        j = c.post(f"/api/brands/{b['id']}/scan-urls", json={"urls": urls}).json()["job_id"]
    else:
        j = c.post(f"/api/brands/{b['id']}/scan", json={"max_candidates": 30}).json()["job_id"]
    app.state.queue.wait(uuid.UUID(j), timeout=180)
    return b, j


def test_vocabulary_covers_every_identifier():
    assert set(SIGNAL_GROUPS) <= set(labels.SIGNAL_LABELS)
    assert set(SIGNAL_GROUPS.values()) <= set(labels.GROUP_LABELS)
    assert (
        labels.state_label("long_watch") == "long watch"
        and labels.state_label("open") == "awaiting verdict"
    )
    assert (
        labels.stream_label("serpapi") == "Google search"
        and labels.stream_label("ct") == "Certificate logs"
    )
    tip = str(labels.term("cloaking"))
    assert (
        'data-href="/ui/how-it-works#g-cloaking"' in tip and "data-tip=" in tip and "<a" not in tip
    )
    assert (
        unicode_host("xn--shopnov-8fg.com") != "xn--shopnov-8fg.com"
        and unicode_host("plain.com") == "plain.com"
    )


def test_explain_sentence_reads_like_a_person():
    s = explain_sentence(
        {
            "brand_tld_swap": 20,
            "favicon_exact": 22,
            "screenshot_similarity_ge_90": 18,
            "credential_form": 14,
            "cloaking_ip_based": 25,
            "age_lt_7d": 10,
        },  # fmt: skip
        {"age_lt_7d": "domain registered 3 day(s) ago"},
        "ShopNova",
    )
    assert s.startswith("Registered 3 days ago.") and "another top-level domain" in s
    assert (
        "favicon and homepage" in s
        and "asks for a password" in s
        and "hides from security scanners" in s
    )
    assert explain_sentence({}, {}, "X").startswith("Only weak evidence")


def test_facts_are_computed_from_the_code():
    f = project_facts(max_age=0)
    assert f["signals"] == len(SIGNAL_GROUPS) and f["signal_groups"] == 7
    assert f["golden"]["total"] >= 40 and f["golden"]["phishing"] >= 10
    assert f["scoring_version"].startswith("v7-") and len(f["immutable_tables"]) >= 10
    assert f["tests"]["functions"] > 250 and f["limits"]["max_redirects"] >= 1


def test_how_it_works_settings_and_dashboard_tell_the_story(engine, tmp_path):
    app = _app(engine, tmp_path)
    with TestClient(app):
        c = _api(app)
        _brand_with_scan(app, c, ["https://shopnova-giftcard.com/", "https://shopn0va.com/"])
        ui = _ui(app)
        page = ui.get("/ui/how-it-works").text
        assert page.count('class="mi-btn"') == 13  # every card has a "More info" panel
        assert (
            "www.virustotal.com" in page
            and "api.shodan.io" in page
            and "detection/cloaking.py" in page
        )
        for needle in ("HOW IT WORKS", "Demo walkthrough", "About this project", 'id="ssrf"', 'id="evidence"', 'id="golden"',
                       'id="g-baseline"', "see it →", ">How it works<"):  # fmt: skip
            assert needle in page, needle
        settings = ui.get("/ui/settings").text
        assert (
            'id="limits"' in settings
            and "Fixed security limits" in settings
            and 'id="quality"' in settings
        )
        assert "curl in 30 seconds" in settings and "Argon2id" in settings
        dash = ui.get("/ui/dashboard").text
        for html in (dash, page, settings):
            assert _nested_links(html) == []
        assert (
            'id="how-strip"' in dash
            and 'id="under-the-hood"' in dash
            and "Nothing is sent automatically" in dash
        )
        login = TestClient(app).get("/ui/login").text
        assert "DEMO · admin / admin" in login and "a human decides every step" in login
        h = c.get("/health").json()
        assert h["facts"]["signals"] == len(SIGNAL_GROUPS) and h["facts"]["api_operations"] > 50
        assert (
            "UI calls the same service functions"
            in c.get("/openapi.json").json()["info"]["description"]
        )


def test_finding_page_explains_cloaked_kit_and_lists_are_human(engine, tmp_path):
    app = _app(engine, tmp_path)
    with TestClient(app):
        c = _api(app)
        b, job = _brand_with_scan(
            app, c, ["https://shopnova-giftcard.com/", "https://xn--shopnov-8fg.com/"]
        )
        rows = {
            r["hostname"]: r for r in c.get("/api/findings", params={"brand_id": b["id"]}).json()
        }
        kit = rows["shopnova-giftcard.com"]
        assert (
            kit["cloaked"] is True
            and kit["signal_items"][0]["points"] >= kit["signal_items"][-1]["points"]
        )
        assert (
            kit["signals"][0] == kit["signal_items"][0]["id"]
        )  # ordered by points, not alphabetically
        ui = _ui(app)
        page = ui.get(f"/ui/findings/{kit['id']}").text
        assert (
            'class="lead"' in page
            and "hides from security scanners" in page
            and "CLOAKED KIT" in page
        )
        assert "what a scanner sees" in page and "what a victim sees" in page
        assert (
            "Append-only by the database" in page and "open the arithmetic" in page and "⚙" in page
        )
        trace = c.get(f"/api/jobs/{job}/trace", params={"host": "shopnova-giftcard.com"}).text
        assert (
            "CANDIDATE · shopnova-giftcard.com" in trace
            and "CANDIDATE · xn--shopnov-8fg.com" not in trace
        )
        lst = ui.get(f"/ui/findings?brand_id={b['id']}").text
        assert (
            "hides from datacenter IPs" in lst
            and "homoglyph" in lst
            and "age_lt_7d</span>" not in lst
        )


def test_baseline_reused_card_and_rebuild_flag(engine, tmp_path):
    app = _app(engine, tmp_path)
    with TestClient(app):
        c = _api(app)
        b, _ = _brand_with_scan(app, c)  # first scan builds the baseline
        j = c.post(f"/api/brands/{b['id']}/scan", json={"max_candidates": 10}).json()["job_id"]
        app.state.queue.wait(uuid.UUID(j), timeout=180)
        ev = c.get(f"/api/jobs/{j}/events").json()["events"]
        assert any(e["stage"] == "baseline" and "reused" in e["message"] for e in ev)
        j = c.post(
            f"/api/brands/{b['id']}/scan", json={"max_candidates": 10, "rebuild_baseline": True}
        ).json()["job_id"]
        app.state.queue.wait(uuid.UUID(j), timeout=180)
        ev = c.get(f"/api/jobs/{j}/events").json()["events"]
        assert any(
            e["stage"] == "baseline"
            and e["message"].startswith("Baseline v")
            and "reused" not in e["message"]
            for e in ev
        )
        assert c.get(f"/api/brands/{b['id']}").json()["baseline"]["version"] >= 2


def test_flaky_demo_provider_shows_resilience_live(engine, tmp_path, monkeypatch):
    from brandwatch.providers.mock import _FLAKED

    monkeypatch.setenv("DEMO_FLAKY_PROVIDER", "virustotal")
    _FLAKED.discard("virustotal")
    app = _app(engine, tmp_path)
    with TestClient(app):
        c = _api(app)
        _, j = _brand_with_scan(app, c, ["https://shopn0va.com/", "https://shopnova-login.com/"])
        alerts = [
            e["data"]["alert"]
            for e in c.get(f"/api/jobs/{j}/events").json()["events"]
            if (e.get("data") or {}).get("alert")
        ]
        assert any(a["kind"] == "outage" and "virustotal" in a["provider"] for a in alerts), alerts
        assert (
            c.get(f"/api/jobs/{j}").json()["state"] == "done"
        )  # the scan carries on with the other feeds
        assert (
            c.get(
                "/api/findings", params={"brand_id": c.get("/api/brands").json()[-1]["id"]}
            ).status_code
            == 200
        )
        page = _ui(app).get(f"/ui/jobs/{j}").text
        assert "what would appear here" in page and "circuit breaker" in page
    _FLAKED.discard("virustotal")


def test_activity_is_presenter_safe_and_candidate_says_what_next(engine, tmp_path):
    app = _app(engine, tmp_path)
    with TestClient(app):
        for _ in range(3):
            TestClient(app).post("/ui/login", data=ADMIN, follow_redirects=False)
        c = _api(app)
        b, _ = _brand_with_scan(app, c, ["https://shopn0va.com/", "https://shopnova-partners.com/"])
        ui = _ui(app)
        act = ui.get("/ui/activity").text
        assert 'data-cat="notable"' in act and "×" in act  # repeated sign-ins collapse into one row
        assert (
            'id="more"' in act and 'class="day"' in act and "--cc:" not in act
        )  # paged, by day, no per-category colors
        cands = {
            r["hostname"]: r for r in c.get("/api/candidates", params={"brand_id": b["id"]}).json()
        }
        watched = ui.get(f"/ui/candidates/{cands['shopnova-partners.com']['id']}").text
        assert "below the finding threshold" in watched
        flagged = ui.get(f"/ui/candidates/{cands['shopn0va.com']['id']}").text
        assert "Next step:" in flagged and "give a verdict" in flagged


def test_deep_info_covers_every_card_and_points_at_real_code():
    from pathlib import Path

    import brandwatch
    from brandwatch.api.deep_info import DEEP

    root = Path(brandwatch.__file__).parent
    assert sorted(DEEP) == list(range(1, 14))
    for n, d in DEEP.items():
        assert d["title"] and d["chain"] and d["local"] and d["limits"] and d["demo_vs_live"], n
        for a in d["apis"]:
            assert {"name", "host", "call", "returns", "key", "cost"} <= set(a), (n, a)
        for m in d["modules"]:
            assert (root / m).is_file(), (n, m)


def test_settings_is_organised_by_section_and_explains_every_key(engine, tmp_path):
    app = _app(engine, tmp_path)
    with TestClient(app):
        ui = _ui(app)
        page = ui.get("/ui/settings").text
        for sec in (
            "keys",
            "lookups",
            "proxy",
            "budget",
            "team",
            "tokens",
            "system",
            "quality",
            "limits",
        ):
            assert f'id="{sec}"' in page and f'href="#{sec}"' in page, sec
        assert (
            "connector not built yet" not in page and "Google Safe Browsing" in page and "SecurityTrails" not in page and "recommended" in page and "No key needed" in page
        )
        assert _nested_links(page) == []
        r = ui.post(
            "/ui/settings/lookups",
            data={"dns_mode": "python", "whois_mode": "python"},
            follow_redirects=False,
        )
        assert r.status_code == 303 and r.headers["location"].endswith("?saved=lookups#lookups")
        assert "Lookup methods saved" in ui.get("/ui/settings?saved=lookups").text


def test_palette_is_calm():
    """Severity colors mean danger; everything else is one accent. No rainbow per category or group."""
    from pathlib import Path

    from brandwatch.api import ui_stats

    assert set(ui_stats.GROUP_COLORS.values()) == {ui_stats.ACCENT} and not ui_stats.CATEGORY_COLORS
    tdir = Path(ui_stats.__file__).parent / "templates"
    for name in (
        "findings.html",
        "activity.html",
        "settings.html",
        "_macros.html",
        "takedowns.html",
        "candidates.html",
    ):
        html = (tdir / name).read_text(encoding="utf-8")
        for c in ("#a78bfa", "#ff5fd2", "var(--violet)", "var(--magenta)"):
            assert c not in html, (name, c)
