"""Stage 2 of the UX upgrade: the first run. The add-brand form asks for four things and folds the rest, the countries follow
the main domain, the AI's word for the business is kept, "start without setting up" is remembered, the scan card says
which parts can really run, Settings has a start-here checklist and the zeros explained, the login says what went
wrong, an admin can set a new password, and a domain the infrastructure map added says which map found it."""

from __future__ import annotations

import uuid

import sqlalchemy as sa
from fastapi.testclient import TestClient
from tests.test_demo_story import _api, _app, _ui

from brandwatch.db.models import Brand
from brandwatch.detection import markets


def _name() -> str:
    return f"First {uuid.uuid4().hex[:5]}"


def test_markets_follow_a_country_code_domain_and_a_generic_one_says_nothing():
    assert markets.for_domain("shopnova.co.il") == [{"country": "il", "langs": ["he", "en"]}]
    assert markets.for_domain("www.shop.de") == [{"country": "de", "langs": ["de", "en"]}]
    assert markets.for_domain("shop.co.uk") == [{"country": "gb", "langs": ["en"]}]
    assert markets.for_domain("shop.com") == [] and markets.for_domain("app.io") == [] and markets.for_domain("x.co") == []
    assert markets.tld_markets()["il"] == [{"country": "il", "langs": ["he", "en"]}]


def test_the_add_form_shows_four_things_and_folds_the_rest(engine, tmp_path):
    app = _app(engine, tmp_path)
    with TestClient(app):
        page = _ui(app).get("/ui/brands").text
    form = page.split('id="addform"')[1].split("</form>")[0]
    before_more = form.split('id="nb-more"')[0]
    assert 'name="entry"' in before_more and 'name="name"' in before_more and 'name="preset"' in before_more and 'name="kind"' in before_more
    assert 'name="vertical"' not in form  # the AI works out the business; nobody has to pick it
    more = form.split('id="nb-more"')[1]
    assert 'name="search_markets"' in more and 'name="social_accounts_max"' in more and 'id="nb-custom"' in more and 'name="ai_answers"' in more
    assert '"il": [{"country": "il"' in page.replace("&#34;", '"') or '"il":' in page  # the ccTLD map the form uses


def test_a_new_brand_on_a_country_domain_searches_its_country_and_is_not_custom(engine, tmp_path):
    app = _app(engine, tmp_path)
    with TestClient(app):
        c, ui = _api(app), _ui(app)
        name = _name()
        r = ui.post("/ui/brands", data={"name": name, "entry": ["shopnova-il.co.il"], "preset": "standard", "kind": "service", "markets_auto": "1",
                                        "search_markets": '[{"country": "us", "langs": ["en"]}]', "search_geo": "us", "search_lang": "en"},
                    follow_redirects=False)  # fmt: skip
        assert r.status_code == 303
        b = next(x for x in c.get("/api/brands").json() if x["name"] == name)
        got = c.get(f"/api/brands/{b['id']}").json()
        det = got["config"]["detection"]
        assert det["search_markets"] == [{"country": "il", "langs": ["he", "en"]}] and det["search_geo"] == "il" and det["search_lang"] == "he"
        assert got["config_custom"] is False  # where the customers are is the brand's, not a change of the track
        # a track change keeps the countries
        c.patch(f"/api/brands/{b['id']}/config", json={"preset": "basic"})
        assert c.get(f"/api/brands/{b['id']}").json()["config"]["detection"]["search_geo"] == "il"
        # the analyst picked the countries: they win over the domain
        name2 = _name()
        ui.post("/ui/brands", data={"name": name2, "entry": ["shop-two.co.il"], "preset": "standard", "kind": "service", "markets_auto": "0",
                                    "search_markets": '[{"country": "fr", "langs": ["fr"]}]'}, follow_redirects=False)  # fmt: skip
        b2 = next(x for x in c.get("/api/brands").json() if x["name"] == name2)
        assert c.get(f"/api/brands/{b2['id']}").json()["config"]["detection"]["search_geo"] == "fr"
        # a .com: the track's default
        b3 = c.post("/api/brands", json={"name": _name(), "domains": ["plain-shop.com"], "preset": "standard"}).json()
        assert c.get(f"/api/brands/{b3['id']}").json()["config"]["detection"]["search_geo"] == "us"


def test_the_ai_vertical_is_kept_on_the_brand(engine, tmp_path):
    app = _app(engine, tmp_path)
    with TestClient(app):
        c = _api(app)
        b = c.post("/api/brands", json={"name": _name(), "domains": ["shopnova.com"], "preset": "standard"}).json()
        out = c.post(f"/api/brands/{b['id']}/search-queries/suggest").json()
        if out.get("available") and out.get("vertical"):
            with engine.connect() as conn:
                assert conn.execute(sa.select(Brand.vertical).where(Brand.id == uuid.UUID(b["id"]))).scalar() == out["vertical"][:64]


def test_start_without_setting_up_is_remembered_and_the_full_form_shows(engine, tmp_path):
    app = _app(engine, tmp_path)
    with TestClient(app):
        c, ui = _api(app), _ui(app)
        b = c.post("/api/brands", json={"name": _name(), "domains": ["shopnova.com"], "preset": "enterprise"}).json()  # Deep: Google on, queries unapproved
        page = ui.get(f"/ui/brands/{b['id']}").text
        assert "Set up &amp; start the scan" in page and 'name="skip_setup"' in page
        r = ui.post(f"/ui/brands/{b['id']}/scan", data={"skip_setup": "1"}, follow_redirects=False)
        assert r.status_code == 303 and r.headers["location"].startswith("/ui/jobs/")
        app.state.queue.wait(uuid.UUID(r.headers["location"].rsplit("/", 1)[-1]), timeout=120)
        page = ui.get(f"/ui/brands/{b['id']}").text
        assert "Set up &amp; start the scan" not in page and 'name="max_candidates"' in page  # the normal Start scan
        assert "finish the set-up" in page  # still one click away


def test_the_set_up_page_says_what_it_approves_and_where_the_list_came_from(engine, tmp_path):
    app = _app(engine, tmp_path)
    with TestClient(app):
        c, ui = _api(app), _ui(app)
        b = c.post("/api/brands", json={"name": _name(), "domains": ["shopnova.com"], "preset": "enterprise"}).json()
        page = ui.get(f"/ui/brands/{b['id']}/setup").text
        assert "Approving saves the Google queries and the scan size" in page and "Approving saves ;" not in page
        assert "The list below:" in page and "nothing runs until you approve it" in page
        assert 'id="qai"' in page and 'id="qai" disabled' not in page  # demo mode: the AI answers


def test_the_scan_card_says_which_parts_can_run(engine, tmp_path):
    app = _app(engine, tmp_path)
    with TestClient(app):
        c, ui = _api(app), _ui(app)
        b = c.post("/api/brands", json={"name": _name(), "domains": ["shopnova.com"], "preset": "basic"}).json()
        page = ui.get(f"/ui/brands/{b['id']}").text
        assert "data-open-custom" in page  # "add the search stream" opens Customise parameters
        assert "home / mobile IP probe gated" in page and "markets US EN" in page  # demo: every part can run
    from brandwatch.api import ui as ui_mod

    class _S:  # live mode, nothing configured
        demo_mode = False

        def provider_key(self, _p):
            return None

    class _St:
        settings = _S()

    class _App:
        state = _St()

    class _Req:
        app = _App()

    from sqlalchemy.orm import Session

    from brandwatch.db.models import User

    with Session(engine) as s:
        u = s.scalars(sa.select(User).limit(1)).first()
        _S.economic_limits = app.state.settings.economic_limits
        ready = ui_mod.part_readiness(_Req(), s, u)
    assert ready["residential"] is False and ready["proxy"] is False


def test_settings_lists_the_start_here_steps_and_explains_the_zeros(engine, tmp_path):
    from brandwatch.api.ui_settings import start_here

    steps = start_here([{"provider": "virustotal", "configured": True}, {"provider": "urlscan", "configured": True},
                        {"provider": "safebrowsing", "configured": True}, {"provider": "scraperapi", "configured": True}],
                       {"max_daily_spend": 0})  # fmt: skip
    assert [s["ok"] for s in steps] == [True, False, True, False, False]  # free keys · cap · Google (any of two) · SearchApi · OpenAI
    app = _app(engine, tmp_path)
    with TestClient(app):
        page = _ui(app).get("/ui/settings").text
        assert "0 = no cap" in page and "0 = the home / mobile IP probe is off" in page
        assert 'id="key-virustotal"' in page and ">social media<" in page  # the "used by" tags
        assert 'name="password"' in page.split('id="team"')[1].split("</section>")[0]  # a new password for a user
        assert 'id="ws-token"' in page


def test_the_login_says_what_went_wrong_and_an_admin_resets_a_password(engine, tmp_path):
    app = _app(engine, tmp_path)
    with TestClient(app):
        c = _api(app)
        email = f"analyst-{uuid.uuid4().hex[:5]}@example.com"
        uid = c.post("/api/admin/users", json={"email": email, "password": "first-password-1", "role": "analyst"}).json()["id"]
        anon = TestClient(app)
        bad = anon.post("/ui/login", data={"email": email, "password": "nope-nope-nope"}, follow_redirects=False)
        assert "Wrong username or password" in bad.text and "An admin sets a new one in Settings → Team" in bad.text
        admin = _ui(app)
        r = admin.post(f"/ui/settings/users/{uid}", data={"role": "analyst", "is_active": "true", "password": "second-password-2"}, follow_redirects=False)
        assert r.status_code == 303
        assert anon.post("/ui/login", data={"email": email, "password": "second-password-2"}, follow_redirects=False).status_code == 303
        admin.post(f"/ui/settings/users/{uid}", data={"role": "analyst", "is_active": "false"}, follow_redirects=False)
        off = TestClient(app).post("/ui/login", data={"email": email, "password": "second-password-2"}, follow_redirects=False)
        assert "This account is disabled" in off.text  # told only to someone with the right password
        wrong = TestClient(app).post("/ui/login", data={"email": email, "password": "not-it-at-all"}, follow_redirects=False)
        assert "This account is disabled" not in wrong.text


def test_a_brand_never_scanned_is_named_on_the_dashboard(engine, tmp_path):
    app = _app(engine, tmp_path)
    with TestClient(app):
        c, ui = _api(app), _ui(app)
        name = _name()
        b = c.post("/api/brands", json={"name": name, "domains": ["never-scanned.example"], "preset": "basic"}).json()
        page = ui.get("/ui/dashboard").text
        panel = page.split('id="first-scan"')[1].split('id="action-required"')[0].split('id="hero"')[0][:4000]
        assert "Not scanned yet" in panel and (name in panel or "brands with no scan" in panel)
        assert f'href="/ui/brands/{b["id"]}#scan"' in page

