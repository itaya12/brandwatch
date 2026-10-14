"""Set the track's parameters yourself, from the moment the brand is created.

The add-brand form used to offer only the three tracks; streams, cadence, probes and thresholds could be
changed only on the brand page afterwards, where picking another track (or switching "Customise" off) threw the
edited values away without asking. Now the form has "Customise parameters" (the visible values are saved on top of
the track) and "start from the parameters of <a brand>", and the brand page asks before replacing custom values.
"""

from __future__ import annotations

import uuid

from fastapi.testclient import TestClient
from tests.test_demo_story import _api, _app, _ui

NAME = lambda: f"Params {uuid.uuid4().hex[:6]}"  # noqa: E731


def _create(c, **extra):
    return c.post("/api/brands", json={"name": NAME(), "domains": ["shopnova.com"], "preset": "basic", **extra})


def test_a_brand_can_be_created_with_its_own_parameters(engine, tmp_path):
    app = _app(engine, tmp_path)
    with TestClient(app):
        c = _api(app)
        r = _create(c, detection={"streams": ["dnstwist", "ct", "search"], "max_candidates": 777, "tlds": "all", "cloaking_probes": False},
                    scoring={"thresholds": {"medium": 20, "high": 45, "critical": 70}})  # fmt: skip
        assert r.status_code == 201, r.text
        got = c.get(f"/api/brands/{r.json()['id']}").json()
        det = got["config"]["detection"]
        assert got["config"]["preset"] == "basic" and got["config_custom"] is True
        assert det["max_candidates"] == 777 and det["tlds"] == "all" and det["cloaking_probes"] is False
        assert det["streams"] == ["dnstwist", "ct", "search"]
        assert got["config"]["scoring"]["thresholds"] == {"medium": 20, "high": 45, "critical": 70}
        plain = c.get(f"/api/brands/{_create(c).json()['id']}").json()  # without parameters: the pure track, as before
        assert plain["config_custom"] is False and plain["config"]["detection"]["max_candidates"] != 777


def test_bad_parameters_are_refused_and_no_half_brand_is_left(engine, tmp_path):
    app = _app(engine, tmp_path)
    with TestClient(app):
        c = _api(app)
        before = len(c.get("/api/brands").json())
        r = _create(c, scoring={"thresholds": {"medium": 80, "high": 40, "critical": 20}})  # must rise: medium < high < critical
        assert r.status_code in (400, 422), r.text
        assert len(c.get("/api/brands").json()) == before


def test_the_form_saves_the_visible_parameters_on_top_of_the_track(engine, tmp_path):
    app = _app(engine, tmp_path)
    with TestClient(app):
        c, ui = _api(app), _ui(app)
        name = NAME()
        data = {"name": name, "domains": "shopnova.com", "preset": "standard", "kind": "service", "mode": "custom",
                "streams": ["dnstwist", "ct", "nrd"], "tlds": "all", "max_candidates": "1234", "search_queries_max": "7",
                "search_geo": "il", "search_lang": "he", "watch_window_days": "60", "watch_cadence_hours": "8",
                "residential_probe": "off", "cloaking_probes": "on", "t_medium": "30", "t_high": "55", "t_critical": "80"}  # fmt: skip
        r = ui.post("/ui/brands", data=data, follow_redirects=False)
        assert r.status_code == 303, r.text[:300]
        brand = next(b for b in c.get("/api/brands").json() if b["name"] == name)
        got = c.get(f"/api/brands/{brand['id']}").json()
        det = got["config"]["detection"]
        assert got["config"]["preset"] == "standard" and got["config_custom"] is True
        assert (det["max_candidates"], det["search_geo"], det["search_lang"], det["residential_probe"]) == (1234, "il", "he", "off")
        assert det["streams"] == ["dnstwist", "ct", "nrd"] and det["watch_cadence_hours"] == 8 and det["social_accounts"] is False
        assert det["ai_second_opinion"] is False  # an unticked box is a decision, not "keep the default"
        assert got["config"]["scoring"]["thresholds"] == {"medium": 30, "high": 55, "critical": 80}


def test_the_form_without_customising_is_the_pure_track(engine, tmp_path):
    app = _app(engine, tmp_path)
    with TestClient(app):
        c, ui = _api(app), _ui(app)
        name = NAME()
        # the parameter fields are on the page but "Customise parameters" is off: they are not saved
        ui.post("/ui/brands", data={"name": name, "domains": "shopnova.com", "preset": "enterprise", "kind": "service",
                                    "mode": "preset", "max_candidates": "5", "streams": ["dnstwist"]}, follow_redirects=False)  # fmt: skip
        got = c.get(f"/api/brands/{next(b for b in c.get('/api/brands').json() if b['name'] == name)['id']}").json()
        assert got["config_custom"] is False and got["config"]["preset"] == "enterprise"
        assert got["config"]["detection"]["max_candidates"] != 5 and "search" in got["config"]["detection"]["streams"]


def test_a_bad_number_in_the_form_comes_back_as_a_message(engine, tmp_path):
    app = _app(engine, tmp_path)
    with TestClient(app):
        ui = _ui(app)
        r = ui.post("/ui/brands", data={"name": NAME(), "domains": "shopnova.com", "preset": "basic", "mode": "custom",
                                        "max_candidates": "lots", "streams": ["dnstwist"]}, follow_redirects=False)  # fmt: skip
        assert r.status_code == 200 and "invalid literal" in r.text  # the add-brand page again, with the error


def test_the_add_form_offers_the_parameters_and_the_other_brands_to_copy(engine, tmp_path):
    app = _app(engine, tmp_path)
    with TestClient(app):
        c, ui = _api(app), _ui(app)
        name = NAME()
        c.post("/api/brands", json={"name": name, "domains": ["copyme.com"], "preset": "standard"})
        page = ui.get("/ui/brands").text
        assert 'id="nb-custom"' in page and "Customise parameters" in page and 'name="mode"' in page
        assert f">{name}</option>" in page  # a brand to copy the parameters of
        assert 'name="streams"' in page and 'name="t_critical"' in page


def test_the_brand_page_asks_before_replacing_custom_values(engine, tmp_path):
    app = _app(engine, tmp_path)
    with TestClient(app):
        c, ui = _api(app), _ui(app)
        b = _create(c, detection={"max_candidates": 321}).json()
        page = ui.get(f"/ui/brands/{b['id']}").text
        assert "Replace your custom parameters with the" in page and "Switch off custom parameters?" in page


def test_an_async_handler_takes_the_write_lock_before_it_writes(engine):
    """Creating a brand while a scan is writing used to answer "Not possible right now" about 4 times in 10: the
    handler became async (to read the form), and get_session pre-locks only sync handlers."""
    import sqlite3

    import pytest

    from brandwatch.db.base import make_session_factory, take_write_lock

    path = engine.url.database
    if not path or str(path) == ":memory:":
        pytest.skip("needs a file database")
    with make_session_factory(engine)() as session:
        session.execute(__import__("sqlalchemy").text("select 1"))  # what the user lookup does: begins a read transaction
        take_write_lock(session)
        other = sqlite3.connect(path, timeout=0, isolation_level=None)  # a "scan" that wants to write now
        try:
            with pytest.raises(sqlite3.OperationalError, match="locked"):
                other.execute("BEGIN IMMEDIATE")
        finally:
            other.close()
        session.rollback()  # the lock is released with the transaction
        again = sqlite3.connect(path, timeout=0, isolation_level=None)
        try:
            again.execute("BEGIN IMMEDIATE")
            again.execute("ROLLBACK")
        finally:
            again.close()


# ------------------------------------------------------------------------------------------ the size of the scan, from the start
def test_the_size_of_the_scan_is_set_when_the_brand_is_created(engine, tmp_path):
    app = _app(engine, tmp_path)
    with TestClient(app):
        c, ui = _api(app), _ui(app)
        name = NAME()
        r = ui.post("/ui/brands", data={"name": name, "domains": "shopnova.com", "preset": "standard", "kind": "service", "mode": "custom",
                                        "streams": ["dnstwist", "ct"], "max_candidates": "77", "max_names_checked": "4321"}, follow_redirects=False)
        assert r.status_code == 303
        b = next(x for x in c.get("/api/brands").json() if x["name"] == name)
        det = c.get(f"/api/brands/{b['id']}").json()["config"]["detection"]
        assert det["max_candidates"] == 77 and det["max_names_checked"] == 4321
        # the API takes the same two numbers, and refuses nonsense
        ok = _create(c, detection={"max_candidates": 10, "max_names_checked": 55})
        assert ok.status_code == 201 and c.get(f"/api/brands/{ok.json()['id']}").json()["config"]["detection"]["max_names_checked"] == 55
        assert _create(c, detection={"max_names_checked": 10_000_000}).status_code in (400, 422)


def test_the_form_offers_both_numbers_and_the_brand_page_too(engine, tmp_path):
    app = _app(engine, tmp_path)
    with TestClient(app):
        c, ui = _api(app), _ui(app)
        page = ui.get("/ui/brands").text
        assert 'name="max_candidates"' in page and 'name="max_names_checked"' in page and "Max sites to visit per scan" in page and "Max look-alike names to check" in page
        b = _create(c, detection={"max_candidates": 321}).json()
        brand_page = ui.get(f"/ui/brands/{b['id']}").text
        assert 'name="max_names_checked"' in brand_page and "look-alike names" in brand_page  # the custom block and the track cards
        saved = ui.post(f"/ui/brands/{b['id']}/config", data={"mode": "custom", "preset": "basic", "streams": ["dnstwist"], "max_candidates": "40", "max_names_checked": "2500"}, follow_redirects=False)
        assert saved.status_code == 303
        assert c.get(f"/api/brands/{b['id']}").json()["config"]["detection"]["max_names_checked"] == 2500


def test_the_setup_page_sets_the_size_of_the_first_scan(engine, tmp_path):
    app = _app(engine, tmp_path)
    with TestClient(app):
        c, ui = _api(app), _ui(app)
        name = NAME()
        r = ui.post("/ui/brands", data={"name": name, "domains": "shopnova.com", "preset": "enterprise", "kind": "service"}, follow_redirects=False)
        setup = r.headers["location"]
        assert setup.endswith("/setup")
        bid = setup.split("/")[3]
        page = ui.get(setup).text
        assert "How big should the scan be?" in page and 'name="max_candidates"' in page and 'name="max_names_checked"' in page
        assert 'value="20000"' in page  # the Deep track's default for look-alike names, prefilled
        before = c.get(f"/api/brands/{bid}").json()["config"]["detection"]
        done = ui.post(f"/ui/brands/{bid}/setup", follow_redirects=False,
                       data={"action": "save", "q": ["shopnova login"], "max_candidates": "120", "max_names_checked": "8000"})
        assert done.status_code == 303
        det = c.get(f"/api/brands/{bid}").json()["config"]["detection"]
        assert det["max_candidates"] == 120 and det["max_names_checked"] == 8000
        assert det["streams"] == before["streams"] and det["tlds"] == before["tlds"]  # only the two numbers changed
        bad = ui.post(f"/ui/brands/{bid}/setup", data={"action": "save", "q": ["shopnova login"], "max_names_checked": "9999999"})
        assert bad.status_code == 200 and "Max look-alike names to check must be between 1 and 100,000" in bad.text  # a plain message
        assert c.get(f"/api/brands/{bid}").json()["config"]["detection"]["max_names_checked"] == 8000


def test_the_workspace_cap_on_sites_is_explained_and_linked(engine, tmp_path):
    app = _app(engine, tmp_path)
    with TestClient(app):
        c, ui = _api(app), _ui(app)
        c.patch("/api/admin/workspace", json={"economic_limits": {"max_candidate_count": 100}})
        try:
            b = _create(c, detection={"max_candidates": 800}).json()  # the brand asks for more than the workspace allows
            c.post(f"/api/brands/{b['id']}/baseline")
            page = ui.get(f"/ui/brands/{b['id']}").text
            assert "Only <b>100</b> will be visited: the workspace limit caps it." in page
            assert "no scan visits more than <b>100</b> sites" in page and 'href="/ui/settings#budget"' in page
            setup = ui.get(f"/ui/brands/{b['id']}/setup")
            assert setup.status_code in (200, 303)
            # the analyst's number is what the fields show, never the limit in its place, and the cut is said out loud
            assert 'id="maxc" name="max_candidates" type="number" min="1" max="5000" value="800"' in page
            assert "your 800 is saved, but this scan visits 100" in page
            if setup.status_code == 200:
                assert 'value="800" data-cap="100"' in setup.text and "The workspace limit cuts this to 100." in setup.text
                assert 'name="raise_cap"' in setup.text  # the admin raises it in one click
            # "Raise the limit to 900": the brand keeps 900 and the workspace limit follows it
            r = ui.post(f"/ui/brands/{b['id']}/setup", data={"raise_cap": "1", "max_candidates": "900", "max_names_checked": "3000"}, follow_redirects=False)
            assert r.status_code == 303 and r.headers["location"].endswith("/setup?cap=raised#s-size")
            assert c.get(f"/api/brands/{b['id']}").json()["config"]["detection"]["max_candidates"] == 900
            assert c.get("/api/admin/workspace").json()["economic_limits"]["max_candidate_count"] == 900
            assert "your 900 is saved" not in ui.get(f"/ui/brands/{b['id']}").text
        finally:
            c.patch("/api/admin/workspace", json={"economic_limits": {"max_candidate_count": 500}})  # the default again: the database is shared
