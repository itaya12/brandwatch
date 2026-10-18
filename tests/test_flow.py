"""Flow & navigation clean-up: nav order, smart landing, brand edit, watchlist "known legit",
takedowns list, console → attack-infrastructure link, and the brand-page error path."""

import uuid

from fastapi.testclient import TestClient

from brandwatch.api.main import create_app
from brandwatch.config.settings import Settings

ADMIN = {"email": "admin@test.local", "password": "test-admin-password"}


def _app(engine, tmp_path):
    settings = Settings(_env_file=None, demo_mode=True, evidence_dir=str(tmp_path / "ev"), bootstrap_admin_email=ADMIN["email"],
                        bootstrap_admin_password=ADMIN["password"], secret_key="unit-test-secret-0123456789abcdef")  # fmt: skip
    return create_app(settings=settings, engine=engine)


def _api(app):
    c = TestClient(app)
    token = c.post("/api/auth/login", json=ADMIN).json()["access_token"]
    c.headers["Authorization"] = f"Bearer {token}"
    return c


def _ui(app, next="/ui/dashboard"):
    ui = TestClient(app)
    ui.post("/ui/login", data={**ADMIN, "next": next}, follow_redirects=False)
    return ui


def test_nav_order_and_labels(engine, tmp_path):
    app = _app(engine, tmp_path)
    with TestClient(app):
        ui = _ui(app)
        page = ui.get("/ui/findings").text
        labels = ["Dashboard", "Brands &amp; Scans", "Findings", "Watchlist", "Attack infrastructure", "Takedowns", "Activity", "Settings"]  # fmt: skip
        positions = [page.index(f">{lbl}</a>") for lbl in labels]
        assert positions == sorted(positions), "nav must follow the analyst lifecycle"
        assert ">Campaigns</a>" not in page  # the attacker graph is no longer called a campaign
        assert "Phase 1" not in ui.get("/ui/logout", follow_redirects=True).text


def test_smart_landing_and_getting_started(engine, tmp_path):
    app = _app(engine, tmp_path)
    with TestClient(app) as c:
        ui = TestClient(app)
        # an empty workspace (fresh engine may already hold brands from other tests → create a fresh workspace user)
        import sqlalchemy as sa

        from brandwatch.db.models import Brand

        with app.state.session_factory() as s:
            ws_has_brand = s.scalar(sa.select(Brand.id).limit(1)) is not None
        r = ui.post("/ui/login", data=ADMIN, follow_redirects=False)
        assert r.status_code == 303
        if not ws_has_brand:
            assert r.headers["location"] == "/ui/brands"
            page = ui.get("/ui/brands").text
            assert "Getting started" in page and 'id="add"' in page
            assert ui.get("/ui", follow_redirects=False).headers["location"] == "/ui/brands"
        token = c.post("/api/auth/login", json=ADMIN).json()["access_token"]
        c.headers["Authorization"] = f"Bearer {token}"
        c.post(
            "/api/brands",
            json={"name": f"Land {uuid.uuid4().hex[:4]}", "domains": ["shopnova.com"]},
        )
        r = ui.post("/ui/login", data=ADMIN, follow_redirects=False)
        assert r.headers["location"] == "/ui/dashboard"
        assert ui.get("/ui", follow_redirects=False).headers["location"] == "/ui/dashboard"
        dash = ui.get("/ui/dashboard").text
        assert (
            'class="kpi lnk crit" href="/ui/findings?severity=critical' in dash
        )  # KPI tiles are links now


def test_brand_edit_name_domains_and_error_path(engine, tmp_path):
    app = _app(engine, tmp_path)
    with TestClient(app) as c:
        c = _api(app)
        b = c.post(
            "/api/brands", json={"name": "EditMe", "domains": ["shopnova.com", "www.shopnova.com"]}
        ).json()
        r = c.patch(
            f"/api/brands/{b['id']}",
            json={
                "name": "Edited Brand",
                "vertical": "crypto",
                "domains": ["shopnova.com", "shopnova.io"],
            },
        )
        assert r.status_code == 200
        out = r.json()
        assert (
            out["name"] == "Edited Brand"
            and out["vertical"] == "crypto"
            and out["domains_changed"] is True
        )
        assert sorted(out["domains"]) == ["shopnova.com", "shopnova.io"]  # www. removed, .io added
        assert c.patch(f"/api/brands/{b['id']}", json={"domains": []}).status_code == 422
        assert (
            c.patch(f"/api/brands/{b['id']}", json={"domains": ["not a domain!!"]}).status_code
            == 422
        )
        # UI: edit form present, save redirects with the rebuild-baseline hint, config error path renders (no 500)
        ui = _ui(app)
        page = ui.get(f"/ui/brands/{b['id']}").text
        assert 'id="edit"' in page and "Save brand" in page and 'id="whitelist"' in page
        # tabs: Overview · Scan setup (the track) · Social, ads & AI · Brand & site (edit, whitelist, start over)
        assert page.index('data-pane="setup"') < page.index('id="config"') < page.index('data-pane="brand" role="tabpanel"')
        assert page.index('data-pane="brand" role="tabpanel"') < page.index('id="edit"') < page.index('id="whitelist"') < page.index("Start over")
        assert "Detection track &amp; search rules" in page and "edit search rules" in page
        r = ui.post(f"/ui/brands/{b['id']}/edit", data={"name": "Edited Brand", "domains": "shopnova.com, shopnova.io, shopnova.net", "vertical": "crypto"}, follow_redirects=False)  # fmt: skip
        assert r.status_code == 303 and "edited=domains" in r.headers["location"]
        assert "Official domains changed" in ui.get(r.headers["location"]).text
        r = ui.post(
            f"/ui/brands/{b['id']}/edit",
            data={"name": "Edited Brand", "domains": "", "vertical": ""},
            follow_redirects=False,
        )
        assert (
            r.status_code == 200 and "official domain" in r.text
        )  # error rendered on the page, not a 500


def test_watchlist_known_legit_whitelists_and_dismisses(engine, tmp_path):
    app = _app(engine, tmp_path)
    with TestClient(app) as c:
        c = _api(app)
        brand = c.post(
            "/api/brands", json={"name": f"WL {uuid.uuid4().hex[:4]}", "domains": ["shopnova.com"]}
        ).json()
        job = c.post(f"/api/brands/{brand['id']}/scan-urls", json={"urls": ["https://shopn0va.com/", "https://shopnova-partners.com/"]}).json()["job_id"]  # fmt: skip
        app.state.queue.wait(uuid.UUID(job), timeout=180)
        rows = c.get("/api/candidates", params={"brand_id": brand["id"]}).json()
        by_host = {r["hostname"]: r for r in rows}
        assert "shopnova-partners.com" in by_host
        legit = by_host["shopnova-partners.com"]
        # a sibling host under the same registrable domain, still on the watchlist
        from brandwatch.db.enums import Surface
        from brandwatch.db.models import Candidate

        with app.state.session_factory() as s:
            s.add(Candidate(brand_id=uuid.UUID(brand["id"]), canonical_domain="cdn.shopnova-partners.com",
                            canonical_url="https://cdn.shopnova-partners.com/", hostname="cdn.shopnova-partners.com",
                            surface=Surface.NAME))  # fmt: skip
            s.commit()
        phish = by_host["shopn0va.com"]
        assert phish["finding"] and phish["finding"]["state"] == "open"  # rows carry their finding
        r = c.post(
            f"/api/candidates/{legit['id']}/dismiss",
            json={"reason": "known legit", "whitelist": True},
        )
        assert r.status_code == 200
        out = r.json()
        assert out["whitelisted"] == "shopnova-partners.com"
        assert set(out["dismissed"]) == {"shopnova-partners.com", "cdn.shopnova-partners.com"}
        rows = {
            r["hostname"]: r["state"]
            for r in c.get("/api/candidates", params={"brand_id": brand["id"]}).json()
        }
        # whitelisted hosts leave the watchlist entirely (they are dismissed, never shown as suspects)
        assert "shopnova-partners.com" not in rows and "cdn.shopnova-partners.com" not in rows
        assert c.get(f"/api/candidates/{legit['id']}").json()["candidate"]["state"] == "dismissed"
        assert rows["shopn0va.com"] != "dismissed"
        wl = c.get(f"/api/brands/{brand['id']}").json()["whitelist"]
        assert any(
            w["domain"] == "shopnova-partners.com" and w["kind"] == "known_legit" for w in wl
        )
        # UI: actions in the table (the phishing row is still open), finding link on the row
        ui = _ui(app)
        page = ui.get(f"/ui/candidates?brand_id={brand['id']}").text
        assert "Known legit" in page and "Rescan" in page and "/ui/findings/" in page
        assert "analyzing" not in page.split("Lifecycle funnel")[0]
        # dismissing the phishing candidate closes its open finding too
        r = c.post(
            f"/api/candidates/{phish['id']}/dismiss",
            json={"reason": "ours after all", "whitelist": False},
        )
        assert r.json()["findings_closed"] == 1 and r.json()["whitelisted"] is None
        assert (
            c.get(f"/api/findings/{phish['finding']['id']}").json()["finding"]["state"]
            == "dismissed"
        )
        # UI: dismiss form redirects back with filters
        ui = _ui(app)
        r = ui.post(f"/ui/candidates/{phish['id']}/dismiss", data={"reason": "x", "whitelist": "on", "next": f"/ui/candidates?brand_id={brand['id']}"}, follow_redirects=False)  # fmt: skip
        assert r.status_code == 303 and r.headers["location"].endswith(f"brand_id={brand['id']}")
        empty = ui.get("/ui/candidates?state=new&brand_id=" + str(uuid.uuid4())).text
        assert "No domains match" in empty


def test_console_links_to_the_infrastructure_map_and_takedowns_list(engine, tmp_path):
    app = _app(engine, tmp_path)
    with TestClient(app) as c:
        c = _api(app)
        brand = c.post(
            "/api/brands", json={"name": f"Map {uuid.uuid4().hex[:4]}", "domains": ["shopnova.com"]}
        ).json()
        job = c.post(
            f"/api/brands/{brand['id']}/scan-urls", json={"urls": ["https://shopn0va.com/"]}
        ).json()["job_id"]
        app.state.queue.wait(uuid.UUID(job), timeout=120)
        f = c.get("/api/findings", params={"brand_id": brand["id"]}).json()[0]
        assert f["candidate_id"]
        c.post(f"/api/findings/{f['id']}/confirm", json={"reason": "clone"})
        inv = c.post(f"/api/findings/{f['id']}/investigate").json()["job_id"]
        app.state.queue.wait(uuid.UUID(inv), timeout=120)
        j = c.get(f"/api/jobs/{inv}").json()
        assert j["campaign_id"] and j["finding_id"] == f["id"]
        assert c.get(f"/api/findings/{f['id']}").json()["campaign_id"] == j["campaign_id"]
        ui = _ui(app)
        console = ui.get(f"/ui/jobs/{inv}").text
        assert (
            f"/ui/campaigns/{j['campaign_id']}" in console
            and "Open attack infrastructure map" in console
        )
        assert 'id="st-investigation"' in console and 'id="st-dnstwist"' not in console
        fpage = ui.get(f"/ui/findings/{f['id']}").text
        assert (
            f"/ui/campaigns/{j['campaign_id']}" in fpage
            and "What do I do" in fpage
            and f"/ui/candidates/{f['candidate_id']}" in fpage
        )
        assert "(Phase 2)" not in fpage
        cpage = ui.get(f"/ui/campaigns/{j['campaign_id']}").text
        assert (
            f"/ui/brands/{brand['id']}" in cpage
            and f"/ui/jobs/{inv}" in cpage
            and "Delete this map" in cpage
        )
        assert "ATTACK INFRASTRUCTURE" in ui.get("/ui/campaigns").text
        # takedown → appears in the new list
        r = ui.post(f"/ui/findings/{f['id']}/takedown", follow_redirects=False)
        tid = r.headers["location"].rsplit("/", 1)[-1]
        lst = ui.get("/ui/takedowns").text
        assert "TAKEDOWNS" in lst and f"/ui/takedowns/{tid}" in lst and "shopn0va.com" in lst
        assert (
            f"/ui/takedowns/{tid}"
            in ui.get(f"/ui/takedowns?state=draft&brand_id={brand['id']}").text
        )
        assert f"/ui/takedowns/{tid}" not in ui.get("/ui/takedowns?state=resolved").text
        tpage = ui.get(f"/ui/takedowns/{tid}").text
        assert "Takedown request" in tpage and 'href="/ui/takedowns"' in tpage
        page = ui.get(f"/ui/findings/{f['id']}/intel").text  # redirects to the finding page
        assert "Map attack infrastructure" in page and "Site &amp; network investigation" in page
        assert 'data-tab="network"' in page and 'id="invbar"' in page


def test_every_session_dependency_commits_before_the_response(engine, tmp_path):
    """Regression: with the default "request" scope the commit ran after the response was sent."""
    from fastapi.routing import APIRoute

    from brandwatch.api.deps import get_session

    app = _app(engine, tmp_path)
    found = 0

    def walk(dep):
        nonlocal found
        if dep.call is get_session:
            found += 1
            assert dep.scope == "function", dep
        for sub in dep.dependencies:
            walk(sub)

    def routes(items):
        for r in items:
            inner = getattr(r, "original_router", None)  # include_router() wraps sub-routers
            if inner is not None:
                yield from routes(inner.routes)
            elif isinstance(r, APIRoute):
                yield r

    for route in routes(app.routes):
        walk(route.dependant)
    assert found > 100


def test_shared_hosting_whitelist_protects_only_that_site():
    """Whitelisting one site on a platform (github.io, pages.dev …) must not protect the platform."""
    from brandwatch.detection.normalize import protected_root, whitelist_for
    from brandwatch.detection.protect import is_protected

    assert protected_root("shopnova.github.io") == "shopnova.github.io"
    assert protected_root("blog.shopnova.com") == "shopnova.com"
    wl = whitelist_for(["shopnova.com", "shopnova.github.io"])
    assert is_protected("www.shopnova.com", wl) and is_protected("docs.shopnova.github.io", wl)
    assert not is_protected("shopnova-login.github.io", wl) and not is_protected("evil.github.io", wl)


def test_whitelisting_a_flagged_host_closes_its_open_finding_and_activity_links_jobs(engine, tmp_path):
    app = _app(engine, tmp_path)
    with TestClient(app):
        c = _api(app)
        b = c.post("/api/brands", json={"name": f"Wl {uuid.uuid4().hex[:4]}", "domains": ["shopnova.com"]}).json()
        job = c.post(f"/api/brands/{b['id']}/scan-urls", json={"urls": ["https://shopnova-login.com/"]}).json()["job_id"]
        app.state.queue.wait(uuid.UUID(job), timeout=180)
        rows = c.get("/api/findings", params={"brand_id": b["id"], "state": "open"}).json()
        assert [r["hostname"] for r in rows] == ["shopnova-login.com"]
        r = c.post(f"/api/brands/{b['id']}/whitelist", json={"domain": "shopnova-login.com", "kind": "partner"})
        assert r.status_code in (200, 201), r.text
        assert c.get("/api/findings", params={"brand_id": b["id"], "state": "open"}).json() == []
        # the audit row of the scan points at the job, so Activity links to its console
        act = _ui(app).get("/ui/activity").text
        assert f'href="/ui/jobs/{job}"' in act
        dash = _ui(app).get("/ui/dashboard").text
        assert dash.count('data-k="') == 6  # the 20 s refresh updates tiles by key, not position
