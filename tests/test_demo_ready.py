"""Demo readiness (tier 1): one finding per site, filters that accept "all", UI errors as pages,
the brand's own sites never suspects, and a finished-scan console that renders its result first."""

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
    c.headers["Authorization"] = (
        "Bearer " + c.post("/api/auth/login", json=ADMIN).json()["access_token"]
    )
    return c


def _ui(app):
    ui = TestClient(app)
    ui.post("/ui/login", data={**ADMIN, "next": "/ui/findings"}, follow_redirects=False)
    return ui


def _scan(app, c, bid, urls):
    j = c.post(f"/api/brands/{bid}/scan-urls", json={"urls": urls}).json()["job_id"]
    app.state.queue.wait(uuid.UUID(j), timeout=180)
    return j


def test_rescan_of_confirmed_site_appends_score_instead_of_reopening(engine, tmp_path):
    app = _app(engine, tmp_path)
    with TestClient(app):
        c = _api(app)
        b = c.post(
            "/api/brands", json={"name": f"One {uuid.uuid4().hex[:4]}", "domains": ["shopnova.com"]}
        ).json()
        cfg = c.get(f"/api/brands/{b['id']}").json()["config"]["detection"]
        c.patch(
            f"/api/brands/{b['id']}/config",
            json={"detection": {**cfg, "auto_map_on_confirm": False}},
        )
        _scan(app, c, b["id"], ["https://shopn0va.com/"])
        f = c.get("/api/findings", params={"brand_id": b["id"]}).json()[0]
        c.post(f"/api/findings/{f['id']}/confirm", json={"reason": "clone"})
        j = _scan(app, c, b["id"], ["https://shopn0va.com/"])  # the site is seen again
        rows = [
            r
            for st in ("open", "confirmed")
            for r in c.get(
                "/api/findings", params={"brand_id": b["id"], "state": st, "limit": 50}
            ).json()
        ]
        mine = [r for r in rows if r["hostname"] == "shopn0va.com"]
        assert len(mine) == 1 and mine[0]["state"] == "confirmed" and mine[0]["id"] == f["id"]
        assert len(c.get(f"/api/findings/{f['id']}").json()["score_history"]) >= 2
        ev = c.get(f"/api/jobs/{j}/events").json()["events"]
        assert any("confirmed earlier" in e["message"] for e in ev)
        assert (
            c.get("/api/dashboard", params={"brand_id": b["id"]}).json()["kpis"]["findings_open"]
            == 0
        )


def test_filters_accept_all_and_ui_errors_are_pages(engine, tmp_path):
    app = _app(engine, tmp_path)
    with TestClient(app):
        ui = _ui(app)
        for path in ("/ui/findings?brand_id=&state=&severity=", "/ui/findings?brand_id=not-a-uuid&state=bogus",
                     "/ui/candidates?brand_id=&state=", "/ui/campaigns?brand_id=", "/ui/takedowns?brand_id=&state=",
                     "/ui/dashboard?brand_id="):  # fmt: skip
            r = ui.get(path)
            assert r.status_code == 200 and r.headers["content-type"].startswith("text/html"), path
        r = ui.get(f"/ui/findings/{uuid.uuid4()}")
        assert (
            r.status_code == 404
            and "text/html" in r.headers["content-type"]
            and "Not found" in r.text
        )
        assert "ERROR 404" in r.text and 'href="/ui/findings"' in r.text  # nav + ways back
        r = ui.get("/ui/findings/not-a-uuid")
        assert r.status_code == 422 and "text/html" in r.headers["content-type"]
        api = _api(app)
        r = api.get(f"/api/findings/{uuid.uuid4()}")
        assert r.status_code == 404 and r.headers["content-type"].startswith(
            "application/json"
        )  # API contract kept


def test_official_and_whitelisted_sites_never_become_suspects(engine, tmp_path):
    app = _app(engine, tmp_path)
    with TestClient(app):
        c = _api(app)
        b = c.post(
            "/api/brands",
            json={
                "name": f"Own {uuid.uuid4().hex[:4]}",
                "domains": ["shopnova.com", "www.shopnova.com"],
            },
        ).json()
        _scan(
            app,
            c,
            b["id"],
            ["https://shopn0va.com/", "https://shopnova.com/", "https://www.shopnova.com/login"],
        )
        hosts = {
            r["hostname"] for r in c.get("/api/candidates", params={"brand_id": b["id"]}).json()
        }
        assert (
            "shopn0va.com" in hosts
            and "shopnova.com" not in hosts
            and "www.shopnova.com" not in hosts
        )
        f = next(
            x
            for x in c.get("/api/findings", params={"brand_id": b["id"]}).json()
            if x["hostname"] == "shopn0va.com"
        )
        c.post(f"/api/findings/{f['id']}/confirm", json={"reason": "clone"})
        r = c.post(f"/api/findings/{f['id']}/investigate")
        app.state.queue.wait(uuid.UUID(r.json()["job_id"]), timeout=180)
        hosts = {
            r["hostname"] for r in c.get("/api/candidates", params={"brand_id": b["id"]}).json()
        }
        assert not {"shopnova.com", "www.shopnova.com"} & hosts
        camp = c.get("/api/campaigns", params={"brand_id": b["id"]}).json()[0]
        nodes = {n["value"]: n for n in c.get(f"/api/campaigns/{camp['id']}").json()["nodes"]}
        for own in ("shopnova.com", "www.shopnova.com"):
            if own in nodes:
                assert nodes[own]["included"] is False and "official" in (
                    nodes[own]["triage_reason"] or ""
                )
        # whitelisting later takes an existing row off the watchlist at once
        c.post(
            f"/api/brands/{b['id']}/whitelist", json={"domain": "shopn0va.com", "kind": "partner"}
        )
        hosts = {
            r["hostname"] for r in c.get("/api/candidates", params={"brand_id": b["id"]}).json()
        }
        assert "shopn0va.com" not in hosts


def test_finished_scan_console_renders_result_first(engine, tmp_path):
    app = _app(engine, tmp_path)
    with TestClient(app):
        c = _api(app)
        b = c.post(
            "/api/brands", json={"name": f"Con {uuid.uuid4().hex[:4]}", "domains": ["shopnova.com"]}
        ).json()
        j = _scan(app, c, b["id"], ["https://shopn0va.com/", "https://shopnova-login.com/"])
        page = _ui(app).get(f"/ui/jobs/{j}").text
        assert 'id="report-steps"><li' in page  # the report is server-rendered at first paint
        assert 'id="k-findings">—<' not in page and 'id="now-hl"' in page and "skip to end" in page
        assert "stage timings" in page and "for engineers: every provider call" in page
        assert "const FINISHED_AT_LOAD = true" in page
