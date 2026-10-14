"""Phase 1 API + analyst UI: brand → scan → live events → findings → Explain Finding → verdict."""

from __future__ import annotations

import uuid

import pytest
from fastapi.testclient import TestClient

from brandwatch.api.main import create_app
from brandwatch.config.settings import Settings

ADMIN = {"email": "admin@test.local", "password": "test-admin-password"}


@pytest.fixture
def app_client(engine, tmp_path):
    settings = Settings(
        _env_file=None,
        demo_mode=True,
        evidence_dir=str(tmp_path / "evidence"),
        bootstrap_admin_email=ADMIN["email"],
        bootstrap_admin_password=ADMIN["password"],
        secret_key="unit-test-secret-0123456789abcdef",
    )
    app = create_app(settings=settings, engine=engine)
    with TestClient(app) as c:
        token = c.post("/api/auth/login", json=ADMIN).json()["access_token"]
        c.headers["Authorization"] = f"Bearer {token}"
        yield c, app


def _wait(app, job_id: str) -> None:
    app.state.queue.wait(uuid.UUID(job_id), timeout=120)


def test_full_analyst_loop_over_the_api(app_client):
    c, app = app_client
    name = f"ShopNova {uuid.uuid4().hex[:6]}"

    # brand
    r = c.post(
        "/api/brands",
        json={
            "name": name,
            "domains": ["shopnova.com", "WWW.shopnova.com"],
            "vertical": "ecommerce",
        },
    )
    assert r.status_code == 201, r.text
    brand = r.json()
    assert (
        brand["domains"] == ["shopnova.com", "www.shopnova.com"]
        and brand["fingerprint_version"] == 0
    )
    assert any(b["id"] == brand["id"] for b in c.get("/api/brands").json())
    assert c.post("/api/brands", json={"name": "x", "domains": ["not a domain"]}).status_code == 422

    # scan analyst-supplied URLs (runs on the threaded queue; the API returns immediately)
    r = c.post(
        f"/api/brands/{brand['id']}/scan-urls",
        json={"urls": ["https://shopn0va.com/", "shopnova-partners.com", "nope-shopnova.com"]},
    )
    assert r.status_code == 202
    job_id = r.json()["job_id"]
    _wait(app, job_id)

    job = c.get(f"/api/jobs/{job_id}").json()
    assert job["state"] == "done", job["error"]
    assert [s["name"] for s in job["stages"]][:2] == ["baseline", "discovery"]
    feed = c.get(f"/api/jobs/{job_id}/events").json()
    assert (
        feed["state"] == "done"
        and feed["events"][0]["seq"] == 1
        and feed["events"][-1]["stage"] == "summary"
    )
    tail = c.get(f"/api/jobs/{job_id}/events", params={"from_seq": feed["last_seq"] - 1}).json()
    assert len(tail["events"]) == 1 and tail["events"][0]["seq"] == feed["last_seq"]
    assert c.get(f"/api/jobs?brand_id={brand['id']}").json()[0]["id"] == job_id

    # baseline exists now
    detail = c.get(f"/api/brands/{brand['id']}").json()
    assert detail["baseline"]["version"] == 1 and "shopnova" in detail["baseline"]["keywords"]
    assert (
        c.get(f"/api/brands/{brand['id']}/baseline/screenshot").headers["content-type"]
        == "image/png"
    )

    # findings table
    rows = c.get("/api/findings", params={"brand_id": brand["id"]}).json()
    assert [r["hostname"] for r in rows] == ["shopn0va.com"]
    row = rows[0]
    assert (
        row["severity"] == "critical" and row["thumbnail_url"] and "favicon_exact" in row["signals"]
    )

    # Explain Finding
    d = c.get(f"/api/findings/{row['id']}").json()
    assert d["finding"]["state"] == "open"
    names = {s["name"] for s in d["score"]["signals"]}
    assert {"favicon_exact", "credential_form", "lure_language"} <= names
    assert all(s["detail"] for s in d["score"]["signals"])
    assert d["score"]["rules_fired"] and d["score"]["confidence_breakdown"]["hard_confirmers"]
    assert d["screenshots"]["suspect_url"] and d["screenshots"]["baseline_url"]
    assert d["screenshots"]["similarity_pct"] >= 90
    roles = {e["type"]: e["role"] for e in d["evidence"]}
    assert roles["favicon"] == "primary" and roles["dns"] == "supporting"
    assert len(d["observations"]) == 1 and d["score_history"][-1]["is_current"]

    # artifacts are served (HTML never as text/html)
    html_ev = next(e for e in d["evidence"] if e["type"] == "html")
    a = c.get(html_ev["artifact_url"])
    assert a.status_code == 200 and a.headers["content-type"].startswith("text/plain")
    shot = c.get(d["screenshots"]["suspect_url"])
    assert shot.status_code == 200 and shot.content[:4] == b"\x89PNG"

    # watchlist shows the partner site, the dead one is dismissed
    cands = {
        x["hostname"]: x["state"]
        for x in c.get("/api/candidates", params={"brand_id": brand["id"]}).json()
    }
    assert (
        cands["shopnova-partners.com"] == "watching" and cands["nope-shopnova.com"] == "dismissed"
    )

    # analyst verdict (analyst-only transition, audited, final)
    r = c.post(f"/api/findings/{row['id']}/confirm", json={"reason": "cloned login"})
    assert r.status_code == 200 and r.json()["state"] == "confirmed"
    assert c.post(f"/api/findings/{row['id']}/dismiss", json={"reason": "x"}).status_code == 409
    assert c.get("/api/findings", params={"brand_id": brand["id"], "state": "open"}).json() == []


def test_brand_scan_with_cap_runs_discovery(app_client):
    c, app = app_client
    brand = c.post(
        "/api/brands", json={"name": f"Cap {uuid.uuid4().hex[:6]}", "domains": ["shopnova.com"]}
    ).json()
    r = c.post(f"/api/brands/{brand['id']}/scan", json={"max_candidates": 25})
    assert r.status_code == 202
    _wait(app, r.json()["job_id"])
    feed = c.get(f"/api/jobs/{r.json()['job_id']}/events").json()
    summary = feed["events"][-1]["data"]
    assert summary["hits"] == 25 and summary["errors"] == 0 and summary["cost_usd"] == 0.0


def test_other_workspace_cannot_see_findings(app_client, engine):
    """Workspace isolation: a finding id from another workspace is a 404, not a leak."""
    c, _ = app_client
    assert c.get(f"/api/findings/{uuid.uuid4()}").status_code == 404
    assert c.get(f"/api/brands/{uuid.uuid4()}").status_code == 404
    assert c.get(f"/api/jobs/{uuid.uuid4()}").status_code == 404


def test_ui_pages_render_with_cookie_session(app_client):
    c, app = app_client
    brand = c.post(
        "/api/brands", json={"name": f"UI {uuid.uuid4().hex[:6]}", "domains": ["shopnova.com"]}
    ).json()
    r = c.post(
        f"/api/brands/{brand['id']}/scan-urls", json={"urls": ["https://shopnova-login.com/"]}
    )
    _wait(app, r.json()["job_id"])
    finding_id = c.get("/api/findings", params={"brand_id": brand["id"]}).json()[0]["id"]

    ui = TestClient(app)  # no bearer header: the UI uses the session cookie
    assert ui.get("/ui/findings", follow_redirects=False).status_code == 303  # → login
    r = ui.post("/ui/login", data={**ADMIN, "next": "/ui/findings"}, follow_redirects=False)
    assert r.status_code == 303 and "bw_session" in r.cookies

    page = ui.get("/ui/findings")
    assert page.status_code == 200 and "shopnova-login.com" in page.text
    page = ui.get(f"/ui/findings/{finding_id}")
    assert page.status_code == 200
    for needle in (
        "Explain Finding",
        "external_form_action",
        "Observation timeline",
        "Suspect vs. official",
        "Confirm phishing",
    ):
        assert needle in page.text, needle
    assert (
        ui.get(
            f"/ui/jobs/{r.cookies and c.get(f'/api/jobs?brand_id={brand["id"]}').json()[0]['id']}"
        ).status_code
        == 200
    )
    assert ui.get("/ui/brands").status_code == 200 and brand["name"] in ui.get("/ui/brands").text
    assert ui.get(f"/ui/brands/{brand['id']}").status_code == 200
    assert ui.get("/ui/candidates").status_code == 200
    assert ui.get("/ui/activity").status_code == 200
    # the JSON API accepts the same cookie (the Live Console polls it)
    assert ui.get(f"/api/jobs?brand_id={brand['id']}").status_code == 200

    # verdict through the UI form
    r = ui.post(
        f"/ui/findings/{finding_id}/verdict",
        data={"action": "dismiss", "reason": "test", "verdict": "suspicious"},
        follow_redirects=False,
    )
    assert r.status_code == 303
    assert c.get(f"/api/findings/{finding_id}").json()["finding"]["state"] == "dismissed"
    assert ui.get("/ui/logout", follow_redirects=False).status_code == 303
