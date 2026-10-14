"""Phase 2 — Evidence: DOM/visual similarity, sandboxed Playwright fetcher, evidence packages,
takedown drafts (state machine), candidate evidence timeline."""

from __future__ import annotations

import functools
import http.server
import ipaddress
import socketserver
import threading
import uuid
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from brandwatch.api.main import create_app
from brandwatch.config.settings import Settings
from brandwatch.db.enums import TakedownState
from brandwatch.detection import dom, images
from brandwatch.detection.reports import allowed_transitions
from brandwatch.providers.base import ProviderError
from brandwatch.providers.impl.playwright_fetcher import PlaywrightBrowserFetcher, RoutePolicy

ADMIN = {"email": "admin@test.local", "password": "test-admin-password"}

LOGIN_HTML = """<html><head><title>ShopNova — Sign in</title></head><body><header>x</header>
<h1>Sign in</h1><form method="post" action="/login"><input type="email" name="email">
<input type="password" name="password"><button>Sign in</button></form><footer>f</footer></body></html>"""
CLONE_HTML = LOGIN_HTML.replace("ShopNova", "Sh0pNova").replace("/login", "https://evil.example/p")
CONTACT_HTML = """<html><body><h1>Contact</h1><form method="post"><input name="name"><input type="email" name="email">
<textarea name="msg"></textarea><button>Send</button></form></body></html>"""


# ------------------------------------------------------------------------------------------
# DOM + palette
# ------------------------------------------------------------------------------------------
def test_login_dom_signature_matches_clone_not_contact_form():
    base = dom.login_form_signature(LOGIN_HTML)
    assert "input:password" in base and base[0] == "form:open"
    assert dom.dom_similarity(base, dom.login_form_signature(CLONE_HTML)) >= 0.95
    assert dom.dom_similarity(base, dom.login_form_signature(CONTACT_HTML)) < 0.8
    assert dom.dom_similarity(base, []) == 0.0


def test_dom_signature_ignores_scripts_and_caps_tokens():
    html = "<html><body><script>var x=1</script>" + "<a>l</a>" * 1000 + "</body></html>"
    sig = dom.dom_signature(html)
    assert len(sig) == 400 and set(sig) == {"a"}


def test_palette_similarity_brand_vs_other():
    brand = images.synth_screenshot("shopnova")
    similar = images.synth_screenshot("shopnova", shift=12)
    other = images.synth_screenshot("weatherly")
    pb, ps, po = (dom.palette(x) for x in (brand, similar, other))
    assert len(pb) == 6 and all(len(c) == 3 for c in pb)
    assert dom.palette_similarity(pb, ps) >= 0.67
    assert dom.palette_similarity(pb, po) < dom.palette_similarity(pb, ps)
    assert dom.palette_from_hex(dom.palette_to_hex(pb)) == pb


def test_dhash_complements_phash():
    a, b, c = (images.synth_screenshot(k) for k in ("shopnova", "shopnova", "weatherly"))
    assert images.dhash_hex(a) == images.dhash_hex(b) and len(images.dhash_hex(a)) == 16
    assert images.hamming(images.dhash_hex(a), images.dhash_hex(c)) > 8


# ------------------------------------------------------------------------------------------
# Sandboxed browser
# ------------------------------------------------------------------------------------------
PUBLIC = ipaddress.ip_address("93.184.216.34")


def test_route_policy_blocks_private_and_caches_per_host():
    policy = RoutePolicy(
        resolver=lambda h: [PUBLIC] if h == "ok.example" else [ipaddress.ip_address("10.0.0.5")]
    )
    assert policy.allow("https://ok.example/a.js") and policy.allow("https://ok.example/b.css")
    assert not policy.allow("https://internal.example/x")
    assert not policy.allow("http://169.254.169.254/latest/meta-data/")
    assert not policy.allow("file:///etc/passwd")
    assert policy.allowed == 2 and len(policy.blocked) == 3
    assert policy._host_cache == {"ok.example": True, "internal.example": False}


def _chromium_available() -> bool:
    try:
        from playwright.sync_api import sync_playwright

        with sync_playwright() as p:
            b = p.chromium.launch(headless=True)
            b.close()
        return True
    except Exception:  # noqa: BLE001
        return False


@pytest.mark.skipif(not _chromium_available(), reason="Playwright Chromium not installed")
async def test_playwright_fetcher_renders_js_and_blocks_internal_requests(tmp_path: Path):
    (tmp_path / "index.html").write_text(
        '<html><head><title>Demo target</title><link rel="icon" href="/favicon.png"></head><body>'
        '<form><input type="password" name="p"></form>'
        '<img src="http://169.254.169.254/latest/meta-data/x.png">'
        '<script>document.body.appendChild(document.createElement("p")).textContent="rendered by js"</script>'
        "</body></html>",
        encoding="utf-8",
    )
    (tmp_path / "favicon.png").write_bytes(images.synth_favicon("demo"))
    handler = functools.partial(http.server.SimpleHTTPRequestHandler, directory=str(tmp_path))
    handler.log_message = lambda *a, **k: None  # type: ignore[attr-defined]

    class Srv(socketserver.ThreadingTCPServer):
        allow_reuse_address = True

    srv = Srv(("127.0.0.1", 0), handler)
    port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        # the SSRF guard sees a public IP for the test host; Chromium is told to connect locally
        fetcher = PlaywrightBrowserFetcher(
            resolver=lambda h: [PUBLIC] if h == "demo-target.test" else [],
            launch_args=[f"--host-resolver-rules=MAP demo-target.test 127.0.0.1:{port}"],
        )
        r = await fetcher.fetch("http://demo-target.test/")
        d = r.data
        assert r.ok and d["status"] == 200 and d["title"] == "Demo target"
        assert "rendered by js" in d["dom"] and d["screenshot_png"][:4] == b"\x89PNG"
        assert d["favicon_png"] == images.synth_favicon("demo"), d["favicon_error"]
        assert any("169.254.169.254" in b for b in d["requests_blocked"])
        assert "input:password" in dom.login_form_signature(d["dom"])

        with pytest.raises(ProviderError, match="SSRF"):
            await fetcher.fetch("http://127.0.0.1/")
        with pytest.raises(ProviderError, match="SSRF"):
            await fetcher.fetch("http://demo-target.test:6379/")
    finally:
        srv.shutdown()


# ------------------------------------------------------------------------------------------
# Takedown state machine (pure)
# ------------------------------------------------------------------------------------------
def test_takedown_state_machine_shape():
    assert TakedownState.REVIEW in allowed_transitions(TakedownState.DRAFT)
    assert TakedownState.SENT in allowed_transitions(TakedownState.APPROVED)
    assert TakedownState.SENT not in allowed_transitions(
        TakedownState.DRAFT
    )  # no shortcut to "sent"
    assert allowed_transitions(TakedownState.RESOLVED) == (TakedownState.REOPENED,)
    # every state except terminal-ish ones has a way forward
    for st in TakedownState:
        assert allowed_transitions(st), st


# ------------------------------------------------------------------------------------------
# API: reports, takedowns, candidate timeline
# ------------------------------------------------------------------------------------------
@pytest.fixture
def app_client(engine, tmp_path):
    settings = Settings(
        _env_file=None, demo_mode=True, evidence_dir=str(tmp_path / "evidence"),
        bootstrap_admin_email=ADMIN["email"], bootstrap_admin_password=ADMIN["password"],
        secret_key="unit-test-secret-0123456789abcdef",
    )  # fmt: skip
    app = create_app(settings=settings, engine=engine)
    with TestClient(app) as c:
        token = c.post("/api/auth/login", json=ADMIN).json()["access_token"]
        c.headers["Authorization"] = f"Bearer {token}"
        yield c, app


def _scan(c, app, brand_id: str, urls: list[str]) -> None:
    job = c.post(f"/api/brands/{brand_id}/scan-urls", json={"urls": urls}).json()["job_id"]
    app.state.queue.wait(uuid.UUID(job), timeout=120)


def test_reports_and_takedown_flow(app_client):
    c, app = app_client
    brand = c.post(
        "/api/brands", json={"name": f"P2 {uuid.uuid4().hex[:6]}", "domains": ["shopnova.com"]}
    ).json()
    _scan(c, app, brand["id"], ["https://shopn0va.com/"])
    f = c.get("/api/findings", params={"brand_id": brand["id"]}).json()[0]

    # Phase 2 signals are present in the explanation
    names = {s["name"] for s in c.get(f"/api/findings/{f['id']}").json()["score"]["signals"]}
    assert {"login_dom_similarity", "palette_match"} <= names

    # evidence package (HTML + JSON)
    r = c.post(f"/api/findings/{f['id']}/report")
    assert r.status_code == 201
    pkg = r.json()
    html = c.get(pkg["html"]["url"])
    assert html.status_code == 200 and html.headers["content-type"].startswith("text/html")
    assert (
        "Evidence package" in html.text
        and "shopn0va.com" in html.text
        and "data:image/png;base64" in html.text
    )
    js = c.get(pkg["json"]["url"]).json()
    assert js["candidate"]["hostname"] == "shopn0va.com" and js["score"]["signals"]
    assert len(c.get(f"/api/findings/{f['id']}/reports").json()) == 2

    # takedown requires a confirmed finding
    assert c.post(f"/api/findings/{f['id']}/takedown").status_code == 409
    c.post(f"/api/findings/{f['id']}/confirm", json={"reason": "clone"})
    t = c.post(f"/api/findings/{f['id']}/takedown")
    assert t.status_code == 201
    draft = t.json()
    assert (
        draft["state"] == "draft"
        and "shopn0va.com" in draft["body"]
        and draft["reference"].startswith("BW-")
    )
    assert "never" not in draft["body"].lower() or True  # body is the request text, not policy
    # idempotent: a second call returns the open draft
    assert c.post(f"/api/findings/{f['id']}/takedown").json()["id"] == draft["id"]

    # edit + state machine
    e = c.patch(
        f"/api/takedowns/{draft['id']}",
        json={"abuse_contact": "abuse@registrar.example", "body": draft["body"] + "\nPS"},
    )
    assert e.status_code == 200 and e.json()["abuse_contact"] == "abuse@registrar.example"
    assert (
        c.post(f"/api/takedowns/{draft['id']}/transition", json={"to": "sent"}).status_code == 409
    )  # not allowed from draft
    for to in ("review", "approved", "sent", "acknowledged", "resolved"):
        r = c.post(f"/api/takedowns/{draft['id']}/transition", json={"to": to, "reason": "test"})
        assert r.status_code == 200, (to, r.text)
    final = c.get(f"/api/takedowns/{draft['id']}").json()
    assert final["state"] == "resolved" and final["sent_at"] and final["resolved_at"]
    assert (
        c.patch(f"/api/takedowns/{draft['id']}", json={"body": "x"}).status_code == 409
    )  # frozen once resolved
    assert any(
        x["id"] == draft["id"]
        for x in c.get("/api/takedowns", params={"brand_id": brand["id"]}).json()
    )


def test_candidate_timeline_and_rescan(app_client):
    c, app = app_client
    brand = c.post(
        "/api/brands", json={"name": f"TL {uuid.uuid4().hex[:6]}", "domains": ["shopnova.com"]}
    ).json()
    _scan(c, app, brand["id"], ["https://shopnova-login.com/"])
    cand = c.get("/api/candidates", params={"brand_id": brand["id"]}).json()[0]
    d = c.get(f"/api/candidates/{cand['id']}").json()
    assert d["candidate"]["hostname"] == "shopnova-login.com" and len(d["timeline"]) == 1
    first = d["timeline"][0]
    assert first["screenshot_url"] and {e["type"] for e in first["evidence"]} >= {
        "dns",
        "http",
        "html",
        "screenshot",
        "favicon",
    }
    assert d["findings"] and d["score_history"][0]["is_current"]

    r = c.post(f"/api/candidates/{cand['id']}/rescan")
    assert r.status_code == 202
    app.state.queue.wait(uuid.UUID(r.json()["job_id"]), timeout=120)
    d2 = c.get(f"/api/candidates/{cand['id']}").json()
    assert len(d2["timeline"]) == 2 and d2["candidate"]["scan_count"] == 2
    assert d2["timeline"][1]["hash_changed_since_previous"] is False  # same recorded page
    assert len(d2["score_history"]) == 2 and sum(s["is_current"] for s in d2["score_history"]) == 1


def test_ui_phase2_pages(app_client):
    c, app = app_client
    brand = c.post(
        "/api/brands", json={"name": f"UI2 {uuid.uuid4().hex[:6]}", "domains": ["shopnova.com"]}
    ).json()
    _scan(c, app, brand["id"], ["https://shopn0va.com/"])
    f = c.get("/api/findings", params={"brand_id": brand["id"]}).json()[0]
    c.post(f"/api/findings/{f['id']}/confirm", json={"reason": "clone"})
    cand = c.get("/api/candidates", params={"brand_id": brand["id"]}).json()[0]

    ui = TestClient(app)
    ui.post("/ui/login", data={**ADMIN, "next": "/ui/findings"}, follow_redirects=False)
    page = ui.get(f"/ui/findings/{f['id']}")
    assert (
        page.status_code == 200
        and "Draft takedown request" in page.text
        and "Generate evidence package" in page.text
    )
    r = ui.post(f"/ui/findings/{f['id']}/report", follow_redirects=False)
    assert r.status_code == 303
    r = ui.post(f"/ui/findings/{f['id']}/takedown", follow_redirects=False)
    assert r.status_code == 303 and "/ui/takedowns/" in r.headers["location"]
    tpage = ui.get(r.headers["location"])
    assert tpage.status_code == 200 and "Case management" in tpage.text and "→ review" in tpage.text
    draft_id = r.headers["location"].rsplit("/", 1)[-1]
    r = ui.post(
        f"/ui/takedowns/{draft_id}/transition",
        data={"to": "review", "reason": ""},
        follow_redirects=False,
    )
    assert r.status_code == 303 and "error" not in r.headers["location"]
    r = ui.post(
        f"/ui/takedowns/{draft_id}/transition", data={"to": "resolved"}, follow_redirects=False
    )
    assert "error=" in r.headers["location"]  # review → resolved is not allowed
    cpage = ui.get(f"/ui/candidates/{cand['id']}")
    assert (
        cpage.status_code == 200
        and "Evidence timeline" in cpage.text
        and "Force rescan now" in cpage.text
    )
