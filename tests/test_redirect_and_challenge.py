"""A flagged look-alike's redirect destination is part of the same operation; and a bot check is shown, not just counted.

1. cryptohopper.app redirected to cryptohopper.ai. Only the first was found, so the address visitors really land on was
   never rated. Now the destination of a High finding's redirect joins the scan, carries the verdict of the site that sends
   visitors to it (``redirect_from_suspect``, floor High), and says where it came from.
2. The same site was rated "blocks bots +8" because the word "captcha" is in the scripts of its login form. A bot check is
   now a *page* that is a gate (thin, or titled like one), and the finding keeps its screenshot, says which visitor was
   challenged (its User-Agent, the headers it sent) and why that one, next to the ordinary browser visit.
"""

from __future__ import annotations

import asyncio
import dataclasses
import uuid

import sqlalchemy as sa
from fastapi.testclient import TestClient
from tests.conftest import make_brand, make_workspace
from tests.test_demo_story import _api, _app, _ui

import brandwatch.db.models as m
from brandwatch.config.settings import Settings
from brandwatch.db.enums import CandidateState, DiscoverySource, EvidenceType
from brandwatch.detection.cloaking import is_challenge_page
from brandwatch.detection.discovery import manual_hits
from brandwatch.detection.html import is_bot_challenge, visible_text
from brandwatch.detection.normalize import deduplicate, normalize
from brandwatch.detection.runner import run_scan
from brandwatch.pipeline.stages import DiscoveryHit
from brandwatch.providers.mock.fixtures import default_store


class _Scenarios:
    """Extra recorded sites for one test, taken out again afterwards (the store is shared)."""

    def __init__(self, *rows):
        self.rows, self.store = rows, default_store()

    def __enter__(self):
        for host, base, http, extra in self.rows:
            sc = self.store.get(base)
            self.store._by_host[host] = dataclasses.replace(
                sc, host=host, url=f"https://{host}/", http={**sc.http, **http}, **extra)  # fmt: skip
        return self

    def __exit__(self, *exc):
        for host, *_ in self.rows:
            self.store._by_host.pop(host, None)


def _scan(engine, tmp_path, urls, *, official="shopnova.com", prepare=None):
    from brandwatch.db.base import make_session_factory

    settings = Settings(_env_file=None, demo_mode=True, evidence_dir=str(tmp_path / f"ev-{uuid.uuid4().hex[:6]}"))
    with make_session_factory(engine)() as s:
        ws = make_workspace(s, f"rc-{uuid.uuid4().hex[:6]}")
        b = make_brand(s, ws, "ShopNova")
        s.add(m.BrandDomain(brand_id=b.id, domain=official, is_official=True, kind="official"))
        if prepare:
            prepare(s, b)
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
            out[cand.canonical_domain] = {
                "cand": cand, "finding": f, "signals": dict(cur.signals or {}) if cur else {},
                "severity": cur.severity.value if cur else None,
                "sources": [x.source for x in s.scalars(sa.select(m.CandidateSource).where(m.CandidateSource.candidate_id == cand.id)).all()],
                "shots": [(e.source_type, str(e.id)) for e in s.scalars(sa.select(m.Evidence).where(
                    m.Evidence.candidate_id == cand.id, m.Evidence.type == EvidenceType.SCREENSHOT)).all()],
            }  # fmt: skip
        return summary, events, out, (ws.id, b.id)


# ------------------------------------------------------------------------------------------ what is a bot check
def test_a_bot_check_is_a_page_that_is_a_gate_not_a_word_in_a_script():
    login_page = ("<html><head><title>Cryptohopper.AI — Build crypto trading bots</title></head><body>" + "<p>Build bots. </p>" * 200
                  + '<script>var t = {"captchaFailed":"Captcha verification failed. Please try again."}</script></body></html>')
    assert is_challenge_page("Cryptohopper.AI — Build crypto trading bots", login_page) is False  # the case that was rated "blocks bots"
    thin_with_script = '<html><head><title>Shop</title></head><body><h1>Welcome</h1><script>if (captcha) {}</script></body></html>'
    assert is_challenge_page("Shop", thin_with_script) is False
    assert is_challenge_page("Just a moment...", "<html><body>" + "x " * 4000 + "</body></html>") is True  # the title says it
    assert is_challenge_page("Attention Required! | Cloudflare", "<html></html>") is True
    assert is_challenge_page("", "<html><body><h1>Verify you are human</h1><div class='g-recaptcha'></div></body></html>") is True
    assert is_challenge_page("Security check", "<html><body><p>Please complete the CAPTCHA below to continue.</p></body></html>") is True
    assert is_challenge_page(None, None) is False
    assert visible_text("<p>Hi <b>there</b></p><script>var a = 1;</script><style>p{}</style>") == "Hi there"
    # the baseline and the fetcher use the same test: the words in a script of a full page are not a gate either
    scripted = "<html><body>" + "<p>Welcome back. </p>" * 120 + '<script>var m = "verify you are human";</script></body></html>'
    assert is_bot_challenge("Sign in", scripted) is False
    thin_scripted = '<html><body><h1>Sign in</h1><script src="/cdn-cgi/challenge-platform/scripts/jsd/main.js"></script><script>var m = "verify you are human";</script></body></html>'
    assert is_bot_challenge("Sign in", thin_scripted) is False  # even a thin page: the words are in a script, not on the page
    assert is_bot_challenge(None, '<div id="cf-chl-widget">Enable JavaScript and cookies to continue</div>') is True


# ------------------------------------------------------------------------------------------ the screenshot, the visitor, the why
def test_a_bot_check_shown_to_the_crawler_is_kept_with_its_screenshot_and_explained(engine, tmp_path):
    with _Scenarios(("shopnova-botwall.com", "shopn0va.com", {"challenge_for": ["bot"]}, {"cloak": {}})):
        summary, events, out, _ids = _scan(engine, tmp_path, ["https://shopnova-botwall.com/"])
    o = out["shopnova-botwall.com"]
    sig = o["signals"]
    assert o["finding"] is not None and "bot_blocking" in sig
    ch = sig["_challenge"]
    assert ch["visitor"] == "BrandWatch crawler probe" and ch["probe"] == "bot" and ch["profile"] == "bot"
    assert "BrandWatchBot" in ch["user_agent"] and ch["status"] == 403 and ch["title"] == "Just a moment..."
    assert ch["vendor"] == "Cloudflare" and "verify you are human" in ch["said"].lower()
    assert ch["compared"]["challenged"] is False and ch["compared"]["profile"] == "datacenter" and "Chrome/124" in ch["compared"]["user_agent"]
    assert [d["header"] for d in ch["differences"]] == ["user-agent"]  # the same headers otherwise: the User-Agent is what differed
    assert "same data-centre IP" in ch["why"] and "User-Agent" in ch["why"] and "BrandWatchBot" in ch["why"]
    assert ch["not_sent"] == ["sec-ch-ua", "sec-fetch-site", "sec-fetch-mode", "sec-fetch-dest"]  # the recorded visits send accept-language only
    assert "A person's browser also sends sec-ch-ua, sec-fetch-site" in ch["why"] and "nor did the browser-like one" in ch["why"]
    assert ch["headers"]["accept-language"] == "en-US" and ch["headers"]["user-agent"] == ch["user_agent"]  # exactly what was sent
    assert sig["_details"]["bot_blocking"].startswith("the crawler (User-Agent “Mozilla/5.0 (compatible; BrandWatchBot/0.1")
    assert "the browser-like visit was not" in sig["_details"]["bot_blocking"]
    kinds = [k for k, _ in o["shots"]]
    assert "challenge_screenshot" in kinds and ch["screenshot_evidence_id"] in [i for _, i in o["shots"]]
    said = [e.message for e in events if e.stage == "cloaking"]
    assert any("BrandWatchBot" in x for x in said) and any("Cloaking detected: bot_blocking" in x for x in said), said


def test_the_finding_page_shows_the_challenge_screenshot_and_never_takes_it_for_the_suspect(engine, tmp_path):
    app = _app(engine, tmp_path)
    with _Scenarios(("shopnova-botwall2.com", "shopn0va.com", {"challenge_for": ["bot"]}, {"cloak": {}})), TestClient(app):
        c, ui = _api(app), _ui(app)
        brand = c.post("/api/brands", json={"name": f"Botwall {uuid.uuid4().hex[:4]}", "domains": ["shopnova.com"]}).json()
        job = c.post(f"/api/brands/{brand['id']}/scan-urls", json={"urls": ["https://shopnova-botwall2.com/"]}).json()["job_id"]
        app.state.queue.wait(uuid.UUID(job), timeout=120)
        f = c.get("/api/findings", params={"brand_id": brand["id"]}).json()[0]
        d = c.get(f"/api/findings/{f['id']}").json()
        ch = d["score"]["challenge"]
        assert ch and ch["screenshot_url"].endswith("/artifact") and ch["visitor"] == "BrandWatch crawler probe"
        assert d["screenshots"]["suspect_url"] and d["screenshots"]["suspect_url"] != ch["screenshot_url"]
        art = c.get(ch["screenshot_url"])
        assert art.status_code == 200 and art.content[:4] == b"\x89PNG"
        page = ui.get(f"/ui/findings/{f['id']}").text
        assert 'id="bot-check"' in page and "Bot check — who was challenged, and why" in page
        assert ch["screenshot_url"] in page and "BrandWatchBot" in page and "Every header it sent" in page
        assert "What differed" in page and "bot check shown" in page  # the probe table's note is no longer "captcha"


def test_a_site_that_only_mentions_captcha_in_its_scripts_is_not_rated_as_blocking_bots(engine, tmp_path):
    page = ("<html><head><title>ShopN0va — Sign in</title></head><body><form><input type='password' name='p'></form>"
            + "<p>Sign in to your account.</p>" * 20
            + '<script>var msgs = {"captchaFailed":"Captcha verification failed. Please try again.", "verify": "verify you are human"}</script></body></html>')
    with _Scenarios(("shopnova-scripted.com", "shopn0va.com", {"html": page}, {"cloak": {}})):
        _s, _e, out, _ids = _scan(engine, tmp_path, ["https://shopnova-scripted.com/"])
    o = out["shopnova-scripted.com"]
    assert o["finding"] is not None, o
    assert "bot_blocking" not in o["signals"], (o["signals"].get("_details", {}).get("bot_blocking"), o["signals"].get("_scanner_block"))
    assert "_challenge" not in o["signals"]
    assert all(k != "challenge_screenshot" for k, _ in o["shots"])


# ------------------------------------------------------------------------------------------ the redirect
def test_the_destination_of_a_flagged_sites_redirect_is_checked_and_flagged_with_it(engine, tmp_path):
    with _Scenarios(
        ("shopnova-promo.net", "shopn0va.com", {"location": "https://shopnova-rewards-hub.com/"}, {}),
        ("shopnova-rewards-hub.com", "shopnova-login.com", {}, {}),
    ):
        summary, events, out, _ids = _scan(engine, tmp_path, ["https://shopnova-promo.net/"])
    a, b = out["shopnova-promo.net"], out["shopnova-rewards-hub.com"]
    assert a["finding"] is not None and a["severity"] in ("high", "critical"), (a["severity"], a["signals"])
    assert b["finding"] is not None and b["severity"] in ("high", "critical"), (b["severity"], b["signals"])
    assert "redirect_from_suspect" in b["signals"] and "shopnova-promo.net" in b["signals"]["_details"]["redirect_from_suspect"]
    assert "rated HIGH" in b["signals"]["_details"]["redirect_from_suspect"] or "rated CRITICAL" in b["signals"]["_details"]["redirect_from_suspect"]
    assert DiscoverySource.REDIRECT in b["sources"] and DiscoverySource.MANUAL in a["sources"]
    step = next(st for st in summary.steps if "reached through a flagged look-alike's redirect" in st["title"])
    assert step["items"] == [{"label": "shopnova-rewards-hub.com", "tag": "from shopnova-promo.net"}]
    said = " ".join(e.message for e in events)
    assert "shopnova-promo.net redirects its visitors to shopnova-rewards-hub.com" in said
    assert any(e.message.startswith("Processing https://shopnova-rewards-hub.com/") and "redirects its visitors here" in e.message for e in events)
    assert summary.processed == 2  # the destination was visited in addition to what was asked for


def test_the_destination_floor_is_high_even_when_its_own_page_is_plain(engine, tmp_path):
    # no credential form, no favicon match: on its own that address would be a Low; the verdict of the sender is the evidence
    with _Scenarios(
        ("shopnova-promo2.net", "shopn0va.com", {"location": "https://shopnova-quiet-offers.com/"},
         {"reputation": {"virustotal": "positive", "safebrowsing": "positive", "phishtank": "positive"}}),
        ("shopnova-quiet-offers.com", "shopnova-login.com", {"html": "<html><head><title>Offers</title></head><body>" + "<p>Offers for you, only this week. </p>" * 30 + "</body></html>"},
         {"favicon": None, "screenshot": "other", "whois": {"age_days": 900, "registrar": "Reg", "registrant": "x"}}),
    ):
        _s, _e, out, _ids = _scan(engine, tmp_path, ["https://shopnova-promo2.net/"])
    assert "shopnova-quiet-offers.com" in out, (out["shopnova-promo2.net"]["severity"], out["shopnova-promo2.net"]["signals"], list(out))
    b = out["shopnova-quiet-offers.com"]
    assert b["finding"] is not None and b["severity"] == "high" and "redirect_from_suspect" in b["signals"]


def test_a_redirect_that_gives_nothing_away_adds_nothing(engine, tmp_path):
    with _Scenarios(
        ("shopnova-promo3.net", "shopn0va.com", {"location": "https://parked-sales-page.net/"}, {}),
        ("parked-sales-page.net", "shopnova-login.com", {"html": "<html><head><title>Domain for sale</title></head><body><p>This domain is for sale.</p></body></html>"},
         {"favicon": None, "screenshot": "other"}),
        ("shopnova-promo4.net", "shopn0va.com", {"location": "https://www.google.com/"}, {}),
        ("shopnova-promo5.net", "shopn0va.com", {"location": "https://www.shopnova.com/"}, {}),
    ):
        # note: only the first hop is a brand look-alike; none of the destinations is related to the brand or asks for a login
        for host in ("shopnova-promo3.net", "shopnova-promo4.net", "shopnova-promo5.net"):
            sc = default_store().get(host)
            assert sc is not None
        default_store()._by_host["www.google.com"] = dataclasses.replace(
            default_store().get("shopnova-login.com"), host="www.google.com", url="https://www.google.com/",
            http={**default_store().get("shopnova-login.com").http, "html": "<html><head><title>Google</title></head><body>Search</body></html>"})  # fmt: skip
        try:
            summary, _e, out, _ids = _scan(
                engine, tmp_path, ["https://shopnova-promo3.net/", "https://shopnova-promo4.net/", "https://shopnova-promo5.net/"])
        finally:
            default_store()._by_host.pop("www.google.com", None)
    assert not [h for h in out if h in ("parked-sales-page.net", "www.google.com", "google.com", "shopnova.com", "www.shopnova.com")]
    assert not any("redirect" in st["title"] for st in summary.steps if "reached through" in st["title"])


def test_a_destination_the_analyst_already_dismissed_is_left_alone(engine, tmp_path):
    def dismiss_first(session, brand):
        norm = normalize(DiscoveryHit(DiscoverySource.MANUAL, "https://shopnova-ok-hub.com/", __import__("brandwatch.db.enums", fromlist=["Surface"]).Surface.NAME))
        cand = session.get(m.Candidate, deduplicate(session, brand.id, norm).candidate_id)
        cand.state = CandidateState.DISMISSED

    with _Scenarios(
        ("shopnova-promo6.net", "shopn0va.com", {"location": "https://shopnova-ok-hub.com/"}, {}),
        ("shopnova-ok-hub.com", "shopnova-login.com", {}, {}),
    ):
        _s, _e, out, _ids = _scan(engine, tmp_path, ["https://shopnova-promo6.net/"], prepare=dismiss_first)
    assert out["shopnova-ok-hub.com"]["cand"].state is CandidateState.DISMISSED and out["shopnova-ok-hub.com"]["finding"] is None
    assert out["shopnova-promo6.net"]["finding"] is not None


# ------------------------------------------------------------------------------------------ the real browser
def test_the_sandboxed_browser_reports_what_it_sent_and_the_redirect_it_followed(monkeypatch):
    import http.server
    import ipaddress
    import socketserver
    import threading

    import pytest
    from tests.test_phase2 import _chromium_available

    from brandwatch.providers.impl import playwright_fetcher as pf

    if not _chromium_available():
        pytest.skip("Playwright Chromium not installed")
    monkeypatch.setattr(pf, "CHALLENGE_WAIT_STEPS", 1)  # a bot check is waited out for 8 s; one is enough here
    wall = "<html><head><title>Just a moment...</title></head><body><h1>Checking your browser</h1><p>Verify you are human.</p></body></html>"
    page = "<html><head><title>Landing</title></head><body>" + "<p>Welcome to the landing page. </p>" * 60 + "</body></html>"

    class H(http.server.BaseHTTPRequestHandler):
        def log_message(self, *a, **k):
            pass

        def do_GET(self):  # noqa: N802 - http.server API
            if "bot" in (self.headers.get("User-Agent") or "").lower():  # the site tells crawlers apart by their User-Agent
                body, code = wall.encode(), 403
            elif self.path == "/promo":
                self.send_response(302)
                self.send_header("Location", "/landing")
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            else:
                body, code = page.encode(), 200
            self.send_response(code)
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
            resolver=lambda h: [ipaddress.ip_address("93.184.216.34")] if h == "gate.test" else [],
            launch_args=[f"--host-resolver-rules=MAP gate.test 127.0.0.1:{port}"],
        )
        ordinary = asyncio.run(fetcher.fetch("http://gate.test/promo", "datacenter")).data
        assert ordinary["status"] == 200 and ordinary["final_url"] == "http://gate.test/landing"
        assert ordinary["redirect_chain"] == ["http://gate.test/promo"]  # where it was sent away from
        assert "Chrome/124" in ordinary["user_agent"] and ordinary["request_headers"]["user-agent"] == ordinary["user_agent"]
        # what the sandboxed Chromium really sends: no Accept-Language, no client hints (the finding says so next to a bot check)
        assert "accept" in ordinary["request_headers"] and "accept-language" not in ordinary["request_headers"]
        assert is_challenge_page(ordinary["title"], ordinary["dom"]) is False

        crawler = asyncio.run(fetcher.fetch("http://gate.test/promo", "bot")).data
        assert crawler["status"] == 403 and "BrandWatchBot" in crawler["user_agent"]
        assert crawler["request_headers"]["user-agent"] == crawler["user_agent"]
        assert crawler["bot_challenge"] is True and is_challenge_page(crawler["title"], crawler["dom"]) is True
        assert crawler["screenshot_png"][:4] == b"\x89PNG"  # the picture of the bot check that the finding keeps
        # the two visits differ in the User-Agent and nothing the page could be judged by besides it
        diff = {k for k in set(ordinary["request_headers"]) | set(crawler["request_headers"])
                if ordinary["request_headers"].get(k) != crawler["request_headers"].get(k)}  # fmt: skip
        assert "user-agent" in diff
    finally:
        srv.shutdown()


def test_a_site_that_refuses_the_scan_says_who_was_refused(engine, tmp_path):
    app = _app(engine, tmp_path)
    with TestClient(app):
        c, ui = _api(app), _ui(app)
        brand = c.post("/api/brands", json={"name": f"Refused {uuid.uuid4().hex[:4]}", "domains": ["shopnova.com"]}).json()
        job = c.post(f"/api/brands/{brand['id']}/scan-urls", json={"urls": ["https://shopnova-eu.com/"]}).json()["job_id"]
        app.state.queue.wait(uuid.UUID(job), timeout=120)
        f = c.get("/api/findings", params={"brand_id": brand["id"]}).json()[0]
        sb = c.get(f"/api/findings/{f['id']}").json()["score"]["scanner_block"]
        assert sb["status"] == 403 and "Chrome/124" in sb["user_agent"] and sb["profile"] == "datacenter"
        assert sb["headers"]["user-agent"] == sb["user_agent"]
        page = ui.get(f"/ui/findings/{f['id']}").text
        assert "Who was refused" in page and "BrandWatch&#39;s browser visit (datacenter profile" in page.replace("'", "&#39;")
        assert "A person&#39;s browser also sends sec-ch-ua" in page.replace("'", "&#39;") and "every header it sent" in page


def test_both_findings_point_at_each_other(engine, tmp_path):
    app = _app(engine, tmp_path)
    with _Scenarios(
        ("shopnova-promo7.net", "shopn0va.com", {"location": "https://shopnova-rewards-hub7.com/"}, {}),
        ("shopnova-rewards-hub7.com", "shopnova-login.com", {}, {}),
    ), TestClient(app):
        c, ui = _api(app), _ui(app)
        brand = c.post("/api/brands", json={"name": f"Redir {uuid.uuid4().hex[:4]}", "domains": ["shopnova.com"]}).json()
        job = c.post(f"/api/brands/{brand['id']}/scan-urls", json={"urls": ["https://shopnova-promo7.net/"]}).json()["job_id"]
        app.state.queue.wait(uuid.UUID(job), timeout=120)
        rows = {f["hostname"] if "hostname" in f else f["host"]: f for f in c.get("/api/findings", params={"brand_id": brand["id"]}).json()}
        a, b = rows["shopnova-promo7.net"], rows["shopnova-rewards-hub7.com"]
        da, db_ = c.get(f"/api/findings/{a['id']}").json(), c.get(f"/api/findings/{b['id']}").json()
        assert da["redirect"]["to"]["finding_id"] == b["id"] and da["redirect"]["to"]["host"] == "shopnova-rewards-hub7.com"
        assert da["redirect"]["from"] is None
        assert db_["redirect"]["from"]["finding_id"] == a["id"] and db_["redirect"]["from"]["host"] == "shopnova-promo7.net"
        pa, pb = ui.get(f"/ui/findings/{a['id']}").text, ui.get(f"/ui/findings/{b['id']}").text
        assert f'href="/ui/findings/{b["id"]}"' in pa and "Redirects its visitors to" in pa and "also a finding" in pa
        assert f'href="/ui/findings/{a["id"]}"' in pb and "are redirected here: the same operation" in pb
        # the scan's own report says where the second site came from
        assert db_["candidate"]["sources"][0]["source"] == "redirect" and db_["candidate"]["sources"][0]["pattern"] == "shopnova-promo7.net"
