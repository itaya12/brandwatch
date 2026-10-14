"""What the live scans of On (2026-10-11) taught: a Cloudflare "Suspected Phishing" interstitial is a
verdict, an old domain is no excuse once a blocklist flags it, saved brand configs pick up signals
added later, and free calls never use up the day's API budget."""

from __future__ import annotations

import asyncio

from brandwatch.config.brand_config import CATALOGUE_ADDITIONS, SCORING_VERSION, ScoringConfig
from brandwatch.config.settings import Settings
from brandwatch.db.enums import Severity
from brandwatch.detection import html
from brandwatch.providers.mock.fixtures import default_store


def test_cloudflare_phishing_interstitial_is_recognised():
    sc = default_store().get("shopnova--sneakers.com")
    page = sc.http["html"]
    assert html.is_cloudflare_phish_warning("Suspected Phishing | Cloudflare", page)
    assert html.is_cloudflare_phish_warning(None, page)  # the bypass form alone is enough
    assert not html.is_cloudflare_phish_warning("Just a moment...", "<html>cf-chl</html>")  # a bot check is not a verdict
    assert html.extract_features(page, sc.url, ["shopnova"]).cloudflare_phish_warning


def _url_scan(engine, tmp_path, url: str, *, full_check: bool = False):
    """One URL scanned for a service brand in demo mode → (candidate.last_analysis, current score)."""
    import uuid

    import sqlalchemy as sa
    from tests.conftest import make_brand, make_workspace

    import brandwatch.db.models as m
    from brandwatch.db.base import make_session_factory
    from brandwatch.detection.discovery import manual_hits
    from brandwatch.detection.runner import run_scan

    settings = Settings(_env_file=None, demo_mode=True, evidence_dir=str(tmp_path / "ev"))
    with make_session_factory(engine)() as s:
        ws = make_workspace(s, f"cf-{uuid.uuid4().hex[:6]}")
        brand = make_brand(s, ws, "ShopNova")
        s.add(m.BrandDomain(brand_id=brand.id, domain="shopnova.com"))
        job = m.ScanJob(workspace_id=ws.id, brand_id=brand.id, kind="url_scan", payload={"full_check": True} if full_check else None)
        s.add(job)
        s.flush()
        asyncio.run(run_scan(s, job.id, settings=settings, hits=manual_hits([url])))
        s.commit()
        cand = s.scalars(sa.select(m.Candidate).where(m.Candidate.brand_id == brand.id)).one()
        f = s.scalars(sa.select(m.Finding).where(m.Finding.candidate_id == cand.id)).first()
        cur = f.current_score if f else None
        return dict(cand.last_analysis or {}), (cur.score, cur.severity, dict(cur.signals or {}), dict(cur.groups or {})) if cur else None


def test_the_oncloud_sneakers_case_is_high_and_old_age_is_no_excuse(engine, tmp_path):
    last, cur = _url_scan(engine, tmp_path, "https://shopnova--sneakers.com/")
    assert "cloudflare_phishing_warning" in last["signals"] and "vt_flagged" in last["signals"]
    assert "age_gt_2y" not in last["fp_flags"]  # 3 years old, but a blocklist flags it
    assert cur is not None, last
    score, sev, signals, groups = cur
    assert sev in (Severity.HIGH, Severity.CRITICAL), (score, last)
    rules = [x["rule"] for x in groups["_breakdown"]["combination_rules_fired"]]
    assert "cloudflare_flagged_lookalike" in rules
    assert "no false-positive discount" in signals["_details"]["age_gt_2y"]


def test_a_free_call_never_uses_up_the_budget():
    from brandwatch.config.settings import EconomicLimits
    from brandwatch.providers.ledger import InMemoryLedger

    led = InMemoryLedger(EconomicLimits(max_api_calls=2, max_daily_spend=0.01))
    for _ in range(50):
        assert led.check("local_dns", 0.0)
        led.record("local_dns", 1, 0.0)
    assert led.check("serpapi", 0.01)
    led.record("serpapi", 1, 0.01)
    assert not led.check("serpapi", 0.01) and led.check("playwright", 0.0)


def test_saved_configs_gain_signals_added_later():
    old_default = {"version": "v1", "weights": {"vt_flagged": 12}}
    assert ScoringConfig.model_validate(old_default).version == SCORING_VERSION  # untouched defaults → today's
    custom = ScoringConfig().model_dump(mode="json")
    custom["version"] = "v1-1234abcd"
    custom["weights"].pop("cloudflare_phishing_warning")
    custom["weights"]["vt_flagged"] = 9  # the analyst's own value stays
    custom["combination_rules"] = [r for r in custom["combination_rules"] if not r["name"].startswith("cloudflare")]
    up = ScoringConfig.model_validate(custom)
    assert up.weights["cloudflare_phishing_warning"] == 15 and up.weights["vt_flagged"] == 9
    assert {r.name for r in up.combination_rules} >= set(CATALOGUE_ADDITIONS["rules"])
    assert up.version == f"v1-1234abcd+{CATALOGUE_ADDITIONS['rev']}"


def test_the_browser_proceeds_past_cloudflares_warning():
    """A real Chromium against a local server that plays Cloudflare: "/" serves the "Suspected
    Phishing" interstitial until the bypass form sets a cookie; behind it is the fake store."""
    import http.server
    import socketserver
    import threading

    import pytest
    from tests.test_phase2 import PUBLIC, _chromium_available

    from brandwatch.providers.impl.playwright_fetcher import PlaywrightBrowserFetcher

    if not _chromium_available():
        pytest.skip("Playwright Chromium not installed")
    warning = default_store().get("shopnova--sneakers.com").http["html"].replace(
        "https://www.shopnova--sneakers.com/cdn-cgi/phish-bypass", "/cdn-cgi/phish-bypass")
    store_page = ("<html><head><title>ShopNova Official Store</title></head><body><h1>ShopNova Runner $49</h1>"
                  "<p>Limited stock — official outlet prices. Free shipping on every order.</p>"
                  "<form action='/checkout'><input name='cardnumber'><input name='cvv'><button>Pay now</button></form></body></html>")

    hits: list[str] = []

    class H(http.server.BaseHTTPRequestHandler):
        def log_message(self, *a, **k):
            pass

        def do_GET(self):  # noqa: N802 - http.server API
            hits.append(self.path)
            if self.path.startswith("/cdn-cgi/phish-bypass"):
                self.send_response(302)
                self.send_header("Set-Cookie", "__cf_bypass=1; Path=/")
                self.send_header("Location", "/")
                self.end_headers()
                return
            proceeded = "__cf_bypass=1" in (self.headers.get("Cookie") or "")
            body = (store_page if proceeded else warning).encode()
            self.send_response(200 if proceeded else 403)
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
        fetcher = PlaywrightBrowserFetcher(
            resolver=lambda h: [PUBLIC] if h == "cf-target.test" else [],
            launch_args=[f"--host-resolver-rules=MAP cf-target.test 127.0.0.1:{port}"],
        )
        # an ordinary visit leaves the warning alone: somebody already judged the site, nothing is pressed
        plain = asyncio.run(fetcher.fetch("http://cf-target.test/")).data
        assert plain["title"] == "Suspected Phishing | Cloudflare" and "ShopNova Runner" not in plain["html"]
        assert plain["cloudflare_warning"]["proceeded"] is False and "not opened" in plain["cloudflare_warning"]["skipped"]
        assert not any(p.startswith("/cdn-cgi/phish-bypass") for p in hits)
        # an analyst's full check presses "Ignore & Proceed" and looks at the site behind it
        r = asyncio.run(fetcher.fetch("http://cf-target.test/", "datacenter-proceed"))
        d = r.data
        assert r.ok and d["title"] == "ShopNova Official Store" and "ShopNova Runner $49" in d["html"]
        cfw = d["cloudflare_warning"]
        assert cfw["proceeded"] and cfw["title"] == "Suspected Phishing | Cloudflare" and "phish-bypass" in cfw["interstitial_html"]
        assert any(p.startswith("/cdn-cgi/phish-bypass") for p in hits)
    finally:
        srv.shutdown()


def test_a_security_warning_is_a_verdict_rated_high_without_opening_the_site(engine, tmp_path):
    last, cur = _url_scan(engine, tmp_path, "https://shopnova--sneakers.com/")
    score, sev, signals, groups = cur
    assert sev in (Severity.HIGH, Severity.CRITICAL)
    assert "known_phishing" in last["signals"] and "cloudflare_phishing_warning" in last["signals"]
    assert "payment_form" not in last["signals"] and "title_claims_brand" not in last["signals"]  # the store behind it was not studied
    rules = [x["rule"] for x in groups["_breakdown"]["combination_rules_fired"]]
    assert "known_phishing_verdict" in rules
    assert signals["_security_warning"]["vendor"] == "Cloudflare"


def test_an_analysts_full_check_does_look_behind_the_warning(engine, tmp_path):
    last, cur = _url_scan(engine, tmp_path, "https://shopnova--sneakers.com/", full_check=True)
    assert "payment_form" in last["signals"] and "title_claims_brand" in last["signals"]  # the store behind it
    assert "cloudflare_phishing_warning" in last["signals"] and "known_phishing" in last["signals"]  # and the verdict still counts


def test_set_up_before_the_first_scan(engine, tmp_path):
    """A new brand goes to the set-up page: the Google queries (and, for a retail brand, countries and
    prices) are approved once, then the scan runs without stopping to ask."""
    import uuid

    from fastapi.testclient import TestClient
    from tests.test_demo_story import _api, _app, _ui

    app = _app(engine, tmp_path)
    with TestClient(app):
        c, ui = _api(app), _ui(app)
        r = ui.post("/ui/brands", data={"name": f"ShopNova {uuid.uuid4().hex[:4]}", "domains": "shopnova.com",
                                        "preset": "enterprise", "kind": "retail"}, follow_redirects=False)  # fmt: skip
        assert r.status_code == 303 and r.headers["location"].endswith("/setup")
        bid = r.headers["location"].split("/")[3]
        page = ui.get(r.headers["location"]).text
        for needle in ("Google search queries", "Suggest with AI", "Where it is sold", "Approve &amp; start the scan"):
            assert needle in page, needle
        brand_page = ui.get(f"/ui/brands/{bid}").text
        assert "Set up &amp; start the scan" in brand_page and 'id="qmodal"' not in brand_page  # no pop-up any more
        # nothing to search with → a clear message, nothing saved
        bad = ui.post(f"/ui/brands/{bid}/setup", data={"action": "scan", "countries": "IL"})
        assert bad.status_code == 200 and "add at least one Google query" in bad.text
        assert not c.get(f"/api/brands/{bid}").json()["search_queries"]["approved"]
        # approve & start: queries approved, profile saved, the scan starts
        r = ui.post(f"/ui/brands/{bid}/setup", follow_redirects=False, data={
            "action": "scan", "q": ["shopnova runner sale", "shopnova outlet", ""], "countries": "IL, US",
            "ad_keywords": "shopnova runner", "product_name": ["ShopNova Runner", ""], "product_price": ["799", ""],
            "product_currency": ["ILS", ""], "product_country": ["IL", ""], "product_source": ["analyst", "analyst"]})  # fmt: skip
        assert r.status_code == 303 and r.headers["location"].startswith("/ui/jobs/")
        b = c.get(f"/api/brands/{bid}").json()
        assert b["search_queries"]["approved"] and b["search_queries"]["queries"] == ["shopnova runner sale", "shopnova outlet"]
        assert b["profile"]["countries"] == ["IL", "US"] and b["profile"]["products"][0]["price"] == 799
        assert "Set up &amp; start the scan" not in ui.get(f"/ui/brands/{bid}").text  # set up: Start scan is back
        # a service brand on a track without Google needs no set-up
        r2 = ui.post("/ui/brands", data={"name": f"Quantix {uuid.uuid4().hex[:4]}", "domains": "quantix.io",
                                         "preset": "basic"}, follow_redirects=False)  # fmt: skip
        assert not r2.headers["location"].endswith("/setup")


def test_a_busy_database_is_a_plain_message(engine, tmp_path):
    import sqlalchemy as sa
    from fastapi.testclient import TestClient
    from tests.test_demo_story import _app

    app = _app(engine, tmp_path)

    @app.get("/ui/_busy_probe")
    def _busy():
        raise sa.exc.OperationalError("INSERT", {}, Exception("database is locked"))

    @app.get("/api/_busy_probe")
    def _busy_api():
        raise sa.exc.OperationalError("INSERT", {}, Exception("database is locked"))

    with TestClient(app, raise_server_exceptions=False) as t:
        r = t.get("/ui/_busy_probe")
        assert r.status_code == 409 and "A scan is writing to the database right now" in r.text
        r = t.get("/api/_busy_probe")
        assert r.status_code == 503 and r.headers["retry-after"] == "5"


def test_one_target_that_does_not_answer_is_not_an_alert():
    from brandwatch.providers.base import classify_provider_error as kind

    assert kind("dns: no answer for nocloud.com (method service)") == "site"
    assert kind("searchapi: Instagram Profile not found.") == "site"
    assert kind("navigation failed: Page.goto: net::ERR_HTTP2_PROTOCOL_ERROR at http://x/") == "site"
    assert kind("HTTP 503 from upstream") == "outage" and kind("no API key") == "auth"


def test_a_human_check_on_proceed_is_never_attempted():
    import http.server
    import socketserver
    import threading

    import pytest
    from tests.test_phase2 import PUBLIC, _chromium_available

    from brandwatch.providers.impl.playwright_fetcher import PlaywrightBrowserFetcher

    if not _chromium_available():
        pytest.skip("Playwright Chromium not installed")
    warning = default_store().get("shopnova--sneakers.com").http["html"].replace(
        "https://www.shopnova--sneakers.com/cdn-cgi/phish-bypass", "/cdn-cgi/phish-bypass").replace(
        '<input type="hidden" name="original_path" value="/">',
        '<input type="hidden" name="original_path" value="/"><div class="cf-turnstile" data-sitekey="x"></div>'
        '<input type="hidden" name="cf-turnstile-response" value="">')
    hits: list[str] = []

    class H(http.server.BaseHTTPRequestHandler):
        def log_message(self, *a, **k):
            pass

        def do_GET(self):  # noqa: N802 - http.server API
            hits.append(self.path)
            if self.path.startswith("/cdn-cgi/phish-bypass"):
                body = b"bad request"
                self.send_response(400)
            else:
                body = warning.encode()
                self.send_response(403)
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
        fetcher = PlaywrightBrowserFetcher(
            resolver=lambda h: [PUBLIC] if h == "cf-human.test" else [],
            launch_args=[f"--host-resolver-rules=MAP cf-human.test 127.0.0.1:{port}"],
        )
        d = asyncio.run(fetcher.fetch("http://cf-human.test/", "datacenter-proceed")).data  # the full check is what meets the Turnstile
        cfw = d["cloudflare_warning"]
        assert not cfw["proceeded"] and cfw.get("human_check") and "Turnstile" in cfw["error"]
        assert d["title"] == "Suspected Phishing | Cloudflare" and "phish-bypass" in d["html"]  # the warning is analysed
        assert not any(p.startswith("/cdn-cgi/phish-bypass") for p in hits)  # never even tried
        assert d["bot_challenge"] is False
    finally:
        srv.shutdown()


def test_a_dead_redirect_hop_or_a_host_that_never_answers_is_the_site_not_the_collector():
    from brandwatch.providers.base import classify_provider_error as kind

    # both came from one scan: a tracking domain in a redirect chain, and a host that timed out on connect
    assert kind("blocked by SSRF guard: 'go.aztrackr.com' did not resolve") == "site"
    assert kind("fetch failed: ConnectTimeout: ") == "site"
    assert kind("fetch failed: ConnectError: [Errno 111] connection refused") == "site"
    # a collector that is really broken is still reported
    assert kind("crtsh: ReadTimeout: ") == "network" and kind("fetch limit: body too large") == "error"
    assert kind("blocked by SSRF guard: '10.0.0.1' is a private address") == "error"


def test_crtsh_gets_a_longer_read_timeout_than_the_other_clients():
    from brandwatch.providers.impl.clients import CertSpotterClient, CrtshClient

    assert CrtshClient.timeout.read >= 30 and CrtshClient.timeout.connect <= 10
    assert CertSpotterClient.timeout.read < CrtshClient.timeout.read


async def test_a_crtsh_timeout_falls_back_at_once_instead_of_waiting_three_times(monkeypatch):
    import httpx
    import pytest
    import respx

    from brandwatch.providers.base import ProviderError
    from brandwatch.providers.impl.clients import CrtshClient

    async def no_wait(_s):
        return None

    monkeypatch.setattr(asyncio, "sleep", no_wait)
    with respx.mock:
        route = respx.get("https://crt.sh/").mock(side_effect=httpx.ReadTimeout(""))
        with pytest.raises(ProviderError) as e:
            await CrtshClient(client=httpx.AsyncClient()).ct_search("%brand%")
        assert e.value.retryable is False and route.call_count == 1
        route = respx.get("https://crt.sh/").mock(return_value=httpx.Response(502))  # an overload spike is still waited out
        with pytest.raises(ProviderError):
            await CrtshClient(client=httpx.AsyncClient()).ct_search("%brand%")
        assert route.call_count == 1 + 4  # the same route object keeps counting: the timeout call, then four tries
