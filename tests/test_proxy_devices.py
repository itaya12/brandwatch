"""Settings → Proxy: which proxy the probe goes through (residential or mobile) and which device it visits as (desktop, a phone, both).

Kits that target victims on phones show the lure to a mobile browser only. The Tier-4 probe also used to look for an environment
variable instead of the proxy set in Settings, so a proxy entered in the UI was never used.
"""

from __future__ import annotations

import asyncio
import dataclasses
import uuid

import sqlalchemy as sa
from fastapi.testclient import TestClient
from tests.conftest import make_brand, make_workspace
from tests.test_demo_story import _app, _ui

import brandwatch.db.models as m
from brandwatch import keys as keystore
from brandwatch import proxy as proxy_mod
from brandwatch import tenancy
from brandwatch.config.settings import Settings
from brandwatch.db.enums import ScannerProfile
from brandwatch.detection.discovery import manual_hits
from brandwatch.detection.runner import run_scan
from brandwatch.providers.mock.fixtures import default_store


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


def _scan(engine, tmp_path, urls, *, devices="desktop", kind="residential", hits_brand="ShopNova"):
    from brandwatch.db.base import make_session_factory

    settings = Settings(_env_file=None, demo_mode=True, evidence_dir=str(tmp_path / f"ev-{uuid.uuid4().hex[:6]}"))
    with make_session_factory(engine)() as s:
        ws = make_workspace(s, f"px-{uuid.uuid4().hex[:6]}")
        tenancy.set_workspace_probe(s, ws.id, kind, devices)
        b = make_brand(s, ws, hits_brand)
        s.add(m.BrandDomain(brand_id=b.id, domain="shopnova.com", is_official=True, kind="official"))
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
            ev = s.scalars(sa.select(m.Evidence).where(m.Evidence.candidate_id == cand.id, m.Evidence.source_type == "probe")).all()
            obs = s.scalars(sa.select(m.Observation).where(m.Observation.candidate_id == cand.id)).all()
            out[cand.canonical_domain] = {
                "finding": f, "signals": dict(cur.signals or {}) if cur else {}, "severity": cur.severity.value if cur else None,
                "probes": {e.request_profile["probe"]: (e.request_profile["profile"], e.request_profile.get("user_agent")) for e in ev},
                "profiles": [o.scanner_profile for o in obs],
            }  # fmt: skip
        return summary, events, out


# ------------------------------------------------------------------------------------------ the settings
def test_the_choices_are_stored_and_the_mobile_proxy_is_built_from_its_own_slot(engine, tmp_path):
    from brandwatch.db.base import make_session_factory

    settings = Settings(_env_file=None, demo_mode=True, evidence_dir=str(tmp_path / "ev"), secret_key="unit-test-secret-0123456789abcdef")
    with make_session_factory(engine)() as s:
        ws = make_workspace(s, f"px-{uuid.uuid4().hex[:6]}")
        assert tenancy.workspace_probe_settings(s, ws.id) == {"proxy_kind": "residential", "devices": "desktop"}  # what it was before
        assert tenancy.set_workspace_probe(s, ws.id, "mobile", "both") == {"proxy_kind": "mobile", "devices": "both"}
        assert tenancy.set_workspace_probe(s, ws.id, "bogus", "nonsense") == {"proxy_kind": "residential", "devices": "desktop"}
        tenancy.set_workspace_probe(s, ws.id, "mobile", "mobile")
        tenancy.set_workspace_mobile_proxy(s, ws.id, {"mode": "manual", "host": "mob.example.net", "port": "9000", "username": "u1"})
        keystore.store_key(s, ws.id, "mobile_proxy_password", "s3cret-mobile", settings)
        cfg = asyncio.run(tenancy.resolve_proxy(s, ws.id, settings))  # the workspace chose mobile
        assert cfg.kind == "mobile" and cfg.enabled and cfg.host == "mob.example.net" and cfg.port == 9000
        assert cfg.url("us") == "http://u1:s3cret-mobile@mob.example.net:9000"  # no Webshare-style country suffix on a mobile proxy
        resi = asyncio.run(tenancy.resolve_proxy(s, ws.id, settings, kind="residential"))
        assert resi.kind == "residential" and not resi.enabled  # the residential slot is empty: the choice decides which one is used
        assert proxy_mod.from_stored_mobile({"mode": "off"}, "x").enabled is False


def test_the_settings_page_has_both_choices_and_saves_them(engine, tmp_path):
    app = _app(engine, tmp_path)
    with TestClient(app):
        ui = _ui(app)
        page = ui.get("/ui/settings").text
        for needle in ('name="proxy_kind" value="residential"', 'name="proxy_kind" value="mobile"', 'name="proxy_kind" value="both"', 'name="devices" value="desktop"',
                       'name="devices" value="mobile"', 'name="devices" value="both"', "MOBILE PROXY", 'name="mobile_host"', 'name="mobile_password"'):
            assert needle in page, needle
        r = ui.post("/ui/settings/proxy", data={"mode": "off", "proxy_kind": "mobile", "devices": "both", "mobile_enabled": "on",
                                                "mobile_host": "mob.example.net", "mobile_port": "9000", "mobile_username": "u1",
                                                "mobile_password": "s3cret-mobile"}, follow_redirects=False)
        assert r.status_code == 303 and "saved=proxy" in r.headers["location"]
        page = ui.get("/ui/settings").text
        import re

        assert re.search(r'name="proxy_kind" value="mobile"\s+checked', page) and re.search(r'name="devices" value="both"\s+checked', page)
        assert 'value="mob.example.net"' in page and "s3cret-mobile" not in page  # the password is never shown again
        ui.post("/ui/settings/proxy", data={"mode": "off", "proxy_kind": "residential", "devices": "desktop"}, follow_redirects=False)  # back to what it was


# ------------------------------------------------------------------------------------------ the probes
def test_a_phone_visit_is_made_only_when_asked_for(engine, tmp_path):
    with _Scenarios(("shopnova-phone1.com", "shopn0va.com", {}, {"cloak": {}})):
        _s, _e, desk = _scan(engine, tmp_path, ["https://shopnova-phone1.com/"], devices="desktop")
        _s, _e, both = _scan(engine, tmp_path, ["https://shopnova-phone1.com/"], devices="both")
    assert "mobile" not in desk["shopnova-phone1.com"]["probes"]
    prof, ua = both["shopnova-phone1.com"]["probes"]["mobile"]
    assert prof == "mobile" and "Android" in ua and "Mobile Safari" in ua  # a phone, from the data-centre IP


def test_a_lure_that_only_a_phone_sees_is_found_and_scored(engine, tmp_path):
    with _Scenarios(("shopnova-phoneonly.com", "shopn0va.com", {}, {"cloak": {"mode": "device", "benign_html": "<html><body><h1>Under maintenance</h1></body></html>"}})):
        _s, events, desk = _scan(engine, tmp_path, ["https://shopnova-phoneonly.com/"], devices="desktop")
        _s, events2, both = _scan(engine, tmp_path, ["https://shopnova-phoneonly.com/"], devices="both")
    # on a desktop-only check the kit shows its harmless page: nothing hidden is found
    assert "device_gating" not in desk["shopnova-phoneonly.com"]["signals"]
    sig = both["shopnova-phoneonly.com"]["signals"]
    assert "device_gating" in sig and "mobile phone" in sig["_details"]["device_gating"]
    assert both["shopnova-phoneonly.com"]["severity"] in ("high", "critical")
    assert any("Cloaking detected" in e.message and "device_gating" in e.message for e in events2)


def test_the_proxy_visit_is_made_as_the_chosen_devices_and_says_which_network(engine, tmp_path):
    with _Scenarios(("shopnova-viaproxy.com", "shopn0va.com", {}, {"cloak": {"mode": "ip", "benign_html": "<html><body><h1>Under maintenance</h1></body></html>"}})):
        _s, events, both = _scan(engine, tmp_path, ["https://shopnova-viaproxy.com/"], devices="both", kind="mobile")
        _s, _e, mob = _scan(engine, tmp_path, ["https://shopnova-viaproxy.com/"], devices="mobile", kind="residential")
        _s, _e, desk = _scan(engine, tmp_path, ["https://shopnova-viaproxy.com/"], devices="desktop", kind="residential")
    b = both["shopnova-viaproxy.com"]
    assert b["probes"]["residential"][0] == "residential" and b["probes"]["residential-mobile"][0] == "residential+mobile"  # one visit per device
    assert "Android" in b["probes"]["residential-mobile"][1] and "Android" not in b["probes"]["residential"][1]
    assert "cloaking_ip_based" in b["signals"] and "mobile-network IP gets the phishing page" in b["signals"]["_details"]["cloaking_ip_based"]
    assert ScannerProfile.MOBILE in b["profiles"]  # the observation says the picture came from a mobile network
    said = [e.message for e in events if e.stage == "cloaking"]
    assert any("through a mobile-network IP" in x and "as a desktop browser and as a phone" in x for x in said), said
    # phone only: no desktop visit through the proxy; residential choice: named so
    assert "residential" not in mob["shopnova-viaproxy.com"]["probes"] and "residential-mobile" in mob["shopnova-viaproxy.com"]["probes"]
    assert sorted(desk["shopnova-viaproxy.com"]["probes"]) == ["bot", "param", "referer", "residential"]  # JSONB keeps no key order


def test_both_proxies_make_one_visit_each_and_the_mobile_one_is_named(engine, tmp_path):
    with _Scenarios(("shopnova-bothnets.com", "shopn0va.com", {}, {"cloak": {"mode": "ip", "benign_html": "<html><body><h1>Under maintenance</h1></body></html>"}})):
        _s, events, out = _scan(engine, tmp_path, ["https://shopnova-bothnets.com/"], devices="both", kind="both")
    probes = out["shopnova-bothnets.com"]["probes"]
    assert probes["residential"][0] == "residential" and probes["mobile-network"][0] == "carrier"  # one desktop visit through each
    assert probes["residential-mobile"][0] == "residential+mobile" and probes["mobile-network-phone"][0] == "carrier+mobile"
    assert "Android" in probes["mobile-network-phone"][1]
    assert "cloaking_ip_based" in out["shopnova-bothnets.com"]["signals"]


def test_every_visit_but_the_crawlers_is_a_person_s_chrome():
    from brandwatch.providers.impl.browser_identity import accept_language, identity
    from brandwatch.providers.mock import _mock_request

    il = identity("il")
    assert il.locale == "he-IL" and il.timezone == "Asia/Jerusalem" and il.languages[:2] == ["he-IL", "he"]
    assert accept_language("he-IL") == "he-IL,he;q=0.9,en-US;q=0.8,en;q=0.7" and accept_language("en-US") == "en-US,en;q=0.9"
    phone = identity("zz", mobile=True)  # an unknown country: a US browser
    assert phone.locale == "en-US" and phone.headers()["sec-ch-ua-mobile"] == "?1" and phone.ua_override()["userAgentMetadata"]["model"] == "Pixel 8"
    assert "HeadlessChrome" not in il.headers()["sec-ch-ua"] and "navigator, 'languages'" in il.init_script()
    _ua, crawler = _mock_request("bot")
    _ua, person = _mock_request("residential")
    assert "accept-language" not in crawler and "sec-ch-ua" not in crawler  # the control stays an honest crawler
    assert person["accept-language"] and '"Google Chrome"' in person["sec-ch-ua"]


def test_a_proxy_set_in_settings_is_what_the_probe_looks_for(engine):
    # the allowance used to look at an environment variable only: a proxy entered in the UI was never used
    from types import SimpleNamespace

    from brandwatch.detection.cloaking import residential_allowance

    class Cfg:
        residential_probe = "gated"

    class Limits:
        max_residential_gb = 1.0

    def ctx(enabled, kind="residential", demo=False):
        return SimpleNamespace(
            config=SimpleNamespace(detection=Cfg, economic_limits=Limits), settings=SimpleNamespace(demo_mode=demo, residential_proxy_url=None),
            extra={"proxy_enabled": enabled, "proxy_kind": kind}, session=None, workspace_id=uuid.uuid4())

    assert residential_allowance(ctx(False)) == (False, "no residential proxy configured (Settings → Proxy)")
    assert residential_allowance(ctx(False, "mobile")) == (False, "no mobile proxy configured (Settings → Proxy)")
    assert residential_allowance(ctx(False, demo=True))[0] is True


def test_the_sandboxed_browser_really_is_a_phone_when_asked():
    import http.server
    import ipaddress
    import socketserver
    import threading

    import pytest
    from tests.test_phase2 import _chromium_available

    from brandwatch.providers.impl import playwright_fetcher as pf

    if not _chromium_available():
        pytest.skip("Playwright Chromium not installed")

    class H(http.server.BaseHTTPRequestHandler):
        def log_message(self, *a, **k):
            pass

        def do_GET(self):  # noqa: N802 - http.server API
            phone = "Android" in (self.headers.get("User-Agent") or "")
            # the kind that targets phones: the lure for a mobile browser, a harmless page for everybody else
            body = ("<html><head><title>Sign in</title></head><body><form><input type=password></form>" + "<p>Sign in to your account. </p>" * 20
                    if phone else "<html><head><title>Maintenance</title></head><body>" + "<p>Back soon. </p>" * 30)
            body += '<p id="w"></p><script>document.getElementById("w").textContent = "screen=" + screen.width + " touch=" + (navigator.maxTouchPoints > 0)</script></body></html>'
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body.encode())))
            self.end_headers()
            self.wfile.write(body.encode())

    class Srv(socketserver.ThreadingTCPServer):
        allow_reuse_address = True

    srv = Srv(("127.0.0.1", 0), H)
    port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        fetcher = pf.PlaywrightBrowserFetcher(
            resolver=lambda h: [ipaddress.ip_address("93.184.216.34")] if h == "phone.test" else [],
            launch_args=[f"--host-resolver-rules=MAP phone.test 127.0.0.1:{port}"],
        )
        desk = asyncio.run(fetcher.fetch("http://phone.test/", "datacenter")).data
        phone = asyncio.run(fetcher.fetch("http://phone.test/", "mobile")).data
        assert desk["title"] == "Maintenance" and "touch=false" in desk["dom"] and "Android" not in desk["user_agent"]
        assert phone["title"] == "Sign in" and "touch=true" in phone["dom"] and "screen=412" in phone["dom"] and "Mobile Safari" in phone["user_agent"]
        with pytest.raises(Exception, match="no residential / mobile proxy configured"):
            asyncio.run(fetcher.fetch("http://phone.test/", "residential+mobile"))  # a phone through the proxy needs the proxy
    finally:
        srv.shutdown()
