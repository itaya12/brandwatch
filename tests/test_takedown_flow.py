"""Confirm → auto-map, takedown call-to-action, dashboard action panel, the Takedowns page as the
list of every confirmed site, one-click Known legit, and the takedown channels / report portals."""

import uuid

from fastapi.testclient import TestClient

from brandwatch.api.main import create_app
from brandwatch.config.settings import Settings
from brandwatch.detection import takedown_channels as tc

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


def _ui(app):
    ui = TestClient(app)
    ui.post("/ui/login", data={**ADMIN, "next": "/ui/findings"}, follow_redirects=False)
    return ui


def _confirmed_finding(app, c, brand_name):
    brand = c.post("/api/brands", json={"name": brand_name, "domains": ["shopnova.com"]}).json()
    job = c.post(
        f"/api/brands/{brand['id']}/scan-urls", json={"urls": ["https://shopn0va.com/"]}
    ).json()["job_id"]
    app.state.queue.wait(uuid.UUID(job), timeout=120)
    f = c.get("/api/findings", params={"brand_id": brand["id"]}).json()[0]
    return brand, f


def test_confirm_auto_maps_and_cta_and_dashboard_panel(engine, tmp_path):
    app = _app(engine, tmp_path)
    with TestClient(app):
        c = _api(app)
        brand, f = _confirmed_finding(app, c, f"Auto {uuid.uuid4().hex[:4]}")
        ui = _ui(app)
        # confirm through the UI form → the brand's default maps the infrastructure right away
        r = ui.post(
            f"/ui/findings/{f['id']}/verdict",
            data={"action": "confirm", "reason": "clone"},
            follow_redirects=False,
        )
        assert r.status_code == 303
        page = ui.get(f"/ui/findings/{f['id']}").text
        assert (
            "Confirmed phishing" in page and "DRAFT TAKEDOWN REQUEST" in page
        )  # the call to action
        assert ("mapping now" in page) or ("mapped → open the map" in page)
        api_f = c.get(f"/api/findings/{f['id']}").json()
        # an explicit map request reuses the running job (never two in parallel)
        r2 = c.post(f"/api/findings/{f['id']}/investigate")
        assert r2.status_code == 202
        app.state.queue.wait(uuid.UUID(r2.json()["job_id"]), timeout=120)
        assert c.get(f"/api/findings/{f['id']}").json()["campaign_id"]
        camps = c.get("/api/campaigns", params={"brand_id": brand["id"]}).json()
        assert len(camps) == 1
        # attack-infrastructure page lists the confirmed site as mapped
        page = ui.get(f"/ui/campaigns?brand_id={brand['id']}").text
        assert (
            "Confirmed phishing sites" in page
            and "mapped → open" in page
            and "shopn0va.com" in page
        )
        # dashboard: action panel says one confirmed site has no takedown yet
        dash = ui.get(f"/ui/dashboard?brand_id={brand['id']}").text
        assert 'id="action-required"' in dash and "with no takedown request" in dash
        assert (
            c.get("/api/dashboard", params={"brand_id": brand["id"]}).json()["kpis"][
                "confirmed_no_takedown"
            ]
            == 1
        )
        # takedowns page lists the confirmed site with "no takedown yet" + the CTA button
        td = ui.get("/ui/takedowns?state=none").text
        assert "shopn0va.com" in td and "Draft request" in td
        # draft it from there → row shows the state, action panel item goes away
        r = ui.post(f"/ui/findings/{f['id']}/takedown", follow_redirects=False)
        tid = r.headers["location"].rsplit("/", 1)[-1]
        td = ui.get(f"/ui/takedowns?brand_id={brand['id']}").text
        assert "draft → open" in td and "no takedown yet" not in td.split('<table class="rwd">')[1]
        assert (
            c.get("/api/dashboard", params={"brand_id": brand["id"]}).json()["kpis"][
                "confirmed_no_takedown"
            ]
            == 0
        )
        page = ui.get(f"/ui/findings/{f['id']}").text
        assert f"/ui/takedowns/{tid}" in page and "TAKEDOWN · DRAFT" in page
        assert api_f["finding"]["state"] == "confirmed"


def test_auto_map_can_be_switched_off_per_brand(engine, tmp_path):
    app = _app(engine, tmp_path)
    with TestClient(app):
        c = _api(app)
        brand, f = _confirmed_finding(app, c, f"NoAuto {uuid.uuid4().hex[:4]}")
        cfg = c.get(f"/api/brands/{brand['id']}").json()["config"]
        assert cfg["detection"]["auto_map_on_confirm"] is True
        r = c.patch(
            f"/api/brands/{brand['id']}/config",
            json={"detection": {**cfg["detection"], "auto_map_on_confirm": False}},
        )
        assert r.status_code == 200, r.text
        out = c.post(f"/api/findings/{f['id']}/confirm", json={"reason": "clone"}).json()
        assert out["map_job_id"] is None
        ui = _ui(app)
        page = ui.get(f"/ui/campaigns?brand_id={brand['id']}").text
        assert "not mapped" in page and "Map now" in page


def test_known_legit_is_one_click(engine, tmp_path):
    app = _app(engine, tmp_path)
    with TestClient(app):
        c = _api(app)
        brand = c.post(
            "/api/brands",
            json={"name": f"Click {uuid.uuid4().hex[:4]}", "domains": ["shopnova.com"]},
        ).json()
        job = c.post(
            f"/api/brands/{brand['id']}/scan-urls",
            json={"urls": ["https://shopnova-partners.com/"]},
        ).json()["job_id"]
        app.state.queue.wait(uuid.UUID(job), timeout=120)
        ui = _ui(app)
        page = ui.get(f"/ui/candidates?brand_id={brand['id']}").text
        assert (
            "Known legit ✓" in page
            and 'id="bulkform"' in page  # several at once, too
            and 'name="whitelist" value="on"' in page
        )
        cid = c.get("/api/candidates", params={"brand_id": brand["id"]}).json()[0]["id"]
        r = ui.post(f"/ui/candidates/{cid}/dismiss", data={"next": f"/ui/candidates?brand_id={brand['id']}", "whitelist": "on", "reason": "known legitimate domain"}, follow_redirects=False)  # fmt: skip
        assert r.status_code == 303
        assert c.get("/api/candidates", params={"brand_id": brand["id"]})
        assert any(
            w["kind"] == "known_legit"
            for w in c.get(f"/api/brands/{brand['id']}").json()["whitelist"]
        )


def test_takedown_channels_and_report_portals(engine, tmp_path):
    app = _app(engine, tmp_path)
    with TestClient(app):
        c = _api(app)
        brand, f = _confirmed_finding(app, c, f"Chan {uuid.uuid4().hex[:4]}")
        c.post(f"/api/findings/{f['id']}/confirm", json={"reason": "clone"})
        # intel cache for the site (demo mocks: Cloudflare-like data is not in the fixture, so seed a known desk)
        inv = c.post(f"/api/findings/{f['id']}/intel").json()["job_id"]
        app.state.queue.wait(uuid.UUID(inv), timeout=120)
        tid = c.post(f"/api/findings/{f['id']}/takedown").json()["id"]
        t = c.get(f"/api/takedowns/{tid}").json()
        assert t["channels"] == {} and t["reported_count"] == 0  # resolved lazily by the page
        ui = _ui(app)
        page = ui.get(f"/ui/takedowns/{tid}").text
        assert "Where to send it" in page and "Report the site everywhere" in page
        assert (
            "1 · Registrar" in page
            and "2 · Hosting provider" in page
            and "3 · CDN / DNS provider" in page
        )
        assert (
            "203.0.113.66" in page and "BulletproofHost BV" in page
        )  # hosting from the intel cache
        assert (
            "Google Safe Browsing" in page
            and "Netcraft" in page
            and "ESET" in page
            and "safebrowsing/report_phish/?url=https%3A%2F%2Fshopn0va.com" in page
        )
        assert "mailto:reportphishing@apwg.org" in page
        # record: hosting contact + sent, registrar contact saved, two portals ticked
        r = ui.post(
            f"/ui/takedowns/{tid}/channel",
            data={
                "channel": "hosting:203.0.113.66",
                "contact": "abuse@bulletproof.example",
                "mark": "sent",
            },
            follow_redirects=False,
        )
        assert r.status_code == 303
        ui.post(
            f"/ui/takedowns/{tid}/channel",
            data={
                "channel": "registrar",
                "contact": "abuse@mock-registrar.example",
                "mark": "save",
            },
            follow_redirects=False,
        )
        ui.post(
            f"/ui/takedowns/{tid}/reported",
            data={"portal": "google_safebrowsing"},
            follow_redirects=False,
        )
        ui.post(
            f"/ui/takedowns/{tid}/reported", data={"portal": "netcraft"}, follow_redirects=False
        )
        t = c.get(f"/api/takedowns/{tid}").json()
        assert t["channels_sent"] == ["hosting:203.0.113.66"] and t["reported_count"] == 2
        assert t["channels"]["sent"]["hosting:203.0.113.66"]["to"] == "abuse@bulletproof.example"
        assert t["abuse_contact"] == "abuse@mock-registrar.example"
        page = ui.get(f"/ui/takedowns/{tid}").text
        assert (
            "✓ 203.0.113.66" in page
            and '<span class="rep-count">2</span> of' in page
            and "mailto:abuse@bulletproof.example" in page
        )
        # untick one
        ui.post(
            f"/ui/takedowns/{tid}/reported", data={"portal": "netcraft"}, follow_redirects=False
        )
        assert c.get(f"/api/takedowns/{tid}").json()["reported_count"] == 1
        assert (
            "unknown report portal"
            in ui.get(
                ui.post(
                    f"/ui/takedowns/{tid}/reported", data={"portal": "nope"}, follow_redirects=False
                ).headers["location"]
            ).text
        )
        # the list shows the counts
        lst = ui.get("/ui/takedowns").text
        assert "1 of " in lst and "portal(s)" in lst and "1 channel(s)" in lst


def test_known_desks_and_whois_parsing():
    assert (
        tc.known_desk("CLOUDFLARENET")["name"] == "Cloudflare"
        and tc.known_desk("CLOUDFLARENET")["cdn"]
    )
    assert tc.known_desk("AMAZON-02")["email"] == "abuse@amazonaws.com"
    assert tc.known_desk("Some Random Hosting Ltd") is None
    assert (
        tc.known_desk("natasha.ns.cloudflare.com")["form"]
        == "https://abuse.cloudflare.com/phishing"
    )
    whois = "inetnum: 1.2.3.0 - 1.2.3.255\norg-name: Example Host\nabuse-mailbox: abuse@example-host.net\n"
    assert tc._abuse_from_whois(whois) == "abuse@example-host.net"
    assert (
        tc._abuse_from_whois("OrgAbuseEmail: abuse@arin-style.example\n")
        == "abuse@arin-style.example"
    )
    assert tc._abuse_from_whois("nothing here") is None
    links = tc.portal_links("https://evil.example/login", "evil.example", "subj", "body")
    g = next(p for p in links if p["key"] == "google_safebrowsing")
    assert g["link"].endswith("?url=https%3A%2F%2Fevil.example%2Flogin")
    assert tc.mailto(None, "s", "b") is None and tc.mailto("a@b.c", "s", "b").startswith(
        "mailto:a@b.c?subject=s&body=b"
    )
    assert len(tc.mailto("a@b.c", "s", "x" * 5000)) < 2300  # long bodies are cut for mail clients


def test_review_fixes_validation_and_safe_confirms(engine, tmp_path):
    # desks: a Linode VPS is a host, not a CDN edge; Akamai proper still is
    assert tc.known_desk("Linode, LLC")["name"].startswith("Linode") and not tc.known_desk(
        "Linode, LLC"
    ).get("cdn")
    assert tc.known_desk("AKAMAI-LINODE-AP")["name"].startswith("Linode")
    assert tc.known_desk("Akamai Technologies")["cdn"] is True
    # mailto: plain addresses only, encoded link short enough for Outlook
    assert (
        tc.mailto("javascript:alert(1)", "s", "b") is None
        and tc.mailto("a@b.c?cc=x@y.z", "s", "b") is None
    )
    assert len(tc.mailto("a@b.c", "s" * 50, "é" * 5000)) <= 1900
    app = _app(engine, tmp_path)
    with TestClient(app):
        c = _api(app)
        brand, f = _confirmed_finding(app, c, f"Fix {uuid.uuid4().hex[:4]}")
        c.post(f"/api/findings/{f['id']}/confirm", json={"reason": "clone"})
        tid = c.post(f"/api/findings/{f['id']}/takedown").json()["id"]
        ui = _ui(app)
        # invalid contact / unknown channel → error shown, nothing stored
        r = ui.post(
            f"/ui/takedowns/{tid}/channel",
            data={"channel": "registrar", "contact": "not an email", "mark": "save"},
            follow_redirects=False,
        )
        assert "plain%20e-mail" in r.headers["location"]
        r = ui.post(
            f"/ui/takedowns/{tid}/channel",
            data={"channel": "hosting:9.9.9.9", "contact": "a@b.c", "mark": "sent"},
            follow_redirects=False,
        )
        assert "unknown%20channel" in r.headers["location"]
        assert c.get(f"/api/takedowns/{tid}").json()["channels"] == {}
        # an override survives re-resolution and is marked as the analyst's
        ui.post(
            f"/ui/takedowns/{tid}/channel",
            data={"channel": "cdn", "contact": "abuse@dns-host.example", "mark": "save"},
            follow_redirects=False,
        )
        page = ui.get(f"/ui/takedowns/{tid}").text
        assert "abuse@dns-host.example" in page and "mailto:abuse@dns-host.example" in page
        assert c.get(f"/api/takedowns/{tid}").json()["channels"]["overrides"] == {
            "cdn": "abuse@dns-host.example"
        }
        # the questions live in data attributes (apostrophes cannot break them) and the interface's own dialog asks them
        wl = ui.get(f"/ui/candidates?brand_id={brand['id']}").text
        assert 'data-confirm="Known legit: remove' in wl and "confirm('Known legit" not in wl
        bp = ui.get(f"/ui/brands/{brand['id']}").text
        assert (
            f'data-confirm-expect="{brand["name"]}"' in bp
            and "|tojson" not in bp.split("Start over")[1][:600]
        )
        # activity log links takedown drafts and scan jobs
        act = ui.get("/ui/activity").text
        assert f"/ui/takedowns/{tid}" in act


def test_report_portals_are_well_formed_and_link_to_the_form():
    from brandwatch.detection import takedown_channels as tc

    keys = [p["key"] for p in tc.REPORT_PORTALS]
    assert len(keys) == len(set(keys)) and {"google_safebrowsing", "netcraft", "apwg", "ncsc_uk", "zscaler"} <= set(keys)
    for p in tc.REPORT_PORTALS:
        assert p["group"] in tc.PORTAL_GROUPS and p["note"] and p["url"].startswith(("https://", "mailto:")), p
    links = {x["key"]: x["link"] for x in tc.portal_links("https://evil.example/login", "evil.example", "s", "b")}
    assert links["google_safebrowsing"].endswith("?url=https%3A%2F%2Fevil.example%2Flogin")
    assert links["kaspersky"] == "https://opentip.kaspersky.com/evil.example/"
    assert links["microsoft_smartscreen"].endswith("report-unsafe-site-guest")  # the form itself, no sign-in
