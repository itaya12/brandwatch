"""Dashboard (spec §14 tab 1, §12 metrics): KPIs, distributions, geo points for the globe, live feed."""

from __future__ import annotations

import uuid

import pytest
import sqlalchemy as sa
from fastapi.testclient import TestClient

import brandwatch.db.models as m
from brandwatch.api.main import create_app
from brandwatch.config.settings import Settings

ADMIN = {"email": "admin@test.local", "password": "test-admin-password"}


@pytest.fixture
def client(engine, tmp_path):
    settings = Settings(_env_file=None, demo_mode=True, evidence_dir=str(tmp_path / "ev"), bootstrap_admin_email=ADMIN["email"],
                        bootstrap_admin_password=ADMIN["password"], secret_key="unit-test-secret-0123456789abcdef")  # fmt: skip
    app = create_app(settings=settings, engine=engine)
    with TestClient(app) as c:
        token = c.post("/api/auth/login", json=ADMIN).json()["access_token"]
        c.headers["Authorization"] = f"Bearer {token}"
        yield c, app


def test_dashboard_payload_and_geo_points(client, engine):
    c, app = client
    brand = c.post(
        "/api/brands", json={"name": f"Dash {uuid.uuid4().hex[:4]}", "domains": ["shopnova.com"]}
    ).json()
    job = c.post(
        f"/api/brands/{brand['id']}/scan-urls",
        json={
            "urls": [
                "https://shopn0va.com/",
                "https://shopnowa.com/",
                "https://shopnova-partners.com/",
            ]
        },
    ).json()["job_id"]
    app.state.queue.wait(uuid.UUID(job), timeout=120)
    f = next(
        x
        for x in c.get("/api/findings", params={"brand_id": brand["id"]}).json()
        if x["hostname"] == "shopn0va.com"
    )
    # this test measures a plain scan: switch off the automatic mapping and investigation on confirm
    cfg = c.get(f"/api/brands/{brand['id']}").json()["config"]
    c.patch(
        f"/api/brands/{brand['id']}/config",
        json={"detection": {**cfg["detection"], "auto_map_on_confirm": False, "auto_investigate_on_confirm": False}},
    )
    assert (
        c.post(f"/api/findings/{f['id']}/confirm", json={"reason": "clone"}).json()["map_job_id"]
        is None
    )

    d = c.get("/api/dashboard", params={"brand_id": brand["id"]}).json()
    k = d["kpis"]
    assert d["brand"]["id"] == brand["id"]
    assert k["candidates_total"] == 3 and k["findings_confirmed"] == 1 and k["findings_open"] == 1
    assert (
        k["critical_open"] + k["findings_confirmed"] >= 1
        and k["scans_today"] == 1
        and k["candidates_scanned_today"] == 3
    )
    assert k["evidence_rows"] > 10 and k["screenshots"] == 3 and k["cost_today_usd"] == 0.0
    assert sum(d["severity_distribution"].values()) == k["findings_open"]
    assert (
        sum(d["score_histogram"]) == 2
        and len(d["scans_per_day"]) == 14
        and d["scans_per_day"][-1]["jobs"] == 1
    )
    assert {p["stage"] for p in d["pipeline"]} >= {
        "baseline",
        "discovery",
        "enrichment_analysis_scoring",
    }
    assert (
        d["source_effectiveness"][0]["source"] == "manual"
        and d["source_effectiveness"][0]["findings"] == 2
    )
    assert d["recent_criticals"] and d["recent_criticals"][0]["hostname"] in (
        "shopn0va.com",
        "shopnowa.com",
    )
    assert (
        d["metrics"]["labels"] == 1
        and d["metrics"]["precision"] == 1.0
        and d["metrics"]["mttc_hours"] is not None
    )
    assert d["metrics"]["mttd_hours"] is not None  # domain age from WHOIS → time-to-detect
    # geo: the two phishing hosts resolve to geolocated kit servers (Amsterdam / Moscow in the recorded data)
    pts = {p["hostname"]: p for p in d["geo"]["points"]}
    assert pts["shopn0va.com"]["city"] == "Amsterdam" and pts["shopnowa.com"]["country"] == "RU"
    assert pts["shopn0va.com"]["state"] == "confirmed" and d["geo"]["home"]["label"] == "ShopNova HQ · Austin"
    assert (
        "shopnova-partners.com" not in pts
    )  # watchlist-only candidates are not threats on the globe
    assert d["system"]["demo_mode"] is True and d["system"]["providers"]["geo"] == ["mock:ipapi"]
    # ip_addresses rows carry the geolocation
    with app.state.session_factory() as s:
        ip = s.scalars(sa.select(m.IpAddress).where(m.IpAddress.ip == "203.0.113.66")).one()
        assert ip.lat and ip.geo_source == "mock:ipapi" and ip.org

    feed = c.get("/api/dashboard/feed", params={"brand_id": brand["id"], "limit": 10}).json()
    assert len(feed) == 10 and feed[0]["stage"] == "summary" and feed[0]["brand"] == brand["name"]

    # whole-workspace view works too and the UI renders the globe page
    assert c.get("/api/dashboard").json()["kpis"]["brands"] >= 1
    ui = TestClient(app)
    r = ui.post("/ui/login", data=ADMIN, follow_redirects=False)
    assert r.headers["location"] == "/ui/dashboard"
    page = ui.get(f"/ui/dashboard?brand_id={brand['id']}")
    assert page.status_code == 200
    for needle in (
        "BRAND MONITOR",
        "globe.gl",
        "canvasGlobe",
        "Live feed",
        "What the system does",
        "Budget meter",
        "shopn0va.com",
    ):
        assert needle in page.text, needle
    assert ui.get("/ui", follow_redirects=False).headers["location"] == "/ui/dashboard"


def test_a_cdn_edge_is_not_a_place_on_the_globe_and_not_a_country(client, engine):
    """www.cryptohopper.ai resolved to CloudFront addresses that were "in Tel Aviv": a CDN answers with the node nearest to whoever asks,
    so the place is the asker's, not the site's. Such a site is not plotted; the page says how many are behind a CDN."""
    from brandwatch.detection import hosting

    assert hosting.is_cdn("AWS CloudFront (GLOBAL)") and hosting.is_cdn("Cloudflare, Inc.") and hosting.is_cdn(None, "104.21.26.55")
    assert not hosting.is_cdn("Gransy s.r.o") and not hosting.is_cdn("AWS EC2 (us-west-1)") and not hosting.is_cdn(None, "203.0.113.5")
    c, app = client
    brand = c.post("/api/brands", json={"name": f"Cdn {uuid.uuid4().hex[:4]}", "domains": ["shopnova.com"]}).json()
    job = c.post(f"/api/brands/{brand['id']}/scan-urls", json={"urls": ["https://shopn0va.com/", "https://shopnowa.com/"]}).json()["job_id"]
    app.state.queue.wait(uuid.UUID(job), timeout=120)
    before = {p["hostname"] for p in c.get("/api/dashboard", params={"brand_id": brand["id"]}).json()["geo"]["points"]}
    assert {"shopn0va.com", "shopnowa.com"} <= before
    from sqlalchemy import update

    from brandwatch.db.models import IpAddress

    with app.state.session_factory() as s:  # both kit servers turn out to be a CDN's edge
        s.execute(update(IpAddress).values(org="AWS CloudFront (GLOBAL)", city="Tel Aviv", country="IL"))
        s.commit()
    d = c.get("/api/dashboard", params={"brand_id": brand["id"]}).json()["geo"]
    assert not {"shopn0va.com", "shopnowa.com"} & {p["hostname"] for p in d["points"]}
    assert d["cdn_hidden"] >= 2 and "IL" not in d["countries"]


def test_the_investigation_does_not_claim_a_country_for_a_cdn_edge(session):
    from tests.conftest import make_workspace

    from brandwatch.detection import intel as intel_mod

    ws = make_workspace(session, f"cdn-{uuid.uuid4().hex[:6]}")
    intel_mod.put_row(session, ws.id, "ip", "3.169.64.27", "geo", "report", {"ip": "3.169.64.27", "country": "IL", "city": "Tel Aviv", "org": "AWS CloudFront (GLOBAL)"})
    intel_mod.put_row(session, ws.id, "ip", "198.51.100.7", "geo", "report", {"ip": "198.51.100.7", "country": "NL", "city": "Amsterdam", "org": "Gransy s.r.o"})
    edge = intel_mod._ip_view(session, ws.id, "3.169.64.27")
    assert edge["country"] is None and edge["country_name"] is None and edge["city"] is None
    assert edge["cdn"] == "AWS CloudFront (GLOBAL)" and edge["edge"] == {"country": "IL", "city": "Tel Aviv"}  # kept as a note, never as the place
    server = intel_mod._ip_view(session, ws.id, "198.51.100.7")
    assert server["country"] == "NL" and server["city"] == "Amsterdam" and server["cdn"] is None


def test_the_arcs_do_not_start_at_a_cdn_edge(session, monkeypatch):
    import socket
    from types import SimpleNamespace

    from tests.conftest import make_brand, make_workspace

    import brandwatch.db.models as m
    from brandwatch.api import dashboard

    ws = make_workspace(session, f"home-cdn-{uuid.uuid4().hex[:6]}")
    b = make_brand(session, ws, "Acme")
    session.add(m.BrandDomain(brand_id=b.id, domain="acme-edge.example", is_official=True, kind="official"))
    session.flush()
    monkeypatch.setattr(socket, "getaddrinfo", lambda *a, **k: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("104.21.26.55", 443))])
    dashboard._HOME_CACHE.clear()

    async def locate(ip):
        return SimpleNamespace(ok=True, data={"lat": 43.65, "lon": -79.38, "city": "Toronto", "country": "CA", "org": "Cloudflare, Inc."})

    req = SimpleNamespace(app=SimpleNamespace(state=SimpleNamespace(providers=SimpleNamespace(geo=lambda: SimpleNamespace(locate=locate)))))
    assert dashboard._brand_home(session, req, [b.id], [{"hostname": "x"}]) is None  # Cloudflare's Toronto edge is not where the brand is
