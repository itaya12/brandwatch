"""Site & network intel: VirusTotal/urlscan client additions (respx), TLS certificate parsing,
flags, VT pacing, and the end-to-end demo flow (job → cache → API view → UI pages)."""

import uuid
from datetime import UTC, datetime, timedelta

import httpx
import respx
from fastapi.testclient import TestClient

from brandwatch.api.main import create_app
from brandwatch.config.settings import Settings
from brandwatch.db.enums import ProviderStatus
from brandwatch.detection import intel as intel_mod
from brandwatch.providers.impl.clients import UrlscanClient, VirusTotalClient
from brandwatch.security import tls_probe
from brandwatch.ui import flags

ADMIN = {"email": "admin@test.local", "password": "test-admin-password"}
VT = "https://www.virustotal.com/api/v3"


# --------------------------------------------------------------------------------------------
# clients
# --------------------------------------------------------------------------------------------
@respx.mock
async def test_virustotal_reports_and_relationships():
    respx.get(f"{VT}/domains/evil.example").mock(return_value=httpx.Response(200, json={"data": {"id": "evil.example", "attributes": {
        "last_analysis_stats": {"malicious": 9, "suspicious": 1, "harmless": 60, "undetected": 22},
        "last_dns_records": [{"type": "A", "ttl": 300, "value": "104.21.37.218"}],
        "last_https_certificate": {"subject": {"CN": "evil.example"}, "issuer": {"O": "Google Trust Services", "CN": "WE1"},
                                   "validity": {"not_before": "2026-09-22 15:39:00", "not_after": "2026-12-21 16:38:57"},
                                   "thumbprint_sha256": "ab" * 32, "extensions": {"subject_alternative_name": ["evil.example"]}},
        "whois": "Registrar: NICENIC\\n", "jarm": "27d40d", "categories": {"Sophos": "phishing"}}}}))  # fmt: skip
    respx.get(f"{VT}/ip_addresses/104.21.37.218").mock(return_value=httpx.Response(200, json={"data": {"attributes": {
        "country": "US", "asn": 13335, "as_owner": "CLOUDFLARENET", "network": "104.16.0.0/12",
        "last_analysis_stats": {"malicious": 0, "harmless": 90, "undetected": 2}}}}))  # fmt: skip
    respx.get(f"{VT}/ip_addresses/104.21.37.218/resolutions").mock(return_value=httpx.Response(200, json={
        "data": [{"id": "x", "type": "resolution", "attributes": {"host_name": "other-site.example", "date": 1760000000,
                                                                    "host_name_last_analysis_stats": {"malicious": 4, "harmless": 80, "undetected": 8}}}],
        "meta": {"count": 1, "cursor": "next-1"}}))  # fmt: skip
    respx.get(f"{VT}/domains/evil.example/historical_whois").mock(
        return_value=httpx.Response(403, json={"error": {"code": "ForbiddenError"}})
    )
    vt = VirusTotalClient("k", client=httpx.AsyncClient())

    d = await vt.domain_report("evil.example")
    assert (
        d.status is ProviderStatus.POSITIVE and d.data["positives"] == 10 and d.data["total"] == 92
    )
    assert d.data["attributes"]["last_dns_records"][0]["value"] == "104.21.37.218"
    ip = await vt.ip_report("104.21.37.218")
    assert (
        ip.data["attributes"]["as_owner"] == "CLOUDFLARENET"
        and ip.status is ProviderStatus.NEGATIVE
    )
    rel = await vt.relationship("ip_addresses", "104.21.37.218", "resolutions", limit=100)
    assert (
        rel.data["items"][0]["host_name"] == "other-site.example"
        and rel.data["next_cursor"] == "next-1"
    )
    assert (
        rel.data["items"][0]["host_name_last_analysis_stats"]["malicious"] == 4
    )  # detections come with the list
    # a premium-only relationship is "not applicable", never an auth failure that disables the key
    hw = await vt.relationship("domains", "evil.example", "historical_whois")
    assert hw.status is ProviderStatus.NOT_APPLICABLE and hw.data["note"] == "premium_only"


@respx.mock
async def test_urlscan_submit_search_and_screenshot():
    respx.post("https://urlscan.io/api/v1/scan/").mock(
        return_value=httpx.Response(
            200,
            json={
                "uuid": "abc-123",
                "result": "https://urlscan.io/result/abc-123/",
                "visibility": "unlisted",
            },
        )
    )
    respx.get("https://urlscan.io/api/v1/search/").mock(return_value=httpx.Response(200, json={"total": 1, "results": [
        {"page": {"url": "https://clone.example/login", "domain": "clone.example", "ip": "1.2.3.4", "country": "DE", "title": "Sign in"},
         "task": {"uuid": "t-1", "time": "2026-10-01T10:00:00Z"}, "verdicts": {"malicious": True}}]}))  # fmt: skip
    us = UrlscanClient("key", client=httpx.AsyncClient())
    sub = await us.submit("https://evil.example/")
    assert sub.ok and sub.data["task_id"] == "abc-123"
    assert UrlscanClient.screenshot_url("abc-123") == "https://urlscan.io/screenshots/abc-123.png"
    srch = await us.search("hash:deadbeef")
    assert (
        srch.data["results"][0]["domain"] == "clone.example"
        and srch.data["results"][0]["malicious"] is True
    )
    assert (
        await UrlscanClient(None, client=httpx.AsyncClient()).submit("https://x.example/")
    ).status is ProviderStatus.NOT_APPLICABLE


def test_tls_certificate_parsing_from_a_self_signed_cert():
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "3commasgcc.com")])
    now = datetime.now(UTC)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(0x5E4C39).not_valid_before(now - timedelta(days=1)).not_valid_after(now + timedelta(days=89))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName("3commasgcc.com"), x509.DNSName("www.3commasgcc.com")]), critical=False)
            .sign(key, hashes.SHA256()))  # fmt: skip
    info = tls_probe.parse_certificate(cert.public_bytes(serialization.Encoding.DER))
    assert info["subject_cn"] == "3commasgcc.com" and info["sans"] == [
        "3commasgcc.com",
        "www.3commasgcc.com",
    ]
    assert (
        info["serial"] == "5e4c39"
        and len(info["sha256"]) == 64
        and "ECDSA" in info["signature_algorithm"].upper()
    )
    assert info["not_after"] > info["not_before"]


def test_flags_and_country_names():
    assert flags.country_name("us") == "United States" and flags.country_name(None) == "unknown"
    img = str(flags.flag_img("NL"))
    assert (
        'src="https://flagcdn.com/w20/nl.png"' in img and 'alt="NL"' in img and "Netherlands" in img
    )
    assert "flag-none" in str(flags.flag_img(""))


async def test_vt_pacer_sliding_window():
    slept: list[float] = []

    async def fake_sleep(d: float) -> None:
        slept.append(d)

    p = intel_mod._Pacer(4, sleep=fake_sleep)
    for _ in range(4):
        await p.wait()
    assert slept == []  # the first 4 calls are immediate
    await p.wait()  # the 5th must wait for the oldest stamp to leave the 60s window
    assert len(slept) == 1 and 59 < slept[0] <= 60.5


# --------------------------------------------------------------------------------------------
# end to end (demo mode: mocks, no network)
# --------------------------------------------------------------------------------------------
def test_intel_job_cache_views_and_pages(engine, tmp_path):
    settings = Settings(_env_file=None, demo_mode=True, evidence_dir=str(tmp_path / "ev"), bootstrap_admin_email=ADMIN["email"],
                        bootstrap_admin_password=ADMIN["password"], secret_key="unit-test-secret-0123456789abcdef")  # fmt: skip
    app = create_app(settings=settings, engine=engine)
    with TestClient(app) as c:
        token = c.post("/api/auth/login", json=ADMIN).json()["access_token"]
        c.headers["Authorization"] = f"Bearer {token}"
        brand = c.post(
            "/api/brands",
            json={"name": f"Intel {uuid.uuid4().hex[:4]}", "domains": ["shopnova.com"]},
        ).json()
        job = c.post(
            f"/api/brands/{brand['id']}/scan-urls", json={"urls": ["https://shopn0va.com/"]}
        ).json()["job_id"]
        app.state.queue.wait(uuid.UUID(job), timeout=120)
        f = c.get("/api/findings", params={"brand_id": brand["id"]}).json()[0]

        r = c.post(f"/api/findings/{f['id']}/intel")
        assert r.status_code == 202
        app.state.queue.wait(uuid.UUID(r.json()["job_id"]), timeout=120)
        assert c.get(f"/api/jobs/{r.json()['job_id']}").json()["state"] == "done"

        v = c.get(f"/api/findings/{f['id']}/intel").json()
        assert (
            v["detections"]["positives"] == 8
            and v["detections"]["total"] == 90
            and v["detections"]["engines"][0]["category"] == "malicious"
        )
        assert {rec["type"] for rec in v["dns"]["records"]} >= {"A", "NS", "MX", "SOA"}
        assert (
            v["certificate"]["subject_cn"] == "shopn0va.com"
            and v["certificate"]["validity_pct"] is not None
        )
        assert v["rdap"]["registrar"] == "Mock Registrar LLC"
        rel = v["relations"]
        assert (
            rel["resolutions"][0]["ip"] == "203.0.113.66"
            and rel["resolutions"][0]["positives"] == 3
        )
        assert (
            rel["historical_whois"]
            and rel["historical_ssl"]
            and rel["ct"]
            and rel["subdomains"][0]["host"] == "login.shopn0va.com"
        )
        assert (
            rel["communicating_files"][0]["positives"]
            >= rel["communicating_files"][-1]["positives"]
        )
        ip = v["ips"][0]
        assert (
            ip["ip"] == "203.0.113.66"
            and ip["country"] == "NL"
            and ip["country_name"] == "Netherlands"
        )
        assert (
            ip["as_owner"] == "BulletproofHost BV"
            and ip["hosted"]
            and all("positives" in h for h in ip["hosted"])
        )
        assert ip["hosted"][0]["positives"] >= ip["hosted"][-1]["positives"] and ip["files"]
        us = v["urlscan"]
        # recorded scans show the rendered picture of the site (served by the demo server)
        assert (
            us["scan"]["task_id"] == "mock-shopn0va.com"
            and us["scan"]["screenshot"] == "/ui/demo-shot/shopn0va.com"
        )
        assert us["similar"]["by_hash"] and us["similar"]["queries"]["by_hash"].startswith("hash:")
        assert (
            "VirusTotal domain" in v["links"]
            and "Shodan" in v["links"]
            and v["job"]["state"] == "done"
        )
        assert v["missing"] == []

        # cache: a second run reuses every row (no new lookups) unless forced
        r2 = c.post(f"/api/findings/{f['id']}/intel")
        app.state.queue.wait(uuid.UUID(r2.json()["job_id"]), timeout=60)
        ev = c.get(f"/api/jobs/{r2.json()['job_id']}/events").json()["events"]
        summary = next(e for e in ev if e["step"] == "intel" and e["status"] == "done")
        assert summary["data"]["api_calls"] == 0
        r3 = c.post(f"/api/findings/{f['id']}/intel", params={"force": "true"})
        app.state.queue.wait(uuid.UUID(r3.json()["job_id"]), timeout=60)
        ev = c.get(f"/api/jobs/{r3.json()['job_id']}/events").json()["events"]
        assert (
            next(e for e in ev if e["step"] == "intel" and e["status"] == "done")["data"][
                "api_calls"
            ]
            > 10
        )

        # IP-only investigation + validation
        assert c.post("/api/intel/ip/10.0.0.1").status_code == 400
        assert c.post("/api/intel/ip/not-an-ip").status_code == 400
        r4 = c.post("/api/intel/ip/198.51.100.77")
        app.state.queue.wait(uuid.UUID(r4.json()["job_id"]), timeout=60)
        v2 = c.get("/api/intel/ip/198.51.100.77").json()
        assert v2["ips"][0]["country"] == "RU" and v2["ips"][0]["hosted"]

        # UI
        ui = TestClient(app)
        ui.post("/ui/login", data={**ADMIN, "next": "/ui/findings"}, follow_redirects=False)
        fpage = ui.get(f"/ui/findings/{f['id']}")
        assert (
            "INVESTIGATE SITE AND ITS NETWORK" in fpage.text
            and fpage.text.count(">THREAT INTEL<") == 1
        )
        # one page per site: the investigation tabs live on the finding page; the old URL redirects there
        old = ui.get(f"/ui/findings/{f['id']}/intel", follow_redirects=False)
        assert (
            old.status_code == 303
            and old.headers["location"] == f"/ui/findings/{f['id']}#reputation"
        )
        page = ui.get(old.headers["location"])
        assert page.status_code == 200 and "Site &amp; network investigation" in page.text
        for tab in ("evidence", "investigation", "history"):  # four groups of panes (+ AI when there is an opinion)
            assert f'data-tab="{tab}"' in page.text, tab
        for pane in ("why", "looks", "reputation", "domain", "network", "timeline", "evidence"):
            assert f'id="tab-{pane}"' in page.text, pane
        assert "Not investigated yet" not in page.text  # the job above filled the cache
        for needle in (
            "flagcdn.com/w40/nl.png",
            "Mock Registrar LLC",
            "BulletproofHost BV",
            "login.shopn0va.com",
            "Similar sites",
            "Sites hosted on this server".upper(),
            "Draky and the Twilight Castle.apk",
        ):
            assert needle in page.text, needle
        shot = ui.get("/ui/demo-shot/shopn0va.com")
        assert (
            shot.status_code == 200
            and shot.headers["content-type"] == "image/png"
            and shot.content[1:4] == b"PNG"
        )
        assert ui.get("/ui/demo-shot/no-such-site.example").status_code == 404
        ippage = ui.get("/ui/intel/ip/203.0.113.66")
        assert (
            ippage.status_code == 200
            and "203.0.113.66" in ippage.text
            and "Abuse reports · AbuseIPDB" in ippage.text
        )
        assert ui.get("/ui/intel/ip/10.0.0.1").status_code == 404


def test_intel_view_handles_empty_cache(session):
    from tests.conftest import make_workspace

    ws = make_workspace(session)
    v = intel_mod.intel_view(session, ws.id, "nothing.example", url="https://nothing.example/")
    assert (
        v["detections"]["available"] is False
        and v["dns"]["records"] == []
        and v["certificate"] is None
    )
    assert v["ips"] == [] and v["fetched_at"] is None and "crt.sh" in v["links"]
    assert intel_mod._rdap_view(None)["available"] is False


async def test_certificate_history_runs_alongside_the_virustotal_waits():
    # the first live run: 287 s, of which 74 s were crt.sh while nothing else happened; VirusTotal's 4 requests a
    # minute is what the job waits for, and CT does not use VirusTotal
    import asyncio
    import time

    import pytest

    started: dict[str, float] = {}

    class Fake(intel_mod.Collector):
        def __init__(self):  # no session, no providers: only the two steps under test
            pass

        async def _ct(self, reg):
            started["ct"] = time.monotonic()
            await asyncio.sleep(0.3)

        async def _domain(self, host, reg):
            started["domain"] = time.monotonic()
            await asyncio.sleep(0.3)
            return {"reg": reg}

    t0 = time.monotonic()
    assert await Fake().domain("login.Shopn0va.com") == {"reg": "shopn0va.com"}
    assert time.monotonic() - t0 < 0.5  # 0.3 + 0.3 one after the other would be 0.6
    assert abs(started["ct"] - started["domain"]) < 0.1

    class Broken(Fake):
        async def _domain(self, host, reg):
            raise RuntimeError("boom")

    loop_tasks_before = len(asyncio.all_tasks())
    with pytest.raises(RuntimeError):
        await Broken().domain("shopn0va.com")
    await asyncio.sleep(0)
    assert len(asyncio.all_tasks()) <= loop_tasks_before  # the CT task was cancelled, not left running


def test_a_cloudflare_edge_address_is_not_asked_about_its_neighbours(engine, tmp_path):
    # the two edge addresses of one site cost about 90 s of VirusTotal quota for lists about Cloudflare's customers
    from tests.test_redirect_and_challenge import _Scenarios

    settings = Settings(_env_file=None, demo_mode=True, evidence_dir=str(tmp_path / "ev"), bootstrap_admin_email=ADMIN["email"],
                        bootstrap_admin_password=ADMIN["password"], secret_key="unit-test-secret-0123456789abcdef")  # fmt: skip
    app = create_app(settings=settings, engine=engine)
    cf = "104.21.32.129"
    rows = (("shopnova-cdn.com", "shopn0va.com", {}, {"dns": {"A": [cf]}, "infra": {"ip": cf}}),)
    with _Scenarios(*rows), TestClient(app) as c:
        c.headers["Authorization"] = "Bearer " + c.post("/api/auth/login", json=ADMIN).json()["access_token"]
        brand = c.post("/api/brands", json={"name": f"Edge {uuid.uuid4().hex[:4]}", "domains": ["shopnova.com"]}).json()
        job = c.post(f"/api/brands/{brand['id']}/scan-urls", json={"urls": ["https://shopnova-cdn.com/"]}).json()["job_id"]
        app.state.queue.wait(uuid.UUID(job), timeout=120)
        f = c.get("/api/findings", params={"brand_id": brand["id"]}).json()[0]
        r = c.post(f"/api/findings/{f['id']}/intel", params={"force": "true"})
        app.state.queue.wait(uuid.UUID(r.json()["job_id"]), timeout=120)
        v = c.get(f"/api/findings/{f['id']}/intel").json()
        ip = next(i for i in v["ips"] if i["ip"] == cf)
        assert ip["shared"] is True and ip["hosted"] == [] and ip["files"] == [] and ip["historical_whois"] == []
        assert {ip["status"][f"virustotal/{k}"]["status"] for k in ("resolutions", "communicating_files", "historical_whois")} == {"skipped"}
        assert ip["status"]["virustotal/resolutions"]["error"].startswith("Cloudflare address shared by a great many unrelated sites")
        assert ip["status"]["virustotal/report"]["status"] == "ok" and ip["cdn"] and ip["country"] is None and ip["edge"]["country"]  # its own report and abuse score are still looked up; the place is only noted: an edge is where the asker is, not where the site is
        events = c.get(f"/api/jobs/{r.json()['job_id']}/events").json()["events"]
        said = [e["message"] for e in events]
        assert any(f"{cf} is a Cloudflare address shared by a great many unrelated sites" in x for x in said)
        assert not any(f"VirusTotal resolutions for {cf}" in x for x in said)  # the question was never asked
        done = next(e for e in events if e["step"] == "intel" and e["status"] == "done")
        assert done["data"]["skipped"] == 3 and "3 skipped (shared Cloudflare address)" in done["message"]
        ui = TestClient(app)
        ui.post("/ui/login", data={**ADMIN, "next": "/ui/findings"}, follow_redirects=False)
        page = ui.get(f"/ui/findings/{f['id']}").text
        assert 'id="shared-cloudflare"' in page and "skipped · shared Cloudflare address" in page
        assert "a Cloudflare address shared by a great many sites: the lists of sites, files and WHOIS history were skipped" in page
