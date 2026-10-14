"""Google Safe Browsing and AbuseIPDB: the clients (respx), live chain selection, and what the demo
shows on the finding page and the intel page."""

import json
import uuid

import httpx
import respx
from fastapi.testclient import TestClient

from brandwatch.api.main import create_app
from brandwatch.config.settings import Settings
from brandwatch.db.enums import ProviderStatus
from brandwatch.providers.base import ProviderError
from brandwatch.providers.impl.clients import AbuseIPDBClient, SafeBrowsingClient
from brandwatch.providers.registry import ProviderRegistry

ADMIN = {"email": "admin@test.local", "password": "test-admin-password"}
SB = "https://safebrowsing.googleapis.com/v4/threatMatches:find"
AB = "https://api.abuseipdb.com/api/v2/check"


@respx.mock
async def test_safe_browsing_client():
    route = respx.post(SB).mock(return_value=httpx.Response(200, json={"matches": [
        {"threatType": "SOCIAL_ENGINEERING", "platformType": "ANY_PLATFORM", "threat": {"url": "http://evil.example/"}}]}))  # fmt: skip
    sb = SafeBrowsingClient("goog-key-123", client=httpx.AsyncClient())
    res = await sb.lookup_domain("evil.example")
    req = route.calls.last.request
    body = json.loads(req.content)
    assert req.headers["X-Goog-Api-Key"] == "goog-key-123" and "goog-key-123" not in str(req.url)
    assert [e["url"] for e in body["threatInfo"]["threatEntries"]] == [
        "http://evil.example/",
        "https://evil.example/",
    ]
    assert "SOCIAL_ENGINEERING" in body["threatInfo"]["threatTypes"]
    assert res.status is ProviderStatus.POSITIVE and res.data["threats"] == ["SOCIAL_ENGINEERING"]

    respx.post(SB).mock(return_value=httpx.Response(200, json={}))
    clean = await sb.lookup_url("https://fresh-kit.example/login")
    assert clean.status is ProviderStatus.NEGATIVE and clean.data["threats"] == []

    respx.post(SB).mock(
        return_value=httpx.Response(
            400,
            json={
                "error": {"code": 400, "message": "API key not valid. Please pass a valid API key."}
            },
        )
    )
    try:
        await sb.lookup_domain("x.example")
        raise AssertionError("expected an error")
    except ProviderError as exc:
        assert "API key not valid" in str(exc) and "goog-key-123" not in str(exc)


@respx.mock
async def test_abuseipdb_client():
    route = respx.get(AB).mock(return_value=httpx.Response(200, json={"data": {
        "ipAddress": "203.0.113.9", "abuseConfidenceScore": 64, "totalReports": 51, "numDistinctUsers": 17,
        "lastReportedAt": "2026-10-09T21:14:00+00:00", "isp": "Example Hosting", "usageType": "Data Center/Web Hosting/Transit",
        "countryCode": "NL", "isTor": False, "isWhitelisted": False}}))  # fmt: skip
    ab = AbuseIPDBClient("ab-key-123", client=httpx.AsyncClient())
    res = await ab.lookup_ip("203.0.113.9")
    req = route.calls.last.request
    assert (
        req.headers["Key"] == "ab-key-123"
        and req.url.params["ipAddress"] == "203.0.113.9"
        and req.url.params["maxAgeInDays"] == "90"
    )
    assert (
        res.status is ProviderStatus.POSITIVE
        and res.data["abuse_score"] == 64
        and res.data["distinct_users"] == 17
    )
    assert (await ab.lookup_domain("evil.example")).status is ProviderStatus.NOT_APPLICABLE

    respx.get(AB).mock(
        return_value=httpx.Response(
            200,
            json={
                "data": {"ipAddress": "198.51.100.1", "abuseConfidenceScore": 0, "totalReports": 0}
            },
        )
    )
    assert (await ab.check_ip("198.51.100.1")).status is ProviderStatus.NEGATIVE
    respx.get(AB).mock(
        return_value=httpx.Response(
            401,
            json={
                "errors": [
                    {
                        "detail": "Authentication failed. Your API key is either missing, incorrect, or revoked."
                    }
                ]
            },
        )
    )
    try:
        await ab.check_ip("198.51.100.1")
        raise AssertionError("expected an error")
    except ProviderError as exc:
        assert "Authentication failed" in str(exc)


def test_live_reputation_chain_uses_safe_browsing_only_with_a_key():
    bare = ProviderRegistry(
        Settings(_env_file=None, demo_mode=False), key_overrides={"virustotal": "v"}
    )
    assert bare.describe()["reputation"] == ["virustotal"]  # no PhishTank, no keyless Safe Browsing
    keyed = ProviderRegistry(
        Settings(_env_file=None, demo_mode=False),
        key_overrides={"virustotal": "v", "safebrowsing": "g"},
    )
    assert keyed.describe()["reputation"] == ["virustotal", "safebrowsing"]
    assert keyed.single("reputation", "abuseipdb") is None
    assert (
        ProviderRegistry(
            Settings(_env_file=None, demo_mode=False), key_overrides={"abuseipdb": "a"}
        )
        .single("reputation", "abuseipdb")
        .name
        == "abuseipdb"
    )


def test_demo_finding_and_intel_pages_show_both(engine, tmp_path):
    settings = Settings(_env_file=None, demo_mode=True, evidence_dir=str(tmp_path / "ev"), bootstrap_admin_email=ADMIN["email"],
                        bootstrap_admin_password=ADMIN["password"], secret_key="unit-test-secret-0123456789abcdef")  # fmt: skip
    app = create_app(settings=settings, engine=engine)
    with TestClient(app) as c:
        c.headers["Authorization"] = (
            "Bearer " + c.post("/api/auth/login", json=ADMIN).json()["access_token"]
        )
        b = c.post(
            "/api/brands", json={"name": f"Rep {uuid.uuid4().hex[:4]}", "domains": ["shopnova.com"]}
        ).json()
        job = c.post(
            f"/api/brands/{b['id']}/scan-urls",
            json={"urls": ["https://shopn0va.com/", "https://shopnova-giftcard.com/"]},
        ).json()["job_id"]
        app.state.queue.wait(uuid.UUID(job), timeout=180)
        rows = {
            f["hostname"]: f for f in c.get("/api/findings", params={"brand_id": b["id"]}).json()
        }
        seed = c.get(f"/api/findings/{rows['shopn0va.com']['id']}").json()
        fresh = c.get(f"/api/findings/{rows['shopnova-giftcard.com']['id']}").json()
        sb_seed = next(t for t in seed["threat_intel"] if t["provider"] == "safebrowsing")
        sb_fresh = next(t for t in fresh["threat_intel"] if t["provider"] == "safebrowsing")
        assert sb_seed["status"] == "positive" and "Google warns users" in sb_seed["summary"]
        assert (
            sb_fresh["status"] == "negative" and "not on Google's list yet" in sb_fresh["summary"]
        )
        assert "phishtank" not in {t["provider"] for t in seed["threat_intel"]}
        assert "safe_browsing" in {sg["name"] for sg in seed["score"]["signals"]}  # the recorded verdict still scores

        r = c.post(f"/api/findings/{rows['shopn0va.com']['id']}/intel")
        app.state.queue.wait(uuid.UUID(r.json()["job_id"]), timeout=180)
        v = c.get(f"/api/findings/{rows['shopn0va.com']['id']}/intel").json()
        kit = next(ip for ip in v["ips"] if ip["ip"] == "203.0.113.66")
        assert kit["abuse"]["abuse_score"] == 87 and kit["abuse"]["total_reports"] == 143
        ui = TestClient(app)
        ui.post("/ui/login", data=ADMIN, follow_redirects=False)
        page = ui.get(f"/ui/findings/{rows['shopn0va.com']['id']}/intel").text
        assert "Abuse reports · AbuseIPDB" in page and "143</b> report(s)" in page
