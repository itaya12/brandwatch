"""WHOIS history: the analyzer (timeline, privacy switched on, re-registration, transfers), the
WhoisXML WHOIS History client, single-provider access and the demo flow on the intel page."""

import uuid

import httpx
import pytest
import respx
from fastapi.testclient import TestClient

from brandwatch.api.main import create_app
from brandwatch.config.settings import Settings
from brandwatch.db.enums import ProviderStatus
from brandwatch.detection.whois_history import analyze, contact_view, is_private
from brandwatch.providers.base import ProviderError, RateLimited
from brandwatch.providers.impl.clients import WhoisXmlClient
from brandwatch.providers.registry import ProviderRegistry

ADMIN = {"email": "admin@test.local", "password": "test-admin-password"}
HIST = "https://whois-history.whoisxmlapi.com/api/v1"


def rec(
    seen, created, registrar="Reg A", expires="2027-01-01", ns=("ns1.a.example",), **registrant
):
    return {"createdDateISO8601": f"{created}T00:00:00Z", "expiresDateISO8601": f"{expires}T00:00:00Z",
            "audit": {"createdDate": f"{seen} 00:00:00 UTC", "updatedDate": f"{seen} 00:00:00 UTC"},
            "registrarName": registrar, "nameServers": list(ns), "registrantContact": registrant, "rawText": "Domain Name: X"}  # fmt: skip


PRIV = {
    "name": "REDACTED FOR PRIVACY",
    "organization": "Privacy service provided by Withheld for Privacy ehf",
}


def test_privacy_detection():
    assert (
        is_private("REDACTED FOR PRIVACY")
        and is_private("Domains By Proxy, LLC")
        and is_private("WhoisGuard, Inc.")
    )
    assert not is_private("Jordan Marlow") and not is_private("")
    c = contact_view(
        {"name": "REDACTED FOR PRIVACY", "email": "x@withheldforprivacy.example", "country": "IS"}
    )
    assert c["hidden"] and c["visible"] == {}
    assert not contact_view({"organization": "ShopNova Inc.", "country": "US"})["hidden"]


def test_privacy_switched_on_leaves_a_lead():
    h = analyze(
        [  # out of order on purpose: snapshots are sorted by the date they were seen
            rec("2026-10-07", "2026-10-06", **PRIV),
            rec(
                "2026-10-06",
                "2026-10-06",
                name="Jordan Marlow",
                email="jm@mailbox.example",
                country="GB",
            ),
        ]
    )
    kinds = [e["kind"] for e in h["events"]]
    assert kinds == ["registered", "privacy_on"]
    sm = h["summary"]
    assert sm["hidden_now"] and sm["hidden_since"] == "2026-10-07"
    assert (
        sm["leaked_owner"]["email"] == "jm@mailbox.example"
        and sm["leaked_owner"]["first_seen"] == "2026-10-06"
    )
    assert (
        "Jordan Marlow" in h["events"][0]["title"]
        and "jm@mailbox.example" in h["events"][1]["detail"]
    )


def test_re_registration_never_blames_the_previous_owner():
    h = analyze(
        [
            rec(
                "2020-10-01",
                "2020-03-15",
                "Legacy Names",
                expires="2021-03-15",
                name="Dana Whitfield",
                email="dana@old.example",
            ),
            rec(
                "2024-04-23",
                "2020-03-15",
                "Legacy Names",
                expires="2026-09-05",
                name="Dana Whitfield",
                email="dana@old.example",
            ),
            rec("2026-10-08", "2026-10-07", "Mock Registrar", expires="2027-10-07", **PRIV),
        ]
    )
    kinds = [e["kind"] for e in h["events"]]
    assert "re_registered" in kinds and "renewed" in kinds
    sm = h["summary"]
    assert (
        sm["re_registrations"] == 1
        and sm["first_registered"] == "2020-03-15"
        and sm["latest_registration"] == "2026-10-07"
    )
    assert sm["hidden_now"] and sm["leaked_owner"] is None  # the 2020 owner is not today's operator


def test_transfer_owner_change_and_nameservers():
    h = analyze(
        [
            rec(
                "2025-01-01",
                "2024-12-30",
                "Reg A",
                organization="Acme Corp",
                email="it@acme.example",
            ),
            rec(
                "2025-06-01",
                "2024-12-30",
                "Reg B",
                ns=("ns1.b.example",),
                organization="Beta LLC",
                email="ops@beta.example",
            ),
        ]
    )
    kinds = [e["kind"] for e in h["events"]]
    assert kinds == ["registered", "transfer", "owner_change", "nameservers"]
    assert (
        h["summary"]["transfers"] == 1
        and h["summary"]["owner_changes"] == 1
        and not h["summary"]["hidden_now"]
    )
    assert set(h["snapshots"][1]["changed"]) >= {"registrar", "registrant", "nameservers"}
    assert analyze([])["summary"]["records"] == 0


def _history_route(counts=2, records=None):
    """The documented API: mode=preview answers with the count only, mode=purchase with the records."""
    recs = records if records is not None else [
        {**rec("2026-10-06", "2026-10-06", name="J"), "cleanText": "x" * 9000, "rawText": "r" * 9000},
        rec("2026-10-07", "2026-10-06", **PRIV)]  # fmt: skip

    def answer(request):
        if request.url.params["mode"] == "preview":
            return httpx.Response(200, json={"recordsCount": counts})
        return httpx.Response(200, json={"recordsCount": len(recs), "records": recs})

    return respx.get(HIST).mock(side_effect=answer)


@respx.mock
async def test_whoisxml_history_client_previews_then_buys():
    route = _history_route()
    wx = WhoisXmlClient("secret-key-123", client=httpx.AsyncClient())
    res = await wx.history("shopnova-giftcard.example")
    modes = [c.request.url.params["mode"] for c in route.calls]
    assert modes == ["preview", "purchase"]  # 1 credit to see there is something, then the 50-credit purchase
    req = route.calls.last.request
    q = req.url.params
    assert q["domainName"] == "shopnova-giftcard.example" and q["skipLiveWhois"] == "1" and q["outputFormat"] == "JSON"
    assert req.headers["X-Authentication-Token"] == "secret-key-123"  # the documented header ...
    assert "apiKey" not in q and "secret-key-123" not in str(req.url)  # ... so the key is never in a URL or a log
    assert res.status is ProviderStatus.POSITIVE and res.data["records_count"] == 2 and res.cost_usd > WhoisXmlClient.HISTORY_COST
    first = res.data["records"][0]
    assert "cleanText" not in first and len(first["rawText"]) == 4000
    assert "secret-key-123" not in str(res.raw)


@respx.mock
async def test_a_domain_without_history_costs_one_credit_not_fifty():
    route = _history_route(counts=0)
    res = await WhoisXmlClient("k", client=httpx.AsyncClient()).history("nothing-here.example")
    assert [c.request.url.params["mode"] for c in route.calls] == ["preview"]  # no purchase
    assert res.status is ProviderStatus.UNKNOWN and res.data == {"domain": "nothing-here.example", "records_count": 0, "records": []}
    assert res.cost_usd == WhoisXmlClient.HISTORY_PREVIEW_COST


@respx.mock
async def test_a_preview_without_a_count_still_goes_on_to_the_purchase():
    route = respx.get(HIST).mock(side_effect=lambda r: httpx.Response(200, json={} if r.url.params["mode"] == "preview" else {"recordsCount": 1, "records": [rec("2026-10-06", "2026-10-06", name="J")]}))
    res = await WhoisXmlClient("k", client=httpx.AsyncClient()).history("x.example")
    assert [c.request.url.params["mode"] for c in route.calls] == ["preview", "purchase"] and res.data["records_count"] == 1


@respx.mock
async def test_the_documented_errors_say_what_to_do():
    import pytest

    wx = WhoisXmlClient("secret-key-123", client=httpx.AsyncClient())
    cases = {
        401: ("API key is missing or invalid", False),
        403: ("IP allowlist", False),
        408: ("timed out", True),
        410: ("no longer available", False),
        422: ("is the domain name valid", False),
        500: ("server error", True),
    }
    for code, (words, retryable) in cases.items():
        respx.get(HIST).mock(return_value=httpx.Response(code, json={"code": code, "messages": "Access restricted. Check the credits balance."} if code == 403 else {}))
        with pytest.raises(ProviderError) as e:
            await wx.history("x.example")
        msg = str(e.value)
        assert f"HTTP {code}" in msg and words in msg and "secret-key-123" not in msg, (code, msg)
        assert e.value.retryable is retryable, code
    # a 403 tells the three reasons the vendor lists, and repeats what the vendor said
    respx.get(HIST).mock(return_value=httpx.Response(403, json={"messages": "Access restricted. Check the credits balance."}))
    with pytest.raises(ProviderError) as e:
        await wx.history("x.example")
    assert "credits" in str(e.value) and "WhoisXML said: Access restricted" in str(e.value)


@respx.mock
async def test_rate_limit_and_timeouts_and_errors_inside_a_200():
    import pytest

    wx = WhoisXmlClient("k", client=httpx.AsyncClient())
    respx.get(HIST).mock(return_value=httpx.Response(429, headers={"retry-after": "3"}))
    with pytest.raises(RateLimited) as e:
        await wx.history("x.example")
    assert e.value.retry_after == 3
    respx.get(HIST).mock(side_effect=httpx.ReadTimeout("slow"))
    with pytest.raises(ProviderError) as e2:
        await wx.history("x.example")
    assert "no answer within 60 s" in str(e2.value) and e2.value.retryable
    respx.get(HIST).mock(return_value=httpx.Response(200, json={"messages": "Domain name is invalid"}))
    with pytest.raises(ProviderError) as e3:
        await wx.history("x.example")
    assert "Domain name is invalid" in str(e3.value) and not e3.value.retryable


@respx.mock
async def test_the_preview_is_the_settings_test_and_costs_one_credit():
    route = _history_route(counts=7)
    res = await WhoisXmlClient("k", client=httpx.AsyncClient()).history_preview("google.com")
    assert [c.request.url.params["mode"] for c in route.calls] == ["preview"]
    assert res.data == {"domain": "google.com", "records_count": 7} and res.cost_usd == WhoisXmlClient.HISTORY_PREVIEW_COST


def test_the_settings_test_knows_both_whoisxml_products(engine, tmp_path):
    from fastapi.testclient import TestClient
    from tests.test_demo_story import _api, _app, _ui

    from brandwatch.api.admin import _TEST_CALLS

    assert _TEST_CALLS["whoisxml"][0] == "balance" and _TEST_CALLS["whoisxml-history"][0] == "history_ready"
    app = _app(engine, tmp_path)
    with TestClient(app):
        c, ui = _api(app), _ui(app)
        c.put("/api/admin/api-keys/whoisxml", json={"key": "k" * 24})
        try:
            r = c.post("/api/admin/api-keys/whoisxml-history/test")
            assert r.status_code == 200 and r.json()["ok"] is True and "demo mode" in r.json()["detail"]  # the demo never calls out
            page = ui.get("/ui/settings").text
            assert 'data-p="whoisxml-history"' in page and ">Test history</button>" in page and 'class="small keytest-out"' in page
        finally:  # the database is shared with the other tests, some of which count the stored keys
            c.delete("/api/admin/api-keys/whoisxml")


def test_single_provider_access_live_and_demo():
    live = ProviderRegistry(Settings(_env_file=None, demo_mode=False))
    assert (
        live.single("whois", "whoisxml") is None
    )  # no key → the intel page says so instead of calling
    keyed = ProviderRegistry(
        Settings(_env_file=None, demo_mode=False), key_overrides={"whoisxml": "k"}
    )
    assert keyed.single("whois", "whoisxml").name == "whoisxml"
    demo = ProviderRegistry(Settings(_env_file=None, demo_mode=True))
    assert demo.single("whois", "whoisxml").name == "mock:whoisxml"
    assert demo.single("whois", "whoisxml") is demo.single("whois", "whoisxml")


def test_demo_whois_history_on_the_intel_page(engine, tmp_path):
    settings = Settings(_env_file=None, demo_mode=True, evidence_dir=str(tmp_path / "ev"), bootstrap_admin_email=ADMIN["email"],
                        bootstrap_admin_password=ADMIN["password"], secret_key="unit-test-secret-0123456789abcdef")  # fmt: skip
    app = create_app(settings=settings, engine=engine)
    with TestClient(app) as c:
        c.headers["Authorization"] = (
            "Bearer " + c.post("/api/auth/login", json=ADMIN).json()["access_token"]
        )
        b = c.post(
            "/api/brands",
            json={"name": f"Hist {uuid.uuid4().hex[:4]}", "domains": ["shopnova.com"]},
        ).json()
        job = c.post(
            f"/api/brands/{b['id']}/scan-urls",
            json={"urls": ["https://shopnova-giftcard.com/", "https://shopnova-refund.net/"]},
        ).json()["job_id"]
        app.state.queue.wait(uuid.UUID(job), timeout=180)
        rows = {
            f["hostname"]: f for f in c.get("/api/findings", params={"brand_id": b["id"]}).json()
        }
        for host in ("shopnova-refund.net", "shopnova-giftcard.com"):
            r = c.post(f"/api/findings/{rows[host]['id']}/intel")
            app.state.queue.wait(uuid.UUID(r.json()["job_id"]), timeout=180)
            assert c.get(f"/api/jobs/{r.json()['job_id']}").json()["state"] == "done"
        v = c.get(f"/api/findings/{rows['shopnova-giftcard.com']['id']}/intel").json()
        h = v["whois_history"]
        assert (
            h["summary"]["hidden_now"]
            and h["summary"]["leaked_owner"]["email"] == "jm.digital.media@mailbox.example"
        )
        assert any(
            r["email"] == "jm.digital.media@mailbox.example"
            and "shopnova-refund.net" in r["domains"]
            for r in h["related"]
        )
        events = c.get(f"/api/jobs/{r.json()['job_id']}/events").json()["events"]
        assert any(
            e["stage"] == "intel" and "owner visible before privacy" in e["message"] for e in events
        )
        ui = TestClient(app)
        ui.post("/ui/login", data=ADMIN, follow_redirects=False)
        page = ui.get(f"/ui/findings/{rows['shopnova-giftcard.com']['id']}/intel").text
        assert (
            'id="sec-history"' in page
            and "Owner details visible before privacy was switched on" in page
        )
        assert "jm.digital.media@mailbox.example" in page and "Privacy switched on" in page



BAL = "https://user.whoisxmlapi.com/user-service/account-balance"


def _balance(whois=0, drs=0):
    return httpx.Response(200, json={"data": [{"product_id": 1, "product": {"id": 1, "name": "WHOIS API"}, "credits": whois},
                                              {"product_id": 14, "product": {"id": 14, "name": "Domain Research Suite"}, "credits": drs},
                                              {"product_id": 20, "product": {"id": 20, "name": "Domain Reputation API"}, "credits": 100}]})


@respx.mock
async def test_the_free_balance_names_each_pool():
    route = respx.get(BAL).mock(return_value=_balance(whois=12, drs=0))
    res = await WhoisXmlClient("secret-key-123", client=httpx.AsyncClient()).balance()
    assert route.calls.last.request.url.params["apiKey"] == "secret-key-123"
    assert res.data["whois_api"] == 12 and res.data["drs"] == 0 and res.data["products"]["Domain Reputation API"] == 100
    assert "Domain Research Suite 0 credits" in res.data["summary"] and res.cost_usd == 0
    respx.get(BAL).mock(return_value=httpx.Response(403, json={"messages": "denied"}))
    with pytest.raises(ProviderError) as e:
        await WhoisXmlClient("secret-key-123", client=httpx.AsyncClient()).balance()
    assert "allowlist" in str(e.value) and "secret-key-123" not in str(e.value)


@respx.mock
async def test_a_403_on_history_says_the_real_cause_from_the_balance():
    wx = WhoisXmlClient("secret-key-123", client=httpx.AsyncClient())
    respx.get(HIST).mock(return_value=httpx.Response(403, json={"messages": "Access restricted. Reasons: insufficient credits balance"}))
    respx.get(BAL).mock(return_value=_balance(whois=0, drs=0))
    with pytest.raises(ProviderError) as e:
        await wx.history("x.example")
    msg = str(e.value)
    assert msg.startswith("whoisxml history: HTTP 403: no WHOIS History credits: your Domain Research Suite balance is 0")
    assert "separate pool" in msg and "user.whoisxmlapi.com/products" in msg and "allowlist" not in msg  # the cause is known: no list of maybes
    assert "secret-key-123" not in msg
    respx.get(BAL).mock(return_value=_balance(whois=0, drs=480))  # credits are there: so it is the key, the product or the IP
    with pytest.raises(ProviderError) as e2:
        await wx.history("x.example")
    assert "balance is not the problem" in str(e2.value) and "IP allowlist" in str(e2.value)
    respx.get(BAL).mock(return_value=httpx.Response(500))  # the hint is best-effort: the original error still comes through
    with pytest.raises(ProviderError) as e3:
        await wx.history("x.example")
    assert "HTTP 403" in str(e3.value) and "no WHOIS History credits" not in str(e3.value.args[0].split("not enough WHOIS History credits")[0])


@respx.mock
async def test_the_history_test_spends_nothing_when_there_is_nothing_to_spend():
    hist = respx.get(HIST).mock(return_value=httpx.Response(200, json={"recordsCount": 3}))
    respx.get(BAL).mock(return_value=_balance(whois=0, drs=0))
    res = await WhoisXmlClient("k", client=httpx.AsyncClient()).history_ready()
    assert res.data["ok"] is False and "no WHOIS History credits" in res.data["summary"] and not hist.called
    respx.get(BAL).mock(return_value=_balance(whois=0, drs=500))
    res2 = await WhoisXmlClient("k", client=httpx.AsyncClient()).history_ready()
    assert res2.data["ok"] is True and "3 snapshots" in res2.data["summary"] and hist.call_count == 1  # the one preview


def test_a_record_whose_only_visible_field_is_a_phone_number_does_not_crash():
    # the live scan of cryptohopper crashed here: telephone is an identity field but not one the label looked at
    h = analyze([
        rec("2026-10-06", "2026-10-06", **PRIV),
        rec("2026-10-07", "2026-10-06", telephone="+972.501234567"),
    ])
    assert [e["kind"] for e in h["events"]] == ["registered", "privacy_off"]
    assert "+972.501234567" in h["events"][1]["detail"]
    h2 = analyze([
        rec("2026-10-06", "2026-10-06", telephone="+972.501234567"),
        rec("2026-10-07", "2026-10-06", telephone="+1.5550100"),
    ])
    assert h2["events"][-1]["kind"] == "owner_change" and "+1.5550100" in h2["events"][-1]["detail"]
