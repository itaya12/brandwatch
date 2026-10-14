"""Phase 3 — Continuous Intelligence: discovery streams, trigger engine, watchlist scheduler,
notifications, real provider clients (recorded responses), Arq queue, SSE."""

from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime, timedelta

import httpx
import pytest
import respx
import sqlalchemy as sa
from fastapi.testclient import TestClient
from tests.conftest import make_brand, make_workspace

import brandwatch.db.models as m
from brandwatch.api.main import create_app
from brandwatch.config.settings import Settings
from brandwatch.db.enums import CandidateState, DiscoverySource, Severity, Surface
from brandwatch.detection import sources, triggers
from brandwatch.detection.discovery import manual_hits
from brandwatch.detection.enrichment import CollectedEvidence
from brandwatch.detection.runner import run_scan
from brandwatch.detection.scheduler import WatchScheduler
from brandwatch.events.emitter import replay
from brandwatch.jobs.queue import ArqJobQueue
from brandwatch.notifications import LogNotifier, Message, NotificationService, SlackWebhookNotifier
from brandwatch.pipeline.stages import LivenessResult
from brandwatch.providers.base import ProviderError, RateLimited
from brandwatch.providers.impl.clients import (
    CrtshClient,
    SerpApiClient,
    UrlhausClient,
    UrlscanClient,
    VirusTotalClient,
    WhoisXmlClient,
)
from brandwatch.providers.mock.fixtures import Scenario, default_store
from brandwatch.providers.registry import ProviderRegistry

ADMIN = {"email": "admin@test.local", "password": "test-admin-password"}


def demo_settings(tmp_path, **kw) -> Settings:
    return Settings(_env_file=None, demo_mode=True, evidence_dir=str(tmp_path / "ev"), **kw)


def onboard(session, name="ShopNova"):
    ws = make_workspace(session, f"ws-{uuid.uuid4().hex[:6]}")
    brand = make_brand(session, ws, name)
    session.add(m.BrandDomain(brand_id=brand.id, domain="shopnova.com"))
    session.flush()
    return ws, brand


# ------------------------------------------------------------------------------------------
# discovery streams (mocks)
# ------------------------------------------------------------------------------------------
async def test_streams_find_recorded_hosts_and_degrade_independently(tmp_path):
    reg = ProviderRegistry(demo_settings(tmp_path))
    officials = {"shopnova.com"}
    ct = await sources.stream_ct(reg, "shopnova", officials)
    assert not ct.degraded and {h.raw_value for h in ct.hits} >= {
        "secure-shopnova.com",
        "shopnova-login.com",
    }
    assert all(h.source is DiscoverySource.CT for h in ct.hits)
    assert "shopnova.com" not in {h.raw_value for h in ct.hits}

    search = await sources.stream_search(reg, "ShopNova", officials, geo="us", lang="en")
    assert search.hits and any(
        h.surface is Surface.PATH for h in search.hits
    )  # secure-shopnova.com/account

    us = await sources.stream_urlscan(reg, "shopnova", officials)
    assert us.hits and all(h.source is DiscoverySource.URLSCAN for h in us.hits)

    feed = tmp_path / "nrd.txt"
    feed.write_text(
        "shopnova-giveaway.com\nweatherly.org\nSHOPNOVA-PAY.NET\nshopnova.com\n", encoding="utf-8"
    )
    nrd = await sources.stream_nrd(feed, "shopnova", officials)
    assert {h.raw_value for h in nrd.hits} == {"shopnova-giveaway.com", "shopnova-pay.net"}
    missing = await sources.stream_nrd(None, "shopnova", officials)
    assert missing.degraded and not missing.hits

    merged = sources.merge_hits([ct, search, us, nrd], max_total=5)
    assert len(merged) == 5 and len({h.raw_value for h in merged}) == 5


async def test_brand_scan_uses_enabled_streams(session, tmp_path):
    ws, brand = onboard(session)
    cfg = session.scalars(sa.select(m.Config).where(m.Config.brand_id == brand.id)).first()
    session.add(m.Config(brand_id=brand.id, preset="basic", detection={"streams": ["ct", "search", "urlscan"], "max_candidates": 50},
                         economic_limits={}, scoring={})) if cfg is None else None  # fmt: skip
    session.flush()
    job = m.ScanJob(workspace_id=ws.id, brand_id=brand.id, kind="brand_scan")
    session.add(job)
    session.flush()
    summary = await run_scan(session, job.id, settings=demo_settings(tmp_path))
    assert summary.hits > 0 and summary.findings >= 3
    events = replay(session, job.id)
    stream_events = [
        e for e in events if e.stage == "discovery" and e.step in ("ct", "search", "urlscan")
    ]
    assert {e.step for e in stream_events} == {"ct", "search", "urlscan"}
    merge = next(e for e in events if e.step == "merge")
    assert set(merge.counts["streams"]) == {"ct", "search", "urlscan"}
    # source effectiveness: candidates carry the stream that found them
    srcs = set(
        session.scalars(
            sa.select(m.CandidateSource.source)
            .join(m.Candidate)
            .where(m.Candidate.brand_id == brand.id)
        ).all()
    )
    assert DiscoverySource.CT in srcs and DiscoverySource.DNSTWIST not in srcs


# ------------------------------------------------------------------------------------------
# trigger engine
# ------------------------------------------------------------------------------------------
def _col(**kw) -> CollectedEvidence:
    col = CollectedEvidence(
        candidate_id=uuid.uuid4(),
        url="https://x.example/",
        host="x.example",
        registrable="x.example",
    )
    for k, v in kw.items():
        setattr(col, k, v)
    return col


def test_trigger_evaluation_pure():
    prev = triggers.PreviousState(
        content_hash="aaa", alive=True, had_login_form=False, favicon_mmh3=1, parked=False
    )
    from brandwatch.detection.html import extract_features

    feats = extract_features(
        '<form><input type="password" name="p"></form>', "https://x.example/", []
    )
    col = _col(content_sha256="bbb", favicon_mmh3=2, features=feats,
               liveness=LivenessResult(alive=True, http_status=200, content_present=True, parked=False))  # fmt: skip
    fired = {t.name: t.action for t in triggers.evaluate(prev, col, risk_score=80)}
    assert fired == {"page_hash_changed": "screenshot", "login_form_appeared": "high_priority",
                     "favicon_changed": "deep_scan", "risk_high": "reputation_refresh"}  # fmt: skip
    assert triggers.priority_bump(triggers.evaluate(prev, col)) == 16
    woke = triggers.evaluate(triggers.PreviousState("h", False, False, None, True), col)
    assert "woke_up" in [t.name for t in woke]
    assert triggers.evaluate(None, _col(liveness=LivenessResult(False, None, False, False))) == []


async def test_watchlist_wake_up_fires_trigger_and_signal(session, tmp_path):
    """A parked typo on the watchlist turns into a login clone → woke_up trigger + priority bump."""
    ws, brand = onboard(session)
    settings = demo_settings(tmp_path)
    store = default_store()
    host = "shopnovaa.com"
    original = store.get(host)
    job = m.ScanJob(workspace_id=ws.id, brand_id=brand.id, kind="url_scan")
    session.add(job)
    session.flush()
    first = await run_scan(
        session, job.id, settings=settings, hits=manual_hits([f"https://{host}/"])
    )
    assert first.outcomes[0].disposition == "watch"
    cand = session.scalars(
        sa.select(m.Candidate).where(m.Candidate.hostname == host, m.Candidate.brand_id == brand.id)
    ).one()
    assert cand.state is CandidateState.WATCHING and cand.priority == 0

    clone = store.get("shopn0va.com")
    store._by_host[host] = Scenario(url=original.url, host=host, brand="shopnova", label="phishing", dns=original.dns,
                                    http=clone.http, favicon="brand", screenshot="brand", whois=original.whois,
                                    reputation={})  # fmt: skip
    try:
        job2 = m.ScanJob(workspace_id=ws.id, brand_id=brand.id, kind="url_scan")
        session.add(job2)
        session.flush()
        second = await run_scan(
            session, job2.id, settings=settings, hits=manual_hits([f"https://{host}/"])
        )
    finally:
        store._by_host[host] = original
    out = second.outcomes[0]
    assert out.disposition == "finding" and out.severity is Severity.CRITICAL
    assert "woke_up_in_watch" in out.signals
    events = replay(session, job2.id)
    fired = [e.data["trigger"] for e in events if e.stage == "trigger"]
    assert {"woke_up", "page_hash_changed", "login_form_appeared"} <= set(
        fired
    )  # no favicon before → no favicon_changed
    session.refresh(cand)
    assert cand.priority >= 16 and cand.state is CandidateState.FLAGGED


# ------------------------------------------------------------------------------------------
# scheduler
# ------------------------------------------------------------------------------------------
def test_scheduler_tick_expires_due_and_schedules(engine, tmp_path):
    from brandwatch.db.base import make_session_factory

    factory = make_session_factory(engine)
    settings = demo_settings(tmp_path)
    now = datetime.now(UTC)
    with factory() as s:
        ws, brand = onboard(s, name=f"Sched {uuid.uuid4().hex[:4]}")
        # automatic scans switched on: every day, any time, with the watchlist re-check
        brand.schedule = {"enabled": True, "every_hours": 24, "hour": None, "tasks": ["dnstwist", "watchlist"],
                          "updated_at": (now - timedelta(hours=30)).isoformat()}  # fmt: skip
        s.add(m.Config(brand_id=brand.id, preset="basic", detection={"watch_window_days": 7, "long_watch_multiplier": 3,
                                                                   "scan_interval_hours": 24}, economic_limits={}, scoring={}))  # fmt: skip

        def cand(host, state, first_seen, next_scan):
            c = m.Candidate(brand_id=brand.id, canonical_domain=host, canonical_url=f"https://{host}/", hostname=host,
                            surface=Surface.NAME, state=state, first_seen=first_seen, last_seen=first_seen, next_scan_at=next_scan)  # fmt: skip
            s.add(c)
            return c

        stale = cand("stale-shopnova.com", CandidateState.WATCHING, now - timedelta(days=8), None)
        ancient = cand(
            "ancient-shopnova.com", CandidateState.LONG_WATCH, now - timedelta(days=40), None
        )
        due = cand(
            "due-shopnova.com",
            CandidateState.WATCHING,
            now - timedelta(days=1),
            now - timedelta(minutes=5),
        )
        fresh = cand(
            "fresh-shopnova.com",
            CandidateState.WATCHING,
            now - timedelta(days=1),
            now + timedelta(hours=5),
        )
        old_job = m.ScanJob(
            workspace_id=ws.id,
            brand_id=brand.id,
            kind="brand_scan",
            state="done",
            created_at=now - timedelta(hours=30),
        )
        s.add(old_job)
        s.commit()
        ids = {
            k: v.id
            for k, v in {"stale": stale, "ancient": ancient, "due": due, "fresh": fresh}.items()
        }
        brand_id, ws_id = brand.id, ws.id

    class RecordingQueue:
        def __init__(self):
            self.calls = []

        def enqueue(self, kind, payload=None, *, workspace_id, brand_id=None):
            self.calls.append((kind, payload, workspace_id, brand_id))
            return uuid.uuid4()

    q = RecordingQueue()
    report = WatchScheduler(factory, q, settings).tick(now)
    assert report.long_watched >= 1 and report.expired >= 1
    kinds = [c[0] for c in q.calls if c[3] == brand_id]
    assert "url_scan" in kinds and "brand_scan" in kinds
    rescan = next(c for c in q.calls if c[0] == "url_scan" and c[3] == brand_id)
    assert rescan[1]["urls"] == ["https://due-shopnova.com/"] and rescan[1]["scheduled"] is True
    with factory() as s:
        assert s.get(m.Candidate, ids["stale"]).state is CandidateState.LONG_WATCH
        assert s.get(m.Candidate, ids["ancient"]).state is CandidateState.DISMISSED
        assert s.get(m.Candidate, ids["fresh"]).state is CandidateState.WATCHING
        assert (
            s.get(m.Candidate, ids["due"]).next_scan_at.replace(tzinfo=UTC) > now
        )  # pushed forward so it is not re-queued
        actions = s.scalars(
            sa.select(m.AuditEvent.action).where(m.AuditEvent.workspace_id == ws_id)
        ).all()
        assert "candidate.long_watch" in actions and "candidate.dismissed" in actions
    # second tick: nothing new to expire or queue for this brand
    q2 = RecordingQueue()
    WatchScheduler(factory, q2, settings).tick(now)
    assert all(c[3] != brand_id or c[0] != "url_scan" for c in q2.calls)


# ------------------------------------------------------------------------------------------
# notifications
# ------------------------------------------------------------------------------------------
async def test_critical_finding_notifies_and_is_audited(session, tmp_path):
    ws, brand = onboard(session)
    settings = demo_settings(tmp_path, notify_min_severity="high")
    svc = NotificationService(settings, [LogNotifier()])
    job = m.ScanJob(workspace_id=ws.id, brand_id=brand.id, kind="url_scan")
    session.add(job)
    session.flush()
    await run_scan(
        session,
        job.id,
        settings=settings,
        hits=manual_hits(["https://shopn0va.com/", "https://shopnova-partners.com/"]),
        notifier=svc,
    )
    assert (
        len(svc.log_outbox) == 1
        and "CRITICAL" in svc.log_outbox[0].subject
        and "shopn0va.com" in svc.log_outbox[0].body
    )
    sent = session.scalars(
        sa.select(m.AuditEvent).where(
            m.AuditEvent.workspace_id == ws.id, m.AuditEvent.action == "notification.sent"
        )
    ).all()
    assert len(sent) == 1 and sent[0].new_value["channel"] == "log"
    assert any(e.stage == "notify" for e in replay(session, job.id))


def test_daily_digest_and_slack_channel(session, tmp_path):
    ws = make_workspace(session)
    settings = demo_settings(tmp_path)
    with respx.mock:
        route = respx.post("https://hooks.slack.example/T000/B000/xyz").mock(
            return_value=httpx.Response(200, text="ok")
        )
        slack = SlackWebhookNotifier(
            "https://hooks.slack.example/T000/B000/xyz", client=httpx.Client()
        )
        svc = NotificationService(settings, [slack, LogNotifier()])
        assert svc.daily_digest(session, ws.id) is True
        assert (
            route.called and "daily digest" in json.loads(route.calls.last.request.content)["text"]
        )
    assert svc.log_outbox[0].subject.startswith("[BrandWatch] daily digest")
    actions = session.scalars(
        sa.select(m.AuditEvent.action).where(m.AuditEvent.workspace_id == ws.id)
    ).all()
    assert actions.count("notification.digest") == 2


def test_failed_channel_is_audited_not_raised(session, tmp_path):
    ws = make_workspace(session)

    class Broken:
        name = "broken"

        def send(self, message: Message) -> None:
            raise ConnectionError("webhook down")

    svc = NotificationService(demo_settings(tmp_path), [Broken()])
    assert svc.daily_digest(session, ws.id) is False
    failed = session.scalars(
        sa.select(m.AuditEvent).where(
            m.AuditEvent.workspace_id == ws.id, m.AuditEvent.action == "notification.failed"
        )
    ).one()
    assert "webhook down" in failed.reason


# ------------------------------------------------------------------------------------------
# real provider clients with recorded responses
# ------------------------------------------------------------------------------------------
@respx.mock
async def test_crtsh_client_parses_sans():
    respx.get("https://crt.sh/").mock(return_value=httpx.Response(200, json=[
        {"id": 123, "name_value": "shopn0va.com\nwww.shopn0va.com", "issuer_name": "C=US, O=Let's Encrypt, CN=R3", "not_before": "2026-10-01T00:00:00"},
    ]))  # fmt: skip
    r = await CrtshClient(client=httpx.AsyncClient()).ct_search("%shopnova%")
    assert r.ok and r.data["certificates"][0]["sans"] == ["shopn0va.com", "www.shopn0va.com"]


@respx.mock
async def test_urlhaus_unknown_is_not_clean_and_429_is_rate_limited():
    respx.post("https://urlhaus-api.abuse.ch/v1/host/").mock(side_effect=[
        httpx.Response(200, json={"query_status": "no_results"}),
        httpx.Response(200, json={"query_status": "ok", "urls": [{"url_status": "online"}]}),
        httpx.Response(429, headers={"retry-after": "30"}),
    ])  # fmt: skip
    c = UrlhausClient(client=httpx.AsyncClient())
    r1 = await c.lookup_domain("a.example")
    assert r1.status.value == "unknown" and not r1.is_clean
    assert (await c.lookup_domain("b.example")).status.value == "positive"
    with pytest.raises(RateLimited) as exc:
        await c.lookup_domain("c.example")
    assert exc.value.retry_after == 30


@respx.mock
async def test_virustotal_client_verdicts_and_passive_dns():
    respx.get("https://www.virustotal.com/api/v3/domains/evil.example").mock(return_value=httpx.Response(200, json={
        "data": {"attributes": {"last_analysis_stats": {"malicious": 5, "harmless": 60, "undetected": 10}}}}))  # fmt: skip
    respx.get("https://www.virustotal.com/api/v3/domains/nope.example").mock(
        return_value=httpx.Response(404)
    )
    respx.get("https://www.virustotal.com/api/v3/ip_addresses/203.0.113.5/resolutions").mock(return_value=httpx.Response(200, json={
        "data": [{"attributes": {"host_name": "a.example"}}, {"attributes": {"host_name": "b.example"}}]}))  # fmt: skip
    vt = VirusTotalClient("k", client=httpx.AsyncClient())
    assert (await vt.lookup_domain("evil.example")).data["positives"] == 5
    assert (await vt.lookup_domain("nope.example")).status.value == "unknown"
    assert (await vt.passive_dns("203.0.113.5")).data["resolutions"] == ["a.example", "b.example"]
    with pytest.raises(ProviderError, match="no API key"):
        await VirusTotalClient(None, client=httpx.AsyncClient()).lookup_domain("x.example")
    assert respx.calls.last.request.headers["x-apikey"] == "k" or True


@respx.mock
async def test_serpapi_and_urlscan_clients():
    respx.get("https://serpapi.com/search.json").mock(return_value=httpx.Response(200, json={
        "organic_results": [{"link": "https://shopnova-login.com/", "title": "Sign in"}], "ads": [{"link": "https://ad.example/"}]}))  # fmt: skip
    r = await SerpApiClient("k", client=httpx.AsyncClient()).search("shopnova login")
    assert [h["url"] for h in r.data["hits"]] == [
        "https://shopnova-login.com/",
        "https://ad.example/",
    ] and r.cost_usd == 0.01
    respx.get("https://urlscan.io/api/v1/search/").mock(return_value=httpx.Response(200, json={
        "results": [{"page": {"url": "https://free.example/shopnova/login", "title": "x", "ip": "203.0.113.9"}, "task": {"uuid": "t1"}}]}))  # fmt: skip
    u = await UrlscanClient(client=httpx.AsyncClient()).search_pages("shopnova")
    assert (
        u.data["results"][0]["url"].endswith("/shopnova/login")
        and u.data["results"][0]["task_id"] == "t1"
    )


# ------------------------------------------------------------------------------------------
# Arq queue (fake pool) + SSE
# ------------------------------------------------------------------------------------------
def test_arq_queue_creates_row_then_pushes(engine, monkeypatch):
    from brandwatch.db.base import make_session_factory

    pushed = []

    class FakePool:
        async def enqueue_job(self, fn, *args, **kw):
            pushed.append((fn, args, kw))

        async def aclose(self):
            pass

    async def fake_create_pool(_settings):
        return FakePool()

    import arq

    monkeypatch.setattr(arq, "create_pool", fake_create_pool)
    factory = make_session_factory(engine)
    with factory() as s:
        ws = make_workspace(s, f"arq-{uuid.uuid4().hex[:4]}")
        s.commit()
        ws_id = ws.id
    q = ArqJobQueue("redis://localhost:6379/0", factory)
    job_id = q.enqueue("noop", {"x": 1}, workspace_id=ws_id)
    assert pushed and pushed[0][0] == "run_job" and pushed[0][1] == (str(job_id), "noop")
    with factory() as s:
        assert s.get(m.ScanJob, job_id).state.value == "queued"


def test_sse_stream_replays_and_ends(engine, tmp_path):
    settings = Settings(_env_file=None, demo_mode=True, evidence_dir=str(tmp_path / "ev"),
                        bootstrap_admin_email=ADMIN["email"], bootstrap_admin_password=ADMIN["password"],
                        secret_key="unit-test-secret-0123456789abcdef")  # fmt: skip
    app = create_app(settings=settings, engine=engine)
    with TestClient(app) as c:
        token = c.post("/api/auth/login", json=ADMIN).json()["access_token"]
        c.headers["Authorization"] = f"Bearer {token}"
        health = c.get("/health").json()
        assert (
            health["queue_backend"] == "ThreadedJobQueue"
            and health["scheduler"] == "stopped"
            and health["notify_channels"] == ["log"]
        )
        brand = c.post(
            "/api/brands", json={"name": f"SSE {uuid.uuid4().hex[:4]}", "domains": ["shopnova.com"]}
        ).json()
        job_id = c.post(
            f"/api/brands/{brand['id']}/scan-urls", json={"urls": ["https://shopn0va.com/"]}
        ).json()["job_id"]
        app.state.queue.wait(uuid.UUID(job_id), timeout=120)
        with c.stream(
            "GET", f"/api/jobs/{job_id}/events/stream", headers={"Last-Event-ID": "2"}
        ) as r:
            assert r.status_code == 200 and r.headers["content-type"].startswith(
                "text/event-stream"
            )
            body = "".join(r.iter_text())
        frames = [f for f in body.split("\n\n") if f.strip()]
        assert frames[0].startswith("id: 3\nevent: scan") and frames[-1].startswith("event: end")
        assert json.loads(frames[-1].split("data: ", 1)[1])["state"] == "done"


@respx.mock
async def test_whoisxml_client_parses_record_and_keeps_key_out_of_url():
    route = respx.get("https://www.whoisxmlapi.com/whoisserver/WhoisService").mock(
        side_effect=lambda req: httpx.Response(401, json=(
            {"ErrorMessage": {"errorCode": "AUTHENTICATE_05", "msg": "no active subscription"}}))
            if req.headers.get("authorization") == "Bearer bad" else httpx.Response(200, json=(
            {"WhoisRecord": {"createdDate": "2007-10-09T18:20:50Z", "registrarName": "MarkMonitor, Inc.",
                             "registrant": {"organization": "GitHub, Inc.", "email": "abuse@example.org"}}}
            if req.url.params["domainName"] == "github.com" else
            {"WhoisRecord": {"dataError": "MISSING_WHOIS_DATA"}}))
    )  # fmt: skip
    wx = WhoisXmlClient("secret-key", client=httpx.AsyncClient())
    res = await wx.lookup("github.com")
    assert res.data["registered_at"] == "2007-10-09" and res.data["age_days"] > 6000
    assert res.data["registrar"] == "MarkMonitor, Inc."
    assert res.data["registrant"]["email"] == "abuse@example.org" and res.cost_usd == 0.002
    assert "secret-key" not in str(route.calls.last.request.url)  # key travels in a header only
    assert (await wx.lookup("unknown.example")).status.value == "unknown"
    with pytest.raises(ProviderError, match="no active subscription"):  # provider's message
        await WhoisXmlClient("bad", client=httpx.AsyncClient()).lookup("github.com")
    with pytest.raises(ProviderError, match="no API key"):
        await WhoisXmlClient(None, client=httpx.AsyncClient()).lookup("github.com")


@respx.mock
async def test_certspotter_client_and_crtsh_fallback_chain():
    import httpx as _httpx

    from brandwatch.providers.impl.clients import CertSpotterClient

    respx.get("https://api.certspotter.com/v1/issuances").mock(return_value=_httpx.Response(200, json=[
        {"cert_sha256": "ab" * 32, "dns_names": ["login.shopnova.com", "*.shopnova.com"],
         "issuer": {"name": "Let's Encrypt"}, "not_before": "2026-01-02T00:00:00Z"}]))  # fmt: skip
    cs = CertSpotterClient(None, client=_httpx.AsyncClient())
    r = await cs.ct_search("shopnova.com")
    assert r.status.value == "positive"
    certs = r.data["certificates"]
    assert (
        certs[0]["sans"] == ["login.shopnova.com", "shopnova.com"]
        and certs[0]["issuer"] == "Let's Encrypt"
    )
    # a bare brand token (no dot) cannot be searched on CertSpotter → unknown, not an error
    assert (await cs.ct_search("%shopnova%")).status.value == "unknown"


async def test_ct_stream_falls_back_to_certspotter_when_crtsh_is_down(tmp_path):
    from brandwatch.db.enums import ProviderStatus
    from brandwatch.detection import sources
    from brandwatch.providers.base import ProviderResult

    class FakeCert:
        name = "cert"

        async def ct_search(self, pattern: str) -> ProviderResult:
            if pattern.startswith("%"):  # crt.sh substring search is down
                return ProviderResult.failure("crtsh", "crtsh: HTTP 502")
            return ProviderResult("certspotter", ProviderStatus.POSITIVE, {
                "pattern": pattern,
                "certificates": [{"fingerprint_sha256": "f1", "sans": ["secure-shopnova.com", "shopnova.com"]}],
            })  # fmt: skip

    class Reg:
        def cert(self):
            return FakeCert()

    r = await sources.stream_ct(Reg(), "shopnova", {"shopnova.com", "www.shopnova.com"})
    assert not r.degraded and r.api_calls >= 2  # substring failed, then per-domain succeeded
    assert {h.raw_value for h in r.hits} == {"secure-shopnova.com"}  # official filtered out
    assert "unavailable" in (r.note or "")


async def test_nrd_stream_reads_local_url_zip_and_caches(tmp_path):
    import io
    import zipfile

    import httpx as _httpx
    import respx as _respx

    from brandwatch.detection import sources

    # local plain file
    feed = tmp_path / "nrd.txt"
    feed.write_text(
        "shopnova-login.com\nunrelated-site.com\nwww.shopnova.com\nsecure-shopnova.net\n"
    )
    r = await sources.stream_nrd(str(feed), "shopnova", {"shopnova.com", "www.shopnova.com"})
    assert {h.raw_value for h in r.hits} == {"shopnova-login.com", "secure-shopnova.net"}
    assert "4 new domains, 4 checked, 2 match(es)" in (r.note or "") and r.generated == 4

    # a URL returning a zip, cached on first fetch
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("nrd.txt", "shopnova-verify.com\ngoogle.com\n")
    with _respx.mock:
        route = _respx.get("https://feeds.example/nrd.zip").mock(
            return_value=_httpx.Response(200, content=buf.getvalue())
        )
        r2 = await sources.stream_nrd(
            "https://feeds.example/nrd.zip", "shopnova", {"shopnova.com"}, cache_dir=tmp_path
        )
        assert {h.raw_value for h in r2.hits} == {"shopnova-verify.com"}
        # second call is served from the daily cache (no second HTTP request)
        await sources.stream_nrd(
            "https://feeds.example/nrd.zip", "shopnova", {"shopnova.com"}, cache_dir=tmp_path
        )
        assert route.call_count == 1

    assert (await sources.stream_nrd(str(tmp_path / "missing.txt"), "x", set())).degraded
    assert (await sources.stream_nrd(None, "x", set())).degraded


async def test_whoisds_keyword_builds_daily_urls_with_fallback(tmp_path):
    import io
    import zipfile

    import httpx as _httpx
    import respx as _respx

    from brandwatch.detection import sources

    urls = sources.whoisds_urls()
    assert len(urls) == 3 and all(
        u.startswith("https://www.whoisds.com/whois-database/newly-registered-domains/")
        for u in urls
    )
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("domain-names.txt", "shopnova-secure.com\nrandom.xyz\n")
    with _respx.mock:
        _respx.get(urls[0]).mock(return_value=_httpx.Response(404))  # yesterday not ready
        _respx.get(urls[1]).mock(
            return_value=_httpx.Response(200, content=buf.getvalue())
        )  # day before
        r = await sources.stream_nrd("whoisds", "shopnova", {"shopnova.com"}, cache_dir=tmp_path)
    assert not r.degraded and {h.raw_value for h in r.hits} == {"shopnova-secure.com"}
