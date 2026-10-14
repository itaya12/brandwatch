"""A security product already says "phishing": rate it High, and do not open the site any further.

Cloudflare, an antivirus on the scanning machine or a DNS filter often answers a scan with its own "this site is
phishing" page. That is a verdict somebody else already made. BrandWatch used to press "Ignore & Proceed" and study the
site behind it with a Chromium visit, cloaking probes and an AI opinion, and rated it only by the points it collected.
Now the verdict itself is the finding: the signal ``known_phishing`` and its rule floor the severity at High, a plain HTTP
request (not a browser) is enough to see a Cloudflare warning, and the analyst's Rescan is the full check.
"""

from __future__ import annotations

import asyncio
import uuid

import httpx
import respx
import sqlalchemy as sa
from fastapi.testclient import TestClient
from tests.conftest import make_brand, make_workspace
from tests.test_demo_story import _api, _app, _ui

import brandwatch.db.models as m
from brandwatch.config.brand_config import DEFAULT_COMBINATION_RULES, BrandConfig, ScoringConfig
from brandwatch.config.settings import Settings
from brandwatch.db.enums import ProviderStatus, Severity
from brandwatch.detection.discovery import manual_hits
from brandwatch.detection.html import security_warning
from brandwatch.detection.runner import run_scan

KASPERSKY = ("Dangerous link blocked", "<h1>Kaspersky: dangerous link blocked</h1><p>Kaspersky Internet Security blocked this page. It was reported as a phishing site.</p>")


# ------------------------------------------------------------------------------------------ the detector
def test_security_product_warning_pages_are_recognised_and_attributed():
    assert security_warning(*KASPERSKY)["vendor"] == "Kaspersky"
    assert security_warning("This site has been reported as unsafe", "<p>Microsoft Defender SmartScreen reported this site as a phishing site.</p>")["vendor"] == "Microsoft Defender SmartScreen"
    assert security_warning("Site blocked", "<p>This site is blocked due to a phishing threat. Cisco Umbrella</p>")["vendor"] == "Cisco Umbrella / OpenDNS"
    assert security_warning("Phishing site blocked", "<p>Access to this page was stopped.</p>")["vendor"] == "a security service"  # a tiny page whose own title says so
    cf = security_warning("Suspected Phishing | Cloudflare", "<html><form action='/cdn-cgi/phish-bypass'></form></html>")
    assert cf["vendor"] == "Cloudflare" and "Suspected Phishing" in cf["reason"]


def test_pages_that_are_not_a_verdict_are_left_alone():
    for title, body in (
        ("Sign in", "<form><input type=password></form><p>Beware of phishing emails. Report suspected phishing to us.</p>"),  # a bank's own notice
        ("What is phishing?", "<p>" + "Phishing is a scam that steals passwords. " * 300 + "</p>"),  # an article
        ("Access Denied", "<h1>Access Denied</h1>"),  # a block, not a verdict
        ("Just a moment...", "<p>Checking your browser before accessing the site</p>"),  # a bot check
        ("Phishing awareness training", "<p>Learn to spot phishing. Warning signs include urgent requests.</p>"),
        ("ShopNova — Sign in", "<form><input type=password></form>"),
    ):
        assert security_warning(title, body) is None, title
    assert security_warning(None, None) is None


# ------------------------------------------------------------------------------------------ the scan
def _scan(engine, tmp_path, urls, *, full_check=False, brand="ShopNova", official="shopnova.com"):
    from brandwatch.db.base import make_session_factory

    settings = Settings(_env_file=None, demo_mode=True, evidence_dir=str(tmp_path / f"ev-{uuid.uuid4().hex[:6]}"))
    with make_session_factory(engine)() as s:
        ws = make_workspace(s, f"kp-{uuid.uuid4().hex[:6]}")
        b = make_brand(s, ws, brand)
        s.add(m.BrandDomain(brand_id=b.id, domain=official, is_official=True, kind="official"))
        job = m.ScanJob(workspace_id=ws.id, brand_id=b.id, kind="url_scan", payload={"full_check": True} if full_check else None)
        s.add(job)
        s.flush()
        summary = asyncio.run(run_scan(s, job.id, settings=settings, hits=manual_hits(urls)))
        s.commit()
        events = s.scalars(sa.select(m.ScanEventRecord).where(m.ScanEventRecord.job_id == job.id).order_by(m.ScanEventRecord.seq)).all()
        out = {}
        for u in urls:
            host = u.split("/")[2]
            cand = s.scalars(sa.select(m.Candidate).where(m.Candidate.brand_id == b.id, m.Candidate.canonical_domain == host)).first()
            f = s.scalars(sa.select(m.Finding).where(m.Finding.candidate_id == cand.id)).first() if cand else None
            cur = f.current_score if f else None
            out[host] = {"signals": dict(cur.signals or {}) if cur else {}, "severity": cur.severity if cur else None,
                         "breakdown": dict((cur.groups or {}).get("_breakdown", {})) if cur else {}}  # fmt: skip
        return summary, events, out


def test_a_cloudflare_warning_is_rated_high_and_no_browser_is_launched(engine, tmp_path, monkeypatch):
    from brandwatch.providers.mock import MockBrowserFetcher

    real_fetch = MockBrowserFetcher.fetch
    visits: list[str] = []

    async def spy(self, url, profile="datacenter"):
        visits.append(url)
        return await real_fetch(self, url, profile)

    monkeypatch.setattr(MockBrowserFetcher, "fetch", spy)
    summary, events, out = _scan(engine, tmp_path, ["https://shopnova--sneakers.com/"])
    o = out["shopnova--sneakers.com"]
    assert [v for v in visits if "sneakers" in v] == []  # a plain request saw the warning: Chromium was never asked for it (only the brand's own site)
    assert o["severity"] in (Severity.HIGH, Severity.CRITICAL)
    sig = o["signals"]
    assert "known_phishing" in sig and "cloudflare_phishing_warning" in sig and sig["_security_warning"]["vendor"] == "Cloudflare"
    assert "known_phishing_verdict" in [x["rule"] for x in o["breakdown"]["combination_rules_fired"]]
    assert "payment_form" not in sig and "title_claims_brand" not in sig  # the store behind the warning was not studied
    said = [e.message for e in events if e.stage == "enrichment"]
    assert any(x.startswith("shopnova--sneakers.com is already flagged as phishing by Cloudflare — rated High") for x in said), said
    assert not [e for e in events if e.stage == "cloaking"]  # no cloaking probes
    step = next(st for st in summary.steps if "already flagged as phishing by a security service" in st["title"])
    assert step["title"].startswith("1 site(s) were already flagged") and step["items"][0] == {"label": "shopnova--sneakers.com", "tag": "Cloudflare"}


def test_an_antivirus_warning_page_is_a_verdict_too(engine, tmp_path):
    summary, events, out = _scan(engine, tmp_path, ["https://shopnova-id-check.com/"])
    o = out["shopnova-id-check.com"]
    assert o["severity"] in (Severity.HIGH, Severity.CRITICAL), o["signals"]
    assert o["signals"]["_security_warning"]["vendor"] == "Kaspersky"
    assert "ai" not in o["breakdown"]  # no advisory opinion on a verdict somebody else made
    assert not [e for e in events if e.stage == "cloaking"]


def test_an_ordinary_site_is_visited_as_before(engine, tmp_path):
    summary, events, out = _scan(engine, tmp_path, ["https://shopn0va.com/"])
    sig = out["shopn0va.com"]["signals"]
    assert "_security_warning" not in sig and "screenshot_similarity_ge_90" in sig  # the browser looked
    assert not any("already flagged" in st["title"] for st in summary.steps)


def test_an_analysts_full_check_looks_behind_the_warning(engine, tmp_path):
    summary, events, out = _scan(engine, tmp_path, ["https://shopnova--sneakers.com/"], full_check=True)
    sig = out["shopnova--sneakers.com"]["signals"]
    assert "payment_form" in sig and "title_claims_brand" in sig  # the store behind it
    assert "known_phishing" in sig  # and the verdict still counts


def test_rescan_asks_for_the_full_check(engine, tmp_path):
    app = _app(engine, tmp_path)
    with TestClient(app):
        c = _api(app)
        brand = c.post("/api/brands", json={"name": f"Rs {uuid.uuid4().hex[:4]}", "domains": ["shopnova.com"], "preset": "basic"}).json()
        job = c.post(f"/api/brands/{brand['id']}/scan-urls", json={"urls": ["https://shopnova--sneakers.com/"]}).json()["job_id"]
        app.state.queue.wait(uuid.UUID(job), timeout=120)
        cand = c.get("/api/candidates", params={"brand_id": brand["id"]}).json()
        cid = (cand["items"] if isinstance(cand, dict) else cand)[0]["id"]
        rid = c.post(f"/api/candidates/{cid}/rescan").json()["job_id"]
        app.state.queue.wait(uuid.UUID(rid), timeout=120)
        with app.state.session_factory() as s:
            assert s.get(m.ScanJob, uuid.UUID(rid)).payload["full_check"] is True


def test_the_finding_page_says_somebody_already_judged_it(engine, tmp_path):
    app = _app(engine, tmp_path)
    with TestClient(app):
        ui, c = _ui(app), _api(app)
        brand = c.post("/api/brands", json={"name": f"Fp {uuid.uuid4().hex[:4]}", "domains": ["shopnova.com"], "preset": "basic"}).json()
        job = c.post(f"/api/brands/{brand['id']}/scan-urls", json={"urls": ["https://shopnova-id-check.com/"]}).json()["job_id"]
        app.state.queue.wait(uuid.UUID(job), timeout=120)
        fid = next(f["id"] for f in c.get("/api/findings", params={"brand_id": brand["id"]}).json() if f["hostname"] == "shopnova-id-check.com")
        page = ui.get(f"/ui/findings/{fid}").text
        assert "Already flagged as phishing by Kaspersky." in page and "Press <b>Rescan</b> for a full check" in page


# ------------------------------------------------------------------------------------------ the other verdict sources and the scoring
def _evidence(**kw):
    from brandwatch.detection.enrichment import CollectedEvidence

    return CollectedEvidence(candidate_id=uuid.uuid4(), url="https://plain-widgets.example/", host="plain-widgets.example", registrable="plain-widgets.example", **kw)


def _analyze(ev):
    from brandwatch.detection.analysis import analyze
    from brandwatch.detection.baseline import BrandBaseline

    base = BrandBaseline(brand_id=uuid.uuid4(), brand_key="acme", version=1, official_domains=("acme.com",), favicon_mmh3=None,
                         favicon_phash=None, screenshot_phash=None, screenshot_dhash=None, palette=(), keywords=("acme",))  # fmt: skip
    return analyze(ev, base, BrandConfig.for_preset("standard").scoring)


def test_blocklists_and_engines_are_verdicts_when_they_say_phishing():
    positive = ProviderStatus.POSITIVE
    sb = _analyze(_evidence(reputation={"safebrowsing": positive}, reputation_detail={"safebrowsing": {"threats": ["SOCIAL_ENGINEERING"]}}))
    assert "known_phishing" in sb.signals and "Google Safe Browsing" in sb.details["signals"]["known_phishing"]
    pt = _analyze(_evidence(reputation={"phishtank": positive}))
    assert "known_phishing" in pt.signals and "PhishTank" in pt.details["signals"]["known_phishing"]
    vt3 = _analyze(_evidence(reputation={"virustotal": positive}, reputation_detail={"virustotal": {"phishing_engines": ["Fortinet", "Kaspersky", "Sophos"]}}))
    assert "known_phishing" in vt3.signals and "3 VirusTotal engines" in vt3.details["signals"]["known_phishing"]
    # not every flag is "phishing": malware lists, one engine, a malware threat type
    for ev in (_evidence(reputation={"urlhaus": positive}),
               _evidence(reputation={"safebrowsing": positive}, reputation_detail={"safebrowsing": {"threats": ["MALWARE"]}}),
               _evidence(reputation={"virustotal": positive}, reputation_detail={"virustotal": {"phishing_engines": ["Fortinet", "Sophos"]}}),
               _evidence()):
        assert "known_phishing" not in _analyze(ev).signals


def test_the_verdict_alone_floors_the_severity_at_high():
    from brandwatch.detection.scoring import score

    cfg = BrandConfig.for_preset("standard").scoring
    an = _analyze(_evidence(security_warning={"vendor": "Kaspersky", "reason": "x"}))
    assert set(an.signals) == {"known_phishing"}  # nothing else about this domain looks wrong
    risk = score(an, cfg)
    assert risk.severity is Severity.HIGH and [r["rule"] for r in risk.breakdown["combination_rules_fired"]] == ["known_phishing_verdict"]
    assert score(_analyze(_evidence()), cfg).severity is Severity.LOW


def test_a_single_signal_rule_is_allowed_and_older_saved_configs_gain_it():
    assert any(r.name == "known_phishing_verdict" and r.signals_all == ["known_phishing"] for r in DEFAULT_COMBINATION_RULES)
    saved = ScoringConfig().model_dump(mode="json")
    saved["version"] = "v2"
    saved["weights"].pop("known_phishing")
    saved["combination_rules"] = [r for r in saved["combination_rules"] if r["name"] != "known_phishing_verdict"]
    up = ScoringConfig.model_validate(saved)
    assert up.weights["known_phishing"] == 15 and any(r.name == "known_phishing_verdict" for r in up.combination_rules)
    assert up.version.endswith("+c7")


@respx.mock
async def test_virustotal_reports_which_engines_say_phishing():
    from brandwatch.providers.impl.clients import VirusTotalClient

    respx.get("https://www.virustotal.com/api/v3/domains/bad.example").mock(return_value=httpx.Response(200, json={"data": {"attributes": {
        "last_analysis_stats": {"malicious": 4, "suspicious": 0, "harmless": 60},
        "last_analysis_results": {"Fortinet": {"category": "malicious", "result": "phishing"}, "Kaspersky": {"category": "malicious", "result": "Phishing"},
                                  "Sophos": {"category": "malicious", "result": "malware"}, "Google": {"category": "harmless", "result": "clean"}}}}}))
    res = await VirusTotalClient("k", client=httpx.AsyncClient()).lookup_domain("bad.example")
    assert res.status is ProviderStatus.POSITIVE and res.data["phishing_engines"] == ["Fortinet", "Kaspersky"]


def test_the_catalogue_names_the_signal(engine, tmp_path):
    from brandwatch.api.labels import signal_label

    assert signal_label("known_phishing") == "already flagged as phishing"


def test_a_site_served_by_cloudflare_is_recognised_by_its_addresses():
    from brandwatch.detection.enrichment import _on_cloudflare

    assert _on_cloudflare(["104.16.132.229"]) and _on_cloudflare(["203.0.113.5", "172.67.1.2"]) and _on_cloudflare(["2606:4700::6810:84e5"])
    assert not _on_cloudflare(["8.8.8.8", "2001:db8::1"]) and not _on_cloudflare([]) and not _on_cloudflare(None) and not _on_cloudflare(["not-an-ip"])
