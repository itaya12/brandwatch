"""Phase 1 vertical slice: discovery → normalize/dedup → evidence → signals → score → finding."""

from __future__ import annotations

import pytest
import sqlalchemy as sa
from tests.conftest import make_brand, make_user, make_workspace

import brandwatch.db.models as m
from brandwatch.config.brand_config import ScoringConfig
from brandwatch.config.settings import Settings
from brandwatch.db.enums import (
    CandidateState,
    DiscoverySource,
    EvidenceRole,
    EvidenceType,
    FindingState,
    Severity,
    Surface,
)
from brandwatch.detection import scoring
from brandwatch.detection.discovery import (
    discover_dnstwist,
    interleave_by_fuzzer,
    manual_hits,
    split_host,
)
from brandwatch.detection.finding import confirm, dismiss
from brandwatch.detection.html import extract_features
from brandwatch.detection.normalize import deduplicate, normalize, pre_filter, whitelist_for
from brandwatch.detection.runner import run_scan
from brandwatch.events.emitter import replay
from brandwatch.pipeline.stages import AnalysisResult, DiscoveryHit
from brandwatch.providers.mock.fixtures import default_store


# --------------------------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------------------------
def demo_settings(tmp_path) -> Settings:
    return Settings(_env_file=None, demo_mode=True, evidence_dir=str(tmp_path / "evidence"))


def onboard_demo_brand(session):
    ws = make_workspace(session, "demo")
    brand = make_brand(session, ws, "ShopNova")
    session.add(m.BrandDomain(brand_id=brand.id, domain="shopnova.com"))
    session.add(m.BrandDomain(brand_id=brand.id, domain="www.shopnova.com", kind="alias"))
    job = m.ScanJob(workspace_id=ws.id, brand_id=brand.id, kind="url_scan")
    session.add(job)
    session.flush()
    return ws, brand, job


def analysis_of(signals: dict[str, float], **details) -> AnalysisResult:
    d = {
        "screenshot_captured": True,
        "html_captured": True,
        "whois_age_days": 5,
        "reputation_positives": 0,
    }
    d.update(details.pop("details", {}))
    return AnalysisResult(signals=signals, evidence_refs=(), details=d, **details)


# --------------------------------------------------------------------------------------------
# discovery (pure)
# --------------------------------------------------------------------------------------------
def test_dnstwist_discovery_finds_known_lookalikes_and_excludes_official():
    hits = discover_dnstwist(["shopnova.com", "www.shopnova.com"], max_hits=500)
    hosts = {h.raw_value for h in hits}
    assert {
        "shopn0va.com",
        "shopnova-login.com",
        "secure-shopnova.com",
        "shopnova.co",
        "shopnovaa.com",
    } <= hosts
    assert "shopnova.com" not in hosts and "www.shopnova.com" not in hosts
    assert all(h.source is DiscoverySource.DNSTWIST and h.surface is Surface.NAME for h in hits)
    assert len(hits) == 500
    first_fuzzers = {h.matched_pattern.split(":")[0] for h in hits[:30]}
    assert len(first_fuzzers) >= 8, "the cap must sample every permutation technique"


def test_interleave_round_robins_in_priority_order():
    perms = [("homoglyph", f"h{i}.com") for i in range(5)] + [
        ("dictionary", "d0.com"),
        ("tld-swap", "t0.co"),
    ]
    out = interleave_by_fuzzer(perms)
    assert out[:3] == [("dictionary", "d0.com"), ("tld-swap", "t0.co"), ("homoglyph", "h0.com")]
    assert len(out) == 7


def test_split_host_uses_bundled_public_suffix_list():
    assert split_host("login.shopnova.co.uk").registrable == "shopnova.co.uk"
    assert split_host("shopnova.com").sld == "shopnova"


# --------------------------------------------------------------------------------------------
# normalize / dedup / pre-filter
# --------------------------------------------------------------------------------------------
def test_normalize_variants():
    name = normalize(DiscoveryHit(DiscoverySource.DNSTWIST, "ShopN0va.com.", Surface.NAME))
    assert name.canonical_url == "https://shopn0va.com/" and name.surface is Surface.NAME
    sub = normalize(DiscoveryHit(DiscoverySource.CT, "login.shopnova-evil.com", Surface.NAME))
    assert sub.surface is Surface.SUBDOMAIN and sub.canonical_domain == "shopnova-evil.com"
    path = normalize(
        DiscoveryHit(DiscoverySource.MANUAL, "http://evil.com/shopnova/login", Surface.NAME)
    )
    assert path.surface is Surface.PATH and path.canonical_url == "http://evil.com/shopnova/login/"
    idn = normalize(DiscoveryHit(DiscoverySource.MANUAL, "https://shopnovа.com/", Surface.NAME))
    assert idn.hostname.startswith("xn--")
    assert normalize(DiscoveryHit(DiscoverySource.MANUAL, "not a host", Surface.NAME)) is None
    assert normalize(DiscoveryHit(DiscoverySource.MANUAL, "localhost", Surface.NAME)) is None


def test_manual_hits_detect_surface():
    hits = manual_hits(["evil.com", "https://evil.com/paypal/login", ""])
    assert [h.surface for h in hits] == [Surface.NAME, Surface.PATH]


def test_deduplicate_one_candidate_many_sources(session):
    brand = make_brand(session, make_workspace(session))
    n1 = normalize(
        DiscoveryHit(DiscoverySource.DNSTWIST, "shopn0va.com", Surface.NAME, "homoglyph")
    )
    n2 = normalize(DiscoveryHit(DiscoverySource.CT, "shopn0va.com", Surface.NAME, "san"))
    n3 = normalize(DiscoveryHit(DiscoverySource.CT, "shopn0va.com", Surface.NAME, "san-again"))
    r1, r2, r3 = (deduplicate(session, brand.id, n) for n in (n1, n2, n3))
    assert r1.is_new and r1.source_added
    assert not r2.is_new and r2.source_added and r2.candidate_id == r1.candidate_id
    assert not r3.is_new and not r3.source_added
    sources = session.scalars(
        sa.select(m.CandidateSource.source).where(m.CandidateSource.candidate_id == r1.candidate_id)
    ).all()
    assert sorted(sources) == [DiscoverySource.CT, DiscoverySource.DNSTWIST]


def test_pre_filter_whitelist_is_fail_open():
    wl = whitelist_for(["shopnova.com", "www.shopnova.com"], extra=["cdn.shopnova-static.net"])
    assert not pre_filter("shopnova.com", wl).keep
    assert not pre_filter("login.shopnova.com", wl).keep
    assert not pre_filter("img.cdn.shopnova-static.net", wl).keep
    assert pre_filter("shopnova-login.com", wl).keep
    assert pre_filter("shopn0va.com", wl).keep


# --------------------------------------------------------------------------------------------
# HTML features (on recorded scenarios)
# --------------------------------------------------------------------------------------------
def test_html_features_from_golden_scenarios():
    st = default_store()
    clone = st.get("shopn0va.com")
    f = extract_features(clone.http["html"], clone.url, ["shopnova", "free shipping"])
    assert f.credential_form and "shopnova" in f.brand_keywords and f.lure_terms
    assert f.favicon_url == "https://shopn0va.com/favicon.ico"
    exfil = st.get("shopnova-login.com")
    assert extract_features(exfil.http["html"], exfil.url, []).external_form_action
    outlet = st.get("shopnova-outlet-store.com")
    f2 = extract_features(outlet.http["html"], outlet.url, [])
    assert f2.payment_form and not f2.credential_form
    parked = st.get("shopnovaa.com")
    assert extract_features(parked.http["html"], parked.url, []).is_parked
    partner = st.get("shopnova-partners.com")
    f3 = extract_features(partner.http["html"], partner.url, ["shopnova"])
    assert not f3.credential_form and not f3.payment_form and "shopnova" in f3.brand_keywords


# --------------------------------------------------------------------------------------------
# scoring (pure)
# --------------------------------------------------------------------------------------------
def test_scoring_confident_clone_is_critical_with_high_confidence():
    cfg = ScoringConfig()
    an = analysis_of(
        {"brand_exact_in_domain": 12, "levenshtein_le_2": 8, "favicon_exact": 22, "screenshot_similarity_ge_90": 18,
         "credential_form": 14, "lure_language": 6, "brand_keywords_in_content": 6, "age_lt_7d": 10, "vt_flagged": 12},
        details={"reputation_positives": 2},
    )  # fmt: skip
    r = scoring.score(an, cfg)
    assert r.severity is Severity.CRITICAL and r.score >= 75
    assert r.groups["visual"] == 30 and r.groups["identity"] == 20  # caps applied
    assert r.breakdown["bonus_total"] == 15  # favicon_exact + credential_form + brand_exact cluster
    assert r.confidence >= 90
    assert r.scoring_version == "v7"


def test_scoring_ambiguous_suspect_has_lower_confidence():
    cfg = ScoringConfig()
    an = analysis_of(
        {
            "brand_exact_in_domain": 12,
            "combosquat": 8,
            "favicon_phash_near": 14,
            "credential_form": 14,
        },
        unavailable=("screenshot", "reputation", "whois"),
        details={"screenshot_captured": False, "whois_age_days": None},
    )
    r = scoring.score(an, cfg)
    assert r.severity in (Severity.MEDIUM, Severity.HIGH)
    assert r.confidence < 60
    assert r.breakdown["confidence"]["unavailable_penalty"] == -24


def test_scoring_partner_site_is_low_after_fp_penalty():
    cfg = ScoringConfig()
    an = analysis_of({"brand_exact_in_domain": 12, "combosquat": 8, "brand_keywords_in_content": 6}, fp_flags=("age_gt_2y",),
                     details={"whois_age_days": 900})  # fmt: skip
    r = scoring.score(an, cfg)
    assert r.severity is Severity.LOW and r.breakdown["penalty_total"] == -15


def test_combination_rule_floors_severity():
    cfg = ScoringConfig()
    an = analysis_of({"screenshot_similarity_ge_90": 18, "credential_form": 14, "age_lt_30d": 6})
    r = scoring.score(an, cfg)
    assert r.raw < cfg.raw_max * cfg.thresholds.high / 100  # by sum alone this would be Medium …
    assert r.severity is Severity.HIGH  # … but the rule floors it
    assert r.score == cfg.thresholds.high  # and the number follows, so "HIGH · 38" never shows
    assert r.breakdown["combination_rules_fired"][0]["rule"] == "fresh_lookalike_login"


def test_scoring_is_deterministic_and_unknown_reputation_adds_nothing():
    cfg = ScoringConfig()
    an = analysis_of({"credential_form": 14}, details={"reputation": {"virustotal": "unknown"}})
    assert scoring.score(an, cfg) == scoring.score(an, cfg)
    assert scoring.score(an, cfg).groups["reputation"] == 0


# --------------------------------------------------------------------------------------------
# end-to-end in demo mode (mock providers, recorded scenarios)
# --------------------------------------------------------------------------------------------
async def test_url_scan_end_to_end_creates_findings_and_evidence(session, tmp_path):
    ws, brand, job = onboard_demo_brand(session)
    urls = ["https://shopn0va.com/", "https://shopnova-partners.com/", "https://shopnovaa.com/",
            "https://does-not-exist-shopnova.com/", "https://www.shopnova.com/"]  # fmt: skip
    summary = await run_scan(
        session, job.id, settings=demo_settings(tmp_path), hits=manual_hits(urls)
    )

    assert summary.whitelisted == 1  # www.shopnova.com
    assert summary.processed == 4
    by_host = {o.host: o for o in summary.outcomes}
    assert by_host["shopn0va.com"].disposition == "finding"
    assert by_host["shopn0va.com"].severity is Severity.CRITICAL
    assert by_host["shopnova-partners.com"].disposition == "watch"  # Low → watchlist, no Finding
    assert by_host["shopnovaa.com"].disposition == "watch"  # parked
    assert by_host["does-not-exist-shopnova.com"].disposition == "dismissed"  # NXDOMAIN

    # baseline built on first run
    fp = session.scalars(
        sa.select(m.BrandFingerprint).where(m.BrandFingerprint.brand_id == brand.id)
    ).one()
    assert fp.favicon_mmh3 is not None and "shopnova" in fp.keywords["terms"]

    # finding + current score + explainable signals
    finding = session.scalars(sa.select(m.Finding).where(m.Finding.brand_id == brand.id)).one()
    assert finding.state is FindingState.OPEN and finding.severity is Severity.CRITICAL
    cur = finding.current_score
    assert (
        cur.is_current and cur.score >= 60 and cur.scoring_version == "v7"
    )  # rule floors to Critical
    fired = {k for k in cur.signals if not k.startswith("_")}
    assert {
        "favicon_exact",
        "credential_form",
        "levenshtein_le_2",
        "age_lt_7d",
        "vt_flagged",
    } <= fired
    assert cur.signals["_details"]["favicon_exact"].startswith("favicon mmh3")

    # evidence rows with provenance, roles and a chain
    links = session.scalars(
        sa.select(m.FindingEvidence).where(m.FindingEvidence.finding_id == finding.id)
    ).all()
    roles = {session.get(m.Evidence, link.evidence_id).type: link.role for link in links}
    assert roles[EvidenceType.FAVICON] is EvidenceRole.PRIMARY
    assert roles[EvidenceType.HTML] is EvidenceRole.PRIMARY
    assert roles[EvidenceType.DNS] is EvidenceRole.SUPPORTING
    shot = next(
        session.get(m.Evidence, link.evidence_id)
        for link in links
        if session.get(m.Evidence, link.evidence_id).type is EvidenceType.SCREENSHOT
    )
    assert shot.artifact_location.startswith("local://") and shot.parent_evidence_id is not None
    assert (tmp_path / "evidence").exists()

    # observation timeline + candidate states
    cand = session.get(m.Candidate, finding.candidate_id)
    assert (
        cand.state is CandidateState.FLAGGED
        and cand.scan_count == 1
        and cand.next_scan_at is not None
    )
    obs = session.scalars(
        sa.select(m.Observation).where(m.Observation.candidate_id == cand.id)
    ).all()
    assert len(obs) == 1 and obs[0].screenshot_evidence_id == shot.id and obs[0].http_status == 200
    states = dict(
        session.execute(
            sa.select(m.Candidate.hostname, m.Candidate.state).where(
                m.Candidate.brand_id == brand.id
            )
        ).all()
    )
    assert states["does-not-exist-shopnova.com"] is CandidateState.DISMISSED
    assert states["shopnovaa.com"] is CandidateState.WATCHING

    # live console feed
    events = replay(session, job.id)
    assert events[0].stage == "baseline" and events[-1].stage == "summary"
    assert any("Favicon vs official: MATCH" in e.message for e in events)
    assert any("CRITICAL" in e.message for e in events if e.stage == "scoring")
    assert events[-1].data["findings"] == 1 and events[-1].data["cost_usd"] == 0.0
    job = session.get(m.ScanJob, job.id)
    assert job.state.value == "done"


async def test_rescan_appends_score_history_and_keeps_one_current(session, tmp_path):
    ws, brand, job = onboard_demo_brand(session)
    settings = demo_settings(tmp_path)
    await run_scan(session, job.id, settings=settings, hits=manual_hits(["https://shopn0va.com/"]))
    job2 = m.ScanJob(workspace_id=ws.id, brand_id=brand.id, kind="url_scan")
    session.add(job2)
    session.flush()
    summary = await run_scan(
        session, job2.id, settings=settings, hits=manual_hits(["https://shopn0va.com/"])
    )
    assert summary.existing_candidates == 1 and summary.new_candidates == 0
    finding = session.scalars(sa.select(m.Finding).where(m.Finding.brand_id == brand.id)).one()
    scores = session.scalars(
        sa.select(m.RiskScore).where(m.RiskScore.finding_id == finding.id)
    ).all()
    assert len(scores) == 2 and sum(s.is_current for s in scores) == 1
    cand = session.get(m.Candidate, finding.candidate_id)
    assert cand.scan_count == 2
    assert (
        len(
            session.scalars(
                sa.select(m.Observation).where(m.Observation.candidate_id == cand.id)
            ).all()
        )
        == 2
    )


async def test_analyst_confirm_and_dismiss_are_audited(session, tmp_path):
    ws, brand, job = onboard_demo_brand(session)
    analyst = make_user(session, ws, "analyst@shopnova.test")
    await run_scan(
        session, job.id, settings=demo_settings(tmp_path),
        hits=manual_hits(["https://shopn0va.com/", "https://shopnova-verify.com/"]),
    )  # fmt: skip
    findings = {
        session.get(m.Candidate, f.candidate_id).hostname: f
        for f in session.scalars(sa.select(m.Finding).where(m.Finding.brand_id == brand.id)).all()
    }
    clone, outlet = findings["shopn0va.com"], findings["shopnova-verify.com"]
    # no favicon match, but the page looks 100% like the real site: above 85% the risk is very high
    assert outlet.severity is Severity.CRITICAL

    confirm(session, clone, analyst, reason="cloned login, exfil form")
    dismiss(session, outlet, analyst, reason="registrar already took it down")
    assert clone.state is FindingState.CONFIRMED and clone.analyst_verdict.value == "phishing"
    assert outlet.state is FindingState.DISMISSED
    assert session.get(m.Candidate, outlet.candidate_id).state is CandidateState.DISMISSED
    labels = session.scalars(
        sa.select(m.AnalystLabel).where(m.AnalystLabel.finding_id.in_([clone.id, outlet.id]))
    ).all()
    assert {lab.label for lab in labels} == {"phishing", "legitimate"}
    actions = session.scalars(
        sa.select(m.AuditEvent.action).where(m.AuditEvent.actor_id == analyst.id)
    ).all()
    assert sorted(actions) == ["finding.confirmed", "finding.dismissed"]
    with pytest.raises(ValueError):
        confirm(session, clone, analyst)  # already confirmed: analyst-only transition is final


async def test_dnstwist_scan_with_cap_whitelists_and_dismisses(session, tmp_path):
    ws, brand, job = onboard_demo_brand(session)
    job.kind = "brand_scan"
    summary = await run_scan(session, job.id, settings=demo_settings(tmp_path), max_candidates=40)
    assert summary.hits == 40 and summary.new_candidates == 40
    assert summary.dismissed >= 30  # unregistered permutations do not resolve in demo mode
    assert summary.errors == 0
    stages = [
        s.name
        for s in session.scalars(sa.select(m.ScanStage).where(m.ScanStage.job_id == job.id)).all()
    ]
    assert stages == [
        "baseline",
        "discovery",
        "normalize_dedup_prefilter",
        "enrichment_analysis_scoring",
    ]


def test_exact_brand_on_another_tld_that_calls_itself_the_brand_is_high():
    import uuid as _uuid

    from brandwatch.detection.analysis import analyze
    from brandwatch.detection.baseline import BrandBaseline
    from brandwatch.detection.enrichment import CollectedEvidence
    from brandwatch.detection.html import extract_features

    base = BrandBaseline(
        brand_id=_uuid.uuid4(), brand_key="cryptohopper", official_domains=("cryptohopper.com", "www.cryptohopper.com"),
        favicon_mmh3=None, favicon_phash=None, screenshot_phash=None, keywords=("cryptohopper",),
    )  # fmt: skip

    def ev(url, title, final=None, html_extra=""):
        host = url.split("/")[2]
        e = CollectedEvidence(candidate_id=_uuid.uuid4(), url=url, host=host, registrable=host)
        e.final_url = final or url
        e.features = extract_features(
            f"<html><head><title>{title}</title></head><body>{html_extra}</body></html>",
            url,
            ["cryptohopper"],
        )
        e.whois_age_days = 1422  # an old squat still gets the age_gt_2y penalty …
        return e

    cfg = ScoringConfig()
    r = scoring.score(analyze(ev("https://cryptohopper.online/", "Cryptohopper"), base, cfg), cfg)
    assert r.severity is Severity.HIGH and r.score >= cfg.thresholds.high  # … but the rule wins
    assert {x["rule"] for x in r.breakdown["combination_rules_fired"]} == {
        "exact_brand_impersonation"
    }
    login = ev(
        "https://cryptohopper.online/",
        "Cryptohopper",
        html_extra="<form><input type=password></form>",
    )
    assert scoring.score(analyze(login, base, cfg), cfg).severity is Severity.CRITICAL
    # the brand's own defensive registration redirects home: not a threat
    owned = scoring.score(
        analyze(
            ev(
                "https://cryptohopper.online/",
                "Cryptohopper",
                final="https://www.cryptohopper.com/",
            ),
            base,
            cfg,
        ),
        cfg,
    )
    assert owned.severity is Severity.LOW and "brand_tld_swap" not in owned.signals
    # a combosquat whose title names the brand gets the title signal, not the TLD-swap one
    combo = analyze(ev("https://cryptohopper-bonus.com/", "Cryptohopper Bonus"), base, cfg)
    assert "title_claims_brand" in combo.signals and "brand_tld_swap" not in combo.signals
