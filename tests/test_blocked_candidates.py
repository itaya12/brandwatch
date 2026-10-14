"""A suspect that refuses the scanner (HTTP 403 / a bot check): score the refusal, and look at urlscan.io.

A site behind Akamai / Cloudflare answers "Access Denied" to BrandWatch's browser. That page used to be analysed as if
it were the site: nothing to compare, no information, and no sign that anything was hidden. Now the refusal is a
signal (``bot_blocking``), the block page is never taken for the site, and when urlscan.io has a public scan of the
suspect, its screenshot and title (and DOM, with a key) are compared with the real brand — labelled as a snapshot.
"""

from __future__ import annotations

import asyncio
import uuid

import sqlalchemy as sa
from fastapi.testclient import TestClient
from tests.conftest import make_brand, make_workspace
from tests.test_demo_story import _app, _ui

import brandwatch.db.models as m
from brandwatch.config.settings import Settings
from brandwatch.db.enums import EvidenceType
from brandwatch.detection.discovery import manual_hits
from brandwatch.detection.runner import run_scan


def _scan(engine, tmp_path, hosts, *, brand="ShopNova", official="shopnova.com"):
    from brandwatch.db.base import make_session_factory

    settings = Settings(_env_file=None, demo_mode=True, evidence_dir=str(tmp_path / f"ev-{uuid.uuid4().hex[:6]}"))
    with make_session_factory(engine)() as s:
        ws = make_workspace(s, f"blk-{uuid.uuid4().hex[:6]}")
        b = make_brand(s, ws, brand)
        s.add(m.BrandDomain(brand_id=b.id, domain=official, is_official=True, kind="official"))
        job = m.ScanJob(workspace_id=ws.id, brand_id=b.id, kind="url_scan")
        s.add(job)
        s.flush()
        summary = asyncio.run(run_scan(s, job.id, settings=settings, hits=manual_hits([f"https://{h}/" for h in hosts])))
        s.commit()
        events = s.scalars(sa.select(m.ScanEventRecord).where(m.ScanEventRecord.job_id == job.id).order_by(m.ScanEventRecord.seq)).all()
        out = {}
        for h in hosts:
            cand = s.scalars(sa.select(m.Candidate).where(m.Candidate.brand_id == b.id, m.Candidate.canonical_domain == h)).first()
            f = s.scalars(sa.select(m.Finding).where(m.Finding.candidate_id == cand.id)).first() if cand else None
            shots = s.scalars(sa.select(m.Evidence).where(m.Evidence.candidate_id == cand.id, m.Evidence.type == EvidenceType.SCREENSHOT)).all() if cand else []
            out[h] = {"cand": cand, "finding": f, "signals": dict(f.current_score.signals or {}) if f and f.current_score else {},
                      "severity": f.current_score.severity.value if f and f.current_score else None,
                      "screens": [(e.source, e.source_type, e.trust_level) for e in shots]}  # fmt: skip
        return summary, events, out, (ws.id, b.id)


def test_a_blocked_clone_is_compared_through_the_urlscan_snapshot_and_scored_for_refusing(engine, tmp_path):
    summary, events, out, _ids = _scan(engine, tmp_path, ["shopnova-eu.com"])
    o = out["shopnova-eu.com"]
    sig = o["signals"]
    assert o["finding"] is not None and o["severity"] in ("high", "critical"), (o["severity"], sig)
    assert "bot_blocking" in sig  # the refusal itself is scored
    assert "screenshot_similarity_ge_90" in sig and "title_claims_brand" in sig  # the snapshot's picture and title were compared
    assert "live_page" in sig["_unavailable"]  # the live page was not seen: confidence says so
    assert "the site refuses automated visitors: HTTP 403 (Akamai)" == sig["_details"]["bot_blocking"]
    assert sig["_scanner_block"]["status"] == 403 and sig["_scanner_block"]["vendor"] == "Akamai"
    snap = sig["_snapshot"]
    assert snap["scan_id"] == "mock-snap-shopnova-eu.com" and snap["has_dom"] is True
    # the picture on file is the snapshot's, labelled as a third party's — the block page's screenshot is not the evidence shown
    assert ("urlscan", "urlscan_snapshot", "third_party") in o["screens"]
    said = [e.message for e in events if e.stage == "enrichment"]
    assert any(x.startswith("shopnova-eu.com answered HTTP 403 (Akamai) — using the urlscan.io snapshot of") for x in said), said
    step = next(st for st in summary.steps if "refused the scanner" in st["title"])
    assert step["title"].startswith("1 site(s) refused") and "1 examined through a urlscan.io snapshot" in step["detail"]
    assert step["items"][0]["label"] == "shopnova-eu.com" and "snapshot" in step["items"][0]["tag"]


def test_a_blocked_site_urlscan_never_saw_is_scored_and_said_to_be_unseen(engine, tmp_path):
    summary, events, out, _ids = _scan(engine, tmp_path, ["ironvale.com"])
    o = out["ironvale.com"]
    cand = o["cand"]
    assert cand is not None
    # no finding is invented from a block page; the refusal is still a signal when a finding exists
    said = [e for e in events if e.stage == "enrichment" and "ironvale.com answered HTTP 403" in e.message]
    assert said and said[0].level == "warn" and "no urlscan.io snapshot, its real page was not seen" in said[0].message
    assert ("urlscan", "urlscan_snapshot", "third_party") not in o["screens"]
    step = next(st for st in summary.steps if "refused the scanner" in st["title"])
    assert "0 examined through a urlscan.io snapshot" in step["detail"] and "no snapshot" in step["items"][0]["tag"]


def test_the_snapshot_lookups_per_scan_are_capped(engine, tmp_path, monkeypatch):
    from brandwatch.detection import enrichment

    monkeypatch.setattr(enrichment, "MAX_SNAPSHOTS_PER_SCAN", 0)
    summary, events, out, _ids = _scan(engine, tmp_path, ["shopnova-eu.com"])
    sig = out["shopnova-eu.com"]["signals"]
    assert ("urlscan", "urlscan_snapshot", "third_party") not in out["shopnova-eu.com"]["screens"]
    assert "bot_blocking" in sig and "live_page" in sig.get("_unavailable", [])
    assert "screenshot_similarity_ge_90" not in sig  # without the snapshot the block page cannot look like the brand
    assert "_snapshot" not in sig and sig["_scanner_block"]["status"] == 403  # nothing came from urlscan.io


def test_a_site_that_answers_normally_is_untouched(engine, tmp_path):
    summary, events, out, _ids = _scan(engine, tmp_path, ["shopn0va.com"])
    sig = out["shopn0va.com"]["signals"]
    assert sig and "bot_blocking" not in sig and "live_page" not in sig["_unavailable"]
    assert "_snapshot" not in sig and "_scanner_block" not in sig
    assert not any("refused the scanner" in st["title"] for st in summary.steps)


def test_the_blocking_signal_comes_from_the_collected_evidence():
    from brandwatch.config.brand_config import BrandConfig
    from brandwatch.detection.analysis import analyze
    from brandwatch.detection.baseline import BrandBaseline
    from brandwatch.detection.enrichment import CollectedEvidence

    cfg = BrandConfig.for_preset("standard")
    base = BrandBaseline(brand_id=uuid.uuid4(), brand_key="acme", version=1, official_domains=("acme.com",), favicon_mmh3=None,
                         favicon_phash=None, screenshot_phash=None, screenshot_dhash=None, palette=(), keywords=("acme",))  # fmt: skip

    def ev(block):
        return CollectedEvidence(candidate_id=uuid.uuid4(), url="https://acme-shop.com/", host="acme-shop.com", registrable="acme-shop.com",
                                 scanner_block=block)  # fmt: skip

    plain = analyze(ev(None), base, cfg.scoring)
    blocked = analyze(ev({"kind": "blocked", "status": 403, "vendor": None, "reason": "x"}), base, cfg.scoring)
    assert "bot_blocking" not in plain.signals and blocked.signals["bot_blocking"] == cfg.scoring.weights["bot_blocking"]
    assert blocked.details["signals"]["bot_blocking"] == "the site refuses automated visitors: HTTP 403"
    assert blocked.details["scanner_block"]["status"] == 403


def test_the_finding_page_says_the_picture_is_a_snapshot(engine, tmp_path):
    from tests.test_demo_story import _api

    app = _app(engine, tmp_path)
    with TestClient(app):
        ui, c = _ui(app), _api(app)
        brand = c.post("/api/brands", json={"name": f"Snap {uuid.uuid4().hex[:4]}", "domains": ["shopnova.com"], "preset": "standard"}).json()
        job = c.post(f"/api/brands/{brand['id']}/scan-urls", json={"urls": ["https://shopnova-eu.com/"]}).json()["job_id"]
        app.state.queue.wait(uuid.UUID(job), timeout=120)
        fid = next(f["id"] for f in c.get("/api/findings", params={"brand_id": brand["id"]}).json() if f["hostname"] == "shopnova-eu.com")
        page = ui.get(f"/ui/findings/{fid}").text
        assert "This picture is a urlscan.io snapshot, not what BrandWatch saw." in page and "HTTP 403, Akamai" in page
        assert "open it on urlscan.io" in page
