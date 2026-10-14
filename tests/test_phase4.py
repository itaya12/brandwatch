"""Phase 4 — Investigation: pivoting BFS with budget, co-hosted triage, campaign graph,
infrastructure signals, IOC normalisation and STIX export."""

from __future__ import annotations

import json
import uuid

import sqlalchemy as sa
from fastapi.testclient import TestClient
from tests.conftest import make_brand, make_user, make_workspace

import brandwatch.db.models as m
from brandwatch.api.main import create_app
from brandwatch.config.settings import Settings
from brandwatch.db.enums import EdgeType, EvidenceType, IocType, NodeType, Severity
from brandwatch.detection import investigation as inv
from brandwatch.detection.discovery import manual_hits
from brandwatch.detection.finding import confirm
from brandwatch.detection.html import extract_features
from brandwatch.detection.runner import run_scan
from brandwatch.events.emitter import ScanEventEmitter, replay
from brandwatch.providers.mock.fixtures import default_store
from brandwatch.providers.registry import ProviderRegistry
from brandwatch.security.limits import SYSTEM_LIMITS

ADMIN = {"email": "admin@test.local", "password": "test-admin-password"}


def demo_settings(tmp_path) -> Settings:
    return Settings(_env_file=None, demo_mode=True, evidence_dir=str(tmp_path / "ev"))


def onboard(session):
    ws = make_workspace(session, f"ws-{uuid.uuid4().hex[:6]}")
    brand = make_brand(session, ws, "ShopNova")
    session.add(m.BrandDomain(brand_id=brand.id, domain="shopnova.com"))
    session.flush()
    return ws, brand


async def _scan(session, ws, brand, settings, urls):
    job = m.ScanJob(workspace_id=ws.id, brand_id=brand.id, kind="url_scan")
    session.add(job)
    session.flush()
    return await run_scan(session, job.id, settings=settings, hits=manual_hits(urls))


def test_golden_infra_clusters_and_tracking_ids():
    st = default_store()
    cluster = {s.host for s in st.by_ip("203.0.113.66")}
    assert cluster == {"shopn0va.com", "shopnova-login.com", "secure-shopnova.com", "shopnova.co"}
    assert st.get("shopn0va.com").infra["cert_fp"] == "a" * 64
    f = extract_features(st.get("shopn0va.com").http["html"], "https://shopn0va.com/", [])
    assert f.tracking_ids == ["UA-424242-1"]
    assert (
        extract_features(
            st.get("weatherly-forecasts.org").http["html"], "https://x/", []
        ).tracking_ids
        == []
    )


def test_budget_is_clamped_by_system_limits():
    b = inv.Budget(max_depth=9, max_nodes=10_000, max_edges=10_000).clamp()
    assert (b.max_depth, b.max_nodes, b.max_edges) == (
        SYSTEM_LIMITS.MAX_BFS_DEPTH, SYSTEM_LIMITS.MAX_PIVOT_NODES, SYSTEM_LIMITS.MAX_PIVOT_EDGES
    )  # fmt: skip


async def test_investigation_builds_campaign_with_triage_and_iocs(session, tmp_path):
    ws, brand = onboard(session)
    settings = demo_settings(tmp_path)
    analyst = make_user(session, ws, "an@test.local")
    await _scan(
        session, ws, brand, settings, ["https://shopn0va.com/", "https://shopnova-login.com/"]
    )
    seed = session.scalars(
        sa.select(m.Finding)
        .join(m.Candidate)
        .where(m.Candidate.hostname == "shopn0va.com", m.Finding.brand_id == brand.id)
    ).one()
    confirm(session, seed, analyst, "clone")

    job = m.ScanJob(
        workspace_id=ws.id,
        brand_id=brand.id,
        kind="investigate",
        payload={"finding_id": str(seed.id)},
    )
    session.add(job)
    session.flush()
    result = await inv.run_investigation(session, job.id, seed.id, settings=settings)
    assert result.nodes >= 6 and result.edges >= 5 and not result.budget_exhausted

    camp = session.get(m.Campaign, result.campaign_id)
    nodes = {
        (n.type, n.value): n
        for n in session.scalars(
            sa.select(m.CampaignNode).where(m.CampaignNode.campaign_id == camp.id)
        ).all()
    }
    # seed + its server, certificate and tracking id
    assert nodes[(NodeType.DOMAIN, "shopn0va.com")].included
    assert nodes[(NodeType.IP, "203.0.113.66")].included
    assert nodes[(NodeType.CERTIFICATE, "a" * 64)].included
    assert nodes[(NodeType.TRACKING_ID, "UA-424242-1")].included
    # co-hosted kit siblings included (brand pattern / cert); unrelated tenants excluded with a reason
    for sibling in ("shopnova-login.com", "secure-shopnova.com", "shopnova.co"):
        assert nodes[(NodeType.DOMAIN, sibling)].included, sibling
    noise = nodes[(NodeType.DOMAIN, "bakery-menu.example")]
    assert not noise.included and "reverse-IP noise" in noise.triage_reason
    edge_types = {
        e.type
        for e in session.scalars(
            sa.select(m.CampaignEdge).where(m.CampaignEdge.campaign_id == camp.id)
        ).all()
    }
    assert {EdgeType.PASSIVE_DNS, EdgeType.CERT, EdgeType.TRACKING_ID} <= edge_types
    # both findings now belong to the campaign; new siblings became candidates (source: pivot)
    session.refresh(seed)
    other = session.scalars(
        sa.select(m.Finding)
        .join(m.Candidate)
        .where(m.Candidate.hostname == "shopnova-login.com", m.Finding.brand_id == brand.id)
    ).one()
    assert seed.campaign_id == camp.id == other.campaign_id
    new_cand = session.scalars(
        sa.select(m.Candidate).where(
            m.Candidate.brand_id == brand.id, m.Candidate.hostname == "secure-shopnova.com"
        )
    ).one()
    assert new_cand.priority == 20
    pattern = session.scalars(
        sa.select(m.CandidateSource.matched_pattern).where(
            m.CandidateSource.candidate_id == new_cand.id
        )
    ).one()
    assert pattern.startswith("pivot:")
    # IOCs are normalised and traceable
    iocs = session.scalars(sa.select(m.Ioc).where(m.Ioc.campaign_id == camp.id)).all()
    types = {i.type for i in iocs}
    assert {
        IocType.DOMAIN,
        IocType.HOSTNAME,
        IocType.URL,
        IocType.IP,
        IocType.CERT_FP,
        IocType.FAVICON_HASH,
        IocType.TRACKING_ID,
        IocType.EMAIL,
    } <= types
    ip_ioc = next(i for i in iocs if i.type is IocType.IP)
    assert (
        ip_ioc.value == "203.0.113.66"
        and ip_ioc.source_evidence_id is not None
        and ip_ioc.finding_id == seed.id
    )
    # Live Console feed + audit
    msgs = [e.message for e in replay(session, job.id)]
    assert any("co-hosted → triage →" in x for x in msgs) and msgs[-1].startswith("Campaign ")
    assert session.scalars(
        sa.select(m.AuditEvent).where(
            m.AuditEvent.action == "campaign.investigated", m.AuditEvent.object_id == camp.id
        )
    ).one()
    # actor profile
    assert (
        camp.actor_profile["registrant_email"] == "kitops@proton.example"
        and "203.0.113.66" in camp.actor_profile["servers"]
    )
    # STIX bundle
    bundle = inv.stix_bundle(session, iocs, camp, brand)
    kinds = [o["type"] for o in bundle["objects"]]
    assert kinds.count("indicator") == len(iocs) and "campaign" in kinds and "relationship" in kinds
    ind = next(
        o
        for o in bundle["objects"]
        if o["type"] == "indicator" and o["pattern"].startswith("[ipv4-addr")
    )
    assert ind["pattern"] == "[ipv4-addr:value = '203.0.113.66']"


async def test_infrastructure_signals_fire_after_a_campaign_exists(session, tmp_path):
    """A brand-new lookalike on the kit's server/cert/tracking id gets Infrastructure points."""
    ws, brand = onboard(session)
    settings = demo_settings(tmp_path)
    analyst = make_user(session, ws, "an2@test.local")
    await _scan(session, ws, brand, settings, ["https://shopn0va.com/"])
    seed = session.scalars(sa.select(m.Finding).where(m.Finding.brand_id == brand.id)).one()
    confirm(session, seed, analyst, "clone")
    job = m.ScanJob(
        workspace_id=ws.id,
        brand_id=brand.id,
        kind="investigate",
        payload={"finding_id": str(seed.id)},
    )
    session.add(job)
    session.flush()
    await inv.run_investigation(session, job.id, seed.id, settings=settings)

    summary = await _scan(session, ws, brand, settings, ["https://shopnova.co/"])
    out = summary.outcomes[0]
    assert out.disposition == "finding"
    assert {
        "linked_to_known_campaign",
        "cohosted_with_known_phish",
        "cert_shared_with_phish",
        "tracking_id_shared",
    } <= set(out.signals)
    assert out.severity is Severity.CRITICAL and out.confidence >= 90
    # the unrelated legit site on a different server gets nothing from the Infrastructure group
    other = await _scan(session, ws, brand, settings, ["https://weatherly-forecasts.org/"])
    assert not {"linked_to_known_campaign", "cohosted_with_known_phish"} & set(
        other.outcomes[0].signals
    )


async def test_shared_hosting_stops_the_pivot(session, tmp_path, monkeypatch):
    ws, brand = onboard(session)
    settings = demo_settings(tmp_path)
    analyst = make_user(session, ws, "an3@test.local")
    await _scan(session, ws, brand, settings, ["https://shopn0va.com/"])
    seed = session.scalars(sa.select(m.Finding).where(m.Finding.brand_id == brand.id)).one()
    confirm(session, seed, analyst, "clone")
    from brandwatch.providers import mock as mock_mod

    monkeypatch.setitem(
        mock_mod.SHARED_HOSTING_NEIGHBOURS,
        "203.0.113.66",
        [f"tenant{i}.cdn.example" for i in range(40)],
    )
    job = m.ScanJob(
        workspace_id=ws.id,
        brand_id=brand.id,
        kind="investigate",
        payload={"finding_id": str(seed.id)},
    )
    session.add(job)
    session.flush()
    await inv.run_investigation(session, job.id, seed.id, settings=settings)
    camp = session.scalars(sa.select(m.Campaign).where(m.Campaign.brand_id == brand.id)).one()
    ip_node = session.scalars(
        sa.select(m.CampaignNode).where(
            m.CampaignNode.campaign_id == camp.id, m.CampaignNode.value == "203.0.113.66"
        )
    ).one()
    assert (ip_node.ai_verdict or {}).get("shared_hosting") is True
    hosts = {
        n.value
        for n in session.scalars(
            sa.select(m.CampaignNode).where(
                m.CampaignNode.campaign_id == camp.id, m.CampaignNode.type == NodeType.DOMAIN
            )
        ).all()
    }
    assert not any(
        h.startswith("tenant") for h in hosts
    )  # neighbours of a shared hoster are never pivoted
    assert any("shared hosting" in e.message for e in replay(session, job.id))


async def test_budget_exhaustion_keeps_partial_graph(session, tmp_path):
    ws, brand = onboard(session)
    settings = demo_settings(tmp_path)
    analyst = make_user(session, ws, "an4@test.local")
    await _scan(session, ws, brand, settings, ["https://shopn0va.com/"])
    seed = session.scalars(sa.select(m.Finding).where(m.Finding.brand_id == brand.id)).one()
    confirm(session, seed, analyst, "clone")
    job = m.ScanJob(workspace_id=ws.id, brand_id=brand.id, kind="investigate")
    session.add(job)
    session.flush()
    em = ScanEventEmitter(session, job.id)
    investigator = inv.Investigator(
        session, brand, ProviderRegistry(settings), em, inv.Budget(max_api_calls=1)
    )
    nodes, edges = await investigator.run(seed)
    assert (
        investigator.exhausted_reason == "max_api_calls" and nodes and len(nodes) < 20
    )  # seeds + one expansion only


def test_campaign_api_and_pages(engine, tmp_path):
    settings = Settings(_env_file=None, demo_mode=True, evidence_dir=str(tmp_path / "ev"), bootstrap_admin_email=ADMIN["email"],
                        bootstrap_admin_password=ADMIN["password"], secret_key="unit-test-secret-0123456789abcdef")  # fmt: skip
    app = create_app(settings=settings, engine=engine)
    with TestClient(app) as c:
        token = c.post("/api/auth/login", json=ADMIN).json()["access_token"]
        c.headers["Authorization"] = f"Bearer {token}"
        brand = c.post(
            "/api/brands",
            json={"name": f"Camp {uuid.uuid4().hex[:4]}", "domains": ["shopnova.com"]},
        ).json()
        job = c.post(
            f"/api/brands/{brand['id']}/scan-urls", json={"urls": ["https://shopn0va.com/"]}
        ).json()["job_id"]
        app.state.queue.wait(uuid.UUID(job), timeout=120)
        f = c.get("/api/findings", params={"brand_id": brand["id"]}).json()[0]
        assert (
            c.post(f"/api/findings/{f['id']}/investigate").status_code == 409
        )  # must be confirmed first
        c.post(f"/api/findings/{f['id']}/confirm", json={"reason": "clone"})
        r = c.post(f"/api/findings/{f['id']}/investigate")
        assert r.status_code == 202
        app.state.queue.wait(uuid.UUID(r.json()["job_id"]), timeout=120)
        camps = c.get("/api/campaigns", params={"brand_id": brand["id"]}).json()
        assert len(camps) == 1 and camps[0]["stats"]["included"] >= 5
        detail = c.get(f"/api/campaigns/{camps[0]['id']}").json()
        assert detail["edges"] and all(
            e["source_value"] and e["target_value"] for e in detail["edges"]
        )
        csv_text = c.get("/api/iocs", params={"campaign_id": camps[0]["id"], "format": "csv"}).text
        assert csv_text.startswith("type,value,first_seen") and "203.0.113.66" in csv_text
        stix = c.get("/api/iocs", params={"campaign_id": camps[0]["id"], "format": "stix"})
        assert stix.headers["content-type"].startswith("application/stix+json")
        assert json.loads(stix.text)["type"] == "bundle"
        assert c.get("/api/iocs", params={"type": "ip"}).json()

        ui = TestClient(app)
        ui.post("/ui/login", data={**ADMIN, "next": "/ui/findings"}, follow_redirects=False)
        page = ui.get("/ui/campaigns")
        assert page.status_code == 200 and camps[0]["name"] in page.text
        page = ui.get(f"/ui/campaigns/{camps[0]['id']}")
        assert (
            page.status_code == 200
            and "Co-hosted triage" in page.text
            and "STIX 2.1 bundle" in page.text
        )
        fpage = ui.get(f"/ui/findings/{f['id']}")
        assert "Map attack infrastructure" in fpage.text


async def test_iocs_dedupe_values_repeated_across_evidence(session, tmp_path):
    """Regression: a site scanned twice carries the same IP in two DNS evidence rows; extracting
    IOCs must not insert the value twice (UNIQUE workspace/type/value)."""
    ws, brand = onboard(session)
    settings = demo_settings(tmp_path)
    analyst = make_user(session, ws, "dup@test.local")
    for _ in range(2):
        await _scan(session, ws, brand, settings, ["https://shopn0va.com/"])
    seed = session.scalars(
        sa.select(m.Finding).join(m.Candidate)
        .where(m.Candidate.hostname == "shopn0va.com", m.Finding.brand_id == brand.id)
    ).one()  # fmt: skip
    dns_rows = session.scalars(
        sa.select(m.Evidence.id).join(m.FindingEvidence, m.FindingEvidence.evidence_id == m.Evidence.id)
        .where(m.FindingEvidence.finding_id == seed.id, m.Evidence.type == EvidenceType.DNS)
    ).all()  # fmt: skip
    assert len(dns_rows) >= 2  # the precondition that used to break the insert
    confirm(session, seed, analyst, "clone")
    session.flush()
    with session.no_autoflush:  # production sessions run with autoflush=False (db/base.py)
        iocs = inv.extract_iocs(session, seed)
    ips = [i for i in iocs if i.type is IocType.IP and i.value == "203.0.113.66"]
    assert len({i.id for i in ips}) == 1
    assert inv.extract_iocs(session, seed)  # idempotent on a second run
