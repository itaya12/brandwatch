"""Google search queries: the AI proposes, an analyst approves, and Google is searched only with the
approved list — by every scan and by the scheduled one."""

from __future__ import annotations

import uuid
from types import SimpleNamespace

import sqlalchemy as sa
from fastapi.testclient import TestClient
from tests.conftest import make_brand, make_workspace
from tests.test_demo_story import _api, _app, _ui

import brandwatch.db.models as m
from brandwatch.config.settings import Settings
from brandwatch.db.enums import DiscoverySource
from brandwatch.detection import search_queries as sq
from brandwatch.detection.runner import run_scan
from brandwatch.events.emitter import replay


def _baseline(version: int, queries: list[str]) -> SimpleNamespace:
    return SimpleNamespace(version=version, search_queries=tuple(queries), brand_key="oncloud")


def _brand(profile=None, kind="retail") -> SimpleNamespace:
    return SimpleNamespace(name="On Cloud", kind=kind, profile=profile or {})


NO_CONFIG = SimpleNamespace(search_queries=[])


def test_proposal_waits_for_approval():
    st = sq.query_state(_brand(), NO_CONFIG, _baseline(2, ["on cloud sale", "on cloud outlet"]))
    assert st.status == "pending" and not st.approved
    assert st.proposal == ["on cloud sale", "on cloud outlet"] and "v2" in st.proposal_source
    assert "waiting for your approval" in st.waiting_note()
    # no fingerprint yet: the default list for the kind of business is the proposal
    st = sq.query_state(_brand(), NO_CONFIG, None)
    assert st.status == "pending" and "on cloud sale" in st.proposal and "default" in st.proposal_source


def test_approved_list_wins_and_a_new_ai_list_is_only_flagged():
    brand = _brand()
    sq.approve(brand, ["on cloud sale", "און קלאוד מבצע"], by="analyst@example.com", baseline_version=2)
    st = sq.query_state(brand, NO_CONFIG, _baseline(2, ["on cloud sale", "on cloud outlet"]))
    assert st.status == "approved" and st.queries == ["on cloud sale", "און קלאוד מבצע"]
    assert not st.new_proposal  # same fingerprint the analyst saw
    st = sq.query_state(brand, NO_CONFIG, _baseline(3, ["on cloud sale", "on cloud outlet"]))
    assert st.queries == ["on cloud sale", "און קלאוד מבצע"]  # still the approved list
    assert st.new_proposal and st.added == ["on cloud outlet"] and st.removed == ["און קלאוד מבצע"]


def test_old_configuration_list_counts_as_approved():
    st = sq.query_state(_brand(), SimpleNamespace(search_queries=["x login"]), _baseline(1, ["y"]))
    assert st.status == "configured" and st.approved and st.queries == ["x login"]


def test_clean_queries():
    assert sq.clean_queries(["  On  Cloud SALE ", "on cloud sale", "a", "און\tקלאוד", "", None]) == [
        "on cloud sale", "און קלאוד",
    ]  # fmt: skip
    assert len(sq.clean_queries([f"q {i}" for i in range(50)])) == sq.MAX_QUERIES


# ------------------------------------------------------------------------------------------ API + UI
def test_suggest_approve_and_audit(engine, tmp_path):
    app = _app(engine, tmp_path)
    with TestClient(app):
        c = _api(app)
        b = c.post("/api/brands", json={"name": f"ShopNova {uuid.uuid4().hex[:4]}", "domains": ["shopnova.com"]}).json()
        got = c.get(f"/api/brands/{b['id']}").json()
        assert got["search_queries"]["status"] == "pending"
        sug = c.post(f"/api/brands/{b['id']}/search-queries/suggest").json()
        assert sug["available"] and sug["queries"]
        r = c.put(f"/api/brands/{b['id']}/search-queries", json={"queries": [*sug["queries"][:3], "ShopNova  Outlet"]})
        assert r.status_code == 200 and r.json()["search_queries"]["status"] == "approved"
        got = c.get(f"/api/brands/{b['id']}").json()["search_queries"]
        assert got["queries"][-1] == "shopnova outlet" and got["approved_by"]
        assert c.put(f"/api/brands/{b['id']}/search-queries", json={"queries": [" "]}).status_code == 422
    from brandwatch.db.base import make_session_factory

    with make_session_factory(engine)() as s:
        row = s.scalars(sa.select(m.AuditEvent).where(m.AuditEvent.action == "brand.search_queries_approved",
                                                      m.AuditEvent.object_id == uuid.UUID(b["id"]))).first()  # fmt: skip
        assert row is not None and row.new_value["approved"][-1] == "shopnova outlet"


def test_brand_page_panel_and_form(engine, tmp_path):
    app = _app(engine, tmp_path)
    with TestClient(app):
        c = _api(app)
        b = c.post("/api/brands", json={"name": f"ShopNova {uuid.uuid4().hex[:4]}", "domains": ["shopnova.com"]}).json()
        ui = _ui(app)
        page = ui.get(f"/ui/brands/{b['id']}").text
        assert 'id="queries"' in page and "Waiting for your approval" in page and "Approve these queries" in page
        r = ui.post(f"/ui/brands/{b['id']}/search-queries", data={"q": ["shopnova login", "", "shopnova outlet"]},
                    follow_redirects=False)  # fmt: skip
        assert r.status_code == 303 and "queries=approved" in r.headers["location"]
        page = ui.get(f"/ui/brands/{b['id']}?queries=approved").text
        assert "Queries approved" in page and "Waiting for your approval" not in page
        assert c.get(f"/api/brands/{b['id']}").json()["search_queries"]["queries"] == ["shopnova login", "shopnova outlet"]


# ------------------------------------------------------------------------------------------ scans
def _scan(session, tmp_path, brand):
    job = m.ScanJob(workspace_id=brand.workspace_id, brand_id=brand.id, kind="brand_scan")
    session.add(job)
    session.flush()
    settings = Settings(_env_file=None, demo_mode=True, evidence_dir=str(tmp_path / "ev"))
    return job, run_scan(session, job.id, settings=settings, max_candidates=30)


async def test_scan_skips_google_until_the_queries_are_approved(session, tmp_path):
    ws = make_workspace(session, f"ws-{uuid.uuid4().hex[:6]}")
    brand = make_brand(session, ws, "ShopNova")
    session.add(m.BrandDomain(brand_id=brand.id, domain="shopnova.com"))
    session.add(m.Config(brand_id=brand.id, preset="basic", detection={"streams": ["ct", "search"], "max_candidates": 30},
                         economic_limits={}, scoring={}))  # fmt: skip
    session.flush()

    job, run = _scan(session, tmp_path, brand)
    await run
    events = replay(session, job.id)
    skipped = [e for e in events if e.step == "search" and e.status == "skipped"]
    assert skipped and skipped[0].data["alert"]["kind"] == "approval"
    assert skipped[0].data["alert"]["settings_url"].endswith("#queries")
    srcs = set(session.scalars(sa.select(m.CandidateSource.source).join(m.Candidate)
                               .where(m.Candidate.brand_id == brand.id)).all())  # fmt: skip
    assert DiscoverySource.SERPAPI not in srcs

    sq.approve(brand, ["shopnova login", "shopnova support"], by="analyst@example.com", baseline_version=1)
    session.flush()
    job, run = _scan(session, tmp_path, brand)
    await run
    events = replay(session, job.id)
    done = [e for e in events if e.step == "search" and e.status != "skipped" and e.stage == "discovery"]
    queries = {e.message.split("“")[1].split("”")[0] for e in done if "“" in e.message}
    assert queries == {"shopnova login", "shopnova support"}  # exactly the approved list, nothing else


def test_dashboard_offers_globe_and_flat_map(engine, tmp_path):
    app = _app(engine, tmp_path)
    with TestClient(app):
        ui = _ui(app)
        world = ui.get("/ui/assets/world-land.json")
        assert world.status_code == 200 and len(world.json()["rings"]) > 100  # coastlines ship with the app
        page = ui.get("/ui/dashboard").text
        assert "function flatMap" in page and "gswitch" in page and "/ui/assets/world-land.json" in page
