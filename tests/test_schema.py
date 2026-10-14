"""Schema + constraint tests (Phase 0 DoD): the DB enforces the invariants, not Python."""

from __future__ import annotations

import uuid

import pytest
import sqlalchemy as sa
from alembic.autogenerate import compare_metadata
from alembic.migration import MigrationContext
from alembic.script import ScriptDirectory
from sqlalchemy.exc import DBAPIError, IntegrityError
from tests.conftest import (
    alembic_config,
    make_brand,
    make_candidate,
    make_evidence,
    make_finding,
    make_job,
    make_risk_score,
    make_user,
    make_workspace,
    seed_immutable_row,
)

import brandwatch.db.models as m
from brandwatch.db.enums import (
    CandidateState,
    DiscoverySource,
    IocType,
    NodeType,
    ScannerProfile,
)

# --------------------------------------------------------------------------------------------
# Migration
# --------------------------------------------------------------------------------------------


def test_migration_is_at_head(engine, db_url):
    head = ScriptDirectory.from_config(alembic_config(db_url)).get_current_head()
    with engine.connect() as conn:
        current = MigrationContext.configure(conn).get_current_revision()
    assert current == head and head is not None  # always migrated to the newest revision


def test_models_match_migration(engine):
    """Migration 001 must build exactly the schema the ORM models describe."""
    with engine.connect() as conn:
        ctx = MigrationContext.configure(conn, opts={"compare_type": True, "render_as_batch": True})
        diffs = compare_metadata(ctx, m.Base.metadata)
    assert diffs == [], f"models and migration have drifted:\n{diffs}"


def test_every_spec_table_exists(engine):
    expected = {
        "workspaces", "users", "audit_events", "brands", "brand_domains", "brand_fingerprints",
        "configs", "candidates", "candidate_sources", "observations", "findings",
        "finding_evidence", "analyst_labels", "evidence", "screenshots", "html_snapshots",
        "http_responses", "dns_observations", "whois_observations", "ssl_observations",
        "reputation_observations", "risk_scores", "risk_score_versions", "rule_versions",
        "domains", "hostnames", "urls", "ip_addresses", "asns", "certificates", "registrars",
        "nameservers", "campaigns", "campaign_nodes", "campaign_edges", "scan_jobs",
        "scan_stages", "scan_events", "api_providers", "api_keys", "api_usage", "iocs",
        "reports", "takedown_drafts",
    }  # fmt: skip
    present = set(sa.inspect(engine).get_table_names())
    assert expected <= present, expected - present


def test_every_fk_is_on_delete_restrict():
    for table in m.Base.metadata.tables.values():
        for fkc in table.foreign_key_constraints:
            assert fkc.ondelete == "RESTRICT", f"{table.name}.{fkc.column_keys} is not RESTRICT"


# --------------------------------------------------------------------------------------------
# Dedup / uniqueness
# --------------------------------------------------------------------------------------------


def test_duplicate_candidate_source_rejected(session):
    brand = make_brand(session, make_workspace(session))
    cand = make_candidate(session, brand)
    session.add(m.CandidateSource(candidate_id=cand.id, source=DiscoverySource.CT))
    session.flush()
    session.add(m.CandidateSource(candidate_id=cand.id, source=DiscoverySource.CT))
    with pytest.raises(IntegrityError):
        session.flush()


def test_candidate_identity_is_unique_per_brand(session):
    brand = make_brand(session, make_workspace(session))
    make_candidate(session, brand, url="https://shopn0va.com/")
    with pytest.raises(IntegrityError):
        make_candidate(session, brand, url="https://shopn0va.com/")


def test_same_url_allowed_for_different_brands(session):
    ws = make_workspace(session)
    b1, b2 = make_brand(session, ws, "A"), make_brand(session, ws, "B")
    make_candidate(session, b1, url="https://shared.example/")
    make_candidate(session, b2, url="https://shared.example/")  # no error


def test_ioc_unique_per_workspace(session):
    ws = make_workspace(session)
    session.add(m.Ioc(workspace_id=ws.id, type=IocType.DOMAIN, value="evil.com"))
    session.flush()
    session.add(m.Ioc(workspace_id=ws.id, type=IocType.DOMAIN, value="evil.com"))
    with pytest.raises(IntegrityError):
        session.flush()


def test_campaign_node_unique(session):
    brand = make_brand(session, make_workspace(session))
    camp = m.Campaign(brand_id=brand.id, name="c")
    session.add(camp)
    session.flush()
    session.add(m.CampaignNode(campaign_id=camp.id, type=NodeType.IP, value="1.2.3.4"))
    session.flush()
    session.add(m.CampaignNode(campaign_id=camp.id, type=NodeType.IP, value="1.2.3.4"))
    with pytest.raises(IntegrityError):
        session.flush()


def test_scan_event_seq_unique_per_job(session):
    job = make_job(session, make_workspace(session))
    session.add(
        m.ScanEventRecord(job_id=job.id, seq=1, stage="s", step="t", status="done", message="m")
    )
    session.flush()
    session.add(
        m.ScanEventRecord(job_id=job.id, seq=1, stage="s", step="t", status="done", message="m")
    )
    with pytest.raises(IntegrityError):
        session.flush()


def test_email_unique_is_case_insensitive(session):
    ws = make_workspace(session)
    make_user(session, ws, email="Analyst@Example.com")
    with pytest.raises(IntegrityError):
        make_user(session, ws, email="analyst@example.com")


# --------------------------------------------------------------------------------------------
# Scoring: exactly one current score, append-only history
# --------------------------------------------------------------------------------------------


def test_only_one_current_risk_score(session):
    f = make_finding(session, make_candidate(session, make_brand(session, make_workspace(session))))
    make_risk_score(session, f, is_current=True)
    with pytest.raises(IntegrityError):
        make_risk_score(session, f, is_current=True)


def test_rescore_flips_is_current_and_keeps_history(session):
    f = make_finding(session, make_candidate(session, make_brand(session, make_workspace(session))))
    first = make_risk_score(session, f, is_current=True)
    session.execute(
        sa.update(m.RiskScore).where(m.RiskScore.id == first.id).values(is_current=False)
    )
    second = make_risk_score(session, f, is_current=True)
    session.flush()
    session.expire_all()
    rows = session.scalars(sa.select(m.RiskScore).where(m.RiskScore.finding_id == f.id)).all()
    assert len(rows) == 2
    assert {r.id: r.is_current for r in rows} == {first.id: False, second.id: True}
    assert session.get(m.Finding, f.id).current_score.id == second.id


def test_risk_score_frozen_columns_cannot_change(session):
    f = make_finding(session, make_candidate(session, make_brand(session, make_workspace(session))))
    r = make_risk_score(session, f)
    with pytest.raises(DBAPIError, match="append-only"):
        session.execute(sa.update(m.RiskScore).where(m.RiskScore.id == r.id).values(score=1))
    session.rollback()


def test_risk_score_cannot_be_deleted(session):
    f = make_finding(session, make_candidate(session, make_brand(session, make_workspace(session))))
    r = make_risk_score(session, f)
    with pytest.raises(DBAPIError, match="immutable"):
        session.execute(sa.delete(m.RiskScore).where(m.RiskScore.id == r.id))
    session.rollback()


# --------------------------------------------------------------------------------------------
# Immutable evidence (defense in depth: DB triggers)
# --------------------------------------------------------------------------------------------

_UPDATE_COLUMN = {
    "audit_events": ("reason", "changed"),
    "observations": ("content_hash", "changed"),
    "evidence": ("trust_level", "changed"),
    "screenshots": ("path", "changed"),
    "html_snapshots": ("path", "changed"),
    "http_responses": ("status", 500),
    "dns_observations": ("resolver", "changed"),
    "whois_observations": ("registrar", "changed"),
    "ssl_observations": ("issuer", "changed"),
    "reputation_observations": ("verdict", "changed"),
}


def test_immutable_table_list_covers_all_evidence_tables():
    assert set(m.IMMUTABLE_TABLES) == set(_UPDATE_COLUMN)


@pytest.mark.parametrize("table", m.IMMUTABLE_TABLES)
def test_immutable_table_rejects_update(session, table):
    tbl, pk = seed_immutable_row(session, table)
    col, value = _UPDATE_COLUMN[table]
    where = sa.and_(*[tbl.c[k] == v for k, v in pk.items()])
    with pytest.raises(DBAPIError, match="immutable"):
        session.execute(sa.update(tbl).where(where).values({col: value}))
    session.rollback()


@pytest.mark.parametrize("table", m.IMMUTABLE_TABLES)
def test_immutable_table_rejects_delete(session, table):
    tbl, pk = seed_immutable_row(session, table)
    where = sa.and_(*[tbl.c[k] == v for k, v in pk.items()])
    with pytest.raises(DBAPIError, match="immutable"):
        session.execute(sa.delete(tbl).where(where))
    session.rollback()


def test_evidence_chain_links_parent(session):
    cand = make_candidate(session, make_brand(session, make_workspace(session)))
    parent = make_evidence(session, cand)
    child = m.Evidence(
        candidate_id=cand.id,
        type=parent.type,
        source="s",
        source_type="t",
        collector="c",
        collector_version="1",
        parent_evidence_id=parent.id,
    )
    session.add(child)
    session.flush()
    session.expire_all()
    assert session.get(m.Evidence, child.id).parent.id == parent.id


# --------------------------------------------------------------------------------------------
# FK deletion policy
# --------------------------------------------------------------------------------------------


def test_cannot_delete_candidate_that_has_evidence(session):
    cand = make_candidate(session, make_brand(session, make_workspace(session)))
    make_evidence(session, cand)
    with pytest.raises(IntegrityError):
        session.execute(sa.delete(m.Candidate).where(m.Candidate.id == cand.id))
    session.rollback()


def test_cannot_delete_candidate_that_has_observations(session):
    cand = make_candidate(session, make_brand(session, make_workspace(session)))
    session.add(
        m.Observation(
            candidate_id=cand.id,
            source=DiscoverySource.MANUAL,
            scanner_profile=ScannerProfile.DATACENTER,
            state_at_time=CandidateState.NEW,
        )
    )
    session.flush()
    with pytest.raises(IntegrityError):
        session.execute(sa.delete(m.Candidate).where(m.Candidate.id == cand.id))
    session.rollback()


def test_fk_to_missing_row_rejected(session):
    brand = make_brand(session, make_workspace(session))
    session.commit()  # released savepoint: the brand survives the rollback below
    session.add(
        m.Candidate(
            brand_id=uuid.uuid4(),  # does not exist
            canonical_domain="x.example",
            canonical_url="https://x.example/",
            hostname="x.example",
            surface="name",
        )
    )
    with pytest.raises(IntegrityError):
        session.flush()
    session.rollback()
    assert session.get(m.Brand, brand.id) is not None
