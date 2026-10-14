"""Shared fixtures.

* ``TEST_DATABASE_URL`` selects the database (CI sets a PostgreSQL URL); default is a temp-file
  SQLite database so the suite runs with zero setup.
* The schema is built once per session by running ``alembic upgrade head`` — the real migration,
  not ``create_all`` — so the tests exercise exactly what production would run.
* Each test runs inside an outer transaction that is rolled back afterwards (SAVEPOINT pattern),
  which is the only way to isolate tests when the DB forbids DELETE on evidence tables.
"""

from __future__ import annotations

import os
import uuid
from collections.abc import Iterator
from datetime import UTC, datetime
from decimal import Decimal
from pathlib import Path

import pytest
import sqlalchemy as sa
from alembic import command
from alembic.config import Config
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker

import brandwatch.db.models as m
from brandwatch.db.base import is_sqlite, make_engine
from brandwatch.db.enums import (
    CandidateState,
    DiscoverySource,
    EvidenceType,
    ProviderStatus,
    ScannerProfile,
    Severity,
    Surface,
    UserRole,
)

ROOT = Path(__file__).resolve().parents[1]

# Force deterministic, keyless behaviour for every test regardless of the developer's .env.
os.environ["DEMO_MODE"] = "true"
os.environ.setdefault("SECRET_KEY", "test-secret-key-not-for-production")
os.environ.setdefault("BOOTSTRAP_ADMIN_EMAIL", "admin@test.local")
os.environ.setdefault("BOOTSTRAP_ADMIN_PASSWORD", "test-admin-password")


# --------------------------------------------------------------------------------------------
# Database
# --------------------------------------------------------------------------------------------
@pytest.fixture(scope="session")
def db_url(tmp_path_factory: pytest.TempPathFactory) -> str:
    url = os.environ.get("TEST_DATABASE_URL")
    if url:
        return url
    path = tmp_path_factory.mktemp("db") / "brandwatch_test.db"
    return "sqlite:///" + path.as_posix()


def alembic_config(url: str) -> Config:
    cfg = Config(str(ROOT / "alembic.ini"))
    cfg.set_main_option("script_location", str(ROOT / "migrations"))
    cfg.set_main_option("sqlalchemy.url", url)
    cfg.attributes["url_from_caller"] = True
    cfg.attributes["skip_logging_config"] = True
    return cfg


@pytest.fixture(scope="session")
def engine(db_url: str) -> Iterator[Engine]:
    eng = make_engine(db_url)  # SQLite: make_engine already installs the pysqlite SAVEPOINT recipe
    if not is_sqlite(db_url):
        with eng.begin() as conn:
            conn.execute(sa.text("DROP SCHEMA IF EXISTS public CASCADE"))
            conn.execute(sa.text("CREATE SCHEMA public"))
    command.upgrade(alembic_config(db_url), "head")
    yield eng
    eng.dispose()


@pytest.fixture
def session(engine: Engine) -> Iterator[Session]:
    conn = engine.connect()
    outer = conn.begin()
    factory = sessionmaker(
        bind=conn, join_transaction_mode="create_savepoint", expire_on_commit=False
    )
    s = factory()
    try:
        yield s
    finally:
        s.close()
        outer.rollback()
        conn.close()


# --------------------------------------------------------------------------------------------
# Factories (minimal valid rows)
# --------------------------------------------------------------------------------------------
def make_workspace(s: Session, name: str = "ws") -> m.Workspace:
    ws = m.Workspace(name=name)
    s.add(ws)
    s.flush()
    return ws


def make_user(s: Session, ws: m.Workspace, email: str = "a@example.com") -> m.User:
    u = m.User(workspace_id=ws.id, email=email, password_hash="x", role=UserRole.ANALYST)
    s.add(u)
    s.flush()
    return u


def make_brand(s: Session, ws: m.Workspace, name: str = "ShopNova") -> m.Brand:
    b = m.Brand(workspace_id=ws.id, name=name, vertical="ecommerce")
    s.add(b)
    s.flush()
    return b


def make_candidate(s: Session, brand: m.Brand, url: str = "https://shopn0va.com/") -> m.Candidate:
    host = url.split("/")[2]
    c = m.Candidate(
        brand_id=brand.id,
        canonical_domain=host,
        canonical_url=url,
        hostname=host,
        surface=Surface.NAME,
    )
    s.add(c)
    s.flush()
    return c


def make_evidence(
    s: Session, cand: m.Candidate, etype: EvidenceType = EvidenceType.HTTP
) -> m.Evidence:
    e = m.Evidence(
        candidate_id=cand.id,
        type=etype,
        source="httpx",
        source_type="fetch",
        collector="fetcher",
        collector_version="0.0.1",
        content_sha256="0" * 64,
    )
    s.add(e)
    s.flush()
    return e


def make_finding(s: Session, cand: m.Candidate) -> m.Finding:
    f = m.Finding(
        candidate_id=cand.id,
        brand_id=cand.brand_id,
        severity=Severity.HIGH,
        confidence=Decimal("60.00"),
    )
    s.add(f)
    s.flush()
    return f


def make_risk_score(s: Session, finding: m.Finding, *, is_current: bool = True) -> m.RiskScore:
    r = m.RiskScore(
        finding_id=finding.id,
        is_current=is_current,
        score=80,
        raw_score=120,
        severity=Severity.CRITICAL,
        confidence=Decimal("90.00"),
        scoring_version="v1",
        signals={"favicon_exact": 22},
        groups={"visual": 22},
    )
    s.add(r)
    s.flush()
    return r


def make_job(s: Session, ws: m.Workspace) -> m.ScanJob:
    j = m.ScanJob(workspace_id=ws.id, kind="noop")
    s.add(j)
    s.flush()
    return j


def seed_immutable_row(s: Session, table: str) -> tuple[sa.Table, dict]:
    """Insert one row into an immutable table; return (table, pk_filter)."""
    ws = make_workspace(s, name=f"ws-{uuid.uuid4().hex[:6]}")
    brand = make_brand(s, ws)
    cand = make_candidate(s, brand, url=f"https://{uuid.uuid4().hex[:8]}.example/")
    tbl = m.Base.metadata.tables[table]
    if table == "audit_events":
        row = m.AuditEvent(workspace_id=ws.id, actor_type="system", action="t", object_type="x")
        s.add(row)
        s.flush()
        return tbl, {"id": row.id}
    if table == "observations":
        row = m.Observation(
            candidate_id=cand.id,
            source=DiscoverySource.MANUAL,
            scanner_profile=ScannerProfile.DATACENTER,
            state_at_time=CandidateState.NEW,
        )
        s.add(row)
        s.flush()
        return tbl, {"id": row.id}
    ev = make_evidence(s, cand)
    if table == "evidence":
        return tbl, {"id": ev.id}
    child = {
        "screenshots": m.Screenshot(evidence_id=ev.id, path="a.png"),
        "html_snapshots": m.HtmlSnapshot(evidence_id=ev.id, path="a.html"),
        "http_responses": m.HttpResponse(evidence_id=ev.id, status=200),
        "dns_observations": m.DnsObservation(evidence_id=ev.id, records={"A": ["1.2.3.4"]}),
        "whois_observations": m.WhoisObservation(evidence_id=ev.id, registrar="r"),
        "ssl_observations": m.SslObservation(evidence_id=ev.id, issuer="i"),
        "reputation_observations": m.ReputationObservation(
            evidence_id=ev.id, provider="mock", status=ProviderStatus.UNKNOWN
        ),
    }[table]
    s.add(child)
    s.flush()
    return tbl, {"evidence_id": ev.id}


def now() -> datetime:
    return datetime.now(UTC)
