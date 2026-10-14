"""/health + basic admin login (Phase 0 DoD)."""

from __future__ import annotations

import pytest
import sqlalchemy as sa
from fastapi.testclient import TestClient

from brandwatch.api.main import create_app
from brandwatch.config.settings import Settings
from brandwatch.db.base import make_session_factory
from brandwatch.db.enums import UserRole
from brandwatch.db.models import AuditEvent, User, Workspace

ADMIN_EMAIL = "admin@test.local"
ADMIN_PASSWORD = "test-admin-password"


@pytest.fixture
def settings() -> Settings:
    return Settings(
        _env_file=None,
        demo_mode=True,
        bootstrap_admin_email=ADMIN_EMAIL,
        bootstrap_admin_password=ADMIN_PASSWORD,
        secret_key="unit-test-secret-0123456789abcdef",
    )


@pytest.fixture
def client(engine, settings):
    app = create_app(settings=settings, engine=engine)
    with TestClient(app) as c:
        yield c


def login(client: TestClient, email=ADMIN_EMAIL, password=ADMIN_PASSWORD):
    return client.post("/api/auth/login", json={"email": email, "password": password})


def test_health(client):
    r = client.get("/health")
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "ok" and body["db"] == "ok" and body["demo_mode"] is True
    assert body["providers"]["reputation"][0] == "mock:virustotal"


def test_login_wrong_password_is_401(client):
    r = login(client, password="nope")
    assert r.status_code == 401
    assert r.json()["detail"] == "invalid credentials"


def test_login_unknown_user_is_401_with_same_message(client):
    r = login(client, email="ghost@test.local", password="whatever")
    assert r.status_code == 401
    assert r.json()["detail"] == "invalid credentials"


def test_login_rejects_malformed_login(client):
    # a plain username ("admin") is allowed; an address with "@" must still be a real e-mail,
    # and whitespace is never valid
    for bad in ("bad@", "a b", "x@y"):
        r = client.post("/api/auth/login", json={"email": bad, "password": "x"})
        assert r.status_code == 422, bad
    assert (
        client.post("/api/auth/login", json={"email": "ghost", "password": "x"}).status_code == 401
    )


def test_login_returns_token_and_me_works(client):
    r = login(client)
    assert r.status_code == 200
    token = r.json()
    assert token["token_type"] == "bearer" and token["expires_in"] > 0
    me = client.get("/api/auth/me", headers={"Authorization": f"Bearer {token['access_token']}"})
    assert me.status_code == 200
    body = me.json()
    assert body["email"] == ADMIN_EMAIL and body["role"] == "admin"


def test_login_email_is_case_insensitive(client):
    assert login(client, email=ADMIN_EMAIL.upper()).status_code == 200


def test_me_requires_valid_token(client):
    assert client.get("/api/auth/me").status_code == 401
    assert (
        client.get("/api/auth/me", headers={"Authorization": "Bearer garbage"}).status_code == 401
    )
    assert client.get("/api/auth/me", headers={"Authorization": "Basic abc"}).status_code == 401


def test_token_signed_with_other_secret_is_rejected(client, settings):
    import jwt

    forged = jwt.encode(
        {"sub": "00000000-0000-0000-0000-000000000000"},
        "other-secret-key-that-is-long-enough-12345",
        "HS256",
    )
    assert (
        client.get("/api/auth/me", headers={"Authorization": f"Bearer {forged}"}).status_code == 401
    )


def test_bootstrap_is_idempotent_and_hashes_with_argon2(engine, settings):
    for _ in range(2):  # two app startups
        with TestClient(create_app(settings=settings, engine=engine)):
            pass
    with make_session_factory(engine)() as s:
        workspaces = s.scalars(sa.select(Workspace).where(Workspace.name == "default")).all()
        admins = s.scalars(sa.select(User).where(User.email == ADMIN_EMAIL)).all()
        assert len(workspaces) == 1 and len(admins) == 1
        assert admins[0].role is UserRole.ADMIN
        assert admins[0].password_hash.startswith("$argon2id$")
        assert ADMIN_PASSWORD not in admins[0].password_hash


def test_logins_are_audited(client, engine):
    login(client)
    login(client, password="wrong")
    with make_session_factory(engine)() as s:
        admin = s.scalars(sa.select(User).where(User.email == ADMIN_EMAIL)).one()
        actions = s.scalars(
            sa.select(AuditEvent.action).where(AuditEvent.object_id == admin.id)
        ).all()
    assert "user.bootstrap" in actions
    assert "user.login" in actions and "user.login_failed" in actions
