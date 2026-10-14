"""Phase 6 — Productization: RBAC (admin / analyst / viewer), personal access tokens, encrypted
provider keys, workspace budget inheritance, multi-tenant isolation, scoring editor with live
re-score preview, whitelist, settings UI."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

import pytest
import sqlalchemy as sa
from fastapi.testclient import TestClient

import brandwatch.db.models as m
from brandwatch import keys as keystore
from brandwatch import tenancy
from brandwatch.api.main import create_app
from brandwatch.config.settings import Settings
from brandwatch.providers.registry import ProviderRegistry

ADMIN = {"email": "admin@test.local", "password": "test-admin-password"}
PW = "a-long-password-123"


@pytest.fixture
def env(engine, tmp_path):
    settings = Settings(_env_file=None, demo_mode=True, evidence_dir=str(tmp_path / "ev"), bootstrap_admin_email=ADMIN["email"],
                        bootstrap_admin_password=ADMIN["password"], secret_key="unit-test-secret-0123456789abcdef")  # fmt: skip
    app = create_app(settings=settings, engine=engine)
    with TestClient(app) as admin:
        admin.headers["Authorization"] = (
            "Bearer " + admin.post("/api/auth/login", json=ADMIN).json()["access_token"]
        )
        yield app, admin, settings


def login_client(app, email, password=PW) -> TestClient:
    c = TestClient(app)
    r = c.post("/api/auth/login", json={"email": email, "password": password})
    assert r.status_code == 200, r.text
    c.headers["Authorization"] = "Bearer " + r.json()["access_token"]
    return c


def new_user(admin: TestClient, role: str) -> str:
    email = f"{role}-{uuid.uuid4().hex[:6]}@test.local"
    r = admin.post("/api/admin/users", json={"email": email, "password": PW, "role": role})
    assert r.status_code == 201, r.text
    return email


def scan(app, client, brand_id, urls):
    r = client.post(f"/api/brands/{brand_id}/scan-urls", json={"urls": urls})
    assert r.status_code == 202, r.text
    app.state.queue.wait(uuid.UUID(r.json()["job_id"]), timeout=120)


def make_brand(client, name=None):
    r = client.post(
        "/api/brands",
        json={"name": name or f"ShopNova {uuid.uuid4().hex[:4]}", "domains": ["shopnova.com"]},
    )
    assert r.status_code == 201, r.text
    return r.json()


# ------------------------------------------------------------------------------------------ RBAC
def test_roles_are_enforced_on_every_mutation(env):
    app, admin, _ = env
    brand = make_brand(admin)
    scan(app, admin, brand["id"], ["https://shopn0va.com/"])
    finding = admin.get("/api/findings", params={"brand_id": brand["id"]}).json()[0]

    viewer = login_client(app, new_user(admin, "viewer"))
    assert viewer.get("/api/findings", params={"brand_id": brand["id"]}).status_code == 200
    assert viewer.get(f"/api/findings/{finding['id']}").status_code == 200
    for method, url, body in (
        ("post", f"/api/brands/{brand['id']}/scan", {}),
        ("post", f"/api/brands/{brand['id']}/scan-urls", {"urls": ["https://x.example/"]}),
        ("post", f"/api/findings/{finding['id']}/confirm", {"reason": "x"}),
        ("post", f"/api/findings/{finding['id']}/report", None),
        ("post", "/api/brands", {"name": "Nope Brand", "domains": ["nope.example"]}),
        ("patch", f"/api/brands/{brand['id']}/config", {"preset": "standard"}),
        ("post", "/api/ml/train", {"source": "golden"}),
    ):
        r = (
            getattr(viewer, method)(url, json=body)
            if body is not None
            else getattr(viewer, method)(url)
        )
        assert r.status_code == 403, (url, r.status_code)

    analyst = login_client(app, new_user(admin, "analyst"))
    assert (
        analyst.post(f"/api/findings/{finding['id']}/confirm", json={"reason": "clone"}).status_code
        == 200
    )
    for url in (
        "/api/admin/users",
        "/api/admin/workspace",
        "/api/admin/api-keys",
        "/api/admin/workspaces",
    ):
        assert analyst.get(url).status_code == 403, url

    # the UI enforces the same rule
    vui = TestClient(app)
    v_email = next(
        u["email"] for u in admin.get("/api/admin/users").json() if u["role"] == "viewer"
    )
    assert (
        vui.post(
            "/ui/login", data={"email": v_email, "password": PW}, follow_redirects=False
        ).status_code
        == 303
    )
    assert vui.post(f"/ui/brands/{brand['id']}/scan", data={}).status_code == 403
    page = vui.get(f"/ui/findings/{finding['id']}").text
    assert "Viewer access" in page and "Confirm phishing" not in page


def test_last_admin_cannot_be_demoted_or_disabled(env):
    app, admin, _ = env
    users = admin.get("/api/admin/users").json()
    me = next(u for u in users if u["email"] == ADMIN["email"])
    others = [u for u in users if u["role"] == "admin" and u["is_active"] and u["id"] != me["id"]]
    for o in others:  # make sure the bootstrap admin is the only active admin in this workspace
        admin.patch(f"/api/admin/users/{o['id']}", json={"is_active": False})
    assert admin.patch(f"/api/admin/users/{me['id']}", json={"role": "viewer"}).status_code == 409
    assert admin.patch(f"/api/admin/users/{me['id']}", json={"is_active": False}).status_code == 409
    second = new_user(admin, "admin")
    sid = next(u["id"] for u in admin.get("/api/admin/users").json() if u["email"] == second)
    assert admin.patch(f"/api/admin/users/{sid}", json={"role": "analyst"}).status_code == 200
    assert (
        admin.post(
            "/api/admin/users", json={"email": ADMIN["email"], "password": PW, "role": "viewer"}
        ).status_code
        == 409
    )
    assert (
        admin.post(
            "/api/admin/users",
            json={"email": "short@test.local", "password": "short", "role": "viewer"},
        ).status_code
        == 422
    )


# ------------------------------------------------------------------------------------------ tokens
def test_access_tokens_scopes_revocation_and_expiry(env, engine):
    app, admin, _ = env
    brand = make_brand(admin)
    analyst_email = new_user(admin, "analyst")
    analyst = login_client(app, analyst_email)

    read = analyst.post("/api/tokens", json={"name": "SIEM export", "scope": "read"}).json()
    write = analyst.post(
        "/api/tokens", json={"name": "automation", "scope": "write", "expires_days": 1}
    ).json()
    assert read["token"].startswith("bw_") and read["prefix"] == read["token"][:10]
    bot_r = TestClient(app)
    bot_r.headers["Authorization"] = f"Bearer {read['token']}"
    assert bot_r.get("/api/findings").status_code == 200
    assert (
        bot_r.post(
            f"/api/brands/{brand['id']}/scan-urls", json={"urls": ["https://shopn0va.com/"]}
        ).status_code
        == 403
    )
    bot_w = TestClient(app)
    bot_w.headers["Authorization"] = f"Bearer {write['token']}"
    r = bot_w.post(f"/api/brands/{brand['id']}/scan-urls", json={"urls": ["https://shopn0va.com/"]})
    assert r.status_code == 202
    app.state.queue.wait(uuid.UUID(r.json()["job_id"]), timeout=120)

    listed = analyst.get("/api/tokens").json()
    assert {t["name"] for t in listed} >= {"SIEM export", "automation"} and all(
        "token" not in t for t in listed
    )
    assert next(t for t in listed if t["name"] == "SIEM export")["last_used_at"] is not None
    # only the hash is stored
    with app.state.session_factory() as s:
        row = s.scalars(sa.select(m.AccessToken).where(m.AccessToken.name == "SIEM export")).first()
        assert read["token"] not in (row.token_hash, row.prefix) and len(row.token_hash) == 64
        # expire the write token
        wrow = s.scalars(sa.select(m.AccessToken).where(m.AccessToken.name == "automation")).first()
        wrow.expires_at = datetime.now(UTC) - timedelta(minutes=1)
        s.commit()
    assert bot_w.get("/api/findings").status_code == 401
    assert analyst.delete(f"/api/tokens/{read['id']}").status_code == 204
    assert bot_r.get("/api/findings").status_code == 401
    garbage = TestClient(app)
    garbage.headers["Authorization"] = "Bearer bw_not-a-real-token"
    assert garbage.get("/api/findings").status_code == 401

    viewer = login_client(app, new_user(admin, "viewer"))
    assert viewer.post("/api/tokens", json={"name": "nope", "scope": "write"}).status_code == 403
    assert viewer.post("/api/tokens", json={"name": "ok", "scope": "read"}).status_code == 201


# ------------------------------------------------------------------------------------------ provider keys
def test_provider_keys_are_envelope_encrypted_per_workspace(env):
    app, admin, settings = env
    secret = "vt-live-0123456789abcdef-a4f2"
    r = admin.put("/api/admin/api-keys/virustotal", json={"key": secret})
    assert r.status_code == 200 and r.json()["masked"] == "…a4f2"
    keys = {k["provider"]: k for k in admin.get("/api/admin/api-keys").json()}
    assert keys["virustotal"]["source"] == "workspace" and keys["virustotal"]["masked"] == "…a4f2"
    assert keys["shodan"]["configured"] is False
    with app.state.session_factory() as s:
        row = s.scalars(sa.select(m.ApiKey).where(m.ApiKey.provider == "virustotal")).first()
        assert secret.encode() not in row.ciphertext and secret.encode() not in row.dek_wrapped
        assert keystore.decrypt_key(row, settings) == secret
        # bound to its workspace: the same blob under another workspace id does not decrypt
        forged = m.ApiKey(
            workspace_id=uuid.uuid4(),
            provider="virustotal",
            ciphertext=row.ciphertext,
            dek_wrapped=row.dek_wrapped,
            last4="a4f2",
        )
        with pytest.raises(Exception):  # noqa: B017 - cryptography InvalidTag
            keystore.decrypt_key(forged, settings)
        loaded = keystore.load_keys(s, row.workspace_id, settings)
        assert loaded == {"virustotal": secret}
    # a live registry for this workspace uses the stored key instead of the mock
    live = Settings(
        _env_file=None, demo_mode=False, secret_key=settings.secret_key.get_secret_value()
    )
    reg = ProviderRegistry(live, key_overrides=loaded)
    assert not reg.uses_mock("virustotal") and reg.uses_mock("shodan")
    assert reg.reputation().primary.inner._api_key == secret
    assert (
        admin.post("/api/admin/api-keys/virustotal/test").json()["ok"] is True
    )  # demo: decrypts, not contacted
    assert (
        admin.put("/api/admin/api-keys/not-a-provider", json={"key": "12345678"}).status_code == 422
    )
    assert admin.delete("/api/admin/api-keys/virustotal").status_code == 204
    assert admin.delete("/api/admin/api-keys/virustotal").status_code == 404
    acts = admin.get("/api/dashboard/feed").status_code  # unrelated endpoint still fine
    assert acts == 200


# ------------------------------------------------------------------------------------------ budget + tenants
def test_workspace_budget_inherited_by_brands_and_dashboard(env):
    app, admin, _ = env
    r = admin.patch(
        "/api/admin/workspace",
        json={"economic_limits": {"max_daily_spend": 25, "max_residential_gb": 2}},
    )
    assert r.status_code == 200 and r.json()["economic_limits"]["max_daily_spend"] == 25
    assert (
        admin.patch(
            "/api/admin/workspace", json={"economic_limits": {"max_api_calls": -5}}
        ).status_code
        == 422
    )
    brand = make_brand(admin)
    assert (
        admin.get(f"/api/brands/{brand['id']}").json()["config"]["economic_limits"][
            "max_daily_spend"
        ]
        == 25
    )
    assert (
        admin.patch(
            f"/api/brands/{brand['id']}/config", json={"economic_limits": {"max_daily_spend": 3}}
        ).status_code
        == 200
    )
    assert (
        admin.get(f"/api/brands/{brand['id']}").json()["config"]["economic_limits"][
            "max_daily_spend"
        ]
        == 3
    )
    assert admin.get("/api/dashboard").json()["system"]["budget"]["max_daily_spend"] == 25
    with app.state.session_factory() as s:
        ws = s.scalars(sa.select(m.Workspace).order_by(m.Workspace.created_at)).first()
        assert tenancy.workspace_limits(s, ws.id).max_residential_gb == 2


def test_tenants_are_isolated(env):
    app, admin, _ = env
    brand = make_brand(admin)
    scan(app, admin, brand["id"], ["https://shopn0va.com/"])
    finding = admin.get("/api/findings", params={"brand_id": brand["id"]}).json()[0]
    b_admin = f"tenant-{uuid.uuid4().hex[:6]}@acme.test"
    r = admin.post(
        "/api/admin/workspaces",
        json={"name": f"Acme {uuid.uuid4().hex[:4]}", "admin_email": b_admin, "admin_password": PW},
    )
    assert r.status_code == 201, r.text
    assert any(w["id"] == r.json()["id"] for w in admin.get("/api/admin/workspaces").json())

    other = login_client(app, b_admin)
    assert other.get("/api/brands").json() == []
    assert other.get("/api/findings").json() == []
    assert other.get(f"/api/findings/{finding['id']}").status_code == 404
    assert other.get(f"/api/brands/{brand['id']}").status_code == 404
    assert other.post(f"/api/findings/{finding['id']}/confirm", json={}).status_code == 404
    assert other.get(f"/api/campaigns?brand_id={brand['id']}").json() == []
    assert (
        other.get("/api/admin/workspaces").status_code == 403
    )  # tenant admins do not manage tenants
    assert other.get("/api/dashboard").json()["kpis"]["candidates_total"] == 0
    # its own brand works normally and stays invisible to the platform workspace
    ob = make_brand(other, "Acme Shop")
    assert admin.get(f"/api/brands/{ob['id']}").status_code == 404


# ------------------------------------------------------------------------------------------ scoring editor + whitelist
def test_scoring_preview_apply_and_version_history(env):
    app, admin, _ = env
    brand = make_brand(admin)
    scan(app, admin, brand["id"], ["https://shopnova-support-center.com/", "https://shopn0va.com/"])
    before = {
        f["hostname"]: f
        for f in admin.get("/api/findings", params={"brand_id": brand["id"]}).json()
    }
    assert before["shopnova-support-center.com"]["severity"] == "high"

    harsher = {"scoring": {"thresholds": {"medium": 20, "high": 35, "critical": 50}}}
    p = admin.post(f"/api/brands/{brand['id']}/config/preview", json=harsher).json()
    rows = {r["hostname"]: r for r in p["findings"]}
    assert (
        rows["shopnova-support-center.com"]["after"]["severity"] == "critical"
        and p["severity_changes"] >= 1
    )
    assert p["version"].startswith("v7-")
    # preview is read-only
    assert admin.get("/api/findings", params={"brand_id": brand["id"]}).json()[0]["severity"] in (
        "critical",
        "high",
    )
    assert (
        before["shopnova-support-center.com"]["severity"]
        == admin.get(f"/api/findings/{before['shopnova-support-center.com']['id']}").json()["finding"][
            "severity"
        ]
    )

    r = admin.patch(f"/api/brands/{brand['id']}/config?apply_rescore=true", json=harsher)
    assert r.status_code == 200 and r.json()["rescored"] == 2
    version = r.json()["scoring_version"]
    d = admin.get(f"/api/findings/{before['shopnova-support-center.com']['id']}").json()
    assert d["finding"]["severity"] == "critical" and d["score"]["scoring_version"] == version
    assert [h["scoring_version"] for h in d["score_history"]] == ["v7", version]
    assert sum(h["is_current"] for h in d["score_history"]) == 1
    with app.state.session_factory() as s:
        assert (
            s.scalars(sa.select(m.RiskScoreVersion).where(m.RiskScoreVersion.version == version))
            .one()
            .thresholds["high"]
            == 35
        )
    # idempotent: applying the same config again appends nothing
    assert admin.post(f"/api/brands/{brand['id']}/rescore").json()["rescored"] == 0
    # validation: unknown signal, negative weight, security limit smuggling, non-monotonic thresholds
    for bad in ({"scoring": {"weights": {"made_up": 3}}}, {"scoring": {"weights": {"favicon_exact": -1}}},
                {"detection": {"MAX_RESPONSE_SIZE": 1}}, {"scoring": {"thresholds": {"medium": 60, "high": 50}}}):  # fmt: skip
        assert admin.patch(f"/api/brands/{brand['id']}/config", json=bad).status_code == 422, bad


def test_whitelist_drops_partners_before_any_fetch(env):
    app, admin, _ = env
    brand = make_brand(admin)
    assert (
        admin.post(
            f"/api/brands/{brand['id']}/whitelist",
            json={"domain": "shopnova-partners.com", "kind": "partner"},
        ).status_code
        == 201
    )
    assert (
        admin.post(
            f"/api/brands/{brand['id']}/whitelist", json={"domain": "shopnova-partners.com"}
        ).status_code
        == 409
    )
    detail = admin.get(f"/api/brands/{brand['id']}").json()
    assert detail["whitelist"] == [{"domain": "shopnova-partners.com", "kind": "partner"}]
    assert detail["domains"] == [
        "shopnova.com"
    ]  # partners are not official (not permuted, not baselined)
    r = admin.post(
        f"/api/brands/{brand['id']}/scan-urls",
        json={"urls": ["https://shopnova-partners.com/", "https://shopn0va.com/"]},
    )
    app.state.queue.wait(uuid.UUID(r.json()["job_id"]), timeout=120)
    hosts = {
        c["hostname"] for c in admin.get("/api/candidates", params={"brand_id": brand["id"]}).json()
    }
    assert hosts == {"shopn0va.com"}
    summary = admin.get(f"/api/jobs/{r.json()['job_id']}/events").json()["events"][-1]["data"]
    assert summary["whitelisted"] == 1
    assert (
        admin.delete(f"/api/brands/{brand['id']}/whitelist/shopnova-partners.com").status_code
        == 204
    )
    assert (
        admin.delete(f"/api/brands/{brand['id']}/whitelist/shopnova.com").status_code == 404
    )  # official ≠ whitelist entry


# ------------------------------------------------------------------------------------------ settings UI
def test_settings_ui_admin_and_token_shown_once(env):
    app, admin, _ = env
    brand = make_brand(admin)
    ui = TestClient(app)
    ui.post("/ui/login", data=ADMIN, follow_redirects=False)
    page = ui.get("/ui/settings").text
    for needle in (
        "Workspace &amp; budget",
        "Users &amp; roles",
        "Provider API keys",
        "My API access tokens",
        "Tenants",
        "Classifier",
    ):
        assert needle in page, needle
    r = ui.post(
        "/ui/settings/tokens", data={"name": "ui token", "scope": "read", "expires_days": "7"}
    )
    assert r.status_code == 200 and "copy it now" in r.text
    token = r.text.split(
        'word-break:break-all;background:#060910;padding:10px;border-radius:6px">', 1
    )[1].split("<", 1)[0]
    assert token.startswith("bw_") and token not in ui.get("/ui/settings").text  # never shown again
    assert (
        ui.post(
            "/ui/settings/workspace",
            data={"name": "Default WS", "max_daily_spend": "12"},
            follow_redirects=False,
        ).status_code
        == 303
    )
    assert admin.get("/api/admin/workspace").json()["economic_limits"]["max_daily_spend"] == 12
    assert ui.post("/ui/settings/users", data={"email": f"ui-{uuid.uuid4().hex[:4]}@test.local", "password": PW, "role": "viewer"},
                   follow_redirects=False).status_code == 303  # fmt: skip
    assert (
        ui.post(
            "/ui/settings/api-keys/shodan",
            data={"key": "shodan-key-12345678"},
            follow_redirects=False,
        ).status_code
        == 303
    )
    assert "…5678" in ui.get("/ui/settings").text
    bpage = ui.get(f"/ui/brands/{brand['id']}").text
    assert (
        "Detection track" in bpage
        and "Start scan" in bpage
        and "Preview re-score" in bpage
        and "False-positive whitelist" in bpage
    )
    r = ui.post(f"/ui/brands/{brand['id']}/config", data={"w_favicon_exact": "30", "t_medium": "25", "t_high": "50", "t_critical": "75",
                                                         "streams": ["dnstwist", "ct"], "cloaking_probes": "on"}, follow_redirects=False)  # fmt: skip
    assert r.status_code == 303
    cfg = admin.get(f"/api/brands/{brand['id']}").json()["config"]
    assert cfg["scoring"]["weights"]["favicon_exact"] == 30 and cfg["detection"]["streams"] == [
        "dnstwist",
        "ct",
    ]
    assert cfg["detection"]["ai_second_opinion"] is False
    # analysts see the settings page without admin sections
    analyst_email = new_user(admin, "analyst")
    aui = TestClient(app)
    aui.post("/ui/login", data={"email": analyst_email, "password": PW}, follow_redirects=False)
    apage = aui.get("/ui/settings").text
    assert "Users &amp; roles" not in apage and "My API access tokens" in apage
    assert (
        aui.post("/ui/settings/users", data={"email": "x@test.local", "password": PW}).status_code
        == 403
    )
