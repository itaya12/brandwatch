"""AI-generated Google search queries for the search stream; delete campaign; purge a brand
("start over") with the evidence immutability suspended for exactly that transaction."""

import uuid

import pytest
import sqlalchemy as sa
from fastapi.testclient import TestClient

from brandwatch.api.main import create_app
from brandwatch.config.settings import Settings
from brandwatch.db.enums import NodeType
from brandwatch.db.models import Campaign, CampaignNode, Candidate, Evidence, Finding
from brandwatch.detection import ai, sources
from brandwatch.providers.registry import ProviderRegistry

ADMIN = {"email": "admin@test.local", "password": "test-admin-password"}


def demo_settings(tmp_path, **kw) -> Settings:
    return Settings(
        _env_file=None, demo_mode=True, evidence_dir=str(tmp_path / "ev"),
        bootstrap_admin_email=ADMIN["email"], bootstrap_admin_password=ADMIN["password"],
        secret_key="unit-test-secret-0123456789abcdef", **kw,
    )  # fmt: skip


def test_default_search_queries_cover_intents_and_misspellings():
    qs = ai.default_search_queries("CryptoHopper", "cryptohopper")
    assert {"cryptohopper login", "cryptohopper sign up", "cryptohopper support"} <= set(qs)
    assert any("crypto hopper" in q for q in qs)  # a space inside the name
    assert any("cryptohoper" in q for q in qs)  # squeezed double letter
    assert len(qs) <= 15 and len(set(qs)) == len(qs)


async def test_mock_profile_lists_queries_and_the_stream_runs_each_one(tmp_path):
    reg = ProviderRegistry(demo_settings(tmp_path))
    prof = await ai.brand_profile(reg, brand_name="ShopNova", homepage_text="shop nova store")
    assert prof["search_queries"] and all("shop" in q for q in prof["search_queries"])
    res = await sources.stream_search(
        reg, "ShopNova", {"shopnova.com"}, geo="us", lang="en",
        queries=["shopnova login", "shopnova support"],
    )  # fmt: skip
    assert res.api_calls == 2 and not res.degraded and res.hits
    assert len({h.raw_value for h in res.hits}) == len(res.hits)  # merged across queries
    assert all("shopnova login" in h.matched_pattern or "shopnova support" in h.matched_pattern
               for h in res.hits)  # fmt: skip


def _scan(c, app, brand_id: str, url: str) -> None:
    job = c.post(f"/api/brands/{brand_id}/scan-urls", json={"urls": [url]}).json()["job_id"]
    app.state.queue.wait(uuid.UUID(job), timeout=120)


def test_delete_campaign_then_purge_brand_and_immutability_survives(engine, tmp_path):
    app = create_app(settings=demo_settings(tmp_path), engine=engine)
    with TestClient(app) as c:
        token = c.post("/api/auth/login", json=ADMIN).json()["access_token"]
        c.headers["Authorization"] = f"Bearer {token}"
        brand = c.post(
            "/api/brands",
            json={"name": f"Reset {uuid.uuid4().hex[:4]}", "domains": ["shopnova.com"],
                  "preset": "standard"},
        ).json()  # fmt: skip
        bid = uuid.UUID(brand["id"])
        _scan(c, app, brand["id"], "https://shopnova-giftcard.com/")
        finding = c.get("/api/findings", params={"brand_id": brand["id"]}).json()[0]
        assert c.get(f"/api/brands/{brand['id']}").json()["baseline"]["search_queries"]

        with app.state.session_factory() as s:  # a campaign linked to the finding
            camp = Campaign(brand_id=bid, name="test campaign")
            s.add(camp)
            s.flush()
            s.add(
                CampaignNode(
                    campaign_id=camp.id, type=NodeType("domain"), value="shopnova-giftcard.com"
                )
            )
            s.execute(
                sa.update(Finding)
                .where(Finding.id == uuid.UUID(finding["id"]))
                .values(campaign_id=camp.id)
            )
            s.commit()
            cid = camp.id
        assert c.delete(f"/api/campaigns/{cid}").status_code == 204
        assert c.delete(f"/api/campaigns/{cid}").status_code == 404
        with app.state.session_factory() as s:
            assert s.get(Finding, uuid.UUID(finding["id"])).campaign_id is None
            assert (
                s.scalar(
                    sa.select(sa.func.count())
                    .select_from(Evidence)
                    .join(Candidate)
                    .where(Candidate.brand_id == bid)
                )
                > 0
            )

        ev_dir = tmp_path / "ev"
        assert sum(1 for p in ev_dir.rglob("*") if p.is_file()) > 0
        assert c.delete(f"/api/brands/{brand['id']}").status_code == 204
        assert sum(1 for p in ev_dir.rglob("*") if p.is_file()) == 0  # artifacts removed too
        assert c.get(f"/api/brands/{brand['id']}").status_code == 404
        with app.state.session_factory() as s:
            assert (
                s.scalar(
                    sa.select(sa.func.count())
                    .select_from(Candidate)
                    .where(Candidate.brand_id == bid)
                )
                == 0
            )
            assert (
                s.scalar(
                    sa.select(sa.func.count()).select_from(Finding).where(Finding.brand_id == bid)
                )
                == 0
            )
            audit_rows = s.execute(  # this brand's purge only: the database is shared with other tests
                sa.text("select count(*) from audit_events where action='brand.purged' and object_id = :oid"),
                {"oid": uuid.UUID(brand["id"]).hex},
            ).scalar()
            assert audit_rows == 1

        # immutability is back in force after the purge: evidence still cannot be edited
        brand2 = c.post(
            "/api/brands",
            json={"name": f"After {uuid.uuid4().hex[:4]}", "domains": ["shopnova.com"]},
        ).json()
        _scan(c, app, brand2["id"], "https://shopnova-giftcard.com/")
        with app.state.session_factory() as s:
            ev = s.scalars(
                sa.select(Evidence)
                .join(Candidate)
                .where(Candidate.brand_id == uuid.UUID(brand2["id"]))
            ).first()
            assert ev is not None
            with pytest.raises(sa.exc.DBAPIError):
                s.execute(
                    sa.update(Evidence).where(Evidence.id == ev.id).values(trust_level="forged")
                )
                s.flush()
            s.rollback()
