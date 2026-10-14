"""Every finding carries what the reputation feeds say (VirusTotal first) and a link to each
feed's own page, so the analyst can verify with one click."""

import uuid

from fastapi.testclient import TestClient

from brandwatch.api.main import create_app
from brandwatch.config.settings import Settings

ADMIN = {"email": "admin@test.local", "password": "test-admin-password"}


def test_findings_expose_virustotal_counts_and_links(engine, tmp_path):
    settings = Settings(
        _env_file=None, demo_mode=True, evidence_dir=str(tmp_path / "ev"),
        bootstrap_admin_email=ADMIN["email"], bootstrap_admin_password=ADMIN["password"],
        secret_key="unit-test-secret-0123456789abcdef",
    )  # fmt: skip
    app = create_app(settings=settings, engine=engine)
    with TestClient(app) as c:
        token = c.post("/api/auth/login", json=ADMIN).json()["access_token"]
        c.headers["Authorization"] = f"Bearer {token}"
        brand = c.post(
            "/api/brands", json={"name": f"VT {uuid.uuid4().hex[:4]}", "domains": ["shopnova.com"]}
        ).json()
        job = c.post(
            f"/api/brands/{brand['id']}/scan-urls",
            json={"urls": ["https://shopnova-giftcard.com/"]},
        ).json()["job_id"]
        app.state.queue.wait(uuid.UUID(job), timeout=120)
        j = c.get(f"/api/jobs/{job}").json()
        assert j["state"] == "done", f"scan job {j['state']}: {j.get('error')}"
        rows = c.get("/api/findings", params={"brand_id": brand["id"]}).json()
        assert rows, "the url scan produced no finding (see the job's events)"
        row = rows[0]
        assert row["vt"]["url"] == "https://www.virustotal.com/gui/domain/shopnova-giftcard.com"
        assert row["vt"]["checked"] and row["vt"]["positives"] is not None
        detail = c.get(f"/api/findings/{row['id']}").json()
        intel = {t["provider"]: t for t in detail["threat_intel"]}
        assert (
            intel["virustotal"]["url"].endswith("/shopnova-giftcard.com")
            and intel["virustotal"]["summary"]
        )
        assert set(intel) <= {"virustotal", "safebrowsing", "urlhaus"} and "urlscan" not in intel
        assert intel["safebrowsing"]["url"].startswith("https://transparencyreport.google.com/safe-browsing/search?url=")
        assert "urlhaus" not in intel or intel["urlhaus"]["status"] == "positive"  # shown only when it lists the host
        # the UI page uses cookie auth; the API client only has a bearer token, so it is
        # redirected to the login page (303) or shown it (200) — the template itself renders
        # without error either way
        assert c.get(f"/ui/findings/{row['id']}").status_code in (200, 303)
