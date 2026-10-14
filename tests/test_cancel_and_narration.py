"""Stop scan (cooperative cancellation) and the dnstwist narration callbacks."""

import uuid

from fastapi.testclient import TestClient

from brandwatch.api.main import create_app
from brandwatch.config.settings import Settings
from brandwatch.db.enums import JobState
from brandwatch.db.models import ScanJob
from brandwatch.detection import sources
from brandwatch.detection.discovery import TLD_SETS
from brandwatch.events.emitter import replay
from brandwatch.jobs.queue import create_job

ADMIN = {"email": "admin@test.local", "password": "test-admin-password"}


def demo_settings(tmp_path, **kw) -> Settings:
    return Settings(
        _env_file=None, demo_mode=True, evidence_dir=str(tmp_path / "ev"),
        bootstrap_admin_email=ADMIN["email"], bootstrap_admin_password=ADMIN["password"],
        secret_key="unit-test-secret-0123456789abcdef", **kw,
    )  # fmt: skip


async def test_dnstwist_narrates_generation_and_progress_and_can_stop():
    generated: list[tuple[int, dict]] = []
    progress: list[tuple[int, int, int]] = []
    calls: list[str] = []

    def resolver(name: str) -> bool:
        calls.append(name)
        return name.endswith(".io")

    r = await sources.stream_dnstwist(
        ["cryptohopper.com"], tlds="common", max_hits=None, dictionary=["login", "trading"],
        resolver=resolver, concurrency=20,
        on_generated=lambda total, bd: generated.append((total, bd)),
        on_progress=lambda done, total, reg, unknown=0: progress.append((done, total, len(reg))),
    )  # fmt: skip
    total, breakdown = generated[0]
    assert (
        total == r.generated == len(calls) and "dictionary" in breakdown and "tld-swap" in breakdown
    )
    assert breakdown["dictionary"]["label"] == "combinations with keywords"
    assert any(
        x.startswith("cryptohopper") and "trading" in x
        for x in breakdown["dictionary"]["examples"] + [h.raw_value for h in r.hits] + calls
    )
    assert progress and progress[-1][0] == total and progress[-1][2] == len(r.hits)
    assert r.tlds == len(TLD_SETS["common"]) and all(h.raw_value.endswith(".io") for h in r.hits)

    # Stop after the first batch: far fewer names checked, and the note says so
    ticks = {"n": 0}

    def stop_after_first() -> bool:
        ticks["n"] += 1
        return ticks["n"] > 1

    calls.clear()
    r2 = await sources.stream_dnstwist(
        ["cryptohopper.com"], tlds="common", max_hits=None, resolver=resolver, concurrency=20,
        should_stop=stop_after_first,
    )  # fmt: skip
    assert len(calls) < r2.generated and "stopped by the analyst" in (r2.note or "")


def test_cancel_api_and_runner_respect_it(engine, tmp_path):
    app = create_app(settings=demo_settings(tmp_path), engine=engine)
    with TestClient(app) as c:
        token = c.post("/api/auth/login", json=ADMIN).json()["access_token"]
        c.headers["Authorization"] = f"Bearer {token}"
        brand = c.post(
            "/api/brands",
            json={"name": f"Stop {uuid.uuid4().hex[:4]}", "domains": ["shopnova.com"]},
        ).json()
        me = c.get("/api/auth/me").json()
        # a job that is queued but not picked up by a worker: cancel it, then run the handler
        with app.state.session_factory() as s:
            job = create_job(
                s, "url_scan", {"urls": ["https://shopnova-giftcard.com/"]},
                workspace_id=uuid.UUID(me["workspace_id"]), brand_id=uuid.UUID(brand["id"]),
            )  # fmt: skip
            s.commit()
            jid = job.id
        assert c.post(f"/api/jobs/{jid}/cancel").json()["state"] == "cancelled"
        assert c.post(f"/api/jobs/{jid}/cancel").status_code == 409  # already finished
        handler = app.state.queue.handlers["url_scan"]
        with app.state.session_factory() as s:
            handler(s, jid)
            s.commit()
        with app.state.session_factory() as s:
            j = s.get(ScanJob, jid)
            assert j.state is JobState.CANCELLED and j.finished_at is not None
            assert replay(s, jid) == []  # never started: nothing was scanned
        # a finished job cannot be cancelled
        done = c.post(
            f"/api/brands/{brand['id']}/scan-urls",
            json={"urls": ["https://shopnova-giftcard.com/"]},
        ).json()["job_id"]
        app.state.queue.wait(uuid.UUID(done), timeout=120)
        assert c.post(f"/api/jobs/{done}/cancel").status_code == 409
        page = c.get(f"/ui/jobs/{done}")
        assert page.status_code in (200, 303)
