"""Automatic scans: per brand, off until switched on; how often, at what local hour, which tasks."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import sqlalchemy as sa
from fastapi.testclient import TestClient
from tests.conftest import make_brand, make_workspace
from tests.test_demo_story import _api, _app, _ui

import brandwatch.db.models as m
from brandwatch.config.settings import Settings
from brandwatch.db.enums import JobState
from brandwatch.detection import schedule as sched
from brandwatch.detection.runner import run_scan
from brandwatch.detection.scheduler import WatchScheduler
from brandwatch.events.emitter import replay


def _s(**kw):
    base = {"enabled": True, "every_hours": 24, "hour": 3, "tz_offset": -180, "tasks": ["dnstwist"]}  # Israel: UTC+3
    return sched.Schedule(**{**base, **kw})


# ------------------------------------------------------------------------------------ the clock
def test_every_day_at_three_local_time():
    s = _s(updated_at="2026-10-11T12:00:00+00:00")
    # first run: the next 03:00 Israel time (00:00 UTC) after switching on
    assert sched.next_due(s, None, datetime(2026, 10, 11, 12, tzinfo=UTC)) == datetime(2026, 10, 12, 0, 0, tzinfo=UTC)
    # then every day at that hour, even if the last run started a few minutes late
    last = datetime(2026, 10, 12, 0, 4, tzinfo=UTC)
    assert sched.next_due(s, last, last) == datetime(2026, 10, 13, 0, 0, tzinfo=UTC)


def test_every_two_days_and_any_time():
    last = datetime(2026, 10, 12, 0, 0, tzinfo=UTC)
    assert sched.next_due(_s(every_hours=48), last, last) == datetime(2026, 10, 14, 0, 0, tzinfo=UTC)
    assert sched.next_due(_s(every_hours=168, hour=None), last, last) == last + timedelta(days=7) - timedelta(hours=3)
    assert sched.next_due(_s(every_hours=12, hour=None), last, last) == last + timedelta(hours=12)


def test_clean_and_defaults():
    c = sched.clean({"enabled": True, "every_hours": "48", "hour": "any", "tz_offset": 99999, "tasks": ["social", "bogus", "ct"]})
    assert c == {"enabled": True, "every_hours": 48, "hour": None, "tz_offset": 840, "tasks": ["ct", "social"]}
    assert sched.clean({"enabled": True, "tasks": []})["enabled"] is False  # nothing to do = off
    brand = SimpleNamespace(schedule=None, kind="retail")
    det = SimpleNamespace(streams=["dnstwist", "ct", "search"], social_accounts=True)
    s = sched.load(brand, det)
    assert not s.enabled and s.tasks == ["dnstwist", "ct", "search", "meta_ads", "social", "watchlist"]


def test_cost_estimate_counts_only_paid_tasks():
    free = sched.cost_estimate(_s(tasks=["dnstwist", "ct", "nrd", "urlscan"]), approved_queries=10, search_max=10,
                               geos=1, retail=False, ad_queries=2)  # fmt: skip
    assert free["per_run"] == 0 and not free["lines"]
    paid = sched.cost_estimate(_s(tasks=["search", "social"]), approved_queries=10, search_max=10, geos=2,
                               retail=False, ad_queries=2)  # fmt: skip
    assert paid["per_run"] > 0.2 and abs(paid["per_month"] - paid["per_run"] * 30) < 0.2


# ------------------------------------------------------------------------------------ the scheduler
class _Queue:
    def __init__(self):
        self.calls = []

    def enqueue(self, kind, payload=None, *, workspace_id, brand_id=None):
        self.calls.append((kind, payload, brand_id))
        return uuid.uuid4()


def test_scheduler_only_scans_brands_switched_on(engine, tmp_path):
    from brandwatch.db.base import make_session_factory

    factory = make_session_factory(engine)
    settings = Settings(_env_file=None, demo_mode=True, evidence_dir=str(tmp_path / "ev"))
    now = datetime.now(UTC)
    with factory() as s:
        ws = make_workspace(s, f"sch-{uuid.uuid4().hex[:6]}")
        off = make_brand(s, ws, "Off Brand")
        on = make_brand(s, ws, "On Brand")
        on.schedule = {"enabled": True, "every_hours": 24, "hour": None, "tasks": ["ct", "social", "fingerprint"],
                       "updated_at": (now - timedelta(hours=1)).isoformat()}  # fmt: skip
        busy = make_brand(s, ws, "Busy Brand")
        busy.schedule = dict(on.schedule)
        s.add(m.ScanJob(workspace_id=ws.id, brand_id=busy.id, kind="brand_scan", state=JobState.RUNNING))
        s.commit()
        ids = {"off": off.id, "on": on.id, "busy": busy.id}
    q = _Queue()
    WatchScheduler(factory, q, settings).tick(now)
    mine = {k: [c for c in q.calls if c[2] == v and c[0] == "brand_scan"] for k, v in ids.items()}
    assert not mine["off"] and not mine["busy"]  # off: never; busy: one scan at a time
    (kind, payload, _b), = mine["on"]
    assert payload["scheduled"] and payload["tasks"] == ["ct", "social", "fingerprint"] and payload["rebuild_baseline"]
    # the next tick: not due again until tomorrow
    with factory() as s:
        s.add(m.ScanJob(workspace_id=s.get(m.Brand, ids["on"]).workspace_id, brand_id=ids["on"], kind="brand_scan",
                        state=JobState.DONE, payload=payload, created_at=now))  # fmt: skip
        s.commit()
    q2 = _Queue()
    WatchScheduler(factory, q2, settings).tick(now + timedelta(hours=2))
    assert not [c for c in q2.calls if c[2] == ids["on"] and c[0] == "brand_scan"]


async def test_an_automatic_run_does_exactly_its_tasks(session, tmp_path):
    ws = make_workspace(session, f"tasks-{uuid.uuid4().hex[:6]}")
    brand = make_brand(session, ws, "ShopNova")
    session.add(m.BrandDomain(brand_id=brand.id, domain="shopnova.com"))
    session.add(m.Config(brand_id=brand.id, preset="basic", detection={"streams": ["dnstwist", "ct", "urlscan"], "max_candidates": 10},
                         economic_limits={}, scoring={}))  # fmt: skip
    job = m.ScanJob(workspace_id=ws.id, brand_id=brand.id, kind="brand_scan",
                    payload={"scheduled": True, "schedule": "every day at 03:00", "tasks": ["ct"]})  # fmt: skip
    session.add(job)
    session.flush()
    summary = await run_scan(session, job.id, settings=Settings(_env_file=None, demo_mode=True, evidence_dir=str(tmp_path / "ev")),
                             max_candidates=10)  # fmt: skip
    steps = {e.step for e in replay(session, job.id) if e.stage == "discovery"}
    assert "ct" in steps and not ({"dnstwist", "urlscan", "social"} & steps)  # the track has more; the run did only CT
    assert any(st["title"].startswith("Automatic scan · every day at 03:00") for st in summary.steps)


# ------------------------------------------------------------------------------------ API + page
def test_schedule_api_and_panel(engine, tmp_path):
    app = _app(engine, tmp_path)
    with TestClient(app):
        c = _api(app)
        b = c.post("/api/brands", json={"name": f"ShopNova {uuid.uuid4().hex[:4]}", "domains": ["shopnova.com"]}).json()
        got = c.get(f"/api/brands/{b['id']}").json()["schedule"]
        assert got["enabled"] is False and "dnstwist" in got["tasks"] and got["next"] is None
        r = c.put(f"/api/brands/{b['id']}/schedule", json={"enabled": True, "every_hours": 48, "hour": 3, "tz_offset": -180,
                                                            "tasks": ["dnstwist", "social", "watchlist"]})  # fmt: skip
        sc = r.json()["schedule"]
        assert r.status_code == 200 and sc["enabled"] and sc["label"] == "every 2 days at 03:00" and sc["next"]
        assert c.put(f"/api/brands/{b['id']}/schedule", json={"enabled": True, "tasks": []}).status_code == 422
        ui = _ui(app)
        page = ui.get(f"/ui/brands/{b['id']}").text
        assert 'id="schedule"' in page and "Scan automatically" in page and "automatic: every 2 days at 03:00" in page
        r = ui.post(f"/ui/brands/{b['id']}/schedule", data={"every_hours": "168", "hour": "any", "tz_offset": "0",
                                                            "tasks": ["ct"]}, follow_redirects=False)  # fmt: skip
        assert r.status_code == 303 and "schedule=saved" in r.headers["location"]
        sc = c.get(f"/api/brands/{b['id']}").json()["schedule"]
        assert sc["enabled"] is False and sc["every_hours"] == 168 and sc["tasks"] == ["ct"]  # unticked = off
    from brandwatch.db.base import make_session_factory

    with make_session_factory(engine)() as s:
        assert s.scalars(sa.select(m.AuditEvent).where(m.AuditEvent.action == "brand.schedule_updated",
                                                      m.AuditEvent.object_id == uuid.UUID(b["id"]))).first()  # fmt: skip

