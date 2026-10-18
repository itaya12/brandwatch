"""The findings list as a queue: server-side search, "since", sort and paging; a verdict that opens the next open
finding with an undo (reopen); a dismiss that also allowlists the domain; "new since my last visit"."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

import sqlalchemy as sa
from fastapi.testclient import TestClient
from tests.test_demo_story import _api, _app, _ui
from tests.test_findings_bulk import HOSTS, _brand

from brandwatch.db.models import AuditEvent, BrandDomain, User


def test_search_since_sort_and_paging_on_the_api(engine, tmp_path):
    app = _app(engine, tmp_path)
    with TestClient(app):
        c = _api(app)
        brand, rows = _brand(c, app)
        bid = brand["id"]
        q = lambda **p: c.get("/api/findings", params={"brand_id": bid, "state": "open", **p}).json()  # noqa: E731
        assert {f["hostname"] for f in q(q="login")} == {"shopnova-login.com"}
        assert {f["hostname"] for f in q(q="SHOPN0VA")} == {"shopn0va.com"}  # case does not matter
        assert q(q="nothing-like-this") == []
        assert len(q(since="24h")) == len(HOSTS) and len(q(since="7d")) == len(HOSTS)
        newest = [f["hostname"] for f in q(sort="newest")]
        assert newest == [f["hostname"] for f in q(sort="oldest")][::-1]
        scores = [f["score"] for f in q(sort="score")]
        assert scores == sorted(scores, reverse=True)
        page1, page2 = q(limit=3, offset=0), q(limit=3, offset=3)
        assert len(page1) == 3 and len(page2) == 1 and not {f["id"] for f in page1} & {f["id"] for f in page2}
        assert c.get("/api/findings", params={"sort": "sideways"}).status_code == 422
        assert c.get("/api/findings", params={"since": "forever"}).status_code == 422


def test_the_page_pages_sorts_searches_and_shows_the_total(engine, tmp_path):
    app = _app(engine, tmp_path)
    with TestClient(app):
        c, ui = _api(app), _ui(app)
        brand, rows = _brand(c, app)
        base = f"/ui/findings?brand_id={brand['id']}&state=open"
        page = ui.get(base).text
        assert f"{len(HOSTS)} open" in page and 'name="q"' in page and 'name="since"' in page and 'name="sort"' in page
        assert "page 1 /" not in page  # one page: no pager
        found = ui.get(base + "&q=login").text
        assert "shopnova-login.com" in found.split('id="ftable"')[-1] and "shopn0va.com" not in found.split('id="ftable"')[-1]
        assert "1 match" in found
        assert "Nothing matches these filters" in ui.get(base + "&q=zzz").text
        # a bad page number lands on the last page, never a 500
        assert ui.get(base + "&page=99").status_code == 200
        assert ui.get(base + "&sort=sideways").status_code == 200  # unknown sort → the default, not an error


def test_a_verdict_opens_the_next_open_finding_and_undo_reopens_it(engine, tmp_path):
    app = _app(engine, tmp_path)
    with TestClient(app):
        c, ui = _api(app), _ui(app)
        brand, rows = _brand(c, app)
        order = [f["id"] for f in c.get("/api/findings", params={"brand_id": brand["id"], "state": "open"}).json()]
        first, second = order[0], order[1]
        page = ui.get(f"/ui/findings/{first}").text
        assert f'href="/ui/findings/{second}" rel="next"' in page and f"{len(order)} open for" in page
        assert page.count('id="verdict-kind"') == 1 and 'id="verdict"' in page  # the select and the panel have their own ids
        assert 'name="whitelist"' in page
        r = ui.post(f"/ui/findings/{first}/verdict", data={"action": "confirm", "reason": "cloned login", "next": "/ui/findings"}, follow_redirects=False)
        assert r.status_code == 303 and r.headers["location"].startswith(f"/ui/findings/{second}?flash=confirmed:")
        shown = ui.get(r.headers["location"]).text
        assert 'id="flash"' in shown and "confirmed as phishing" in shown and f'action="/ui/findings/{first}/reopen"' in shown
        assert c.get(f"/api/findings/{first}").json()["finding"]["state"] == "confirmed"
        # undo
        u = ui.post(f"/ui/findings/{first}/reopen", data={"next": f"/ui/findings/{second}?flash=confirmed:x:{first}"}, follow_redirects=False)
        assert u.status_code == 303 and u.headers["location"].startswith(f"/ui/findings/{second}?flash=reopened:") and u.headers["location"].endswith(first)
        assert "flash=confirmed" not in u.headers["location"]  # never two flashes
        f = c.get(f"/api/findings/{first}").json()["finding"]
        assert f["state"] == "open" and f["analyst_verdict"] is None
        with engine.connect() as conn:
            acts = conn.execute(sa.select(AuditEvent.action).where(AuditEvent.object_id == uuid.UUID(first))).scalars().all()
        assert "finding.reopened" in acts and "finding.confirmed" in acts
        # reopening an open finding is a conflict on the API
        assert c.post(f"/api/findings/{first}/reopen").status_code == 409
        # the last open finding of the brand: back to the list with the flash
        for fid in order[1:]:
            c.post(f"/api/findings/{fid}/dismiss", json={"reason": "x"})
        last = ui.post(f"/ui/findings/{first}/verdict", data={"action": "dismiss", "verdict": "legitimate", "next": "/ui/findings?state=open"}, follow_redirects=False)
        assert last.headers["location"].startswith("/ui/findings?state=open&flash=dismissed:")


def test_dismiss_can_allowlist_the_domain_alone_and_in_bulk(engine, tmp_path):
    app = _app(engine, tmp_path)
    with TestClient(app):
        c, ui = _api(app), _ui(app)
        brand, rows = _brand(c, app)
        one = rows["shopnowa.com"]["id"]
        out = c.post(f"/api/findings/{one}/dismiss", json={"reason": "a parked page", "verdict": "legitimate", "whitelist": True}).json()
        assert out["whitelisted"] == "shopnowa.com"
        r = ui.post("/ui/findings/bulk", data={"ids": [rows["shopn0va.com"]["id"], rows["secure-shopnova.com"]["id"]], "action": "dismiss",
                                                "verdict": "suspicious", "whitelist": "on", "next": "/ui/findings"}, follow_redirects=False)  # fmt: skip
        assert r.status_code == 303
        for h in ("shopn0va.com", "secure-shopnova.com"):
            assert c.get(f"/api/findings/{rows[h]['id']}").json()["finding"]["analyst_verdict"] == "suspicious"  # the bulk verdict travels
        with engine.connect() as conn:
            doms = conn.execute(sa.select(BrandDomain.domain, BrandDomain.kind).where(BrandDomain.brand_id == uuid.UUID(brand["id"]), BrandDomain.is_official.is_(False))).all()
        assert {d for d, _ in doms} >= {"shopnowa.com", "shopn0va.com", "secure-shopnova.com"} and all(k == "known_legit" for _, k in doms)
        # the allowlisted sites are not flagged again
        job = c.post(f"/api/brands/{brand['id']}/scan-urls", json={"urls": ["https://shopnowa.com/"]}).json()["job_id"]
        app.state.queue.wait(uuid.UUID(job), timeout=120)
        assert all(f["hostname"] != "shopnowa.com" for f in c.get("/api/findings", params={"brand_id": brand["id"], "state": "open"}).json())


def test_new_since_my_last_visit_uses_the_previous_sign_in(engine, tmp_path):
    app = _app(engine, tmp_path)
    with TestClient(app):
        c = _api(app)
        brand, rows = _brand(c, app)
        with engine.begin() as conn:
            conn.execute(sa.update(User).values(previous_login_at=datetime.now(UTC) + timedelta(hours=1)))  # "last visit" after every finding
        assert c.get("/api/findings", params={"brand_id": brand["id"], "since": "visit"}).json() == []
        with engine.begin() as conn:
            conn.execute(sa.update(User).values(previous_login_at=datetime.now(UTC) - timedelta(days=1)))
        assert len(c.get("/api/findings", params={"brand_id": brand["id"], "since": "visit"}).json()) == len(HOSTS)
        with engine.begin() as conn:
            conn.execute(sa.update(User).values(previous_login_at=None))  # first sign-in: everything is new
        assert len(c.get("/api/findings", params={"brand_id": brand["id"], "since": "visit"}).json()) == len(HOSTS)


def test_record_login_keeps_the_previous_sign_in():
    u = User(workspace_id=uuid.uuid4(), email="q@example.com", password_hash="x")
    t0 = datetime(2026, 10, 18, 9, 0, tzinfo=UTC)
    u.record_login(t0)
    assert u.last_login_at == t0 and u.previous_login_at is None
    u.record_login(t0 + timedelta(minutes=2))  # a second tab: not a new visit
    assert u.previous_login_at is None and u.last_login_at == t0 + timedelta(minutes=2)
    u.record_login(t0 + timedelta(days=1))
    assert u.previous_login_at == t0 + timedelta(minutes=2)
    u.last_login_at = (t0 + timedelta(days=1)).replace(tzinfo=None)  # as SQLite returns it
    u.record_login(t0 + timedelta(days=2))
    assert u.previous_login_at == t0 + timedelta(days=1)
