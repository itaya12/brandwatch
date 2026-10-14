"""MAP ALL, INVESTIGATE ALL, the progress of each site on the Attack infrastructure page, and one map of every confirmed site.

Mapping and investigating confirmed sites one at a time, from each finding, was the slow part of a day's work. Now one button maps
every site that has no map (one after the other, in one batch job), one button investigates every site that has no investigation
(three at a time, sharing VirusTotal's quota), the table shows where each one is, and one page puts every confirmed site on one map
to show which of them are connected and by what.
"""

from __future__ import annotations

import uuid

import sqlalchemy as sa
from fastapi.testclient import TestClient
from tests.test_demo_story import _api, _app, _ui
from tests.test_pages_js import BROKEN

import brandwatch.db.models as m
from brandwatch.db.enums import JobState

HOSTS = ("shopn0va.com", "shopnova-login.com", "shopnowa.com")


def _confirmed(c, app, *, auto=False):
    brand = c.post("/api/brands", json={"name": f"All {uuid.uuid4().hex[:4]}", "domains": ["shopnova.com"]}).json()
    if not auto:  # confirmations that start nothing: the buttons do the work
        c.patch(f"/api/brands/{brand['id']}/config", json={"detection": {"auto_map_on_confirm": False, "auto_investigate_on_confirm": False}})
    job = c.post(f"/api/brands/{brand['id']}/scan-urls", json={"urls": [f"https://{h}/" for h in HOSTS]}).json()["job_id"]
    app.state.queue.wait(uuid.UUID(job), timeout=120)
    rows = {(f.get("hostname") or f.get("host")): f for f in c.get("/api/findings", params={"brand_id": brand["id"]}).json()}
    for f in rows.values():
        out = c.post(f"/api/findings/{f['id']}/confirm", json={"reason": "cloned"}).json()
        assert out["map_job_id"] is None and out["intel_job_id"] is None
    return brand, rows


def test_map_all_maps_every_unmapped_site_one_after_the_other(engine, tmp_path):
    app = _app(engine, tmp_path)
    with TestClient(app):
        c = _api(app)
        brand, rows = _confirmed(c, app)
        r = c.post("/api/campaigns/map-all", json={"brand_id": brand["id"]}).json()
        assert r["count"] == 3 and r["job_id"]
        app.state.queue.wait(uuid.UUID(r["job_id"]), timeout=300)
        assert c.get(f"/api/jobs/{r['job_id']}").json()["state"] == "done"
        said = [e["message"] for e in c.get(f"/api/jobs/{r['job_id']}/events").json()["events"]]
        assert said[0] == "Mapping 3 confirmed site(s), one by one …" and said[-1] == "Mapped 3 of 3 confirmed site(s)"
        assert [x for x in said if x.startswith("Mapping ") and " of 3: " in x] == [f"Mapping {i} of 3: {h} …" for i, h in enumerate(_order(app, r["job_id"]), 1)]
        with app.state.session_factory() as s:
            for h, f in rows.items():
                assert s.get(m.Finding, uuid.UUID(f["id"])).campaign_id is not None, h  # every site has its map
            kids = s.scalars(sa.select(m.ScanJob).where(m.ScanJob.kind == "investigate")).all()
            mine = [k for k in kids if (k.payload or {}).get("batch") == r["job_id"]]
            assert len(mine) == 3 and all(k.state is JobState.DONE for k in mine)  # an ordinary map job per site, with its own console
        again = c.post("/api/campaigns/map-all", json={"brand_id": brand["id"]}).json()
        assert again == {"job_id": None, "kind": "map_all", "count": 0}  # nothing left to map
        remap = c.post("/api/campaigns/map-all", json={"brand_id": brand["id"], "remap": True}).json()
        assert remap["count"] == 3
        app.state.queue.wait(uuid.UUID(remap["job_id"]), timeout=300)


def _order(app, job_id):
    with app.state.session_factory() as s:
        ids = s.get(m.ScanJob, uuid.UUID(job_id)).payload["finding_ids"]
        return [s.get(m.Candidate, s.get(m.Finding, uuid.UUID(i)).candidate_id).hostname for i in ids]


def test_investigate_all_investigates_every_site_without_one_and_builds_their_packages(engine, tmp_path):
    app = _app(engine, tmp_path)
    with TestClient(app):
        c = _api(app)
        brand, rows = _confirmed(c, app)
        # the test database is shared: a site another test investigated already has its (cached) investigation
        todo = sorted(h for h, f in rows.items() if c.get(f"/api/findings/{f['id']}/intel").json()["fetched_at"] is None)
        r = c.post("/api/campaigns/investigate-all", json={"brand_id": brand["id"]}).json()
        assert r["count"] == len(todo) and sorted(r["hosts"]) == todo
        for jid in r["job_ids"]:
            app.state.queue.wait(uuid.UUID(jid), timeout=300)
        for h in todo:
            iv = c.get(f"/api/findings/{rows[h]['id']}/intel").json()
            assert iv["job"]["state"] == "done" and iv["job"]["light"] is True
            assert {x["format"] for x in c.get(f"/api/findings/{rows[h]['id']}/reports").json()} == {"html", "json"}
        remap = c.post("/api/campaigns/investigate-all", json={"brand_id": brand["id"], "remap": True}).json()
        assert remap["count"] == 3  # "again, all of them" is possible too
        for jid in remap["job_ids"]:
            app.state.queue.wait(uuid.UUID(jid), timeout=300)
        assert c.post("/api/campaigns/investigate-all", json={"brand_id": brand["id"]}).json()["count"] == 0


def test_one_map_of_every_confirmed_site_says_which_are_connected(engine, tmp_path):
    app = _app(engine, tmp_path)
    with TestClient(app):
        c, ui = _api(app), _ui(app)
        brand, rows = _confirmed(c, app)
        data = c.get("/api/campaigns/all-map", params={"brand_id": brand["id"]}).json()
        assert data["stats"]["sites"] == 3
        group = next(g for g in data["groups"] if "shopn0va.com" in g["sites"])
        assert "shopnova-login.com" in group["sites"]  # both sit on 203.0.113.66
        assert any(link["label"] == "the same server" and link["value"] == "203.0.113.66" for link in group["links"])
        assert "are tied together" in data["headline"] and "the same TLS certificate" in data["headline"]  # the headline names the solid ties; a server nobody has looked up is only a hint
        ids = {n["id"] for n in data["nodes"]}
        assert "site:shopn0va.com" in ids and "ip:203.0.113.66" in ids
        assert all(e["source"] in ids and e["target"] in ids for e in data["edges"])
        weak = [n for n in data["nodes"] if n["level"] == "weak"]
        assert weak and all("not proof" in n["triage_reason"] for n in weak)  # a common registrar / favicon is drawn faint, never as a link
        assert all("a hint" in n["triage_reason"] for n in data["nodes"] if n["level"] == "possible")  # a hint is drawn dashed, and says it is not enough alone
        assert all(n["included"] for n in data["nodes"] if n["level"] == "solid")
        page = ui.get("/ui/campaigns/all", params={"brand_id": brand["id"]}).text
        assert "Scroll</b> to zoom" in page and "Which sites are connected" in page and 'id="graph"' in page and "203.0.113.66" in page and 'data-g="all"' in page
        _no_script_errors(page)


def test_the_page_has_the_buttons_and_shows_where_each_site_is(engine, tmp_path):
    app = _app(engine, tmp_path)
    with TestClient(app):
        c, ui = _api(app), _ui(app)
        brand, rows = _confirmed(c, app)
        page = ui.get("/ui/campaigns", params={"brand_id": brand["id"]}).text
        assert "MAP ALL" in page and "(3 left)" in page and "INVESTIGATE ALL" in page and "One map of all sites" in page
        _no_script_errors(page)
        # a batch that is running, and an investigation that is waiting for VirusTotal: the rows say so
        fid = rows["shopn0va.com"]["id"]
        with app.state.session_factory() as s:
            ws = s.get(m.Brand, uuid.UUID(brand["id"])).workspace_id
            batch = m.ScanJob(workspace_id=ws, brand_id=uuid.UUID(brand["id"]), kind="map_all", state=JobState.RUNNING,
                              payload={"finding_ids": [rows[h]["id"] for h in HOSTS]})  # fmt: skip
            intel = m.ScanJob(workspace_id=ws, brand_id=uuid.UUID(brand["id"]), kind="intel", state=JobState.RUNNING, payload={"finding_id": fid, "light": True, "package": True})
            s.add_all([batch, intel])
            s.flush()
            s.add(m.ScanEventRecord(job_id=batch.id, seq=1, stage="map_all", step="x", status="running", level="info",
                                    message="Mapping 1 of 3: shopn0va.com …", progress={"current": 0, "total": 3}, counts={}))  # fmt: skip
            s.add(m.ScanEventRecord(job_id=intel.id, seq=1, stage="intel", step="quota", status="running", level="info",
                                    message="waiting 51s for VirusTotal quota (public API: 4 requests/min)", counts={}))  # fmt: skip
            s.commit()
            batch_id, intel_id = batch.id, intel.id
        try:
            page = ui.get("/ui/campaigns", params={"brand_id": brand["id"]}).text
            assert "MAP ALL is running" in page and "Mapping 1 of 3: shopn0va.com" in page and "0 of 3 done" in page
            assert "waiting · 2 of 3" in page and "waiting · 3 of 3" in page  # its place in the batch
            assert "investigating…" in page and "waiting 51s for VirusTotal quota" in page and "after the investigation" in page
            assert 'data-active="1"' in page  # the table follows the jobs while they run
            _no_script_errors(page)
        finally:
            with app.state.session_factory() as s:
                for jid in (batch_id, intel_id):
                    s.get(m.ScanJob, jid).state = JobState.CANCELLED
                s.commit()


def _no_script_errors(html):
    import pytest

    sync = pytest.importorskip("playwright.sync_api")
    with sync.sync_playwright() as pw:
        try:
            b = pw.chromium.launch()
        except Exception as exc:  # noqa: BLE001
            pytest.skip(f"no sandboxed Chromium here: {exc}")
        page = b.new_page()
        errors: list[str] = []
        page.on("pageerror", lambda e: errors.append(str(e)))
        page.set_content(html, wait_until="domcontentloaded")
        page.wait_for_timeout(400)
        b.close()
    assert [e for e in errors if BROKEN.search(e)] == []


# ------------------------------------------------------------------------------------------ the new kinds of link
def _isolated(ip, cert, tds=None, sink=None):
    """A recorded site that shares nothing with the others except what the test gives it."""
    extra = {"dns": {"A": [ip]}, "infra": {"ip": ip, "cert_fp": cert * 64, "tracking_ids": [], "registrant": {"email": f"o{cert}@mail.example"}},
             "cloak": {}}  # fmt: skip
    from brandwatch.providers.mock.fixtures import default_store

    n = 9000000 + ord(cert)  # its own analytics id: the recorded page carries a shared one
    http = {"html": default_store().get("shopn0va.com").http["html"].replace("UA-424242-1", f"UA-{n}-1")}
    if tds:
        http["hops"] = [f"https://qemow.example/go/{tds[0]}?subid1={tds[1]}"]
        http["final_url"] = f"https://qemow.example/go/{tds[0]}?subid1={tds[1]}&tm"
    return http, extra


def test_sites_are_tied_by_the_campaign_number_of_their_traffic_link(engine, tmp_path):
    from tests.test_redirect_and_challenge import _Scenarios

    ha, ea = _isolated("198.51.100.201", "b", tds=("3115960", "map-a.com"))
    hb, eb = _isolated("198.51.100.202", "c", tds=("3115960", "map-b.com"))
    hc, ec = _isolated("198.51.100.203", "d", tds=("7000001", "map-c.com"))  # another campaign: not tied
    app = _app(engine, tmp_path)
    with _Scenarios(("shopnova-tds-a.com", "shopn0va.com", ha, ea), ("shopnova-tds-b.com", "shopn0va.com", hb, eb), ("shopnova-tds-c.com", "shopn0va.com", hc, ec)), TestClient(app):
        c = _api(app)
        brand = c.post("/api/brands", json={"name": f"Tds {uuid.uuid4().hex[:4]}", "domains": ["shopnova.com"]}).json()
        c.patch(f"/api/brands/{brand['id']}/config", json={"detection": {"auto_map_on_confirm": False, "auto_investigate_on_confirm": False}})
        job = c.post(f"/api/brands/{brand['id']}/scan-urls", json={"urls": [f"https://shopnova-tds-{x}.com/" for x in "abc"]}).json()["job_id"]
        app.state.queue.wait(uuid.UUID(job), timeout=120)
        for f in c.get("/api/findings", params={"brand_id": brand["id"]}).json():
            c.post(f"/api/findings/{f['id']}/confirm", json={"reason": "x"})
        data = c.get("/api/campaigns/all-map", params={"brand_id": brand["id"]}).json()
        grp = [g for g in data["groups"] if "shopnova-tds-a.com" in g["sites"]]
        assert grp and sorted(grp[0]["sites"]) == ["shopnova-tds-a.com", "shopnova-tds-b.com"]
        assert [lk["value"] for lk in grp[0]["links"] if lk["kind"] == "tds_campaign"] == ["qemow.example/go/3115960"]
        assert "shopnova-tds-c.com" in data["alone"]
        assert "traffic-distribution campaign" in data["headline"]


def test_cloudflare_account_dns_tokens_and_shared_servers_are_classified(session):
    from types import SimpleNamespace

    from brandwatch.detection import all_map

    assert all_map._tds_campaign("https://qemow.com/go/3115960?subid1=x", "own.com") == "qemow.com/go/3115960"
    assert all_map._tds_campaign("https://own.com/go/3115960", "own.com") is None and all_map._tds_campaign("https://x.com/about", "own.com") is None
    t = all_map._TOKEN.match("google-site-verification=AbCdEf123456_xyz")
    assert t and t.group(1) == "google-site-verification" and all_map._TOKEN.match("v=spf1 include:x ~all") is None
    assert all_map._SINK.search("credential/payment form posts to another host: https://drop.example/collect.php").group(1) == "https://drop.example/collect.php"
    assert {"cf_ns_pair", "dns_token", "tds_campaign", "data_sink"} <= set(all_map.STRONG) and "shared_ip" in all_map.WEAK
    assert SimpleNamespace  # (the end-to-end case above covers the rest)


# ------------------------------------------------------------------------------------------ one page back
def test_a_verdict_goes_back_to_the_page_the_analyst_came_from(engine, tmp_path):
    app = _app(engine, tmp_path)
    with TestClient(app):
        c, ui = _api(app), _ui(app)
        brand = c.post("/api/brands", json={"name": f"Back {uuid.uuid4().hex[:4]}", "domains": ["shopnova.com"]}).json()
        c.patch(f"/api/brands/{brand['id']}/config", json={"detection": {"auto_map_on_confirm": False, "auto_investigate_on_confirm": False}})
        job = c.post(f"/api/brands/{brand['id']}/scan-urls", json={"urls": [f"https://{h}/" for h in HOSTS]}).json()["job_id"]
        app.state.queue.wait(uuid.UUID(job), timeout=120)
        a, b, d = c.get("/api/findings", params={"brand_id": brand["id"]}).json()[:3]
        came_from = f"/ui/findings?brand_id={brand['id']}&state=open"
        page = ui.get(f"/ui/findings/{a['id']}", headers={"referer": f"http://testserver{came_from}"}).text
        assert f'name="next" value="{came_from}"' in page.replace("&amp;", "&")
        r = ui.post(f"/ui/findings/{a['id']}/verdict", data={"action": "confirm", "reason": "cloned", "next": came_from}, follow_redirects=False)
        assert r.status_code == 303 and r.headers["location"] == came_from  # back where the list was
        assert c.get(f"/api/findings/{a['id']}").json()["finding"]["state"] == "confirmed"
        # a dismissal too; without a page to go back to (or with a foreign / own address) the finding page stays
        r = ui.post(f"/ui/findings/{b['id']}/verdict", data={"action": "dismiss", "reason": "ok", "verdict": "legitimate", "next": came_from}, follow_redirects=False)
        assert r.headers["location"] == came_from
        # a referer from another site, or the finding's own page, is never offered as "back"
        page = ui.get(f"/ui/findings/{d['id']}", headers={"referer": "http://evil.example/ui/x"}).text
        assert 'name="next" value=""' in page
        page = ui.get(f"/ui/findings/{d['id']}", headers={"referer": f"http://testserver/ui/findings/{d['id']}#why"}).text
        assert 'name="next" value=""' in page
        r = ui.post(f"/ui/findings/{d['id']}/verdict", data={"action": "confirm", "reason": "x", "next": "https://evil.example/"}, follow_redirects=False)
        assert r.status_code == 303 and r.headers["location"] == f"/ui/findings/{d['id']}"


# ------------------------------------------------------------------------------------------ the pattern, and the search backwards
def test_the_pattern_of_a_group_is_described_in_plain_words():
    from datetime import date

    from brandwatch.detection import pattern as pat

    sites = [{"host": f"cryptohopper{x}.com", "registered": f"2026-10-0{i}", "signals": ["levenshtein_le_2", "favicon_exact", "cloaking_ua_based"], "tld": "com",
              "country": "Netherlands", "behind_cloudflare": i % 2 == 0, "severity": "critical"} for i, x in enumerate("lrc", 1)]
    sites.append({"host": "cryptohopper.app", "registered": "2026-05-01", "signals": ["brand_tld_swap"], "tld": "app", "country": None, "behind_cloudflare": False, "severity": "high"})
    d = pat.describe(sites, [{"kind": "cf_ns_pair"}, {"kind": "tds_campaign"}, {"kind": "ip"}], "cryptohopper")
    assert "3 of 4 domains were registered within 3 day(s)" in d["facts"][0] and "a batch" in d["facts"][0]
    assert any(f.startswith("names: 3 × a typo of the brand, 1 × the brand name on another ending of cryptohopper") for f in d["facts"])
    assert any("endings: .com (3)" in f for f in d["facts"]) and any("1 of 4 sit behind Cloudflare" in f or "2 of 4 sit behind Cloudflare" in f for f in d["facts"])
    assert any("the kit copies the brand's favicon (3/4)" in f and "shows scanners a harmless page (3/4)" in f for f in d["facts"])
    assert d["verdict"] == "3 independent kinds of link: very likely one operation" and d["timeline"][0] == {"date": "2026-05-01", "host": "cryptohopper.app"}
    assert pat.burst([date(2026, 10, 1), date(2026, 10, 2), date(2026, 11, 20)]) == (2, date(2026, 10, 1), date(2026, 10, 2))
    assert pat.describe([{"host": "a.com"}, {"host": "b.com"}], [])["verdict"] == "no strong link"


def test_the_query_and_the_domains_of_a_backwards_search():
    from brandwatch.detection import reverse_search as rs

    assert rs.query_for("tds_campaign", "qemow.com/go/3115960") == 'page.domain:qemow.com AND page.url:"go/3115960"'
    assert rs.query_for("data_sink", "drop.example") == "domain:drop.example" and rs.query_for("data_sink", "not a host") is None
    assert rs.query_for("dns_token", "google-site-verification=abcdefgh") is None and rs.query_for("cf_ns_pair", "a.ns.cloudflare.com + b.ns.cloudflare.com") is None
    hits = [{"url": "https://qemow.com/go/3115960?subid1=found-one.com&x=1", "time": "2026-10-13T07:00:00", "task_id": "t1"},
            {"url": "https://qemow.com/go/3115960?subid1=found-one.com", "time": "2026-10-12T07:00:00", "task_id": "t2"},  # the same site twice
            {"url": "https://qemow.com/go/3115960?subid1=mine.com"}, {"url": "https://qemow.com/go/3115960?subid1=not-a-domain"}]
    got = rs.extract_domains(hits, "tds_campaign", {"mine.com"})
    assert [g["domain"] for g in got] == ["found-one.com"] and got[0]["result"] == "https://urlscan.io/result/t1/"
    assert [g["domain"] for g in rs.extract_domains([{"domain": "Victim.example", "url": "https://victim.example/"}], "data_sink", set())] == ["victim.example"]


def test_search_for_more_lists_the_other_sites_of_a_campaign_and_marks_those_with_the_brands_name(engine, tmp_path):
    from tests.test_redirect_and_challenge import _Scenarios

    ha, ea = _isolated("198.51.100.211", "e", tds=("3115960", "shopnova-offers-x.com"))
    hb, eb = _isolated("198.51.100.212", "f", tds=("3115960", "plain-offers.example"))
    app = _app(engine, tmp_path)
    with _Scenarios(("shopnova-rev-a.com", "shopn0va.com", ha, ea), ("shopnova-rev-b.com", "shopn0va.com", hb, eb)), TestClient(app):
        c, ui = _api(app), _ui(app)
        brand = c.post("/api/brands", json={"name": f"Rev {uuid.uuid4().hex[:4]}", "domains": ["shopnova.com"]}).json()
        c.patch(f"/api/brands/{brand['id']}/config", json={"detection": {"auto_map_on_confirm": False, "auto_investigate_on_confirm": False}})
        job = c.post(f"/api/brands/{brand['id']}/scan-urls", json={"urls": ["https://shopnova-rev-a.com/", "https://shopnova-rev-b.com/"]}).json()["job_id"]
        app.state.queue.wait(uuid.UUID(job), timeout=120)
        for f in c.get("/api/findings", params={"brand_id": brand["id"]}).json():
            c.post(f"/api/findings/{f['id']}/confirm", json={"reason": "x"})
        before = c.get("/api/campaigns/all-map", params={"brand_id": brand["id"]}).json()
        link = next(lk for g in before["groups"] for lk in g["links"] if lk["kind"] == "tds_campaign")
        assert link["searchable"] is True and link["found"] is None and before["groups"][0]["pattern"]["summary"].startswith("2 sites")
        page = ui.get("/ui/campaigns/all", params={"brand_id": brand["id"]}).text
        assert "search for more" in page and "The pattern" in page and "very likely" not in page.split("The pattern")[0]
        r = ui.post("/ui/campaigns/reverse-search", data={"kind": "tds_campaign", "value": link["value"], "brand_id": brand["id"]}, follow_redirects=False)
        assert r.status_code == 303 and r.headers["location"].endswith("#groups")
        after = c.get("/api/campaigns/all-map", params={"brand_id": brand["id"]}).json()
        found = next(lk for g in after["groups"] for lk in g["links"] if lk["kind"] == "tds_campaign")["found"]
        domains = {s["domain"]: s["brand_related"] for s in found["sites"]}
        assert domains["shopnova-offers-x.com"] is True and domains["plain-offers.example"] is False and "unrelated-offers.example" in domains
        assert found["query"] == 'page.domain:qemow.example AND page.url:"go/3115960"'
        page = ui.get("/ui/campaigns/all", params={"brand_id": brand["id"]}).text
        assert "other site(s) found" in page and "scan the 1 that carry the brand&#39;s name" in page.replace("'", "&#39;") and "a lead, not proof" in page
        assert c.post("/api/campaigns/reverse-search", json={"kind": "dns_token", "value": "x"}).status_code == 422


def test_a_campaign_number_that_hundreds_of_unrelated_sites_use_stops_being_evidence(engine, tmp_path):
    from tests.test_redirect_and_challenge import _Scenarios

    from brandwatch.db.base import make_session_factory
    from brandwatch.detection import reverse_search as rs

    ha, ea = _isolated("198.51.100.221", "g", tds=("3115961", "x-a.example"))
    hb, eb = _isolated("198.51.100.222", "h", tds=("3115961", "x-b.example"))
    app = _app(engine, tmp_path)
    with _Scenarios(("shopnova-big-a.com", "shopn0va.com", ha, ea), ("shopnova-big-b.com", "shopn0va.com", hb, eb)), TestClient(app):
        c = _api(app)
        brand = c.post("/api/brands", json={"name": f"Big {uuid.uuid4().hex[:4]}", "domains": ["shopnova.com"]}).json()
        c.patch(f"/api/brands/{brand['id']}/config", json={"detection": {"auto_map_on_confirm": False, "auto_investigate_on_confirm": False}})
        job = c.post(f"/api/brands/{brand['id']}/scan-urls", json={"urls": ["https://shopnova-big-a.com/", "https://shopnova-big-b.com/"]}).json()["job_id"]
        app.state.queue.wait(uuid.UUID(job), timeout=120)
        for f in c.get("/api/findings", params={"brand_id": brand["id"]}).json():
            c.post(f"/api/findings/{f['id']}/confirm", json={"reason": "x"})
        first = c.get("/api/campaigns/all-map", params={"brand_id": brand["id"]}).json()
        assert any(lk["kind"] == "tds_campaign" for g in first["groups"] for lk in g["links"])  # tied, until somebody looks
        with make_session_factory(engine)() as s:
            ws = s.get(m.Brand, uuid.UUID(brand["id"])).workspace_id
            rs.store(s, ws, "tds_campaign", "qemow.example/go/3115961", {"query": "q", "total": 1986, "sites": [], "note": None})
            s.commit()
        after = c.get("/api/campaigns/all-map", params={"brand_id": brand["id"]}).json()
        assert not any(lk["kind"] == "tds_campaign" for g in after["groups"] for lk in g["links"])  # 1986 scans: an affiliate network, not one operator
        assert any(n["triage_reason"].startswith("a traffic campaign used by hundreds of unrelated sites") for n in after["nodes"] if not n["included"])


# ------------------------------------------------------------------------------------------ exclude
def test_a_kind_of_link_or_a_single_one_can_be_left_out_of_the_map(engine, tmp_path):
    app = _app(engine, tmp_path)
    with TestClient(app):
        c, ui = _api(app), _ui(app)
        brand, rows = _confirmed(c, app)
        q = {"brand_id": brand["id"]}
        full = c.get("/api/campaigns/all-map", params=q).json()
        strong_kinds = sorted({lk["kind"] for g in full["groups"] for lk in g["links"]})
        assert "ip" in strong_kinds and "certificate" in strong_kinds
        chips = {k["kind"]: k for k in full["kinds"]}
        assert chips["ip"]["count"] >= 1 and chips["ip"]["excluded"] is False and chips["ip"]["strong"] is True
        try:
            # one value: that server only
            r = c.post("/api/campaigns/map-exclude", json={"kind": "ip", "value": "203.0.113.66"})
            assert r.status_code == 200 and r.json()["items"] == [{"kind": "ip", "value": "203.0.113.66"}]
            one = c.get("/api/campaigns/all-map", params=q).json()
            assert not any(lk["kind"] == "ip" and lk["value"] == "203.0.113.66" for g in one["groups"] for lk in g["links"])
            assert any(x["kind"] == "ip" and x["value"] == "203.0.113.66" and x["by"] == "item" for x in one["excluded"])
            assert one["groups"], "the sites are still tied by their certificate, analytics id and registrant"
            # a whole kind, through the page's button
            for kind in strong_kinds:
                r = ui.post("/ui/campaigns/map-exclude", data={"kind": kind, "exclude": "1", "brand_id": brand["id"]}, follow_redirects=False)
                assert r.status_code == 303 and r.headers["location"].endswith("#groups") and "re=out:" in r.headers["location"]
            none = c.get("/api/campaigns/all-map", params=q).json()
            assert none["groups"] == [] and sorted(none["alone"]) == sorted(HOSTS) and none["stats"]["strong_links"] == 0
            assert all(k["excluded"] for k in none["kinds"] if k["kind"] in strong_kinds)
            assert "no strong link" in none["headline"] or "nothing strong ties" in none["headline"]
            page = ui.get("/ui/campaigns/all", params=q).text
            assert "What counts as a connection" in page and "switched off: click to count it again" in page and "Left out:" in page
            assert c.post("/api/campaigns/map-exclude", json={"kind": "nonsense"}).status_code == 422
        finally:  # the test database is shared: put everything back
            for kind in strong_kinds:
                c.post("/api/campaigns/map-exclude", json={"kind": kind, "exclude": False})
            c.post("/api/campaigns/map-exclude", json={"kind": "ip", "value": "203.0.113.66", "exclude": False})
        back = c.get("/api/campaigns/all-map", params=q).json()
        assert back["groups"] and back["excluded"] == []
        page = ui.get("/ui/campaigns/all", params={**q, "re": "out:3:1:9:4:the%20same%20server"}).text
        assert "Analysed again." in page and "3 → 1" in page and "9 → 4" in page  # what the new analysis found, said plainly
        assert "✕ not evidence" in page and 'id="analysing"' in page and "show only this group on the map" in page  # one red button per link, in its own column
        assert any(set(n["groups"]) <= {0, 1, 2, 3} for n in back["nodes"]) and all("groups" in n and "label" in n for n in back["nodes"])  # the group filter has what it needs


# ------------------------------------------------------------------------------------------ the globe's arcs in live mode
def test_the_globe_starts_its_arcs_at_the_brands_own_site_when_no_home_is_configured(session, monkeypatch):
    import socket
    from types import SimpleNamespace

    from tests.conftest import make_brand, make_workspace

    from brandwatch.api import dashboard

    ws = make_workspace(session, f"home-{uuid.uuid4().hex[:6]}")
    b = make_brand(session, ws, "Acme")
    session.add(m.BrandDomain(brand_id=b.id, domain="acme-home.example", is_official=True, kind="official"))
    session.flush()
    calls = []

    async def locate(ip):
        calls.append(ip)
        return SimpleNamespace(ok=True, data={"lat": 52.37, "lon": 4.9, "city": "Amsterdam", "country": "NL"})

    req = SimpleNamespace(app=SimpleNamespace(state=SimpleNamespace(providers=SimpleNamespace(geo=lambda: SimpleNamespace(locate=locate)))))
    monkeypatch.setattr(socket, "getaddrinfo", lambda *a, **k: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("198.51.100.9", 443))])
    dashboard._HOME_CACHE.clear()
    points = [{"hostname": "x"}]
    home = dashboard._brand_home(session, req, [b.id], points)
    assert home == {"label": "Acme · Amsterdam", "lat": 52.37, "lon": 4.9} and calls == ["198.51.100.9"]
    assert dashboard._brand_home(session, req, [b.id], points) == home and calls == ["198.51.100.9"]  # cached: one lookup
    assert dashboard._brand_home(session, req, [b.id], []) is None  # no attacks, no arcs to draw
    dashboard._HOME_CACHE.clear()
    monkeypatch.setattr(socket, "getaddrinfo", lambda *a, **k: (_ for _ in ()).throw(OSError("no dns")))
    assert dashboard._brand_home(session, req, [b.id], points) is None  # an unreachable site is not an error


def test_an_investigation_never_holds_the_database_lock_while_it_waits(engine, tmp_path, monkeypatch):
    # three investigations at once, each waiting minutes for the shared quota, used to hold an open write transaction and kill each other
    # with "database is locked". Every event they write is committed at once.
    from brandwatch.events.emitter import ScanEventEmitter

    seen: list[bool] = []
    orig = ScanEventEmitter.__init__

    def spy(self, *a, **kw):
        seen.append(bool(kw.get("commit")))
        orig(self, *a, **kw)

    monkeypatch.setattr(ScanEventEmitter, "__init__", spy)
    app = _app(engine, tmp_path)
    with TestClient(app):
        c = _api(app)
        brand, rows = _confirmed(c, app)
        f = next(iter(rows.values()))
        seen.clear()
        j1 = c.post(f"/api/findings/{f['id']}/intel").json()["job_id"]
        app.state.queue.wait(uuid.UUID(j1), timeout=200)
        j2 = c.post(f"/api/findings/{f['id']}/investigate").json()["job_id"]
        app.state.queue.wait(uuid.UUID(j2), timeout=200)
        assert seen and all(seen), seen


def test_the_map_can_be_zoomed_moved_and_limited_to_one_group_in_a_real_browser(engine, tmp_path):
    import pytest

    sync = pytest.importorskip("playwright.sync_api")
    app = _app(engine, tmp_path)
    with TestClient(app):
        c, ui = _api(app), _ui(app)
        brand, _rows = _confirmed(c, app)
        html = ui.get("/ui/campaigns/all", params={"brand_id": brand["id"]}).text
    with sync.sync_playwright() as pw:
        try:
            b = pw.chromium.launch()
        except Exception as exc:  # noqa: BLE001
            pytest.skip(f"no sandboxed Chromium here: {exc}")
        page = b.new_page(viewport={"width": 1280, "height": 900})
        errors: list[str] = []
        page.on("pageerror", lambda e: errors.append(str(e)))
        page.set_content(html, wait_until="domcontentloaded")
        page.wait_for_timeout(500)
        total = page.evaluate("document.querySelectorAll('#graph circle:not(.halo)').length")
        assert total >= 4 and page.evaluate("document.querySelectorAll('#graph line').length") >= 2  # things shared by the same sites are one dot with one line per site
        start = page.evaluate("document.querySelector('#graph > g').getAttribute('transform')")  # the map, fitted to the canvas
        page.locator("#graph").scroll_into_view_if_needed()
        box = page.locator("#graph").bounding_box()
        page.mouse.move(box["x"] + box["width"] / 2, box["y"] + box["height"] / 2)
        page.mouse.wheel(0, -300)  # scroll up: zoom in
        page.wait_for_timeout(200)
        assert page.evaluate("document.querySelector('#graph > g').getAttribute('transform')") != start
        page.mouse.move(box["x"] + 30, box["y"] + 30)  # drag the background: the map moves
        before = page.evaluate("document.querySelector('#graph > g').getAttribute('transform')")
        page.mouse.down()
        page.mouse.move(box["x"] + 130, box["y"] + 90, steps=4)
        page.mouse.up()
        assert page.evaluate("document.querySelector('#graph > g').getAttribute('transform')") != before
        page.click("text=reset view")
        assert page.evaluate("document.querySelector('#graph > g').getAttribute('transform')") == start
        page.click("#gsel button[data-g='1']")  # only group 1
        page.wait_for_timeout(300)
        assert page.evaluate("document.querySelector('#gsel button.on').dataset.g") == "1"
        assert page.evaluate("document.querySelectorAll('#graph circle:not(.halo)').length") <= total
        page.click("#gsel button[data-g='all']")
        assert page.evaluate("document.querySelectorAll('#graph circle:not(.halo)').length") == total
        # taking a link out says that it is analysing again
        page.evaluate("document.querySelector('#kinds form.xf').addEventListener('submit', e => e.preventDefault())")
        page.click("#kinds form.xf button")
        assert page.evaluate("getComputedStyle(document.getElementById('analysing')).display") == "flex"
        b.close()
    from tests.test_pages_js import BROKEN

    assert [e for e in errors if BROKEN.search(e)] == []
