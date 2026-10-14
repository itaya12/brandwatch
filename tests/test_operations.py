"""The map of all sites finds the attacker, not only the shared things.

The real-world case that started it: 8 typo domains forward visitors to the real shop with the same affiliate id (``?atid=70321``) through
the same short-link host. The old map tied 6 of them by AWS addresses, left 2 out, and called two CDN addresses and a privacy
placeholder "strong". Now every kind of link has a weight, hints add up, a CDN is no evidence, and each group is an operation with
a name, what it does, its toolkit and the shortest way to stop it.
"""

from __future__ import annotations

import uuid

from fastapi.testclient import TestClient
from tests.test_demo_story import _api, _app, _ui
from tests.test_map_all import _no_script_errors
from tests.test_redirect_and_challenge import _Scenarios

from brandwatch.detection import all_map, hosting, operations
from brandwatch.detection import reverse_search as rs
from brandwatch.detection.whois_history import is_private
from brandwatch.providers.mock.fixtures import default_store


# ------------------------------------------------------------------------------------------ what kind of network
def test_a_network_is_a_cdn_a_cloud_a_hoster_or_unknown():
    assert hosting.classify("AWS CloudFront (GLOBAL)") == "cdn" and hosting.classify("Cloudflare, Inc.") == "cdn"
    assert hosting.classify("AWS EC2 (us-west-1)") == "cloud" and hosting.classify("Hetzner Online GmbH") == "cloud"
    assert hosting.classify("Akamai Connected Cloud") == "cloud" and hosting.classify("Akamai Technologies") == "cdn"
    assert hosting.classify("Gransy s.r.o") == "hoster" and hosting.classify("Alexhost SRL") == "hoster"
    assert hosting.classify(None) == "unknown" and hosting.classify("") == "unknown"
    assert hosting.ip_class(None, uuid.uuid4(), "not-an-ip") == ("unknown", None)  # type: ignore[arg-type]


def test_the_cloudflare_registrar_contact_is_a_privacy_placeholder():
    assert is_private("domaincontact-cloudflareregistrar-com@cloudflareregistrar.com")
    assert is_private("Data Redacted") and is_private("REDACTED FOR PRIVACY")
    assert not is_private("owner@evil-kit.example")


# ------------------------------------------------------------------------------------------ weights
def test_hints_add_up_but_the_same_kind_twice_is_one_and_weak_kinds_never_join():
    pc = all_map.pair_confidence
    assert pc({"affiliate_id": 0.95}) >= all_map.JOIN and pc({"ip": 0.8}) >= all_map.JOIN and pc({"tds_campaign": 0.8}) >= all_map.JOIN
    assert pc({"redirector": 0.6}) < all_map.JOIN  # a redirect host alone is a hint
    assert pc({"redirector": 0.6, "batch": 0.3}) < all_map.JOIN  # two hints that are both common: still not one operation
    assert pc({"redirector": 0.6, "past_ip": 0.5}) >= all_map.JOIN  # a redirect host and a server both once used: yes
    assert abs(pc({"a": 0.5, "b": 0.5}) - 0.75) < 1e-9
    assert all_map.level(0.95) == "solid" and all_map.level(0.6) == "possible" and all_map.level(0.1) == "weak"
    assert all_map.weight({"kind": "ip", "cls": "hoster"}) == 0.8 and all_map.weight({"kind": "ip", "cls": "cloud"}) == 0.5
    assert all_map.weight({"kind": "ip", "cls": "unknown"}) == 0.5  # nobody has looked the network up: not proof
    assert all_map.weight({"kind": "redirector", "common": True}) == 0.1 and all_map.weight({"kind": "redirector"}) == 0.6
    assert set(all_map.WEAK).isdisjoint(all_map.STRONG) and set(all_map.ORDER) == set(all_map.LABEL)


def test_an_affiliate_id_is_read_from_links_to_the_brands_own_site_only():
    own = {"shopnova.com"}
    chain = ["https://shopnva.com/", "https://www.shopnova.com/?atid=70321&utm_source=x", "https://www.shopnova.com/"]
    assert all_map._affiliate_ids(chain, own, "shopnva.com") == ["atid=70321"]
    assert all_map._affiliate_ids(["https://other.example/?atid=1234567"], own, "x.com") == []  # not the brand's site: not an affiliate link
    assert all_map._affiliate_ids(["https://www.shopnova.com/?ref=shopnva.com"], own, "shopnva.com") == []  # the id is the site itself
    assert all_map._affiliate_ids(["https://www.shopnova.com/?a=1"], own, "x.com") == []


def test_a_screenshot_hash_within_a_few_bits_looks_the_same():
    assert all_map._hamming("da678b352ac96389", "da678b352ac96389") == 0
    assert all_map._hamming("da678b352ac96389", "da658b342acf6389") <= all_map.PHASH_BITS
    assert all_map._hamming("da678b352ac96389", "25987ccad53c9c76") > all_map.PHASH_BITS and all_map._hamming("zz", "00") == 64


# ------------------------------------------------------------------------------------------ operations
def _site(host, **kw):
    base = {"host": host, "severity": "critical", "brand": "Shop", "registered": "2021-06-03", "signals": ["levenshtein_le_2", "favicon_exact"], "registrar": "Dynadot Inc",
            "hosting": [{"ip": "1.1.1.1", "cls": "cloud", "org": "Amazon.com, Inc."}], "nameservers": [], "issuer": None, "affiliate": [], "redirectors": [],
            "forwards_to_brand": False, "parked": False, "sink": None, "tld": "com"}
    return {**base, **kw}


def _group(sites, links):
    return {"sites": [s["host"] for s in sites], "size": len(sites), "confidence": 0.99, "index": 1, "links": links, "also": [],
            "pattern": {"facts": ["registered over 3 days"], "summary": "", "verdict": "", "timeline": [], "when": None, "link_kinds": []}}


def _link(kind, value, sites, w=0.95, lvl="solid"):
    return {"kind": kind, "label": all_map.LABEL[kind], "value": value, "sites": sorted(sites), "weight": w, "level": lvl, "network": None, "class": None}


def test_eight_typo_domains_with_one_affiliate_id_are_one_affiliate_fraud_operation():
    sites = {f"shop{i}.com": _site(f"shop{i}.com", affiliate=["atid=70321"], forwards_to_brand=True, redirectors=["trackz.example"]) for i in range(8)}
    hosts = sorted(sites)
    g = _group([sites[h] for h in hosts], [_link("affiliate_id", "atid=70321", hosts), _link("redirector", "trackz.example", hosts, 0.6, "possible")])
    operations.enrich(g, sites)
    assert g["behaviour"]["key"] == "affiliate_fraud" and g["behaviour"]["icon"] == "$"
    assert g["name"] == "Affiliate atid=70321 · via trackz.example" and g["level"] == "certain"
    assert g["story"].startswith("Each of the 8 domains sends visitors to the real site with an affiliate id")
    assert "8/8 forward to the brand's own site with ?atid=70321" in g["story"]
    titles = [s["title"] for s in g["stop"]]
    assert titles[0] == "Ask Shop's affiliate team to ban atid=70321" and "Report the redirect host trackz.example" in titles
    assert "One bulk abuse report to Dynadot Inc" in titles and "Report the hosting provider Amazon.com, Inc." in titles
    assert all(len(s["targets"]) == 8 for s in g["stop"])  # one report reaches all eight
    assert g["toolkit"]["registrars"] == [{"name": "Dynadot Inc", "count": 8}] and g["toolkit"]["redirectors"] == [{"name": "trackz.example", "count": 8}]
    assert g["matrix"]["kinds"] == ["affiliate_id", "redirector"] and g["matrix"]["rows"][0]["cells"]["affiliate_id"] == ["atid=70321"]
    assert g["report_md"].startswith("## Affiliate atid=70321") and "atid=70321" in g["report_md"] and "How to stop it" in g["report_md"]


def test_what_a_site_does_is_decided_by_the_first_rule_that_fits_and_says_why():
    b = operations.behaviour
    assert b([_site("a.com", signals=["clickfix_lure"])], [])["key"] == "malware_lure"
    cred = b([_site("a.com", signals=["credential_form"]), _site("b.com", signals=["payment_form"])], [])
    assert cred["key"] == "credential_phishing" and "credential form" in cred["why"][0]
    assert b([_site("a.com"), _site("b.com")], [{"kind": "data_sink"}])["key"] == "credential_phishing"
    assert b([_site("a.com", redirectors=["go.example"])], [])["key"] == "traffic_funnel"
    assert b([_site("a.com", parked=True)], [])["key"] == "parked"
    assert b([_site("a.com", signals=["looks_like_brand_ge_85"])], [])["key"] == "clone"
    plain = b([_site("a.com", signals=["levenshtein_le_2"])], [])
    assert plain["key"] == "lookalike" and plain["label"] == "Look-alike domains"
    assert operations.PARKING.search("forsale.godaddy.com") and operations.PARKING.search("www.dan.com") and not operations.PARKING.search("godaddy.com")


def test_without_a_shared_party_the_advice_is_to_report_each_domain():
    sites = {"a.com": _site("a.com", registrar=None, hosting=[]), "b.com": _site("b.com", registrar=None, hosting=[])}
    g = _group(list(sites.values()), [_link("tracking_id", "UA-1-1", ["a.com", "b.com"], 0.9)])
    operations.enrich(g, sites)
    assert [s["title"] for s in g["stop"]] == ["Report each domain on its own"]


def test_the_timeline_puts_every_operation_on_one_axis_and_rings_the_waves():
    sites = {h: _site(h, registered=d) for h, d in {"a.com": "2021-06-03", "b.com": "2021-06-04", "c.com": "2022-01-01", "d.com": "2026-04-13", "e.com": "1990-03-29"}.items()}
    linked = [{"index": 1, "name": "Op one", "sites": ["a.com", "b.com", "c.com"]}]
    lane = all_map._swimlane(linked, ["d.com", "e.com"], sites)
    assert [r["label"] for r in lane["rows"]] == ["Op one", "No strong link"]
    first = {d["host"]: d for d in lane["rows"][0]["dots"]}
    assert first["a.com"]["wave"] and first["b.com"]["wave"] and not first["c.com"]["wave"]  # bought a day apart: a wave
    assert first["a.com"]["x"] == 0 and 0 < first["c.com"]["x"] < 100 and lane["rows"][1]["dots"][0]["host"] == "d.com" and lane["rows"][1]["dots"][0]["x"] == 100
    assert all(d["host"] != "e.com" for r in lane["rows"] for d in r["dots"])  # a WHOIS date before 1995 is a social page's, not a domain's
    assert all_map._swimlane([], [], {}) == {"rows": [], "ticks": []}


def test_the_new_kinds_of_link_can_be_searched_backwards():
    assert {"affiliate_id", "redirector"} <= set(rs.SEARCHABLE)
    assert rs.query_for("affiliate_id", "atid=70321") == 'page.url:"atid=70321"' and rs.query_for("affiliate_id", 'x" OR "y') is None
    assert rs.query_for("redirector", "trackz.example") == "page.domain:trackz.example" and rs.query_for("redirector", "not a host") is None
    hits = [{"url": "https://www.shop.com/?atid=1", "domain": "www.shop.com", "task_domain": "shopp.com", "task_id": "t"}, {"url": "https://x/", "domain": "mine.com", "task_domain": "mine.com"}]
    got = rs.extract_domains(hits, "affiliate_id", {"mine.com"})
    assert [g["domain"] for g in got] == ["shopp.com"]  # the site that was scanned, which led to the link


# ------------------------------------------------------------------------------------------ end to end
def _affiliate(ip, cert, atid, redirect):
    extra = {"dns": {"A": [ip]}, "infra": {"ip": ip, "cert_fp": cert * 64, "tracking_ids": [], "registrant": {"email": f"o{cert}@mail.example"}}, "cloak": {}}
    n = 9100000 + ord(cert)  # its own analytics id: the recorded page carries a shared one
    http = {"html": default_store().get("shopn0va.com").http["html"].replace("UA-424242-1", f"UA-{n}-1"),
            "hops": [f"https://www.shopnova.com/?atid={atid}"], "final_url": f"https://{redirect}/x{cert}"}
    return http, extra


def test_the_page_names_the_operation_behind_sites_that_share_an_affiliate_id(engine, tmp_path):
    ha, ea = _affiliate("198.51.100.231", "k", "70321", "trackz.example")
    hb, eb = _affiliate("198.51.100.232", "l", "70321", "trackz.example")
    hc, ec = _affiliate("198.51.100.233", "n", "77777", "other-short.example")  # another affiliate on another redirect host
    app = _app(engine, tmp_path)
    with _Scenarios(("shopnova-aff-a.com", "shopn0va.com", ha, ea), ("shopnova-aff-b.com", "shopn0va.com", hb, eb), ("shopnova-aff-c.com", "shopn0va.com", hc, ec)), TestClient(app):
        c, ui = _api(app), _ui(app)
        brand = c.post("/api/brands", json={"name": f"Aff {uuid.uuid4().hex[:4]}", "domains": ["shopnova.com"]}).json()
        c.patch(f"/api/brands/{brand['id']}/config", json={"detection": {"auto_map_on_confirm": False, "auto_investigate_on_confirm": False}})
        job = c.post(f"/api/brands/{brand['id']}/scan-urls", json={"urls": [f"https://shopnova-aff-{x}.com/" for x in "abc"]}).json()["job_id"]
        app.state.queue.wait(uuid.UUID(job), timeout=120)
        for f in c.get("/api/findings", params={"brand_id": brand["id"]}).json():
            c.post(f"/api/findings/{f['id']}/confirm", json={"reason": "x"})
        data = c.get("/api/campaigns/all-map", params={"brand_id": brand["id"]}).json()
        op = next(g for g in data["operations"] if "shopnova-aff-a.com" in g["sites"])
        assert sorted(op["sites"]) == ["shopnova-aff-a.com", "shopnova-aff-b.com"] and op["behaviour"]["key"] == "affiliate_fraud"  # the page it ends on is the brand's own: its login form is not a kit
        link = next(lk for lk in op["links"] if lk["kind"] == "affiliate_id")
        assert link["value"] == "atid=70321" and link["weight"] == 0.95 and link["level"] == "solid" and link["searchable"] is True
        assert op["name"].startswith("Affiliate atid=70321") and op["stop"][0]["title"].startswith("Ask ") and "ban atid=70321" in op["stop"][0]["title"]
        assert any(lk["kind"] == "redirector" and lk["value"] == "trackz.example" and lk["level"] == "possible" for lk in op["links"])
        assert "shopnova-aff-c.com" in data["alone"]  # its own affiliate id and its own redirect host: not tied
        assert data["alone_info"]["shopnova-aff-c.com"]["key"] in ("affiliate_fraud", "traffic_funnel", "credential_phishing")
        assert data["operations"] is not None and data["groups"][0]["name"] == data["operations"][0]["name"]
        assert data["swimlane"]["rows"] and data["stats"]["operations"] == data["stats"]["groups"] == len(data["operations"])
        assert any(n["kind"] == "affiliate_id" and n["level"] == "solid" and n["groups"] == [op["index"]] for n in data["nodes"])
        assert any(n["kind"] == "site" and n["detail"]["operation"] == op["name"] and n["detail"]["affiliate"] == ["atid=70321"] for n in data["nodes"])
        assert any(k["kind"] == "redirector" and k["strength"] == "hint" for k in data["kinds"])
        page = ui.get("/ui/campaigns/all", params={"brand_id": brand["id"]}).text
        assert "ban atid=70321" in page and ("Analysis not finished" in page or "Analysis complete" in page)
        assert "How to stop it" in page and "copy report" in page and "show hints" in page and all(f'data-v="{v}"' in page for v in ("graph", "connections", "matrix", "flow", "timeline")) and 'data-v="pivot"' not in page
        _no_script_errors(page)


def test_a_social_page_is_not_infrastructure(engine, tmp_path):
    app = _app(engine, tmp_path)
    with TestClient(app):
        c = _api(app)
        data = c.get("/api/campaigns/all-map").json()
        assert "social" in data and all("/" not in s["host"] for s in data["sites"])
        assert data["stats"]["social"] == len(data["social"])


def test_the_full_report_lists_which_sites_share_which_server_and_every_other_thing():
    hosts = [f"shop{i}.com" for i in range(5)]
    sites = {h: _site(h, hosting=[{"ip": "10.0.0.1" if i < 3 else "10.0.0.2", "cls": "cloud", "org": "Amazon.com, Inc."}], nameservers=["ns1.dyna-ns.net"], final="trackz.example")
             for i, h in enumerate(hosts)}
    links = [_link("ip", "10.0.0.1", hosts[:3], 0.5, "possible"), _link("ip", "10.0.0.2", hosts[3:], 0.5, "possible"), _link("registrant", "bad@kit.example", hosts, 0.9)]
    links[0]["network"] = "Amazon.com, Inc."
    g = _group([sites[h] for h in hosts], links)
    g["also"] = [{**_link("nameserver", "ns1.dyna-ns.net", hosts, 0.1, "weak")}, {**_link("registrar", "Dynadot Inc", hosts, 0.1, "weak")}]
    operations.enrich(g, sites)
    det = g["detail"]
    assert det["summary"] == "3 of the 5 sites are on one server"
    assert [s["title"] for s in det["sections"]] == ["Same server (address)", "Registrants", "Name servers", "Registrars"]  # the servers come first
    servers = det["sections"][0]["rows"]
    assert servers[0] == {"value": "10.0.0.1", "sites": hosts[:3], "network": "Amazon.com, Inc.", "class": None, "weight": 0.5, "level": "possible"} and servers[1]["sites"] == hosts[3:]
    assert [s["host"] for s in det["sites"]] == hosts and det["sites"][0]["ips"] == ["10.0.0.1"] and det["sites"][4]["ips"] == ["10.0.0.2"]
    assert det["sites"][0]["hosting"] == ["Amazon.com, Inc. (cloud)"] and det["sites"][0]["ends_on"] == "trackz.example"
    md = g["report_md"]
    assert "### Who shares what (3 of the 5 sites are on one server)" in md and "**Same server (address)**" in md
    assert "- `10.0.0.1` · Amazon.com, Inc. · 3 sites: shop0.com, shop1.com, shop2.com" in md and "### Site by site" in md
    assert "- **shop0.com**: critical; registered 2021-06-03; registrar Dynadot Inc; server 10.0.0.1; hosting Amazon.com, Inc. (cloud); name servers ns1.dyna-ns.net; ends on trackz.example" in md
    lone = {"a.com": _site("a.com"), "b.com": _site("b.com", hosting=[{"ip": "10.9.9.9", "cls": "hoster", "org": None}])}
    g2 = _group(list(lone.values()), [_link("tracking_id", "UA-1-1", ["a.com", "b.com"], 0.9)])
    operations.enrich(g2, lone)
    assert g2["detail"]["summary"] == "no two of these sites were seen on the same server"


def test_many_links_between_the_same_sites_read_as_one_cluster_and_a_grid_says_who_is_with_whom(engine, tmp_path):
    ha, ea = _affiliate("198.51.100.241", "p", "55555", "trackz.example")
    hb, eb = _affiliate("198.51.100.242", "q", "55555", "trackz.example")
    app = _app(engine, tmp_path)
    with _Scenarios(("shopnova-cl-a.com", "shopn0va.com", ha, ea), ("shopnova-cl-b.com", "shopn0va.com", hb, eb)), TestClient(app):
        c, ui = _api(app), _ui(app)
        brand = c.post("/api/brands", json={"name": f"Cl {uuid.uuid4().hex[:4]}", "domains": ["shopnova.com"]}).json()
        c.patch(f"/api/brands/{brand['id']}/config", json={"detection": {"auto_map_on_confirm": False, "auto_investigate_on_confirm": False}})
        job = c.post(f"/api/brands/{brand['id']}/scan-urls", json={"urls": ["https://shopnova-cl-a.com/", "https://shopnova-cl-b.com/"]}).json()["job_id"]
        app.state.queue.wait(uuid.UUID(job), timeout=120)
        for f in c.get("/api/findings", params={"brand_id": brand["id"]}).json():
            c.post(f"/api/findings/{f['id']}/confirm", json={"reason": "x"})
        data = c.get("/api/campaigns/all-map", params={"brand_id": brand["id"]}).json()
        op = data["operations"][0]
        assert len(op["clusters"]) == 1 and op["clusters"][0]["sites"] == ["shopnova-cl-a.com", "shopnova-cl-b.com"]  # everything they share is one line
        kinds = {k["kind"]: k for k in op["clusters"][0]["by_kind"]}
        assert kinds["affiliate_id"]["vals"] == ["atid=55555"] and kinds["affiliate_id"]["label"] == "affiliate" and kinds["redirector"]["level"] == "possible"
        assert [k["kind"] for k in op["clusters"][0]["by_kind"]][0] == "affiliate_id"  # the strongest first
        grid = op["grid"]
        assert grid["hosts"] == ["shopnova-cl-a.com", "shopnova-cl-b.com"] and grid["cells"][0][0] is None and grid["cells"][1][1] is None
        cell = grid["cells"][0][1]
        assert cell == grid["cells"][1][0] and cell["conf"] >= 0.95 and "affiliate_id" in cell["kinds"]
        page = ui.get("/ui/campaigns/all", params={"brand_id": brand["id"]}).text
        assert "Who is with whom" in page and "Who against whom" in page and 'class="grid"' in page and "share exactly the same things" in page
        _no_script_errors(page)


def test_an_operation_has_a_standalone_html_report_with_every_table(engine, tmp_path):
    ha, ea = _affiliate("198.51.100.251", "r", "66666", "trackz.example")
    hb, eb = _affiliate("198.51.100.252", "s", "66666", "trackz.example")
    app = _app(engine, tmp_path)
    with _Scenarios(("shopnova-rp-a.com", "shopn0va.com", ha, ea), ("shopnova-rp-b.com", "shopn0va.com", hb, eb)), TestClient(app):
        c, ui = _api(app), _ui(app)
        brand = c.post("/api/brands", json={"name": f"Rp {uuid.uuid4().hex[:4]}", "domains": ["shopnova.com"]}).json()
        c.patch(f"/api/brands/{brand['id']}/config", json={"detection": {"auto_map_on_confirm": False, "auto_investigate_on_confirm": False}})
        job = c.post(f"/api/brands/{brand['id']}/scan-urls", json={"urls": ["https://shopnova-rp-a.com/", "https://shopnova-rp-b.com/"]}).json()["job_id"]
        app.state.queue.wait(uuid.UUID(job), timeout=120)
        for f in c.get("/api/findings", params={"brand_id": brand["id"]}).json():
            c.post(f"/api/findings/{f['id']}/confirm", json={"reason": "x"})
        q = {"brand_id": brand["id"], "group": 1}
        page = ui.get("/ui/campaigns/all", params={"brand_id": brand["id"]}).text
        assert f"/ui/campaigns/operation-report?group=1&brand_id={brand['id']}" in page.replace("&amp;", "&") and "HTML report" in page and "download .html" in page
        r = ui.get("/ui/campaigns/operation-report", params=q)
        assert r.status_code == 200 and r.headers["content-type"].startswith("text/html") and "attachment" not in r.headers.get("content-disposition", "")
        html = r.text
        for must in ("operation report", "How to stop it", "The sites", "Who is with whom", "Who against whom", "Who shares what", "Toolkit", "Evidence per site",
                     "atid=66666", "shopnova-rp-a.com", "shopnova-rp-b.com", "Print / save as PDF", "@media print", "When the domains were registered"):
            assert must in html, must
        assert "<script src" not in html and "http://" not in html.replace("http://www.w3.org", "") and "https://fonts" not in html  # one self-contained file
        d = ui.get("/ui/campaigns/operation-report", params={**q, "download": 1})
        assert d.headers["content-disposition"].startswith('attachment; filename="operation-1-') and d.headers["content-disposition"].endswith('.html"')
        assert ui.get("/ui/campaigns/operation-report", params={"brand_id": brand["id"], "group": 99}).status_code == 404
        _no_script_errors(html)


def test_the_map_has_five_views_that_zoom_and_every_card_section_is_a_drop_down(engine, tmp_path):
    import pytest
    from tests.test_map_all import _confirmed

    sync = pytest.importorskip("playwright.sync_api")
    app = _app(engine, tmp_path)
    with TestClient(app):
        c, ui = _api(app), _ui(app)
        brand, _rows = _confirmed(c, app)
        data = c.get("/api/campaigns/all-map", params={"brand_id": brand["id"]}).json()
        v = data["views"]
        assert v["order"] == [s["host"] for s in v["sites"]] and {s["op"] for s in v["sites"]} <= {0, 1, 2, 3}
        assert all(p["conf"] >= all_map.POSSIBLE and p["a"] < p["b"] for p in v["pairs"]) and v["pairs"]
        assert v["flow"]["columns"] == ["Registrar", "Hosting", "Redirect via", "Operation"] and len(v["flow"]["rows"]) == len(v["order"])
        assert all(len(r["vals"]) == 4 for r in v["flow"]["rows"]) and "ip" in v["pivot"] and v["pivot"]["ip"]["rows"][0]["sites"]
        assert data["operations"][0]["basis"] and data["operations"][0]["basis"][0]["weight"] >= data["operations"][0]["basis"][-1]["weight"]
        html = ui.get("/ui/campaigns/all", params={"brand_id": brand["id"]}).text
    assert "Because" in html and "First step:" in html and 'id="expall"' in html and 'class="cnt"' in html
    head = html.split('<details class="sec">')[0]
    assert head.index("Because") < head.index("First step:") and "<details class=\"sec\" open>" not in html  # confidence and why first; every section starts closed
    with sync.sync_playwright() as pw:
        try:
            b = pw.chromium.launch()
        except Exception as exc:  # noqa: BLE001
            pytest.skip(f"no sandboxed Chromium here: {exc}")
        page = b.new_page(viewport={"width": 1280, "height": 900})
        errors: list[str] = []
        page.on("pageerror", lambda e: errors.append(str(e)))
        page.set_content(html, wait_until="domcontentloaded")
        page.wait_for_timeout(400)
        assert page.evaluate("document.querySelector('#vsw button.on').dataset.v") == "graph"  # 3 sites: the graph is the suggested view
        assert page.evaluate("[...document.querySelectorAll('#vsw button')].map(b => b.dataset.v)") == ["graph", "connections", "matrix", "flow", "timeline"]
        assert page.evaluate("[...document.querySelectorAll('.vw')].filter(v => !v.hidden).map(v => v.id)") == ["view-graph"]
        for name in ("connections", "matrix", "flow", "timeline", "graph"):
            page.click(f"#vsw button[data-v='{name}']")
            page.wait_for_timeout(150)
            assert page.evaluate("[...document.querySelectorAll('.vw')].filter(v => !v.hidden).map(v => v.id)") == [f"view-{name}"]
        # Connections: what is shared on the left, the sites on the right, a line for each "has"
        page.click("#vsw button[data-v='connections']")
        assert page.evaluate("document.querySelectorAll('#view-connections g.th').length") >= 1 and page.evaluate("document.querySelectorAll('#view-connections g.st').length") >= 2
        assert page.evaluate("document.querySelectorAll('#view-connections path.ln').length") >= 2
        page.click("#view-connections g.th")
        assert "shared by" in page.inner_text("#cn-info")
        vb = page.evaluate("document.querySelector('#view-connections svg').getAttribute('viewBox')")
        page.click("#view-connections [data-z='in']")
        assert page.evaluate("document.querySelector('#view-connections svg').getAttribute('viewBox')") != vb  # it zooms
        page.click("#view-connections [data-z='fit']")
        assert page.evaluate("document.querySelector('#view-connections svg').getAttribute('viewBox')") == vb
        # Matrix: a row per site, a column per shared thing
        page.click("#vsw button[data-v='matrix']")
        rows, cols = page.evaluate("document.querySelectorAll('#view-matrix g.mrow').length"), page.evaluate("document.querySelectorAll('#view-matrix rect.mc').length")
        assert rows >= 2 and cols % rows == 0 and cols >= rows
        page.hover("#view-matrix rect.mc")
        assert "has" in page.inner_text("#mx-info")
        # Flow: site -> registrar -> hosting -> redirect host -> operation
        page.click("#vsw button[data-v='flow']")
        text = page.inner_text("#view-flow")
        assert all(c in text for c in ("SITE", "REGISTRAR", "HOSTING", "REDIRECT VIA", "OPERATION")) and page.evaluate("document.querySelectorAll('#view-flow path.ln').length") >= 4
        # Timeline: the time axis zooms with the wheel and the ticks change
        page.click("#vsw button[data-v='timeline']")
        assert page.evaluate("document.querySelectorAll('#view-timeline circle.tdot').length") >= 1
        ticks = page.evaluate("[...document.querySelectorAll('#view-timeline svg text')].map(t => t.textContent).join('|')")
        for _ in range(4):
            page.click("#view-timeline [data-z='in']")
        assert page.evaluate("[...document.querySelectorAll('#view-timeline svg text')].map(t => t.textContent).join('|')") != ticks
        page.click("#gsel button[data-g='1']")  # the group filter applies to every view
        page.click("#vsw button[data-v='connections']")
        assert page.evaluate("document.querySelectorAll('#view-connections g.st').length") == 2
        page.click("#vsw button[data-v='graph']")
        # the cards: everything is closed until asked
        assert page.evaluate("document.querySelectorAll('#groups details.sec[open]').length") == 0
        page.click("#expall")
        assert page.evaluate("document.querySelectorAll('#groups details.sec:not([open])').length") == 0
        page.click("#colall")
        assert page.evaluate("document.querySelectorAll('#groups details.sec[open]').length") == 0
        page.click("#group-1 [data-toggle]")
        assert page.evaluate("document.querySelectorAll('#group-1 details.sec[open]').length") == page.evaluate("document.querySelectorAll('#group-1 details.sec').length")
        b.close()
    from tests.test_pages_js import BROKEN

    assert [e for e in errors if BROKEN.search(e)] == [], errors


def test_purchase_days_and_look_alike_pictures_only_support_a_tie_they_never_make_one():
    """In a database full of mock data three weak hints (an old server, a purchase day, a similar picture) reached 0.755 and joined strangers:
    only kinds that are a hint by themselves (0.5 and up) can make two sites one operation."""
    assert all_map.pair_confidence({"past_ip": 0.5, "batch": 0.3, "kit_look": 0.3}) >= all_map.JOIN  # the sum alone would have joined them
    strong_enough = {k: w for k, w in {"past_ip": 0.5, "batch": 0.3, "kit_look": 0.3}.items() if w >= 0.5}
    assert all_map.pair_confidence(strong_enough) < all_map.JOIN
    assert all_map.pair_confidence({k: w for k, w in {"redirector": 0.6, "past_ip": 0.5, "batch": 0.3}.items() if w >= 0.5}) >= all_map.JOIN  # two real hints still do
