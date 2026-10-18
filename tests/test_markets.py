"""Search markets: countries, each in one or more languages (United States · English + Spanish, Israel · Hebrew, Italy · Italian).

A scan runs every approved query once per (country, language); the older ``search_geo`` / ``search_lang`` stay in step; the brand page and the
add-brand form have a searchable picker for them.
"""

from __future__ import annotations

import asyncio
import uuid

from fastapi.testclient import TestClient
from tests.test_demo_story import _api, _app, _ui

from brandwatch.config.brand_config import BrandConfig
from brandwatch.detection import markets as m
from brandwatch.detection.sources import stream_search


def test_markets_are_cleaned_and_the_old_two_fields_are_what_an_empty_list_means():
    raw = '[{"country":"US","langs":["en","es","xx"]},{"country":"il"},{"country":"it","langs":"it"},{"country":"zzz"},{"country":"us","langs":["fr"]},7]'
    assert m.normalize(raw) == [{"country": "us", "langs": ["en", "es", "fr"]}, {"country": "il", "langs": ["he"]}, {"country": "it", "langs": ["it"]}]
    assert m.normalize("not json") == [] and m.normalize(None) == [] and m.normalize([{"country": "de", "langs": ["xx"]}]) == [{"country": "de", "langs": ["de"]}]
    many = [{"country": f"{a}{b}", "langs": ["en"]} for a in "abc" for b in "defg"]
    assert len(m.normalize(many)) == m.MAX_MARKETS and len(m.normalize([{"country": "us", "langs": ["en", "es", "fr", "de", "it", "pt"]}])[0]["langs"]) == m.MAX_LANGS
    assert m.pairs("us, il", "en", None) == [("us", "en"), ("il", "en")] and m.pairs("", "", None) == [("us", "en")]
    mk = [{"country": "us", "langs": ["en", "es"]}, {"country": "il", "langs": ["he"]}, {"country": "it", "langs": ["it"]}]
    assert m.pairs("ignored", "ignored", mk) == [("us", "en"), ("us", "es"), ("il", "he"), ("it", "it")]
    assert m.describe(m.pairs(None, None, mk)) == "US (en, es) · IL (he) · IT (it)" and m.countries(m.pairs(None, None, mk)) == ["us", "il", "it"]
    assert m.legacy(mk) == ("us,il,it", "en") and m.legacy([]) == ("us", "en")
    assert m.from_legacy("us,il", "en") == [{"country": "us", "langs": ["en"]}, {"country": "il", "langs": ["en"]}]
    cfg = BrandConfig.model_validate({"detection": {"search_markets": [{"country": "IL", "langs": ["HE"]}]}})
    assert cfg.detection.search_markets == [{"country": "il", "langs": ["he"]}] and BrandConfig().detection.search_markets == []


class _Search:
    def __init__(self) -> None:
        self.calls: list[tuple[str, str, str]] = []

    async def search(self, query: str, geo: str = "us", lang: str = "en"):
        from brandwatch.providers.base import ProviderResult, ProviderStatus

        self.calls.append((query, geo, lang))
        return ProviderResult(provider="fake", status=ProviderStatus.POSITIVE, data={"hits": [{"url": f"https://shop-{geo}-{lang}.example/", "title": "t", "position": 1}]},
                              raw={}, latency_ms=1)  # fmt: skip


class _Providers:
    def __init__(self) -> None:
        self.s = _Search()

    def search(self) -> _Search:
        return self.s


def test_a_scan_searches_every_query_in_every_country_and_language_of_the_markets():
    prov = _Providers()
    seen: list[str] = []
    res = asyncio.run(stream_search(
        prov, "ShopNova", {"shopnova.com"}, geo="us", lang="en", queries=["shopnova login", "shopnova"], geos=["us", "il"],
        markets=[("us", "en"), ("us", "es"), ("il", "he")], on_query=lambda q, c, r: seen.append(c),
    ))  # fmt: skip
    assert prov.s.calls == [("shopnova login", "us", "en"), ("shopnova", "us", "en"), ("shopnova login", "us", "es"), ("shopnova", "us", "es"),
                            ("shopnova login", "il", "he"), ("shopnova", "il", "he")]  # fmt: skip
    assert res.api_calls == 6 and seen[0] == "us/en" and seen[2] == "us/es" and seen[-1] == "il/he"  # a country in two languages says which
    assert {h.matched_pattern for h in res.hits} >= {"serp:us/en:shopnova login", "serp:us/es:shopnova login", "serp:il/he:shopnova login"}
    # the old call (countries and one language) is unchanged
    prov2 = _Providers()
    asyncio.run(stream_search(prov2, "ShopNova", {"shopnova.com"}, geo="us", lang="en", queries=["shopnova"], geos=["us", "il"]))
    assert prov2.s.calls == [("shopnova", "us", "en"), ("shopnova", "il", "en")]


def test_the_form_and_the_api_keep_the_markets_and_the_two_old_fields_in_step(engine, tmp_path):
    from brandwatch.api.brands import config_patch_from_form

    class Form:
        def __init__(self, **kw):
            self.kw = kw

        def get(self, k, d=None):
            return self.kw.get(k, d)

        def getlist(self, k):
            return []

        def multi_items(self):
            return list(self.kw.items())

        def __contains__(self, k):
            return k in self.kw

    picked = '[{"country":"us","langs":["en","es"]},{"country":"il","langs":["he"]},{"country":"it","langs":["it"]}]'
    _p, det, _s, _c = config_patch_from_form(Form(search_geo="us", search_lang="en", search_markets=picked))
    assert det["search_markets"] == m.normalize(picked) and det["search_geo"] == "us,il,it" and det["search_lang"] == "en"
    _p, det, _s, _c = config_patch_from_form(Form(search_geo="de", search_lang="de"))  # an old client sets the plain fields
    assert det["search_markets"] == [] and det["search_geo"] == "de"
    app = _app(engine, tmp_path)
    with TestClient(app):
        c = _api(app)
        b = c.post("/api/brands", json={"name": f"Mk {uuid.uuid4().hex[:4]}", "domains": ["shopnova.com"]}).json()
        r = c.patch(f"/api/brands/{b['id']}/config", json={"detection": {"search_markets": [{"country": "US", "langs": ["en", "es"]}, {"country": "il", "langs": ["he"]}]}}).json()
        d = r["config"]["detection"]
        assert d["search_markets"] == [{"country": "us", "langs": ["en", "es"]}, {"country": "il", "langs": ["he"]}] and d["search_geo"] == "us,il" and d["search_lang"] == "en"
        d = c.patch(f"/api/brands/{b['id']}/config", json={"detection": {"search_geo": "fr", "search_lang": "fr"}}).json()["config"]["detection"]
        assert d["search_markets"] == [] and d["search_geo"] == "fr"  # set by hand: the markets do not override it
        assert c.patch(f"/api/brands/{b['id']}/config", json={"detection": {"search_markets": [{"country": "zzz", "langs": ["xx"]}, 5]}}).json()["config"]["detection"]["search_markets"] == []


def test_the_brand_page_and_the_add_brand_form_have_a_searchable_country_and_language_picker(engine, tmp_path):
    import pytest

    sync = pytest.importorskip("playwright.sync_api")
    app = _app(engine, tmp_path)
    with TestClient(app):
        c, ui = _api(app), _ui(app)
        b = c.post("/api/brands", json={"name": f"Pk {uuid.uuid4().hex[:4]}", "domains": ["shopnova.com"]}).json()
        c.patch(f"/api/brands/{b['id']}/config", json={"detection": {"search_markets": [{"country": "us", "langs": ["en"]}, {"country": "il", "langs": ["he"]}]}})
        page = ui.get(f"/ui/brands/{b['id']}").text
        form = ui.get("/ui/brands").text
    assert 'class="mkt"' in page and "Where its customers are" in page and 'name="search_markets"' in page and "Add a country" in page
    assert 'class="mkt"' in form and 'name="search_markets"' in form
    with sync.sync_playwright() as pw:
        try:
            br = pw.chromium.launch()
        except Exception as exc:  # noqa: BLE001
            pytest.skip(f"no sandboxed Chromium here: {exc}")
        pg = br.new_page(viewport={"width": 1280, "height": 900})
        errors: list[str] = []
        pg.on("pageerror", lambda e: errors.append(str(e)))
        pg.set_content(page, wait_until="domcontentloaded")
        pg.wait_for_timeout(300)
        pg.click('#btabs [data-pane="setup"]')  # the search rules live in the "Scan setup" tab
        value = lambda n: pg.evaluate(f"document.querySelector('.mkt [name={n}]').value")  # noqa: E731
        assert value("search_geo") == "us,il" and "Israel" in pg.inner_text(".mkt") and "Hebrew" in pg.inner_text(".mkt")
        pg.fill(".mkt-q", "ital")  # search a country by name
        assert pg.evaluate("[...document.querySelectorAll('.mkt-add .mkt-pop .it')].map(e => e.dataset.cc)") == ["it"]
        pg.click(".mkt-add .mkt-pop [data-cc='it']")
        assert value("search_geo") == "us,il,it" and "Italian" in pg.inner_text(".mkt")
        pg.click(".mkt-row:first-child [data-langs]")  # United States: tick Spanish
        pg.fill(".mkt-row:first-child .fq", "span")
        pg.check(".mkt-row:first-child [data-lang='es']")
        import json as _json

        mk = _json.loads(value("search_markets"))
        assert mk[0] == {"country": "us", "langs": ["en", "es"]} and mk[2] == {"country": "it", "langs": ["it"]} and value("search_lang") == "en"
        assert "3 countries · 4 languages" in pg.inner_text(".mkt-sum")
        pg.click(".mkt-row:nth-child(2) [data-del]")  # remove Israel
        assert value("search_geo") == "us,it"
        # a sentence the page can search by: nothing found
        pg.fill(".mkt-q", "zzzz")
        assert "no such country" in pg.inner_text(".mkt-add .mkt-pop")
        br.close()
    assert errors == [], errors
