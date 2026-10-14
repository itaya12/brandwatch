"""ScraperAPI is the fallback of SerpAPI for the Google search stream: same answer shape, used when SerpAPI has no key, no quota or is down."""

from __future__ import annotations

import asyncio

import httpx
import pytest
import respx

from brandwatch.config.settings import DEFAULT_PROVIDER_ROUTES, Settings
from brandwatch.providers.base import ProviderError
from brandwatch.providers.impl import REAL_PROVIDERS
from brandwatch.providers.impl.clients import ScraperApiClient
from brandwatch.providers.registry import ProviderRegistry

URL = "https://api.scraperapi.com/structured/google/search"
SERP = "https://serpapi.com/search.json"


async def _nosleep(_s: float) -> None:
    await asyncio.sleep(0)


def _live(**keys: str) -> ProviderRegistry:
    return ProviderRegistry(Settings(_env_file=None, demo_mode=False), key_overrides=keys, sleep=_nosleep)


def test_scraperapi_is_the_first_fallback_of_serpapi_and_has_its_own_key():
    route = DEFAULT_PROVIDER_ROUTES["search"]
    assert route.primary == "serpapi" and route.fallback[0] == "scraperapi"
    assert REAL_PROVIDERS["scraperapi"] is ScraperApiClient and ScraperApiClient.requires_key
    assert Settings(_env_file=None, scraperapi_api_key="sk-test").provider_key("scraperapi") == "sk-test"
    assert "sk-test" in Settings(_env_file=None, scraperapi_api_key="sk-test").known_secret_values()  # never in a log


@respx.mock
async def test_the_client_asks_for_the_country_google_domain_and_reads_the_results():
    route = respx.get(URL).mock(return_value=httpx.Response(200, json={
        "organic_results": [{"position": 1, "title": "Sign in", "link": "https://shopnova-login.com/", "snippet": "Verify your account " * 30},
                            {"position": 2, "title": "Shop", "link": "https://shopnova.com/"}, {"title": "no link"}],
        "ads": [{"link": "https://ad.example/", "title": "Ad"}]}))  # fmt: skip
    r = await ScraperApiClient("k", client=httpx.AsyncClient()).search("shopnova login", geo="IL", lang="he")
    q = route.calls.last.request.url.params
    assert q["api_key"] == "k" and q["query"] == "shopnova login" and q["country_code"] == "il" and q["tld"] == "co.il" and q["hl"] == "HE"
    assert [h["url"] for h in r.data["hits"]] == ["https://shopnova-login.com/", "https://shopnova.com/", "https://ad.example/"]
    assert r.data["hits"][0]["position"] == 1 and len(r.data["hits"][0]["snippet"]) == 300 and r.data["hits"][2]["kind"] == "ad"
    assert r.provider == "scraperapi" and r.cost_usd == 0.012
    respx.get(URL).mock(return_value=httpx.Response(200, json={"organic_results": []}))
    empty = await ScraperApiClient("k", client=httpx.AsyncClient()).search("nothing")
    assert empty.data["hits"] == [] and respx.calls.last.request.url.params["tld"] == "com"


@respx.mock
async def test_a_missing_key_or_a_refused_key_is_an_error_not_an_empty_answer():
    with pytest.raises(ProviderError, match="no API key"):
        await ScraperApiClient(None, client=httpx.AsyncClient()).search("x")
    respx.get(URL).mock(return_value=httpx.Response(403, json={"error": "plan limit reached"}))
    with pytest.raises(ProviderError) as e:
        await ScraperApiClient("k", client=httpx.AsyncClient()).search("x")
    assert e.value.retryable is False and "403" in str(e.value)


def test_the_chain_uses_only_what_has_a_key():
    only_scraper = _live(scraperapi="k2").get("search")
    assert [p.name for p in only_scraper.providers] == ["scraperapi"]  # no SerpAPI key: ScraperAPI is the search
    both = _live(serpapi="k1", scraperapi="k2").get("search")
    assert [p.name for p in both.providers] == ["serpapi", "scraperapi"]
    assert type(_live().get("search").providers[0]).__name__ == "NotConfiguredProvider"  # no key at all: live mode never answers from recordings


@respx.mock
async def test_when_serpapi_fails_scraperapi_answers_and_the_search_goes_on():
    respx.get(SERP).mock(return_value=httpx.Response(500, text="boom"))
    respx.get(URL).mock(return_value=httpx.Response(200, json={"organic_results": [{"position": 1, "title": "Sign in", "link": "https://shopnova-login.com/"}]}))
    res = await _live(serpapi="k1", scraperapi="k2").get("search").search("shopnova login", geo="us", lang="en")
    assert res.ok and [h["url"] for h in res.data["hits"]] == ["https://shopnova-login.com/"] and res.provider == "scraperapi"
    # SerpAPI out of quota (a refused key): the same
    respx.get(SERP).mock(return_value=httpx.Response(403, json={"error": "Your account has run out of searches."}))
    res = await _live(serpapi="k1", scraperapi="k2").get("search").search("shopnova login")
    assert res.ok and res.provider == "scraperapi"
    # SerpAPI answers: ScraperAPI is not called (it costs 25 credits)
    respx.get(SERP).mock(return_value=httpx.Response(200, json={"organic_results": [{"link": "https://a.example/"}]}))
    before = len([c for c in respx.calls if str(c.request.url).startswith(URL)])
    res = await _live(serpapi="k1", scraperapi="k2").get("search").search("shopnova login")
    assert res.provider == "serpapi" and len([c for c in respx.calls if str(c.request.url).startswith(URL)]) == before
