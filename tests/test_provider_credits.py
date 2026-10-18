"""An empty provider account is not a rate limit.

SearchApi answers HTTP 429 when the account has no requests left. The client called every 429 "rate limited — retry
after 60 s": the scan retried three times (two minutes), said "slow down, re-run later", and the analyst thought the ad
scan was broken. Live, 2026-10-18: the free trial's requests were used up (``/me``: remaining_credits 0).
"""

from __future__ import annotations

import httpx
import pytest
import respx

from brandwatch.providers.base import ProviderError, RateLimited, classify_provider_error
from brandwatch.providers.impl.commerce import SearchApiAdsClient

SEARCH = "https://www.searchapi.io/api/v1/search"


@respx.mock
async def test_a_429_that_says_the_account_is_empty_is_final_and_said_in_its_own_words():
    respx.get(SEARCH).mock(return_value=httpx.Response(429, json={"error": "Your account has run out of searches. Please upgrade your plan."}))
    c = SearchApiAdsClient("k", client=httpx.AsyncClient())
    with pytest.raises(ProviderError) as exc:
        await c.meta_ads("bank hapoalim", "IL")
    assert not isinstance(exc.value, RateLimited) and exc.value.retryable is False
    assert "no_credits" in str(exc.value) and "run out of searches" in str(exc.value)
    assert classify_provider_error(str(exc.value)) == "credits"


@respx.mock
async def test_a_429_that_only_asks_to_slow_down_is_still_a_rate_limit():
    respx.get(SEARCH).mock(return_value=httpx.Response(429, headers={"retry-after": "5"}, json={"error": "Too many requests per second"}))
    c = SearchApiAdsClient("k", client=httpx.AsyncClient())
    with pytest.raises(RateLimited) as exc:
        await c.meta_ads("bank hapoalim", "IL")
    assert exc.value.retry_after == 5 and classify_provider_error(str(exc.value), 5) == "rate_limit"


@respx.mock
async def test_the_settings_test_asks_the_free_account_endpoint_and_says_what_is_left():
    me = respx.get("https://www.searchapi.io/api/v1/me").mock(
        return_value=httpx.Response(200, json={"account": {"current_month_usage": 0, "monthly_allowance": 0, "remaining_credits": 0}}))
    search = respx.get(SEARCH)
    c = SearchApiAdsClient("k", client=httpx.AsyncClient())
    r = await c.account()
    assert me.called and not search.called  # nothing spent
    assert r.data["ok"] is False and "no requests left" in r.data["summary"]
    me.mock(return_value=httpx.Response(200, json={"account": {"current_month_usage": 40, "monthly_allowance": 1000, "remaining_credits": 960}}))
    r = await c.account()
    assert r.data["ok"] is True and "960 request(s) left" in r.data["summary"] and "40 used this month of 1000" in r.data["summary"]
