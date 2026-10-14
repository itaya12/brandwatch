"""Provider abstraction: mocks under DEMO_MODE, resilience wrapper, fallback chain, quota."""

from __future__ import annotations

import pytest
from tests.conftest import make_workspace

from brandwatch.config.settings import EconomicLimits, Settings
from brandwatch.db.enums import ProviderStatus
from brandwatch.db.models import ApiUsage
from brandwatch.providers.base import (
    FallbackChain,
    ProviderError,
    ProviderResult,
    RateLimited,
    ResiliencePolicy,
    ResilientProvider,
)
from brandwatch.providers.impl import REAL_PROVIDERS
from brandwatch.providers.ledger import DbUsageLedger, InMemoryLedger
from brandwatch.providers.mock import MOCKS_BY_KIND, MockReputationProvider
from brandwatch.providers.registry import KINDS, ProviderRegistry


# --------------------------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------------------------
class FakeClock:
    def __init__(self) -> None:
        self.t = 1000.0

    def __call__(self) -> float:
        return self.t

    def advance(self, s: float) -> None:
        self.t += s


class SleepRecorder:
    def __init__(self, clock: FakeClock | None = None) -> None:
        self.calls: list[float] = []
        self.clock = clock

    async def __call__(self, seconds: float) -> None:
        self.calls.append(seconds)
        if self.clock:
            self.clock.advance(seconds)


class Scripted:
    """A provider whose ``lookup_domain`` follows a script of outcomes."""

    name = "scripted"
    requires_key = False
    cost_per_call = 0.25

    def __init__(self, *script):
        self.script = list(script)
        self.calls = 0

    async def lookup_domain(self, domain: str) -> ProviderResult:
        self.calls += 1
        step = self.script.pop(0) if self.script else "ok"
        if isinstance(step, Exception):
            raise step
        if step == "ok":
            return ProviderResult(self.name, ProviderStatus.POSITIVE, {"d": domain}, cost_usd=0.25)
        if step == "err":
            return ProviderResult.failure(self.name, "upstream 500")
        if isinstance(step, tuple) and step[0] == "retry_after":
            return ProviderResult.failure(self.name, "429", retry_after=step[1])
        raise AssertionError(step)


def wrapped(inner, **kw) -> ResilientProvider:
    clock = kw.pop("clock", FakeClock())
    sleep = kw.pop("sleep", SleepRecorder(clock))
    policy = kw.pop("policy", ResiliencePolicy(backoff_base=1.0, cooldown=60, failure_threshold=2))
    return ResilientProvider(inner, policy=policy, sleep=sleep, clock=clock, **kw)


def demo_settings(**overrides) -> Settings:
    return Settings(_env_file=None, **{"demo_mode": True, **overrides})


# --------------------------------------------------------------------------------------------
# ProviderResult semantics
# --------------------------------------------------------------------------------------------
def test_unknown_is_not_clean():
    r = ProviderResult("vt", ProviderStatus.UNKNOWN)
    assert r.ok and not r.is_clean
    assert ProviderResult("vt", ProviderStatus.NEGATIVE).is_clean
    assert not ProviderResult.failure("vt", "x").ok


# --------------------------------------------------------------------------------------------
# Registry / factory
# --------------------------------------------------------------------------------------------
def test_registry_returns_mocks_under_demo_mode():
    reg = ProviderRegistry(demo_settings(virustotal_api_key="real-key"))
    for kind in KINDS:
        chain = reg.get(kind)
        assert isinstance(chain, FallbackChain)
        for p in chain.providers:
            assert isinstance(p.inner, MOCKS_BY_KIND[kind])
            assert p.name.startswith("mock:")
    assert reg.describe()["reputation"] == [
        "mock:virustotal", "mock:urlhaus", "mock:safebrowsing"
    ]  # fmt: skip


def test_registry_uses_real_stub_when_key_present_and_demo_off():
    reg = ProviderRegistry(
        demo_settings(demo_mode=False, virustotal_api_key="real-key", urlhaus_api_key="k")
    )
    chain = reg.reputation()
    assert chain.primary.inner.name == "virustotal" and not chain.primary.name.startswith(
        "mock:"
    )  # real client
    # fallbacks with their keys resolve to their real classes too
    assert type(chain.providers[1].inner) is REAL_PROVIDERS["urlhaus"]
    # a keyed provider WITHOUT a key is never mocked in live mode: it is skipped
    assert reg.uses_mock("shodan") is True
    assert reg.host().primary.name.startswith(
        "not-configured:"
    )  # shodan + censys both keyless here
    assert all(not p.name.startswith("mock:") for k in ("whois", "host", "search", "llm")
               for p in reg.get(k).providers)  # fmt: skip


async def test_live_mode_skips_keyless_primaries_and_never_invents_data():
    reg = ProviderRegistry(demo_settings(demo_mode=False))
    # WHOIS without a WhoisXML key goes straight to the real local WHOIS client
    assert reg.describe()["whois"] == ["rdap", "local_whois"]  # keyless RDAP, then port 43
    # no usable passive-DNS provider → explicit error, not fabricated neighbours
    res = await reg.passive_dns().passive_dns("203.0.113.7")
    assert not res.ok and res.provider.endswith("not-configured:passive_dns")
    reason = res.data["attempts"][0]["error"]
    assert "no provider configured" in reason and "virustotal" in reason


def test_registry_rejects_unknown_kind():
    with pytest.raises(KeyError):
        ProviderRegistry(demo_settings()).get("telepathy")


async def test_mock_pipeline_runs_with_no_keys_at_zero_cost():
    reg = ProviderRegistry(demo_settings(), ledger=InMemoryLedger())
    rep = await reg.reputation().lookup_domain("login-phish-shopnova.com")
    who = await reg.whois().lookup("shopn0va.com")
    dns = await reg.dns().resolve("shopn0va.com")
    assert rep.status is ProviderStatus.POSITIVE and rep.cost_usd == 0
    assert who.data["age_days"] >= 0
    assert dns.data["records"]
    assert reg.ledger.spend == 0 and reg.ledger.calls == 3
    # deterministic
    again = await ProviderRegistry(demo_settings()).whois().lookup("shopn0va.com")
    assert again.data == who.data


async def test_mock_reputation_semantics():
    m = MockReputationProvider("virustotal")
    assert (await m.lookup_domain("totally-clean.example")).is_clean
    unknown = await m.lookup_domain("shopn0va.example")
    assert unknown.status is ProviderStatus.UNKNOWN and not unknown.is_clean


# --------------------------------------------------------------------------------------------
# Resilience wrapper
# --------------------------------------------------------------------------------------------
async def test_retry_then_success_with_exponential_backoff():
    inner = Scripted(ProviderError("timeout"), ProviderError("timeout"), "ok")
    sleep = SleepRecorder()
    p = wrapped(inner, sleep=sleep)
    r = await p.lookup_domain("a.example")
    assert r.ok and inner.calls == 3
    assert sleep.calls == [1.0, 2.0]


async def test_honours_retry_after():
    inner = Scripted(("retry_after", 7), "ok")
    sleep = SleepRecorder()
    r = await wrapped(inner, sleep=sleep).lookup_domain("a.example")
    assert r.ok and sleep.calls == [7.0]


async def test_rate_limited_exception_carries_retry_after():
    inner = Scripted(RateLimited(retry_after=3), "ok")
    sleep = SleepRecorder()
    assert (await wrapped(inner, sleep=sleep).lookup_domain("x")).ok
    assert sleep.calls == [3.0]


async def test_non_retryable_error_fails_fast_without_raising():
    inner = Scripted(ProviderError("bad key", retryable=False), "ok")
    r = await wrapped(inner).lookup_domain("a.example")
    assert not r.ok and "bad key" in r.error and inner.calls == 1


async def test_unexpected_exception_becomes_error_result():
    inner = Scripted(NotImplementedError("Phase 3"), "ok")
    r = await wrapped(inner).lookup_domain("a.example")
    assert not r.ok and "NotImplementedError" in r.error


async def test_exhausted_retries_return_degraded_result():
    inner = Scripted("err", "err", "err")
    r = await wrapped(inner).lookup_domain("a.example")
    assert not r.ok and r.error == "upstream 500" and inner.calls == 3


async def test_circuit_opens_after_failures_and_recovers_after_cooldown():
    clock = FakeClock()
    inner = Scripted(*(["err"] * 6), "ok", "ok")
    p = wrapped(inner, clock=clock, sleep=SleepRecorder())  # threshold 2, cooldown 60
    assert not (await p.lookup_domain("a")).ok  # failure 1 (3 attempts)
    assert not (await p.lookup_domain("b")).ok  # failure 2 → opens
    assert p.breaker.state == "open"
    calls_before = inner.calls
    skipped = await p.lookup_domain("c")
    assert "circuit_open" in skipped.error and inner.calls == calls_before  # inner not touched
    clock.advance(61)
    assert p.breaker.state == "half_open"
    assert (await p.lookup_domain("d")).ok  # probe succeeds
    assert p.breaker.state == "closed"


async def test_cache_hit_marks_cached_and_skips_inner():
    inner = Scripted("ok", "ok")
    p = wrapped(inner)
    first = await p.lookup_domain("a.example")
    second = await p.lookup_domain("a.example")
    other = await p.lookup_domain("b.example")
    assert not first.cached and second.cached and second.cost_usd == 0
    assert inner.calls == 2 and not other.cached


async def test_quota_guard_blocks_and_ledger_records():
    ledger = InMemoryLedger(EconomicLimits(max_api_calls=1))
    inner = Scripted("ok", "ok")
    p = wrapped(inner, ledger=ledger)
    assert (await p.lookup_domain("a")).ok
    blocked = await p.lookup_domain("b")
    assert "quota_exceeded" in blocked.error and inner.calls == 1
    assert ledger.rows == [{"provider": "scripted", "calls": 1, "cost_usd": 0.25, "job_id": None}]


async def test_spend_cap_blocks_before_call():
    ledger = InMemoryLedger(EconomicLimits(max_daily_spend=0.3))
    inner = Scripted("ok", "ok")
    p = wrapped(inner, ledger=ledger)
    assert (await p.lookup_domain("a")).ok  # 0.25 spent
    assert "quota_exceeded" in (await p.lookup_domain("b")).error  # 0.25 + 0.25 > 0.3


async def test_token_bucket_throttles():
    clock = FakeClock()
    sleep = SleepRecorder(clock)
    inner = Scripted(*(["ok"] * 5))
    policy = ResiliencePolicy(rate_per_second=1.0, burst=2)
    p = ResilientProvider(inner, policy=policy, sleep=sleep, clock=clock)
    for i in range(5):  # burst 2 → sleep, 1 token accrues, no sleep, sleep
        await p.lookup_domain(f"d{i}")
    assert len(sleep.calls) == 2 and all(0 < s <= 1.0 for s in sleep.calls)


# --------------------------------------------------------------------------------------------
# Fallback chain
# --------------------------------------------------------------------------------------------
async def test_chain_falls_back_to_next_provider():
    bad = Scripted("err", "err", "err")
    bad.name = "primary"
    good = Scripted("ok")
    good.name = "fallback"
    chain = FallbackChain("reputation", [wrapped(bad), wrapped(good)])
    r = await chain.lookup_domain("a.example")
    assert r.ok and r.provider == "fallback"
    assert chain.name == "reputation:primary>fallback"


async def test_chain_degrades_when_all_fail():
    a, b = Scripted("err", "err", "err"), Scripted(ProviderError("x", retryable=False))
    a.name, b.name = "a", "b"
    r = await FallbackChain("reputation", [wrapped(a), wrapped(b)]).lookup_domain("z")
    assert not r.ok and r.error.startswith("degraded")
    assert [x["provider"] for x in r.data["attempts"]] == ["a", "b"]


def test_chain_requires_method_on_every_member():
    chain = FallbackChain("reputation", [wrapped(Scripted())])
    with pytest.raises(AttributeError):
        chain.no_such_method  # noqa: B018


# --------------------------------------------------------------------------------------------
# DB ledger
# --------------------------------------------------------------------------------------------
async def test_db_ledger_writes_api_usage_and_enforces_calls(session):
    ws = make_workspace(session)
    ledger = DbUsageLedger(session, ws.id, EconomicLimits(max_api_calls=2))
    reg = ProviderRegistry(demo_settings(), ledger=ledger)
    for host in ("a.example", "b.example", "c.example"):
        # recorded demo scenarios are metered but never refused (a demo cannot run out of budget)
        assert (await reg.reputation().lookup_domain(host)).ok
    rows = session.query(ApiUsage).filter_by(workspace_id=ws.id).all()
    assert len(rows) == 3 and {r.provider for r in rows} == {"mock:virustotal"}
    # free calls are recorded but never count toward the cap — only paid calls do
    assert ledger.check("serpapi", 0.01) is True
    ledger.record("serpapi", 1, 0.01)
    ledger.record("searchapi", 1, 0.004)
    assert ledger.check("serpapi", 0.01) is False  # the daily cap of paid calls is used up
    assert ledger.check("local_dns", 0.0) is True  # a free call is never refused
