"""Provider abstraction (spec §4): one result shape, typed Protocols, and a resilience wrapper.

Failure strategy — a provider timeout / 429 / outage must *degrade, not crash* the scan:
retry → backoff → circuit open → fallback → ``status = error`` ("evidence unavailable").
Nothing in this module raises for a provider failure; callers always get a ``ProviderResult``.

"Not detected" ≠ "clean": ``ProviderStatus.UNKNOWN`` (e.g. VirusTotal *not_found*) is never
interpreted as safe — only ``NEGATIVE`` is.
"""

from __future__ import annotations

import asyncio
import inspect
import json
import re
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import Any, Protocol, runtime_checkable

from brandwatch.db.enums import ProviderStatus

SleepFn = Callable[[float], Awaitable[None]]
ClockFn = Callable[[], float]


# --------------------------------------------------------------------------------------------
# Result shape
# --------------------------------------------------------------------------------------------
@dataclass(slots=True)
class ProviderResult:
    provider: str
    status: ProviderStatus
    data: dict[str, Any] | None = None  # parsed, normalized fields
    raw: dict[str, Any] | None = None  # raw API response (when ToS permits) → evidence
    cost_usd: float = 0.0
    latency_ms: int = 0
    cached: bool = False
    error: str | None = None
    retry_after: int | None = None

    @property
    def ok(self) -> bool:
        """The provider answered (even if the answer is 'unknown')."""
        return self.status is not ProviderStatus.ERROR

    @property
    def is_clean(self) -> bool:
        """Only an explicit negative is clean. UNKNOWN / ERROR / N/A are not."""
        return self.status is ProviderStatus.NEGATIVE

    @classmethod
    def failure(
        cls, provider: str, error: str, *, retry_after: int | None = None, latency_ms: int = 0
    ) -> ProviderResult:
        return cls(
            provider=provider,
            status=ProviderStatus.ERROR,
            error=error,
            retry_after=retry_after,
            latency_ms=latency_ms,
        )


class ProviderError(Exception):
    """Raised by implementations for transport / API errors. ``retryable`` drives the policy."""

    def __init__(self, message: str, *, retryable: bool = True, retry_after: int | None = None):
        super().__init__(message)
        self.retryable = retryable
        self.retry_after = retry_after


class RateLimited(ProviderError):
    def __init__(self, retry_after: int | None = None):
        super().__init__("rate limited (429)", retryable=True, retry_after=retry_after)


# --------------------------------------------------------------------------------------------
# Protocols (spec §4 table)
# --------------------------------------------------------------------------------------------
@runtime_checkable
class Provider(Protocol):
    name: str
    requires_key: bool
    cost_per_call: float


class ReputationProvider(Provider, Protocol):
    async def lookup_domain(self, domain: str) -> ProviderResult: ...
    async def lookup_ip(self, ip: str) -> ProviderResult: ...
    async def lookup_url(self, url: str) -> ProviderResult: ...


class WhoisProvider(Provider, Protocol):
    async def lookup(self, domain: str) -> ProviderResult: ...
    async def history(self, domain: str) -> ProviderResult: ...


class DnsProvider(Provider, Protocol):
    async def resolve(self, name: str, rtype: str = "A") -> ProviderResult: ...
    async def passive_dns(self, value: str) -> ProviderResult: ...


class CertProvider(Provider, Protocol):
    async def ct_search(self, pattern: str) -> ProviderResult: ...
    async def by_fingerprint(self, fingerprint_sha256: str) -> ProviderResult: ...


class SearchProvider(Provider, Protocol):
    async def search(self, query: str, geo: str = "us", lang: str = "en") -> ProviderResult: ...
    async def reverse_image(self, image_sha256: str) -> ProviderResult: ...


class HostProvider(Provider, Protocol):
    async def host(self, ip: str) -> ProviderResult: ...
    async def favicon_search(self, favicon_mmh3: int) -> ProviderResult: ...


class BrowserFetcher(Provider, Protocol):
    """Sandboxed-browser fetch contract (spec §7): runs in an isolated worker with public-only
    egress, captures screenshot + HTML + favicon, then the worker is destroyed. ``data`` carries
    artifact references, never the worker itself."""

    async def fetch(self, url: str, profile: str = "datacenter") -> ProviderResult: ...


class ScanSearchProvider(Provider, Protocol):
    """urlscan.io-style page search (brand in page URL / title) and structural similarity."""

    async def search_pages(self, query: str, limit: int = 50) -> ProviderResult: ...
    async def result(self, scan_id: str) -> ProviderResult: ...
    async def snapshot(self, domain: str, scan_id: str | None = None, peek: bool = False) -> ProviderResult: ...


class GeoProvider(Provider, Protocol):
    """IP geolocation (dashboard globe, campaign attribution)."""

    async def locate(self, ip: str) -> ProviderResult: ...


class LLMProvider(Provider, Protocol):
    async def analyze(self, text: str, schema: dict[str, Any]) -> ProviderResult: ...


# --------------------------------------------------------------------------------------------
# Resilience building blocks
# --------------------------------------------------------------------------------------------
class UsageLedger(Protocol):
    """Quota / cost guard (spec §12, §13)."""

    def check(self, provider: str, cost_usd: float) -> bool: ...
    def record(self, provider: str, calls: int, cost_usd: float, job_id: Any = None) -> None: ...


class CircuitBreaker:
    """closed → (N consecutive failures) → open for ``cooldown`` → half-open probe → closed."""

    def __init__(self, failure_threshold: int = 3, cooldown: float = 60.0, clock: ClockFn = None):
        self.failure_threshold = failure_threshold
        self.cooldown = cooldown
        self._clock = clock or time.monotonic
        self._failures = 0
        self._opened_at: float | None = None
        self._probing = False

    @property
    def state(self) -> str:
        if self._opened_at is None:
            return "closed"
        if self._clock() - self._opened_at >= self.cooldown:
            return "half_open"
        return "open"

    def allow(self) -> bool:
        state = self.state
        if state == "closed":
            return True
        if state == "half_open" and not self._probing:
            self._probing = True
            return True
        return False

    def record_success(self) -> None:
        self._failures = 0
        self._opened_at = None
        self._probing = False

    def record_failure(self) -> None:
        self._failures += 1
        self._probing = False
        if self._opened_at is not None or self._failures >= self.failure_threshold:
            self._opened_at = self._clock()


class TokenBucket:
    """Rate limiter: ``rate`` tokens per second, burst ``capacity``."""

    def __init__(self, rate: float, capacity: int, clock: ClockFn = None):
        self.rate = rate
        self.capacity = capacity
        self._clock = clock or time.monotonic
        self._tokens = float(capacity)
        self._updated = self._clock()

    def take(self) -> float:
        """Consume one token; return seconds to wait (0 when a token was available)."""
        now = self._clock()
        self._tokens = min(self.capacity, self._tokens + (now - self._updated) * self.rate)
        self._updated = now
        if self._tokens >= 1:
            self._tokens -= 1
            return 0.0
        wait = (1 - self._tokens) / self.rate
        self._tokens = 0.0
        return wait


class TTLCache:
    def __init__(self, ttl: float = 3600.0, clock: ClockFn = None):
        self.ttl = ttl
        self._clock = clock or time.monotonic
        self._items: dict[str, tuple[float, ProviderResult]] = {}

    def get(self, key: str) -> ProviderResult | None:
        hit = self._items.get(key)
        if hit is None:
            return None
        expires, value = hit
        if self._clock() >= expires:
            del self._items[key]
            return None
        return value

    def set(self, key: str, value: ProviderResult) -> None:
        self._items[key] = (self._clock() + self.ttl, value)


@dataclass(slots=True)
class ResiliencePolicy:
    max_attempts: int = 3
    backoff_base: float = 0.5  # seconds; doubles each retry
    backoff_max: float = 30.0
    failure_threshold: int = 3
    cooldown: float = 60.0
    rate_per_second: float = 4.0
    burst: int = 4
    cache_ttl: float = 3600.0
    cacheable_statuses: tuple[ProviderStatus, ...] = field(
        default=(ProviderStatus.POSITIVE, ProviderStatus.NEGATIVE, ProviderStatus.UNKNOWN)
    )


def _cache_key(provider: str, method: str, args: tuple, kwargs: dict) -> str:
    return json.dumps([provider, method, args, sorted(kwargs.items())], default=str, sort_keys=True)


class ResilientProvider:
    """Wraps any provider: retry + backoff, honours ``retry_after``, circuit breaker,
    token bucket, quota guard (ledger) and TTL cache. Async methods of the inner provider are
    exposed with the same names; failures surface as ``status = error`` results, never raise."""

    def __init__(
        self,
        inner: Any,
        *,
        policy: ResiliencePolicy | None = None,
        ledger: UsageLedger | None = None,
        sleep: SleepFn | None = None,
        clock: ClockFn | None = None,
        job_id: Any = None,
    ) -> None:
        self.inner = inner
        self.name: str = inner.name
        self.policy = policy or ResiliencePolicy()
        self.ledger = ledger
        self._sleep = sleep or asyncio.sleep
        self._clock = clock or time.monotonic
        self.job_id = job_id
        self.breaker = CircuitBreaker(
            self.policy.failure_threshold, self.policy.cooldown, self._clock
        )
        self.bucket = TokenBucket(self.policy.rate_per_second, self.policy.burst, self._clock)
        self.cache = TTLCache(self.policy.cache_ttl, self._clock)
        self.calls_made = 0
        self.issues: list[dict[str, Any]] = []  # drained by the scan runner → analyst alerts
        self.disabled: str | None = (
            None  # set after a rejected key: skipped for the rest of the job
        )

    def _issue(self, kind: str, method: str, error: str, retry_after: int | None = None) -> None:
        self.issues.append(
            {"provider": self.name, "kind": kind, "method": method, "error": error,
             "retry_after": retry_after}
        )  # fmt: skip

    def __getattr__(self, method: str) -> Callable[..., Awaitable[ProviderResult]]:
        target = getattr(self.inner, method)
        if not inspect.iscoroutinefunction(target):
            raise AttributeError(f"{method} is not an async provider method")

        async def call(*args: Any, **kwargs: Any) -> ProviderResult:
            return await self._invoke(method, target, args, kwargs)

        return call

    async def _invoke(
        self, method: str, target: Callable, args: tuple, kwargs: dict
    ) -> ProviderResult:
        key = _cache_key(self.name, method, args, kwargs)
        cached = self.cache.get(key)
        if cached is not None:
            hit = ProviderResult(**{f: getattr(cached, f) for f in cached.__dataclass_fields__})
            hit.cached = True
            hit.cost_usd = 0.0
            return hit

        if self.disabled:
            return ProviderResult.failure(self.name, self.disabled)
        from brandwatch.db.base import checkpoint

        checkpoint()  # release the DB write lock before the (possibly slow) network call
        estimate = float(getattr(self.inner, "cost_per_call", 0.0) or 0.0)
        # recorded demo scenarios cost nothing: they are metered (record below) but never refused,
        # so a demo cannot run out of "budget" half-way through a presentation
        recorded = str(self.name).startswith("mock:")
        if self.ledger is not None and not recorded and not self.ledger.check(self.name, estimate):
            self._issue("quota", method, "quota_exceeded: economic limit reached")
            return ProviderResult.failure(self.name, "quota_exceeded: economic limit reached")
        if not self.breaker.allow():
            self._issue("circuit", method, "circuit_open: provider skipped during cooldown")
            return ProviderResult.failure(
                self.name, "circuit_open: provider skipped during cooldown"
            )

        wait = self.bucket.take()
        if wait > 0:
            await self._sleep(wait)

        last_error = "unknown error"
        last_retry_after: int | None = None
        for attempt in range(1, self.policy.max_attempts + 1):
            started = self._clock()
            try:
                self.calls_made += 1
                result: ProviderResult = await target(*args, **kwargs)
            except ProviderError as exc:
                last_error, last_retry_after = str(exc), exc.retry_after
                if not exc.retryable:
                    break
            except Exception as exc:  # noqa: BLE001 - any other bug in a provider = non-retryable failure
                last_error = f"{type(exc).__name__}: {exc}"
                break
            else:
                result.latency_ms = result.latency_ms or int((self._clock() - started) * 1000)
                if result.status is not ProviderStatus.ERROR:
                    _trace_call(self.name, method, args, kwargs, result)
                    self.breaker.record_success()
                    if self.ledger is not None:
                        self.ledger.record(self.name, 1, result.cost_usd, self.job_id)
                        # commit the cost row now: left open, it would hold SQLite's write lock through
                        # whatever the scan does next (requests would wait, then fail "database is locked")
                        from brandwatch.db.base import checkpoint as _commit_now

                        _commit_now()
                    if result.status in self.policy.cacheable_statuses:
                        self.cache.set(key, result)
                    return result
                last_error, last_retry_after = result.error or "provider error", result.retry_after

            if attempt < self.policy.max_attempts:
                delay = (
                    last_retry_after
                    if last_retry_after is not None
                    else min(self.policy.backoff_base * 2 ** (attempt - 1), self.policy.backoff_max)
                )
                await self._sleep(float(delay))

        if classify_provider_error(last_error, last_retry_after) != "site":
            # a dead name or a page that never loads says nothing about the provider: counting it would open the circuit after three
            # such sites and skip the browser for every site after them (a scan of 53 sites made 3 browser calls and found nothing)
            self.breaker.record_failure()
        _trace_call(self.name, method, args, kwargs, None, error=last_error)
        if classify_provider_error(last_error, last_retry_after) == "auth":
            # the key is wrong or the plan is inactive: asking again for every candidate only
            # adds latency; the fallback provider answers from now on
            self.disabled = (
                f"{self.name}: skipped for this scan after the key was rejected ({last_error})"
            )
        self._issue(classify_provider_error(last_error, last_retry_after), method, last_error,
                    last_retry_after)  # fmt: skip
        return ProviderResult.failure(self.name, last_error, retry_after=last_retry_after)


def _fetch_summary(data: dict | None) -> dict:
    """A browser fetch result without the megabytes: status, URL, title, sizes, hashes, gate."""
    d = data or {}
    return {
        "status": d.get("status"), "final_url": d.get("final_url"), "title": d.get("title"),
        "html_chars": len(d.get("html") or ""), "html_sha256": d.get("html_sha256"),
        "screenshot": bool(d.get("screenshot_png")), "favicon": bool(d.get("favicon_png")),
        "favicon_error": d.get("favicon_error"), "redirect_chain": d.get("redirect_chain"),
        "tls_error": d.get("tls_error"), "bot_challenge": d.get("bot_challenge"),
        "requests_allowed": d.get("requests_allowed"), "requests_blocked": d.get("requests_blocked"),
        "profile": d.get("profile"),
    }  # fmt: skip


def _trace_call(
    provider: str,
    method: str,
    args: tuple,
    kwargs: dict,
    result: ProviderResult | None,
    error: str | None = None,
) -> None:
    """Scan trace: the exact input and output of a provider call (LLM prompts in full)."""
    from brandwatch import trace

    if trace.current() is None:
        return
    stage = "llm" if method == "analyze" else "provider"
    payload: dict[str, Any] = {"args": list(args), "kwargs": kwargs}
    if result is None:
        payload["error"] = error
    else:
        payload.update(
            status=result.status.value, latency_ms=result.latency_ms, cost_usd=result.cost_usd,
            cached=result.cached,
            data=_fetch_summary(result.data) if method == "fetch" else result.data,
        )  # fmt: skip
        if stage == "llm":
            payload["raw"] = result.raw
    trace.log(stage, f"{provider}.{method}", **payload)


def classify_provider_error(error: str, retry_after: int | None = None) -> str:
    """Bucket a provider failure so the UI can tell the analyst what to do about it."""
    e = (error or "").lower()
    if "quota_exceeded" in e:
        return "quota"
    if retry_after is not None or "rate limit" in e or "429" in e:
        return "rate_limit"
    if (
        "no api key" in e
        or "401" in e
        or "403" in e
        or "invalid key" in e
        or "forbidden" in e
        or "api key is invalid" in e
        or "unauthori" in e
    ):
        return "auth"
    if "circuit_open" in e:
        return "circuit"
    if re.search(r"http 5\d\d", e):
        return "outage"
    if "no provider configured" in e:
        return "not_configured"
    # one target that did not answer — a dead DNS name, a site that will not load, an account that
    # was deleted — is not a provider problem and nothing for the analyst to fix
    if re.search(r"no answer for|navigation failed|browser timeout|net::err_|err_http2|err_connection|"
                 r"profile not found|does not exist or has been deleted|not found\.?$|"
                 r"'[^']+' did not resolve|fetch failed: (connecttimeout|connecterror|readtimeout|remoteprotocolerror)", e):
        return "site"  # a name that does not exist, or a host that never picks up: that one site, not the collector
    if "timeout" in e or "timed out" in e or "connecterror" in e or "readerror" in e:
        return "network"
    return "error"


class FallbackChain:
    """primary → fallback[0] → fallback[1] … ; the first non-error result wins.
    When every provider fails the chain returns one ``error`` result marked *degraded*."""

    def __init__(self, kind: str, providers: list[ResilientProvider]) -> None:
        if not providers:
            raise ValueError("FallbackChain needs at least one provider")
        self.kind = kind
        self.providers = providers

    @property
    def name(self) -> str:
        return f"{self.kind}:" + ">".join(p.name for p in self.providers)

    @property
    def primary(self) -> ResilientProvider:
        return self.providers[0]

    def __getattr__(self, method: str) -> Callable[..., Awaitable[ProviderResult]]:
        for p in self.providers:  # validate the method exists on every member up-front
            getattr(p, method)

        async def call(*args: Any, **kwargs: Any) -> ProviderResult:
            attempts: list[dict[str, Any]] = []
            for p in self.providers:
                result = await getattr(p, method)(*args, **kwargs)
                if result.ok:
                    if attempts:  # an earlier provider failed but this one answered: say so
                        for earlier in self.providers:
                            if earlier is p:
                                break
                            for iss in getattr(earlier, "issues", None) or []:
                                iss.setdefault("recovered_by", p.name)
                    return result
                attempts.append({"provider": p.name, "error": result.error})
            degraded = ProviderResult.failure(
                self.name, "degraded: all providers failed", retry_after=None
            )
            degraded.data = {"attempts": attempts}
            return degraded

        return call
