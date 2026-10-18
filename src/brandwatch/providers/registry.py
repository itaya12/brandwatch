"""Provider factory (spec §4): real ↔ mock selection and primary/fallback wiring.

Under ``DEMO_MODE`` every provider resolves to its mock, so the whole pipeline runs
deterministically at $0. In live mode a mock is **never** used: a provider that needs a key which is
not configured is skipped and the chain continues with the next real provider (e.g. WHOIS without
a WhoisXML key → the local WHOIS client). When nothing real is left the chain answers with an
explicit "not configured" error, so missing keys degrade coverage instead of inventing evidence.
"""

from __future__ import annotations

from typing import Any

from brandwatch.config.settings import Settings
from brandwatch.providers.base import (
    ClockFn,
    FallbackChain,
    ProviderResult,
    ResiliencePolicy,
    ResilientProvider,
    SleepFn,
    UsageLedger,
)
from brandwatch.providers.impl import REAL_PROVIDERS
from brandwatch.providers.mock import MOCKS_BY_KIND

KINDS: tuple[str, ...] = tuple(MOCKS_BY_KIND)


class NotConfiguredProvider:
    """Live-mode stand-in when no real provider of a kind is usable (all need missing keys).
    Every call returns an error result — the pipeline treats it like an unavailable provider."""

    requires_key = False

    def __init__(self, kind: str, skipped: list[str]) -> None:
        self.kind = kind
        self.skipped = skipped
        self.name = f"not-configured:{kind}"
        self.issues: list[dict[str, Any]] = []

    def __getattr__(self, method: str) -> Any:
        if method.startswith("__"):
            raise AttributeError(method)
        missing = ", ".join(self.skipped)

        async def call(*args: Any, **kwargs: Any) -> ProviderResult:
            msg = (
                f"{self.kind}: no provider configured (add an API key for: {missing})"
                if missing
                else f"{self.kind}: no provider available in this version"
            )
            if not self.issues:  # once per scan is enough
                self.issues.append({"provider": self.name, "kind": "not_configured",
                                    "method": method, "error": msg, "retry_after": None,
                                    "candidates": list(self.skipped)})  # fmt: skip
            return ProviderResult.failure(self.name, msg)

        return call


class ProviderRegistry:
    def __init__(
        self,
        settings: Settings,
        *,
        ledger: UsageLedger | None = None,
        policy: ResiliencePolicy | None = None,
        sleep: SleepFn | None = None,
        clock: ClockFn | None = None,
        job_id: Any = None,
        key_overrides: dict[str, str] | None = None,
        route_overrides: dict[str, list[str]] | None = None,
        residential_proxy: str | None = None,
    ) -> None:
        self.settings = settings
        self.route_overrides = dict(route_overrides or {})
        self.residential_proxy = residential_proxy
        self.key_overrides = dict(key_overrides or {})
        self.ledger = ledger
        self.policy = policy
        self._sleep = sleep
        self._clock = clock
        self.job_id = job_id
        self._chains: dict[str, FallbackChain] = {}
        self._singles: dict[str, Any] = {}

    # --- selection -------------------------------------------------------------------------------
    def uses_mock(self, provider_name: str) -> bool:
        if self.settings.demo_mode:
            return True
        cls = REAL_PROVIDERS.get(provider_name)
        if cls is None:
            return True  # unknown provider name → safest is the mock
        if not getattr(cls, "implemented", True):
            return True  # a stub for a later phase: never called in live mode
        return bool(cls.requires_key) and self.key_for(provider_name) is None

    def key_for(self, provider_name: str) -> str | None:
        """Workspace-stored (encrypted) key first, then the environment."""
        return self.key_overrides.get(provider_name) or self.settings.provider_key(provider_name)

    def _build_inner(self, kind: str, provider_name: str) -> Any:
        if self.uses_mock(provider_name):
            return MOCKS_BY_KIND[kind](stand_in_for=provider_name)
        kwargs: dict[str, Any] = {"api_key": self.key_for(provider_name)}
        if provider_name == "playwright":
            proxy = self.residential_proxy or (
                self.settings.residential_proxy_url.get_secret_value()
                if self.settings.residential_proxy_url else None
            )  # fmt: skip
            if proxy:
                kwargs["residential_proxy"] = proxy
        if provider_name == "openai":
            kwargs["model"] = self.settings.openai_model
        return REAL_PROVIDERS[provider_name](**kwargs)

    def _wrap(self, inner: Any) -> ResilientProvider:
        policy = self.policy
        if policy is None and str(getattr(inner, "name", "")).startswith("mock:"):
            policy = ResiliencePolicy(
                rate_per_second=10_000, burst=10_000
            )  # recorded data: no rate limit
        return ResilientProvider(
            inner,
            policy=policy,
            ledger=self.ledger,
            sleep=self._sleep,
            clock=self._clock,
            job_id=self.job_id,
        )

    def get(self, kind: str) -> FallbackChain:
        if kind not in MOCKS_BY_KIND:
            raise KeyError(f"unknown provider kind '{kind}'; known: {sorted(MOCKS_BY_KIND)}")
        chain = self._chains.get(kind)
        if chain is None:
            route = self.settings.providers.get(kind)
            names = [route.primary, *route.fallback] if route else [f"mock-{kind}"]
            if self.route_overrides.get(kind):
                names = list(self.route_overrides[kind])
            if not self.settings.demo_mode:
                usable = [n for n in names if not self.uses_mock(n)]
                if usable:
                    names = usable
                else:  # live mode never falls back to recorded/mock data
                    keyable = [n for n in names
                               if getattr(REAL_PROVIDERS.get(n), "implemented", True)]  # fmt: skip
                    chain = FallbackChain(kind, [NotConfiguredProvider(kind, keyable)])  # type: ignore[list-item]
                    self._chains[kind] = chain
                    return chain
            chain = FallbackChain(kind, [self._wrap(self._build_inner(kind, n)) for n in names])
            self._chains[kind] = chain
        return chain

    def single(self, kind: str, provider_name: str) -> Any | None:
        """One named provider, outside its chain and wrapped like every other call (cache, budget,
        circuit breaker, retry). Used where a specific product is wanted whatever the chain says,
        e.g. WhoisXML's WHOIS history while WHOIS lookups go to RDAP. Live mode: None when it
        cannot be used (no key, or the connector is not built)."""
        if not self.settings.demo_mode and self.uses_mock(provider_name):
            return None
        key = f"{kind}:{provider_name}"
        if key not in self._singles:
            self._singles[key] = self._wrap(self._build_inner(kind, provider_name))
        return self._singles[key]

    # --- typed accessors ---------------------------------------------------------------------------
    def reputation(self) -> FallbackChain:
        return self.get("reputation")

    def whois(self) -> FallbackChain:
        return self.get("whois")

    def dns(self) -> FallbackChain:
        return self.get("dns")

    def passive_dns(self) -> FallbackChain:
        return self.get("passive_dns")

    def cert(self) -> FallbackChain:
        return self.get("cert")

    def search(self) -> FallbackChain:
        return self.get("search")

    def host(self) -> FallbackChain:
        return self.get("host")

    def browser(self) -> FallbackChain:
        return self.get("browser")

    def urlscan(self) -> FallbackChain:
        return self.get("urlscan")

    def geo(self) -> FallbackChain:
        return self.get("geo")

    def llm(self) -> FallbackChain:
        return self.get("llm")

    def ads(self) -> FallbackChain:
        return self.get("ads")

    def social(self) -> FallbackChain:
        return self.get("social")

    def ai_answers(self) -> FallbackChain:
        return self.get("ai_answers")

    def drain_issues(self) -> list[dict[str, Any]]:
        """Provider problems since the last call (quota, rate limit, bad key, outage …)."""
        out: list[dict[str, Any]] = []
        members = [p for chain in self._chains.values() for p in chain.providers]
        for p in members + list(self._singles.values()):
            issues = getattr(p, "issues", None)
            if issues:
                out.extend(issues)
                issues.clear()
        return out

    def describe(self) -> dict[str, list[str]]:
        """``{kind: [provider names in order]}`` — for /health and the Live Console."""
        return {kind: [p.name for p in self.get(kind).providers] for kind in KINDS}
