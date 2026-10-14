"""A MetaMask scan of 53 sites made 3 browser calls and found nothing. Three faults together:

1. the SSRF guard's DNS check gave up after 1.5-3 s and called live pages.dev sites "did not resolve";
2. those one-site failures opened the browser's circuit breaker, so every later site was skipped ("no HTTP answer");
3. ScraperAPI answered Google's own redirect links (google.com/goto?url=…), so the scan "visited" google.com.
"""

from __future__ import annotations

import asyncio

import pytest

from brandwatch.providers.base import (
    ProviderError,
    ProviderResult,
    ProviderStatus,
    ResiliencePolicy,
    ResilientProvider,
)
from brandwatch.providers.impl.clients import ScraperApiClient


class _Browser:
    name = "playwright"
    cost_per_call = 0.0

    def __init__(self, dead: set[str]):
        self.dead, self.calls = dead, 0

    async def fetch(self, url: str, profile: str = "datacenter") -> ProviderResult:
        self.calls += 1
        host = url.split("//")[1].strip("/")
        if host in self.dead:
            raise ProviderError(f"'{host}' did not resolve (no DNS record: nothing was blocked, the name does not exist or was taken down)", retryable=False)
        return ProviderResult(provider=self.name, status=ProviderStatus.POSITIVE, data={"html": "<html></html>"}, raw={}, latency_ms=1)


async def _nosleep(_s: float) -> None:
    await asyncio.sleep(0)


def test_sites_that_do_not_answer_never_switch_the_browser_off_for_the_rest_of_the_scan():
    dead = {f"gone{i}.pages.dev" for i in range(6)}
    inner = _Browser(dead)
    browser = ResilientProvider(inner, policy=ResiliencePolicy(rate_per_second=10_000, burst=10_000, cache_ttl=0), sleep=_nosleep)
    for host in sorted(dead):
        assert not (asyncio.run(browser.fetch(f"https://{host}/"))).ok
    ok = asyncio.run(browser.fetch("https://alive.example/"))
    assert ok.ok and inner.calls == 7  # six dead sites in a row, and the seventh is still opened


def test_a_provider_that_is_really_down_still_opens_the_circuit():
    class Down(_Browser):
        async def fetch(self, url: str, profile: str = "datacenter") -> ProviderResult:
            self.calls += 1
            raise ProviderError("HTTP 503", retryable=False)

    inner = Down(set())
    browser = ResilientProvider(inner, policy=ResiliencePolicy(rate_per_second=10_000, burst=10_000, cache_ttl=0), sleep=_nosleep)
    for i in range(5):
        asyncio.run(browser.fetch(f"https://s{i}.example/"))
    assert inner.calls == 3  # three outages in a row: the next calls are skipped during the cooldown, as before


def test_the_guard_asks_the_system_resolver_when_the_dns_servers_time_out_but_believes_nxdomain(monkeypatch):
    import socket

    import dns.resolver

    from brandwatch.security import fetcher_guard

    class Slow:
        nameservers: list[str] = []
        timeout = lifetime = 0

        def __init__(self, configure: bool = False):
            pass

        def resolve(self, host: str, rtype: str):
            raise dns.resolver.LifetimeTimeout()

    monkeypatch.setattr(dns.resolver, "Resolver", Slow)
    monkeypatch.setattr("brandwatch.detection.dnslookup.service_nameservers", lambda: ["192.0.2.53"])
    monkeypatch.setattr(socket, "getaddrinfo", lambda host, port: [(2, 1, 6, "", ("172.66.44.169", 0))])
    assert [str(ip) for ip in fetcher_guard.default_resolver("metamask--wallet.pages.dev")] == ["172.66.44.169"]

    class Gone(Slow):
        def resolve(self, host: str, rtype: str):
            raise dns.resolver.NXDOMAIN()

    asked = []
    monkeypatch.setattr(dns.resolver, "Resolver", Gone)
    monkeypatch.setattr(socket, "getaddrinfo", lambda host, port: asked.append(host) or [])
    assert fetcher_guard.default_resolver("never-registered.example") == [] and asked == []  # NXDOMAIN is an answer: no second opinion


@pytest.mark.parametrize(("item", "want"), [
    ({"link": "https://metamask-support-help.com/login", "displayed_link": "metamask-support-help.com"}, "https://metamask-support-help.com/login"),
    ({"link": "https://www.google.com/goto?url=CAEStwEB6zswFX_P9s", "displayed_link": "https://metamask.io › download"}, "https://metamask.io"),
    ({"link": "https://www.google.co.uk/goto?url=CAESWQHrOzAV", "displayed_link": "support.metamask.io › hc › en-us"}, "https://support.metamask.io"),
    ({"link": "https://www.google.com/url?q=https://phish.example/x&sa=U"}, "https://phish.example/x"),
    ({"link": "https://play.google.com/store/apps/details?id=io.metamask"}, "https://play.google.com/store/apps/details?id=io.metamask"),
    ({"link": "https://www.google.it/goto?url=CAES", "displayed_link": "MetaMask Wallet"}, None),
])
def test_google_redirect_links_are_turned_into_the_site_they_point_at(item, want):
    assert ScraperApiClient.real_link(item) == want
