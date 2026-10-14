"""Real provider implementations and stubs (spec §4 implementations table).

Phase 1 ships the **keyless, free** implementations the Basic tier needs:

* ``LocalDnsProvider``     — dnspython resolution
* ``LocalWhoisProvider``   — python-whois (port 43)
* ``HttpxBrowserFetcher``  — HTML + favicon through the SSRF-safe ``SafeFetcher`` (no screenshot)
* ``PlaywrightBrowserFetcher`` — sandboxed headless Chromium: rendered DOM + screenshot + favicon
                             (Phase 2, see ``playwright_fetcher.py``)

Everything that needs a paid key is still a stub naming its phase. The registry already selects
real classes over mocks when ``DEMO_MODE=false`` and (where required) a key is configured.
"""

from __future__ import annotations

import asyncio
import hashlib
import time
from datetime import UTC, date, datetime
from typing import Any
from urllib.parse import urljoin

from brandwatch.db.enums import ProviderStatus
from brandwatch.providers.base import ProviderError, ProviderResult
from brandwatch.providers.impl.clients import (
    AbuseIPDBClient,
    CertSpotterClient,
    CrtshClient,
    GeoIpApiClient,
    OpenAIClient,
    RdapClient,
    SafeBrowsingClient,
    ScraperApiClient,
    SerpApiClient,
    ShodanClient,
    UrlhausClient,
    UrlscanClient,
    VirusTotalClient,
    WhoisXmlClient,
)
from brandwatch.providers.impl.playwright_fetcher import PlaywrightBrowserFetcher
from brandwatch.security.fetcher_guard import (
    FetchLimitExceeded,
    FetchProfile,
    SafeFetcher,
    SsrfBlocked,
    guard_message,
)


class _Stub:
    name = "stub"
    requires_key = True
    cost_per_call = 0.0
    phase = "Phase 3"
    implemented = False  # live mode skips it (see ProviderRegistry.uses_mock)
    implemented = False  # live mode skips it (see ProviderRegistry.uses_mock)
    implemented = False  # live mode skips it (see ProviderRegistry.uses_mock)

    def __init__(self, api_key: str | None = None) -> None:
        self._api_key = api_key

    def _todo(self, method: str) -> ProviderResult:
        raise NotImplementedError(f"{self.name}.{method} is implemented in {self.phase}")


# --- reputation --------------------------------------------------------------------------------
class VirusTotalProvider(_Stub):
    name, cost_per_call = "virustotal", 0.0

    async def lookup_domain(self, domain: str) -> ProviderResult:
        return self._todo("lookup_domain")

    async def lookup_ip(self, ip: str) -> ProviderResult:
        return self._todo("lookup_ip")

    async def lookup_url(self, url: str) -> ProviderResult:
        return self._todo("lookup_url")


class UrlhausProvider(VirusTotalProvider):
    name, requires_key = "urlhaus", False


class PhishTankProvider(VirusTotalProvider):
    name, requires_key = "phishtank", False


class SafeBrowsingProvider(VirusTotalProvider):
    name = "safebrowsing"


class AbuseIPDBProvider(VirusTotalProvider):
    name = "abuseipdb"


# --- whois -------------------------------------------------------------------------------------
class WhoisXMLProvider(_Stub):
    name, cost_per_call = "whoisxml", 0.002

    async def lookup(self, domain: str) -> ProviderResult:
        return self._todo("lookup")

    async def history(self, domain: str) -> ProviderResult:
        return self._todo("history")


def _first(value: Any) -> Any:
    if isinstance(value, list | tuple):
        return value[0] if value else None
    return value


class LocalWhoisProvider:
    """python-whois over port 43. Free, rate-limited by registries → degrade on failure."""

    name = "local_whois"
    requires_key = False
    cost_per_call = 0.0

    def __init__(self, api_key: str | None = None) -> None:
        self._api_key = api_key

    async def lookup(self, domain: str) -> ProviderResult:
        import whois  # python-whois; local import keeps module import cheap

        started = time.monotonic()
        try:
            record = await asyncio.to_thread(whois.whois, domain)
        except Exception as exc:  # noqa: BLE001 - registry refusals / timeouts → degraded
            raise ProviderError(f"whois failed: {exc}") from exc
        latency = int((time.monotonic() - started) * 1000)
        created = _first(record.get("creation_date"))
        age_days: int | None = None
        registered_at: str | None = None
        if isinstance(created, datetime):
            created_d = created.date()
        elif isinstance(created, date):
            created_d = created
        else:
            created_d = None
        if created_d is not None:
            registered_at = created_d.isoformat()
            age_days = (datetime.now(UTC).date() - created_d).days
        raw = {k: str(v) for k, v in dict(record).items() if v is not None}
        status = ProviderStatus.POSITIVE if raw.get("domain_name") else ProviderStatus.UNKNOWN
        return ProviderResult(
            provider=self.name,
            status=status,
            data={
                "domain": domain,
                "registered_at": registered_at,
                "age_days": age_days,
                "registrar": _first(record.get("registrar")),
                "registrant": {
                    "org": _first(record.get("org")),
                    "name": _first(record.get("name")),
                },
            },
            raw=raw,
            latency_ms=latency,
        )

    async def history(self, domain: str) -> ProviderResult:
        return ProviderResult(
            self.name, ProviderStatus.NOT_APPLICABLE, {"domain": domain, "records": []}
        )


# --- dns ---------------------------------------------------------------------------------------
class LocalDnsProvider:
    """dnspython resolution through the system resolver."""

    name = "local_dns"
    requires_key = False
    cost_per_call = 0.0

    def __init__(self, api_key: str | None = None) -> None:
        self._api_key = api_key

    async def resolve(self, name: str, rtype: str = "A") -> ProviderResult:
        """A records through the workspace's DNS method (Python from the root, or a public
        resolver service), with its fallback; other record types through the healthy resolvers."""
        from brandwatch.detection import dnslookup

        if rtype == "A":
            records, method = await asyncio.to_thread(dnslookup.a_records, name)
            if records is None:
                raise ProviderError(f"dns: no answer for {name} (method {method})")
        else:
            outcome, ans = await asyncio.to_thread(dnslookup._service_query, name, rtype)
            if outcome == "error":
                raise ProviderError(f"dns: no answer for {name} {rtype}")
            records, method = ([r.to_text() for r in ans] if outcome == "answer" else []), "service"
        status = ProviderStatus.POSITIVE if records else ProviderStatus.NEGATIVE
        return ProviderResult(
            self.name, status, {"name": name, "type": rtype, "records": records, "method": method}
        )

    async def passive_dns(self, value: str) -> ProviderResult:
        return ProviderResult(self.name, ProviderStatus.NOT_APPLICABLE, {"value": value})


class SecurityTrailsProvider(_Stub):
    name, phase = "securitytrails", "Phase 4"

    async def resolve(self, name: str, rtype: str = "A") -> ProviderResult:
        return self._todo("resolve")

    async def passive_dns(self, value: str) -> ProviderResult:
        return self._todo("passive_dns")


# --- certificates ------------------------------------------------------------------------------
class CrtshProvider(_Stub):
    name, requires_key = "crtsh", False

    async def ct_search(self, pattern: str) -> ProviderResult:
        return self._todo("ct_search")

    async def by_fingerprint(self, fingerprint_sha256: str) -> ProviderResult:
        return self._todo("by_fingerprint")


class CensysProvider(CrtshProvider):
    name, requires_key, phase = "censys", True, "Phase 4"

    async def host(self, ip: str) -> ProviderResult:
        return self._todo("host")

    async def favicon_search(self, favicon_mmh3: int) -> ProviderResult:
        return self._todo("favicon_search")


# --- search ------------------------------------------------------------------------------------
class SerpApiProvider(_Stub):
    name, cost_per_call = "serpapi", 0.01

    async def search(self, query: str, geo: str = "us", lang: str = "en") -> ProviderResult:
        return self._todo("search")

    async def reverse_image(self, image_sha256: str) -> ProviderResult:
        return self._todo("reverse_image")


class SerperProvider(SerpApiProvider):
    name, cost_per_call = "serper", 0.001


# --- host --------------------------------------------------------------------------------------
class ShodanProvider(_Stub):
    name, phase = "shodan", "Phase 4"

    async def host(self, ip: str) -> ProviderResult:
        return self._todo("host")

    async def favicon_search(self, favicon_mmh3: int) -> ProviderResult:
        return self._todo("favicon_search")


# --- browser / llm -----------------------------------------------------------------------------


class HttpxBrowserFetcher:
    """Datacenter 'browser' without a browser: HTML + favicon via the SSRF-safe fetcher.

    No screenshot (``screenshot_png`` is None → that evidence is *unavailable*, never clean).
    Same ``data`` keys as the Playwright fetcher so the enrichment stage is backend-agnostic.
    """

    name = "httpx_datacenter"
    requires_key = False
    cost_per_call = 0.0

    def __init__(self, api_key: str | None = None, fetcher: SafeFetcher | None = None) -> None:
        self._fetcher = fetcher or SafeFetcher()

    async def peek(self, url: str) -> ProviderResult:
        """One plain request, no favicon: just what the site answers (status, title, HTML). Used to recognise a
        security product's warning page without launching a browser."""
        from brandwatch.detection.html import extract_features

        try:
            page = await self._fetcher.fetch(url, FetchProfile(name="datacenter"))
        except SsrfBlocked as exc:
            raise ProviderError(guard_message(exc), retryable=False) from exc
        except FetchLimitExceeded as exc:
            raise ProviderError(f"fetch limit: {exc}", retryable=False) from exc
        except Exception as exc:  # noqa: BLE001
            raise ProviderError(f"fetch failed: {type(exc).__name__}: {exc}") from exc
        html = page.body.decode("utf-8", errors="replace")
        return ProviderResult(
            provider=self.name, status=ProviderStatus.POSITIVE, raw={"peek": True}, cost_usd=0.0,
            data={"url": url, "final_url": page.final_url, "profile": "datacenter", "status": page.status,
                  "content_type": page.content_type, "html": html, "title": extract_features(html, page.final_url, []).title,
                  "html_sha256": hashlib.sha256(page.body).hexdigest(), "screenshot_png": None, "favicon_png": None,
                  "redirect_chain": list(page.redirect_chain), "ip": page.ip},
        )  # fmt: skip

    async def fetch(self, url: str, profile: str = "datacenter") -> ProviderResult:
        from brandwatch.detection.html import extract_features

        if profile == "datacenter-proceed":  # the analyst's full check: this collector cannot press through a warning
            profile = "datacenter"
        if profile.startswith("residential"):
            raise ProviderError("the httpx collector has no residential egress", retryable=False)
        fp = FetchProfile(name=profile)
        if profile == "bot":
            fp = FetchProfile(
                name=profile,
                user_agent="Mozilla/5.0 (compatible; BrandWatchBot/0.1; +https://example.invalid/bot)",
            )
        elif profile == "referer":
            fp = FetchProfile(name=profile, referer="https://www.google.com/")
        elif profile == "mobile":  # a phone from the data-centre IP
            from brandwatch.providers.impl.playwright_fetcher import MOBILE_UA

            fp = FetchProfile(name=profile, user_agent=MOBILE_UA)
        try:
            page = await self._fetcher.fetch(url, fp)
        except SsrfBlocked as exc:
            raise ProviderError(guard_message(exc), retryable=False) from exc
        except FetchLimitExceeded as exc:
            raise ProviderError(f"fetch limit: {exc}", retryable=False) from exc
        except Exception as exc:  # noqa: BLE001 - network errors → retryable degrade
            raise ProviderError(f"fetch failed: {type(exc).__name__}: {exc}") from exc

        html = page.body.decode("utf-8", errors="replace")
        favicon: bytes | None = None
        features = extract_features(html, page.final_url, [])
        icon_url = features.favicon_url or urljoin(page.final_url, "/favicon.ico")
        try:
            icon = await self._fetcher.fetch(icon_url, FetchProfile(name=profile))
            if (
                icon.status == 200
                and icon.body
                and (
                    (icon.content_type or "").startswith("image/")
                    or icon.body[:4] == b"\x89PNG"
                    or icon.body[:4] == b"\x00\x00\x01\x00"
                )
            ):
                favicon = icon.body
        except Exception:  # noqa: BLE001 - a missing favicon is not an error
            favicon = None

        return ProviderResult(
            provider=self.name,
            status=ProviderStatus.POSITIVE,
            data={
                "url": url,
                "final_url": page.final_url,
                "profile": profile,
                "status": page.status,
                "content_type": page.content_type,
                "html": html,
                "html_sha256": hashlib.sha256(page.body).hexdigest(),
                "screenshot_png": None,
                "favicon_png": favicon,
                "redirect_chain": list(page.redirect_chain),
                "ip": page.ip,
            },
            raw={"headers": page.headers, "status": page.status},
            latency_ms=page.elapsed_ms,
        )


class OpenAIProvider(_Stub):
    name, cost_per_call, phase = "openai", 0.01, "Phase 5"

    async def analyze(self, text: str, schema: dict[str, Any]) -> ProviderResult:
        return self._todo("analyze")


from brandwatch.providers.impl.commerce import COMMERCE_CLIENTS  # noqa: E402

REAL_PROVIDERS: dict[str, type] = {
    cls.name: cls
    for cls in (
        VirusTotalProvider,
        UrlhausProvider,
        PhishTankProvider,
        SafeBrowsingProvider,
        AbuseIPDBProvider,
        WhoisXMLProvider,
        LocalWhoisProvider,
        LocalDnsProvider,
        SecurityTrailsProvider,
        CrtshProvider,
        CensysProvider,
        SerpApiProvider,
        SerperProvider,
        ShodanProvider,
        PlaywrightBrowserFetcher,
        HttpxBrowserFetcher,
        OpenAIProvider,
    )
}
# Phase 3/4: real HTTP clients override the stubs of the same name.
for _cls in (
    CertSpotterClient,
    CrtshClient,
    UrlhausClient,
    VirusTotalClient,
    ScraperApiClient,
    SerpApiClient,
    UrlscanClient,
    ShodanClient,
    WhoisXmlClient,
    RdapClient,
    SafeBrowsingClient,
    AbuseIPDBClient,
):
    REAL_PROVIDERS[_cls.name] = _cls
REAL_PROVIDERS[GeoIpApiClient.name] = GeoIpApiClient
for _cls in COMMERCE_CLIENTS:  # Meta ads (SearchApi.io) and company registries
    REAL_PROVIDERS[_cls.name] = _cls
REAL_PROVIDERS[OpenAIClient.name] = OpenAIClient
