"""Residential / mobile proxy for the Tier-4 cloaking probe (and only that — never for attacks).

Two modes, chosen in Settings → Residential proxy:

* ``manual``   — any proxy: host, port, username, password. Used verbatim.
* ``webshare`` — Webshare rotating residential. The analyst pastes their API token; the token
                 fetches the proxy username/password from Webshare's API, and a country is applied
                 the Webshare way (``<user>-rotate-<cc>``), so each probe rotates to a fresh
                 residential IP in that country.

The non-secret parts (mode, host, port, username, rotating) live in the workspace settings; the
password and the Webshare token are stored encrypted in the key store. The country for a scan
comes from the brand (its search country / language), so a brand aimed at a US-English audience is
probed from a US residential IP — that is where its real users, and its phishing victims, are.
"""

from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import quote

import httpx

_UA = "BrandWatch/0.1 (+phishing-domain-intelligence; abuse-reporting tool)"
_WEBSHARE_HOST = "p.webshare.io"
_WEBSHARE_PORT = 80

# brand language → default residential country (ISO-3166 alpha-2), when the brand sets no country
LANG_COUNTRY: dict[str, str] = {
    "en": "us", "he": "il", "iw": "il", "de": "de", "fr": "fr", "es": "es", "pt": "br",
    "it": "it", "nl": "nl", "ru": "ru", "pl": "pl", "tr": "tr", "ar": "ae", "ja": "jp",
    "ko": "kr", "zh": "cn", "hi": "in", "id": "id", "th": "th", "vi": "vn", "sv": "se",
}  # fmt: skip


def country_for(geo: str | None, lang: str | None) -> str:
    """The residential country for a scan: the brand's search country, else its language's
    home country, else the US."""
    geo = (geo or "").strip().lower()
    if len(geo) == 2 and geo.isalpha():
        return geo
    return LANG_COUNTRY.get((lang or "").strip().lower()[:2], "us")


@dataclass(frozen=True)
class ProxyConfig:
    mode: str = "off"  # off | manual | webshare
    kind: str = "residential"  # residential (home broadband) | mobile (a 4G / 5G carrier's addresses)
    host: str = ""
    port: int = 0
    username: str = ""
    password: str = ""
    rotating: bool = True  # webshare: rotate to a new IP each request

    @property
    def enabled(self) -> bool:
        return self.mode in ("manual", "webshare") and bool(self.host and self.username)

    def username_for(self, country: str | None) -> str:
        """Webshare encodes rotation and country in the username (<user>-rotate-<cc>)."""
        if self.mode != "webshare":
            return self.username
        user = self.username.split("-rotate")[0].split("-country")[0]
        parts = [user]
        if self.rotating:
            parts.append("rotate")
        cc = (country or "").strip().lower()
        if cc and cc != "worldwide":
            parts += ["country", cc]
        return "-".join(parts)

    def url(self, country: str | None = None) -> str:
        """``http://user:pass@host:port`` with the country applied. Credentials are URL-encoded."""
        user = quote(self.username_for(country), safe="")
        pw = quote(self.password, safe="")
        auth = f"{user}:{pw}@" if user else ""
        return f"http://{auth}{self.host}:{self.port}"


def from_stored(
    config: dict | None, password: str | None, webshare_creds: tuple[str, str] | None
) -> ProxyConfig:
    """Build the proxy config from the stored (non-secret) settings and the decrypted secrets.
    For ``webshare`` the username/password come from the Webshare API lookup (``webshare_creds``)."""
    config = config or {}
    mode = config.get("mode", "off")
    if mode == "webshare":
        if not webshare_creds:
            return ProxyConfig(mode="webshare")  # not usable until the token resolves
        user, pw = webshare_creds
        return ProxyConfig(
            mode="webshare", host=config.get("host") or _WEBSHARE_HOST,
            port=int(config.get("port") or _WEBSHARE_PORT), username=user, password=pw,
            rotating=bool(config.get("rotating", True)),
        )  # fmt: skip
    if mode == "manual":
        return ProxyConfig(
            mode="manual", host=config.get("host", ""), port=int(config.get("port") or 0),
            username=config.get("username", ""), password=password or "",
            rotating=bool(config.get("rotating", False)),
        )  # fmt: skip
    return ProxyConfig(mode="off")


def from_stored_mobile(config: dict | None, password: str | None) -> ProxyConfig:
    """The mobile proxy: any provider's 4G / 5G proxy by host, port, username and password (Webshare sells none)."""
    config = config or {}
    if config.get("mode") != "manual":
        return ProxyConfig(mode="off", kind="mobile")
    return ProxyConfig(mode="manual", kind="mobile", host=config.get("host", ""), port=int(config.get("port") or 0),
                       username=config.get("username", ""), password=password or "", rotating=False)  # fmt: skip


async def webshare_credentials(token: str) -> tuple[str, str]:
    """The default rotating-proxy username/password for a Webshare account, from its API token.
    Raises ``ProxyError`` with the API's message on failure (bad token, no plan …)."""
    headers = {"Authorization": f"Token {token.strip()}", "User-Agent": _UA}
    transport = httpx.AsyncHTTPTransport(local_address="0.0.0.0")  # this network's IPv6 is broken
    async with httpx.AsyncClient(timeout=15, transport=transport) as c:
        r = await c.get("https://proxy.webshare.io/api/v2/proxy/config/", headers=headers)
        if r.status_code in (401, 403):
            raise ProxyError("Webshare rejected the API token (check Settings on webshare.io)")
        if r.status_code >= 400:
            raise ProxyError(f"Webshare API error HTTP {r.status_code}: {r.text[:120]}")
        data = r.json()
    user, pw = data.get("username"), data.get("password")
    if not user or not pw:
        raise ProxyError("Webshare returned no proxy username/password for this account")
    return str(user), str(pw)


async def test_proxy(url: str) -> dict:
    """Send one request through the proxy and report the egress IP and its country, so the analyst
    can confirm the proxy works and lands in the expected country."""
    transport = httpx.AsyncHTTPTransport(local_address="0.0.0.0")
    try:
        async with httpx.AsyncClient(proxy=url, timeout=20, transport=transport) as c:
            r = await c.get("https://ipv4.webshare.io/")
            ip = r.text.strip()
    except Exception as exc:  # noqa: BLE001
        raise ProxyError(
            f"could not reach the internet through the proxy: {type(exc).__name__}"
        ) from exc
    geo: dict = {"ip": ip}
    try:
        async with httpx.AsyncClient(timeout=10, transport=transport) as c:
            g = (
                await c.get(f"http://ip-api.com/json/{ip}?fields=country,countryCode,city,isp")
            ).json()
        geo.update(
            country=g.get("country"),
            country_code=g.get("countryCode"),
            city=g.get("city"),
            isp=g.get("isp"),
        )
    except Exception:  # noqa: BLE001 - the IP alone already proves the proxy works
        pass
    return geo


class ProxyError(Exception):
    pass
