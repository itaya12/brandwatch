"""SSRF guard + immutable system limits (Phase 0 DoD)."""

from __future__ import annotations

import dataclasses
import ipaddress

import httpx
import pytest
import respx

from brandwatch.config.brand_config import BrandConfig
from brandwatch.config.settings import Settings
from brandwatch.security.fetcher_guard import (
    FetchLimitExceeded,
    SafeFetcher,
    SsrfBlocked,
    is_blocked_ip,
    resolve_and_validate,
    validate_url,
)
from brandwatch.security.limits import SYSTEM_LIMIT_NAMES, SYSTEM_LIMITS, SystemLimits

PUBLIC_IP = ipaddress.ip_address("93.184.216.34")


def resolver_returning(*ips: str):
    parsed = [ipaddress.ip_address(ip) for ip in ips]
    return lambda _host: list(parsed)


# --------------------------------------------------------------------------------------------
# IP policy
# --------------------------------------------------------------------------------------------
@pytest.mark.parametrize(
    "ip",
    [
        "0.0.0.0",
        "10.0.0.1",
        "100.64.0.1",
        "127.0.0.1",
        "127.1.2.3",
        "169.254.169.254",  # cloud metadata
        "169.254.1.1",
        "172.16.5.5",
        "172.31.255.255",
        "192.0.0.1",
        "192.168.1.1",
        "198.18.0.1",
        "224.0.0.1",
        "255.255.255.255",
        "::",
        "::1",
        "::ffff:127.0.0.1",  # IPv4-mapped loopback
        "::ffff:10.0.0.1",
        "64:ff9b::7f00:1",  # NAT64 → 127.0.0.1
        "fc00::1",
        "fd00::1",
        "fe80::1",
        "fd00:ec2::254",  # AWS IMDS v6
        "2001:db8::1",
    ],
)
def test_blocked_addresses(ip):
    assert is_blocked_ip(ipaddress.ip_address(ip)) is True


@pytest.mark.parametrize("ip", ["93.184.216.34", "8.8.8.8", "1.1.1.1", "2606:4700:4700::1111"])
def test_public_addresses_allowed(ip):
    assert is_blocked_ip(ipaddress.ip_address(ip)) is False


# --------------------------------------------------------------------------------------------
# URL validation (no network)
# --------------------------------------------------------------------------------------------
@pytest.mark.parametrize(
    "url, reason",
    [
        ("file:///etc/passwd", "scheme"),
        ("ftp://example.com/", "scheme"),
        ("javascript:alert(1)", "scheme"),
        ("gopher://example.com/", "scheme"),
        ("http://user:pw@example.com/", "userinfo"),
        ("http://example.com:22/", "port"),
        ("http://example.com:6379/", "port"),
        ("http://127.0.0.1/", "blocked"),
        ("http://169.254.169.254/latest/meta-data/", "blocked"),
        ("http://[::1]/", "blocked"),
        ("http://[::ffff:169.254.169.254]/", "blocked"),
        ("http://localhost/", "blocked"),
        ("http://metadata.google.internal/computeMetadata/v1/", "blocked"),
        ("http://db.internal/", "blocked"),
        ("http://router.local/", "blocked"),
        ("http://intranet/", "single-label"),
        ("http:///path", "no host"),
    ],
)
def test_validate_url_rejects(url, reason):
    with pytest.raises(SsrfBlocked, match=reason):
        validate_url(url)


def test_validate_url_normalizes_and_handles_idn():
    t = validate_url("HTTPS://ShopNova.Example.com./login?x=1#frag")
    assert t.scheme == "https"
    assert t.host == "shopnova.example.com"
    assert t.port == 443
    assert t.path == "/login?x=1"
    assert t.url == "https://shopnova.example.com/login?x=1"
    idn = validate_url("https://pаypal.com/")  # Cyrillic 'а' homoglyph
    assert idn.host.startswith("xn--")


def test_validate_url_non_default_allowed_port():
    t = validate_url("https://example.com:8443/a")
    assert t.port == 8443
    assert t.host_header == "example.com:8443"


# --------------------------------------------------------------------------------------------
# Resolution (fail-closed)
# --------------------------------------------------------------------------------------------
def test_resolve_rejects_if_any_answer_is_private():
    resolver = resolver_returning("93.184.216.34", "10.0.0.5")
    with pytest.raises(SsrfBlocked, match="blocked address 10.0.0.5"):
        resolve_and_validate("evil.example", resolver)


def test_resolve_rejects_unresolvable():
    with pytest.raises(SsrfBlocked, match="did not resolve"):
        resolve_and_validate("nxdomain.example", lambda _h: [])


def test_resolve_accepts_public():
    assert resolve_and_validate("ok.example", resolver_returning("93.184.216.34")) == [PUBLIC_IP]


# --------------------------------------------------------------------------------------------
# SafeFetcher (httpx mocked with respx)
# --------------------------------------------------------------------------------------------
@pytest.fixture
def fetcher():
    return SafeFetcher(resolver=resolver_returning(str(PUBLIC_IP)), verify=False)


@respx.mock
async def test_fetch_pins_connection_to_validated_ip(fetcher):
    """Rebinding defence: the socket goes to the IP we validated; Host/SNI carry the hostname."""
    route = respx.get(f"https://{PUBLIC_IP}/login").mock(
        return_value=httpx.Response(
            200, text="<html>ok</html>", headers={"content-type": "text/html"}
        )
    )
    result = await fetcher.fetch("https://shopn0va.example/login")
    assert route.called
    request = route.calls.last.request
    assert request.url.host == str(PUBLIC_IP)
    assert request.headers["host"] == "shopn0va.example"
    assert request.extensions["sni_hostname"] == "shopn0va.example"
    assert result.status == 200
    assert result.ip == str(PUBLIC_IP)
    assert result.final_url == "https://shopn0va.example/login"
    assert result.sha256 == __import__("hashlib").sha256(b"<html>ok</html>").hexdigest()


@respx.mock
async def test_fetch_rejects_redirect_to_metadata(fetcher):
    respx.get(f"https://{PUBLIC_IP}/").mock(
        return_value=httpx.Response(
            302, headers={"location": "http://169.254.169.254/latest/meta-data/"}
        )
    )
    with pytest.raises(SsrfBlocked, match="blocked"):
        await fetcher.fetch("https://shopn0va.example/")


@respx.mock
async def test_fetch_rejects_redirect_to_private_hostname():
    calls = {"n": 0}

    def resolver(host):
        calls["n"] += 1
        return [PUBLIC_IP] if host == "shopn0va.example" else [ipaddress.ip_address("10.0.0.9")]

    f = SafeFetcher(resolver=resolver, verify=False)
    respx.get(f"https://{PUBLIC_IP}/").mock(
        return_value=httpx.Response(301, headers={"location": "https://backend.example/"})
    )
    with pytest.raises(SsrfBlocked, match="blocked address 10.0.0.9"):
        await f.fetch("https://shopn0va.example/")
    assert calls["n"] == 2  # every hop is re-resolved and re-validated


@respx.mock
async def test_fetch_follows_redirects_and_records_chain(fetcher):
    respx.get(f"https://{PUBLIC_IP}/a").mock(
        return_value=httpx.Response(302, headers={"location": "/b"})
    )
    respx.get(f"https://{PUBLIC_IP}/b").mock(
        return_value=httpx.Response(200, text="done", headers={"content-type": "text/plain"})
    )
    result = await fetcher.fetch("https://shopn0va.example/a")
    assert result.status == 200
    assert result.redirect_chain == ("https://shopn0va.example/a",)
    assert result.final_url == "https://shopn0va.example/b"


@respx.mock
async def test_fetch_caps_redirects(fetcher):
    respx.get(url__regex=rf"https://{PUBLIC_IP}/.*").mock(
        return_value=httpx.Response(302, headers={"location": "/loop"})
    )
    with pytest.raises(FetchLimitExceeded, match="redirects"):
        await fetcher.fetch("https://shopn0va.example/loop")


@respx.mock
async def test_fetch_caps_streamed_body_size():
    limits = SystemLimits(MAX_RESPONSE_SIZE=100)
    f = SafeFetcher(resolver=resolver_returning(str(PUBLIC_IP)), limits=limits, verify=False)
    respx.get(f"https://{PUBLIC_IP}/big").mock(
        return_value=httpx.Response(200, content=b"x" * 101, headers={"content-type": "text/html"})
    )
    with pytest.raises(FetchLimitExceeded, match="MAX_RESPONSE_SIZE"):
        await f.fetch("https://shopn0va.example/big")


@respx.mock
async def test_fetch_rejects_declared_oversize():
    limits = SystemLimits(MAX_RESPONSE_SIZE=100)
    f = SafeFetcher(resolver=resolver_returning(str(PUBLIC_IP)), limits=limits, verify=False)
    respx.get(f"https://{PUBLIC_IP}/big").mock(
        return_value=httpx.Response(
            200, content=b"x", headers={"content-type": "text/html", "content-length": "5000000"}
        )
    )
    with pytest.raises(FetchLimitExceeded, match="content-length"):
        await f.fetch("https://shopn0va.example/big")


@respx.mock
async def test_fetch_rejects_disallowed_content_type(fetcher):
    respx.get(f"https://{PUBLIC_IP}/x.exe").mock(
        return_value=httpx.Response(
            200, content=b"MZ", headers={"content-type": "application/x-msdownload"}
        )
    )
    with pytest.raises(FetchLimitExceeded, match="content-type"):
        await fetcher.fetch("https://shopn0va.example/x.exe")


async def test_fetch_never_connects_for_blocked_url(fetcher):
    with pytest.raises(SsrfBlocked):
        await fetcher.fetch("http://169.254.169.254/latest/")


# --------------------------------------------------------------------------------------------
# System limits are immutable and never configurable
# --------------------------------------------------------------------------------------------
def test_system_limits_are_frozen():
    with pytest.raises(dataclasses.FrozenInstanceError):
        SYSTEM_LIMITS.MAX_REDIRECTS = 99  # type: ignore[misc]


def test_system_limits_not_in_settings():
    settings_fields = {f.lower() for f in Settings.model_fields}
    leaked = {n for n in SYSTEM_LIMIT_NAMES if n.lower() in settings_fields}
    assert leaked == set()


def test_brand_config_cannot_set_security_limits():
    from pydantic import ValidationError

    with pytest.raises(ValidationError):
        BrandConfig.model_validate({"MAX_RESPONSE_SIZE": 10**9})
    with pytest.raises(ValidationError):
        BrandConfig.model_validate({"detection": {"BLOCK_PRIVATE_IPS": False}})


def test_a_name_without_dns_is_not_reported_as_a_security_block():
    from brandwatch.security.fetcher_guard import (
        SsrfBlocked,
        SsrfUnresolved,
        guard_message,
        resolve_and_validate,
    )

    with pytest.raises(SsrfUnresolved) as gone:
        resolve_and_validate("metamask-loging--run.pages.dev", resolver=lambda host: [])
    assert isinstance(gone.value, SsrfBlocked)  # still refused, and every caller that catches SsrfBlocked keeps working
    text = guard_message(gone.value)
    assert "did not resolve" in text and "nothing was blocked" in text and "blocked by SSRF guard" not in text
    with pytest.raises(SsrfBlocked) as bad:
        resolve_and_validate("evil.example", resolver=lambda host: [ipaddress.ip_address("10.0.0.5")])
    assert not isinstance(bad.value, SsrfUnresolved) and guard_message(bad.value).startswith("blocked by SSRF guard: ")
