"""SSRF-safe fetching of attacker-supplied URLs (spec §7).

The system fetches URLs that attackers chose, so the fetcher defends itself:

1. ``validate_url``      — scheme / port / userinfo / hostname blocklist; IDN → punycode.
2. ``resolve_and_validate`` — resolve A/AAAA, unwrap IPv4-mapped IPv6, and reject if **any**
   address is private / loopback / link-local / metadata / otherwise non-global (fail-closed).
3. ``SafeFetcher``        — connects to the *validated IP* (URL host swapped for the IP, ``Host``
   header + TLS SNI carry the original hostname) so a DNS-rebinding attacker cannot change the
   destination between validation and connect; follows redirects manually and re-validates every
   hop; caps redirects, response size, timeout and content type.

Every cap comes from :data:`brandwatch.security.limits.SYSTEM_LIMITS`; nothing here is brand-
configurable.
"""

from __future__ import annotations

import hashlib
import ipaddress
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from ipaddress import IPv4Address, IPv6Address
from urllib.parse import SplitResult, urljoin, urlsplit, urlunsplit

import httpx

from brandwatch.security.limits import SYSTEM_LIMITS, SystemLimits

IPAddress = IPv4Address | IPv6Address
Resolver = Callable[[str], Sequence[IPAddress]]

_DEFAULT_PORTS = {"http": 80, "https": 443}


class SsrfBlocked(Exception):
    """The target was rejected before any connection was made."""


class SsrfUnresolved(SsrfBlocked):
    """The name has no DNS answer: nothing dangerous was refused, there is simply no site (a taken-down or never-registered name)."""


def guard_message(exc: SsrfBlocked) -> str:
    """What an analyst reads: a refusal is a refusal, a name that does not exist is not a security event."""
    if isinstance(exc, SsrfUnresolved):
        return f"{exc} (no DNS record: nothing was blocked, the name does not exist or was taken down)"
    return f"blocked by SSRF guard: {exc}"


class FetchLimitExceeded(Exception):
    """A system limit (size / redirects / content type) was hit during the fetch."""


@dataclass(frozen=True, slots=True)
class ParsedTarget:
    scheme: str
    host: str  # ASCII (punycode) lowercase hostname, or IP literal
    port: int
    path: str  # path + query, always starting with "/"
    url: str  # normalized URL

    @property
    def is_ip_literal(self) -> bool:
        return _parse_ip(self.host) is not None

    @property
    def host_header(self) -> str:
        if self.port == _DEFAULT_PORTS[self.scheme]:
            return self.host
        return f"{self.host}:{self.port}"


@dataclass(frozen=True, slots=True)
class FetchProfile:
    """Request profile (datacenter / residential / ...). Phase 0 ships datacenter only."""

    name: str = "datacenter"
    user_agent: str = "Mozilla/5.0 (compatible; BrandWatch/0.1; +https://example.invalid/bot)"
    referer: str | None = None
    extra_headers: dict[str, str] = field(default_factory=dict)
    proxy: str | None = None  # residential proxies arrive in Phase 5


@dataclass(frozen=True, slots=True)
class FetchResult:
    url: str
    final_url: str
    status: int
    headers: dict[str, str]
    body: bytes
    redirect_chain: tuple[str, ...]
    ip: str
    elapsed_ms: int
    sha256: str
    content_type: str | None


# --------------------------------------------------------------------------------------------
# Validation
# --------------------------------------------------------------------------------------------
def _parse_ip(value: str) -> IPAddress | None:
    try:
        return ipaddress.ip_address(value.strip("[]"))
    except ValueError:
        return None


def is_blocked_ip(ip: IPAddress, limits: SystemLimits = SYSTEM_LIMITS) -> bool:
    """True if connecting to ``ip`` could reach something that is not the public internet."""
    if isinstance(ip, IPv6Address) and ip.ipv4_mapped is not None:
        return True  # mapped form itself is suspicious; the unwrapped v4 is also checked by callers
    if any(ip in net for net in limits.BLOCKED_NETWORKS):
        return True
    if limits.BLOCK_PRIVATE_IPS and not ip.is_global:
        return True
    return False


def _unwrap(ip: IPAddress) -> IPAddress:
    if isinstance(ip, IPv6Address) and ip.ipv4_mapped is not None:
        return ip.ipv4_mapped
    return ip


def _hostname_blocked(host: str, limits: SystemLimits) -> str | None:
    if host in limits.BLOCKED_HOSTNAMES:
        return f"hostname '{host}' is blocked"
    for suffix in limits.BLOCKED_HOSTNAME_SUFFIXES:
        if host.endswith(suffix):
            return f"hostname suffix '{suffix}' is blocked"
    if "." not in host:
        return "single-label hostnames are blocked (would resolve via internal search domains)"
    return None


def validate_url(url: str, limits: SystemLimits = SYSTEM_LIMITS) -> ParsedTarget:
    """Syntactic + policy validation. Raises :class:`SsrfBlocked`. Makes no network calls."""
    try:
        parts: SplitResult = urlsplit(url.strip())
    except ValueError as exc:  # pragma: no cover - urlsplit rarely raises
        raise SsrfBlocked(f"unparseable URL: {exc}") from exc

    scheme = parts.scheme.lower()
    if scheme not in limits.ALLOWED_SCHEMES:
        raise SsrfBlocked(f"scheme '{scheme or '<none>'}' not allowed")
    if parts.username is not None or parts.password is not None:
        raise SsrfBlocked("userinfo in URL not allowed")
    raw_host = parts.hostname
    if not raw_host:
        raise SsrfBlocked("URL has no host")

    try:
        host = raw_host.encode("idna").decode("ascii").lower().rstrip(".")
    except UnicodeError as exc:
        raise SsrfBlocked(f"invalid IDN hostname: {exc}") from exc
    if not host:
        raise SsrfBlocked("URL has no host")

    try:
        port = parts.port or _DEFAULT_PORTS[scheme]
    except ValueError as exc:
        raise SsrfBlocked(f"invalid port: {exc}") from exc
    if port not in limits.ALLOWED_PORTS:
        raise SsrfBlocked(f"port {port} not allowed")

    literal = _parse_ip(host)
    if literal is not None:
        if is_blocked_ip(literal, limits) or is_blocked_ip(_unwrap(literal), limits):
            raise SsrfBlocked(f"IP literal {literal} is blocked")
        host = str(literal)
    else:
        reason = _hostname_blocked(host, limits)
        if reason:
            raise SsrfBlocked(reason)

    path = parts.path or "/"
    if parts.query:
        path = f"{path}?{parts.query}"
    netloc = f"[{host}]" if ":" in host else host
    if port != _DEFAULT_PORTS[scheme]:
        netloc = f"{netloc}:{port}"
    normalized = urlunsplit((scheme, netloc, parts.path or "/", parts.query, ""))
    return ParsedTarget(scheme=scheme, host=host, port=port, path=path, url=normalized)


def default_resolver(host: str) -> list[IPAddress]:
    """A + AAAA through the scan's healthy resolvers (the system DNS may be broken — a dead VPN
    adapter or a filtering router — which would wrongly block every fetch). Returns [] on
    NXDOMAIN / no A record / no answer."""
    import dns.resolver

    from brandwatch.detection import dnslookup

    servers = dnslookup.service_nameservers()
    res = dns.resolver.Resolver(configure=False)
    if servers:
        res.nameservers = servers[:3]
    # a cold cache behind a home router can take seconds: 1.5 s / 3 s made live sites "not resolve"
    res.timeout, res.lifetime = 2.5, 6.0
    answers: list[IPAddress] = []
    definite = False  # NXDOMAIN or "no such record": the name really has no address
    for rtype in ("A", "AAAA"):
        try:
            for rdata in res.resolve(host, rtype):
                parsed = _parse_ip(rdata.address)
                if parsed is not None:
                    answers.append(parsed)
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            definite = True
            continue
        except Exception:  # noqa: BLE001 - a timeout or no reachable server: unsure, asked again below
            continue
        if answers:
            break  # an A answer is enough to check the target
    if not answers and not definite:  # every server timed out: the operating system's resolver gets a say
        import socket

        try:
            for info in socket.getaddrinfo(host, None):
                parsed = _parse_ip(str(info[4][0]))
                if parsed is not None and parsed not in answers:
                    answers.append(parsed)
        except OSError:
            pass
    return answers


def resolve_and_validate(
    host: str,
    resolver: Resolver | None = None,
    limits: SystemLimits = SYSTEM_LIMITS,
) -> list[IPAddress]:
    """Resolve ``host`` and reject if any address is blocked (fail-closed)."""
    literal = _parse_ip(host)
    if literal is not None:
        if is_blocked_ip(literal, limits) or is_blocked_ip(_unwrap(literal), limits):
            raise SsrfBlocked(f"IP literal {literal} is blocked")
        return [literal]

    ips = list((resolver or default_resolver)(host))
    if not ips:
        raise SsrfUnresolved(f"'{host}' did not resolve")
    for ip in ips:
        if is_blocked_ip(ip, limits) or is_blocked_ip(_unwrap(ip), limits):
            raise SsrfBlocked(f"'{host}' resolves to blocked address {ip}")
    return ips


# --------------------------------------------------------------------------------------------
# Fetching
# --------------------------------------------------------------------------------------------
def _pinned_url(target: ParsedTarget, ip: IPAddress) -> str:
    host = f"[{ip}]" if isinstance(ip, IPv6Address) else str(ip)
    netloc = host if target.port == _DEFAULT_PORTS[target.scheme] else f"{host}:{target.port}"
    return f"{target.scheme}://{netloc}{target.path}"


def _content_type_allowed(content_type: str | None, limits: SystemLimits) -> bool:
    if not content_type:
        return True  # missing header: let the parser decide
    ct = content_type.split(";", 1)[0].strip().lower()
    return any(ct.startswith(prefix) for prefix in limits.ALLOWED_CONTENT_TYPE_PREFIXES)


class SafeFetcher:
    """Datacenter HTTP fetcher wrapped in the SSRF guard. One instance is reusable."""

    def __init__(
        self,
        *,
        resolver: Resolver | None = None,
        limits: SystemLimits = SYSTEM_LIMITS,
        transport: httpx.AsyncBaseTransport | None = None,
        verify: bool = True,
    ) -> None:
        self._resolver = resolver
        self._limits = limits
        self._transport = transport
        self._verify = verify

    def _client(self) -> httpx.AsyncClient:
        timeout = httpx.Timeout(self._limits.FETCH_TIMEOUT, connect=self._limits.CONNECT_TIMEOUT)
        return httpx.AsyncClient(
            transport=self._transport,
            follow_redirects=False,
            timeout=timeout,
            verify=self._verify,
            max_redirects=0,
        )

    async def fetch(self, url: str, profile: FetchProfile | None = None) -> FetchResult:
        profile = profile or FetchProfile()
        limits = self._limits
        started = time.monotonic()
        chain: list[str] = []
        current = url

        async with self._client() as client:
            for _hop in range(limits.MAX_REDIRECTS + 1):
                target = validate_url(current, limits)
                ip = resolve_and_validate(target.host, self._resolver, limits)[0]

                headers = {
                    "Host": target.host_header,
                    "User-Agent": profile.user_agent,
                    "Accept": "text/html,application/xhtml+xml,*/*;q=0.8",
                    **profile.extra_headers,
                }
                if profile.referer:
                    headers["Referer"] = profile.referer

                request = client.build_request(
                    "GET",
                    _pinned_url(target, ip),
                    headers=headers,
                    extensions={"sni_hostname": target.host} if target.scheme == "https" else {},
                )
                response = await client.send(request, stream=True)
                try:
                    if response.is_redirect and response.headers.get("location"):
                        chain.append(target.url)
                        current = urljoin(target.url, response.headers["location"])
                        continue

                    content_type = response.headers.get("content-type")
                    if not _content_type_allowed(content_type, limits):
                        raise FetchLimitExceeded(f"content-type '{content_type}' not allowed")
                    declared = response.headers.get("content-length")
                    if declared and declared.isdigit() and int(declared) > limits.MAX_RESPONSE_SIZE:
                        raise FetchLimitExceeded(
                            f"declared content-length {declared} exceeds MAX_RESPONSE_SIZE"
                        )

                    body = bytearray()
                    async for chunk in response.aiter_bytes():
                        body.extend(chunk)
                        if len(body) > limits.MAX_RESPONSE_SIZE:
                            raise FetchLimitExceeded("response exceeds MAX_RESPONSE_SIZE")
                finally:
                    await response.aclose()

                return FetchResult(
                    url=url,
                    final_url=target.url,
                    status=response.status_code,
                    headers=dict(response.headers),
                    body=bytes(body),
                    redirect_chain=tuple(chain),
                    ip=str(ip),
                    elapsed_ms=int((time.monotonic() - started) * 1000),
                    sha256=hashlib.sha256(body).hexdigest(),
                    content_type=content_type,
                )

        raise FetchLimitExceeded(f"more than {limits.MAX_REDIRECTS} redirects")
