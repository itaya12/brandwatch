"""System Security Limits — immutable, global, never brand-overridable (spec §7, §13).

These are deliberately NOT part of ``brandwatch.config.settings.Settings``: a brand config or an
environment variable can never weaken them. Production code must only ever reference
``SYSTEM_LIMITS``; tests may construct a ``SystemLimits`` with smaller values to exercise caps.
"""

from __future__ import annotations

from dataclasses import dataclass
from ipaddress import IPv4Network, IPv6Network, ip_network
from typing import Final

_BLOCKED_NETWORKS: tuple[IPv4Network | IPv6Network, ...] = tuple(
    ip_network(n)
    for n in (
        # IPv4
        "0.0.0.0/8",  # "this" network
        "10.0.0.0/8",  # RFC1918
        "100.64.0.0/10",  # CGNAT shared address space
        "127.0.0.0/8",  # loopback
        "169.254.0.0/16",  # link-local incl. cloud metadata 169.254.169.254
        "172.16.0.0/12",  # RFC1918
        "192.0.0.0/24",  # IETF protocol assignments
        "192.0.2.0/24",  # TEST-NET-1
        "192.168.0.0/16",  # RFC1918
        "198.18.0.0/15",  # benchmarking
        "198.51.100.0/24",  # TEST-NET-2
        "203.0.113.0/24",  # TEST-NET-3
        "224.0.0.0/4",  # multicast
        "240.0.0.0/4",  # reserved + broadcast
        # IPv6
        "::/128",  # unspecified
        "::1/128",  # loopback
        "::ffff:0:0/96",  # IPv4-mapped (also unwrapped and re-checked)
        "64:ff9b::/96",  # NAT64 well-known prefix
        "100::/64",  # discard-only
        "2001:db8::/32",  # documentation
        "fc00::/7",  # unique local
        "fe80::/10",  # link-local
        "ff00::/8",  # multicast
        "fd00:ec2::254/128",  # AWS IMDS IPv6
    )
)


@dataclass(frozen=True, slots=True)
class SystemLimits:
    # --- fetcher caps -----------------------------------------------------------------------
    MAX_RESPONSE_SIZE: int = 5 * 1024 * 1024  # bytes
    MAX_REDIRECTS: int = 5
    FETCH_TIMEOUT: float = 15.0  # seconds, total per request
    CONNECT_TIMEOUT: float = 5.0  # seconds
    ALLOWED_SCHEMES: frozenset[str] = frozenset({"http", "https"})
    ALLOWED_PORTS: frozenset[int] = frozenset({80, 443, 8080, 8443})
    ALLOWED_CONTENT_TYPE_PREFIXES: tuple[str, ...] = (
        "text/",
        "application/xhtml",
        "application/xml",
        "application/json",
        "application/javascript",
        "application/x-javascript",
        "application/octet-stream",  # favicons are often served like this
        "image/",
    )
    # --- SSRF ---------------------------------------------------------------------------------
    BLOCK_PRIVATE_IPS: bool = True
    BLOCK_METADATA_IPS: bool = True
    BLOCKED_NETWORKS: tuple[IPv4Network | IPv6Network, ...] = _BLOCKED_NETWORKS
    BLOCKED_HOSTNAMES: frozenset[str] = frozenset(
        {"localhost", "metadata", "metadata.google.internal", "instance-data", "ip6-localhost"}
    )
    BLOCKED_HOSTNAME_SUFFIXES: tuple[str, ...] = (
        ".localhost",
        ".internal",
        ".local",
        ".localdomain",
        ".home.arpa",
    )
    # --- browser worker -----------------------------------------------------------------------
    BROWSER_NETWORK_POLICY: str = "egress_public_only"  # no internal network from the sandbox
    BROWSER_OP_TIMEOUT: float = 45.0
    # --- investigation budget ceilings (brand budgets may be lower, never higher) ------------
    MAX_BFS_DEPTH: int = 2
    MAX_PIVOT_NODES: int = 100
    MAX_PIVOT_EDGES: int = 300


SYSTEM_LIMITS: Final[SystemLimits] = SystemLimits()

# Field names, exported so tests can assert they never leak into Settings / BrandConfig.
SYSTEM_LIMIT_NAMES: Final[frozenset[str]] = frozenset(SystemLimits.__dataclass_fields__)
