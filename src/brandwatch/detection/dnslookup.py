"""DNS look-ups with a choice of method (Settings → Lookups) and an optional fallback.

* ``python``  — pure Python, no third party: the query walks the DNS tree itself, from the root
               servers to the TLD registry and on to the domain's own name servers
               (iterative resolution with dnspython messages). "Is it registered" is answered by
               the registry itself: a delegation (NS) means registered, NXDOMAIN means free.
* ``service`` — a public recursive resolver does the walking (Cloudflare 1.1.1.1, Quad9
               9.9.9.9, Google 8.8.8.8, plus any of this machine's own DNS servers that answer
               correctly — dead or lying ones are probed out once per process).

Every answer is tri-state: ``True`` / ``False`` / ``None`` (no usable answer). With fallback on,
``None`` from the chosen method is retried with the other one.
"""

from __future__ import annotations

import random
import threading
import time
from contextvars import ContextVar
from dataclasses import dataclass
from typing import Any

from brandwatch import trace

ROOT_SERVERS: tuple[str, ...] = (
    "198.41.0.4", "170.247.170.2", "192.33.4.12", "199.7.91.13", "192.203.230.10", "192.5.5.241",
    "192.112.36.4", "198.97.190.53", "192.36.148.17", "192.58.128.30", "193.0.14.129",
    "199.7.83.42", "202.12.27.33",
)  # fmt: skip
PUBLIC_RESOLVERS: tuple[str, ...] = ("1.1.1.1", "9.9.9.9", "8.8.8.8")
MODES = ("python", "service")


@dataclass(frozen=True)
class LookupPolicy:
    mode: str = "python"
    fallback: bool = True

    @property
    def other(self) -> str:
        return "service" if self.mode == "python" else "python"


_policy: ContextVar[LookupPolicy | None] = ContextVar("brandwatch_dns_policy", default=None)


def set_policy(mode: str, fallback: bool) -> LookupPolicy:
    p = LookupPolicy(mode if mode in MODES else "python", bool(fallback))
    _policy.set(p)
    return p


def current_policy() -> LookupPolicy:
    return _policy.get() or LookupPolicy()


# ============================== python: iterative resolution ==============================
_zone_cache: dict[str, list[str]] = {}  # zone ("com.", "online.") → name-server IPs
_cache_lock = threading.Lock()


def _ask(server: str, name: str, rtype: str, timeout: float = 1.5) -> Any:
    import dns.flags
    import dns.message
    import dns.query

    q = dns.message.make_query(name, rtype)
    q.flags &= ~dns.flags.RD  # iterative: we do the walking ourselves
    try:
        return dns.query.udp(q, server, timeout=timeout)
    except Exception:  # noqa: BLE001 - timeout / network: try TCP once (truncation, UDP blocked)
        try:
            return dns.query.tcp(q, server, timeout=timeout)
        except Exception:  # noqa: BLE001
            return None


def _glue(resp: Any) -> tuple[str | None, list[str], list[str]]:
    """(zone of the referral, glue IPv4s, NS names without glue)."""
    import dns.rdatatype

    zone, ns_names = None, []
    for rrset in resp.authority:
        if rrset.rdtype == dns.rdatatype.NS:
            zone = rrset.name.to_text().lower()
            ns_names = [r.target.to_text().lower() for r in rrset]
    ips = [r.address for rrset in resp.additional if rrset.rdtype == dns.rdatatype.A for r in rrset]
    glued = {rrset.name.to_text().lower() for rrset in resp.additional}
    return zone, ips, [n for n in ns_names if n not in glued]


def _walk(name: str, rtype: str, depth: int = 0) -> tuple[str, Any]:
    """Iterate from the deepest cached zone (or the root) towards ``name``.
    Returns (outcome, last response): outcome in nxdomain / answer / nodata / delegated / error."""
    import dns.rcode
    import dns.rdatatype

    if depth > 4:
        return "error", None
    fq = name.rstrip(".").lower() + "."
    servers: list[str] = []
    labels = fq.split(".")
    with _cache_lock:
        for i in range(len(labels) - 1):
            zone = ".".join(labels[i:])
            if zone in _zone_cache:
                servers = list(_zone_cache[zone])
                break
    if not servers:
        servers = list(ROOT_SERVERS)
    for _hop in range(8):
        random.shuffle(servers)
        resp = None
        for srv in servers[:3]:
            resp = _ask(srv, fq, rtype)
            if resp is not None:
                break
        if resp is None:
            return "error", None
        rc = resp.rcode()
        if rc == dns.rcode.NXDOMAIN:
            return "nxdomain", resp
        if rc != dns.rcode.NOERROR:
            return "error", resp
        if resp.answer:
            return "answer", resp
        zone, ips, unglued = _glue(resp)
        if zone is None or not resp.authority:
            return "nodata", resp  # the authoritative server says: exists, no record of this type
        if zone == fq and rtype == "NS":
            return "delegated", resp  # the parent zone delegates exactly this name: registered
        if not ips and unglued:  # name servers inside another zone: resolve one of them
            for ns_name in unglued[:2]:
                outcome, r2 = _walk(ns_name, "A", depth + 1)
                if outcome == "answer":
                    ips = [
                        rr.address
                        for rrset in r2.answer
                        if rrset.rdtype == dns.rdatatype.A
                        for rr in rrset
                    ]
                    if ips:
                        break
        if not ips:
            return "error", resp
        with _cache_lock:
            if zone.count(".") <= 2:  # cache TLD / public-suffix zones only (stable, few)
                _zone_cache[zone] = ips
        servers = ips
    return "error", None


def python_registered(name: str) -> bool | None:
    outcome, _ = _walk(name, "NS")
    if outcome == "nxdomain":
        return False
    if outcome in ("delegated", "answer", "nodata"):
        return True
    return None


def python_a(name: str, _depth: int = 0) -> list[str] | None:
    import dns.rdatatype

    outcome, resp = _walk(name, "A")
    if outcome in ("nxdomain", "nodata"):
        return []
    if outcome != "answer":
        return None
    ips = [r.address for rrset in resp.answer if rrset.rdtype == dns.rdatatype.A for r in rrset]
    if ips:
        return ips
    cnames = [
        r.target.to_text()
        for rrset in resp.answer
        if rrset.rdtype == dns.rdatatype.CNAME
        for r in rrset
    ]
    if cnames and _depth < 5:
        return python_a(cnames[-1], _depth + 1)
    return []


# ============================== service: public / healthy resolvers ==============================
_svc_lock = threading.Lock()
_svc_servers: list[str] | None = None
_svc_report: dict[str, str] = {}


def service_nameservers() -> list[str]:
    """Responsive recursive resolvers, fastest first, probed once per process. Dead entries
    (a disconnected VPN adapter) and servers that answer NXDOMAIN for example.com are dropped."""
    global _svc_servers
    with _svc_lock:
        if _svc_servers is not None:
            return _svc_servers
        import dns.resolver

        try:
            system = list(dns.resolver.Resolver().nameservers)
        except Exception:  # noqa: BLE001
            system = []
        probed: list[tuple[float, str]] = []
        for ns in dict.fromkeys([*system, *PUBLIC_RESOLVERS]):
            r = dns.resolver.Resolver(configure=False)
            r.nameservers = [ns]
            r.timeout = r.lifetime = 1.5
            t0 = time.monotonic()
            try:
                r.resolve("example.com", "A")
                ms = (time.monotonic() - t0) * 1000
                probed.append((ms + (0 if ns in system else 5), ns))
                _svc_report[ns] = f"ok {ms:.0f} ms"
            except Exception as exc:  # noqa: BLE001
                _svc_report[ns] = f"no answer ({type(exc).__name__})"
        _svc_servers = [ns for _ms, ns in sorted(probed)]
        trace.log("dns", "service resolvers", system_servers=system, probe=dict(_svc_report),
                  using=_svc_servers or "none")  # fmt: skip
        return _svc_servers


def _service_query(name: str, rtype: str) -> tuple[str, Any]:
    import dns.resolver

    servers = service_nameservers()
    if not servers:
        return "error", None
    res = dns.resolver.Resolver(configure=False)
    res.nameservers = servers[:3]
    res.rotate = True
    res.timeout = 1.0
    res.lifetime = 2.5
    try:
        return "answer", res.resolve(name, rtype)
    except dns.resolver.NXDOMAIN:
        return "nxdomain", None
    except dns.resolver.NoAnswer:
        return "nodata", None
    except Exception:  # noqa: BLE001 - timeout / SERVFAIL everywhere
        return "error", None


def service_registered(name: str) -> bool | None:
    for rtype in ("A", "NS"):
        outcome, _ = _service_query(name, rtype)
        if outcome == "answer":
            return True
        if outcome == "nxdomain":
            return False
        if outcome == "error":
            return None
    return False  # exists in no form we can see


def service_a(name: str) -> list[str] | None:
    outcome, ans = _service_query(name, "A")
    if outcome == "answer":
        return [r.to_text() for r in ans]
    if outcome in ("nxdomain", "nodata"):
        return []
    return None


# ============================== policy-aware entry points ==============================
_REGISTERED = {"python": python_registered, "service": service_registered}
_A = {"python": python_a, "service": service_a}


def registered(name: str) -> bool | None:
    """Is the name registered? Chosen method first; on no answer, the other one (if allowed)."""
    p = current_policy()
    result = _REGISTERED[p.mode](name)
    if result is None and p.fallback:
        result = _REGISTERED[p.other](name)
    return result


def a_records(name: str) -> tuple[list[str] | None, str]:
    """(IPv4 addresses or [] for "does not resolve" or None for "no answer", method used)."""
    p = current_policy()
    result = _A[p.mode](name)
    if result is None and p.fallback:
        return _A[p.other](name), p.other
    return result, p.mode
