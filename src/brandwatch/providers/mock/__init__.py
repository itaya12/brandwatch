"""Deterministic, $0 mock providers (spec §4 "Demo mode", §18).

Every mock first consults the recorded scenarios (``fixtures.FixtureStore``); hosts without a
scenario get a hash-derived default. Two rules keep a demo scan bounded and honest:

* DNS: a host **without** a scenario does not resolve (NXDOMAIN → candidate dismissed as dead).
* Reputation: only an explicit recorded verdict is positive/negative; otherwise *unknown*.

The browser mock serves real PNG bytes (synthetic, derived from the scenario's class) so the
evidence store, favicon hashing and screenshot similarity run exactly as in production.
"""

from __future__ import annotations

import hashlib
import re
from datetime import UTC, datetime, timedelta
from functools import lru_cache
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from brandwatch.db.enums import ProviderStatus
from brandwatch.detection import images
from brandwatch.providers.base import ProviderResult
from brandwatch.providers.mock.fixtures import FixtureStore, Scenario, default_store


def _digest(*parts: Any) -> int:
    return int(hashlib.sha256("|".join(map(str, parts)).encode()).hexdigest()[:8], 16)


def _verdict(value: str) -> ProviderStatus:
    v = value.lower()
    if any(k in v for k in ("phish", "evil", "malware")):
        return ProviderStatus.POSITIVE
    if any(k in v for k in ("clean", "safe", "legit")):
        return ProviderStatus.NEGATIVE
    return ProviderStatus.UNKNOWN


def _host_of(value: str) -> str:
    if "://" in value:
        from urllib.parse import urlsplit

        return (urlsplit(value).hostname or "").lower()
    return value.lower().rstrip(".")


# Realistic reverse-IP noise: every kit server also hosts unrelated customers (spec §8 caveat).
SHARED_HOSTING_NEIGHBOURS: dict[str, list[str]] = {
    "203.0.113.66": ["bakery-menu.example", "cheap-vps-customer7.example", "nordbank-verify.com"],
    "198.51.100.77": ["gallery-of-cats.example"],
}


class _MockBase:
    requires_key = False
    cost_per_call = 0.0

    def __init__(self, stand_in_for: str = "mock", store: FixtureStore | None = None) -> None:
        self.name = f"mock:{stand_in_for}"
        self.stand_in_for = stand_in_for
        self._store = store

    @property
    def store(self) -> FixtureStore:
        return self._store or default_store()

    def scenario(self, value: str) -> Scenario | None:
        return self.store.get(_host_of(value))

    def _ok(self, status: ProviderStatus, data: dict[str, Any], raw: dict[str, Any] | None = None):
        return ProviderResult(
            provider=self.name, status=status, data=data, raw=raw or {"mock": True}, cost_usd=0.0
        )


_FLAKED: set[str] = set()


def _maybe_flake(name: str) -> None:
    """Demo only: one simulated outage per process for DEMO_FLAKY_PROVIDER, so the resilience path
    (an alert with a plain-language fix while the scan carries on) can be shown live."""
    import os

    from brandwatch.providers.base import ProviderError

    if os.environ.get("DEMO_FLAKY_PROVIDER", "").strip().lower() == name and name not in _FLAKED:
        _FLAKED.add(name)
        raise ProviderError(f"{name}: HTTP 503 (simulated outage for the demo)", retryable=False)


class MockReputationProvider(_MockBase):
    def _lookup(self, value: str) -> ProviderResult:
        _maybe_flake(self.stand_in_for)
        sc = self.scenario(value)
        if self.stand_in_for == "safebrowsing":
            # Google's list answers "listed" or "not listed": fresh kits are usually not on it yet
            recorded = sc.reputation.get("safebrowsing") if sc is not None else None
            listed = recorded == ProviderStatus.POSITIVE.value
            matches = (
                [
                    {
                        "threatType": "SOCIAL_ENGINEERING",
                        "platformType": "ANY_PLATFORM",
                        "threat": {"url": f"http://{_host_of(value)}/"},
                    }
                ]
                if listed
                else []
            )
            return self._ok(ProviderStatus.POSITIVE if listed else ProviderStatus.NEGATIVE,
                            {"value": value, "threats": ["SOCIAL_ENGINEERING"] if listed else [], "positives": 1 if listed else 0},
                            {"matches": matches})  # fmt: skip
        if sc is not None:
            recorded = sc.reputation.get(self.stand_in_for)
            status = ProviderStatus(recorded) if recorded else ProviderStatus.UNKNOWN
        else:
            status = _verdict(value)
        positives = 7 if status is ProviderStatus.POSITIVE else 0
        return self._ok(status, {"value": value, "positives": positives, "total": 90})

    async def lookup_domain(self, domain: str) -> ProviderResult:
        return self._lookup(domain)

    async def lookup_ip(self, ip: str) -> ProviderResult:
        return self._ok(_verdict(ip), {"ip": ip, "asn": 64512 + _digest(ip) % 100})

    async def lookup_url(self, url: str) -> ProviderResult:
        return self._lookup(url)

    async def check_ip(self, ip: str) -> ProviderResult:
        """AbuseIPDB-shaped answer: the kit servers carry community abuse reports, others are quiet."""
        hosts = default_store().by_ip(ip)
        phishing = [h for h in hosts if getattr(h, "label", "") == "phishing"]
        h = _digest(ip)
        if ip == "203.0.113.66":
            score, reports, users, hours = 87, 143, 38, 6
        elif phishing:
            score, reports, users, hours = 35 + h % 45, 8 + h % 50, 3 + h % 15, 2 + h % 40
        else:
            score, reports, users, hours = 0, 0, 0, 0
        org = _KNOWN_GEO.get(ip, (None, None, None, None, "Mock Hosting LLC"))[4]
        data = {"ip": ip, "abuse_score": score, "total_reports": reports, "distinct_users": users,
                "last_reported": (datetime.now(UTC) - timedelta(hours=hours)).isoformat() if reports else None,
                "isp": org, "usage_type": "Data Center/Web Hosting/Transit", "domain": None, "country": None,
                "is_tor": False, "is_whitelisted": False, "positives": 1 if score >= 25 else 0}  # fmt: skip
        return self._ok(ProviderStatus.POSITIVE if score >= 25 else ProviderStatus.NEGATIVE, data)

    # --- intel page (VirusTotal-shaped objects, deterministic) -----------------------------
    _ENGINES = ("Fortinet", "Kaspersky", "BitDefender", "Sophos", "ESET", "Google Safebrowsing",
                "Phishtank", "OpenPhish", "CRDF", "Webroot", "Quttera", "Netcraft")  # fmt: skip

    def _bad(self, value: str) -> bool:
        sc = self.scenario(value)
        if sc is not None and sc.reputation.get(self.stand_in_for):
            return ProviderStatus(sc.reputation[self.stand_in_for]) is ProviderStatus.POSITIVE
        return _verdict(value) is ProviderStatus.POSITIVE

    def _stats(self, value: str) -> dict[str, int]:
        bad = self._bad(value)
        return {"malicious": 7 if bad else 0, "suspicious": 1 if bad else 0,
                "harmless": 68 if bad else 72, "undetected": 14 if bad else 18, "timeout": 0}  # fmt: skip

    def _results(self, value: str) -> dict[str, dict]:
        bad = self._bad(value)
        out = {}
        for i, eng in enumerate(self._ENGINES):
            flagged = bad and i < 8
            out[eng] = {"engine_name": eng, "category": "malicious" if flagged else "harmless",
                        "result": "phishing" if flagged else "clean", "method": "blacklist"}  # fmt: skip
        return out

    @staticmethod
    def _ip_for(value: str) -> str:
        sc = default_store().get(_host_of(value))
        return (sc.infra.get("ip") if sc and sc.infra else None) or "203.0.113.66"

    async def domain_report(self, domain: str) -> ProviderResult:
        ip = self._ip_for(domain)
        sc = self.scenario(
            domain
        )  # the recorded WHOIS age, so VirusTotal agrees with RDAP and WHOIS history
        age = (
            int(sc.whois.get("age_days"))
            if sc is not None and sc.whois and sc.whois.get("age_days") is not None
            else _digest(domain) % 400 + 3
        )
        created = int((datetime.now(UTC) - timedelta(days=age)).timestamp())
        attrs = {
            "last_analysis_stats": self._stats(domain), "last_analysis_results": self._results(domain),
            "last_dns_records": [
                {"type": "A", "ttl": 300, "value": ip},
                {"type": "AAAA", "ttl": 300, "value": "2001:db8::" + format(_digest(domain) % 0xFFFF, "x")},
                {"type": "NS", "ttl": 21600, "value": "ns1.mock-dns.example"},
                {"type": "NS", "ttl": 21600, "value": "ns2.mock-dns.example"},
                {"type": "MX", "ttl": 3600, "value": "mail." + domain, "priority": 10},
                {"type": "SOA", "ttl": 1800, "value": "ns1.mock-dns.example", "rname": "hostmaster." + domain,
                 "serial": 2026100801},
            ],
            "last_https_certificate": {
                "subject": {"CN": domain}, "issuer": {"C": "US", "O": "Mock Trust Services", "CN": "MT1"},
                "validity": {"not_before": "2026-09-20 00:00:00", "not_after": "2026-12-19 00:00:00"},
                "thumbprint_sha256": hashlib.sha256(("cert|" + domain).encode()).hexdigest(),
                "thumbprint": hashlib.sha1(("cert|" + domain).encode()).hexdigest(),
                "serial_number": format(_digest(domain), "x"),
                "cert_signature": {"signature_algorithm": "sha256ECDSA"},
                "public_key": {"algorithm": "EC", "ec": {"oid": "secp256r1"}},
                "extensions": {"subject_alternative_name": [domain, "www." + domain]}, "version": "V3",
            },
            "jarm": hashlib.sha256(("jarm|" + ip).encode()).hexdigest()[:62],
            "whois": f"Domain Name: {domain.upper()}\nRegistrar: Mock Registrar LLC\nRegistrar Abuse Contact Email: abuse@mock-registrar.example\n"
                     f"Creation Date: {datetime.fromtimestamp(created, UTC).date().isoformat()}T00:00:00Z\nName Server: NS1.MOCK-DNS.EXAMPLE\nRegistrant Country: US\n",
            "registrar": "Mock Registrar LLC", "creation_date": created,
            "categories": {"Mock Category Service": "phishing" if self._bad(domain) else "uncategorized"},
            "popularity_ranks": {}, "reputation": -5 if self._bad(domain) else 0,
        }  # fmt: skip
        status = ProviderStatus.POSITIVE if self._bad(domain) else _verdict(domain)
        st = attrs["last_analysis_stats"]
        return self._ok(status, {"domain": domain, "positives": st["malicious"] + st["suspicious"],
                                 "total": sum(st.values()), "attributes": attrs},
                        {"data": {"id": domain, "type": "domain", "attributes": attrs}})  # fmt: skip

    async def ip_report(self, ip: str) -> ProviderResult:
        geo = _KNOWN_GEO.get(ip)
        cc, org = (
            (geo[0], geo[4])
            if geo
            else (_CITIES[_digest(ip) % len(_CITIES)][0], "Mock Hosting LLC")
        )
        bad = ip in _KNOWN_GEO
        st = {"malicious": 3 if bad else 0, "suspicious": 0, "harmless": 60, "undetected": 31 if bad else 34, "timeout": 0}  # fmt: skip
        attrs = {"country": cc, "asn": 64512 + _digest(ip) % 100, "as_owner": org, "network": ip.rsplit(".", 1)[0] + ".0/24",
                 "last_analysis_stats": st, "last_analysis_results": self._results("evil" if bad else "clean"),
                 "regional_internet_registry": "RIPE NCC", "whois": f"inetnum: {ip.rsplit('.', 1)[0]}.0 - {ip.rsplit('.', 1)[0]}.255\norg-name: {org}\nabuse-mailbox: abuse@{org.split()[0].lower()}.example\n",
                 "reputation": -3 if bad else 0}  # fmt: skip
        return self._ok(ProviderStatus.POSITIVE if bad else ProviderStatus.NEGATIVE,
                        {"ip": ip, "positives": st["malicious"], "total": sum(st.values()), "attributes": attrs},
                        {"data": {"id": ip, "type": "ip_address", "attributes": attrs}})  # fmt: skip

    async def relationship(self, kind: str, value: str, rel: str, limit: int = 40, cursor: str | None = None) -> ProviderResult:  # fmt: skip
        today = datetime.now(UTC)
        items: list[dict] = []
        if rel == "resolutions" and kind == "domains":
            items = [{"id": f"{self._ip_for(value)}{value}", "date": int((today - timedelta(days=17)).timestamp()),
                      "ip_address": self._ip_for(value), "host_name": value,
                      "ip_address_last_analysis_stats": {"malicious": 3, "harmless": 60, "undetected": 29, "suspicious": 0}}]  # fmt: skip
        elif rel == "resolutions":  # ip → hostnames: the recorded kit cluster + filler
            hosts = [
                sc.url.split("/")[2]
                for sc in self.store.all()
                if (sc.infra or {}).get("ip") == value
            ]
            hosts += [f"{w}-{value.replace('.', '')[-4:]}.{t}" for w, t in (("secure-login", "top"), ("verify-account", "xyz"), ("wallet-sync", "online"), ("support-desk", "site"))]  # fmt: skip
            for i, h in enumerate(dict.fromkeys(hosts)):
                bad = _verdict(h) is ProviderStatus.POSITIVE or i % 3 == 0
                items.append({"id": f"{value}{h}", "date": int((today - timedelta(days=2 * i + 1)).timestamp()),
                              "host_name": h, "ip_address": value,
                              "host_name_last_analysis_stats": {"malicious": 5 if bad else 0, "harmless": 70, "undetected": 20, "suspicious": 0}})  # fmt: skip
        elif rel == "historical_whois":
            items = [{"id": "w1", "first_seen_date": int((today - timedelta(days=30)).timestamp()), "last_updated": int((today - timedelta(days=30)).timestamp()),
                      "registrar_name": "Mock Registrar LLC", "whois_map": {"Registrant Organization": "REDACTED FOR PRIVACY", "Registrant Country": "US", "Name Server": "NS1.MOCK-DNS.EXAMPLE"}}]  # fmt: skip
        elif rel == "historical_ssl_certificates":
            items = [{"id": hashlib.sha256((f"c{i}|" + value).encode()).hexdigest(), "first_seen_date": int((today - timedelta(days=5 + 25 * i)).timestamp()),
                      "thumbprint_sha256": hashlib.sha256((f"c{i}|" + value).encode()).hexdigest(), "subject": {"CN": value},
                      "issuer": {"O": "Mock Trust Services"}, "validity": {"not_before": (today - timedelta(days=5 + 25 * i)).date().isoformat(), "not_after": (today + timedelta(days=85 - 25 * i)).date().isoformat()}} for i in range(2)]  # fmt: skip
        elif rel == "communicating_files":
            names = (("Draky and the Twilight Castle.apk", "Android", 6), ("REMITTANCE 2-For-Cokecanada.pdf", "PDF", 0), ("Orbit - Igra s gravitaciey.apk", "Android", 5), ("invoice_4411.pdf", "PDF", 4))  # fmt: skip
            items = [{"id": hashlib.sha256((n + value).encode()).hexdigest(), "sha256": hashlib.sha256((n + value).encode()).hexdigest(),
                      "meaningful_name": n, "type_description": t, "last_analysis_date": int((today - timedelta(days=9 * i + 3)).timestamp()),
                      "last_analysis_stats": {"malicious": d, "harmless": 0, "undetected": 66 - d, "suspicious": 0}, "size": 100000 + 777 * i}
                     for i, (n, t, d) in enumerate(names)]  # fmt: skip
        elif rel == "subdomains":
            items = [{"id": f"{sub}.{value}", "last_analysis_stats": {"malicious": 2 if sub == "login" else 0, "harmless": 70, "undetected": 20, "suspicious": 0}}
                     for sub in ("login", "www", "mail")]  # fmt: skip
        elif rel == "referrer_files":
            items = []
        return self._ok(ProviderStatus.POSITIVE if items else ProviderStatus.UNKNOWN,
                        {"value": value, "relation": rel, "items": items[:limit], "next_cursor": None, "count": len(items)})  # fmt: skip


class MockWhoisProvider(_MockBase):
    async def lookup(self, domain: str) -> ProviderResult:
        sc = self.scenario(domain)
        if sc is not None and sc.whois:
            age_days = int(sc.whois.get("age_days", 0))
            registrar = sc.whois.get("registrar", "Mock Registrar LLC")
            registrant = sc.infra.get("registrant") or sc.whois.get(
                "registrant", {"org": "REDACTED FOR PRIVACY"}
            )
        else:
            age_days = _digest(domain) % 400
            registrar, registrant = "Mock Registrar LLC", {"org": "REDACTED FOR PRIVACY"}
        registered = datetime.now(UTC).date() - timedelta(days=age_days)
        return self._ok(
            ProviderStatus.POSITIVE,
            {
                "domain": domain,
                "registered_at": registered.isoformat(),
                "age_days": age_days,
                "registrar": registrar,
                "registrant": registrant,
            },
        )

    async def history(self, domain: str) -> ProviderResult:
        """WHOIS history in WhoisXML's record shape (see mock/whois_history.py)."""
        from brandwatch.providers.mock.whois_history import records_for

        sc = self.scenario(domain)
        whois = None
        if sc is not None and sc.whois:
            whois = {
                **sc.whois,
                "registrant": sc.infra.get("registrant") or sc.whois.get("registrant"),
            }
        records = records_for(domain, whois)
        return self._ok(ProviderStatus.POSITIVE if records else ProviderStatus.UNKNOWN,
                        {"domain": domain, "records_count": len(records), "records": records})  # fmt: skip


class MockDnsProvider(_MockBase):
    async def resolve(self, name: str, rtype: str = "A") -> ProviderResult:
        sc = self.scenario(name)
        if sc is None or sc.dns is None:
            # NXDOMAIN: a definite answer ("negative"), not an error.
            return self._ok(ProviderStatus.NEGATIVE, {"name": name, "type": rtype, "records": []})
        records = list(sc.dns.get(rtype, []))
        status = ProviderStatus.POSITIVE if records else ProviderStatus.NEGATIVE
        return self._ok(status, {"name": name, "type": rtype, "records": records})

    async def passive_dns(self, value: str) -> ProviderResult:
        """Reverse IP ("what else is on the server") or forward history from the recorded infra."""
        import ipaddress

        try:
            ipaddress.ip_address(value)
        except ValueError:
            sc = self.scenario(value)
            ips = [sc.infra["ip"]] if sc and sc.infra.get("ip") else []
            return self._ok(
                ProviderStatus.POSITIVE if ips else ProviderStatus.UNKNOWN,
                {"value": value, "resolutions": ips},
            )
        hosts = [sc.host for sc in self.store.by_ip(value)]
        hosts += SHARED_HOSTING_NEIGHBOURS.get(value, [])
        if not hosts:  # unknown IP: a couple of unrelated neighbours, like real reverse-IP data
            hosts = [
                f"customer{i}-{_digest(value, i) % 997}.hosting.example"
                for i in range(_digest(value) % 3)
            ]
        return self._ok(
            ProviderStatus.POSITIVE if hosts else ProviderStatus.UNKNOWN,
            {"value": value, "resolutions": hosts},
        )


class MockCertProvider(_MockBase):
    """crt.sh-style search: certificates whose SANs are recorded hosts matching the pattern,
    plus a couple of deterministic decoys that will not resolve."""

    async def ct_search(self, pattern: str) -> ProviderResult:
        pat = pattern.strip("%").lower()
        certs = []
        for sc in self.store.all():
            if pat and pat in sc.host and sc.dns is not None:
                certs.append(
                    {
                        "fingerprint_sha256": hashlib.sha256(
                            f"cert:{sc.host}".encode()
                        ).hexdigest(),
                        "sans": [sc.host, f"www.{sc.host}"],
                        "issuer": "C=US, O=Let's Encrypt, CN=R3",
                        "not_before": "2026-09-30",
                    }
                )
        for i in range(_digest(pattern) % 3):
            certs.append(
                {
                    "fingerprint_sha256": hashlib.sha256(f"{pattern}{i}".encode()).hexdigest(),
                    "sans": [f"mail{i}.{pat}-cdn.net"],
                    "issuer": "Mock CA",
                    "not_before": "2026-09-01",
                }
            )
        return self._ok(ProviderStatus.POSITIVE, {"pattern": pattern, "certificates": certs})

    async def by_fingerprint(self, fingerprint_sha256: str) -> ProviderResult:
        hosts = [sc.host for sc in self.store.by_cert(fingerprint_sha256)]
        certs = (
            [
                {
                    "fingerprint_sha256": fingerprint_sha256,
                    "sans": hosts,
                    "issuer": "C=US, O=Let's Encrypt, CN=R3",
                }
            ]
            if hosts
            else []
        )
        return self._ok(
            ProviderStatus.POSITIVE if hosts else ProviderStatus.UNKNOWN,
            {"fingerprint_sha256": fingerprint_sha256, "certificates": certs},
        )


class MockSearchProvider(_MockBase):
    """SerpAPI-style search: recorded pages whose host or title mentions the query."""

    async def search(self, query: str, geo: str = "us", lang: str = "en") -> ProviderResult:
        low = query.lower()
        for site in ("instagram", "facebook"):  # profile discovery: site:instagram.com "<brand>"
            if low.startswith(f"site:{site}.com"):
                urls = social_world()["google"][site] if "nova" in low else []
                hits = [{"url": u, "title": u.rstrip("/").rsplit("/", 1)[-1], "position": i} for i, u in enumerate(urls, 1)]
                return self._ok(ProviderStatus.POSITIVE if hits else ProviderStatus.UNKNOWN,
                                {"query": query, "geo": geo, "lang": lang, "hits": hits})  # fmt: skip
        # a shop's recorded Google results: "<company>" (presence) or "<shop> reviews …"
        shop_query = query.startswith('"') or any(
            w in low for w in ("review", "ביקורות", "scam", "avis", "opiniones", "erfahrungen", "отзывы",
                               "recensioni", "opinie", "ervaringen", "تقييمات", "yorumlar", "avaliações")
        )  # fmt: skip
        for sc in self.store.all() if shop_query else ():
            if not sc.reviews:
                continue
            sld = sc.host.split(".")[0]
            name = str((sc.registry or {}).get("name") or "").lower()
            number = str((sc.registry or {}).get("number") or "")
            if sld in low or (name and name in low) or (number and number in low):
                want = "presence" if query.startswith('"') else "review"
                rows = [r for r in sc.reviews if r.get("kind", "review") == want]
                hits = [{"url": r["url"], "title": r.get("title"), "snippet": r.get("snippet", ""), "position": i}
                        for i, r in enumerate(rows, 1)]  # fmt: skip
                return self._ok(ProviderStatus.POSITIVE if hits else ProviderStatus.UNKNOWN,
                                {"query": query, "geo": geo, "lang": lang, "hits": hits})  # fmt: skip
        q = query.lower().replace(" ", "")
        hits = []
        for sc in self.store.all():
            html = (sc.http or {}).get("html", "").lower()
            if sc.http is not None and (q in sc.host.replace("-", "") or q in html):
                hits.append(
                    {
                        "url": sc.url,
                        "title": html.split("<title>")[-1].split("</title>")[0][:80],
                        "position": len(hits) + 1,
                    }
                )
        return self._ok(
            ProviderStatus.POSITIVE, {"query": query, "geo": geo, "lang": lang, "hits": hits[:20]}
        )

    async def reverse_image(self, image_sha256: str) -> ProviderResult:
        return self._ok(ProviderStatus.UNKNOWN, {"image_sha256": image_sha256, "matches": []})


class MockHostProvider(_MockBase):
    async def host(self, ip: str) -> ProviderResult:
        shared = len(self.store.by_ip(ip)) + len(SHARED_HOSTING_NEIGHBOURS.get(ip, []))
        return self._ok(
            ProviderStatus.POSITIVE,
            {
                "ip": ip,
                "ports": [80, 443],
                "org": "Mock Hosting LLC",
                "asn": 64512 + _digest(ip) % 100,
                "hostnames_seen": shared,
            },
        )

    async def favicon_search(self, favicon_mmh3: int) -> ProviderResult:
        ips = sorted(
            {
                sc.infra["ip"]
                for sc in self.store.all()
                if sc.favicon == "brand"
                and sc.infra.get("ip")
                and images.favicon_mmh3(images.synth_favicon(sc.brand)) == favicon_mmh3
            }
        )
        return self._ok(
            ProviderStatus.POSITIVE if ips else ProviderStatus.UNKNOWN,
            {"favicon_mmh3": favicon_mmh3, "ips": ips},
        )


MOCK_BROWSER_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
MOCK_BOT_UA = "Mozilla/5.0 (compatible; BrandWatchBot/0.1; +https://example.invalid/bot)"
MOCK_MOBILE_UA = "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Mobile Safari/537.36"


@lru_cache(maxsize=1)
def _white_png() -> bytes:
    """What a gate that has not forwarded yet looks like: one flat colour."""
    import io

    from PIL import Image

    out = io.BytesIO()
    Image.new("RGB", (320, 200), "white").save(out, format="PNG")
    return out.getvalue()


def _mock_request(profile: str) -> tuple[str, dict[str, str]]:
    """What a visit with this profile sends: the same headers the real browser would, the crawler's own User-Agent."""
    ua = MOCK_MOBILE_UA if "mobile" in profile else (MOCK_BOT_UA if profile == "bot" else MOCK_BROWSER_UA)
    headers = {"user-agent": ua, "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
               "accept-language": "en-US", "accept-encoding": "gzip, deflate, br", "upgrade-insecure-requests": "1"}  # fmt: skip
    if profile == "referer":
        headers["referer"] = "https://www.google.com/"
    return ua, headers


def _cloaked_view(sc: Scenario, url: str, profile: str) -> bool:
    """True when this profile should get the kit's decoy page instead of the phishing page."""
    mode = (sc.cloak or {}).get("mode")
    if mode == "ip":
        return not profile.startswith("residential")
    if mode == "device":  # the lure reaches a phone only
        return "mobile" not in profile
    if mode == "ua":
        return profile == "bot"
    if mode == "param":
        return "email=" not in url
    if mode == "referer":
        return profile != "referer"
    return False


# Rendered pictures of the recorded sites (scripts/render_demo_images.py). The demo brand's clones get
# the brand's own picture — a cloned page *is* the same picture — and every other site its own one.
DEMO_ASSETS = Path(__file__).resolve().parents[2] / "demo" / "assets"
DEMO_BRAND = "shopnova"


@lru_cache(maxsize=256)
def _asset(kind: str, name: str) -> bytes | None:
    path = DEMO_ASSETS / kind / f"{name}.png"
    return path.read_bytes() if path.is_file() else None


def demo_screenshot(sc: Scenario, *, decoy: bool = False, similar_shift: int = 12) -> bytes | None:
    """The screenshot a visit to this scenario returns: the rendered picture when there is one,
    else the deterministic synthetic page (custom test scenarios, other brands)."""
    if decoy:
        return _asset("shots", f"{sc.host}__decoy") or images.synth_screenshot(f"{sc.host}-decoy")
    if sc.screenshot == "brand":
        return (
            _asset("shots", "_brand") if sc.brand == DEMO_BRAND else None
        ) or images.synth_screenshot(sc.brand)
    if sc.screenshot == "similar":
        return (
            _asset("shots", "_brand_similar") if sc.brand == DEMO_BRAND else None
        ) or images.synth_screenshot(sc.brand, shift=similar_shift)
    if sc.screenshot == "other":
        return _asset("shots", sc.host) or images.synth_screenshot(sc.host)
    return None


def demo_favicon(sc: Scenario) -> bytes | None:
    if sc.favicon == "brand":
        return (
            _asset("icons", "_brand") if sc.brand == DEMO_BRAND else None
        ) or images.synth_favicon(sc.brand)
    if sc.favicon == "other":
        return _asset("icons", sc.host) or images.synth_favicon(sc.host)
    return None


class MockBrowserFetcher(_MockBase):
    """Serves the scenario's page + synthetic screenshot/favicon PNGs.

    data keys: status, final_url, content_type, html, screenshot_png, favicon_png, profile
    """

    SIMILAR_SHIFT = 12  # colour nudge for the "similar" class → small pHash/palette distance

    async def peek(self, url: str) -> ProviderResult:
        """One plain request: what the site answers, without a browser (a warning page shows here too)."""
        host = _host_of(url)
        sc = self.scenario(url) or (self.scenario(host[4:]) if host.startswith("www.") else None)
        if sc is None or sc.http is None:
            return ProviderResult.failure(self.name, f"connection failed: {host} unreachable")
        html = sc.http.get("html", "")
        path = urlsplit(url).path or "/"
        if sc.pages and path in sc.pages:  # another page of the same site (an official contact page)
            html = sc.pages[path]
        title = html.split("<title>")[-1].split("</title>")[0][:120] if "<title>" in html else None
        return self._ok(ProviderStatus.POSITIVE, {
            "url": url, "final_url": sc.url, "profile": "datacenter", "status": 403 if sc.behind_warning else int(sc.http.get("status", 200)),
            "content_type": sc.http.get("content_type", "text/html"), "html": html, "title": title,
            "html_sha256": hashlib.sha256(html.encode()).hexdigest(), "screenshot_png": None, "favicon_png": None,
            "redirect_chain": [], "ip": sc.infra.get("ip")})  # fmt: skip

    async def fetch(self, url: str, profile: str = "datacenter") -> ProviderResult:
        proceed = profile == "datacenter-proceed"
        if proceed:
            profile = "datacenter"
        host = _host_of(url)
        sc = self.scenario(url) or (self.scenario(host[4:]) if host.startswith("www.") else None)  # www. answers too
        if sc is None or sc.http is None:
            return ProviderResult.failure(self.name, f"connection failed: {host} unreachable")

        http = sc.http
        if http.get("location"):
            target = self.store.get(_host_of(http["location"]))
            sc, http = (target, target.http) if target and target.http else (sc, http)
        html = http.get("html", "")
        path = urlsplit(url).path or "/"
        if sc.pages and path in sc.pages:  # another page of the same site (a shop's terms / contact page)
            html = sc.pages[path]
        cf_warning = None
        if sc.behind_warning and proceed:  # an analyst's full check presses "Ignore & Proceed" on Cloudflare's warning
            cf_warning = {"title": "Suspected Phishing | Cloudflare", "proceeded": True, "status": 200,
                          "html_sha256": hashlib.sha256(html.encode()).hexdigest(), "interstitial_html": html}  # fmt: skip
            html = sc.behind_warning
        elif sc.behind_warning:  # every other visit leaves the warning alone: it is the verdict
            cf_warning = {"title": "Suspected Phishing | Cloudflare", "proceeded": False, "status": 403,
                          "html_sha256": hashlib.sha256(html.encode()).hexdigest(), "interstitial_html": html,
                          "skipped": "Cloudflare already judged the site; the page behind its warning was not opened"}  # fmt: skip
            http = {**http, "status": 403}
        status = int(http.get("status", 200))
        blocked_for = http.get("blocked_for") or []
        egress = "residential" if profile.startswith("residential") else ("datacenter" if profile == "mobile" else profile)
        blocked = "*" in blocked_for or profile in blocked_for or egress in blocked_for  # bot protection refusing this kind of visitor ("*": all)
        if blocked:
            status, html = 403, http.get("block_html") or "<html><head><title>Access Denied</title></head><body>Access Denied</body></html>"
        challenged = profile in (http.get("challenge_for") or [])  # a bot check in front of the page for this visitor
        if challenged and not blocked:
            status = 403
            html = ("<html><head><title>Just a moment...</title></head><body><h1>Checking your browser before accessing "
                    f"{sc.host}</h1><p>Verify you are human by completing the action below. Cloudflare Ray ID: 8c1f2a</p></body></html>")
        decoy = _cloaked_view(sc, url, profile)
        if decoy and not blocked and not challenged:
            html = sc.cloak.get(
                "benign_html", "<html><body><h1>Under maintenance</h1></body></html>"
            )

        screenshot = demo_screenshot(sc, decoy=bool(decoy), similar_shift=self.SIMILAR_SHIFT)
        favicon = None if decoy else demo_favicon(sc)
        if blocked:  # a block page: no picture of the site, but the favicon URL is usually still served
            screenshot = None
        if challenged and not blocked:  # the picture is the bot check, not the site
            screenshot, favicon = images.synth_screenshot(f"{sc.host}-challenge"), None
        blank_for = http.get("blank_for") or []
        blanked = ("*" in blank_for or profile in blank_for) and not blocked and not challenged  # a gate that shows nothing
        if blanked:
            # what a forwarding gate really looks like: nothing to read, a hidden form that a script submits
            html = ('<html><head><title>...</title><meta http-equiv="refresh" content="2;url=?tm"></head><body>'
                    '<form style="display: none" method="POST" action="/go"><input type="hidden" name="q" value="x"></form>'
                    "<script>document.forms[0].submit()</script></body></html>")
            screenshot, favicon = _white_png(), None
        user_agent, request_headers = _mock_request(profile)

        return self._ok(
            ProviderStatus.POSITIVE,
            {
                "url": url,
                "final_url": http.get("final_url") or sc.url,
                "profile": profile,
                "status": status,
                "content_type": http.get("content_type", "text/html"),
                "html": html,
                "html_sha256": hashlib.sha256(html.encode()).hexdigest(),
                "screenshot_png": screenshot,
                "favicon_png": favicon,
                "redirect_chain": [url, *http.get("hops", [])] if (sc.url != url or http.get("hops")) else [],
                "user_agent": user_agent,
                "request_headers": request_headers,
                "tls_fingerprint_sha256": sc.infra.get("cert_fp"),
                "ip": sc.infra.get("ip"),
                "cloudflare_warning": cf_warning,
            },
            raw={"mock": True, "scenario": sc.host},
        )


class MockScanSearchProvider(_MockBase):
    """urlscan-style search: pages whose URL contains the query, from the recorded scenarios."""

    async def search_pages(self, query: str, limit: int = 50) -> ProviderResult:
        q = query.lower()
        hits = [
            {
                "url": sc.url,
                "task_id": hashlib.sha1(sc.url.encode()).hexdigest()[:12],
                "page_title": (sc.http or {})
                .get("html", "")
                .split("<title>")[-1]
                .split("</title>")[0][:80],
            }
            for sc in self.store.all()
            if q in sc.url.lower() and sc.http is not None
        ][:limit]
        return self._ok(ProviderStatus.POSITIVE, {"query": query, "results": hits})

    async def result(self, scan_id: str) -> ProviderResult:
        if not scan_id.startswith("mock-"):
            return self._ok(ProviderStatus.UNKNOWN, {"task_id": scan_id})
        url = "https://" + scan_id[5:] + "/"
        host = scan_id[5:]
        ip = "203.0.113.66"
        main_hash = hashlib.sha256(("doc|" + host).encode()).hexdigest()
        raw = {"page": {"url": url, "domain": host, "ip": ip, "asn": "AS64512", "asnname": "BulletproofHost BV", "country": "NL",
                        "server": "nginx", "title": f"{host} - Sign in"},
               "lists": {"ips": [ip], "domains": [host, "cdn.mock-static.example"], "hashes": [main_hash], "countries": ["NL"], "asns": ["AS64512"]},
               "verdicts": {"overall": {"malicious": _verdict(host) is ProviderStatus.POSITIVE, "score": 80 if _verdict(host) is ProviderStatus.POSITIVE else 0, "categories": ["phishing"] if _verdict(host) is ProviderStatus.POSITIVE else []}},
               "stats": {"uniqIPs": 1, "uniqCountries": 1, "requests": 23, "malicious": 1},
               "task": {"uuid": scan_id, "time": datetime.now(UTC).isoformat(), "url": url, "visibility": "unlisted"},
               "data": {"requests": [{"response": {"hash": main_hash}}]}}  # fmt: skip
        return self._ok(ProviderStatus.POSITIVE, {"task_id": scan_id, "url": url, "ip": ip, "asn": "AS64512", "ips": [ip],
                                                  "domains": raw["lists"]["domains"], "hashes": [main_hash],
                                                  "verdict": raw["verdicts"]["overall"]}, raw)  # fmt: skip

    async def picture_of(self, domain: str, limit: int = 6) -> ProviderResult:
        """A recorded public scan with a real picture, for a site whose own screenshot is blank. A scenario with
        ``http.no_snapshot`` has none."""
        sc = self.store.get(domain.lower()) or (self.store.get(domain[4:]) if domain.lower().startswith("www.") else None)
        if sc is None or sc.http is None or sc.http.get("no_snapshot"):
            return self._ok(ProviderStatus.UNKNOWN, {"domain": domain, "note": "no public scan with a picture (0 looked at)"})
        shot = demo_screenshot(sc) or images.synth_screenshot(sc.host)
        when = (datetime.now(UTC) - timedelta(days=2)).isoformat()
        return self._ok(ProviderStatus.POSITIVE, {
            "domain": domain, "scan_id": "mock-pic-" + sc.host, "url": f"https://{sc.host}/", "reached": sc.http.get("final_url") or sc.url,
            "time": when, "title": None, "screenshot_url": f"/ui/demo-shot/{sc.host}", "result_url": f"https://urlscan.io/result/mock-pic-{sc.host}/",
            "via": "a scan of the site itself", "screenshot_png": shot})  # fmt: skip

    async def snapshot(self, domain: str, scan_id: str | None = None, peek: bool = False) -> ProviderResult:
        """A recorded public scan of the homepage: the real page, its picture and its icon, a few days old.
        A scenario with ``http.no_snapshot`` has none (the 'urlscan.io does not know it' path). ``scan_id``
        ("mock-snap-<host>") points at one scan, like a pasted urlscan.io link."""
        host = domain.lower()
        if scan_id:
            if not scan_id.startswith("mock-snap-"):
                return self._ok(ProviderStatus.UNKNOWN, {"domain": domain, "note": "urlscan.io does not list that scan"})
            host = scan_id.removeprefix("mock-snap-")
        sc = self.store.get(host) or (self.store.get(host[4:]) if host.startswith("www.") else None)
        if sc is None or sc.http is None or sc.http.get("no_snapshot"):
            return self._ok(ProviderStatus.UNKNOWN, {"domain": domain, "note": "no public scan of the homepage"})
        html = sc.http.get("html", "")
        title = html.split("<title>")[-1].split("</title>")[0][:120] if "<title>" in html else None
        when = (datetime.now(UTC) - timedelta(days=3)).isoformat()
        meta = {"domain": domain, "scan_id": "mock-snap-" + sc.host, "url": f"https://{sc.host}/", "time": when,
                "title": title, "screenshot_url": f"/ui/demo-shot/{sc.host}",
                "result_url": f"https://urlscan.io/result/mock-snap-{sc.host}/", "has_key": True}  # fmt: skip
        if peek:
            return self._ok(ProviderStatus.POSITIVE, meta)
        return self._ok(ProviderStatus.POSITIVE, {**meta, "screenshot_png": demo_screenshot(sc, decoy=False, similar_shift=0),
                                                  "html": html, "favicon_png": demo_favicon(sc)})  # fmt: skip

    @staticmethod
    def screenshot_url(scan_id: str) -> str:
        # recorded scans show the rendered picture of the site, served by the demo server
        if scan_id.startswith("mock-"):
            return f"/ui/demo-shot/{scan_id[5:]}"
        return f"https://urlscan.io/screenshots/{scan_id}.png"

    async def submit(self, url: str, visibility: str = "unlisted") -> ProviderResult:
        host = url.split("/")[2]
        return self._ok(ProviderStatus.POSITIVE, {"url": url, "task_id": "mock-" + host, "visibility": visibility,
                                                  "result_url": f"https://urlscan.io/result/mock-{host}/"})  # fmt: skip

    async def search(self, query: str, limit: int = 50) -> ProviderResult:
        """Similar pages: the recorded kit cluster for hash:/page.ip:/page.domain: queries."""
        q = query.lower()
        results = []
        if q.startswith("page.domain:") and ' and page.url:"' in q:  # a traffic-distribution campaign: the recorded sites whose link carries its number
            path = q.split(' and page.url:"', 1)[1].rstrip('"')
            for sc in self.store.all():
                for hop in (sc.http or {}).get("hops", []):
                    if path in hop:
                        results.append({"url": hop, "domain": hop.split("/")[2], "task_id": "mock-tds-" + sc.host, "time": datetime.now(UTC).isoformat(),
                                        "page_title": None})  # fmt: skip
            results += [{"url": f"https://{h}/go/{path.rsplit('/', 1)[-1]}?subid1={d}", "domain": h, "task_id": "mock-tds-" + d, "time": datetime.now(UTC).isoformat(),
                         "page_title": None} for h, d in (("tds.example", "unrelated-offers.example"),)] if results else []  # fmt: skip
            return self._ok(ProviderStatus.POSITIVE if results else ProviderStatus.UNKNOWN, {"query": query, "results": results[:limit], "total": len(results)})
        for i, sc in enumerate(self.store.all()):
            host = sc.url.split("/")[2]
            same_ip = (sc.infra or {}).get("ip") == "203.0.113.66"
            if q.startswith("hash:") and not same_ip:
                continue
            if q.startswith("page.ip:") and not same_ip:
                continue
            if q.startswith("page.domain:") and q.split("*")[1] not in host.replace("0", "o"):
                continue
            bad = _verdict(host) is ProviderStatus.POSITIVE
            results.append({"url": sc.url, "domain": host, "task_id": "mock-" + host, "time": (datetime.now(UTC) - timedelta(days=i)).isoformat(),
                            "page_title": f"{host} - Sign in", "ip": (sc.infra or {}).get("ip") or "203.0.113.66", "asn": "AS64512",
                            "asnname": "BulletproofHost BV", "country": "NL", "server": "nginx", "malicious": bad,
                            "screenshot": f"/ui/demo-shot/{host}"})  # fmt: skip
        return self._ok(ProviderStatus.POSITIVE if results else ProviderStatus.UNKNOWN,
                        {"query": query, "results": results[:limit], "total": len(results)})  # fmt: skip


_CITIES = [
    ("NL", "Amsterdam", 52.3676, 4.9041),
    ("DE", "Frankfurt", 50.1109, 8.6821),
    ("US", "Ashburn", 39.0438, -77.4874),
    ("US", "Los Angeles", 34.0522, -118.2437),
    ("RU", "Moscow", 55.7558, 37.6173),
    ("SG", "Singapore", 1.3521, 103.8198),
    ("BR", "Sao Paulo", -23.5505, -46.6333),
    ("IN", "Mumbai", 19.0760, 72.8777),
    ("GB", "London", 51.5074, -0.1278),
    ("TR", "Istanbul", 41.0082, 28.9784),
    ("HK", "Hong Kong", 22.3193, 114.1694),
    ("ZA", "Johannesburg", -26.2041, 28.0473),
    ("FR", "Paris", 48.8566, 2.3522),
    ("JP", "Tokyo", 35.6762, 139.6503),
    ("NG", "Lagos", 6.5244, 3.3792),
]
_KNOWN_GEO = {
    "203.0.113.66": ("NL", "Amsterdam", 52.3676, 4.9041, "BulletproofHost BV"),
    "198.51.100.77": ("RU", "Moscow", 55.7558, 37.6173, "Fast VPS LLC"),
}


class MockGeoProvider(_MockBase):
    """Deterministic geolocation: known kit servers have fixed cities; others hash into a city list."""

    async def locate(self, ip: str) -> ProviderResult:
        if ip in _KNOWN_GEO:
            cc, city, lat, lon, org = _KNOWN_GEO[ip]
        else:
            cc, city, lat, lon = _CITIES[_digest(ip) % len(_CITIES)]
            org = "Mock Hosting LLC"
        return self._ok(
            ProviderStatus.POSITIVE,
            {"ip": ip, "country": cc, "city": city, "lat": lat, "lon": lon, "org": org},
        )


class MockLLMProvider(_MockBase):
    """Deterministic stand-in for the LLM: transparent heuristics over the brief, same schemas."""

    LURES = (
        "verify",
        "suspended",
        "unusual activity",
        "within 24 hours",
        "confirm your",
        "locked",
        "update your payment",
    )

    async def analyze(self, text: str, schema: dict[str, Any]) -> ProviderResult:
        title = schema.get("title")
        low = text.lower()
        if title == "phishing_triage":
            m = re.search(r"^Title: (.+)$", text, flags=re.M)
            page_title = m.group(1).strip() if m else ""
            brand = (
                re.split(r"\s+[—\-·|]\s+", page_title)[0].strip()
                if page_title and page_title != "-"
                else None
            )
            creds = "password=true" in low
            cards = "card=true" in low
            lure = any(x in low for x in self.LURES)
            external = "external_action=true" in low
            phishing = (creds or cards) and (lure or external or bool(brand))
            conf = 0.35 + 0.3 * (creds or cards) + 0.2 * lure + 0.15 * external
            reasons = [r for r, on in (("credential form", creds), ("card form", cards), ("lure language", lure),
                                       ("form posts off-site", external)) if on]  # fmt: skip
            return self._ok(ProviderStatus.POSITIVE, {
                "is_phishing": phishing,
                "impersonated_brand": brand if phishing else None,
                "confidence": round(min(conf, 0.97), 2),
                "rationale": ("; ".join(reasons) or "no credential or payment capture") + (f"; page presents itself as {brand}" if brand and phishing else ""),
            })  # fmt: skip
        if title == "ai_prompts":
            m = re.search(r"^Brand: (.+)$", text, flags=re.M)
            name = m.group(1).strip() if m else "the brand"
            ml = re.search(r"^Languages: (.+)$", text, flags=re.M)
            langs = [x.strip() for x in (ml.group(1) if ml else "en").split(",") if x.strip()] or ["en"]
            said = {"en": [("support_phone", f"what's the {name} support phone number"), ("contact", f"how do i reach {name} customer service? phone or email"),
                           ("login", f"{name} login page link"), ("fraud", f"someone used my {name} card, who do i call")],
                    "he": [("support_phone", f"מה הטלפון של התמיכה של {name}"), ("contact", f"איך יוצרים קשר עם {name}? טלפון או מייל"),
                           ("login", f"קישור לכניסה לחשבון {name}"), ("fraud", f"גנבו לי את הכרטיס של {name} למי מתקשרים")]}  # fmt: skip
            return self._ok(ProviderStatus.POSITIVE, {"prompts": [{"text": t, "topic": tp, "lang": la}
                                                                  for la in langs for tp, t in said.get(la, said["en"])]})  # fmt: skip
        if title == "brand_profile":
            m = re.search(r"^Brand: (.+)$", text, flags=re.M)
            name = m.group(1).strip().lower() if m else "brand"
            key = re.sub(r"[^a-z0-9]", "", name)
            half = max(2, len(key) // 2)
            return self._ok(ProviderStatus.POSITIVE, {
                "keywords": [key],
                "lures": [f"verify your {name} account", f"your {name} order is on hold", f"{name} security alert",
                          "unusual sign-in activity", "update your payment details"],
                "search_queries": [f"{name} login", f"{name} sign up", f"{name} support", f"{name} app",
                                   f"{key[:half]} {key[half:]} login", f"{key[:half]} {key[half:]}"],
                "vertical": "ecommerce" if "shop" in key else "other",
            })  # fmt: skip
        if title == "brand_commerce_profile":
            m = re.search(r"^Brand: (.+)$", text, flags=re.M)
            name = m.group(1).strip() if m else "Brand"
            key = re.sub(r"[^a-z0-9]", "", name.lower())
            mc = re.search(r"^Countries: (.+)$", text, flags=re.M)
            countries = [
                c.strip().upper() for c in (mc.group(1) if mc else "US").split(",") if c.strip()
            ]
            price = {
                "IL": (480, "ILS"),
                "US": (130, "USD"),
                "GB": (110, "GBP"),
                "DE": (120, "EUR"),
                "FR": (120, "EUR"),
            }
            retail = any(
                w in key for w in ("shop", "store", "running", "shoe", "wear", "sport", "nova")
            )
            products, retailers = [], []
            for c in countries:
                amount, cur = price.get(c, (130, "USD"))
                products += [
                    {
                        "name": f"{name} Runner",
                        "typical_price": amount,
                        "currency": cur,
                        "country": c,
                    },
                    {
                        "name": f"{name} Trail",
                        "typical_price": round(amount * 1.2),
                        "currency": cur,
                        "country": c,
                    },
                ]
                retailers.append(
                    {"name": f"{name} Partners", "domain": f"{key}-partners.com", "country": c}
                )
            return self._ok(ProviderStatus.POSITIVE, {
                "resold_by_retailers": retail,
                "why": ("physical products sold through authorised retailers and marketplaces" if retail
                        else "a service sold only by the brand itself"),
                "ad_keywords": [name.lower(), f"{name.lower()} runner", f"{name.lower()} sale", "trail running shoes"] if retail else [],
                "model_lines": [f"{name.lower()} runner", "running shoes"] if retail else [],
                "products": products if retail else [],
                "authorized_retailers": retailers if retail else [],
            })  # fmt: skip
        if title == "ad_relevance":
            # transparent stand-in: an ad is about the brand when it writes the brand as one word or
            # talks about shoes / pairs / sizes; anything else used the words in another sense
            m = re.search(r"^Brand: (.+)$", text, flags=re.M)
            key = re.sub(r"[^a-z0-9]", "", (m.group(1) if m else "").lower())
            rows = []
            for line in re.findall(r"^\[([^\]]+)\] (.*)$", text, flags=re.M):
                ad_id, rest = line
                about = bool(key and key in re.findall(r"[a-z0-9]+", rest.lower())) or bool(
                    re.search(r"\b(shoes?|sneakers?|pairs?|sizes?)\b|נעל|זוג|מידות", rest, re.I))
                rows.append({"id": ad_id, "about_brand": about,
                             "why": "the ad sells the brand's products" if about
                             else "the words are used in another sense"})  # fmt: skip
            return self._ok(ProviderStatus.POSITIVE, {"ads": rows})
        if title == "social_impersonation":
            # transparent stand-in: self-declared fan pages are fans; an account that does not carry
            # the brand is unrelated; refunds / giveaways / "DM your card" are impersonation
            mb = re.search(r"^Brand: (.+)$", text, flags=re.M)
            ma = re.search(r"^Account: (.+)$", text, flags=re.M)
            key = re.sub(r"[^a-z0-9]", "", (mb.group(1) if mb else "").lower())
            acct = re.sub(r"[^a-z0-9]", "", (ma.group(1) if ma else "").lower())
            body = text.split("--- BEGIN UNTRUSTED ACCOUNT CONTENT ---")[-1].lower()  # the account, not the task
            asks = [w for w, k in (("order number", "order"), ("card details", "card"), ("a direct message", "dm "),
                                   ("shipping payment", "shipping"), ("personal details", "email")) if k in body]  # fmt: skip
            if any(w in body for w in ("not affiliated", "unofficial", "fan group", "fan page")):
                out = ("fan_or_community", 0.8, False, [], ["says it is an unofficial fan community"], "A fan community, not the brand.")
            elif key and key not in acct:
                out = ("unrelated", 0.85, False, [], ["the account is about another business"], "Another business with a similar name.")
            elif any(w in body for w in ("refund", "giveaway", "dm your", "verify your card", "card you paid", "pay only shipping", "claim")):
                out = ("impersonation", 0.9, True, asks or ["a direct message"],
                       ["calls itself the brand or its support", "asks people to message it or pay outside the official site",
                        "links to a site that is not the brand's"], "Poses as the brand to collect payments or personal details.")
            else:
                out = ("unclear", 0.5, False, [], ["not enough content to tell"], "Not enough content to tell.")
            return self._ok(ProviderStatus.POSITIVE, dict(zip(("verdict", "confidence", "claims_to_be_brand", "asks_for", "reasons", "summary"), out, strict=True)))
        if title == "shop_legitimacy":
            m = re.search(r"^Checks failed: (.*)$", text, flags=re.M)
            failed = [x for x in (m.group(1).split(";") if m else []) if x.strip()]
            replica = "price" in low and any("price" in f for f in failed)
            verdict = (
                "likely_scam" if len(failed) >= 3 else ("suspicious" if failed else "legitimate")
            )
            return self._ok(ProviderStatus.POSITIVE, {
                "verdict": verdict,
                "sells_replicas_likely": replica or verdict == "likely_scam",
                "confidence": round(min(0.95, 0.5 + 0.1 * len(failed)), 2),
                "reasons": [f.strip() for f in failed][:6] or ["company found in the registry, policies and contact details present"],
                "review_summary": ("reviews mention fake or replica products" if "replica" in low or "scam" in low
                                   else "no reviews found about this shop"),
            })  # fmt: skip
        out = {k: f"mock-{k}" for k in schema.get("properties", {})}
        return self._ok(ProviderStatus.POSITIVE, out)


class MockAdsProvider(_MockBase):
    """Meta Ad Library search over the recorded scenarios' ``ads`` blocks: an ad matches when the
    keyword is in its text and it ran in that country. The landing link is wrapped the way Facebook
    wraps it (``l.facebook.com/l.php?u=…&fbclid=…``) so the stream's unwrapping is exercised."""

    PAGE = 4  # ads per page in the recorded world (the real Ad Library answers ~30)

    async def meta_ads(
        self, query: str, country: str, active_status: str = "active", next_page_token: str | None = None
    ) -> ProviderResult:
        from urllib.parse import quote

        q, cc, ads = query.lower().strip(), country.upper(), []
        for sc in self.store.all():
            for i, ad in enumerate(sc.ads):
                text = str(ad.get("text") or "")
                keys = [str(k).lower() for k in ad.get("keywords") or []]
                if (q in text.lower() or q in keys) and (
                    cc == "ALL" or cc in [c.upper() for c in ad.get("countries") or ["US"]]
                ):
                    ad_id = str(int(hashlib.sha256(f"{sc.host}:{i}".encode()).hexdigest()[:13], 16))
                    landing = f"{sc.url}{'&' if '?' in sc.url else '?'}utm_source=facebook&utm_medium=paid&fbclid=IwAR{ad_id[:8]}"
                    ads.append({
                        "ad_id": ad_id, "page_id": str(ad.get("page_id") or ad_id[:12]), "page_name": ad.get("page_name") or sc.host,
                        "text": text[:600], "link_url": f"https://l.facebook.com/l.php?u={quote(landing, safe='')}&h=AT0x",
                        "image": None, "start_date": ad.get("start_date"), "platforms": ["facebook", "instagram"],
                        "country": cc, "active": True, "library_url": f"https://www.facebook.com/ads/library/?id={ad_id}",
                    })  # fmt: skip
        start = int(next_page_token or 0)
        page = ads[start : start + self.PAGE]
        nxt = str(start + self.PAGE) if start + self.PAGE < len(ads) else None
        return self._ok(ProviderStatus.POSITIVE if page else ProviderStatus.UNKNOWN,
                        {"query": query, "country": cc, "ads": page, "total": len(ads), "next_page_token": nxt})  # fmt: skip


class MockRegistryProvider(_MockBase):
    """Company registries: the scenario whose ``registry.number`` matches answers; any other number
    is unknown to the recorded world (NOT_APPLICABLE — never "valid")."""

    async def lookup(self, number: str, country: str, name: str | None = None) -> ProviderResult:
        digits = re.sub(r"\W", "", number or "").upper()
        for sc in self.store.all():
            reg = sc.registry or {}
            if digits and re.sub(r"\W", "", str(reg.get("number") or "")).upper() == digits:
                st = reg.get("status", "found")
                status = {
                    "found": ProviderStatus.POSITIVE,
                    "dissolved": ProviderStatus.POSITIVE,
                }.get(st, ProviderStatus.NEGATIVE)
                return self._ok(status, {
                    "status": "active" if st == "found" else st, "number": digits, "name": reg.get("name"),
                    "registered": reg.get("registered"),
                    "registry": {"il_companies": "the Israeli Registrar of Companies", "companies_house": "UK Companies House",
                                 "vies": "EU VIES", "gleif": "GLEIF", "opencorporates": "OpenCorporates"}.get(self.stand_in_for, self.stand_in_for)
                    + " (recorded)",
                    "source_url": "https://data.gov.il/dataset/ica_companies",
                })  # fmt: skip
        return self._ok(
            ProviderStatus.NOT_APPLICABLE,
            {"status": "not_checked", "why": "no recorded registry answer"},
        )


SOCIAL_FIXTURE = Path(__file__).resolve().parents[2] / "demo" / "social.json"


@lru_cache(maxsize=1)
def social_world() -> dict[str, Any]:
    import json

    return json.loads(SOCIAL_FIXTURE.read_text(encoding="utf-8"))


def _days_ago(n: int | None) -> str | None:
    return None if n is None else (datetime.now(UTC) - timedelta(days=int(n))).date().isoformat()


class MockSocialProvider(_MockBase):
    """Facebook page search, page info and Instagram profiles from the recorded demo world
    (``demo/social.json``). Page search behaves like Meta's typeahead: loose, so a page that only
    shares part of the name (a bakery called "Nova Shop") comes back too and has to be filtered."""

    @staticmethod
    def _page(p: dict[str, Any]) -> dict[str, Any]:
        alias = p.get("page_alias")
        ver = p.get("verification") or "NOT_VERIFIED"
        return {"platform": "facebook", "page_id": p["page_id"], "name": p["name"], "alias": alias, "category": p.get("category"),
                "verified": ver == "BLUE_VERIFIED", "verification": ver, "entity_type": p.get("entity_type"), "image": p.get("image"),
                "likes": p.get("likes"), "ig_username": p.get("ig_username"), "ig_followers": p.get("ig_followers"),
                "url": f"https://www.facebook.com/{alias or p['page_id']}"}  # fmt: skip

    async def page_search(self, query: str, country: str = "ALL") -> ProviderResult:
        q = re.sub(r"[^a-z0-9]", "", query.lower())
        pages = [self._page(p) for p in social_world()["pages"] if q and ("nova" in q or q in re.sub(r"[^a-z0-9]", "", p["name"].lower()))]
        return self._ok(ProviderStatus.POSITIVE if pages else ProviderStatus.UNKNOWN, {"query": query, "pages": pages})

    async def page_info(self, page_id: str) -> ProviderResult:
        p = next((x for x in social_world()["pages"] if x["page_id"] == str(page_id)), None)
        if p is None:
            return self._ok(ProviderStatus.UNKNOWN, {"page_id": str(page_id), "name": None})
        info = p.get("info") or {}
        renamed = _days_ago(info.get("renamed_days_ago"))
        return self._ok(ProviderStatus.POSITIVE, {
            **self._page(p), "about": info.get("about", ""), "created": _days_ago(info.get("created_days_ago")),
            "name_changes": [{"at": renamed, "item": "NAME_CHANGE"}] if renamed else [],
            "admin_countries": dict(info.get("admin_countries") or {}), "owner": None,
        })  # fmt: skip

    async def instagram_profile(self, username: str) -> ProviderResult:
        u = username.lstrip("@").lower()
        x = next((i for i in social_world()["instagram"] if i["username"].lower() == u), None)
        if x is None:
            return self._ok(ProviderStatus.UNKNOWN, {"username": username, "found": False})
        posts = [{"caption": c, "permalink": f"https://www.instagram.com/p/demo{i}/", "date": _days_ago(3 * i + 1), "likes": 10 + i, "comments": i}
                 for i, c in enumerate(x.get("posts") or [])]  # fmt: skip
        return self._ok(ProviderStatus.POSITIVE, {
            "platform": "instagram", "found": True, "username": x["username"], "name": x.get("name", ""), "bio": x.get("bio", ""),
            "image": x.get("image"), "verified": bool(x.get("verified")), "business": bool(x.get("business")),
            "followers": x.get("followers"), "following": x.get("following", 80), "posts_count": len(posts) + 40,
            "external_link": x.get("external_link"), "bio_links": [x["external_link"]] if x.get("external_link") else [],
            "posts": posts, "url": f"https://www.instagram.com/{x['username']}/",
        })  # fmt: skip


AI_ANSWERS_FIXTURE = Path(__file__).resolve().parents[2] / "demo" / "ai_answers.json"
_FOLLOWUP_WORDS = ("official page", "show me", "proof", "evidence", "suspect", "where did", "source", "ראיה", "הוכחה",
                   "חושד", "מאיפה", "עמוד", "הונאה")  # fmt: skip
_LOGIN_WORDS = ("log in", "login", "sign in", "signin", "התחבר", "כניסה", "להיכנס", "connexion", "anmelden", "iniciar sesión")


@lru_cache(maxsize=1)
def ai_answers_world() -> dict[str, Any]:
    import json

    return json.loads(AI_ANSWERS_FIXTURE.read_text(encoding="utf-8"))


class MockAiAnswersProvider(_MockBase):
    """What ChatGPT / Gemini / Google AI Mode answer, from the recorded demo world (``demo/ai_answers.json``).
    The topic comes from the prompt's words (contact details or login); a follow-up that quotes a
    contact gets the follow-up recorded for that contact. Another brand gets an answer without contacts."""

    async def ask(self, engine: str, prompt: str, *, gl: str | None = None, hl: str | None = None,
                  conversation_token: str | None = None) -> ProviderResult:  # fmt: skip
        from brandwatch.detection.contacts import from_text, urls_in
        from brandwatch.providers.impl.commerce import normalize_ai_answer

        world = ai_answers_world()
        low = prompt.lower()
        rec = (world["answers"] or {}).get(engine) or {}
        raw: dict[str, Any]
        if world.get("brand_match", "nova") not in low or not rec:
            raw = {"markdown": world["unknown_brand"], "reference_links": []}
        elif any(w in low for w in _FOLLOWUP_WORDS) and (from_text(prompt) or urls_in(prompt)):
            ups = rec.get("followups") or {}
            quoted = [f.value for f in from_text(prompt)]
            key = next((v for v in quoted if v in ups), None)
            raw = ups[key] if key else {"markdown": world["followup_default"], "reference_links": []}  # keys: normalised values
        elif any(w in low for w in _LOGIN_WORDS):
            raw = rec.get("login") or {"markdown": world["unknown_brand"], "reference_links": []}
        else:
            raw = rec.get("contact") or {"markdown": world["unknown_brand"], "reference_links": []}
        raw = {**raw, "response_metadata": {"model": f"demo-{engine}", "is_web_search_performed": True},
               "pagination": {"conversation_token": f"demo-{engine}-{hashlib.sha256(prompt.encode()).hexdigest()[:10]}"} if engine == "google_ai_mode" else {}}  # fmt: skip
        data = normalize_ai_answer(engine, prompt, raw)
        return self._ok(ProviderStatus.POSITIVE if data["answer"] else ProviderStatus.UNKNOWN, data)


MOCKS_BY_KIND: dict[str, type[_MockBase]] = {
    "ads": MockAdsProvider,
    "social": MockSocialProvider,
    "ai_answers": MockAiAnswersProvider,
    "registry": MockRegistryProvider,
    "reputation": MockReputationProvider,
    "whois": MockWhoisProvider,
    "dns": MockDnsProvider,
    "passive_dns": MockDnsProvider,
    "cert": MockCertProvider,
    "search": MockSearchProvider,
    "host": MockHostProvider,
    "browser": MockBrowserFetcher,
    "urlscan": MockScanSearchProvider,
    "geo": MockGeoProvider,
    "llm": MockLLMProvider,
}

__all__ = [
    "MOCKS_BY_KIND",
    "MockBrowserFetcher",
    "MockCertProvider",
    "MockDnsProvider",
    "MockGeoProvider",
    "MockHostProvider",
    "MockLLMProvider",
    "MockReputationProvider",
    "MockScanSearchProvider",
    "MockSearchProvider",
    "MockWhoisProvider",
]
