"""Site & network intel — the "Investigate site and its network" page.

Everything an analyst would collect by hand on VirusTotal / urlscan for one suspect site, run as a
background job (``kind="intel"``) and cached per (subject, source, relation) in ``intel_lookups``:

* domain: VirusTotal report (detections, last DNS records, last HTTPS certificate, WHOIS text,
  JARM, categories), RDAP registration, live DNS/certificate when VT has none, relations
  (passive DNS with per-IP detections, historical WHOIS, historical certificates, communicating
  files, referrer files, subdomains) and certificate-transparency history;
* each IP behind it: VT report (country, ASN, owner, detections), every other site on the IP with
  its own detections, communicating files, geolocation;
* urlscan: a fresh scan (with a key) or the latest public one, plus "similar sites" (same page
  hash, same server, same brand name).

VirusTotal's public API allows 4 requests/minute: calls are paced with a sliding window so the job
never trips the quota; relations the plan does not include come back as *not available* rows.
"""

from __future__ import annotations

import asyncio
import ipaddress
import re
import threading
import time
import uuid
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from typing import Any

import sqlalchemy as sa
from sqlalchemy.orm import Session

from brandwatch import trace
from brandwatch.config.settings import Settings, get_settings
from brandwatch.db.base import set_checkpoint
from brandwatch.db.enums import JobState, ProviderStatus
from brandwatch.db.models import Brand, Candidate, Finding, IntelLookup, ScanJob, ScanStage
from brandwatch.db.types import utcnow
from brandwatch.detection import dnslookup, hosting, whois_history
from brandwatch.detection.discovery import split_host
from brandwatch.detection.enrichment import _on_cloudflare
from brandwatch.events.emitter import ScanEventEmitter
from brandwatch.providers.base import ProviderResult
from brandwatch.providers.ledger import DbUsageLedger
from brandwatch.providers.registry import ProviderRegistry
from brandwatch.ui.flags import country_name

TTL = timedelta(hours=24)
MAX_IPS = 4
MAX_CALLS = 48
MAX_SECONDS = 600  # of its own working time: the minutes spent waiting for the shared VirusTotal quota do not count
VT_RELATIONS_DOMAIN = (
    "resolutions",
    "historical_whois",
    "historical_ssl_certificates",
    "communicating_files",
    "referrer_files",
    "subdomains",
)
VT_RELATIONS_IP = ("resolutions", "communicating_files", "historical_whois")
# The quick investigation that follows a confirmation: what places the site in a network (where it has pointed, who owned it,
# what hangs under it, who else sits on the server). The files that talked to it, the files that refer to it and its old
# certificates (CT has those) wait for the analyst's own "Investigate": 8 VirusTotal requests instead of 19.
VT_RELATIONS_DOMAIN_LIGHT = ("resolutions", "historical_whois", "subdomains")
VT_RELATIONS_IP_LIGHT = ("resolutions",)
DNS_TYPES = ("A", "AAAA", "CNAME", "NS", "MX", "TXT", "SOA")
STAGE = "intel"
# A Cloudflare edge address is shared by a great many unrelated sites: the sites "hosted" on it, the files that talked to it
# and its WHOIS history are about Cloudflare, not about the suspect, and each of the three costs a VirusTotal request (the free
# plan allows 4 a minute, about 90 s for the two edge addresses of one site). They are skipped, and the page says why.
SHARED_NOTE = ("Cloudflare address shared by a great many unrelated sites: the list was skipped because it says nothing "
               "about this site")  # fmt: skip


# --------------------------------------------------------------------------------------------
# cache
# --------------------------------------------------------------------------------------------
def _get_row(
    session: Session, ws: uuid.UUID, stype: str, subject: str, source: str, relation: str
) -> IntelLookup | None:
    return session.scalar(
        sa.select(IntelLookup).where(
            IntelLookup.workspace_id == ws, IntelLookup.subject_type == stype,
            IntelLookup.subject == subject.lower(), IntelLookup.source == source,
            IntelLookup.relation == relation,
        )
    )  # fmt: skip


def is_fresh(row: IntelLookup | None) -> bool:
    if row is None or row.status == "error":
        return False
    exp = row.expires_at
    if exp is not None and exp.tzinfo is None:
        exp = exp.replace(tzinfo=UTC)
    return exp is None or exp > datetime.now(UTC)


def put_row(
    session: Session, ws: uuid.UUID, stype: str, subject: str, source: str, relation: str,
    payload: Any, *, status: str = "ok", error: str | None = None, ttl: timedelta = TTL,
) -> IntelLookup:  # fmt: skip
    row = _get_row(session, ws, stype, subject, source, relation)
    if row is None:
        row = IntelLookup(
            workspace_id=ws, subject_type=stype, subject=subject.lower(), source=source,
            relation=relation,
        )  # fmt: skip
        session.add(row)
    row.payload = payload
    row.status = status
    row.error = error
    row.fetched_at = utcnow()
    row.expires_at = utcnow() + ttl
    session.flush()
    return row


def related_by_owner(
    session: Session, ws: uuid.UUID, owners: list[dict], exclude: str = ""
) -> list[dict[str, Any]]:
    """Other domains in this workspace tied to the same owner e-mail: in another domain's WHOIS
    history, or in the WHOIS evidence a scan collected. No API call — a reverse-WHOIS on our own data."""
    from brandwatch.db.models import Evidence, WhoisObservation

    emails = sorted({(o.get("visible") or {}).get("email", "").lower() for o in owners} - {""})
    if not emails:
        return []
    found: dict[str, set[str]] = {e: set() for e in emails}
    for subject, payload in session.execute(
        sa.select(IntelLookup.subject, IntelLookup.payload).where(
            IntelLookup.workspace_id == ws, IntelLookup.source == "whoisxml",
            IntelLookup.relation == "history", IntelLookup.status == "ok",
        )
    ).all():  # fmt: skip
        if subject == exclude:
            continue
        text = str(payload).lower()
        for e in emails:
            if e in text:
                found[e].add(subject)
    for host, reg in session.execute(
        sa.select(Candidate.hostname, WhoisObservation.registrant)
        .join(Evidence, Evidence.candidate_id == Candidate.id)
        .join(WhoisObservation, WhoisObservation.evidence_id == Evidence.id)
        .join(Brand, Brand.id == Candidate.brand_id)
        .where(Brand.workspace_id == ws)
    ).all():
        e = str((reg or {}).get("email") or "").lower()
        if e in found and host != exclude and split_host(host).registrable != exclude:
            found[e].add(split_host(host).registrable or host)
    return [{"email": e, "domains": sorted(d)} for e, d in found.items() if d]


def rows_for(session: Session, ws: uuid.UUID, stype: str, subject: str) -> dict[str, IntelLookup]:
    """All cached rows of a subject keyed ``source/relation``."""
    rows = session.scalars(
        sa.select(IntelLookup).where(
            IntelLookup.workspace_id == ws, IntelLookup.subject_type == stype,
            IntelLookup.subject == subject.lower(),
        )
    ).all()  # fmt: skip
    return {f"{r.source}/{r.relation}": r for r in rows}


# --------------------------------------------------------------------------------------------
# the collector
# --------------------------------------------------------------------------------------------
class _Pacer:
    """Sliding-window limiter: at most ``per_minute`` calls in any 60 s window. One pacer is shared by every investigation
    that runs at once (``shared_pacer``): VirusTotal's quota belongs to the key, not to a job, so ten confirmations queue up
    behind each other instead of each spending the minute's four requests. A call reserves its slot before it sleeps."""

    def __init__(self, per_minute: int, sleep: Callable[[float], Any] | None = None) -> None:
        self.per_minute = max(1, int(per_minute))
        self.stamps: list[float] = []  # the times calls were (or are going to be) made, oldest first
        self._sleep = sleep or asyncio.sleep
        self._lock = threading.Lock()

    async def wait(self, on_wait: Callable[[float], None] | None = None) -> None:
        with self._lock:
            now = time.monotonic()
            self.stamps = [t for t in self.stamps if now - t < 60.2]
            at = now
            if len(self.stamps) >= self.per_minute:
                at = max(now, self.stamps[-self.per_minute] + 60.2)  # the call that is `per_minute` places back leaves the window
            self.stamps.append(at)
            delay = at - now
        if delay > 0:
            if on_wait:
                on_wait(delay)
            await self._sleep(delay)


_PACERS: dict[int, _Pacer] = {}
_PACERS_LOCK = threading.Lock()


def shared_pacer(per_minute: int) -> _Pacer:
    with _PACERS_LOCK:
        return _PACERS.setdefault(int(per_minute), _Pacer(per_minute))


class Collector:
    def __init__(
        self, session: Session, ws: uuid.UUID, providers: ProviderRegistry, em: ScanEventEmitter | None,
        settings: Settings, *, force: bool = False, light: bool = False,
    ) -> None:  # fmt: skip
        self.session, self.ws, self.providers, self.em, self.settings = session, ws, providers, em, settings  # fmt: skip
        self.force = force
        self.light = light  # the quick investigation of a confirmation: fewer VirusTotal relations, one page of each
        self.api_calls = 0
        self.cache_hits = 0  # results reused from the 24 h cache (no API call, no cost)
        self.skipped = 0  # lookups not made on purpose (a Cloudflare edge address: see SHARED_NOTE)
        self.cost = 0.0
        self.t0 = time.monotonic()
        self.not_available: list[str] = []
        self.vt = next(
            (p for p in providers.reputation().providers if str(getattr(p, "name", "")).endswith("virustotal")),
            None,
        )  # fmt: skip
        is_mock = str(getattr(self.vt, "name", "")).startswith("mock:")
        self.pacer = _Pacer(10_000) if is_mock else shared_pacer(settings.virustotal_rate_per_minute)

    # --- narration ----------------------------------------------------------------------------
    def say(self, step: str, message: str, **kw: Any) -> None:
        if self.em is not None:
            self.em.running(STAGE, step, message, **kw)
        trace.log(STAGE, f"{step}: {message}")

    def done(self, step: str, message: str, **kw: Any) -> None:
        if self.em is not None:
            self.em.done(STAGE, step, message, **kw)
        trace.log(STAGE, f"{step}: {message}")

    def _budget_left(self) -> bool:
        return self.api_calls < MAX_CALLS and (time.monotonic() - self.t0) < MAX_SECONDS

    # --- one cached lookup ---------------------------------------------------------------------
    async def lookup(
        self, stype: str, subject: str, source: str, relation: str, fn: Callable[[], Any], *,
        shape: Callable[[ProviderResult], Any] | None = None, vt: bool = False,
    ) -> IntelLookup:  # fmt: skip
        """Return the cached row if fresh (and not forced), else call ``fn`` and cache the result."""
        row = _get_row(self.session, self.ws, stype, subject, source, relation)
        if is_fresh(row) and not self.force:
            trace.log(STAGE, f"{source}/{relation} {subject}: cache hit")
            self.cache_hits += 1
            return row
        if not self._budget_left():
            return put_row(self.session, self.ws, stype, subject, source, relation, None,
                           status="error", error="budget exhausted", ttl=timedelta(minutes=5))  # fmt: skip
        if vt:
            waiting_since = time.monotonic()
            await self.pacer.wait(
                lambda d: self.say(
                    "quota",
                    f"waiting {d:.0f}s for VirusTotal quota (public API: "
                    f"{self.pacer.per_minute} requests/min, shared by every investigation that is running) …",
                )  # fmt: skip
            )
            self.t0 += time.monotonic() - waiting_since  # queueing behind other investigations is not this job's time
        set_checkpoint(self.session)
        try:
            res = await fn()
        except Exception as exc:  # noqa: BLE001 - a lookup must never kill the job
            res = ProviderResult.failure(source, f"{type(exc).__name__}: {exc}")
        self.api_calls += 1
        self.cost += float(getattr(res, "cost_usd", 0) or 0)
        if res.status is ProviderStatus.NOT_APPLICABLE:
            note = (res.data or {}).get("note") or "not available"
            self.not_available.append(f"{source}/{relation}")
            return put_row(self.session, self.ws, stype, subject, source, relation, res.data,
                           status="not_available", error=note)  # fmt: skip
        if not res.ok:
            return put_row(self.session, self.ws, stype, subject, source, relation, None,
                           status="error", error=res.error or "error", ttl=timedelta(minutes=10))  # fmt: skip
        payload = shape(res) if shape else res.data
        return put_row(self.session, self.ws, stype, subject, source, relation, payload)

    async def _vt_pages(self, kind: str, value: str, rel: str, pages: int) -> ProviderResult:
        """``rel`` for ``value`` across up to ``pages`` cursor pages (VirusTotal serves at most 40
        items per page). The first page is paced by ``lookup``; later pages pace themselves."""
        merged: list[dict] = []
        cursor: str | None = None
        last: ProviderResult | None = None
        total = None
        for i in range(pages):
            if i:
                waiting_since = time.monotonic()
                await self.pacer.wait(
                    lambda d, i=i: self.say(
                        "quota",
                        f"waiting {d:.0f}s for VirusTotal quota (page {i + 1} of {rel.replace('_', ' ')}) …",
                    )
                )
                self.t0 += time.monotonic() - waiting_since
                self.api_calls += 1
            last = await self.vt.relationship(kind, value, rel, limit=40, cursor=cursor)
            if not last.ok:
                if merged:  # keep what we have
                    break
                return last
            data = last.data or {}
            merged += data.get("items") or []
            total = data.get("count", total)
            cursor = data.get("next_cursor")
            if not cursor:
                break
        return ProviderResult(
            last.provider if last else "virustotal",
            ProviderStatus.POSITIVE if merged else ProviderStatus.UNKNOWN,
            {
                "value": value,
                "relation": rel,
                "items": merged,
                "next_cursor": cursor,
                "count": total,
            },
            cost_usd=0.0,
        )

    # --- WHOIS history ---------------------------------------------------------------------------
    async def whois_history(self, reg: str) -> None:
        """Every WHOIS snapshot WhoisXML has for the registrable domain: past owners, registrars,
        re-registrations, and owner details that were public before privacy was switched on."""
        self.say(
            "whois_history",
            f"WHOIS history for {reg} (WhoisXML): every past owner, registrar and privacy change …",
        )
        wx = self.providers.single("whois", "whoisxml")
        if wx is None:
            put_row(self.session, self.ws, "domain", reg, "whoisxml", "history", None, status="not_available",
                    error="needs a WhoisXML key with the WHOIS History product (Settings → API keys)")  # fmt: skip
            self.not_available.append("whoisxml/history")
            self.done("whois_history", "WhoisXML key not configured → WHOIS history skipped")
            return
        row = await self.lookup("domain", reg, "whoisxml", "history", lambda: wx.history(reg))
        if row.status != "ok":
            self.done("whois_history", f"WHOIS history: {row.error}")
            return
        sm = whois_history.analyze((row.payload or {}).get("records") or [])["summary"]
        msg = (f"{sm['records']} WHOIS snapshot(s) · first registered {sm['first_registered'] or '—'} · "
               f"{sm['owner_changes']} owner change(s) · {sm['transfers']} transfer(s)")  # fmt: skip
        if sm["re_registrations"]:
            msg += " · re-registered after expiry"
        if sm["leaked_owner"]:
            v = sm["leaked_owner"]["visible"]
            msg += f" · owner visible before privacy: {v.get('email') or v.get('name') or v.get('organization')}"
        self.done("whois_history", msg)

    # --- domain ---------------------------------------------------------------------------------
    async def domain(self, host: str) -> dict[str, Any]:
        """Everything about the domain. The certificate-transparency history does not use VirusTotal, whose quota (4
        requests a minute) is what this step waits for, so it runs alongside instead of after: on the first live run
        it took 74 s of a 287 s job."""
        host = host.lower()
        reg = split_host(host).registrable or host
        ct = asyncio.create_task(self._ct(reg))
        try:
            attrs = await self._domain(host, reg)
        except BaseException:
            ct.cancel()
            raise
        await ct
        return attrs

    async def _ct(self, reg: str) -> None:
        self.say("ct", f"certificate transparency history for {reg} (crt.sh / CertSpotter) …")
        row = await self.lookup(
            "domain", reg, "cert", "ct", lambda: self.providers.cert().ct_search(reg)
        )
        self.done("ct", f"{len((row.payload or {}).get('certificates') or [])} certificate(s) in CT logs" if row.status == "ok" else f"CT: {row.error}")  # fmt: skip

    async def _domain(self, host: str, reg: str) -> dict[str, Any]:
        self.say("domain", f"VirusTotal report for {host}: detections, last DNS records, HTTPS certificate, WHOIS …")  # fmt: skip
        attrs: dict = {}
        if self.vt is not None:
            row = await self.lookup("domain", host, "virustotal", "report",
                                    lambda: self.vt.domain_report(host), vt=True)  # fmt: skip
            attrs = ((row.payload or {}).get("attributes") or {}) if row.status == "ok" else {}
            st = attrs.get("last_analysis_stats") or {}
            self.done("domain", f"VirusTotal: {int(st.get('malicious', 0)) + int(st.get('suspicious', 0))}/{sum(int(v) for v in st.values()) or 0} engines flag {host}"
                      if st else f"VirusTotal has no report for {host}")  # fmt: skip
        else:
            put_row(self.session, self.ws, "domain", host, "virustotal", "report", None,
                    status="not_available", error="VirusTotal API key not configured")  # fmt: skip
            self.not_available.append("virustotal")
            self.done("domain", "VirusTotal key not configured → using free sources (RDAP, DNS, live certificate, CT)")  # fmt: skip

        self.say("rdap", f"RDAP registration data for {reg} …")
        rdap_chain = self.providers.whois()
        rdap = next(
            (p for p in rdap_chain.providers if str(getattr(p, "name", "")).endswith("rdap")), None
        )
        if rdap is not None:
            row = await self.lookup("domain", reg, "rdap", "report", lambda: rdap.lookup(reg),
                                    shape=lambda r: {"data": r.data, "raw": r.raw})  # fmt: skip
        else:  # demo / no rdap member → whichever whois provider answers
            row = await self.lookup("domain", reg, "rdap", "report", lambda: rdap_chain.lookup(reg),
                                    shape=lambda r: {"data": r.data, "raw": r.raw})  # fmt: skip
        d = (row.payload or {}).get("data") or {}
        self.done("rdap", f"registrar {d.get('registrar') or '—'} · registered {d.get('registered_at') or '—'}"
                  if row.status == "ok" else f"RDAP: {row.error}")  # fmt: skip
        await self.whois_history(reg)

        if not attrs.get("last_dns_records"):
            self.say("dns", f"resolving {host} in Python: " + ", ".join(DNS_TYPES))
            await self.lookup("domain", host, "dns", "report", lambda: _live_dns(host))
            self.done("dns", "live DNS records collected")
        if not attrs.get("last_https_certificate"):
            self.say("cert", f"fetching the live TLS certificate of {host} (one handshake on the validated IP) …")  # fmt: skip
            await self.lookup("domain", host, "cert", "report", lambda: _live_cert(host))
            self.done("cert", "certificate captured")

        if self.vt is not None:
            for rel in (VT_RELATIONS_DOMAIN_LIGHT if self.light else VT_RELATIONS_DOMAIN):
                self.say("relations", f"VirusTotal {rel.replace('_', ' ')} for {host} …")
                pages = 2 if rel == "resolutions" and not self.light else 1
                row = await self.lookup("domain", host, "virustotal", rel,
                                        lambda rel=rel, pages=pages: self._vt_pages("domains", host, rel, pages), vt=True)  # fmt: skip
                n = len((row.payload or {}).get("items") or []) if row.status == "ok" else 0
                self.done("relations", f"{rel.replace('_', ' ')}: {n} item(s)" if row.status == "ok" else f"{rel.replace('_', ' ')}: {row.error}")  # fmt: skip
        return attrs

    # --- ip -------------------------------------------------------------------------------------
    async def ip(self, ip: str) -> None:
        self.say("ip", f"VirusTotal report for {ip}: country, ASN, detections …")
        if self.vt is not None:
            row = await self.lookup("ip", ip, "virustotal", "report", lambda: self.vt.ip_report(ip), vt=True)  # fmt: skip
            a = ((row.payload or {}).get("attributes") or {}) if row.status == "ok" else {}
            self.done("ip", f"{ip}: {country_name(a.get('country'))} · AS{a.get('asn') or '?'} {a.get('as_owner') or ''}" if a else f"{ip}: {row.error or 'no report'}")  # fmt: skip
            shared = _on_cloudflare([ip])
            if shared:
                self.done("ip", f"{ip} is a Cloudflare address shared by a great many unrelated sites — the sites on it, its files and its WHOIS history are skipped: they say nothing about this site")  # fmt: skip
            for rel in (VT_RELATIONS_IP_LIGHT if self.light else VT_RELATIONS_IP):
                if shared:
                    put_row(self.session, self.ws, "ip", ip, "virustotal", rel, None, status="skipped", error=SHARED_NOTE)
                    self.skipped += 1
                    continue
                self.say("ip", f"VirusTotal {rel.replace('_', ' ')} for {ip}" + (" — every site hosted on this server, each with its own detections …" if rel == "resolutions" else " …"))  # fmt: skip
                pages = 3 if rel == "resolutions" and not self.light else 1
                row = await self.lookup("ip", ip, "virustotal", rel,
                                        lambda rel=rel, pages=pages: self._vt_pages("ip_addresses", ip, rel, pages), vt=True)  # fmt: skip
                n = len((row.payload or {}).get("items") or []) if row.status == "ok" else 0
                self.done("ip", f"{ip} {rel.replace('_', ' ')}: {n}" if row.status == "ok" else f"{ip} {rel.replace('_', ' ')}: {row.error}")  # fmt: skip
        else:
            put_row(self.session, self.ws, "ip", ip, "virustotal", "report", None,
                    status="not_available", error="VirusTotal API key not configured")  # fmt: skip
        self.say("abuse", f"AbuseIPDB community reports for {ip} …")
        ab = self.providers.single("reputation", "abuseipdb")
        if ab is None:
            put_row(self.session, self.ws, "ip", ip, "abuseipdb", "check", None, status="not_available",
                    error="AbuseIPDB key not configured (Settings → API keys)")  # fmt: skip
            self.done("abuse", "AbuseIPDB key not configured → abuse reports skipped")
        else:
            row = await self.lookup("ip", ip, "abuseipdb", "check", lambda: ab.check_ip(ip))
            d = row.payload or {}
            self.done("abuse", f"{ip}: abuse score {d.get('abuse_score', 0)}/100 · {d.get('total_reports', 0)} report(s) from {d.get('distinct_users', 0)} reporter(s)"
                      if row.status == "ok" else f"AbuseIPDB: {row.error}")  # fmt: skip
        self.say("geo", f"geolocating {ip} …")
        row = await self.lookup("ip", ip, "geo", "report", lambda: self.providers.geo().locate(ip))
        g = row.payload or {}
        self.done("geo", f"{ip} → {country_name(g.get('country'))}{', ' + g['city'] if g.get('city') else ''} · {g.get('org') or ''}" if row.status == "ok" else f"geo: {row.error}")  # fmt: skip

    # --- urlscan ----------------------------------------------------------------------------------
    async def urlscan(self, url: str, host: str, ips: list[str], brand_key: str | None) -> None:
        chain = self.providers.urlscan()
        us = chain.providers[0] if chain.providers else None
        if us is None:
            put_row(self.session, self.ws, "domain", host, "urlscan", "scan", None,
                    status="not_available", error="urlscan provider not available")  # fmt: skip
            return
        row = _get_row(self.session, self.ws, "domain", host, "urlscan", "scan")
        if not (is_fresh(row) and not self.force):
            self.say("urlscan", f"submitting {url} to urlscan.io (unlisted scan) …")
            sub = await us.submit(url)
            self.api_calls += 1
            task_id = (sub.data or {}).get("task_id") if sub.ok else None
            result: ProviderResult | None = None
            # poll the raw client: the resilient wrapper caches "unknown" (= not finished yet)
            raw_client = getattr(us, "inner", us)

            async def fetch_result(tid: str) -> ProviderResult | None:
                try:
                    r = await raw_client.result(tid)
                except Exception as exc:  # noqa: BLE001 - keep polling / fall back
                    trace.log(STAGE, f"urlscan result {tid}: {type(exc).__name__}: {exc}")
                    return None
                self.api_calls += 1
                return r if r.ok and r.status is ProviderStatus.POSITIVE else None

            if task_id:
                for attempt in range(16):
                    await asyncio.sleep(0 if attempt == 0 else 5)
                    self.say(
                        "urlscan",
                        f"waiting for urlscan to finish ({task_id[:8]}…) — try {attempt + 1}",
                    )
                    result = await fetch_result(task_id)
                    if result is not None:
                        break
            if result is None:  # no key / not finished → latest finished public scan of the host
                self.say("urlscan", f"looking up the latest public urlscan of {host} …")
                srch = await us.search(f"page.domain:{host}", limit=5)
                self.api_calls += 1
                hits = [h for h in ((srch.data or {}).get("results") or []) if h.get("task_id") and h["task_id"] != task_id] if srch.ok else []  # fmt: skip
                if hits:
                    result = await fetch_result(hits[0]["task_id"])
            if result is not None and result.ok and result.status is ProviderStatus.POSITIVE:
                put_row(
                    self.session,
                    self.ws,
                    "domain",
                    host,
                    "urlscan",
                    "scan",
                    _shape_urlscan(result, us),
                )
                self.done("urlscan", f"urlscan verdict: {'malicious' if ((result.data or {}).get('verdict') or {}).get('malicious') else 'not flagged'}")  # fmt: skip
            else:
                put_row(self.session, self.ws, "domain", host, "urlscan", "scan", None, status="not_available",
                        error=(sub.data or {}).get("note") or sub.error or "no urlscan result")  # fmt: skip
                self.done("urlscan", "no urlscan result available")
        scan = (
            _get_row(self.session, self.ws, "domain", host, "urlscan", "scan") or IntelLookup()
        ).payload or {}
        if (
            is_fresh(_get_row(self.session, self.ws, "domain", host, "urlscan", "similar"))
            and not self.force
        ):
            trace.log(STAGE, f"urlscan/similar {host}: cache hit")
            return
        self.say("similar", "urlscan: pages with the same document hash, the same server and the same brand name …")  # fmt: skip
        groups: dict[str, Any] = {"by_hash": [], "by_ip": [], "by_brand": [], "queries": {}}
        queries: list[tuple[str, str]] = []
        if scan.get("main_hash"):
            queries.append(("by_hash", f"hash:{scan['main_hash']}"))
        for ip in [scan.get("ip")] if scan.get("ip") else ips[:1]:
            queries.append(("by_ip", f"page.ip:{ip}"))
        if brand_key:
            queries.append(("by_brand", f"page.domain:*{brand_key}*"))
        seen = {host}
        for key, q in queries:
            r = await us.search(q, limit=30)
            self.api_calls += 1
            groups["queries"][key] = q
            for hit in (r.data or {}).get("results") or [] if r.ok else []:
                dom = (hit.get("domain") or hit["url"].split("/")[2]).lower()
                if dom in seen:
                    continue
                seen.add(dom)
                groups[key].append(hit)
        put_row(self.session, self.ws, "domain", host, "urlscan", "similar", groups)
        self.done("similar", f"similar sites: {len(groups['by_hash'])} same page · {len(groups['by_ip'])} same server · {len(groups['by_brand'])} same brand")  # fmt: skip


def _shape_urlscan(result: ProviderResult, client: Any) -> dict[str, Any]:
    raw = result.raw or {}
    page = raw.get("page") or {}
    stats = raw.get("stats") or {}
    reqs = (raw.get("data") or {}).get("requests") or []
    main_hash = next((((r.get("response") or {}).get("hash")) for r in reqs if (r.get("response") or {}).get("hash")), None)  # fmt: skip
    task_id = result.data.get("task_id")
    return {
        "task_id": task_id, "url": result.data.get("url"), "ip": page.get("ip"), "asn": page.get("asn"),
        "asnname": page.get("asnname"), "country": page.get("country"), "server": page.get("server"),
        "title": page.get("title"), "verdict": result.data.get("verdict") or {},
        "ips": result.data.get("ips") or [], "domains": result.data.get("domains") or [],
        "countries": (raw.get("lists") or {}).get("countries") or [],
        "requests": stats.get("requests"), "malicious_requests": stats.get("malicious"),
        "main_hash": main_hash,
        # recorded (demo) scans show the rendered picture of the site; real scans urlscan's own screenshot
        "screenshot": (f"/ui/demo-shot/{task_id[5:]}" if str(task_id).startswith("mock-") else f"https://urlscan.io/screenshots/{task_id}.png") if task_id else None,
        "result_url": f"https://urlscan.io/result/{task_id}/" if task_id else None,
        "time": (raw.get("task") or {}).get("time"),
    }  # fmt: skip


async def _live_dns(host: str) -> ProviderResult:
    def q() -> list[dict]:
        out: list[dict] = []
        for rtype in DNS_TYPES:
            outcome, ans = dnslookup._service_query(host, rtype)
            if outcome != "answer" or ans is None:
                continue
            ttl = getattr(getattr(ans, "rrset", None), "ttl", None)
            for r in ans:
                rec: dict[str, Any] = {"type": rtype, "ttl": ttl, "value": r.to_text().strip('"')}
                if rtype == "MX":
                    rec["priority"], rec["value"] = r.preference, r.exchange.to_text()
                if rtype == "SOA":
                    rec["value"], rec["rname"], rec["serial"] = (
                        r.mname.to_text(),
                        r.rname.to_text(),
                        r.serial,
                    )
                out.append(rec)
        return out

    records = await asyncio.to_thread(q)
    return ProviderResult("dns", ProviderStatus.POSITIVE if records else ProviderStatus.UNKNOWN,
                          {"host": host, "records": records, "method": "python"})  # fmt: skip


async def _live_cert(host: str) -> ProviderResult:
    from brandwatch.security.tls_probe import fetch_certificate

    info = await fetch_certificate(host)
    return ProviderResult("cert", ProviderStatus.POSITIVE, info)


# --------------------------------------------------------------------------------------------
# job entry point
# --------------------------------------------------------------------------------------------
def _seed(session: Session, finding: Finding) -> tuple[str, str, list[str], str | None]:
    """host, url, IPs from the finding's evidence (newest DNS A records / HTTP ip), brand key."""
    from brandwatch.detection.investigation import _seed_facts

    cand = session.get(Candidate, finding.candidate_id)
    facts = _seed_facts(session, finding)
    brand = session.get(Brand, finding.brand_id)
    key = re.sub(r"[^a-z0-9]", "", (brand.name or "").lower()) if brand else None
    return cand.hostname, cand.canonical_url, [i for i in facts["ips"] if _is_ip(i)], key or None


def _is_ip(v: str) -> bool:
    try:
        ipaddress.ip_address(v)
        return True
    except ValueError:
        return False


async def run_intel(session: Session, job_id: uuid.UUID, *, settings: Settings | None = None, store: Any = None) -> dict[str, Any]:  # fmt: skip
    settings = settings or get_settings()
    job = session.get(ScanJob, job_id)
    if job is None:
        raise LookupError("job not found")
    payload = job.payload or {}
    force = bool(payload.get("force"))
    light = bool(payload.get("light"))
    job.state = JobState.RUNNING
    job.started_at = utcnow()
    session.flush()
    # commit=True: every event is committed at once. An investigation spends minutes waiting (the shared VirusTotal quota, urlscan.io)
    # and an open write transaction would hold SQLite's lock all that time: the other jobs and the page then died with "database is locked".
    em = ScanEventEmitter(session, job_id, secrets=settings.known_secret_values(), commit=True)
    trace.start(job_id, settings.evidence_dir, secrets=settings.known_secret_values())
    from brandwatch import keys as keystore
    from brandwatch.config.brand_config import BrandConfig

    limits = BrandConfig().economic_limits
    if job.brand_id:
        from brandwatch.detection.runner import load_brand_config

        limits = load_brand_config(session, job.brand_id).economic_limits
    # An analyst-triggered intel run is small (≤ MAX_CALLS, enforced here) and must not be refused
    # because a scan already used the day's call budget; the daily *spend* cap still applies.
    limits = limits.model_copy(update={"max_api_calls": 0})
    providers = ProviderRegistry(
        settings, ledger=DbUsageLedger(session, job.workspace_id, limits), job_id=job_id,
        key_overrides=keystore.load_keys(session, job.workspace_id, settings),
    )  # fmt: skip
    stage = ScanStage(job_id=job_id, name="intel", state=JobState.RUNNING, started_at=utcnow())
    session.add(stage)
    session.flush()
    col = Collector(session, job.workspace_id, providers, em, settings, force=force, light=light)
    t0 = time.monotonic()

    if payload.get("finding_id"):
        finding = session.get(Finding, uuid.UUID(payload["finding_id"]))
        if finding is None:
            raise LookupError("finding not found")
        host, url, ips, brand_key = _seed(session, finding)
        trace.section(f"INTEL · {host}")
        em.running(STAGE, host, f"Investigating {host} and its network — {'fresh lookups (forced)' if force else 'cached results reused for 24h'} …")  # fmt: skip
        attrs = await col.domain(host)
        vt_ips = [r.get("value") for r in (attrs.get("last_dns_records") or []) if r.get("type") == "A" and _is_ip(r.get("value", ""))]  # fmt: skip
        dns_row = _get_row(session, job.workspace_id, "domain", host, "dns", "report")
        live_ips = [r["value"] for r in ((dns_row.payload or {}).get("records") or []) if r.get("type") == "A"] if dns_row and dns_row.status == "ok" else []  # fmt: skip
        all_ips = list(dict.fromkeys([*vt_ips, *live_ips, *ips]))[:MAX_IPS]
        # urlscan only waits for its scan to finish: that happens while the IPs wait for the VirusTotal quota
        scan_task = asyncio.create_task(col.urlscan(url, host, all_ips, brand_key))
        try:
            for ip in all_ips:
                await col.ip(ip)
        except BaseException:
            scan_task.cancel()
            raise
        await scan_task
        session.refresh(job, attribute_names=["payload"])  # a confirmation may have joined this investigation while it ran: it asked for the package
        if (job.payload or {}).get("package"):  # a confirmation asked for the evidence package too: it is built from what was just collected
            _make_package(session, em, finding, store, job, host, url)
        subject = host
    else:
        ip = str(payload.get("ip") or "")
        if not _is_ip(ip):
            raise LookupError("no finding_id or ip in the job payload")
        trace.section(f"INTEL · {ip}")
        em.running(STAGE, ip, f"Investigating the server {ip} …")
        await col.ip(ip)
        subject = ip

    stage.state = JobState.DONE
    stage.api_calls = col.api_calls
    stage.elapsed_ms = int((time.monotonic() - t0) * 1000)
    stage.finished_at = utcnow()
    job.state = JobState.DONE
    job.finished_at = utcnow()
    job.cost_usd = round(col.cost, 4)
    session.flush()
    summary = {"subject": subject, "api_calls": col.api_calls, "cache_hits": col.cache_hits, "cost_usd": col.cost,
               "not_available": sorted(set(col.not_available)), "skipped": col.skipped, "duration_ms": stage.elapsed_ms,
               "findings": 0, "criticals": 0, "hits": 0, "next_run": None}  # fmt: skip
    cached = f", {col.cache_hits} reused from the 24 h cache" if col.cache_hits else ""
    skipped = f", {col.skipped} skipped (shared Cloudflare address)" if col.skipped else ""
    em.done("summary", "intel", f"Intel for {subject} ready: {col.api_calls} new lookup(s){cached}{skipped}, {len(set(col.not_available))} not available on this plan",
            counts={"api_calls": col.api_calls, "cost_usd": col.cost}, data=summary)  # fmt: skip
    return summary


def investigation_summary(view: dict[str, Any]) -> dict[str, Any]:
    """The part of an investigation that belongs in an evidence package: where the site is, who registered it, what the vendors
    say, what else is on its servers. Compact on purpose (the full page stays in the application)."""
    det = view.get("detections") or {}
    cert = view.get("certificate") or {}
    scan = (view.get("urlscan") or {}).get("scan") or {}
    sim = (view.get("urlscan") or {}).get("similar") or {}
    return {
        "fetched_at": view.get("fetched_at").isoformat() if hasattr(view.get("fetched_at"), "isoformat") else view.get("fetched_at"),
        "detections": {"positives": det.get("positives"), "total": det.get("total"), "available": det.get("available")},
        "registrar": view.get("registrar"), "created": view.get("creation_date"),
        "nameservers": [r.get("value") for r in ((view.get("dns") or {}).get("records") or []) if r.get("type") == "NS"][:6],
        "certificate": {"subject": cert.get("subject_cn"), "issuer": cert.get("issuer"), "not_before": cert.get("not_before"), "sha256": cert.get("sha256")} if cert else None,
        "certificates_in_ct": len(((view.get("relations") or {}).get("ct")) or []),
        "subdomains": [s.get("host") for s in ((view.get("relations") or {}).get("subdomains") or [])][:10],
        "servers": [{"ip": i.get("ip"), "country": i.get("country_name"), "asn": i.get("asn"), "owner": i.get("as_owner"),
                     "detections": f"{i.get('positives')}/{i.get('total')}" if i.get("total") else None,
                     "abuse_score": (i.get("abuse") or {}).get("abuse_score"), "shared_cloudflare_address": bool(i.get("shared")),
                     "other_sites_on_it": [h.get("host") for h in (i.get("hosted") or [])[:8]], "other_sites_count": i.get("hosted_count")}
                    for i in (view.get("ips") or [])],
        "urlscan": {"verdict_malicious": (scan.get("verdict") or {}).get("malicious") if isinstance(scan.get("verdict"), dict) else None,
                    "same_server": len(sim.get("by_ip") or []), "same_page": len(sim.get("by_hash") or []), "same_brand": len(sim.get("by_brand") or [])},
    }  # fmt: skip


def _make_package(session: Session, em: ScanEventEmitter, finding: Finding, store: Any, job: ScanJob, host: str, url: str) -> None:
    """The evidence package (HTML + JSON) of the finding, with this investigation in it. Never fails the investigation."""
    if store is None:
        em.done("package", host, "Evidence package skipped: no evidence store in this process", level="warn")
        return
    try:
        from brandwatch.api.findings import finding_detail
        from brandwatch.detection import reports as reports_svc

        em.running("package", host, f"Building the evidence package for {host} …")
        detail = finding_detail(session, finding)
        detail["investigation"] = investigation_summary(intel_view(session, job.workspace_id, host, url=url))
        reports = reports_svc.build_evidence_package(session, finding, detail, store, actor=None)
        for r in reports.values():
            r.finding_id = finding.id
        session.flush()
        em.done("package", host, f"Evidence package ready for {host}: HTML + JSON, with this investigation in it",
                data={"reports": {fmt: str(r.id) for fmt, r in reports.items()}})  # fmt: skip
    except Exception as exc:  # noqa: BLE001 - the package can be built again from the finding page
        em.done("package", host, f"Evidence package could not be built: {type(exc).__name__}: {str(exc)[:160]}", level="warn")


_INTEL_SLOTS = threading.BoundedSemaphore(3)  # investigations running at once; the rest wait their turn (and the quota is shared anyway)


def intel_handler_for(settings: Settings, store: Any = None):
    def handler(session: Session, job_id: uuid.UUID) -> None:
        with _INTEL_SLOTS:
            asyncio.run(run_intel(session, job_id, settings=settings, store=store))

    return handler


# --------------------------------------------------------------------------------------------
# the page model
# --------------------------------------------------------------------------------------------
def _stats(st: dict | None) -> dict[str, int]:
    st = st or {}
    pos = int(st.get("malicious", 0) or 0) + int(st.get("suspicious", 0) or 0)
    total = sum(int(v or 0) for v in st.values())
    return {"positives": pos, "total": total, "malicious": int(st.get("malicious", 0) or 0),
            "suspicious": int(st.get("suspicious", 0) or 0)}  # fmt: skip


def _aware(dt: datetime | None) -> datetime | None:
    """SQLite returns naive timestamps; mark them UTC so ``isoformat()`` carries the offset and the
    browser's relative-time code does not treat them as local time."""
    return dt.replace(tzinfo=UTC) if dt is not None and dt.tzinfo is None else dt


def _ts(v: Any) -> str | None:
    if v in (None, "", 0):
        return None
    if isinstance(v, (int, float)):
        return datetime.fromtimestamp(int(v), UTC).strftime("%Y-%m-%d")
    return str(v)[:19].replace("T", " ")


def _vcard(entity: dict, key: str) -> str | None:
    for item in (entity.get("vcardArray") or [None, []])[1] or []:
        if isinstance(item, list) and item and item[0] == key:
            return str(item[-1])
    return None


def _rdap_view(payload: dict | None) -> dict[str, Any]:
    payload = payload or {}
    d, raw = payload.get("data") or {}, payload.get("raw") or {}
    events = [{"action": e.get("eventAction"), "date": _ts(e.get("eventDate"))} for e in raw.get("events") or []]  # fmt: skip
    registrar = d.get("registrar")
    iana = abuse_email = abuse_phone = registrar_url = None
    for ent in raw.get("entities") or []:
        roles = ent.get("roles") or []
        if "registrar" in roles:
            registrar = registrar or _vcard(ent, "fn")
            for pid in ent.get("publicIds") or []:
                if "IANA" in str(pid.get("type", "")).upper():
                    iana = pid.get("identifier")
            for link in ent.get("links") or []:
                if link.get("rel") in ("about", "self") and str(link.get("href", "")).startswith("http") and "rdap" not in str(link.get("href")):  # fmt: skip
                    registrar_url = registrar_url or link.get("href")
            for sub in ent.get("entities") or []:
                if "abuse" in (sub.get("roles") or []):
                    abuse_email = abuse_email or _vcard(sub, "email")
                    abuse_phone = abuse_phone or _vcard(sub, "tel")
    return {
        "name": raw.get("ldhName") or d.get("domain"), "handle": raw.get("handle"), "events": events,
        "status": raw.get("status") or d.get("status") or [], "registrar": registrar, "registrar_iana_id": iana,
        "registrar_url": registrar_url, "abuse_email": abuse_email, "abuse_phone": abuse_phone,
        "nameservers": [ns.get("ldhName") for ns in raw.get("nameservers") or [] if ns.get("ldhName")],
        "dnssec": (raw.get("secureDNS") or {}).get("delegationSigned"),
        "registered_at": d.get("registered_at"), "age_days": d.get("age_days"),
        "registrant": d.get("registrant") or {}, "links": [l.get("href") for l in raw.get("links") or [] if l.get("href")],  # noqa: E741
        "available": bool(payload),
    }  # fmt: skip


def _cert_view(
    vt_cert: dict | None, live: dict | None, cert_date: Any = None
) -> dict[str, Any] | None:
    if vt_cert:
        c = vt_cert
        subj = c.get("subject") or {}
        iss = c.get("issuer") or {}
        val = c.get("validity") or {}
        return {
            "source": "virustotal", "subject_cn": subj.get("CN"), "subject": " ".join(f"{k}={v}" for k, v in subj.items()),
            "issuer": " ".join(f"{k}={v}" for k, v in iss.items()), "issuer_cn": iss.get("CN") or iss.get("O"),
            "not_before": val.get("not_before"), "not_after": val.get("not_after"),
            "sans": (c.get("extensions") or {}).get("subject_alternative_name") or [],
            "thumbprint_sha256": c.get("thumbprint_sha256"), "thumbprint_sha1": c.get("thumbprint"),
            "serial": c.get("serial_number"), "signature_algorithm": (c.get("cert_signature") or {}).get("signature_algorithm"),
            "public_key": " ".join(str(v) for v in [(c.get("public_key") or {}).get("algorithm"),
                                                      ((c.get("public_key") or {}).get("ec") or {}).get("oid"),
                                                      ((c.get("public_key") or {}).get("rsa") or {}).get("key_size")] if v),
            "version": c.get("version"), "seen": _ts(cert_date), "raw": c,
        }  # fmt: skip
    if live:
        return {"source": "live", "subject_cn": live.get("subject_cn"), "subject": live.get("subject"), "issuer": live.get("issuer"),
                "issuer_cn": live.get("issuer"), "not_before": live.get("not_before"), "not_after": live.get("not_after"),
                "sans": live.get("sans") or [], "thumbprint_sha256": live.get("sha256"), "thumbprint_sha1": live.get("sha1"),
                "serial": live.get("serial"), "signature_algorithm": live.get("signature_algorithm"),
                "public_key": live.get("public_key_algorithm"), "version": live.get("version"), "seen": None,
                "tls_version": live.get("tls_version"), "cipher": live.get("cipher"), "raw": live}  # fmt: skip
    return None


def _validity_pct(nb: str | None, na: str | None) -> int | None:
    try:
        b = datetime.fromisoformat(str(nb).replace(" ", "T")[:19]).replace(tzinfo=UTC)
        a = datetime.fromisoformat(str(na).replace(" ", "T")[:19]).replace(tzinfo=UTC)
    except (ValueError, TypeError):
        return None
    span = (a - b).total_seconds()
    if span <= 0:
        return None
    return max(0, min(100, int((datetime.now(UTC) - b).total_seconds() / span * 100)))


def _ip_view(session: Session, ws: uuid.UUID, ip: str) -> dict[str, Any]:
    rows = rows_for(session, ws, "ip", ip)
    rep = rows.get("virustotal/report")
    a = ((rep.payload or {}).get("attributes") or {}) if rep and rep.status == "ok" else {}
    geo = (rows.get("geo/report").payload or {}) if rows.get("geo/report") and rows["geo/report"].status == "ok" else {}  # fmt: skip
    cc = a.get("country") or geo.get("country")
    hosted = []
    res = rows.get("virustotal/resolutions")
    for it in ((res.payload or {}).get("items") or []) if res and res.status == "ok" else []:
        hosted.append({"host": it.get("host_name"), "date": _ts(it.get("date")), **_stats(it.get("host_name_last_analysis_stats"))})  # fmt: skip
    hosted.sort(key=lambda h: (-h["positives"], h["host"] or ""))
    files = []
    cf = rows.get("virustotal/communicating_files")
    for it in ((cf.payload or {}).get("items") or []) if cf and cf.status == "ok" else []:
        files.append({"sha256": it.get("sha256") or it.get("id"), "name": it.get("meaningful_name") or (it.get("names") or [None])[0] or it.get("id", "")[:16],
                      "type": it.get("type_description") or it.get("type_tag"), "date": _ts(it.get("last_analysis_date")), **_stats(it.get("last_analysis_stats"))})  # fmt: skip
    files.sort(key=lambda f: -f["positives"])
    hw = rows.get("virustotal/historical_whois")
    ab = rows.get("abuseipdb/check")
    abuse = (ab.payload or {}) if ab is not None and ab.status == "ok" else None
    engines = sorted(((a.get("last_analysis_results") or {}).values()), key=lambda e: (e.get("category") not in ("malicious", "suspicious"), e.get("engine_name", "")))  # fmt: skip
    org = a.get("as_owner") or geo.get("org")
    cdn = hosting.is_cdn(org, ip)  # a CDN edge: where it "is" depends on who asks, so no country is claimed
    return {
        "ip": ip, "country": None if cdn else (cc or "").upper() or None, "country_name": None if cdn else country_name(cc), "city": None if cdn else geo.get("city"),
        "cdn": (org or "a CDN") if cdn else None, "edge": {"country": (cc or "").upper() or None, "city": geo.get("city")} if cdn else None,
        "asn": a.get("asn"), "as_owner": a.get("as_owner") or geo.get("org"), "network": a.get("network"),
        "rir": a.get("regional_internet_registry"), "whois": a.get("whois"), "reputation": a.get("reputation"),
        **_stats(a.get("last_analysis_stats")), "engines": engines[:40],
        "shared": bool(res and res.status == "skipped"),  # a Cloudflare edge address: the lists were skipped on purpose
        "shared_note": SHARED_NOTE if res and res.status == "skipped" else None,
        "hosted": hosted, "hosted_count": ((res.payload or {}).get("count") if res and res.status == "ok" else None) or len(hosted),
        "hosted_flagged": sum(1 for h in hosted if h["positives"]),
        "abuse": abuse,
        "files": files, "files_count": ((cf.payload or {}).get("count") if cf and cf.status == "ok" else None) or len(files),
        "historical_whois": [{"date": _ts(it.get("last_updated") or it.get("first_seen_date")), "registrar": it.get("registrar_name"),
                              "map": it.get("whois_map") or {}} for it in (((hw.payload or {}).get("items") or []) if hw and hw.status == "ok" else [])],
        "status": {k: {"status": r.status, "error": r.error} for k, r in rows.items()},
        "fetched_at": _aware(max((r.fetched_at for r in rows.values()), default=None)),
        "links": _links(host=None, ip=ip),
    }  # fmt: skip


def _links(host: str | None, ip: str | None, url: str | None = None) -> dict[str, str]:
    links: dict[str, str] = {}
    if host:
        links.update({
            "VirusTotal domain": f"https://www.virustotal.com/gui/domain/{host}",
            "VirusTotal relations": f"https://www.virustotal.com/gui/domain/{host}/relations",
            "urlscan search": f"https://urlscan.io/search/#page.domain:{host}",
            "URLhaus": f"https://urlhaus.abuse.ch/browse.php?search={host}",
            "crt.sh": f"https://crt.sh/?q={host}",
            "Google Safe Browsing": f"https://transparencyreport.google.com/safe-browsing/search?url={host}",
            "Wayback Machine": f"https://web.archive.org/web/*/{host}",
            "Censys": f"https://search.censys.io/search?resource=hosts&q={host}",
        })  # fmt: skip
    if url:
        links["VirusTotal URL"] = f"https://www.virustotal.com/gui/search/{url}"
    if ip:
        links.update({
            "VirusTotal IP": f"https://www.virustotal.com/gui/ip-address/{ip}",
            "Shodan": f"https://www.shodan.io/host/{ip}",
            "AbuseIPDB": f"https://www.abuseipdb.com/check/{ip}",
            "Censys host": f"https://search.censys.io/hosts/{ip}",
        })  # fmt: skip
    return links


def intel_view(session: Session, ws: uuid.UUID, host: str | None, ips: list[str] | None = None, url: str | None = None) -> dict[str, Any]:  # fmt: skip
    """Everything the page needs, assembled from the cache (never calls a provider)."""
    out: dict[str, Any] = {
        "host": host,
        "url": url,
        "ips": [],
        "links": {},
        "missing": [],
        "fetched_at": None,
    }
    ip_set = list(ips or [])
    if host:
        rows = rows_for(session, ws, "domain", host)
        reg = split_host(host).registrable or host
        rrows = rows_for(session, ws, "domain", reg) if reg != host else rows
        rep = rows.get("virustotal/report")
        a = ((rep.payload or {}).get("attributes") or {}) if rep and rep.status == "ok" else {}
        st = _stats(a.get("last_analysis_stats"))
        engines = sorted(((a.get("last_analysis_results") or {}).values()), key=lambda e: (e.get("category") not in ("malicious", "suspicious"), e.get("engine_name", "")))  # fmt: skip
        dns_live = rows.get("dns/report")
        dns_records = a.get("last_dns_records") or (((dns_live.payload or {}).get("records") or []) if dns_live and dns_live.status == "ok" else [])  # fmt: skip
        dns_source = (
            "virustotal" if a.get("last_dns_records") else ("python" if dns_records else None)
        )
        live_cert = rows.get("cert/report")
        cert = _cert_view(a.get("last_https_certificate"), (live_cert.payload if live_cert and live_cert.status == "ok" else None), a.get("last_https_certificate_date"))  # fmt: skip
        if cert:
            cert["validity_pct"] = _validity_pct(cert.get("not_before"), cert.get("not_after"))
        rdap_row = rrows.get("rdap/report") or rows.get("rdap/report")
        rdap = _rdap_view(rdap_row.payload if rdap_row and rdap_row.status == "ok" else None)

        def items(rel: str) -> list[dict]:
            r = rows.get(f"virustotal/{rel}")
            return ((r.payload or {}).get("items") or []) if r and r.status == "ok" else []

        resolutions = sorted([{"ip": it.get("ip_address"), "date": _ts(it.get("date")), **_stats(it.get("ip_address_last_analysis_stats"))} for it in items("resolutions")],
                             key=lambda x: (x["date"] or ""), reverse=True)  # fmt: skip
        for r in resolutions:
            if r["ip"] and r["ip"] not in ip_set:
                ip_set.append(r["ip"])
        for rec in dns_records:
            if rec.get("type") == "A" and rec.get("value") and rec["value"] not in ip_set:
                ip_set.insert(0, rec["value"])
        ct_row = rrows.get("cert/ct") or rows.get("cert/ct")
        ct = [{"sha256": c.get("fingerprint_sha256"), "sans": c.get("sans") or [], "issuer": c.get("issuer"), "not_before": _ts(c.get("not_before")), "cn": c.get("common_name")}
              for c in (((ct_row.payload or {}).get("certificates") or []) if ct_row and ct_row.status == "ok" else [])]  # fmt: skip
        scan_row, sim_row = rows.get("urlscan/scan"), rows.get("urlscan/similar")
        status = {k: {"status": r.status, "error": r.error, "fetched_at": _aware(r.fetched_at).isoformat() if r.fetched_at else None} for k, r in {**rrows, **rows}.items()}  # fmt: skip
        hist_row = rrows.get("whoisxml/history") or rows.get("whoisxml/history")
        hist = None
        if hist_row is not None and hist_row.status == "ok":
            hist = whois_history.analyze((hist_row.payload or {}).get("records") or [])
            hist["related"] = related_by_owner(session, ws, hist["owners"], exclude=reg)
            hist["fetched_at"] = (
                _aware(hist_row.fetched_at).isoformat() if hist_row.fetched_at else None
            )
        out.update({
            "registrable": reg,
            "detections": {**st, "engines": engines, "categories": a.get("categories") or {}, "reputation": a.get("reputation"),
                           "votes": a.get("total_votes") or {}, "popularity": a.get("popularity_ranks") or {},
                           "last_analysis": _ts(a.get("last_analysis_date")), "available": bool(a),
                           "status": status.get("virustotal/report", {"status": "missing"})},
            "dns": {"records": dns_records, "source": dns_source},
            "certificate": cert, "jarm": a.get("jarm"),
            "rdap": rdap, "whois_text": a.get("whois"), "whois_date": _ts(a.get("whois_date")),
            "whois_history": hist, "whois_history_status": status.get("whoisxml/history", {"status": "missing"}),
            "registrar": rdap.get("registrar") or a.get("registrar"), "creation_date": rdap.get("registered_at") or _ts(a.get("creation_date")),  # RDAP is the registry's own answer
            "relations": {
                "resolutions": resolutions,
                "historical_whois": [{"date": _ts(it.get("last_updated") or it.get("first_seen_date")), "registrar": it.get("registrar_name"), "map": it.get("whois_map") or {}} for it in items("historical_whois")],
                "historical_ssl": [{"first_seen": _ts(it.get("first_seen_date")), "subject_cn": (it.get("subject") or {}).get("CN"), "issuer": (it.get("issuer") or {}).get("O") or (it.get("issuer") or {}).get("CN"),
                                    "thumbprint": it.get("thumbprint_sha256") or it.get("id"), "not_before": (it.get("validity") or {}).get("not_before"), "not_after": (it.get("validity") or {}).get("not_after")} for it in items("historical_ssl_certificates")],
                "ct": ct,
                "subdomains": sorted([{"host": it.get("id"), **_stats(it.get("last_analysis_stats"))} for it in items("subdomains")], key=lambda s: (-s["positives"], s["host"] or "")),
                "communicating_files": sorted([{"sha256": it.get("sha256") or it.get("id"), "name": it.get("meaningful_name") or (it.get("names") or [None])[0] or str(it.get("id", ""))[:16], "type": it.get("type_description") or it.get("type_tag"), "date": _ts(it.get("last_analysis_date")), **_stats(it.get("last_analysis_stats"))} for it in items("communicating_files")], key=lambda f: -f["positives"]),
                "referrer_files": [{"sha256": it.get("sha256") or it.get("id"), "name": it.get("meaningful_name") or str(it.get("id", ""))[:16], "type": it.get("type_description"), "date": _ts(it.get("last_analysis_date")), **_stats(it.get("last_analysis_stats"))} for it in items("referrer_files")],
                "status": {k: v for k, v in status.items() if k.startswith("virustotal/") and k != "virustotal/report"},
            },
            "urlscan": {"scan": (scan_row.payload if scan_row and scan_row.status == "ok" else None),
                        "similar": (sim_row.payload if sim_row and sim_row.status == "ok" else None),
                        "status": status.get("urlscan/scan", {"status": "missing"})},
            "status": status,
        })  # fmt: skip
        out["missing"] = sorted({k for k, v in status.items() if v["status"] != "ok"})
        out["fetched_at"] = _aware(max((r.fetched_at for r in rows.values()), default=None))
    out["ips"] = [_ip_view(session, ws, ip) for ip in list(dict.fromkeys(ip_set))[:MAX_IPS]]
    out["ips"].sort(key=lambda i: bool(i.get("cdn")))  # a real host first: the country of the page is the country of a server, not of an edge
    primary_ip = out["ips"][0]["ip"] if out["ips"] else None
    out["links"] = _links(host, primary_ip, url)
    out["country"] = out["ips"][0]["country"] if out["ips"] else None
    out["country_name"] = country_name(out["country"]) if out["country"] else None
    return out
