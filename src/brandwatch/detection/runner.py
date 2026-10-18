"""Brand scan runner: orchestrates the Phase 1 vertical slice as one job.

    discovery (dnstwist) → normalize → dedup → pre-filter → [per candidate]
    enrichment → analysis → scoring → finding   (dead → dismissed, parked/empty → watchlist)

Every stage emits ScanEvents (the Live Console feed) and a ``scan_stages`` row with hits, API
calls and cost. Registered as the ``brand_scan`` job handler; ``scan_urls`` runs the same slice
on analyst-supplied URLs (and powers the golden-dataset evaluation).
"""

from __future__ import annotations

import asyncio
import dataclasses
import re
import time
import uuid
from collections.abc import Iterable
from dataclasses import dataclass, field
from decimal import Decimal
from typing import Any
from urllib.parse import urlsplit

import sqlalchemy as sa
from sqlalchemy.orm import Session

from brandwatch import keys as keystore
from brandwatch import proxy as proxy_mod
from brandwatch import tenancy, trace
from brandwatch.config.brand_config import BrandConfig
from brandwatch.config.settings import Settings, get_settings
from brandwatch.db.base import set_checkpoint
from brandwatch.db.enums import (
    CandidateState,
    DiscoverySource,
    FindingState,
    JobState,
    Severity,
    Surface,
)
from brandwatch.db.models import ApiUsage, Brand, Candidate, Finding, ScanJob, ScanStage
from brandwatch.db.types import utcnow
from brandwatch.detection import (
    ad_settings,
    baseline_health,
    cloaking,
    discovery,
    dnslookup,
    merchant,
    ml,
    relevance,
)
from brandwatch.detection import ai as ai_stage
from brandwatch.detection import analysis as analysis_stage
from brandwatch.detection import finding as finding_stage
from brandwatch.detection import markets as markets_mod
from brandwatch.detection import regions as regions_mod
from brandwatch.detection import scoring as scoring_stage
from brandwatch.detection import search_queries as search_queries_mod
from brandwatch.detection import sources as streams
from brandwatch.detection import triggers as trigger_engine
from brandwatch.detection.baseline import BrandBaseline, build_baseline, load_baseline
from brandwatch.detection.discovery import manual_hits, split_host
from brandwatch.detection.enrichment import dismiss_dead, enrich, schedule_next_scan
from brandwatch.detection.investigation import known_infrastructure_links, run_investigation
from brandwatch.detection.normalize import (
    deduplicate,
    is_app_store,
    is_known_platform,
    is_shared_hosting,
    normalize,
    pre_filter,
    whitelist_for,
)
from brandwatch.events.emitter import EventLevel, ScanEventEmitter
from brandwatch.evidence.store import EvidenceStore, LocalEvidenceStore
from brandwatch.notifications import NotificationService
from brandwatch.pipeline.stages import AnalysisResult, DiscoveryHit, PipelineContext, RiskResult
from brandwatch.providers.ledger import DbUsageLedger
from brandwatch.providers.registry import ProviderRegistry


@dataclass(slots=True)
class CandidateOutcome:
    candidate_id: uuid.UUID
    host: str
    disposition: str  # finding | watch | dismissed | error
    severity: Severity | None = None
    score: int | None = None
    confidence: float | None = None
    finding_id: uuid.UUID | None = None
    signals: dict[str, float] = field(default_factory=dict)
    error: str | None = None


@dataclass(slots=True)
class ScanSummary:
    job_id: uuid.UUID
    brand_id: uuid.UUID
    hits: int = 0
    new_candidates: int = 0
    existing_candidates: int = 0
    whitelisted: int = 0
    processed: int = 0
    findings: int = 0
    criticals: int = 0
    watching: int = 0
    dismissed: int = 0
    errors: int = 0
    outcomes: list[CandidateOutcome] = field(default_factory=list)
    redirected: list[dict[str, str]] = field(default_factory=list)  # destinations of a flagged site's redirect, added to the scan
    duration_ms: int = 0
    steps: list[dict[str, Any]] = field(default_factory=list)  # the plain-language scan report

    def step(
        self,
        title: str,
        detail: str | None = None,
        items: list[dict] | None = None,
        limit: int = 16,
    ) -> None:
        self.steps.append({"title": title, "detail": detail, "items": (items or [])[:limit],
                           "total": len(items or [])})  # fmt: skip

    def as_dict(self) -> dict[str, Any]:
        return {
            "steps": self.steps,
            "hits": self.hits,
            "new_candidates": self.new_candidates,
            "existing_candidates": self.existing_candidates,
            "whitelisted": self.whitelisted,
            "processed": self.processed,
            "findings": self.findings,
            "criticals": self.criticals,
            "watching": self.watching,
            "dismissed": self.dismissed,
            "errors": self.errors,
            "duration_ms": self.duration_ms,
        }


def load_brand_config(session: Session, brand_id: uuid.UUID) -> BrandConfig:
    """Brand config with economic limits inherited from the workspace (Phase 6)."""
    return tenancy.effective_brand_config(session, brand_id)


class _StageTimer:
    def __init__(self, session: Session, job_id: uuid.UUID, name: str) -> None:
        self.row = ScanStage(job_id=job_id, name=name, state=JobState.RUNNING, started_at=utcnow())
        session.add(self.row)
        session.flush()
        self._t0 = time.monotonic()

    def finish(
        self, *, hits: int = 0, api_calls: int = 0, cost_usd: float = 0.0, failed: bool = False
    ) -> None:
        self.row.state = JobState.FAILED if failed else JobState.DONE
        self.row.hits = hits
        self.row.api_calls = api_calls
        self.row.cost_usd = Decimal(str(round(cost_usd, 4)))
        self.row.elapsed_ms = int((time.monotonic() - self._t0) * 1000)
        self.row.finished_at = utcnow()


# --- "what is the scanner doing right now" for the live console -------------------------------------
STREAM_NOW: dict[str, tuple[str, str]] = {
    "dnstwist": (
        "Generating look-alike domains",
        "Typos, hyphenation, combosquats (login, trading, app …) and {tlds} other TLDs of "
        "{officials} — every name is checked in DNS to see whether someone registered it",
    ),
    "ct": (
        "Searching certificate transparency logs",
        "crt.sh: every TLS certificate ever issued with “{key}” in its name — phishing kits need HTTPS",
    ),
    "search": (
        "Searching Google — top results",
        "SerpAPI query “{brand}” ({geo}/{lang}): who ranks for the brand name, including ads",
    ),
    "urlscan": (
        "Searching the urlscan.io archive",
        "Pages other researchers already scanned whose URL or domain contains “{key}”",
    ),
    "meta_ads": (
        "Searching Meta ads (Facebook · Instagram)",
        "Ads in Meta's Ad Library that sell {brand}'s products — ads that only share the words are "
        "skipped, every shop the others link to is checked next",
    ),
    "nrd": (
        "Checking newly registered domains",
        "Yesterday's newly-registered-domains list (each day's list is published the next morning), filtered for “{key}”",
    ),
}


def _now(
    title: str,
    detail: str | None = None,
    items: list[dict] | None = None,
    *,
    icon: str | None = None,
    image: str | None = None,
) -> dict[str, Any]:
    """Structured hint the scan console renders as the big "NOW" card."""
    return {"now": {"title": title, "detail": detail, "items": (items or [])[:12],
                    "total": len(items or []), "icon": icon, "image": image}}  # fmt: skip


def _by_points(signals: dict[str, Any]) -> list[str]:
    return [k for k, _ in sorted(((k, v) for k, v in signals.items() if not k.startswith("_")),
                                 key=lambda kv: (-float(kv[1] or 0), kv[0]))]  # fmt: skip


def _signal_label(sig: str) -> str:
    from brandwatch.api.labels import signal_label

    return signal_label(sig)


def _hit_items(hits: Iterable[Any]) -> list[dict]:
    out = []
    for h in hits:
        value = getattr(h, "raw_value", None) or str(h)
        src = getattr(h, "source", None)
        out.append({"label": value, "url": value if "://" in str(value) else None,
                    "tag": getattr(src, "value", None)})  # fmt: skip
    return out


ISSUE_HELP: dict[str, tuple[str, str]] = {
    "site": (
        "{provider}: a site or account did not answer",
        "Only that one target is affected — its evidence is marked unavailable and the scan went on; it is "
        "re-checked on the next scan. Nothing to fix. ({error})",
    ),
    "quota": (
        "Daily budget reached",
        "The workspace's daily limit (API calls or spend) is used up, so {provider} is skipped "
        "for the rest of today. Raise the limits under Settings → Workspace & budget, or run "
        "the scan again tomorrow.",
    ),
    "rate_limit": ("{provider}: rate limit hit",
                   "The provider asked us to slow down{after}. Free plans allow only a few requests "
                   "per minute, so some candidates have no {provider} evidence. Re-run the scan "
                   "later or upgrade the plan."),
    "auth": (
        "{provider}: API key rejected",
        "The provider refused the key — it is invalid or expired, or the account has no active "
        "(free) subscription for this product yet. Check the provider's dashboard, then paste "
        "the key again under Settings → Provider API keys and re-run the scan.",
    ),
    "outage": (
        "{provider}: temporarily unavailable",
        "The service answered with a server error, so it is down or overloaded right now "
        "(crt.sh does this often). Nothing to fix on your side — the next scan retries it "
        "automatically; its evidence is marked unavailable for now.",
    ),
    "circuit": ("{provider}: paused after repeated failures",
                "Several errors in a row, so the provider is skipped for a short cooldown. Check "
                "the provider's status page; its evidence is marked unavailable meanwhile."),
    "not_configured": ("No provider for {kind}",
                       "Add an API key for one of: {candidates} under Settings → Provider API keys. "
                       "The scan continues without this evidence."),
    "network": ("{provider}: network problem",
                "Timeout or connection error (already retried). Check the internet connection or "
                "the provider's status; the affected evidence is marked unavailable."),
    "error": ("{provider}: error",
              "{error}. Evidence from this provider is marked unavailable; the scan continues."),
}  # fmt: skip


def _flush_issues(
    providers: ProviderRegistry, em: ScanEventEmitter, seen: dict[tuple[str, str], int]
) -> None:
    """Turn provider failures (quota, rate limit, bad key, outage …) into one alert each,
    with a plain-language fix the analyst can act on."""
    for iss in providers.drain_issues():
        prov = str(iss["provider"]).replace("not-configured:", "")
        if iss.get("recovered_by") and iss["kind"] in (
            "network",
            "outage",
            "circuit",
            "error",
            "auth",
        ):
            key = (prov, "fallback")
            seen[key] = seen.get(key, 0) + 1
            if seen[key] == 1:
                em.emit("provider", prov, "done",
                        f"{prov} did not answer ({iss.get('error')}); {iss['recovered_by']} answered instead",
                        data={"alert": {"kind": "fallback", "provider": prov,
                                        "title": f"{prov} unavailable — {iss['recovered_by']} answered instead",
                                        "fix": "Nothing lost: the fallback provider supplied the evidence. "
                                               "Shown for information only.",
                                        "error": str(iss.get("error") or ""), "retry_after": None,
                                        "settings_url": "/ui/settings"}})  # fmt: skip
            continue
        if iss["kind"] == "circuit" and any(p == prov for (p, _k) in seen):
            continue  # the cause was already reported; the cooldown is a consequence
        key = (prov, iss["kind"])
        seen[key] = seen.get(key, 0) + 1
        if seen[key] > 1:
            continue
        title, fix = ISSUE_HELP.get(iss["kind"], ISSUE_HELP["error"])
        fmt = {
            "provider": prov,
            "kind": prov,
            "error": str(iss.get("error") or "unknown error"),
            "after": f" (retry after {iss['retry_after']}s)" if iss.get("retry_after") else "",
            "candidates": ", ".join(iss.get("candidates") or []) or "a supported provider",
        }
        title, fix = title.format(**fmt), fix.format(**fmt)
        level: EventLevel = "error" if iss["kind"] in ("auth", "quota") else ("info" if iss["kind"] == "site" else "warn")
        em.emit("provider", prov, "skipped", f"{title} — {fix}", level=level,
                data={"alert": {"kind": iss["kind"], "provider": prov, "title": title, "fix": fix,
                                "error": fmt["error"], "retry_after": iss.get("retry_after"),
                                "settings_url": "/ui/settings"}})  # fmt: skip


def _report_baseline_health(em: ScanEventEmitter, summary: ScanSummary, brand: Brand, baseline: BrandBaseline) -> bool:
    """The official site did not answer 2xx (403 / a bot check / a server error …): say so, at the top of the
    console and in the report, with the fixes. Returns True when the baseline is unreliable."""
    fetch = baseline.fetch
    attempts = (fetch or {}).get("attempts") or []
    if fetch and fetch.get("ok", True) and len(attempts) > 1:  # refused at first, then let in: worth showing
        first = attempts[0]
        summary.step("The official site refused a data-centre IP — the residential proxy got in",
                     f"{first['via']}: HTTP {first.get('status') or 'no answer'}"
                     + (f" ({first['vendor']})" if first.get("vendor") else "")
                     + f" → {fetch.get('via')}: HTTP {fetch.get('status')} · the fingerprint is built from the live site")  # fmt: skip
        return False
    if fetch and fetch.get("ok", True) and fetch.get("source") == "urlscan":  # chosen by the analyst while the site answers
        snap = fetch.get("snapshot") or {}
        summary.step("Fingerprint taken from a urlscan.io snapshot (chosen by the analyst)",
                     f"snapshot of {snap.get('url')} from {str(snap.get('time') or '')[:10]} · the live site answers (HTTP {fetch.get('status')})")  # fmt: skip
        return False
    if not fetch or fetch.get("ok", True):
        return False
    vendor = f" ({fetch['vendor']})" if fetch.get("vendor") else ""
    tried = " → ".join(
        f"{a['via']}: HTTP {a['status']}" if a.get("status") else f"{a['via']}: no answer" for a in fetch.get("attempts") or []
    )
    snap = fetch.get("snapshot") if fetch.get("source") == "urlscan" else None
    if snap:
        got = "the screenshot, colours and title" + (", page text and favicon" if snap.get("has_dom") else "")
        title = (f"The official site blocked BrandWatch — HTTP {fetch.get('status') or 'no answer'}{vendor} — "
                 f"fingerprint taken from a urlscan.io snapshot of {str(snap.get('time') or '')[:10]}")  # fmt: skip
        missing = ("The login / sign-up pages cannot be followed from a snapshot"
                   if snap.get("has_dom") else "The login form, page text and favicon are missing (a urlscan API key adds them)")
        fix = (f"{fetch.get('reason')}{' · tried ' + tried if tried else ''}. The comparison uses {got} of the real site "
               f"as urlscan.io saw it (no block page was learned from). {missing}. "
               "For a live fingerprint: the residential proxy, or another official page of the brand.")  # fmt: skip
    else:
        title = f"The official site did not let BrandWatch in — HTTP {fetch.get('status') or 'no answer'}{vendor}"
        fix = (f"{fetch.get('reason')}{' · tried ' + tried if tried else ''}. The block page was NOT used as the fingerprint, "
               "so the visual comparison (logo, screenshot, colours, login form) is off for this brand and only the "
               "name, domain, WHOIS and certificate signals are used. Fix it: scan through the residential proxy, "
               "fingerprint another official page of the brand, or take a urlscan.io snapshot.")  # fmt: skip
    em.emit("baseline", "blocked", "skipped", f"{title} — {fix}", level="warn",
            data={"alert": {"kind": "baseline", "provider": "official site", "title": title, "fix": fix,
                            "error": str(fetch.get("url") or ""),
                            "settings_url": f"/ui/brands/{brand.id}#baseline"}})  # fmt: skip
    if snap:
        summary.step("The official site blocked BrandWatch — fingerprint taken from a urlscan.io snapshot",
                     f"{fetch.get('reason')} · tried {tried or fetch.get('url')} · snapshot of {snap.get('url')} "
                     f"from {str(snap.get('time') or '')[:10]}", [{"label": "screenshot, colours, title", "tag": "snapshot"}])  # fmt: skip
    else:
        summary.step("The official site blocked BrandWatch — visual comparison is off",
                     f"{fetch.get('reason')} · tried {tried or fetch.get('url')}",
                     [{"label": label, "tag": "fix"} for _k, label, _d in baseline_health.FIXES])  # fmt: skip
    return True


def discovery_lexicon(baseline: BrandBaseline) -> list[str]:
    """Combosquat words: the generic lexicon plus the brand's own vocabulary (product words
    from its site), so "cryptohoppertrading.com" is generated for a trading-bot brand."""
    words = list(discovery.DEFAULT_DICTIONARY)
    key = baseline.brand_key
    for kw in baseline.keywords:
        for tok in re.split(r"[^a-z0-9]+", kw.lower()):
            if (
                3 <= len(tok) <= 12
                and tok.isalpha()
                and tok != key
                and tok not in words
                and tok not in key
            ):
                words.append(tok)
    return words[:60]


def _report_stream(
    summary: ScanSummary,
    name: str,
    r: Any,
    *,
    officials: list[str],
    key: str,
    queries: list[str],
    geos: list[str],
    lexicon: list[str],
) -> None:
    """One plain-language line per discovery stream for the scan report."""
    if r.degraded:
        summary.step(f"{name}: skipped", r.note)
        return
    if name == "dnstwist":
        summary.step(
            f"Generated {r.generated} look-alike names of {', '.join(officials[:3])} on {r.tlds} TLDs; "
            + (
                f"checked {r.checked} in DNS"
                if r.checked
                else "DNS answers replayed from the recorded dataset (demo)"
            ),
            f"typos, swapped letters, hyphenation, the brand on other TLDs and combosquats with "
            f"{len(lexicon)} words ({', '.join(lexicon[:6])} …); {len(r.hits)} of them are registered",
            r.seen,
        )
    elif name == "search":
        summary.step(
            f"Scanned Google top results in {', '.join(g.upper() for g in geos)} for {len(queries)} queries",
            f"{len(r.hits)} result(s) queued for a visit out of {len(r.seen)} looked at · queries: "
            + " · ".join(queries[:8])
            + (" …" if len(queries) > 8 else ""),
            [dict(x) for x in r.seen],
            limit=60,
        )
    elif name == "ct":
        summary.step(f"Searched certificate transparency logs (crt.sh) for *{key}*",
                     f"{len(r.hits)} certificate name(s) that are not the official site", _hit_items(r.hits))  # fmt: skip
    elif name == "urlscan":
        summary.step(f"Searched the urlscan.io archive for {key}", f"{len(r.hits)} page(s) found", _hit_items(r.hits))  # fmt: skip
    elif name == "meta_ads":
        shops = len(r.hits)
        summary.step(
            f"Searched Meta ads (Facebook · Instagram) for {len(queries)} keyword(s) in {', '.join(geos)}",
            f"{len(r.seen)} ad(s) looked at"
            + (f" (Meta has {sum(t for t in r.ad_totals.values() if isinstance(t, int)):,} in all — raise “ads per search” "
               "in the brand profile to read more)" if sum(t for t in getattr(r, 'ad_totals', {}).values() if isinstance(t, int)) > len(r.seen) else "")
            + f" · {r.api_calls} page request(s) · {shops} shop(s) to check · "
            f"{getattr(r, 'not_about_brand', 0)} not about the brand (they only shared the words)"
            + (f" · {r.ai_checked} unclear ad(s) read by the AI" if getattr(r, "ai_checked", 0) else "")
            + " · authorised retailers and the brand's own site skipped",
            [dict(x) for x in r.seen],
            limit=60,
        )
    elif name == "nrd":
        summary.step(f"Checked the newly-registered-domains feed for {key}",
                     r.note or f"{len(r.hits)} match(es)", _hit_items(r.hits))  # fmt: skip
    else:
        summary.step(f"Stream {name}", f"{len(r.hits)} hit(s)", _hit_items(r.hits))


def _report_outcomes(summary: ScanSummary, ctx: PipelineContext, issues_seen: dict) -> None:
    for note in ctx.extra.get("summary_notes") or []:  # e.g. "no official prices for IL"
        summary.step(note["title"], note["detail"])
    outs = summary.outcomes
    # what each Google result turned out to be, once visited
    by_host = {o.host: o for o in outs}
    for st in summary.steps:
        if not st["title"].startswith("Scanned Google"):
            continue
        for it in st["items"]:
            o = by_host.get(it.get("host") or "")
            if o is None:
                continue
            verdict = o.severity.value.upper() if o.severity else o.disposition
            it["tag"] = f"{it['tag']} → {verdict}" + (f" {o.score}" if o.score is not None else "")
            it["note"] = f"{it.get('note', '')} · after the visit: {verdict}" + (
                f", risk score {o.score}" if o.score is not None else ""
            )
    alive = [o for o in outs if o.disposition in ("finding", "watch")]
    summary.step(
        f"Visited {len(outs)} site(s) in the sandboxed browser",
        f"{len(alive)} alive and compared with the official site · {summary.dismissed} dead or "
        f"unresolved (dismissed) · {summary.errors} error(s)",
    )
    flagged = ctx.extra.get("flagged_sites") or []
    if flagged:
        summary.step(f"{len(flagged)} site(s) were already flagged as phishing by a security service — rated High without a deeper check",
                     "a warning page from Cloudflare, an antivirus or a DNS filter is a verdict somebody else already made: "
                     "the site was not opened in a browser any further (an analyst's Rescan does a full check)",
                     [{"label": f["host"], "tag": f["vendor"]} for f in flagged])  # fmt: skip
    clickfix = ctx.extra.get("clickfix_sites") or []
    if clickfix:
        summary.step(f"{len(clickfix)} site(s) tried to make the visitor run a command (ClickFix)",
                     "a fake human-verification screen — often a copy of Cloudflare's — tells the visitor to press Win+R, paste and press Enter, "
                     "which installs malware; rated High at least. BrandWatch only read the page, it never followed the steps",
                     [{"label": c["host"], "tag": c["kind"].replace("_", " ")} for c in clickfix])  # fmt: skip
    blank = ctx.extra.get("blank_sites") or []
    if blank:
        summary.step(f"{len(blank)} site(s) showed a blank page and have no screenshot",
                     "a blank page is usually a gate that forwards visitors (or hides from scanners); urlscan.io had no picture either, so the "
                     "finding shows where the visit ended up instead",
                     [{"label": b["host"], "tag": "→ " + str(b["final_url"] or "nowhere visible")[:70]} for b in blank])  # fmt: skip
    blocked = ctx.extra.get("blocked_sites") or []
    if blocked:
        via_snap = [b for b in blocked if b["snapshot"]]
        summary.step(f"{len(blocked)} site(s) refused the scanner (HTTP 403 / a bot check)",
                     f"{len(via_snap)} examined through a urlscan.io snapshot; the other {len(blocked) - len(via_snap)} could not be seen — "
                     "each is scored for refusing automated visitors",
                     [{"label": b["host"], "tag": f"HTTP {b['status']}" + (f" · snapshot {str(b['snapshot'])[:10]}" if b["snapshot"] else " · no snapshot")}
                      for b in blocked])  # fmt: skip
    probed = int(ctx.extra.get("cloaking_probed", 0))
    if probed:
        summary.step(f"Probed {probed} suspicious site(s) for cloaking",
                     "re-visited as a crawler, with a victim-style ?email= link and from a search referer")  # fmt: skip
    sev: dict[str, int] = {}
    for o in outs:
        if o.disposition == "finding" and o.severity is not None:
            sev[o.severity.value] = sev.get(o.severity.value, 0) + 1
    summary.step(
        f"Scored {len(alive)} live site(s): {summary.findings} finding(s), {summary.watching} on the watchlist",
        " · ".join(f"{n} {s}" for s, n in sev.items()) or "nothing above the finding threshold",
        [
            {
                "label": o.host,
                "url": f"https://www.virustotal.com/gui/domain/{o.host}",
                "tag": (o.severity.value if o.severity else o.disposition)
                + (
                    f" · VT {ctx.extra['vt'][o.host][0]}/{ctx.extra['vt'][o.host][1] or '?'}"
                    if o.host in ctx.extra.get("vt", {})
                    else ""
                ),
                "note": "opens the VirusTotal page of this host",
            }
            for o in outs
            if o.disposition == "finding"
        ],
    )
    if issues_seen:
        summary.step(
            f"{len(issues_seen)} provider issue(s)",
            "see the alerts panel for what to do",
            [{"label": p, "tag": k.replace("_", " ")} for (p, k) in issues_seen],
        )


def cancel_requested(session: Session, job_id: uuid.UUID) -> bool:
    """The analyst pressed Stop: the API flips the job to CANCELLED, the runner notices at the
    next checkpoint (between streams, between DNS batches, between candidates)."""
    job = session.get(ScanJob, job_id)
    if job is None:
        return True
    session.refresh(job, attribute_names=["state"])
    return job.state is JobState.CANCELLED


def officials_for_report(baseline: BrandBaseline) -> list[str]:
    return list(baseline.official_domains)[:3]


def _dnstwist_callbacks(em: ScanEventEmitter) -> tuple[Any, Any]:
    """Narration for the dnstwist stream: one event when the names are generated, then a
    heartbeat every few seconds while they are checked in DNS (never a flood)."""
    last_tick = [0.0]

    def on_generated(total: int, breakdown: dict[str, dict]) -> None:
        em.running("discovery", "dnstwist",
                   f"Generated {total} look-alike names — checking which exist in DNS",
                   data=_now(f"Generated {total:,} look-alike names",
                             _breakdown_text(breakdown),
                             [{"label": ex, "tag": b["label"]} for _f, b in sorted(
                                 breakdown.items(), key=lambda kv: -kv[1]["count"])
                              for ex in b["examples"][:3]],
                             icon="dnstwist"))  # fmt: skip

    def on_progress(done: int, total: int, registered: list[str], unknown: int = 0) -> None:
        now_t = time.monotonic()
        if done < total and now_t - last_tick[0] < 4:
            return  # a heartbeat every few seconds, never a flood
        last_tick[0] = now_t
        no_answer = f", {unknown} without a DNS answer" if unknown else ""
        em.running("discovery", "dnstwist",
                   f"DNS check {done}/{total}: {len(registered)} registered so far{no_answer}",
                   data=_now(f"Checking DNS: {done:,} of {total:,} names · {len(registered)} registered",
                             "each name is asked for an A record, then NS (registered without a website); "
                             "NXDOMAIN = not registered" + (f" · {unknown} got no answer (counted apart, not as 'free')" if unknown else ""),
                             [{"label": r, "tag": "registered"} for r in registered[-14:]],
                             icon="dnstwist"))  # fmt: skip

    return on_generated, on_progress


def _search_narrator(em: ScanEventEmitter) -> Any:
    """One console event per Google query: the top results with site, title and what the
    scanner thinks of each (official / skipped platform / suspicious / will be visited)."""

    def on_query(query: str, country: str, results: list[dict]) -> None:
        visit = [r for r in results if r["visit"]]
        official = [r for r in results if r["official"]]
        skipped = [r for r in results if not r["visit"] and not r["official"]]
        suspicious = [r for r in visit if r["tag"].endswith("suspicious")]
        em.done(
            "discovery", "search",
            f"Google {country.upper()} “{query}”: {len(results)} results — {len(visit)} to visit, "
            f"{len(suspicious)} suspicious, {len(official)} official, {len(skipped)} skipped",
            counts={"results": len(results), "visit": len(visit), "suspicious": len(suspicious)},
            data=_now(
                f"Google top {len(results)} in {country.upper()}: “{query}”",
                f"{len(visit)} will be visited ({len(suspicious)} look suspicious) · {len(official)} official · "
                f"{len(skipped)} skipped as well-known platforms — hover a result for the verdict",
                results, icon="search",
            ),
        )  # fmt: skip

    return on_query


def _ads_narrator(em: ScanEventEmitter) -> Any:
    """One console event per Meta ads query: which pages advertise, and which shops they link to."""

    def on_query(keyword: str, country: str, results: list[dict], total: Any = None) -> None:
        shops = sorted({r["host"] for r in results if r["visit"]})
        ignored = sum(1 for r in results if r.get("relevance") == "not about the brand")
        of = f" of {total:,}" if isinstance(total, int) and total > len(results) else ""
        em.done(
            "discovery", "meta_ads",
            f"Meta ads {country} “{keyword}”: {len(results)}{of} ad(s) read — {len(shops)} shop(s) to check"
            + (f", {ignored} not about the brand" if ignored else ""),
            counts={"ads": len(results), "shops": len(shops), "not_about_brand": ignored},
            data=_now(f"Meta ads in {country}: “{keyword}”",
                      f"{len(results)} ad(s) · shops to check: {', '.join(shops[:6]) or 'none'}"
                      + (f" · {ignored} skipped: they only share the words (another meaning)" if ignored else "")
                      + " — hover an ad for its text and why",
                      results, icon="search"),
        )  # fmt: skip

    return on_query


def _vt_suffix(col: Any) -> str:
    """ " · VirusTotal 5/90" when the host was looked up, so the console says it out loud."""
    counts = getattr(col, "reputation_counts", {}) or {}
    vt = counts.get("virustotal")
    if not vt:
        return ""
    pos, total = vt
    return f" · VirusTotal {pos}/{total}" if total else f" · VirusTotal {pos} engine(s)"


def _col_summary(col: Any) -> dict[str, Any]:
    """Everything enrichment learned about one host, for the trace."""
    f = getattr(col, "features", None)
    forms = [
        {"action": getattr(x, "action", None), "fields": getattr(x, "fields", None),
         "has_password": getattr(x, "has_password", None), "external_action": getattr(x, "external_action", None)}
        for x in (getattr(f, "forms", None) or [])
    ]  # fmt: skip
    return {
        "dns_records": getattr(col, "dns_records", None),
        "alive": getattr(getattr(col, "liveness", None), "alive", None),
        "http_status": getattr(col, "http_status", None), "final_url": getattr(col, "final_url", None),
        "title": getattr(f, "title", None), "meta_description": getattr(f, "meta_description", None),
        "html_chars": len(getattr(col, "html", None) or ""), "content_sha256": getattr(col, "content_sha256", None),
        "forms": forms, "brand_keywords_in_page": getattr(f, "brand_keywords", None),
        "lure_terms": getattr(f, "lure_terms", None), "parked": getattr(f, "is_parked", None),
        "tracking_ids": getattr(col, "tracking_ids", None),
        "favicon_mmh3": getattr(col, "favicon_mmh3", None), "favicon_phash": getattr(col, "favicon_phash", None),
        "screenshot_phash": getattr(col, "screenshot_phash", None), "screenshot_dhash": getattr(col, "screenshot_dhash", None),
        "palette": getattr(col, "palette", None), "login_signature": getattr(col, "login_signature", None),
        "whois_age_days": getattr(col, "whois_age_days", None), "whois": getattr(col, "whois", None),
        "reputation": {k: v.value for k, v in (getattr(col, "reputation", None) or {}).items()},
        "reputation_counts": getattr(col, "reputation_counts", None),
        "unavailable": getattr(col, "unavailable", None), "provider_notes": getattr(col, "provider_notes", None),
        "how": "DNS A lookup → sandboxed Chromium fetch (HTML, screenshot, favicon) → WHOIS → reputation "
               "feeds (each provider in the chain) → geo of the IP; 'unavailable' lists what degraded",
    }  # fmt: skip


def visit_cap(requested: int | None, cfg: BrandConfig) -> int:
    """How many sites one scan may visit: the per-scan request (START SCAN field) or the brand's
    track, never above the workspace's "Max candidates per scan" (Settings → Workspace & budget)."""
    caps = [
        c
        for c in (
            requested or cfg.detection.max_candidates,
            cfg.economic_limits.max_candidate_count,
        )
        if c
    ]
    return min(caps) if caps else cfg.detection.max_candidates


def _page_summary(col: Any) -> str:
    """One line about what the sandboxed browser actually saw on the page."""
    f = getattr(col, "features", None)
    parts = [f"HTTP {col.http_status}" if getattr(col, "http_status", None) else "no HTTP answer"]
    sw = getattr(col, "security_warning", None)
    if sw:
        parts.append(f"{str(sw.get('vendor')).upper()} ALREADY FLAGS IT AS PHISHING — {sw.get('reason')}")
    sb, snap = getattr(col, "scanner_block", None), getattr(col, "snapshot", None)
    if sb and not sw:
        vendor = f" ({sb['vendor']})" if sb.get("vendor") else ""
        parts.append(f"REFUSES THE SCANNER{vendor}" + (f" — screenshot and title from a urlscan.io snapshot of {str(snap.get('time') or '')[:10]}" if snap else " — its real page was not seen"))
    final = getattr(col, "final_url", None)
    if final and _norm_url(final) != _norm_url(getattr(col, "url", "")):
        parts.append(f"redirected to {final}")
    if f is not None:
        parts.append(f"title “{(f.title or '—')[:80]}”")
        if f.meta_description:
            parts.append(f"description “{f.meta_description[:110]}”")
        if f.credential_form:
            parts.append("LOGIN FORM (password field)")
        if f.payment_form:
            parts.append("PAYMENT FORM")
        if f.is_parked:
            parts.append("parked page")
    return " · ".join(parts)


def _page_items(col: Any) -> list[dict]:
    f = getattr(col, "features", None)
    items: list[dict] = []
    if f is not None:
        items += [{"label": k, "tag": "brand word on page"} for k in (f.brand_keywords or [])[:6]]
        items += [{"label": t, "tag": "lure phrase"} for t in (f.lure_terms or [])[:4]]
        items += [{"label": a.action or "(same page)", "tag": "form → " + ("password" if a.has_password else "fields")}
                  for a in (f.forms or [])[:3]]  # fmt: skip
    if getattr(col, "dns_records", None):
        items.append({"label": ", ".join(col.dns_records[:3]), "tag": "IP"})
    return items


def _norm_url(u: str) -> str:
    u = (u or "").strip().lower()
    u = u.split("://", 1)[-1].split("#", 1)[0].rstrip("/")
    return u


def _remember_origins(origins: dict[str, str], stream: str, r: Any) -> None:
    """Why each discovered URL is a candidate: the Google result title and query, the dnstwist
    technique, the CT / urlscan source — shown when the candidate is visited."""
    for it in getattr(r, "seen", None) or []:
        if stream == "search" and it.get("url"):
            title = it.get("label") or ""
            origins.setdefault(
                _norm_url(it["url"]),
                f"Google #{it.get('position', '?')} for “{it.get('query', '')}” ({str(it.get('geo', '')).upper()}): “{title[:90]}”",
            )
    for host, ads in (getattr(r, "ads_by_host", None) or {}).items():
        a = ads[0]
        more = f" (+{len(ads) - 1} more ad(s))" if len(ads) > 1 else ""
        origins.setdefault(
            _norm_url(a.get("landing_url") or host),
            f"Meta ad by “{a.get('page_name') or '?'}” ({a.get('country')}"
            + (f", since {a['start_date']}" if a.get("start_date") else "")
            + f"): “{(a.get('text') or '')[:90]}”{more}",
        )
    for h in getattr(r, "hits", None) or []:
        key = _norm_url(h.raw_value)
        if key in origins:
            continue
        pat = h.matched_pattern or ""
        if stream == "dnstwist":
            fuzzer, _, official = pat.partition(":")
            origins[key] = f"look-alike of {official}: {streams.FUZZER_LABELS.get(fuzzer, fuzzer)}"
        elif stream == "ct":
            origins[key] = (
                "found in certificate transparency logs (a TLS certificate was issued for it)"
            )
        elif stream == "urlscan":
            origins[key] = "found in the urlscan.io archive of scanned pages"
        else:
            origins[key] = f"found by {stream}"


def _origin_of(origins: dict[str, str], cand: Any) -> str | None:
    for key in (_norm_url(cand.canonical_url), _norm_url(cand.hostname)):
        if key in origins:
            return origins[key]
    host = _norm_url(cand.hostname)
    return next((v for k, v in origins.items() if k.split("/", 1)[0] == host), None)


MAX_REDIRECT_DEPTH = 2  # A -> B -> C: further than that is a chain nobody built on purpose


def redirect_target(col: Any, cand: Candidate, baseline: BrandBaseline) -> str | None:
    """Where a flagged look-alike sends its visitors, when that is a different site that is not the brand's own: the
    address is part of the same operation. Only a destination that carries the brand in its name, or that is itself a
    page asking for a login while talking about the brand, counts: a kit that sends everybody who is not a victim to
    google.com, or a parked name that forwards to its registrar's shop, has not given anything away."""
    final = getattr(col, "final_url", None) or ""
    host = (urlsplit(final).hostname or "").lower().rstrip(".") if "://" in final else ""
    if not host or "." not in host:
        return None
    if split_host(host).registrable == split_host(cand.hostname).registrable:
        return None  # www., a language folder, http -> https: the same site
    if not pre_filter(host, whitelist_for(baseline.whitelist_domains or baseline.official_domains)).keep:
        return None  # the brand's own site, or one the analyst whitelisted
    if is_known_platform(host) or is_app_store(host):
        return None
    f = getattr(col, "features", None)
    lure = bool(getattr(col, "clickfix", None))  # the landing page itself tries to make the visitor run a command
    if not (lure or streams._looks_related(host, baseline.brand_key) or (f is not None and cloaking.is_phishy(f) and f.brand_keywords)):
        return None
    return final


def _queue_redirect(
    session: Session, brand: Brand, wl: set[str], tgt: dict[str, Any], *, ctx: PipelineContext, to_process: list[Candidate],
    hosts_this_scan: set[str], handled: set[uuid.UUID], origins: dict[str, str], summary: ScanSummary,
) -> None:  # fmt: skip
    """The destination of a flagged look-alike's redirect becomes a candidate of this scan, carrying the verdict of the
    site that sent visitors to it. Beyond the visit cap, and once per address."""
    path = urlsplit(tgt["url"]).path
    hit = DiscoveryHit(DiscoverySource.REDIRECT, tgt["url"], Surface.PATH if path not in ("", "/") else Surface.NAME, tgt["host"])
    norm = normalize(hit)
    if norm is None or not pre_filter(norm.hostname, wl).keep or is_known_platform(norm.hostname):
        return
    if regions_mod.tracked_elsewhere(session, brand.id, norm.canonical_url) is not None:
        return  # another regional campaign of the family already has it
    dd = deduplicate(session, brand.id, norm)
    cand = session.get(Candidate, dd.candidate_id)
    if cand is None or cand.state is CandidateState.DISMISSED:  # the analyst already called it harmless: that stands
        return
    ctx.extra.setdefault("redirect_sources", {})[norm.hostname] = {
        "host": tgt["host"], "severity": tgt["severity"], "finding_id": tgt["finding_id"], "depth": tgt["depth"]}  # fmt: skip
    origins.setdefault(_norm_url(norm.canonical_url), f"{tgt['host']} (rated {tgt['severity'].upper()}) redirects its visitors here")
    summary.redirected.append({"label": norm.hostname, "tag": f"from {tgt['host']}"})
    if cand.id in handled:  # visited already this scan, before the verdict of the site that sends visitors was known
        to_process.append(cand)
    elif norm.hostname not in hosts_this_scan:
        hosts_this_scan.add(norm.hostname)
        to_process.append(cand)
    if dd.is_new:
        summary.new_candidates += 1


def _breakdown_text(breakdown: dict[str, dict]) -> str:
    parts = []
    for _f, b in sorted(breakdown.items(), key=lambda kv: -kv[1]["count"]):
        ex = ", ".join(b["examples"][:2])
        parts.append(f"{b['count']} {b['label']} ({ex})")
    return " · ".join(parts[:6])


_SEV_RANK = {Severity.LOW: 0, Severity.MEDIUM: 1, Severity.HIGH: 2, Severity.CRITICAL: 3}


async def _shop_stage(
    ctx: PipelineContext,
    cand: Candidate,
    col: Any,
    an: AnalysisResult,
    risk: RiskResult,
    shop: dict[str, Any],
) -> tuple[AnalysisResult, RiskResult, str]:
    """Suspicious-shop checks for a retail brand's candidate. When the shop score says more than the
    phishing score (a scam shop is rarely a login kit), the finding becomes a *shop* finding: its
    score row holds the shop score and signals, and the phishing assessment is kept beside it."""
    em, host = ctx.emitter, cand.hostname
    ads = list((shop.get("ads_by_host") or {}).get(host) or [])
    from_ads = bool(ads) or any(s.source is DiscoverySource.META_ADS for s in cand.sources)
    preview = merchant.shop_facts(col.html, cand.canonical_url)
    if not (from_ads or preview.is_shop):
        return an, risk, "phishing"
    terms: relevance.BrandTerms | None = shop.get("terms")
    title = col.features.title if getattr(col, "features", None) is not None else None
    about = (
        relevance.page_about_brand(merchant.visible_text(col.html), title, terms)
        if terms is not None
        else None
    )
    if terms is not None and terms.usable and not (ads or about):
        # a shop, but not for this brand (a look-alike name that sells something else): judging it
        # as a scam shop *for the brand* would only produce false alarms
        em.done("shop", host, f"Shop checks skipped for {host}: it sells something else — nothing on the page "
                f"names {shop.get('brand_name') or 'the brand'} or its products",
                data=_now(f"{host} is not a shop for {shop.get('brand_name') or 'the brand'}",
                          "no brand name, product name or the brand's words next to what it sells", icon="shop"))  # fmt: skip
        return an, risk, "phishing"
    external = shop["checked"] < ad_settings.settings(shop.get("profile"))["shops_checked_max"]
    if external:
        shop["checked"] += 1
        em.running("shop", host, f"Shop checks for {host}: company registry, Google, reviews, AI …",
                   data=_now(f"Is {host} a real shop?",
                             "company number in its country's registry · the company on Google · reviews · "
                             "price vs the official price · contact details · AI opinion", icon="shop"))  # fmt: skip
    th = ctx.config.scoring.thresholds
    res = await merchant.assess(
        ctx.providers, brand_name=shop.get("brand_name") or "", host=host, url=col.final_url or cand.canonical_url,
        html=col.html, age_days=col.whois_age_days, ads=ads, profile=shop.get("profile") or {},
        thresholds={"medium": th.medium, "high": th.high, "critical": th.critical}, external=external,
        terms=terms, about=about or (ads[0].get("why") if ads else None),
    )  # fmt: skip
    s = res["score"]
    country = res["record"].get("country")
    if not (res["record"].get("price") or {}).get("reference") and country not in shop.setdefault("price_warned", set()):
        # without the official price the strongest sign of fake goods cannot fire — say so, once per country
        shop["price_warned"].add(country)
        bid = shop.get("brand_id")
        em.emit("shop", host, "done",
                f"No official price for {shop.get('brand_name') or 'the brand'} in {country}: shops are not compared with it",
                level="warn",
                data={"alert": {"kind": "profile", "provider": "brand profile",
                                "title": f"No official prices for {country} — the price check cannot run",
                                "fix": "A price at half the official one or less is the strongest sign of fake goods. Add the "
                                       f"brand's products and official prices for {country} in the brand profile (Suggest with AI "
                                       "pre-fills them); the next scan compares every shop with them.",
                                "settings_url": f"/ui/brands/{bid}#profile" if bid else "/ui/brands"}})  # fmt: skip
        ctx.extra.setdefault("summary_notes", []).append(
            {"title": f"No official prices for {country} — shops were not compared with the official price",
             "detail": "add the products and prices in the brand profile; a price at half or less is the strongest sign of fakes"})  # fmt: skip
    trace.log("shop", f"{host}: shop score {s['score']} {s['severity'].value}", fired=res["fired"],
              penalties=res["penalties"], registry=res["record"]["registry"].get("status"),
              presence=res["record"]["web"].get("presence"), ai=res["record"].get("ai"))  # fmt: skip
    ai = res["record"].get("ai") or {}
    em.done("shop", host,
            f"Shop checks: {s['score']} {s['severity'].value.upper()}"
            + (f" · AI: {ai['verdict'].replace('_', ' ')}" if ai else ""),
            data={"score": s["score"], "severity": s["severity"].value,
                  **_now(f"{host}: shop risk {s['score']} · {s['severity'].value.upper()}",
                         "; ".join(list(res["fired"].values())[:3]) or "no warning signs", icon="shop",
                         items=[{"label": why, "tag": f"+{merchant.SHOP_SIGNALS[k][0]}", "note": k}
                                for k, why in res["fired"].items()])})  # fmt: skip
    shop_wins = (
        _SEV_RANK[s["severity"]] >= 1 and _SEV_RANK[s["severity"]] > _SEV_RANK[risk.severity]
    )
    if not shop_wins:  # a phishing finding (or nothing): keep the shop record beside it
        risk.breakdown["shop"] = res["record"]
        return an, risk, "phishing"
    phishing = {"score": risk.score, "severity": risk.severity.value, "signals": dict(risk.signals),
                "scoring_version": risk.scoring_version, "ai": risk.breakdown.get("ai")}  # fmt: skip
    new_risk = RiskResult(
        raw=s["raw"], score=s["score"], severity=s["severity"], confidence=s["confidence"],
        signals=s["signals"], groups=s["groups"], scoring_version=merchant.SHOP_SCORING_VERSION,
        breakdown={**s["breakdown"], "shop": res["record"], "phishing": phishing, "cloaking": risk.breakdown.get("cloaking")},
    )  # fmt: skip
    new_an = AnalysisResult(
        signals=dict(s["signals"]), evidence_refs=an.evidence_refs, unavailable=an.unavailable,
        fp_flags=tuple(res["penalties"]), details={"signals": {**res["fired"], **res["penalties"]}},
    )  # fmt: skip
    return new_an, new_risk, "shop"


async def _social_step(
    ctx: PipelineContext, brand: Brand, baseline: BrandBaseline, store: EvidenceStore,
    summary: ScanSummary, geos: list[str],
) -> list[DiscoveryHit]:  # fmt: skip
    """Facebook pages and Instagram profiles under the brand's name: find, read, judge, record.
    Returns the off-brand links the fake accounts send people to, for the web pipeline."""
    from urllib.parse import urlsplit

    from brandwatch.detection import social

    em, cfg, shop = ctx.emitter, ctx.config, ctx.extra["shop"]
    profile, terms = shop["profile"], shop["terms"]
    officials = social.official_handles(profile, baseline.official_social)
    official_domains = {discovery.split_host(d).registrable for d in (*baseline.official_domains, *baseline.whitelist_domains)}
    countries = [c.upper() for c in profile.get("countries") or []] or [g.upper() for g in geos]
    th = cfg.scoring.thresholds
    em.running("discovery", "social", f"Social media: Facebook pages and Instagram profiles named after {brand.name} …",
               data=_now("Searching social media for impostors",
                         "Facebook pages by name (Meta's page search, every country) and Instagram / Facebook profiles Google "
                         "knows — then each one's public content is read and judged", icon="social"))  # fmt: skip

    def narrate(acc: Any) -> None:
        em.running("social", acc.host, f"Looking at the {acc.label}: page history, bio, links, recent posts, profile picture, AI reading …",
                   data=_now(f"Is the {acc.label} really {brand.name}?",
                             "page history (created · renamed · admins) · bio and links · recent posts · profile picture vs the "
                             "logo · the AI reads the content", icon="social"))  # fmt: skip

    try:
        run = await social.scan(
            ctx.providers, brand_name=brand.search_name, brand_key=baseline.brand_key, terms=terms, officials=officials,
            official_domains=official_domains, countries=countries, logo_phash=baseline.favicon_phash,
            thresholds={"medium": th.medium, "high": th.high, "critical": th.critical},
            demo=ctx.settings.demo_mode, search_geo=geos[0] if geos else "us", on_event=narrate,
        )  # fmt: skip
    except Exception as exc:  # noqa: BLE001 - social media never kills a scan
        em.emit("discovery", "social", "skipped", f"Social media check skipped: {type(exc).__name__}: {exc}", level="warn")
        return []
    fakes = watched = unrelated = 0
    for res in run.results:
        acc, sc, ai = res.acc, res.score, res.ai
        em.done("social", acc.host,
                f"{acc.label}: social score {sc['score']} {sc['severity'].value.upper()}"
                + (f" · AI: {ai['verdict'].replace('_', ' ')} ({ai['confidence']:.0%})" if ai else ""),
                data={"score": sc["score"], "severity": sc["severity"].value,
                      **_now(f"{acc.label}: {res.decision}", res.why, icon="social",
                             items=[{"label": why, "tag": f"+{social.SOCIAL_SIGNALS[k][0]}" if k in social.SOCIAL_SIGNALS
                                     else f"−{social.SOCIAL_PENALTIES.get(k, 0)}", "note": k} for k, why in res.record["why"].items()])})  # fmt: skip
        if res.decision == "unrelated":
            unrelated += 1
            continue
        prior = ctx.session.scalars(sa.select(Candidate).where(Candidate.brand_id == brand.id, Candidate.canonical_url == acc.url)).first()
        if prior is not None and prior.state is CandidateState.DISMISSED:  # an analyst already judged it
            em.done("social", acc.host, f"{acc.label}: dismissed by an analyst earlier — not raised again")
            continue
        fr = social.record(ctx.session, store, workspace_id=ctx.workspace_id, brand_id=brand.id, res=res,
                           cfg=cfg.scoring, watch_cadence_hours=cfg.detection.watch_cadence_hours)  # fmt: skip
        ctx.session.commit()
        if fr.disposition == "finding":
            fakes += 1
            summary.findings += 1
            if sc["severity"] is Severity.CRITICAL:
                summary.criticals += 1
            em.done("finding", acc.host, f"Finding {'created' if fr.created else 'updated'} for the {acc.label} ({sc['severity'].value})",
                    level="warn" if sc["severity"] in (Severity.HIGH, Severity.CRITICAL) else "info",
                    data={"finding_id": str(fr.finding_id), "severity": sc["severity"].value})  # fmt: skip
            notifier: NotificationService | None = ctx.extra.get("notifier")
            row = ctx.session.get(Finding, fr.finding_id) if notifier is not None else None
            if notifier is not None and row is not None:
                notifier.notify_finding(ctx.session, row, score=sc["score"], confidence=sc["confidence"], created=fr.created)
        else:
            watched += 1
            summary.watching += 1
    own = sum(1 for e in run.seen if e.get("official"))
    other = sum(1 for e in run.seen if not e.get("visit") and not e.get("official"))
    detail = (f"{fakes} fake account(s) · {watched} on the watchlist · {unrelated + other} not about the brand · {own} the brand's own"
              + (f" · {run.skipped} not looked at (limit {social.SOCIAL_MAX} per scan)" if run.skipped else "")
              + (f" · {len(run.links)} link(s) from fake accounts sent to the website checks" if run.links else ""))  # fmt: skip
    summary.step(f"Checked social media: {len(run.seen)} Facebook page(s) / Instagram profile(s) under the brand's name",
                 detail + (f" — {run.note}" if run.note else ""), run.seen)  # fmt: skip
    em.done("discovery", "social", f"Social media: {len(run.seen)} account(s) named after {brand.name}, {fakes} fake",
            counts={"accounts": len(run.seen), "fake": fakes},
            data=_now(f"Social media: {fakes} fake account(s) of {len(run.seen)}", detail, run.seen, icon="social"))  # fmt: skip
    hits = []
    for url, who in run.links.items():
        path = urlsplit(url).path
        hits.append(DiscoveryHit(DiscoverySource.SOCIAL, url, Surface.PATH if path not in ("", "/") else Surface.NAME,
                                 matched_pattern=f"social: linked from the {who}"))  # fmt: skip
    return hits


async def process_candidate(
    ctx: PipelineContext, cand: Candidate, baseline: BrandBaseline, store: EvidenceStore
) -> CandidateOutcome:
    em = ctx.emitter
    host = cand.hostname
    cfg = ctx.config
    if True:
        em.running("enrichment", host, f"Resolving DNS and fetching {cand.canonical_url} …",
                   data=_now(f"Collecting evidence on {host}",
                             "DNS records · WHOIS age and registrar · TLS certificate · reputation feeds · "
                             "then the page itself in a sandboxed Chromium (HTML, screenshot, favicon)",
                             icon="enrich"))  # fmt: skip
        prev = trigger_engine.PreviousState.load(
            ctx.session, cand.id
        )  # before this run's observation
        trace.section(f"CANDIDATE · {host}")
        col = await enrich(ctx, cand, store, brand_keywords=list(baseline.keywords))
        col.redirected_from = (ctx.extra.get("redirect_sources") or {}).get(host)  # a flagged look-alike redirects here
        trace.log("enrich", f"{host}: evidence collected", **_col_summary(col))
        col.infra_links = known_infrastructure_links(ctx.session, cand, col)
        if not col.liveness.alive and "dns" not in col.unavailable:
            if col.liveness.parked:  # registered look-alike with no A record: watch, do not dismiss
                em.done("enrichment", host,
                        f"{host} is registered but serves no website yet → kept on the watchlist",
                        counts={"evidence": len(col.evidence_ids)},
                        data=_now(f"{host}: registered, no website",
                                  "the domain exists (someone registered this look-alike) but has no web server "
                                  "right now — it is watched and re-checked, since kits often go live later",
                                  icon="enrich"))  # fmt: skip
                return CandidateOutcome(cand.id, host, "watch")
            dismiss_dead(cand)
            em.done(
                "enrichment",
                host,
                f"{host} does not exist (no DNS record) → dismissed",
                counts={"evidence": len(col.evidence_ids)},
            )
            return CandidateOutcome(cand.id, host, "dismissed")
        if col.unavailable:
            em.emit("enrichment", host, "done", f"Evidence collected for {host}; unavailable: {', '.join(col.unavailable)}",
                    level="warn", counts={"evidence": len(col.evidence_ids)},
                    data=_now(f"Captured {cand.canonical_url}",
                              _page_summary(col) + f" · unavailable: {', '.join(col.unavailable)}",
                              _page_items(col), icon="shot", image=f"/api/evidence/{col.evidence_ids['screenshot']}/artifact"
                              if col.evidence_ids.get("screenshot") else None))  # fmt: skip
        else:
            em.done(
                "enrichment",
                host,
                f"Evidence collected for {host}",
                counts={"evidence": len(col.evidence_ids)},
                data=_now(
                    f"Captured {cand.canonical_url}",
                    _page_summary(col),
                    _page_items(col),
                    icon="shot",
                    image=f"/api/evidence/{col.evidence_ids['screenshot']}/artifact"
                    if col.evidence_ids.get("screenshot")
                    else None,
                ),
            )
        if col.clickfix:  # the page itself tries to make the visitor run a command: read, never followed
            ctx.extra.setdefault("clickfix_sites", []).append({"host": host, "kind": col.clickfix["kind"], "reason": col.clickfix["reason"]})
            em.emit("enrichment", host, "done", f"{host}: {col.clickfix['reason']}", level="warn",
                    data=_now(f"{host} tries to make the visitor run a command",
                              f"{col.clickfix['reason']}. " + " · ".join(col.clickfix.get("indicators") or [])
                              + ". BrandWatch only reads the page; it never follows the steps or runs anything.", [],
                              icon="shot", image=f"/api/evidence/{col.evidence_ids['screenshot']}/artifact"
                              if col.evidence_ids.get("screenshot") else None))  # fmt: skip
        if col.no_picture:  # blank, and urlscan.io has no picture either: say where the page leads
            np_ = col.no_picture
            ctx.extra.setdefault("blank_sites", []).append({"host": host, "final_url": np_.get("final_url"), "chain": np_.get("chain") or []})
            lead = " → ".join([*(np_.get("chain") or []), np_.get("final_url") or ""])
            em.emit("enrichment", host, "done", f"{host} showed a blank page — no screenshot; it leads to {np_.get('final_url') or 'nowhere visible'}", level="warn",
                    data=_now(f"{host}: a blank page, so no screenshot",
                              f"{np_.get('why')}. Where the visit ended up: {lead if np_.get('chain') else (np_.get('final_url') or 'the same address')}",
                              [], icon="shot"))  # fmt: skip
        elif col.snapshot and col.snapshot.get("reason") == "blank":
            em.emit("enrichment", host, "done",
                    f"{host} showed a blank page — using the urlscan.io picture of {str(col.snapshot.get('time') or '')[:10]}",
                    data=_now(f"{host}: a blank page, so the picture comes from urlscan.io",
                              f"BrandWatch's own screenshot was one flat colour. urlscan.io has a scan of {col.snapshot.get('url')} "
                              f"({str(col.snapshot.get('time') or '')[:10]}): that picture is shown, labelled as theirs.",
                              [{"label": col.snapshot.get("url") or host, "url": col.snapshot.get("result_url"), "tag": "urlscan.io"}],
                              icon="shot", image=f"/api/evidence/{col.evidence_ids['screenshot']}/artifact"
                              if col.evidence_ids.get("screenshot") else None))  # fmt: skip
        if col.security_warning:  # somebody already judged it: no snapshot, no cloaking probes, no AI — rated High
            sw = col.security_warning
            ctx.extra.setdefault("flagged_sites", []).append({"host": host, "vendor": sw.get("vendor"), "reason": sw.get("reason")})
            em.emit("enrichment", host, "done",
                    f"{host} is already flagged as phishing by {sw.get('vendor')} — rated High without a deeper check",
                    level="warn",
                    data=_now(f"{sw.get('vendor')} already flags {host} as phishing",
                              f"{sw.get('reason')}. BrandWatch did not open the site any further (no Ignore & Proceed, no cloaking probes, "
                              "no AI opinion): the verdict is evidence enough and the site is rated High. Press Rescan on the finding for a full check.",
                              [], icon="shot", image=f"/api/evidence/{col.evidence_ids['screenshot']}/artifact"
                              if col.evidence_ids.get("screenshot") else None))  # fmt: skip
        if col.scanner_block:  # the site refuses automated visitors: say so, and where its picture came from
            sb, snap = col.scanner_block, col.snapshot
            vendor = f" ({sb['vendor']})" if sb.get("vendor") else ""
            ctx.extra.setdefault("blocked_sites", []).append(
                {"host": host, "status": sb.get("status"), "vendor": sb.get("vendor"), "snapshot": (snap or {}).get("time"),
                 "why": (col.provider_notes.get("snapshot") or "")})  # fmt: skip
            if snap:
                em.emit("enrichment", host, "done",
                        f"{host} answered HTTP {sb.get('status')}{vendor} — using the urlscan.io snapshot of {str(snap.get('time') or '')[:10]}",
                        data=_now(f"Got HTTP {sb.get('status')} from {host}{vendor}",
                                  f"{sb.get('reason')}. urlscan.io has a public scan of the site from {str(snap.get('time') or '')[:10]}: its screenshot"
                                  + (" and page" if snap.get("has_dom") else " and title")
                                  + " are compared with the real brand instead of the block page. Scored for refusing scanners too.",
                                  [{"label": snap.get("url") or host, "url": snap.get("result_url"), "tag": "urlscan.io snapshot"}],
                                  icon="shot", image=f"/api/evidence/{col.evidence_ids['screenshot']}/artifact"
                                  if col.evidence_ids.get("screenshot") else None))  # fmt: skip
            else:
                em.emit("enrichment", host, "done", f"{host} answered HTTP {sb.get('status')}{vendor} — no urlscan.io snapshot, its real page was not seen",
                        level="warn",
                        data=_now(f"Got HTTP {sb.get('status')} from {host}{vendor}",
                                  f"{sb.get('reason')}. {col.provider_notes.get('snapshot') or 'urlscan.io was not asked'}. "
                                  "Scored for refusing scanners; the comparison rests on the domain, WHOIS and certificate signals.",
                                  [], icon="shot"))  # fmt: skip
        # ---- Tier 3/4 cloaking multi-probe (Phase 5) ------------------------------------------
        if cfg.detection.cloaking_probes and col.liveness.alive and col.features is not None:
            pre = scoring_stage.score(
                analysis_stage.analyze(col, baseline, cfg.scoring), cfg.scoring
            )
            if cloaking.should_probe(col, baseline.brand_key, pre.severity):
                ctx.extra["cloaking_probed"] = int(ctx.extra.get("cloaking_probed", 0)) + 1
                em.running(
                    "cloaking",
                    host,
                    "Multi-probe: crawler User-Agent (BrandWatchBot) · ?email= parameter · search referer …",
                    data=_now(
                        f"Checking whether {host} hides from scanners",
                        "Re-visiting the page as the BrandWatchBot crawler, with a victim-style ?email= link and "
                        "from a search-engine referer — phishing kits often show a fake page to bots, and a bot check "
                        "in front of the page is kept as a screenshot",
                        icon="cloak",
                    ),
                )
                cres = await cloaking.probe(
                    ctx, cand, col, store, brand_key=baseline.brand_key, keywords=list(baseline.keywords),
                    prelim=pre.severity,
                )  # fmt: skip
                trace.log("cloaking", f"{host}: {len(cres.probes)} probe(s)",
                          probes=[p.summary() for p in cres.probes], signals=cres.signals,
                          revealed_by=cres.revealed_by, residential=cres.residential, suspected=cres.suspected,
                          how="the same URL re-fetched as a crawler UA, with a victim-style ?email= parameter and "
                              "from a search-engine referer; a different page (hash / phishy features) = cloaking")  # fmt: skip
                if cres.residential == "used":
                    rc = str(ctx.extra.get("proxy_country") or "")
                    net = "mobile-network" if ctx.extra.get("proxy_kind") == "mobile" else "residential"
                    dev = {"desktop": "as a desktop browser", "mobile": "as a phone", "both": "as a desktop browser and as a phone"}[str(ctx.extra.get("devices") or "desktop")]
                    em.emit("cloaking", host, "done",
                            f"Re-fetched {host} through a {net} IP" + (f" in {rc.upper()}" if rc else "") + f", {dev}",
                            level="warn" if cres.suspected else "info",
                            data=_now(f"{net.capitalize()} re-fetch of {host}",
                                      f"a real {rc.upper() or 'local'} {net} IP (the proxy you set), {dev} — "
                                      "phishing kits that only show the fake page to local home or phone users are caught here",
                                      icon="cloak"))  # fmt: skip
                if cres.signals:
                    tail = (
                        f"; real page revealed by the {cres.revealed_by} probe"
                        if cres.revealed_by
                        else ""
                    )
                    em.emit("cloaking", host, "done", f"Cloaking detected: {', '.join(sorted(cres.signals))}{tail}",
                            level="warn", data=cres.summary())  # fmt: skip
                else:
                    em.done("cloaking", host,
                            f"No cloaking: {sum(p.ok for p in cres.probes)} probe(s) agree (residential: {cres.residential})",
                            data=cres.summary())  # fmt: skip

        if col.liveness.alive and not col.liveness.content_present:
            cand.state = (
                CandidateState.WATCHING if cand.state is not CandidateState.FLAGGED else cand.state
            )
            schedule_next_scan(cand, hours=cfg.detection.watch_cadence_hours)
            why = "parked" if col.liveness.parked else "no content"
            em.done(
                "analysis",
                host,
                f"{host} is {why} → watchlist (re-check in {cfg.detection.watch_cadence_hours}h)",
            )
            return CandidateOutcome(cand.id, host, "watch")

        fired = trigger_engine.evaluate(prev, col)
        if fired:
            col.triggers = [t.name for t in fired]
            bump = trigger_engine.priority_bump(fired)
            if bump:
                cand.priority = (cand.priority or 0) + bump
            for t in fired:
                em.emit(
                    "trigger",
                    host,
                    "done",
                    f"Trigger {t.name} → {t.action}: {t.detail}",
                    level="warn",
                    data={"trigger": t.name, "action": t.action},
                )
        em.running(
            "analysis",
            host,
            f"Comparing {host} against the {baseline.brand_key} baseline …",
            data=_now(
                f"Comparing {host} with the real {baseline.brand_key}",
                "Favicon hash · screenshot similarity · colour palette · login form · brand keywords · "
                "domain age and hosting",
                icon="compare",
            ),
        )
        an = analysis_stage.analyze(col, baseline, cfg.scoring)
        trace.log("analysis", f"{host}: {len(an.signals)} signal(s) fired",
                  signals=an.signals, why=an.details, fp_flags=list(an.fp_flags),
                  unavailable=list(an.unavailable))  # fmt: skip
        fav = (
            "MATCH"
            if "favicon_exact" in an.signals
            else ("near" if "favicon_phash_near" in an.signals else "no match")
        )
        em.done(
            "analysis",
            host,
            f"Favicon vs official: {fav}; {len(an.signals)} signal(s) fired",
            data={"signals": sorted(an.signals)},
        )

        risk = scoring_stage.score(an, cfg.scoring)
        trace.log("scoring", f"{host}: raw {risk.raw} → score {risk.score} {risk.severity.value} (confidence {risk.confidence:.0f}%)",
                  groups=risk.groups, breakdown=risk.breakdown, version=risk.scoring_version,
                  how="points per signal → capped per group → combination rules/bonuses → false-positive "
                      "penalties → 0-100 score → severity by thresholds; confidence = how much evidence "
                      "was actually available")  # fmt: skip
        if col.reputation_counts.get("virustotal"):
            ctx.extra.setdefault("vt", {})[host] = col.reputation_counts["virustotal"]
        em.done(
            "scoring", host,
            f"Computing risk score… {risk.score} {risk.severity.value.upper()} (confidence {risk.confidence:.0f}%)",
            data={"score": risk.score, "severity": risk.severity.value, "confidence": risk.confidence,
                  **_now(f"{host}: risk {risk.score} · {risk.severity.value.upper()}" + _vt_suffix(col),
                         f"Confidence {risk.confidence:.0f}% · strongest evidence: "
                         + (", ".join(_signal_label(sig) for sig in _by_points(risk.signals)[:5]) or "none"), icon="score",
                         items=[{"label": _signal_label(sig), "tag": f"+{int(risk.signals.get(sig, 0))}", "note": sig}
                                for sig in _by_points(risk.signals)])},
        )  # fmt: skip

        # ---- advisory layers: never change the deterministic score (spec §5) -------------------
        record = {
            "signals": sorted(an.signals), "fp_flags": list(an.fp_flags), "unavailable": list(an.unavailable),
            "score": risk.score, "severity": risk.severity.value, "scoring_version": risk.scoring_version,
        }  # fmt: skip
        cand.last_analysis = record
        cand.last_scored_at = utcnow()
        if col.cloaking_summary:
            risk.breakdown["cloaking"] = col.cloaking_summary
        model = ctx.extra.get("ml_model")
        if model:
            prob = ml.predict(model, record)
            risk.breakdown["ml"] = {
                "probability": prob,
                "model": model["version"],
                "metrics": model.get("metrics"),
            }
            em.done(
                "ml", host, f"Classifier {model['version']}: P(phishing) = {prob:.0%} (advisory)"
            )
        if cfg.detection.ai_second_opinion and not col.security_warning and risk.severity in (
            Severity.MEDIUM,
            Severity.HIGH,
            Severity.CRITICAL,
        ):  # a verdict somebody else made needs no advisory opinion (and costs nothing)
            brand_row = ctx.session.get(Brand, ctx.brand_id)
            try:
                opinion = await ai_stage.second_opinion(
                    ctx.providers,
                    url=cand.canonical_url,
                    features=col.features,
                    brand_name=brand_row.search_name if brand_row else "",
                )
            except Exception:  # noqa: BLE001 - advisory only
                opinion = None
            if opinion:
                risk.breakdown["ai"] = opinion
                trace.log("ai", f"{host}: second opinion", opinion=opinion,
                          how="advisory only — never changes the deterministic score; the exact prompt and raw answer "
                              "are in the llm.analyze line above")  # fmt: skip
                verdict = "phishing" if opinion["is_phishing"] else "not phishing"
                who = (
                    f" impersonating {opinion['impersonated_brand']}"
                    if opinion.get("impersonated_brand")
                    else ""
                )
                em.done(
                    "ai",
                    host,
                    f"AI second opinion (advisory): {verdict}{who} · {opinion['confidence']:.0%}",
                )

        kind = "phishing"
        shop = ctx.extra.get("shop") or {}
        if shop.get("retail") and col.html:
            an, risk, kind = await _shop_stage(ctx, cand, col, an, risk, shop)

        fr = finding_stage.record(
            ctx.session, workspace_id=ctx.workspace_id, cand=cand, col=col, analysis=an, risk=risk,
            cfg=cfg.scoring, watch_cadence_hours=cfg.detection.watch_cadence_hours, kind=kind,
        )  # fmt: skip
        for t in trigger_engine.evaluate(None, col, risk_score=risk.score):
            if t.name == "risk_high":
                em.emit(
                    "trigger",
                    host,
                    "done",
                    f"Trigger {t.name} → {t.action}: {t.detail}",
                    data={"trigger": t.name},
                )
        if fr.disposition == "finding" and risk.severity in (Severity.HIGH, Severity.CRITICAL):
            depth = int((col.redirected_from or {}).get("depth") or 0)
            tgt_url = redirect_target(col, cand, baseline) if depth < MAX_REDIRECT_DEPTH else None
            if tgt_url:  # the loop in run_scan adds it to this scan
                ctx.extra.setdefault("redirect_targets", []).append(
                    {"url": tgt_url, "host": host, "severity": risk.severity.value, "finding_id": str(fr.finding_id), "depth": depth + 1})
                em.emit("enrichment", host, "done", f"{host} redirects its visitors to {urlsplit(tgt_url).hostname} — checked next, with the same suspicion",
                        level="warn",
                        data=_now(f"{host} sends visitors to {urlsplit(tgt_url).hostname}",
                                  f"a site rated {risk.severity.value.upper()} forwards to another address that carries the brand: that address is part of the "
                                  "same operation, so it is added to this scan and rated with that in mind", [], icon="enrich"))  # fmt: skip
        if fr.disposition == "finding":
            verb = (
                "created"
                if fr.created
                else (
                    "updated · confirmed earlier, score history appended"
                    if fr.state is FindingState.CONFIRMED
                    else "updated"
                )
            )
            em.done("finding", host, f"Finding {verb} for {host} ({risk.severity.value})",
                    level="warn" if risk.severity in (Severity.HIGH, Severity.CRITICAL) else "info",
                    data={"finding_id": str(fr.finding_id), "severity": risk.severity.value})  # fmt: skip
            notifier: NotificationService | None = ctx.extra.get("notifier")
            if notifier is not None:
                finding_row = ctx.session.get(Finding, fr.finding_id)
                if finding_row is not None and notifier.notify_finding(
                    ctx.session,
                    finding_row,
                    score=risk.score,
                    confidence=risk.confidence,
                    created=fr.created,
                ):
                    em.emit(
                        "notify",
                        host,
                        "done",
                        f"Notified analysts ({risk.severity.value}) via {', '.join(n.name for n in notifier.notifiers)}",
                    )
        else:
            em.done(
                "finding",
                host,
                f"{host} below finding threshold ({risk.severity.value}) → watchlist",
            )
        return CandidateOutcome(
            cand.id,
            host,
            fr.disposition,
            risk.severity,
            risk.score,
            risk.confidence,
            fr.finding_id,
            risk.signals,
        )


def _finish_cancelled(
    session: Session, em: ScanEventEmitter, job: ScanJob, summary: ScanSummary, where: str
) -> ScanSummary:
    """The analyst pressed Stop: close the job cleanly and tell the console why it ended."""
    job.finished_at = utcnow()
    session.flush()
    summary.step(
        "Stopped by the analyst",
        f"the scan was stopped {where}; everything collected so far is kept",
    )
    em.emit("summary", "scan", "done", f"Scan stopped by the analyst {where}",
            level="warn",
            data={**summary.as_dict(), "cancelled": True,
                  **_now("Stopped by the analyst", f"The scan ended {where}. Evidence, candidates and "
                         "findings collected so far are kept.", icon="done")})  # fmt: skip
    return summary


async def run_scan(
    session: Session,
    job_id: uuid.UUID,
    *,
    settings: Settings | None = None,
    store: EvidenceStore | None = None,
    hits: Iterable[DiscoveryHit] | None = None,
    max_candidates: int | None = None,
    notifier: NotificationService | None = None,
    max_names: int | None = None,
) -> ScanSummary:
    settings = settings or get_settings()
    store = store or LocalEvidenceStore(settings.evidence_dir)
    t0 = time.monotonic()

    job = session.get(ScanJob, job_id)
    if job is None or job.brand_id is None:
        raise LookupError("scan job not found or has no brand")
    brand = session.get(Brand, job.brand_id)
    if brand is None:
        raise LookupError("brand not found")
    if job.state is JobState.CANCELLED:  # stopped while still queued
        job.finished_at = utcnow()
        session.commit()
        return ScanSummary(job_id=job_id, brand_id=brand.id)
    job.state = JobState.RUNNING
    job.started_at = utcnow()
    session.commit()  # the console shows "running" right away

    cfg = load_brand_config(session, brand.id)
    em = ScanEventEmitter(session, job_id, secrets=settings.known_secret_values(), commit=True)
    lookups = tenancy.workspace_lookups(session, job.workspace_id)
    set_checkpoint(session)
    proxy_cfg = await tenancy.resolve_proxy(session, job.workspace_id, settings)
    proxy_country = cfg.detection.residential_country or proxy_mod.country_for(
        cfg.detection.search_geo, cfg.detection.search_lang
    )
    proxy_url = proxy_cfg.url(proxy_country) if proxy_cfg.enabled else None
    trace.start(job_id, settings.evidence_dir, secrets=settings.known_secret_values())
    trace.log("scan", "configuration", brand=brand.name, job_kind=job.kind, preset=cfg.preset,
              detection=cfg.detection.model_dump(), scoring_version=cfg.scoring.version,
              thresholds=cfg.scoring.thresholds, group_caps=cfg.scoring.group_caps,
              weights=cfg.scoring.weights, demo_mode=settings.demo_mode, lookups=lookups,
              whois_chain=tenancy.whois_route(lookups),
              residential_proxy={"mode": proxy_cfg.mode, "enabled": proxy_cfg.enabled,
                                 "country": proxy_country, "host": proxy_cfg.host})  # fmt: skip
    ledger = DbUsageLedger(session, job.workspace_id, cfg.economic_limits)
    dnslookup.set_policy(lookups["dns"]["mode"], lookups["dns"]["fallback"])
    providers = ProviderRegistry(
        settings,
        ledger=ledger,
        job_id=job_id,
        key_overrides=keystore.load_keys(session, job.workspace_id, settings),
        route_overrides={"whois": tenancy.whois_route(lookups)},
        residential_proxy=proxy_url,
    )
    ctx = PipelineContext(
        session=session, job_id=job_id, workspace_id=job.workspace_id, brand_id=brand.id,
        settings=settings, config=cfg, providers=providers, emitter=em,
    )  # fmt: skip
    ctx.extra["notifier"] = notifier
    ctx.extra["full_check"] = bool((job.payload or {}).get("full_check"))  # an analyst's rescan also looks behind warnings
    ctx.extra["proxy_country"] = proxy_country
    ctx.extra["proxy_enabled"] = proxy_cfg.enabled  # the proxy set in Settings (not only an environment variable)
    ctx.extra["proxy_kind"] = proxy_cfg.kind  # residential | mobile
    ctx.extra["devices"] = tenancy.workspace_probe_settings(session, job.workspace_id)["devices"]  # desktop | mobile | both
    ctx.extra["ml_model"] = ml.latest_model(session, job.workspace_id)
    # suspicious shops: only for brands whose products other shops resell
    ctx.extra["shop"] = {"retail": (brand.kind or "service") == "retail", "profile": dict(brand.profile or {}),
                         "ads_by_host": {}, "checked": 0, "brand_name": brand.search_name, "brand_id": str(brand.id)}  # fmt: skip
    summary = ScanSummary(job_id=job_id, brand_id=brand.id)
    issues_seen: dict[tuple[str, str], int] = {}
    origins: dict[
        str, str
    ] = {}  # url / host → how the candidate was found (search title, fuzzer …)

    # --- baseline ----------------------------------------------------------------------------
    baseline = load_baseline(session, brand)
    rebuild = bool((job.payload or {}).get("rebuild_baseline")) and hits is None
    if baseline is not None and not rebuild:
        em.done("baseline", brand.name,
                f"Baseline v{baseline.version} reused: favicon {baseline.favicon_mmh3}, {len(baseline.keywords)} keywords, "
                f"{len(baseline.search_queries)} search queries",
                data=_now(f"Baseline v{baseline.version} reused — the fingerprint of the real {brand.name}",
                          f"favicon hash {baseline.favicon_mmh3} · screenshot pHash {baseline.screenshot_phash or '—'} · "
                          f"{len(baseline.palette)} brand colours · login/sign-up pages: {len(baseline.auth_pages)} · "
                          f"{len(baseline.keywords)} keywords. Tick 'include fingerprinting' on START SCAN to rebuild it.",
                          [{"label": c, "color": c} for c in baseline.palette[:6]] + [{"label": k, "tag": "keyword"} for k in baseline.keywords[:6]],
                          icon="baseline", image=f"/api/brands/{brand.id}/baseline/screenshot" if baseline.screenshot_phash else None))  # fmt: skip
        summary.step(f"Used the fingerprint of the official site (baseline v{baseline.version})",
                     f"{len(baseline.keywords)} keywords, {len(baseline.search_queries)} search queries, "
                     f"{len(baseline.auth_pages)} login/sign-up page(s)", [{"label": q, "tag": "query"} for q in baseline.search_queries])  # fmt: skip
    if baseline is None or rebuild:
        st = _StageTimer(session, job_id, "baseline")
        em.running(
            "baseline",
            brand.name,
            f"No baseline yet — fetching the official site of {brand.name} …",
            data=_now(
                f"Learning what the real {brand.name} looks like",
                "Fetching the official site in the sandbox: favicon, screenshot, colours, "
                "login form and keywords become the fingerprint every candidate is compared with",
                icon="baseline",
            ),
        )

        def narrate_baseline(title: str, detail: str, items: list[dict], image: str | None) -> None:
            em.running("baseline", brand.name, f"{title} — {detail}" if detail else title,
                       data=_now(title, detail or None, items, icon="baseline", image=image))  # fmt: skip

        resid_off = cloaking.residential_gate(
            session, job.workspace_id, settings, cfg.economic_limits.max_residential_gb, proxy_cfg.enabled
        )
        report = await build_baseline(
            session, brand, providers, store, narrate=narrate_baseline,
            escalate=resid_off is None, residential_off=resid_off,
        )  # fmt: skip
        baseline = load_baseline(session, brand)
        st.finish(hits=1, api_calls=1)
        em.done("baseline", brand.name,
                f"Baseline v{report.version}: favicon {report.favicon_mmh3}, {len(report.keywords)} keywords, "
                f"{len(baseline.search_queries)} search queries, {len(baseline.official_apps)} official app listing(s)",
                data={"unavailable": report.unavailable,
                      **_now(f"Learned what {brand.name} looks like",
                             f"{len(report.keywords)} keywords · {len(baseline.search_queries)} Google queries impersonators "
                             f"would target · login/sign-up pages: {len(baseline.auth_pages)} (password form: "
                             f"{'yes' if baseline.has_login_form else 'no'}) · "
                             f"{len(baseline.official_apps)} official app listing(s) · favicon {report.favicon_mmh3}",
                             [{"label": k, "tag": "keyword"} for k in report.keywords[:8]]
                             + [{"label": q, "tag": "query"} for q in baseline.search_queries[:8]],
                             icon="baseline", image=f"/api/brands/{brand.id}/baseline/screenshot")})  # fmt: skip
        summary.step(f"Fingerprinted the official site ({', '.join(officials_for_report(baseline))})",
                     f"{len(report.keywords)} keywords, {len(baseline.search_queries)} AI search queries, "
                     f"{len(baseline.official_apps)} official app listing(s)",
                     [{"label": q, "tag": "query"} for q in baseline.search_queries])  # fmt: skip
    assert baseline is not None
    _report_baseline_health(em, summary, brand, baseline)
    trace.section("BASELINE · the official site's fingerprint")
    trace.log("baseline", "fingerprint in use",
              how="homepage fetched in the sandboxed browser → favicon mmh3/pHash, screenshot pHash/dHash, "
                  "colour palette, login-form DOM signature; keywords = brand token + <title>/<h1>/<h2> words "
                  "+ LLM keywords (see the llm.analyze line above for the exact prompt and answer); search "
                  "queries = LLM list or the default generator; auth pages = Login/Sign-up links followed",
              **{k: v for k, v in dataclasses.asdict(baseline).items() if k != "brand_id"})  # fmt: skip
    _flush_issues(providers, em, issues_seen)
    shop_profile = ctx.extra["shop"]["profile"]
    ctx.extra["shop"]["terms"] = relevance.brand_terms(
        brand.search_name, baseline.brand_key,
        ad_keywords=list(shop_profile.get("ad_keywords") or []) if ctx.extra["shop"]["retail"] else [],
        products=[str(p.get("name") or "") for p in shop_profile.get("products") or [] if isinstance(p, dict)],
        official_domains=list(baseline.official_domains), vertical=baseline.vertical or brand.vertical,
        keywords=list(baseline.keywords),
    )  # fmt: skip

    # --- discovery (multi-stream, each degrades independently) ---------------------------------
    st = _StageTimer(session, job_id, "discovery")
    stream_results: list[streams.StreamResult] = []
    if hits is None:
        officials = list(baseline.official_domains)
        official_set = set(officials) | set(baseline.registrable_domains)
        # an automatic run does exactly the tasks chosen for it; a scan started by hand follows the track
        tasks = (job.payload or {}).get("tasks")
        if tasks is not None:
            enabled = [x for x in ("dnstwist", "ct", "nrd", "search", "urlscan") if x in tasks]
        else:
            enabled = [
                x for x in cfg.detection.streams if x in streams.STREAMS and x != "meta_ads"
            ] or ["dnstwist"]
        shop = ctx.extra["shop"]
        if shop["retail"] and (tasks is None or "meta_ads" in tasks):  # follows the brand kind, not the track
            enabled.append("meta_ads")
        if tasks is not None and (job.payload or {}).get("scheduled"):
            summary.step(f"Automatic scan · {(job.payload or {}).get('schedule') or 'scheduled'}",
                         "tasks: " + ", ".join(tasks) if tasks else "no tasks")  # fmt: skip
        elif tasks is not None:  # "scan now, only …" from the brand page
            summary.step(f"Scan of one part · {(job.payload or {}).get('only') or ', '.join(tasks)}",
                         "only: " + ", ".join(tasks) + " — the other parts of the track do not run")  # fmt: skip
        ad_keywords = list(shop["profile"].get("ad_keywords") or []) or [brand.search_name.lower()]
        ad_countries = (
            [c.upper() for c in shop["profile"].get("countries") or []]
            or [g.strip().upper() for g in cfg.detection.search_geo.split(",") if g.strip()]
            or ["US"]
        )
        if "meta_ads" in enabled and not shop["profile"].get("countries"):
            # nobody said where the brand sells: the ads are searched only in the search country
            em.emit("discovery", "meta_ads", "pending",
                    f"No countries in the brand profile: Facebook / Instagram ads are searched only in {', '.join(ad_countries)}",
                    level="warn",
                    data={"alert": {"kind": "profile", "provider": "brand profile",
                                    "title": f"Ads are searched only in {', '.join(ad_countries)} — no countries in the brand profile",
                                    "fix": "Meta's Ad Library is searched country by country. Add the countries where the brand "
                                           "sells (e.g. IL) and the ad keywords in the brand profile — scam shops advertise "
                                           "locally, in the local language.",
                                    "settings_url": f"/ui/brands/{brand.id}#profile"}})  # fmt: skip
            summary.step(f"Facebook / Instagram ads searched only in {', '.join(ad_countries)}",
                         "no countries in the brand profile — add them so the ads of each country are searched")
        protected_hosts = set(
            whitelist_for(baseline.whitelist_domains or baseline.official_domains)
        )
        cap = visit_cap(max_candidates, cfg)
        # Google runs only with the list an analyst approved; the AI's list is a proposal until then
        qstate = search_queries_mod.query_state(brand, cfg.detection, baseline)
        search_queries = (qstate.queries or [brand.search_name])[: cfg.detection.search_queries_max]
        search_pairs = markets_mod.pairs(cfg.detection.search_geo, cfg.detection.search_lang, cfg.detection.search_markets)
        geos = markets_mod.countries(search_pairs)
        lexicon = discovery_lexicon(baseline)
        resolver = None if settings.demo_mode else streams.dns_registered
        for name in enabled:
            title, detail = STREAM_NOW.get(name, (f"Stream {name}", ""))

            if name == "meta_ads":
                detail = (f"Ads in {', '.join(ad_countries)} for: " + " · ".join(ad_keywords[:6])
                          + " — only ads about the brand count (its name, a product, or its words next to what it "
                          "sells); the shops they link to are checked next, authorised retailers skipped")  # fmt: skip
            if name == "search":
                detail = (
                    f"Google top results in {markets_mod.describe(search_pairs)} "
                    f"· {len(search_queries)} approved queries: "
                    + " · ".join(search_queries[:8])
                    + (" …" if len(search_queries) > 8 else "")
                ) if qstate.approved else qstate.waiting_note()
            em.running("discovery", name, f"Stream {name}: searching for {baseline.brand_key} …",
                       data=_now(title, detail.format(officials=", ".join(officials[:3]), key=baseline.brand_key,
                                                      brand=brand.name, geo=cfg.detection.search_geo,
                                                      lang=cfg.detection.search_lang,
                                                      tlds=len(discovery.TLD_SETS.get(cfg.detection.tlds, ()))), icon=name))  # fmt: skip
            try:
                if name == "dnstwist":
                    on_generated, on_progress = _dnstwist_callbacks(em)
                    r = await streams.stream_dnstwist(
                        officials, tlds=cfg.detection.tlds, max_hits=cap,
                        dictionary=lexicon, resolver=resolver,
                        max_checks=max_names or cfg.detection.max_names_checked,
                        on_generated=on_generated, on_progress=on_progress,
                        should_stop=lambda: cancel_requested(session, job_id),
                        aliases=streams.short_label_aliases(officials, baseline.brand_key),
                    )  # fmt: skip
                elif name == "ct":
                    r = await streams.stream_ct(providers, baseline.brand_key, official_set)
                elif name == "nrd":
                    r = await streams.stream_nrd(
                        settings.nrd_feed_path,
                        baseline.brand_key,
                        official_set,
                        max_hits=cap,
                        cache_dir=settings.evidence_dir,
                    )
                elif name == "search" and not qstate.approved:
                    r = streams.StreamResult("search", degraded=True, note=qstate.waiting_note())
                elif name == "search":
                    r = await streams.stream_search(
                        providers,
                        brand.search_name,
                        official_set,
                        geo=geos[0],
                        lang=search_pairs[0][1],
                        queries=search_queries,
                        geos=geos,
                        markets=search_pairs,
                        brand_key=baseline.brand_key,
                        on_query=_search_narrator(em),
                        official_apps=baseline.official_apps,
                    )
                elif name == "meta_ads":
                    ads_cfg = ad_settings.settings(shop["profile"])
                    r = await streams.stream_meta_ads(
                        providers, ad_keywords, ad_countries, official_set | protected_hosts,
                        terms=shop.get("terms"), max_queries=ads_cfg["ad_searches_max"],
                        ads_per_search=ads_cfg["ads_per_search"], on_query=_ads_narrator(em),
                    )  # fmt: skip
                    shop["ads_by_host"] = dict(r.ads_by_host)
                else:
                    r = await streams.stream_urlscan(providers, baseline.brand_key, official_set)
            except Exception as exc:  # noqa: BLE001 - a stream must never kill discovery
                r = streams.StreamResult(name, degraded=True, note=f"{type(exc).__name__}: {exc}")
            stream_results.append(r)
            _flush_issues(providers, em, issues_seen)
            if getattr(r, "dns_broken", False) and ("dns", "network") not in issues_seen:
                issues_seen[("dns", "network")] = 1
                em.emit("provider", "dns", "skipped",
                        "DNS is not answering — the look-alike check was stopped instead of reporting a false 0",
                        level="error",
                        data={"alert": {"kind": "network", "provider": "dns",
                                        "title": "DNS is not answering on this machine",
                                        "fix": "Look-alike names could not be checked, so they were not reported as free. "
                                               "Check the network / VPN (a disconnected VPN adapter often leaves a dead DNS "
                                               "server first in the list), then run the scan again.",
                                        "error": r.note, "retry_after": None, "settings_url": "/ui/settings"}})  # fmt: skip
            if cancel_requested(session, job_id):
                return _finish_cancelled(session, em, job, summary, "during discovery")
            _remember_origins(origins, name, r)
            _report_stream(summary, name, r, officials=officials, key=baseline.brand_key,
                           queries=ad_keywords if name == "meta_ads" else search_queries,
                           geos=ad_countries if name == "meta_ads" else geos, lexicon=lexicon)  # fmt: skip
            if r.degraded and name == "search" and not qstate.approved:
                em.emit("discovery", name, "skipped",
                        f"Google search skipped: {len(qstate.proposal)} proposed queries wait for your approval",
                        level="warn",
                        data={**_now("Google search: waiting for your approval", r.note, icon=name,
                                     items=[{"label": q, "tag": "proposed"} for q in qstate.proposal[:12]]),
                              "alert": {"kind": "approval", "provider": "google",
                                        "title": "Google search waits for your approval of its queries",
                                        "fix": r.note, "settings_url": f"/ui/brands/{brand.id}#queries"}})  # fmt: skip
            elif r.degraded:
                em.emit(
                    "discovery",
                    name,
                    "skipped",
                    f"Stream {name} degraded: {r.note}",
                    level="warn",
                    data=_now(f"{STREAM_NOW.get(name, (name,))[0]}: skipped", r.note, icon=name),
                )
            else:
                items = r.seen or _hit_items(r.hits)
                if name == "nrd":
                    title = (f"{STREAM_NOW['nrd'][0]}: {r.generated:,} registered yesterday, "
                             f"{r.checked:,} checked, {len(r.hits)} look-alike(s)")  # fmt: skip
                elif name == "dnstwist":
                    denom = r.checked or r.generated or len(items)
                    title = (f"{STREAM_NOW.get(name, (name,))[0]}: {len(r.hits)} registered of "
                             f"{denom:,} {'checked' if r.checked else 'generated'}")  # fmt: skip
                elif name == "meta_ads":
                    title = (f"{STREAM_NOW['meta_ads'][0]}: {len(r.hits)} shop(s) to check from "
                             f"{len(r.seen)} ad(s)"
                             + (f" · {r.not_about_brand} not about the brand" if r.not_about_brand else ""))  # fmt: skip
                elif name == "search":
                    title = (f"{STREAM_NOW.get(name, (name,))[0]}: {len(r.hits)} of "
                             f"{max(len(items), len(r.hits))} results queued for a visit")  # fmt: skip
                elif r.seen:
                    title = (f"{STREAM_NOW.get(name, (name,))[0]}: {len(r.hits)} suspicious of "
                             f"{max(len(items), len(r.hits))} looked at")  # fmt: skip
                else:
                    title = f"{STREAM_NOW.get(name, (name,))[0]}: {len(r.hits)} registered look-alike(s)"
                em.done(
                    "discovery",
                    name,
                    f"Stream {name}: {len(r.hits)} hit(s)"
                    + (f" — {r.note}" if name == "nrd" and r.note else ""),
                    counts={"hits": len(r.hits)},
                    data=_now(title, r.note if name == "nrd" else None, items, icon=name),
                )
        # social media: Facebook pages / Instagram profiles under the brand's name (every brand, when
        # the SearchApi key is set; recorded accounts in demo mode)
        social_hits: list[DiscoveryHit] = []
        social_on = ("social" in tasks) if tasks is not None else cfg.detection.social_accounts
        if social_on and (settings.demo_mode or not providers.uses_mock("searchapi")):
            social_hits = await _social_step(ctx, brand, baseline, store, summary, geos)
            _flush_issues(providers, em, issues_seen)
            for h in social_hits:
                origins[h.raw_value] = h.matched_pattern.replace("social: ", "") if h.matched_pattern else "a fake social account"
            if cancel_requested(session, job_id):
                return _finish_cancelled(session, em, job, summary, "during the social media check")
        # sites a fake social account links to and shops advertised with the brand's products first
        # (the most targeted hits), dnstwist last (the broadest/cheapest) so the visit cap keeps the rarer hits
        ordered = sorted(stream_results, key=lambda r: (r.stream != "meta_ads", r.stream == "dnstwist"))
        hit_list = streams.merge_hits(ordered, max_total=cap)
        if social_hits:  # sites a fake account sends people to, unless a stream already found them: first in line
            have = {streams._host_of(h.raw_value) for h in hit_list}
            extra = [h for h in social_hits if streams._host_of(h.raw_value) not in have]
            hit_list = (extra + hit_list)[: cap or None]
    else:
        hit_list = list(hits)
        em.running("discovery", "manual", f"{len(hit_list)} analyst-supplied target(s)")
        summary.step(f"Took {len(hit_list)} analyst-supplied target(s)", None, _hit_items(hit_list))
    summary.hits = len(hit_list)
    st.finish(hits=len(hit_list), api_calls=sum(r.api_calls for r in stream_results))
    em.done(
        "discovery",
        "merge",
        f"{len(hit_list)} candidate name(s) after merging streams",
        counts={"hits": len(hit_list), "streams": {r.stream: len(r.hits) for r in stream_results}},
        data=_now(
            f"{len(hit_list)} suspicious names to examine",
            " · ".join(f"{r.stream} {len(r.hits)}" for r in stream_results) or None,
            _hit_items(hit_list),
            icon="merge",
        ),
    )

    # --- normalize / dedup / pre-filter ---------------------------------------------------------
    st = _StageTimer(session, job_id, "normalize_dedup_prefilter")
    wl = whitelist_for(baseline.whitelist_domains or baseline.official_domains)
    from brandwatch.detection.protect import dismiss_protected

    if cleaned := dismiss_protected(session, brand.id):  # rows from before a domain was whitelisted
        trace.log("dedup", f"took the brand's own / whitelisted sites off the watchlist: {cleaned}")
    to_process: list[Candidate] = []
    hosts_this_scan: set[str] = set()
    platform_skipped: list[str] = []
    same_host_skipped: list[str] = []
    family_skipped: list[tuple[str, str]] = []
    for hit in hit_list:
        norm = normalize(hit)
        if norm is None:
            continue
        if not pre_filter(norm.hostname, wl).keep:
            summary.whitelisted += 1
            continue
        if is_known_platform(norm.hostname):  # a YouTube video about the brand is not a kit
            platform_skipped.append(norm.hostname)
            trace.log("dedup", f"skip {norm.hostname}: well-known platform", url=hit.raw_value)
            continue
        if norm.hostname in hosts_this_scan and not (
            is_shared_hosting(norm.hostname) or is_app_store(norm.hostname)
        ):
            same_host_skipped.append(norm.hostname)  # one visit per host per scan is enough
            trace.log("dedup", f"skip {hit.raw_value}: host already queued this scan")
            continue
        other = regions_mod.tracked_elsewhere(session, brand.id, norm.canonical_url)
        if other is not None:  # one suspect, one finding per brand family
            family_skipped.append((norm.hostname, other.region or other.name))
            trace.log("dedup", f"skip {hit.raw_value}: already tracked by {other.name}")
            continue
        hosts_this_scan.add(norm.hostname)
        dd = deduplicate(session, brand.id, norm)
        if dd.is_new:
            summary.new_candidates += 1
        else:
            summary.existing_candidates += 1
        cand = session.get(Candidate, dd.candidate_id)
        trace.log("dedup", f"{'new' if dd.is_new else 'known'} candidate {norm.hostname}",
                  url=hit.raw_value, source=hit.source.value, surface=norm.surface.value if hasattr(norm, "surface") else None,
                  state=cand.state.value if cand else None, matched=hit.matched_pattern)  # fmt: skip
        if cand is not None and cand.state is not CandidateState.DISMISSED:
            to_process.append(cand)
    session.flush()
    limit = visit_cap(max_candidates, cfg)
    if len(to_process) > limit:
        trace.log("dedup", f"visit cap {limit}: {len(to_process) - limit} candidate(s) left for the next scan",
                  skipped=[c.hostname for c in to_process[limit:]])  # fmt: skip
        summary.step(f"Visit cap: {limit} site(s) per scan",
                     f"{len(to_process) - limit} more candidate(s) were found and stay on the list for the next scan "
                     "(change the cap on the brand page or in Settings → Workspace & budget)")  # fmt: skip
        to_process = to_process[:limit]
    st.finish(hits=len(to_process))
    if family_skipped:
        summary.step(f"{len(family_skipped)} site(s) already tracked by another regional campaign of this brand",
                     "one suspect, one finding per brand family — it is handled where it was found first",
                     [{"label": h, "tag": f"tracked by {r}"} for h, r in family_skipped[:30]])  # fmt: skip
    summary.step(
        f"Selected {len(to_process)} candidate(s) to visit",
        f"{summary.new_candidates} new, {summary.existing_candidates} already known; skipped "
        f"{len(platform_skipped)} on well-known platforms (YouTube, social …), "
        f"{len(same_host_skipped)} extra URL(s) on hosts already queued, {summary.whitelisted} whitelisted",
        [{"label": c.hostname, "tag": c.surface.value} for c in to_process],
    )
    em.done(
        "deduplicate", "identity",
        f"{summary.new_candidates} new, {summary.existing_candidates} known, {summary.whitelisted} whitelisted, "
        f"{len(platform_skipped)} on well-known platforms, {len(same_host_skipped)} same-host duplicates",
        counts={"new": summary.new_candidates, "existing": summary.existing_candidates, "whitelisted": summary.whitelisted,
                "platforms": len(platform_skipped), "same_host": len(same_host_skipped)},
        data=_now(f"{len(to_process)} candidate(s) will be visited",
                  (f"skipped: {', '.join(sorted(set(platform_skipped)))} (well-known platforms)" if platform_skipped else "")
                  + (f" · {len(same_host_skipped)} extra URL(s) on hosts already queued" if same_host_skipped else "") or None,
                  [{"label": c.hostname, "tag": c.surface.value} for c in to_process], icon="merge"),
    )  # fmt: skip

    # --- per-candidate pipeline ------------------------------------------------------------------
    st = _StageTimer(session, job_id, "enrichment_analysis_scoring")
    total = len(to_process)
    handled: set[uuid.UUID] = set()
    for i, cand in enumerate(to_process, 1):
        total = len(to_process)  # redirect destinations are appended while the loop runs
        if cancel_requested(session, job_id):
            return _finish_cancelled(
                session, em, job, summary, f"after {i - 1} of {total} candidates"
            )
        why = _origin_of(origins, cand)
        em.running(
            "pipeline",
            cand.hostname,
            f"Processing {cand.canonical_url}" + (f" — {why}" if why else ""),
            progress={"current": i, "total": total},
            data=_now(
                f"Candidate {i} of {total}: {cand.canonical_url}", why or None, icon="enrich"
            ),
        )
        try:  # one candidate must never kill the scan
            out = await process_candidate(ctx, cand, baseline, store)
            session.commit()
        except Exception as exc:  # noqa: BLE001
            # roll back only this candidate's uncommitted tail: every event and evidence row
            # written before the failure was already committed (live console, short DB locks)
            session.rollback()
            out = CandidateOutcome(
                cand.id, cand.hostname, "error", error=f"{type(exc).__name__}: {exc}"
            )
            em.error("pipeline", cand.hostname, f"{cand.hostname}: {out.error}")
        handled.add(cand.id)
        for tgt in ctx.extra.pop("redirect_targets", []):
            _queue_redirect(session, brand, wl, tgt, ctx=ctx, to_process=to_process, hosts_this_scan=hosts_this_scan,
                            handled=handled, origins=origins, summary=summary)  # fmt: skip
        summary.outcomes.append(out)
        summary.processed += 1
        if out.disposition == "finding":
            summary.findings += 1
            if out.severity is Severity.CRITICAL:
                summary.criticals += 1
        elif out.disposition == "watch":
            summary.watching += 1
        elif out.disposition == "dismissed":
            summary.dismissed += 1
        else:
            summary.errors += 1
        session.flush()
        _flush_issues(providers, em, issues_seen)
    if summary.redirected:
        summary.step(f"{len(summary.redirected)} site(s) reached through a flagged look-alike's redirect",
                     "a site rated High forwards its visitors to another address that carries the brand: the address is part of the same operation, "
                     "so it was checked too (beyond the visit cap) and carries the verdict of the site that sends visitors to it. "
                     "If it is the brand's own site, add it under the official domains and both stop being flagged.",
                     summary.redirected)  # fmt: skip
    usage = session.execute(
        sa.select(
            sa.func.coalesce(sa.func.sum(ApiUsage.calls), 0),
            sa.func.coalesce(sa.func.sum(ApiUsage.cost_usd), 0),
        ).where(ApiUsage.job_id == job_id)
    ).one()
    st.finish(hits=summary.findings, api_calls=int(usage[0]), cost_usd=float(usage[1]))

    _report_outcomes(summary, ctx, issues_seen)

    # --- finish ----------------------------------------------------------------------------------
    summary.duration_ms = int((time.monotonic() - t0) * 1000)
    job.state = JobState.DONE
    job.finished_at = utcnow()
    job.cost_usd = Decimal(str(round(float(usage[1]), 4)))
    session.flush()
    trace.section("SUMMARY")
    trace.log("summary", "scan finished", **summary.as_dict(), api_calls=int(usage[0]), cost_usd=float(usage[1]),
              issues={f"{p}:{k}": n for (p, k), n in issues_seen.items()})  # fmt: skip
    em.done(
        "summary", "scan",
        f"Scan finished: {summary.findings} finding(s) ({summary.criticals} critical), "
        f"{summary.watching} on watchlist, {summary.dismissed} dead, {summary.errors} error(s)",
        counts={"hits": summary.hits, "findings": summary.findings, "api_calls": int(usage[0]), "cost_usd": float(usage[1])},
        data={**summary.as_dict(), "api_calls": int(usage[0]), "cost_usd": float(usage[1]), "next_run": None,
              "issues": {f"{p}:{k}": n for (p, k), n in issues_seen.items()},
              **_now("Scan finished", f"{summary.findings} finding(s), {summary.criticals} critical · "
                     f"{summary.watching} on the watchlist · {len(issues_seen)} provider issue(s)", icon="done")},
    )  # fmt: skip
    return summary


def brand_scan_handler(session: Session, job_id: uuid.UUID) -> None:
    """Job-queue handler (sync) for kind ``brand_scan``; payload may carry ``max_candidates``."""
    job = session.get(ScanJob, job_id)
    cap = (job.payload or {}).get("max_candidates") if job else None
    asyncio.run(run_scan(session, job_id, max_candidates=int(cap) if cap else None))


def url_scan_handler(session: Session, job_id: uuid.UUID) -> None:
    """Job-queue handler for kind ``url_scan``: payload {"urls": [...]}."""
    job = session.get(ScanJob, job_id)
    urls = (job.payload or {}).get("urls", []) if job else []
    asyncio.run(run_scan(session, job_id, hits=manual_hits(urls)))


HANDLERS = {"brand_scan": brand_scan_handler, "url_scan": url_scan_handler}


def handlers_for(
    settings: Settings, store: EvidenceStore, notifier: NotificationService | None = None
) -> dict[str, Any]:
    """Job handlers bound to the application's Settings and evidence store (the API uses this so
    the job thread writes artifacts exactly where the request handlers read them)."""

    def brand_scan(session: Session, job_id: uuid.UUID) -> None:
        job = session.get(ScanJob, job_id)
        payload = (job.payload or {}) if job else {}
        cap, names = payload.get("max_candidates"), payload.get("max_names")
        asyncio.run(
            run_scan(
                session,
                job_id,
                settings=settings,
                store=store,
                max_candidates=int(cap) if cap else None,
                max_names=int(names) if names else None,
                notifier=notifier,
            )
        )

    def url_scan(session: Session, job_id: uuid.UUID) -> None:
        job = session.get(ScanJob, job_id)
        urls = (job.payload or {}).get("urls", []) if job else []
        asyncio.run(
            run_scan(
                session,
                job_id,
                settings=settings,
                store=store,
                hits=manual_hits(urls),
                notifier=notifier,
            )
        )

    return {
        "brand_scan": brand_scan,
        "url_scan": url_scan,
        "investigate": investigate_handler_for(settings, store),
        "intel": intel_handler_for(settings, store),
        "map_all": map_all_handler_for(settings, store),
    }


def map_all_handler_for(settings: Settings, store: EvidenceStore):
    """``map_all``: the attack-infrastructure map of every confirmed site the analyst asked for, one after the other (a batch of
    maps at once would fight for the same providers and the database). Each site gets an ordinary ``investigate`` job of its own,
    so its row on the Attack infrastructure page, its console and its campaign are the same as when it is mapped by hand."""

    def handler(session: Session, job_id: uuid.UUID) -> None:
        from brandwatch.jobs.queue import create_job, mark_failed

        job = session.get(ScanJob, job_id)
        payload = job.payload or {}
        ids = [uuid.UUID(x) for x in payload.get("finding_ids", [])]
        job.state = JobState.RUNNING
        job.started_at = utcnow()
        session.commit()
        em = ScanEventEmitter(session, job_id, secrets=settings.known_secret_values(), commit=True)
        em.running("map_all", "batch", f"Mapping {len(ids)} confirmed site(s), one by one …", progress={"current": 0, "total": len(ids)})
        mapped = failed = 0
        for i, fid in enumerate(ids, 1):
            if cancel_requested(session, job_id):
                em.done("summary", "map_all", f"Stopped after {mapped} of {len(ids)}", level="warn")
                return
            f = session.get(Finding, fid)
            cand = session.get(Candidate, f.candidate_id) if f is not None else None
            if f is None or cand is None or f.state is not FindingState.CONFIRMED:
                continue
            host = cand.hostname
            em.running("map_all", host, f"Mapping {i} of {len(ids)}: {host} …", progress={"current": i - 1, "total": len(ids)})
            child = create_job(session, "investigate", {"finding_id": str(fid), "requested_by": payload.get("requested_by"), "auto": True,
                                                        "batch": str(job_id)}, workspace_id=job.workspace_id, brand_id=f.brand_id)  # fmt: skip
            session.commit()
            try:
                res = asyncio.run(run_investigation(session, child.id, fid, settings=settings, store=store))
                session.commit()
                mapped += 1
                em.done("map_all", host, f"Mapped {host}: {res.nodes} node(s), {res.edges} edge(s)", progress={"current": i, "total": len(ids)},
                        data={"campaign_id": str(res.campaign_id), "job_id": str(child.id)})  # fmt: skip
            except Exception as exc:  # noqa: BLE001 - one site that cannot be mapped must not stop the others
                session.rollback()
                mark_failed(session, child.id, f"{type(exc).__name__}: {exc}")
                session.commit()
                failed += 1
                em.error("map_all", host, f"{host} could not be mapped: {type(exc).__name__}: {str(exc)[:160]}")
        job = session.get(ScanJob, job_id)
        job.state = JobState.DONE
        job.finished_at = utcnow()
        session.commit()
        em.done("summary", "map_all", f"Mapped {mapped} of {len(ids)} confirmed site(s)" + (f", {failed} failed" if failed else ""),
                data={"mapped": mapped, "failed": failed, "total": len(ids)})  # fmt: skip

    return handler


def intel_handler_for(settings: Settings, store: EvidenceStore):
    from brandwatch.detection.intel import intel_handler_for as _mk

    return _mk(settings, store)


def investigate_handler_for(settings: Settings, store: EvidenceStore):
    def investigate(session: Session, job_id: uuid.UUID) -> None:
        job = session.get(ScanJob, job_id)
        finding_id = uuid.UUID((job.payload or {})["finding_id"])
        asyncio.run(run_investigation(session, job_id, finding_id, settings=settings, store=store))

    return investigate
