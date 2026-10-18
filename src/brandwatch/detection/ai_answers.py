"""What AI assistants tell users about the brand's contacts — and whether it is true.

People ask ChatGPT, Gemini or Google's AI Mode "what is the support phone of <brand>?" and call the
number they get. When the assistant makes a number up (a hallucination) or repeats one a scam page
published, the caller reaches a stranger — and a made-up number is one a scammer can claim tomorrow.

One run, per brand (``detection.ai_answers`` on, prompts approved, the SearchApi key set):

1. **Ask** every approved prompt (``ai_prompts.py``) to every chosen engine, as a user would.
2. **Extract** every phone, short code, e-mail, WhatsApp number and web address from the answers
   (``contacts.py``) and compare them with the brand's official contacts — the ones read from its own
   website plus the ones an analyst added. A contact that is not there is a *suspect*.
3. **Ask for the proof** (at most two follow-ups per suspect): "show me the official page where it
   appears — I suspect it is a fraud". Google AI Mode continues the same conversation.
4. **Check the pages ourselves** — never the engine's word: every page the engines cite is opened
   (through the SSRF guard) and searched for the contact; one Google search of the contact itself
   lists who else publishes it.
5. **Classify** — ``confirmed_official`` (an official page does list it: the crawl missed it, nothing
   is raised), ``offsite`` (only a page that is not the brand's carries it), ``hallucinated`` (no page
   carries it, or the engine took it back), ``url_not_official`` (the answer sends users to a look-alike
   or a known phishing site).
6. **Record** one finding of kind ``ai_answer`` per suspect contact, with the transcripts as immutable
   evidence, on a separate ``aianswer-v1`` score.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from types import SimpleNamespace
from typing import Any
from urllib.parse import urlsplit

import sqlalchemy as sa
from sqlalchemy.orm import Session

from brandwatch import __version__
from brandwatch.db.enums import (
    CandidateState,
    DiscoverySource,
    EvidenceType,
    ScannerProfile,
    Severity,
    Surface,
)
from brandwatch.db.models import Candidate, CandidateSource, Evidence, Finding, Observation
from brandwatch.detection import ai_prompts, contacts
from brandwatch.detection.discovery import split_host
from brandwatch.detection.normalize import is_app_store, is_known_platform
from brandwatch.pipeline.stages import AnalysisResult, RiskResult

# ------------------------------------------------------------------------------------ catalogue
AI_SIGNALS: dict[str, tuple[int, str]] = {
    "ai_contact_not_on_site": (40, "identity"),
    "ai_url_not_official": (40, "identity"),
    "ai_known_suspect": (40, "reputation"),
    "ai_offsite_lookalike": (30, "infrastructure"),
    "ai_offsite_page": (20, "infrastructure"),
    "ai_retracted": (15, "evidence"),
    "ai_cited_page_missing": (15, "evidence"),
    "ai_several_engines": (15, "breadth"),
    "ai_no_source": (10, "evidence"),
}
AI_RAW_MAX = 100
AI_GROUPS: dict[str, str] = {k: g for k, (_p, g) in AI_SIGNALS.items()}
AI_SCORING_VERSION = "aianswer-v1-" + hashlib.sha256(json.dumps({"s": AI_SIGNALS, "m": AI_RAW_MAX}, sort_keys=True).encode()).hexdigest()[:8]
ENGINE_LABEL = {"chatgpt": "ChatGPT", "gemini": "Gemini", "google_ai_mode": "Google AI Mode"}
VERDICT_LABEL = {
    "hallucinated": "made up — no page publishes it",
    "offsite": "published off the brand's website",
    "url_not_official": "sends users to a site that is not the brand's",
    "confirmed_official": "on an official page (the crawl had missed it)",
}
COLLECTOR = "brandwatch.ai_answers"
MAX_SUSPECTS = 10
FOLLOWUPS_PER_SUSPECT = 2
CHECKS_PER_SUSPECT = 5
HUNT_RESULTS = 5
GOOGLE_HL = {"he": "iw"}  # Google's own code for Hebrew


@dataclass
class Said:
    engine: str
    prompt: str
    topic: str
    lang: str
    answer: str
    references: list[dict[str, Any]]
    token: str | None = None


@dataclass
class Suspect:
    kind: str  # phone | star | email | whatsapp | url
    value: str
    display: str
    said: list[Said] = field(default_factory=list)
    followups: list[dict[str, Any]] = field(default_factory=list)
    checks: list[dict[str, Any]] = field(default_factory=list)
    hunt: list[dict[str, Any]] = field(default_factory=list)
    verdict: str = ""
    fired: dict[str, str] = field(default_factory=dict)
    score: dict[str, Any] = field(default_factory=dict)

    @property
    def key(self) -> str:
        return contacts.contact_key(self.kind, self.value) if self.kind != "url" else f"url:{self.value}"

    @property
    def engines(self) -> list[str]:
        return list(dict.fromkeys(s.engine for s in self.said))

    @property
    def canonical_url(self) -> str:
        return f"ai-answer://{'phone' if self.kind == 'whatsapp' else self.kind}/{self.value}"

    def record(self) -> dict[str, Any]:
        return {
            "kind": self.kind, "value": self.value, "display": self.display, "verdict": self.verdict,
            "verdict_label": VERDICT_LABEL.get(self.verdict, self.verdict), "engines": self.engines,
            "said": [{"engine": s.engine, "prompt": s.prompt, "topic": s.topic, "lang": s.lang, "answer": s.answer,
                      "references": s.references} for s in self.said],
            "followups": self.followups, "checks": self.checks, "hunt": self.hunt, "why": self.fired,
            "score": self.score.get("score"), "severity": getattr(self.score.get("severity"), "value", None),
            "scoring_version": AI_SCORING_VERSION,
        }  # fmt: skip


@dataclass
class AiRun:
    transcripts: list[dict[str, Any]] = field(default_factory=list)
    suspects: list[Suspect] = field(default_factory=list)
    matched: dict[str, list[str]] = field(default_factory=dict)  # official contact → engines that gave it
    api_calls: int = 0
    errors: list[str] = field(default_factory=list)
    skipped_suspects: int = 0


# ------------------------------------------------------------------------------------ scoring
def score(fired: dict[str, str], *, thresholds: dict[str, int], verdict: str, checks: int) -> dict[str, Any]:
    pts = {k: float(AI_SIGNALS[k][0]) for k in fired if k in AI_SIGNALS}
    raw = max(0, min(AI_RAW_MAX, int(sum(pts.values()))))
    sc = round(raw / AI_RAW_MAX * 100)
    floor = None
    if "ai_known_suspect" in fired or "ai_offsite_lookalike" in fired:
        floor = Severity.CRITICAL
    elif verdict in ("hallucinated", "url_not_official"):
        floor = Severity.HIGH
    sev = (Severity.CRITICAL if sc >= thresholds["critical"] else Severity.HIGH if sc >= thresholds["high"]
           else Severity.MEDIUM if sc >= thresholds["medium"] else Severity.LOW)  # fmt: skip
    rules = []
    order = [Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
    if floor and order.index(floor) > order.index(sev):
        rules.append({"rule": f"ai_{verdict}_floor", "min_severity": floor.value})
        sev = floor
        sc = max(sc, {Severity.HIGH: thresholds["high"], Severity.CRITICAL: thresholds["critical"]}[floor])
    groups: dict[str, float] = {}
    for k, v in pts.items():
        groups[AI_GROUPS[k]] = groups.get(AI_GROUPS[k], 0) + v
    breadth = {0: 0, 1: 30, 2: 50, 3: 65}.get(len(fired), 75)
    confidence = max(0.0, min(100.0, breadth + 5 * min(checks, 4)))
    return {
        "raw": raw, "score": sc, "severity": sev, "signals": pts, "groups": groups, "confidence": confidence,
        "breakdown": {
            "kind": "ai_answer", "raw_max": AI_RAW_MAX, "thresholds": thresholds, "penalties": [], "bonuses": [],
            "combination_rules_fired": rules,
            "group_detail": {g: {"total": t, "cap": AI_RAW_MAX, "capped": t} for g, t in groups.items()},
            "confidence": {"breadth": breadth, "groups_fired": sorted(groups), "hard_confirmers": [], "hard_confirmer_points": 0,
                           "evidence_completeness": 5 * min(checks, 4), "provider_agreement": 0, "unavailable": [],
                           "unavailable_penalty": 0, "single_weak_signal_penalty": 0},
        },
    }  # fmt: skip


# ------------------------------------------------------------------------------------ the run
def _registrable(host: str) -> str:
    return split_host(host).registrable or host


async def _page(providers: Any, url: str) -> str | None:
    try:
        res = await providers.browser().peek(url)
        html = (res.data or {}).get("html") if res.ok else None
    except Exception:  # noqa: BLE001
        html = None
    if not html or len(contacts.visible_text(html)) < 200:
        try:
            res = await providers.browser().fetch(url, profile="datacenter")
            html = (res.data or {}).get("html") if res.ok else html
        except Exception:  # noqa: BLE001
            pass
    return html


async def run(providers: Any, *, brand_name: str, brand_key: str, prompts: list[dict[str, str]], engines: list[str],
              detection: Any, known: set[str], cc: str, official: set[str], suspect_hosts: dict[str, str],
              thresholds: dict[str, int], on_event: Any = None) -> AiRun:  # fmt: skip
    """Ask, extract, compare, ask for the proof, check the pages, classify (see the module docstring)."""
    say = on_event or (lambda *a, **k: None)
    out = AiRun()
    official_reg = {_registrable(d) for d in official} | {d.lower() for d in official}
    suspects: dict[str, Suspect] = {}

    def is_official(host: str) -> bool:
        host = host.lower()
        return host in official_reg or _registrable(host) in official_reg

    # 1 · ask, extract, compare
    for p in prompts:
        lang = p.get("lang") or "en"
        gl = ai_prompts.market_of(detection, lang)
        for engine in engines:
            say("ask", engine, p["text"])
            try:
                res = await providers.ai_answers().ask(engine, p["text"], gl=gl, hl=GOOGLE_HL.get(lang, lang))
            except Exception as exc:  # noqa: BLE001 - one engine down is not the end of the run
                out.errors.append(f"{ENGINE_LABEL.get(engine, engine)}: {type(exc).__name__}: {exc}"[:200])
                continue
            out.api_calls += 1
            if not res.ok or not res.data:
                out.errors.append(f"{ENGINE_LABEL.get(engine, engine)}: {res.error or 'no answer'}"[:200])
                continue
            d = res.data
            answer, refs = str(d.get("answer") or ""), list(d.get("references") or [])
            found = contacts.from_text(answer, cc=cc)
            bad: list[str] = []
            for f in found:
                key = contacts.contact_key(f.kind, f.value)
                if key in known:
                    out.matched.setdefault(key, [])
                    if engine not in out.matched[key]:
                        out.matched[key].append(engine)
                    continue
                s = suspects.setdefault(key, Suspect(f.kind, f.value, f.display))
                s.said.append(Said(engine, p["text"], p.get("topic") or "custom", lang, answer, refs, d.get("conversation_token")))
                bad.append(f.display)
            for host in contacts.urls_in(answer):
                if is_official(host) or is_known_platform(host) or is_app_store(host):
                    continue
                reg = _registrable(host)
                label = suspect_hosts.get(host) or suspect_hosts.get(reg)
                lookalike = bool(brand_key) and len(brand_key) >= 4 and brand_key in (split_host(host).sld or "").replace("-", "")
                if not (label or lookalike):
                    continue  # an unrelated site mentioned in passing (a news article, a regulator) is not a suspect
                s = suspects.setdefault(f"url:{host}", Suspect("url", host, host))
                s.said.append(Said(engine, p["text"], p.get("topic") or "custom", lang, answer, refs, d.get("conversation_token")))
                bad.append(host)
            out.transcripts.append({"engine": engine, "prompt": p["text"], "topic": p.get("topic"), "lang": lang, "answer": answer,
                                    "references": refs, "contacts": [f.display for f in found], "suspects": bad,
                                    "model": d.get("model"), "web_search": d.get("web_search")})  # fmt: skip

    ranked = sorted(suspects.values(), key=lambda s: (-len(s.engines), s.kind == "star", s.value))
    out.skipped_suspects = max(0, len(ranked) - MAX_SUSPECTS)
    ranked = ranked[:MAX_SUSPECTS]

    # 2 · ask for the proof, then check every page ourselves
    for s in ranked:
        if s.kind != "url":
            per_engine = list({x.engine: x for x in reversed(s.said)}.values())[::-1]  # the first time each assistant said it
            for said in per_engine[:FOLLOWUPS_PER_SUSPECT]:
                q = ai_prompts.follow_up(said.lang, brand=brand_name, contact=s.display, kind=s.kind)
                say("followup", said.engine, q)
                try:
                    res = await providers.ai_answers().ask(said.engine, q, gl=ai_prompts.market_of(detection, said.lang),
                                                           hl=GOOGLE_HL.get(said.lang, said.lang),
                                                           conversation_token=said.token if said.engine == "google_ai_mode" else None)  # fmt: skip
                except Exception as exc:  # noqa: BLE001
                    s.followups.append({"engine": said.engine, "prompt": q, "answer": "", "references": [], "error": str(exc)[:160]})
                    continue
                out.api_calls += 1
                d = res.data or {}
                ans = str(d.get("answer") or "")
                s.followups.append({"engine": said.engine, "prompt": q, "answer": ans, "references": list(d.get("references") or []),
                                    "retracted": ai_prompts.retracted(ans), "still_gives_it": any(
                                        contacts.contact_key(f.kind, f.value) == s.key for f in contacts.from_text(ans, cc=cc))})  # fmt: skip
        urls: list[str] = []
        for fu in s.followups:
            urls += [r["link"] for r in fu.get("references") or [] if r.get("link")]
            urls += [f"https://{h}/" for h in contacts.urls_in(fu.get("answer") or "")]
        for said in s.said:
            urls += [r["link"] for r in said.references if r.get("link")]
        if s.kind == "url":
            urls = [f"https://{s.value}/"]
        for url in dict.fromkeys(u.split("#")[0] for u in urls):
            if len(s.checks) >= CHECKS_PER_SUSPECT:
                break
            host = (urlsplit(url).hostname or "").lower()
            if not host or urlsplit(url).scheme not in ("http", "https"):
                continue
            reg = _registrable(host)
            html = None if s.kind == "url" else await _page(providers, url)
            found = bool(html) and contacts.page_has(html, s.kind, s.value, cc=cc)
            off = is_official(host)
            s.checks.append({"url": url, "host": host, "official": off, "opened": html is not None or s.kind == "url",
                             "found": found, "lookalike": not off and bool(brand_key) and len(brand_key) >= 4 and brand_key in (split_host(host).sld or "").replace("-", ""),
                             "known": suspect_hosts.get(host) or suspect_hosts.get(reg)})  # fmt: skip
        if s.kind in ("phone", "email", "whatsapp") and not any(c["found"] for c in s.checks):
            try:
                res = await providers.search().search(f'"{s.display}"', geo=(ai_prompts.market_of(detection, s.said[0].lang) or "us"),
                                                      lang=s.said[0].lang)  # fmt: skip
                out.api_calls += 1
                for h in ((res.data or {}).get("hits") or [])[:HUNT_RESULTS] if res.ok else []:
                    host = (urlsplit(h.get("url") or "").hostname or "").lower()
                    if host:
                        s.hunt.append({"url": h.get("url"), "title": str(h.get("title") or "")[:160], "host": host, "official": is_official(host),
                                       "lookalike": not is_official(host) and bool(brand_key) and len(brand_key) >= 4 and brand_key in (split_host(host).sld or "").replace("-", ""),
                                       "known": suspect_hosts.get(host) or suspect_hosts.get(_registrable(host))})  # fmt: skip
            except Exception as exc:  # noqa: BLE001 - the hunt is extra evidence
                out.errors.append(f"search for {s.display}: {type(exc).__name__}"[:160])
        classify(s, brand_name=brand_name, thresholds=thresholds)
    out.suspects = ranked
    return out


def classify(s: Suspect, *, brand_name: str, thresholds: dict[str, int]) -> None:
    fired: dict[str, str] = {}
    engines = ", ".join(ENGINE_LABEL.get(e, e) for e in s.engines)
    on_official = [c for c in s.checks if c["official"] and c["found"]]
    offsite = [c for c in s.checks if not c["official"] and c["found"]] + [h for h in s.hunt if not h["official"]]
    if s.kind == "url":
        s.verdict = "url_not_official"
        fired["ai_url_not_official"] = f"{engines} sent users to {s.value}, which is not a site of {brand_name}"
        c = s.checks[0] if s.checks else {}
        if c.get("known"):
            fired["ai_known_suspect"] = f"{s.value} is {c['known']}"
        if c.get("lookalike"):
            fired["ai_offsite_lookalike"] = f"{s.value} carries the brand's name but is not one of its domains"
    elif on_official:
        s.verdict = "confirmed_official"  # the brand does publish it: nothing to raise
    else:
        what = contacts.KIND_LABEL.get(s.kind, s.kind)
        fired["ai_contact_not_on_site"] = f"{engines} gave the {what} {s.display} — it is on none of {brand_name}'s pages"
        cited = [c for c in s.checks if c.get("opened")]
        if cited and not offsite:
            fired["ai_cited_page_missing"] = f"{len(cited)} page(s) the AI cited were opened: none of them carries {s.display}"
        if not s.checks:
            fired["ai_no_source"] = "asked for the official page, the AI gave none"
        if any(fu.get("retracted") for fu in s.followups):
            fired["ai_retracted"] = "asked for the proof, the AI took it back"
        if offsite:
            s.verdict = "offsite"
            hosts = list(dict.fromkeys(x["host"] for x in offsite))
            fired["ai_offsite_page"] = f"{s.display} is published on {', '.join(hosts[:3])} — not a site of {brand_name}"
            look = [x["host"] for x in offsite if x.get("lookalike")]
            known = [f"{x['host']} ({x['known']})" for x in offsite if x.get("known")]
            if look:
                fired["ai_offsite_lookalike"] = f"{', '.join(dict.fromkeys(look))} carries the brand's name: a look-alike publishes the number"
            if known:
                fired["ai_known_suspect"] = "; ".join(dict.fromkeys(known))
        else:
            s.verdict = "hallucinated"
    if len(s.engines) >= 2:
        fired["ai_several_engines"] = f"{len(s.engines)} assistants give it: {engines}"
    s.fired = fired
    s.score = score(fired, thresholds=thresholds, verdict=s.verdict, checks=len(s.checks)) if s.verdict != "confirmed_official" else {}


# ------------------------------------------------------------------------------------ record
def record(session: Session, store: Any, *, workspace_id: uuid.UUID, brand_id: uuid.UUID, s: Suspect, cfg: Any,
           watch_cadence_hours: int, official_sample: list[str] | None = None) -> Any:  # fmt: skip
    """Candidate (address ``ai-answer://<kind>/<value>``) + the transcripts as immutable evidence + a finding of kind
    ``ai_answer``. Re-checked by the next AI-answers run, never by the URL re-scan."""
    from brandwatch.detection import finding as finding_stage

    cand = session.scalars(sa.select(Candidate).where(Candidate.brand_id == brand_id, Candidate.canonical_url == s.canonical_url)).first()
    if cand is None:
        cand = Candidate(brand_id=brand_id, canonical_domain="ai-answer", canonical_url=s.canonical_url, hostname=s.display[:250],
                         surface=Surface.CONTENT, state=CandidateState.NEW)  # fmt: skip
        session.add(cand)
        session.flush()
    cand.last_seen = datetime.now(UTC)
    cand.scan_count = (cand.scan_count or 0) + 1
    have = {x.source for x in session.scalars(sa.select(CandidateSource).where(CandidateSource.candidate_id == cand.id)).all()}
    if DiscoverySource.AI_ANSWER not in have:
        session.add(CandidateSource(candidate_id=cand.id, source=DiscoverySource.AI_ANSWER,
                                    matched_pattern=("AI answer: " + ", ".join(ENGINE_LABEL.get(e, e) for e in s.engines))[:200]))  # fmt: skip
    rec = {**s.record(), "official_sample": list(official_sample or [])[:12]}
    snapshot = json.dumps(rec, ensure_ascii=False, sort_keys=True, default=str).encode()
    art = store.put(snapshot, content_type="application/json", suffix=".json")
    ev = Evidence(candidate_id=cand.id, type=EvidenceType.HTTP, source="searchapi:ai_answers", source_type="ai_transcript",
                  collector=COLLECTOR, collector_version=__version__, parser_version="1",
                  request_profile={"engines": s.engines, "prompts": [x.prompt for x in s.said][:6]},
                  response_meta={"status": "positive", "kind": s.kind, "value": s.value, "verdict": s.verdict},
                  content_sha256=art.sha256, artifact_location=art.location, trust_level="collected")  # fmt: skip
    session.add(ev)
    session.flush()
    prev = session.scalars(sa.select(Observation).where(Observation.candidate_id == cand.id).order_by(Observation.observed_at.desc())).first()
    session.add(Observation(candidate_id=cand.id, source=DiscoverySource.AI_ANSWER, scanner_profile=ScannerProfile.DATACENTER,
                            state_at_time=cand.state, content_hash=art.sha256, http_status=None,
                            changed=bool(prev and prev.content_hash and prev.content_hash != art.sha256)))  # fmt: skip
    sc = s.score
    risk = RiskResult(raw=sc["raw"], score=sc["score"], severity=sc["severity"], confidence=sc["confidence"], signals=sc["signals"],
                      groups=sc["groups"], scoring_version=AI_SCORING_VERSION, breakdown={**sc["breakdown"], "ai_answer": rec})  # fmt: skip
    analysis = AnalysisResult(signals=dict(sc["signals"]), evidence_refs=(ev.id,), fp_flags=(), details={"signals": dict(s.fired)})
    fr = finding_stage.record(session, workspace_id=workspace_id, cand=cand, col=SimpleNamespace(evidence_refs=(ev.id,)),
                              analysis=analysis, risk=risk, cfg=cfg, watch_cadence_hours=watch_cadence_hours, kind="ai_answer")  # fmt: skip
    cand.next_scan_at = None
    session.flush()
    return fr


def ai_record_of(finding: Finding | Any) -> dict[str, Any] | None:
    sc = getattr(finding, "current_score", None)
    return ((sc.groups or {}).get("_breakdown", {}) or {}).get("ai_answer") if sc else None
