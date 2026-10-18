"""Investigation (spec §3 stage 9, §8 "Infrastructure pivoting", Phase 4).

One confirmed finding → the whole campaign: a bounded BFS over passive DNS (reverse IP),
certificate fingerprints, favicon hashes, tracking ids and registrant data. Every co-hosted
neighbour is **triaged before inclusion** (reverse IP is mostly unrelated legit tenants), shared
hosting IPs stop the pivot, and the whole walk lives inside an explicit budget
(depth / nodes / edges / API calls / cost / time) so one hit never explodes into thousands.

Outputs: ``campaigns`` + ``campaign_nodes`` (with ``included`` / ``triage_reason`` / ``ai_verdict``)
+ ``campaign_edges`` (typed pivots, each pointing at its evidence), normalised IOCs (spec §10) and a
STIX 2.1 bundle export. ``known_infrastructure_links`` feeds the Infrastructure signal group of the
scoring engine for every later scan.
"""

from __future__ import annotations

import asyncio
import ipaddress
import time
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

import sqlalchemy as sa
from sqlalchemy.orm import Session

from brandwatch import __version__
from brandwatch.config.settings import Settings, get_settings
from brandwatch.db.base import set_checkpoint
from brandwatch.db.enums import (
    CandidateState,
    DiscoverySource,
    EdgeType,
    EvidenceType,
    FindingState,
    IocType,
    JobState,
    NodeType,
    Surface,
)
from brandwatch.db.models import (
    AuditEvent,
    Brand,
    Campaign,
    CampaignEdge,
    CampaignNode,
    Candidate,
    CandidateSource,
    Evidence,
    Finding,
    FindingEvidence,
    HtmlSnapshot,
    Ioc,
    ScanJob,
    ScanStage,
    SslObservation,
    WhoisObservation,
)
from brandwatch.db.types import utcnow
from brandwatch.detection.baseline import brand_key_for
from brandwatch.detection.discovery import split_host
from brandwatch.detection.enrichment import CollectedEvidence
from brandwatch.detection.sources import _looks_related
from brandwatch.events.emitter import ScanEventEmitter
from brandwatch.evidence.store import EvidenceStore
from brandwatch.pipeline.stages import InvestigationResult
from brandwatch.providers.ledger import DbUsageLedger
from brandwatch.providers.registry import ProviderRegistry
from brandwatch.security.limits import SYSTEM_LIMITS

MAX_AI_TRIAGE = 8  # neighbours classified by the LLM per investigation
SHARED_HOSTING_THRESHOLD = 25  # more co-hosted names than this → shared hoster / CDN: stop pivoting


@dataclass(slots=True)
class Budget:
    max_depth: int = 2
    max_nodes: int = 100
    max_edges: int = 300
    max_api_calls: int = 60
    max_cost_usd: float = 1.0
    time_budget_s: float = 120.0

    def clamp(self) -> Budget:
        self.max_depth = min(self.max_depth, SYSTEM_LIMITS.MAX_BFS_DEPTH)
        self.max_nodes = min(self.max_nodes, SYSTEM_LIMITS.MAX_PIVOT_NODES)
        self.max_edges = min(self.max_edges, SYSTEM_LIMITS.MAX_PIVOT_EDGES)
        return self


@dataclass(slots=True)
class Node:
    type: NodeType
    value: str
    depth: int
    included: bool = True
    triage_reason: str = ""
    attrs: dict[str, Any] = field(default_factory=dict)

    @property
    def key(self) -> tuple[NodeType, str]:
        return (self.type, self.value)


@dataclass(slots=True)
class Edge:
    src: tuple[NodeType, str]
    dst: tuple[NodeType, str]
    type: EdgeType
    evidence_id: uuid.UUID | None = None


# --------------------------------------------------------------------------------------------
# seeds from the finding's evidence
# --------------------------------------------------------------------------------------------
def _seed_facts(session: Session, finding: Finding) -> dict[str, Any]:
    cand = session.get(Candidate, finding.candidate_id)
    rows = session.execute(
        sa.select(Evidence).join(FindingEvidence, FindingEvidence.evidence_id == Evidence.id)
        .where(FindingEvidence.finding_id == finding.id).order_by(Evidence.observed_at.desc())
    ).scalars().all()  # fmt: skip
    facts: dict[str, Any] = {"host": cand.hostname, "ips": [], "cert_fp": None, "favicon_mmh3": None,
                             "tracking_ids": [], "registrant_email": None, "registrant_org": None, "evidence": {}}  # fmt: skip
    for ev in rows:
        meta = ev.response_meta or {}
        if ev.type is EvidenceType.DNS and not facts["ips"]:
            from brandwatch.db.models import DnsObservation

            dns = session.get(DnsObservation, ev.id)
            facts["ips"] = list((dns.records or {}).get("A", [])) if dns else []
            facts["evidence"]["dns"] = ev.id
        elif ev.type is EvidenceType.HTTP and not facts["ips"]:
            from brandwatch.db.models import HttpResponse

            http = session.get(HttpResponse, ev.id)
            if http and http.ip:
                facts["ips"] = [http.ip]
        elif ev.type is EvidenceType.SSL and facts["cert_fp"] is None:
            ssl = session.get(SslObservation, ev.id)
            facts["cert_fp"] = ssl.fingerprint_sha256 if ssl else meta.get("fingerprint_sha256")
            facts["evidence"]["ssl"] = ev.id
        elif ev.type is EvidenceType.FAVICON and facts["favicon_mmh3"] is None:
            facts["favicon_mmh3"] = meta.get("mmh3")
            facts["evidence"]["favicon"] = ev.id
        elif ev.type is EvidenceType.HTML and not facts["tracking_ids"]:
            snap = session.get(HtmlSnapshot, ev.id)
            facts["tracking_ids"] = list((snap.meta or {}).get("tracking_ids", [])) if snap else []
            facts["evidence"]["html"] = ev.id
        elif ev.type is EvidenceType.WHOIS and facts["registrant_email"] is None:
            who = session.get(WhoisObservation, ev.id)
            reg = (who.registrant or {}) if who else {}
            facts["registrant_email"] = reg.get("email")
            facts["registrant_org"] = reg.get("org")
            facts["evidence"]["whois"] = ev.id
    return facts


# --------------------------------------------------------------------------------------------
# the investigator
# --------------------------------------------------------------------------------------------
class Investigator:
    def __init__(
        self,
        session: Session,
        brand: Brand,
        providers: ProviderRegistry,
        emitter: ScanEventEmitter,
        budget: Budget,
    ):
        self.session = session
        self.brand = brand
        self.brand_key = brand_key_for(brand, session)
        self.providers = providers
        self.em = emitter
        self.budget = budget.clamp()
        self.nodes: dict[tuple[NodeType, str], Node] = {}
        self.edges: list[Edge] = []
        self.api_calls = 0
        self.cost = 0.0
        self.started = time.monotonic()
        self.exhausted_reason: str | None = None
        self._known_hosts = self._load_known_hosts()
        from brandwatch.detection.protect import protected_set

        self._protected = protected_set(session, brand.id)  # the brand's own / whitelisted sites
        self.ai_triaged = 0
        self.other_brands: set[str] = set()

    # ---------------------------------------------------------------- helpers
    def _load_known_hosts(self) -> dict[str, tuple[Candidate, Finding | None]]:
        out: dict[str, tuple[Candidate, Finding | None]] = {}
        cands = self.session.scalars(
            sa.select(Candidate).where(Candidate.brand_id == self.brand.id)
        ).all()
        for c in cands:
            f = self.session.scalars(
                sa.select(Finding)
                .where(Finding.candidate_id == c.id)
                .order_by(Finding.created_at.desc())
            ).first()
            out[c.hostname] = (c, f)
        return out

    def _over_budget(self) -> str | None:
        if len(self.nodes) >= self.budget.max_nodes:
            return "max_nodes"
        if len(self.edges) >= self.budget.max_edges:
            return "max_edges"
        if self.api_calls >= self.budget.max_api_calls:
            return "max_api_calls"
        if self.cost >= self.budget.max_cost_usd:
            return "max_cost_usd"
        if time.monotonic() - self.started >= self.budget.time_budget_s:
            return "time_budget"
        return None

    def _add_node(
        self, ntype: NodeType, value: str, depth: int, *, included=True, reason="", **attrs
    ) -> Node:
        key = (ntype, value)
        if key in self.nodes:
            n = self.nodes[key]
            if included and not n.included:
                n.included, n.triage_reason = True, reason or n.triage_reason
            return n
        n = Node(ntype, value, depth, included=included, triage_reason=reason, attrs=attrs)
        self.nodes[key] = n
        return n

    def _add_edge(
        self, src: Node, dst: Node, etype: EdgeType, evidence_id: uuid.UUID | None = None
    ) -> None:
        if any(e.src == src.key and e.dst == dst.key and e.type == etype for e in self.edges):
            return
        self.edges.append(Edge(src.key, dst.key, etype, evidence_id))

    async def _call(self, coro):
        self.api_calls += 1
        res = await coro
        self.cost += float(getattr(res, "cost_usd", 0.0) or 0.0)
        return res

    # ---------------------------------------------------------------- triage
    def triage_host(self, host: str, via: EdgeType, *, link_signals: list[str]) -> tuple[bool, str]:
        """Decide whether a pivoted hostname belongs to the campaign (spec §8 co-hosted triage)."""
        from brandwatch.detection.protect import is_protected

        if is_protected(host, self._protected):
            return (
                False,
                "official or whitelisted site of the brand: shown for context, never a suspect",
            )
        known = self._known_hosts.get(host)
        if known and known[1] is not None and known[1].state is not FindingState.DISMISSED:
            return True, f"already a {known[1].severity.value} finding for this brand"
        if known and known[1] is not None and known[1].state is FindingState.DISMISSED:
            return False, "analyst dismissed this host earlier"
        if _looks_related(host, self.brand_key):
            return True, "brand pattern in hostname"
        strong = [s for s in link_signals if s in ("cert", "favicon", "tracking_id", "registrant")]
        if strong:
            return True, f"shares {', '.join(strong)} with the campaign"
        if via is EdgeType.PASSIVE_DNS:
            return False, "co-hosted neighbour without link signals (reverse-IP noise)"
        return False, "no link signals"

    async def _ai_triage(self, node: Node) -> dict[str, Any] | None:
        """Step 3 of co-hosted triage: fetch the neighbour and ask the (advisory) classifier."""
        from brandwatch.detection import ai as ai_mod
        from brandwatch.detection.html import extract_features

        self.ai_triaged += 1
        page = await self._call(
            self.providers.browser().fetch(f"https://{node.value}/", profile="datacenter")
        )
        if not page.ok or not page.data:
            node.triage_reason = f"{node.triage_reason}; AI triage skipped (unreachable)"
            return None
        html = page.data.get("dom") or page.data.get("html") or ""
        feats = extract_features(
            html, page.data.get("final_url") or f"https://{node.value}/", [self.brand_key]
        )
        verdict = await ai_mod.triage_page(
            self.providers,
            url=f"https://{node.value}/",
            html_features=feats,
            brand_name=self.brand.name,
        )
        self.api_calls += 1
        if not verdict:
            return None
        node.attrs["ai_verdict"] = verdict
        target = (verdict.get("impersonated_brand") or "").lower().replace(" ", "")
        if verdict["is_phishing"] and verdict["confidence"] >= 0.75:
            if self.brand_key and self.brand_key in target:
                node.included = True
                node.triage_reason = f"AI triage: phishing impersonating {self.brand.name} ({verdict['confidence']:.0%})"
            else:
                other = verdict.get("impersonated_brand") or "another brand"
                node.attrs["other_brand"] = other
                self.other_brands.add(other)
                node.triage_reason = f"AI triage: phishing for {other}, not {self.brand.name} — recorded as actor intel"
        else:
            node.triage_reason = (
                f"{node.triage_reason}; AI triage: not phishing ({verdict['confidence']:.0%})"
            )
        return verdict

    # ---------------------------------------------------------------- BFS
    async def run(self, finding: Finding) -> tuple[list[Node], list[Edge]]:
        facts = _seed_facts(self.session, finding)
        seed = self._add_node(
            NodeType.DOMAIN, facts["host"], 0, reason="seed finding", finding_id=str(finding.id)
        )
        frontier: list[Node] = [seed]
        for ip in facts["ips"]:
            n = self._add_node(NodeType.IP, ip, 1, reason="resolved by the seed")
            self._add_edge(seed, n, EdgeType.PASSIVE_DNS, facts["evidence"].get("dns"))
            frontier.append(n)
        if facts["cert_fp"]:
            n = self._add_node(NodeType.CERTIFICATE, facts["cert_fp"], 1, reason="seed certificate")
            self._add_edge(seed, n, EdgeType.CERT, facts["evidence"].get("ssl"))
            frontier.append(n)
        for tid in facts["tracking_ids"]:
            n = self._add_node(NodeType.TRACKING_ID, tid, 1, reason="tracking id in seed page")
            self._add_edge(seed, n, EdgeType.TRACKING_ID, facts["evidence"].get("html"))
            frontier.append(n)
        if facts["registrant_email"] and "REDACTED" not in str(facts["registrant_email"]).upper():
            n = self._add_node(
                NodeType.REGISTRANT, facts["registrant_email"], 1, reason="seed registrant"
            )
            self._add_edge(seed, n, EdgeType.REVERSE_WHOIS, facts["evidence"].get("whois"))
            frontier.append(n)
        favicon_mmh3 = facts["favicon_mmh3"]

        visited: set[tuple[NodeType, str]] = set()
        while frontier:
            node = frontier.pop(0)
            if node.key in visited:
                continue
            visited.add(node.key)
            reason = self._over_budget()
            if reason:
                self.exhausted_reason = reason
                self.em.emit(
                    "investigation",
                    "budget",
                    "skipped",
                    f"Budget exhausted ({reason}) — partial graph kept",
                    level="warn",
                )
                break
            if node.depth >= self.budget.max_depth:
                continue
            new_nodes = await self._expand(node, favicon_mmh3 if node is seed else None)
            frontier.extend(n for n in new_nodes if n.included and n.key not in visited)
        return list(self.nodes.values()), self.edges

    async def _expand(self, node: Node, favicon_mmh3: int | None) -> list[Node]:
        out: list[Node] = []
        if node.type is NodeType.IP:
            res = await self._call(self.providers.passive_dns().passive_dns(node.value))
            hosts = [h for h in (res.data or {}).get("resolutions", []) if res.ok]
            host_info = await self._call(self.providers.host().host(node.value))
            if host_info.ok and host_info.data:
                node.attrs.update({k: host_info.data.get(k) for k in ("org", "asn", "ports")})
            if len(hosts) > SHARED_HOSTING_THRESHOLD:
                node.attrs["shared_hosting"] = True
                self.em.emit(
                    "investigation",
                    node.value,
                    "skipped",
                    f"Reverse-IP {node.value}: {len(hosts)} names → shared hosting, not pivoting further",
                    level="warn",
                )
                return out
            included = excluded = 0
            out_noise: list[Node] = []
            for host in hosts:
                if (
                    host == node.value
                    or (NodeType.DOMAIN, host) in self.nodes
                    and self.nodes[(NodeType.DOMAIN, host)].depth == 0
                ):
                    continue
                ok, why = self.triage_host(host, EdgeType.PASSIVE_DNS, link_signals=[])
                n = self._add_node(NodeType.DOMAIN, host, node.depth + 1, included=ok, reason=why)
                self._add_edge(node, n, EdgeType.PASSIVE_DNS)
                if not ok and why.startswith("co-hosted neighbour"):
                    out_noise.append(n)
                included += ok
                excluded += not ok
                if ok:
                    out.append(n)
            for host_node in [n for n in out_noise if not n.included][
                : max(0, MAX_AI_TRIAGE - self.ai_triaged)
            ]:
                verdict = await self._ai_triage(host_node)
                if verdict and host_node.included:
                    out.append(host_node)
                    included += 1
                    excluded -= 1
            self.em.done(
                "investigation",
                node.value,
                f"Reverse-IP {node.value}: {len(hosts)} co-hosted → triage → {included} included, {excluded} excluded",
                counts={"included": included, "excluded": excluded},
            )
        elif node.type is NodeType.CERTIFICATE:
            res = await self._call(self.providers.cert().by_fingerprint(node.value))
            sans: set[str] = set()
            for cert in (res.data or {}).get("certificates", []) if res.ok else []:
                sans.update(str(x).lower().lstrip("*.") for x in cert.get("sans", []))
            for host in sorted(sans):
                if host.startswith("www."):
                    continue
                ok, why = self.triage_host(host, EdgeType.CERT, link_signals=["cert"])
                n = self._add_node(NodeType.DOMAIN, host, node.depth + 1, included=ok, reason=why)
                self._add_edge(node, n, EdgeType.CERT)
                if ok:
                    out.append(n)
            self.em.done(
                "investigation",
                node.value[:12],
                f"Certificate {node.value[:12]}…: {len(sans)} SAN(s) share it",
            )
        elif node.type is NodeType.TRACKING_ID:
            rows = self.session.execute(
                sa.select(Candidate.hostname).join(Evidence, Evidence.candidate_id == Candidate.id)
                .join(HtmlSnapshot, HtmlSnapshot.evidence_id == Evidence.id)
                .where(Candidate.brand_id == self.brand.id)
            ).scalars().all()  # fmt: skip
            # DB-side JSON filtering is dialect-specific; filter in Python (bounded by brand size)
            hosts = set()
            for host in set(rows):
                snaps = self.session.execute(
                    sa.select(HtmlSnapshot.meta).join(Evidence, Evidence.id == HtmlSnapshot.evidence_id)
                    .join(Candidate, Candidate.id == Evidence.candidate_id).where(Candidate.hostname == host)
                ).scalars().all()  # fmt: skip
                if any(node.value in (m or {}).get("tracking_ids", []) for m in snaps):
                    hosts.add(host)
            for host in sorted(hosts):
                if (NodeType.DOMAIN, host) in self.nodes and self.nodes[
                    (NodeType.DOMAIN, host)
                ].depth == 0:
                    continue
                ok, why = self.triage_host(host, EdgeType.TRACKING_ID, link_signals=["tracking_id"])
                n = self._add_node(NodeType.DOMAIN, host, node.depth + 1, included=ok, reason=why)
                self._add_edge(node, n, EdgeType.TRACKING_ID)
                if ok:
                    out.append(n)
            self.em.done(
                "investigation",
                node.value,
                f"Tracking id {node.value}: {len(hosts)} page(s) in this workspace carry it",
            )
        elif node.type is NodeType.REGISTRANT:
            rows = self.session.execute(
                sa.select(Candidate.hostname, WhoisObservation.registrant)
                .join(Evidence, Evidence.candidate_id == Candidate.id)
                .join(WhoisObservation, WhoisObservation.evidence_id == Evidence.id)
                .where(Candidate.brand_id == self.brand.id)
            ).all()
            hosts = {h for h, reg in rows if (reg or {}).get("email") == node.value}
            for host in sorted(hosts):
                if (NodeType.DOMAIN, host) in self.nodes and self.nodes[
                    (NodeType.DOMAIN, host)
                ].depth == 0:
                    continue
                ok, why = self.triage_host(
                    host, EdgeType.REVERSE_WHOIS, link_signals=["registrant"]
                )
                n = self._add_node(NodeType.DOMAIN, host, node.depth + 1, included=ok, reason=why)
                self._add_edge(node, n, EdgeType.REVERSE_WHOIS)
                if ok:
                    out.append(n)
            self.em.done(
                "investigation", node.value, f"Registrant {node.value}: {len(hosts)} domain(s)"
            )
        elif node.type is NodeType.DOMAIN:
            if favicon_mmh3 is not None:
                res = await self._call(self.providers.host().favicon_search(favicon_mmh3))
                ips = (res.data or {}).get("ips", []) if res.ok else []
                for ip in ips:
                    n = self._add_node(
                        NodeType.IP, ip, node.depth + 1, reason=f"serves favicon {favicon_mmh3}"
                    )
                    self._add_edge(node, n, EdgeType.FAVICON)
                    out.append(n)
                self.em.done(
                    "investigation",
                    "favicon",
                    f"Favicon hash {favicon_mmh3}: {len(ips)} host IP(s) serve the same icon",
                )
            if node.depth > 0:  # pivoted domains: resolve to find their servers
                res = await self._call(self.providers.passive_dns().passive_dns(node.value))
                for ip in (res.data or {}).get("resolutions", []) if res.ok else []:
                    try:
                        ipaddress.ip_address(ip)
                    except ValueError:
                        continue
                    n = self._add_node(
                        NodeType.IP, ip, node.depth + 1, reason=f"resolved from {node.value}"
                    )
                    self._add_edge(node, n, EdgeType.PASSIVE_DNS)
                    out.append(n)
        return out


# --------------------------------------------------------------------------------------------
# persistence: campaign, candidates, IOCs
# --------------------------------------------------------------------------------------------
def persist_campaign(
    session: Session,
    finding: Finding,
    brand: Brand,
    nodes: list[Node],
    edges: list[Edge],
    facts_actor: dict[str, Any],
) -> Campaign:
    campaign = session.get(Campaign, finding.campaign_id) if finding.campaign_id else None
    if campaign is None:
        campaign = Campaign(
            brand_id=brand.id,
            name=f"{brand.name} campaign {str(finding.id)[:8].upper()}",
            actor_profile=facts_actor,
        )
        session.add(campaign)
        session.flush()
    else:
        campaign.actor_profile = {**(campaign.actor_profile or {}), **facts_actor}
    existing = {
        (n.type, n.value): n
        for n in session.scalars(
            sa.select(CampaignNode).where(CampaignNode.campaign_id == campaign.id)
        ).all()
    }
    db_nodes: dict[tuple[NodeType, str], CampaignNode] = {}
    for n in nodes:
        row = existing.get(n.key)
        if row is None:
            row = CampaignNode(
                campaign_id=campaign.id,
                type=n.type,
                value=n.value,
                included=n.included,
                triage_reason=n.triage_reason,
                ai_verdict=n.attrs or None,
            )
            session.add(row)
            session.flush()
        else:
            row.included = row.included or n.included
            row.triage_reason = n.triage_reason or row.triage_reason
            row.ai_verdict = {**(row.ai_verdict or {}), **(n.attrs or {})} or None
        db_nodes[n.key] = row
    have = {
        (e.src_node_id, e.dst_node_id, e.type)
        for e in session.scalars(
            sa.select(CampaignEdge).where(CampaignEdge.campaign_id == campaign.id)
        ).all()
    }
    for e in edges:
        src, dst = db_nodes.get(e.src), db_nodes.get(e.dst)
        if src is None or dst is None or (src.id, dst.id, e.type) in have:
            continue
        session.add(
            CampaignEdge(
                campaign_id=campaign.id,
                src_node_id=src.id,
                dst_node_id=dst.id,
                type=e.type,
                evidence_id=e.evidence_id,
            )
        )
    finding.campaign_id = campaign.id
    # link other findings of this brand whose host is an included node
    included_hosts = {n.value for n in nodes if n.type is NodeType.DOMAIN and n.included}
    for other in session.scalars(sa.select(Finding).join(Candidate, Candidate.id == Finding.candidate_id)
                                 .where(Finding.brand_id == brand.id, Candidate.hostname.in_(included_hosts))).all():  # fmt: skip
        if other.campaign_id is None:
            other.campaign_id = campaign.id
    session.flush()
    return campaign


def ensure_candidates(session: Session, brand: Brand, nodes: list[Node]) -> list[Candidate]:
    """Included domain nodes that are not candidates yet become candidates (source: pivot)."""
    from brandwatch.detection.protect import is_protected, protected_set

    protected = protected_set(session, brand.id)
    created: list[Candidate] = []
    seed = next((n.value for n in nodes if n.type is NodeType.DOMAIN and n.depth == 0), "")
    for n in nodes:
        if n.type is not NodeType.DOMAIN or not n.included or n.depth == 0:
            continue
        if is_protected(n.value, protected):
            continue
        url = f"https://{n.value}/"
        exists = session.scalars(
            sa.select(Candidate).where(
                Candidate.brand_id == brand.id, Candidate.canonical_url == url
            )
        ).first()
        if exists:
            continue
        c = Candidate(brand_id=brand.id, canonical_domain=split_host(n.value).registrable, canonical_url=url, hostname=n.value,
                      surface=Surface.NAME, state=CandidateState.NEW, priority=20)  # fmt: skip
        session.add(c)
        session.flush()
        session.add(
            CandidateSource(
                candidate_id=c.id,
                source=DiscoverySource.MANUAL,
                matched_pattern=f"pivot: the infrastructure map of {seed} — {n.triage_reason}"[:500] if seed else f"pivot:{n.triage_reason}",
            )
        )
        created.append(c)
    session.flush()
    return created


_IOC_FROM_EVIDENCE: dict[EvidenceType, tuple[IocType, ...]] = {
    EvidenceType.DNS: (IocType.IP,),
    EvidenceType.SSL: (IocType.CERT_FP,),
    EvidenceType.FAVICON: (IocType.FAVICON_HASH,),
    EvidenceType.HTML: (IocType.TRACKING_ID,),
    EvidenceType.WHOIS: (IocType.EMAIL,),
}


def extract_iocs(
    session: Session, finding: Finding, campaign_id: uuid.UUID | None = None
) -> list[Ioc]:
    """Normalised, traceable indicators for a finding (spec §10). Idempotent per (workspace, type, value)."""
    brand = session.get(Brand, finding.brand_id)
    cand = session.get(Candidate, finding.candidate_id)
    values: list[tuple[IocType, str, uuid.UUID | None]] = [
        (IocType.DOMAIN, cand.canonical_domain, None),
        (IocType.HOSTNAME, cand.hostname, None),
        (IocType.URL, cand.canonical_url, None),
    ]
    rows = (
        session.execute(
            sa.select(Evidence)
            .join(FindingEvidence, FindingEvidence.evidence_id == Evidence.id)
            .where(FindingEvidence.finding_id == finding.id)
        )
        .scalars()
        .all()
    )
    for ev in rows:
        meta = ev.response_meta or {}
        if ev.type is EvidenceType.DNS:
            from brandwatch.db.models import DnsObservation

            dns = session.get(DnsObservation, ev.id)
            for ip in (dns.records or {}).get("A", []) if dns else []:
                values.append((IocType.IP, ip, ev.id))
        elif ev.type is EvidenceType.SSL:
            ssl = session.get(SslObservation, ev.id)
            if ssl and ssl.fingerprint_sha256:
                values.append((IocType.CERT_FP, ssl.fingerprint_sha256, ev.id))
        elif ev.type is EvidenceType.FAVICON and meta.get("mmh3") is not None:
            values.append((IocType.FAVICON_HASH, str(meta["mmh3"]), ev.id))
        elif ev.type is EvidenceType.HTML:
            snap = session.get(HtmlSnapshot, ev.id)
            for tid in (snap.meta or {}).get("tracking_ids", []) if snap else []:
                values.append((IocType.TRACKING_ID, tid, ev.id))
        elif ev.type is EvidenceType.WHOIS:
            who = session.get(WhoisObservation, ev.id)
            email = ((who.registrant or {}) if who else {}).get("email")
            if email and "@" in str(email):
                values.append((IocType.EMAIL, str(email), ev.id))
    out: list[Ioc] = []
    seen: dict[tuple[IocType, str], Ioc] = {}  # the same IP / hash can sit in several evidence rows
    for itype, value, ev_id in values:
        if (itype, value) in seen:
            row = seen[(itype, value)]
            row.source_evidence_id = row.source_evidence_id or ev_id
            continue
        row = session.scalars(
            sa.select(Ioc).where(
                Ioc.workspace_id == brand.workspace_id, Ioc.type == itype, Ioc.value == value
            )
        ).first()
        if row is None:
            row = Ioc(
                workspace_id=brand.workspace_id,
                type=itype,
                value=value,
                finding_id=finding.id,
                campaign_id=campaign_id,
                source_evidence_id=ev_id,
            )
            session.add(row)
        else:  # re-seen by a newer investigation: the latest attribution wins, so every fresh
            # campaign export is complete (the IOC row itself stays unique per workspace)
            row.campaign_id = campaign_id or row.campaign_id
            row.finding_id = finding.id
            row.source_evidence_id = ev_id or row.source_evidence_id
        seen[(itype, value)] = row
        out.append(row)
    session.flush()
    return out


def known_infrastructure_links(
    session: Session, cand: Candidate, col: CollectedEvidence
) -> dict[str, str]:
    """Infrastructure signals for a fresh observation: does it share servers / certs / tracking ids
    with known phishing (confirmed or critical findings) or with an existing campaign?"""
    links: dict[str, str] = {}
    brand_id = cand.brand_id
    ips = set(col.dns_records or [])
    if col.ip:
        ips.add(col.ip)
    # included campaign nodes of this brand
    node_rows = session.execute(
        sa.select(CampaignNode.type, CampaignNode.value)
        .join(Campaign, Campaign.id == CampaignNode.campaign_id)
        .where(Campaign.brand_id == brand_id, CampaignNode.included.is_(True))
    ).all()
    campaign_values = {(t, v) for t, v in node_rows}
    if any((NodeType.IP, ip) in campaign_values for ip in ips) or (col.tls_fingerprint and (NodeType.CERTIFICATE, col.tls_fingerprint) in campaign_values) \
            or any((NodeType.TRACKING_ID, t) in campaign_values for t in col.tracking_ids):  # fmt: skip
        links["linked_to_known_campaign"] = (
            "shares infrastructure with an investigated campaign of this brand"
        )
    # confirmed / critical findings' infrastructure
    known = session.execute(
        sa.select(Candidate.id, Candidate.hostname).join(Finding, Finding.candidate_id == Candidate.id)
        .where(Finding.brand_id == brand_id, Candidate.id != cand.id,
               sa.or_(Finding.state == FindingState.CONFIRMED, Finding.severity == "critical"))
    ).all()  # fmt: skip
    if not known:
        return links
    known_ids = [k[0] for k in known]
    from brandwatch.db.models import DnsObservation

    phish_ips = set()
    for recs in session.execute(
        sa.select(DnsObservation.records)
        .join(Evidence, Evidence.id == DnsObservation.evidence_id)
        .where(Evidence.candidate_id.in_(known_ids))
    ).scalars():
        phish_ips.update((recs or {}).get("A", []))
    if ips & phish_ips:
        links["cohosted_with_known_phish"] = (
            f"shares server {sorted(ips & phish_ips)[0]} with known phishing of this brand"
        )
    if col.tls_fingerprint:
        fps = set(
            session.execute(
                sa.select(SslObservation.fingerprint_sha256)
                .join(Evidence, Evidence.id == SslObservation.evidence_id)
                .where(Evidence.candidate_id.in_(known_ids))
            ).scalars()
        )
        if col.tls_fingerprint in fps:
            links["cert_shared_with_phish"] = (
                "TLS certificate fingerprint also used by known phishing"
            )
    if col.tracking_ids:
        for meta in session.execute(
            sa.select(HtmlSnapshot.meta)
            .join(Evidence, Evidence.id == HtmlSnapshot.evidence_id)
            .where(Evidence.candidate_id.in_(known_ids))
        ).scalars():
            shared = set(col.tracking_ids) & set((meta or {}).get("tracking_ids", []))
            if shared:
                links["tracking_id_shared"] = (
                    f"tracking id {sorted(shared)[0]} also present on known phishing pages"
                )
                break
    return links


# --------------------------------------------------------------------------------------------
# job entry point
# --------------------------------------------------------------------------------------------
async def run_investigation(session: Session, job_id: uuid.UUID, finding_id: uuid.UUID, *, settings: Settings | None = None,
                            store: EvidenceStore | None = None) -> InvestigationResult:  # fmt: skip
    settings = settings or get_settings()
    job = session.get(ScanJob, job_id)
    finding = session.get(Finding, finding_id)
    if job is None or finding is None:
        raise LookupError("job or finding not found")
    brand = session.get(Brand, finding.brand_id)
    job.state = JobState.RUNNING
    job.started_at = utcnow()
    session.flush()
    em = ScanEventEmitter(session, job_id, secrets=settings.known_secret_values(), commit=True)  # see intel.run_intel: no lock held while waiting
    set_checkpoint(
        session
    )  # commit before every provider call: the write lock is not held for minutes
    from brandwatch.detection.runner import load_brand_config

    cfg = load_brand_config(session, brand.id)
    ledger = DbUsageLedger(session, job.workspace_id, cfg.economic_limits)
    from brandwatch import keys as keystore

    providers = ProviderRegistry(
        settings,
        ledger=ledger,
        job_id=job_id,
        key_overrides=keystore.load_keys(session, job.workspace_id, settings),
    )
    budget = Budget(max_cost_usd=cfg.economic_limits.max_investigation_cost or 1.0)
    stage = ScanStage(
        job_id=job_id, name="investigation", state=JobState.RUNNING, started_at=utcnow()
    )
    session.add(stage)
    session.flush()
    t0 = time.monotonic()
    cand = session.get(Candidate, finding.candidate_id)
    em.running(
        "investigation",
        cand.hostname,
        f"Pivoting from {cand.hostname} (depth ≤ {budget.max_depth}, nodes ≤ {budget.max_nodes}) …",
    )

    inv = Investigator(session, brand, providers, em, budget)
    nodes, edges = await inv.run(finding)
    facts = _seed_facts(session, finding)
    actor = {
        "registrant_email": facts["registrant_email"], "registrant_org": facts["registrant_org"],
        "tracking_ids": facts["tracking_ids"], "servers": sorted({n.value for n in nodes if n.type is NodeType.IP}),
        "certificates": sorted({n.value for n in nodes if n.type is NodeType.CERTIFICATE}),
        "investigated_at": datetime.now(UTC).isoformat(), "generator": f"brandwatch {__version__}",
        "other_brands_hit": sorted(inv.other_brands),
    }  # fmt: skip
    campaign = persist_campaign(session, finding, brand, nodes, edges, actor)
    job.payload = {
        **(job.payload or {}),
        "campaign_id": str(campaign.id),
    }  # console → "open attack infrastructure"
    new_cands = ensure_candidates(session, brand, nodes)
    iocs = extract_iocs(session, finding, campaign.id)
    included = [n for n in nodes if n.included]
    session.add(AuditEvent(workspace_id=brand.workspace_id, actor_type="system", action="campaign.investigated",
                           object_type="campaign", object_id=campaign.id,
                           new_value={"nodes": len(nodes), "included": len(included), "edges": len(edges), "iocs": len(iocs),
                                      "budget_exhausted": inv.exhausted_reason, "api_calls": inv.api_calls}))  # fmt: skip
    stage.state = JobState.DONE
    stage.hits = len(included)
    stage.api_calls = inv.api_calls
    stage.elapsed_ms = int((time.monotonic() - t0) * 1000)
    stage.finished_at = utcnow()
    job.state = JobState.DONE
    job.finished_at = utcnow()
    session.flush()
    em.done("summary", "investigation",
            f"Campaign {campaign.name}: {len(included)} node(s) included, {len(nodes) - len(included)} excluded, {len(edges)} edge(s), "
            f"{len(iocs)} IOC(s), {len(new_cands)} new candidate(s) queued for scanning",
            counts={"nodes": len(nodes), "edges": len(edges), "api_calls": inv.api_calls, "cost_usd": inv.cost},
            data={"campaign_id": str(campaign.id), "nodes": len(nodes), "included": len(included), "edges": len(edges),
                  "iocs": len(iocs), "new_candidates": [c.hostname for c in new_cands], "budget_exhausted": inv.exhausted_reason,
                  "api_calls": inv.api_calls, "cost_usd": inv.cost, "duration_ms": stage.elapsed_ms, "findings": 0, "hits": len(nodes),
                  "criticals": 0, "next_run": None})  # fmt: skip
    return InvestigationResult(
        campaign_id=campaign.id,
        nodes=len(nodes),
        edges=len(edges),
        budget_exhausted=inv.exhausted_reason is not None,
    )


# --------------------------------------------------------------------------------------------
# exports
# --------------------------------------------------------------------------------------------
def campaign_out(session: Session, campaign: Campaign) -> dict[str, Any]:
    nodes = session.scalars(
        sa.select(CampaignNode).where(CampaignNode.campaign_id == campaign.id)
    ).all()
    edges = session.scalars(
        sa.select(CampaignEdge).where(CampaignEdge.campaign_id == campaign.id)
    ).all()
    findings = session.scalars(sa.select(Finding).where(Finding.campaign_id == campaign.id)).all()
    by_id = {n.id: n for n in nodes}
    host_findings = {}
    for f in findings:
        c = session.get(Candidate, f.candidate_id)
        host_findings[c.hostname] = {
            "id": str(f.id),
            "severity": f.severity.value,
            "state": f.state.value,
        }
    return {
        "id": str(campaign.id), "brand_id": str(campaign.brand_id), "name": campaign.name,
        "actor_profile": campaign.actor_profile or {}, "created_at": campaign.created_at.isoformat(),
        "nodes": [
            {"id": str(n.id), "type": n.type.value, "value": n.value, "included": n.included, "triage_reason": n.triage_reason,
             "attrs": n.ai_verdict or {}, "finding": host_findings.get(n.value)}
            for n in nodes
        ],
        "edges": [
            {"id": str(e.id), "source": str(e.src_node_id), "target": str(e.dst_node_id), "type": e.type.value,
             "source_value": by_id[e.src_node_id].value, "target_value": by_id[e.dst_node_id].value,
             "evidence_id": str(e.evidence_id) if e.evidence_id else None}
            for e in edges if e.src_node_id in by_id and e.dst_node_id in by_id
        ],
        "findings": [{"id": str(f.id), "hostname": session.get(Candidate, f.candidate_id).hostname, "severity": f.severity.value, "state": f.state.value} for f in findings],
        "stats": {"nodes": len(nodes), "included": sum(1 for n in nodes if n.included), "excluded": sum(1 for n in nodes if not n.included), "edges": len(edges)},
        **_campaign_story(campaign, nodes, edges, findings, session),
    }  # fmt: skip


EDGE_LABELS = {"passive_dns": "shared server (passive DNS)", "cert": "shared certificate", "favicon": "same favicon",
               "tracking_id": "same tracking ID", "reverse_whois": "same registrant", "reverse_ns": "same name servers"}  # fmt: skip


def _ai_text(attrs: dict[str, Any]) -> str | None:
    v = (attrs or {}).get("ai_verdict")
    if not isinstance(v, dict):
        return None
    verdict = "phishing" if v.get("is_phishing") else "not phishing"
    target = f" impersonating {v['impersonated_brand']}" if v.get("impersonated_brand") else ""
    why = f"; {v['rationale']}" if v.get("rationale") else ""
    return f"AI: {verdict}{target} ({round(float(v.get('confidence') or 0) * 100)}%){why}"


def _campaign_story(campaign: Campaign, nodes: list[CampaignNode], edges: list[CampaignEdge], findings: list[Finding],
                    session: Session) -> dict[str, Any]:  # fmt: skip
    """The map as sentences: what one confirmed site led to."""
    brand = session.get(Brand, campaign.brand_id)
    seed = next((n.value for n in nodes if (n.triage_reason or "") == "seed finding"), None)
    servers = sum(1 for n in nodes if n.type is NodeType.IP and n.included)
    sites = [n for n in nodes if n.type in (NodeType.DOMAIN, NodeType.HOSTNAME) and n.included]
    other = sorted(
        {
            (n.ai_verdict or {}).get("other_brand")
            for n in nodes
            if (n.ai_verdict or {}).get("other_brand")
        }
    )
    counts: dict[str, int] = {}
    for e in edges:
        counts[e.type.value] = counts.get(e.type.value, 0) + 1
    name = brand.name if brand else "the brand"
    headline = (f"One confirmed site{f' ({seed})' if seed else ''} led to {servers} server{'s' if servers != 1 else ''} "
                f"hosting {len(sites)} {name} look-alike{'s' if len(sites) != 1 else ''}"
                + (f" and {len(other)} site(s) of other brands ({', '.join(other)})" if other else "")
                + " — the same operator.")  # fmt: skip
    return {
        "headline": headline,
        "seed": seed,
        "title": f"{seed} campaign" if seed else campaign.name,
        "servers": servers,
        "edge_counts": [{"type": t, "label": EDGE_LABELS.get(t, t.replace("_", " ")), "count": c} for t, c in sorted(counts.items(), key=lambda kv: -kv[1])],
        "ai_text": {str(n.id): _ai_text(n.ai_verdict or {}) for n in nodes if _ai_text(n.ai_verdict or {})},
        "findings_total": len(findings),
    }  # fmt: skip


_STIX_PATTERN = {
    IocType.DOMAIN: lambda v: f"[domain-name:value = '{v}']",
    IocType.HOSTNAME: lambda v: f"[domain-name:value = '{v}']",
    IocType.URL: lambda v: f"[url:value = '{v}']",
    IocType.IP: lambda v: f"[ipv4-addr:value = '{v}']",
    IocType.CERT_FP: lambda v: f"[x509-certificate:hashes.'SHA-256' = '{v}']",
    IocType.FAVICON_HASH: lambda v: f"[x-brandwatch-favicon:mmh3 = '{v}']",
    IocType.TRACKING_ID: lambda v: f"[x-brandwatch-tracking:id = '{v}']",
    IocType.EMAIL: lambda v: f"[email-addr:value = '{v}']",
    IocType.SHA256: lambda v: f"[file:hashes.'SHA-256' = '{v}']",
    IocType.TELEGRAM: lambda v: f"[x-brandwatch-telegram:id = '{v}']",
    IocType.WALLET: lambda v: f"[x-brandwatch-wallet:address = '{v}']",
    IocType.ASN: lambda v: f"[autonomous-system:number = {v}]",
}


def stix_bundle(
    session: Session, iocs: list[Ioc], campaign: Campaign | None = None, brand: Brand | None = None
) -> dict[str, Any]:
    """STIX 2.1 bundle: indicators (+ a campaign object and relationships) for TIP/SIEM/SOAR import."""
    now = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    objects: list[dict[str, Any]] = []
    identity_id = "identity--" + str(uuid.uuid5(uuid.NAMESPACE_DNS, "brandwatch"))
    objects.append({"type": "identity", "spec_version": "2.1", "id": identity_id, "created": now, "modified": now,
                    "name": "BrandWatch", "identity_class": "system"})  # fmt: skip
    camp_id = None
    if campaign is not None:
        camp_id = f"campaign--{campaign.id}"
        objects.append({"type": "campaign", "spec_version": "2.1", "id": camp_id, "created": now, "modified": now,
                        "name": campaign.name, "description": f"Phishing campaign impersonating {brand.name if brand else 'a brand'}",
                        "created_by_ref": identity_id})  # fmt: skip
    for ioc in iocs:
        ind_id = f"indicator--{ioc.id}"
        objects.append({
            "type": "indicator", "spec_version": "2.1", "id": ind_id, "created": now, "modified": now,
            "created_by_ref": identity_id, "name": f"{ioc.type.value}: {ioc.value}",
            "pattern": _STIX_PATTERN[ioc.type](ioc.value), "pattern_type": "stix", "valid_from": ioc.first_seen.isoformat() if ioc.first_seen else now,
            "indicator_types": ["malicious-activity"], "labels": ["phishing", "brand-impersonation", ioc.type.value],
            "external_references": [{"source_name": "brandwatch", "description": f"finding {ioc.finding_id}", "external_id": str(ioc.source_evidence_id or "")}],
        })  # fmt: skip
        if camp_id:
            objects.append({"type": "relationship", "spec_version": "2.1", "id": f"relationship--{uuid.uuid5(uuid.NAMESPACE_URL, ind_id)}",
                            "created": now, "modified": now, "relationship_type": "indicates", "source_ref": ind_id, "target_ref": camp_id})  # fmt: skip
    return {"type": "bundle", "id": f"bundle--{uuid.uuid4()}", "objects": objects}


def iocs_csv(iocs: list[Ioc]) -> str:
    import csv
    import io

    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["type", "value", "first_seen", "finding_id", "campaign_id", "source_evidence_id"])
    for i in iocs:
        w.writerow(
            [
                i.type.value,
                i.value,
                i.first_seen.isoformat() if i.first_seen else "",
                i.finding_id or "",
                i.campaign_id or "",
                i.source_evidence_id or "",
            ]
        )
    return buf.getvalue()


async def _noop():  # pragma: no cover - keeps asyncio imported for type checkers
    await asyncio.sleep(0)
