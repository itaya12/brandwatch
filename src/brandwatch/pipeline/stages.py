"""Pipeline stage contracts and typed results (spec §3).

    Discovery → Normalize → Deduplicate → Pre-filter → Enrichment → Analysis → Scoring
              → Finding → Investigation

Every stage declares its contract (input/output types, cost, timeout, retry, failure behaviour,
evidence written, trigger for the next stage), is idempotent, and emits ScanEvents. Phase 0
ships the contracts and typed results; the stage bodies arrive in Phase 1 (vertical slice).
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from typing import Any, Protocol, TypeVar

from sqlalchemy.orm import Session

from brandwatch.config.brand_config import BrandConfig
from brandwatch.config.settings import Settings
from brandwatch.db.enums import DiscoverySource, FindingState, Severity, Surface
from brandwatch.events.emitter import ScanEventEmitter
from brandwatch.providers.registry import ProviderRegistry


# --------------------------------------------------------------------------------------------
# Typed results (one per stage)
# --------------------------------------------------------------------------------------------
@dataclass(frozen=True, slots=True)
class DiscoveryHit:
    source: DiscoverySource
    raw_value: str  # domain / hostname / URL as the source reported it
    surface: Surface
    matched_pattern: str | None = None


@dataclass(frozen=True, slots=True)
class NormalizedCandidate:
    canonical_domain: str
    canonical_url: str
    hostname: str
    surface: Surface
    source: DiscoverySource
    matched_pattern: str | None = None


@dataclass(frozen=True, slots=True)
class DedupResult:
    candidate_id: uuid.UUID
    is_new: bool
    source_added: bool


@dataclass(frozen=True, slots=True)
class PreFilterResult:
    keep: bool
    reason: str  # "whitelisted" | "brand_owned" | "dead_tld" | "keep"


@dataclass(frozen=True, slots=True)
class LivenessResult:
    alive: bool
    http_status: int | None
    content_present: bool
    parked: bool


@dataclass(frozen=True, slots=True)
class EvidenceResult:
    evidence_ids: tuple[uuid.UUID, ...]
    liveness: LivenessResult
    degraded_providers: tuple[str, ...] = ()  # evidence = unavailable, never "clean"


@dataclass(frozen=True, slots=True)
class AnalysisResult:
    signals: dict[str, float]  # fired signal → points (pre-cap)
    evidence_refs: tuple[uuid.UUID, ...]
    unavailable: tuple[str, ...] = ()  # evidence sources that degraded (dns/http/screenshot/…)
    fp_flags: tuple[str, ...] = ()  # false-positive indicators (age_gt_2y, …) → penalties
    details: dict[str, Any] = field(default_factory=dict)  # per-signal plain-language evidence


@dataclass(frozen=True, slots=True)
class RiskResult:
    raw: int
    score: int  # 0–100
    severity: Severity
    confidence: float  # 0–100 %
    signals: dict[str, float]
    groups: dict[str, float]
    scoring_version: str
    breakdown: dict[str, Any] = field(default_factory=dict)  # bonuses/penalties/rules/confidence


@dataclass(frozen=True, slots=True)
class FindingResult:
    finding_id: uuid.UUID | None  # None when the score stayed below the finding threshold
    state: FindingState | None
    created: bool
    disposition: str = "finding"  # finding | watch | dismissed


@dataclass(frozen=True, slots=True)
class InvestigationResult:
    campaign_id: uuid.UUID
    nodes: int
    edges: int
    budget_exhausted: bool


# --------------------------------------------------------------------------------------------
# Contracts
# --------------------------------------------------------------------------------------------
@dataclass(frozen=True, slots=True)
class StageContract:
    name: str
    input_type: type
    output_type: type
    cost: str
    timeout_s: float | None
    retries: int
    failure_behavior: str
    evidence_written: tuple[str, ...]
    next_trigger: str


CONTRACTS: dict[str, StageContract] = {
    "discovery": StageContract(
        "discovery", dict, DiscoveryHit, "API $ per source (CT/NRD cheap, SerpAPI/logo $)",
        None, 2, "degrade: skip the source, mark it degraded, keep the others",
        (), "each hit → normalize",
    ),
    "normalize": StageContract(
        "normalize", DiscoveryHit, NormalizedCandidate, "0 (pure)", None, 0,
        "drop malformed (logged)", (), "→ deduplicate",
    ),
    "deduplicate": StageContract(
        "deduplicate", NormalizedCandidate, DedupResult, "1 DB upsert on (brand_id, canonical_url)",
        None, 0, "DB uniqueness is authoritative", ("candidates", "candidate_sources"),
        "new → pre_filter; existing → attach source only",
    ),
    "pre_filter": StageContract(
        "pre_filter", DedupResult, PreFilterResult, "0 (no network)", None, 0,
        "fail-open: default keep — never silently miss a threat", (), "keep → enrichment",
    ),
    "enrichment": StageContract(
        "enrichment", DedupResult, EvidenceResult, "provider $ gated by config",
        15.0, 2, "degrade per provider → evidence status = unavailable (never clean)",
        ("http_responses", "dns_observations", "whois_observations", "ssl_observations",
         "reputation_observations", "observations"),
        "content present & suspicious → analysis; empty/parked → watchlist; dead → dismiss",
    ),
    "analysis": StageContract(
        "analysis", EvidenceResult, AnalysisResult, "compute + residential $ (Tier-4 gated)",
        45.0, 1, "partial signals OK; missing = unavailable; browser crash → 1 retry in fresh sandbox",
        ("screenshots", "html_snapshots"), "→ scoring",
    ),
    "scoring": StageContract(
        "scoring", AnalysisResult, RiskResult, "0 (pure, deterministic, reproducible)", None, 0,
        "n/a (pure)", ("risk_scores",), "→ finding",
    ),
    "finding": StageContract(
        "finding", RiskResult, FindingResult, "DB", None, 0, "DB transaction",
        ("findings", "finding_evidence"),
        "severity ≥ threshold → notify; analyst CONFIRM → investigation",
    ),
    "investigation": StageContract(
        "investigation", FindingResult, InvestigationResult, "provider $ capped by budget",
        300.0, 0, "partial graph OK, mark budget_exhausted", ("campaign_nodes", "campaign_edges"),
        "→ report / takedown draft",
    ),
}  # fmt: skip

PIPELINE_ORDER: tuple[str, ...] = tuple(CONTRACTS)


# --------------------------------------------------------------------------------------------
# Context + Stage protocol + stubs
# --------------------------------------------------------------------------------------------
@dataclass(slots=True)
class PipelineContext:
    session: Session
    job_id: uuid.UUID
    workspace_id: uuid.UUID
    brand_id: uuid.UUID
    settings: Settings
    config: BrandConfig
    providers: ProviderRegistry
    emitter: ScanEventEmitter
    extra: dict[str, Any] = field(default_factory=dict)


In = TypeVar("In")
Out = TypeVar("Out")


class Stage(Protocol[In, Out]):
    contract: StageContract

    async def run(self, item: In, ctx: PipelineContext) -> Out: ...


class _NotYet:
    contract: StageContract
    phase = "Phase 1"

    async def run(self, item: Any, ctx: PipelineContext) -> Any:
        raise NotImplementedError(f"{self.contract.name} stage is implemented in {self.phase}")


class DiscoveryStage(_NotYet):
    contract = CONTRACTS["discovery"]


class NormalizeStage(_NotYet):
    contract = CONTRACTS["normalize"]


class DeduplicateStage(_NotYet):
    contract = CONTRACTS["deduplicate"]


class PreFilterStage(_NotYet):
    contract = CONTRACTS["pre_filter"]


class EnrichmentStage(_NotYet):
    contract = CONTRACTS["enrichment"]


class AnalysisStage(_NotYet):
    contract = CONTRACTS["analysis"]


class ScoringStage(_NotYet):
    contract = CONTRACTS["scoring"]


class FindingStage(_NotYet):
    contract = CONTRACTS["finding"]


class InvestigationStage(_NotYet):
    contract = CONTRACTS["investigation"]
    phase = "Phase 4"


STAGES: dict[str, type[_NotYet]] = {
    "discovery": DiscoveryStage,
    "normalize": NormalizeStage,
    "deduplicate": DeduplicateStage,
    "pre_filter": PreFilterStage,
    "enrichment": EnrichmentStage,
    "analysis": AnalysisStage,
    "scoring": ScoringStage,
    "finding": FindingStage,
    "investigation": InvestigationStage,
}
