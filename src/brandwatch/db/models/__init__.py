"""All ORM models. Importing this package registers every table on ``Base.metadata``.

``IMMUTABLE_TABLES`` is the single list the migration uses to install UPDATE/DELETE-rejecting
triggers and that the test suite checks, so the model layer and the DB enforcement cannot drift.
"""

from brandwatch.db.base import Base
from brandwatch.db.models.audit import AuditEvent
from brandwatch.db.models.brand import Brand, BrandDomain, BrandFingerprint, Config
from brandwatch.db.models.campaign import Campaign, CampaignEdge, CampaignNode
from brandwatch.db.models.candidate import Candidate, CandidateSource, Observation
from brandwatch.db.models.evidence import (
    EVIDENCE_CHILD_TABLES,
    DnsObservation,
    Evidence,
    HtmlSnapshot,
    HttpResponse,
    ReputationObservation,
    Screenshot,
    SslObservation,
    WhoisObservation,
)
from brandwatch.db.models.finding import AnalystLabel, Finding, FindingEvidence, FindingNote
from brandwatch.db.models.intel import IntelLookup
from brandwatch.db.models.ioc import Ioc
from brandwatch.db.models.jobs import ScanEventRecord, ScanJob, ScanStage
from brandwatch.db.models.network import (
    Asn,
    Certificate,
    Domain,
    Hostname,
    IpAddress,
    Nameserver,
    Registrar,
    Url,
)
from brandwatch.db.models.output import Report, TakedownDraft
from brandwatch.db.models.provider import ApiKey, ApiProvider, ApiUsage
from brandwatch.db.models.scoring import (
    RISK_SCORES_MUTABLE_COLUMNS,
    RiskScore,
    RiskScoreVersion,
    RuleVersion,
)
from brandwatch.db.models.workspace import AccessToken, User, Workspace

# Append-only tables: the DB rejects UPDATE and DELETE outright (migration 001 triggers).
IMMUTABLE_TABLES: tuple[str, ...] = (
    "audit_events",
    "observations",
    "evidence",
    *EVIDENCE_CHILD_TABLES,
)

# Append-only except for the listed columns (only ``is_current`` may flip on re-score).
PARTIALLY_MUTABLE_TABLES: dict[str, tuple[str, ...]] = {
    "risk_scores": RISK_SCORES_MUTABLE_COLUMNS,
}

__all__ = [
    "AccessToken",
    "Base",
    "IMMUTABLE_TABLES",
    "PARTIALLY_MUTABLE_TABLES",
    "EVIDENCE_CHILD_TABLES",
    "RISK_SCORES_MUTABLE_COLUMNS",
    "AuditEvent",
    "Brand",
    "BrandDomain",
    "BrandFingerprint",
    "Config",
    "Campaign",
    "CampaignEdge",
    "CampaignNode",
    "Candidate",
    "CandidateSource",
    "Observation",
    "DnsObservation",
    "Evidence",
    "HtmlSnapshot",
    "HttpResponse",
    "ReputationObservation",
    "Screenshot",
    "SslObservation",
    "WhoisObservation",
    "AnalystLabel",
    "Finding",
    "FindingEvidence",
    "FindingNote",
    "IntelLookup",
    "Ioc",
    "ScanEventRecord",
    "ScanJob",
    "ScanStage",
    "Asn",
    "Certificate",
    "Domain",
    "Hostname",
    "IpAddress",
    "Nameserver",
    "Registrar",
    "Url",
    "Report",
    "TakedownDraft",
    "ApiKey",
    "ApiProvider",
    "ApiUsage",
    "RiskScore",
    "RiskScoreVersion",
    "RuleVersion",
    "User",
    "Workspace",
]
