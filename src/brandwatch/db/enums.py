"""Every enumerated type in the schema (spec §21), defined once.

Models, the Alembic migration, pydantic schemas and the API all import from here so that
the set of valid values can never drift between layers.
"""

from __future__ import annotations

from enum import StrEnum


class UserRole(StrEnum):
    ADMIN = "admin"
    ANALYST = "analyst"
    VIEWER = "viewer"


class CandidateState(StrEnum):
    NEW = "new"
    WATCHING = "watching"
    ANALYZING = "analyzing"
    FLAGGED = "flagged"
    LONG_WATCH = "long_watch"
    DISMISSED = "dismissed"


class FindingState(StrEnum):
    OPEN = "open"
    CONFIRMED = "confirmed"
    DISMISSED = "dismissed"


class AnalystVerdict(StrEnum):
    PHISHING = "phishing"
    LEGITIMATE = "legitimate"
    SUSPICIOUS = "suspicious"
    UNKNOWN = "unknown"


class Severity(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Surface(StrEnum):
    NAME = "name"
    SUBDOMAIN = "subdomain"
    PATH = "path"
    CONTENT = "content"


class DiscoverySource(StrEnum):
    DNSTWIST = "dnstwist"
    COMBOSQUAT = "combosquat"
    LLM = "llm"
    CT = "ct"
    NRD = "nrd"
    SERPAPI = "serpapi"
    URLSCAN = "urlscan"
    URLHAUS = "urlhaus"
    PHISHTANK = "phishtank"
    LOGO_SEARCH = "logo_search"
    MANUAL = "manual"
    META_ADS = "meta_ads"  # an ad in Meta's Ad Library that links to the site
    SOCIAL = "social"  # a Facebook page / Instagram profile under the brand's name
    REDIRECT = "redirect"  # the address a flagged look-alike redirects its visitors to
    AI_ANSWER = "ai_answer"  # a contact an AI assistant gives for the brand (ChatGPT, Gemini, Google AI Mode)


class ScannerProfile(StrEnum):
    DATACENTER = "datacenter"
    RESIDENTIAL = "residential"
    MOBILE = "mobile"


class EvidenceType(StrEnum):
    SCREENSHOT = "screenshot"
    HTML = "html"
    HTTP = "http"
    DNS = "dns"
    WHOIS = "whois"
    SSL = "ssl"
    REPUTATION = "reputation"
    FAVICON = "favicon"
    CERTIFICATE = "certificate"
    KIT = "kit"


class ProviderStatus(StrEnum):
    """Standard provider verdict. ``UNKNOWN`` (e.g. VT not_found) is never 'clean'."""

    POSITIVE = "positive"
    NEGATIVE = "negative"
    UNKNOWN = "unknown"
    ERROR = "error"
    NOT_APPLICABLE = "not_applicable"


class EvidenceRole(StrEnum):
    PRIMARY = "primary"
    SUPPORTING = "supporting"
    CONTRADICTING = "contradicting"
    CONTEXT = "context"


class JobState(StrEnum):
    QUEUED = "queued"
    RUNNING = "running"
    DONE = "done"
    FAILED = "failed"
    CANCELLED = "cancelled"


class TakedownState(StrEnum):
    DRAFT = "draft"
    REVIEW = "review"
    APPROVED = "approved"
    SENT = "sent"
    ACKNOWLEDGED = "acknowledged"
    IN_PROGRESS = "in_progress"
    RESOLVED = "resolved"
    REJECTED = "rejected"
    REOPENED = "reopened"


class IocType(StrEnum):
    DOMAIN = "domain"
    HOSTNAME = "hostname"
    URL = "url"
    IP = "ip"
    ASN = "asn"
    CERT_FP = "cert_fp"
    FAVICON_HASH = "favicon_hash"
    SHA256 = "sha256"
    EMAIL = "email"
    TELEGRAM = "telegram"
    WALLET = "wallet"
    TRACKING_ID = "tracking_id"


class NodeType(StrEnum):
    DOMAIN = "domain"
    HOSTNAME = "hostname"
    IP = "ip"
    CERTIFICATE = "certificate"
    REGISTRANT = "registrant"
    TRACKING_ID = "tracking_id"


class EdgeType(StrEnum):
    PASSIVE_DNS = "passive_dns"
    FAVICON = "favicon"
    CERT = "cert"
    REVERSE_WHOIS = "reverse_whois"
    REVERSE_NS = "reverse_ns"
    TRACKING_ID = "tracking_id"


# Name of the DB enum type for each Python enum (used by models and the migration).
ENUM_TYPE_NAMES: dict[type[StrEnum], str] = {
    UserRole: "user_role",
    CandidateState: "candidate_state",
    FindingState: "finding_state",
    AnalystVerdict: "analyst_verdict",
    Severity: "severity",
    Surface: "surface",
    DiscoverySource: "discovery_source",
    ScannerProfile: "scanner_profile",
    EvidenceType: "evidence_type",
    ProviderStatus: "provider_status",
    EvidenceRole: "evidence_role",
    JobState: "job_state",
    TakedownState: "takedown_state",
    IocType: "ioc_type",
    NodeType: "node_type",
    EdgeType: "edge_type",
}
