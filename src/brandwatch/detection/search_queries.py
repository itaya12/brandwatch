"""Google search queries: the AI proposes, an analyst approves.

Every scan — and the scheduled scan every ``scan_interval_hours`` — searches Google for each query
in each search country, so the list is part of the brand's set-up and costs money every day. The
AI's list (written when the official site is fingerprinted) is only a *proposal*: Google search runs
with the list an analyst approved, never with an unreviewed one. Rebuilding the fingerprint later
produces a new proposal next to the approved list; it replaces nothing until someone approves it.

Stored in ``brands.profile["search"]``:
``{approved: [..], approved_at, approved_by, approved_version}`` — ``approved_version`` is the
fingerprint version the analyst saw, so a newer fingerprint with a different list is flagged.
A list set the old way (``detection.search_queries`` in the brand configuration) counts as approved.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from brandwatch.db.types import utcnow
from brandwatch.detection.ai import default_search_queries

MAX_QUERIES = 30
_CTRL = re.compile(r"[\x00-\x1f\x7f]")


def clean_queries(items: list[Any]) -> list[str]:
    """What an analyst typed, one query per item: trimmed, single spaces, lower-case, 2–100
    characters, no duplicates, any language ("און קלאוד מבצע" is a fine query in Israel)."""
    out: list[str] = []
    for raw in items:
        q = " ".join(_CTRL.sub(" ", str(raw or "")).split()).lower()[:100]
        if len(q) >= 2 and q not in out:
            out.append(q)
        if len(out) >= MAX_QUERIES:
            break
    return out


@dataclass
class QueryState:
    status: str  # "approved" | "configured" (old config field, counts as approved) | "pending"
    queries: list[str]  # what scans use; while pending, the proposal (not used for Google)
    proposal: list[str]
    proposal_source: str
    approved_at: str | None = None
    approved_by: str | None = None
    approved_version: int = 0
    new_proposal: bool = False  # the fingerprint was rebuilt and the AI now proposes another list
    added: list[str] = field(default_factory=list)  # in the new proposal, not in the approved list
    removed: list[str] = field(default_factory=list)

    @property
    def approved(self) -> bool:
        return self.status in ("approved", "configured")

    def as_dict(self) -> dict[str, Any]:
        return {
            "status": self.status, "approved": self.approved, "queries": self.queries,
            "proposal": self.proposal, "proposal_source": self.proposal_source,
            "approved_at": self.approved_at, "approved_by": self.approved_by,
            "approved_version": self.approved_version, "new_proposal": self.new_proposal,
            "added": self.added, "removed": self.removed,
        }  # fmt: skip

    def waiting_note(self) -> str:
        return (
            f"Google search is waiting for your approval — {len(self.proposal)} queries proposed "
            f"({self.proposal_source}). Approve or edit them on the brand page, under “Google search "
            "queries”; every scan after that (and the scheduled one) uses the approved list."
        )


def query_state(brand: Any, detection: Any, baseline: Any | None) -> QueryState:
    """Which Google queries this brand's scans use, and whether an analyst approved them."""
    key = getattr(baseline, "brand_key", None) or re.sub(r"[^a-z0-9]", "", getattr(brand, "search_name", brand.name).lower())
    if baseline is not None and baseline.search_queries:
        proposal = list(baseline.search_queries)
        source = f"AI, from the fingerprint of the official site (v{baseline.version})"
    else:
        proposal = default_search_queries(getattr(brand, "search_name", brand.name), key, getattr(brand, "kind", None))
        source = "the default list — the AI proposes its own when the official site is fingerprinted"
    saved = dict((brand.profile or {}).get("search") or {})
    approved = list(saved.get("approved") or [])
    if approved:
        version = int(saved.get("approved_version") or 0)
        newer = baseline is not None and baseline.version > version
        added = [q for q in proposal if q not in approved] if newer else []
        removed = [q for q in approved if q not in proposal] if newer else []
        return QueryState(
            "approved", approved, proposal, source, saved.get("approved_at"), saved.get("approved_by"),
            version, new_proposal=bool(newer and (added or removed)), added=added, removed=removed,
        )  # fmt: skip
    configured = list(getattr(detection, "search_queries", None) or [])
    if configured:
        return QueryState("configured", configured, proposal, source)
    return QueryState("pending", proposal, proposal, source)


def approve(brand: Any, queries: list[str], *, by: str, baseline_version: int) -> dict[str, Any]:
    """Save the approved list on the brand (the caller audits and commits)."""
    profile = dict(brand.profile or {})
    old = dict(profile.get("search") or {})
    profile["search"] = {
        "approved": queries, "approved_at": utcnow().isoformat(), "approved_by": by,
        "approved_version": baseline_version,
    }  # fmt: skip
    brand.profile = profile
    return old
