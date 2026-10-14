"""The brand's own sites are never suspects.

Official domains and whitelisted partners / subsidiaries / known-legit domains (and their
subdomains) must never sit on the watchlist, be re-scanned, become a finding or be pulled into an
attacker's infrastructure map. The scan pre-filter already drops them at discovery; this module
covers every other door: infrastructure pivots, rows created before a domain was whitelisted, and
the scheduler.
"""

from __future__ import annotations

import uuid

import sqlalchemy as sa
from sqlalchemy.orm import Session

from brandwatch.db.enums import AnalystVerdict, CandidateState, FindingState
from brandwatch.db.models import AuditEvent, Brand, Candidate, Finding
from brandwatch.db.types import utcnow
from brandwatch.detection.baseline import whitelist_domains
from brandwatch.detection.normalize import pre_filter, whitelist_for


def protected_set(session: Session, brand_id: uuid.UUID) -> set[str]:
    """Official + whitelisted domains of the brand, each with its registrable domain."""
    return whitelist_for(whitelist_domains(session, brand_id))


def is_protected(host: str, protected: set[str]) -> bool:
    return bool(host) and not pre_filter(host, protected).keep


def dismiss_protected(session: Session, brand_id: uuid.UUID) -> list[str]:
    """Take every official / whitelisted host of the brand *and its family* off the watchlist, in every
    campaign of the family (idempotent): a country site added to one region is the brand's own site in all."""
    from brandwatch.detection.regions import family_ids

    hosts: list[str] = []
    for bid in family_ids(session, brand_id):
        hosts += _dismiss_one(session, bid)
    return hosts


def _dismiss_one(session: Session, brand_id: uuid.UUID) -> list[str]:
    protected = protected_set(session, brand_id)
    if not protected:
        return []
    brand = session.get(Brand, brand_id)
    hosts: list[str] = []
    for c in session.scalars(
        sa.select(Candidate).where(
            Candidate.brand_id == brand_id, Candidate.state != CandidateState.DISMISSED
        )
    ).all():
        if is_protected(c.hostname, protected):
            c.state = CandidateState.DISMISSED
            c.next_scan_at = None
            hosts.append(c.hostname)
            # an open finding on a host whitelisted afterwards must leave the work queue as well
            # (no analyst label: the whitelist was the decision, not a verdict on this page)
            for f in session.scalars(
                sa.select(Finding).where(
                    Finding.candidate_id == c.id, Finding.state == FindingState.OPEN
                )
            ).all():
                f.state = FindingState.DISMISSED
                f.analyst_verdict = AnalystVerdict.LEGITIMATE
                f.updated_at = utcnow()
                if brand is not None:
                    session.add(AuditEvent(
                        workspace_id=brand.workspace_id, actor_type="system", actor_id=None,
                        action="finding.dismissed", object_type="finding", object_id=f.id,
                        old_value={"state": "open"}, new_value={"state": "dismissed", "verdict": "legitimate"},
                        reason=f"{c.hostname} is official or whitelisted",
                    ))  # fmt: skip
    if hosts and brand is not None:
        session.add(
            AuditEvent(
                workspace_id=brand.workspace_id, actor_type="system", actor_id=None,
                action="candidate.dismissed", object_type="brand", object_id=brand_id,
                new_value={"hosts": hosts}, reason="official or whitelisted domain: never a suspect",
            )
        )  # fmt: skip
    session.flush()
    return hosts
