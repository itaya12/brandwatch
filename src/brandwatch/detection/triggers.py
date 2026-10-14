"""Trigger engine (spec §6): observations emit events that decide the next action.

    favicon_changed        → deep_scan            (re-analyse with the real browser)
    page_hash_changed      → screenshot           (fresh capture + re-score)
    login_form_appeared    → high_priority        (priority bump + deep analysis)
    woke_up                → deep_scan + signal   (parked/dead → live content: 'woke_up_in_watch')
    went_offline           → watch                (keep observing; kits come and go)
    risk_high (≥ 70)       → reputation_refresh   (ask every reputation provider again)
    cloaking_suspected     → residential_probe    (Phase 5, Tier 4 gate)

Pure: ``evaluate`` compares the previous observation (+ its recorded meta) with the fresh
``CollectedEvidence`` and returns triggers; the runner applies the actions and emits events.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import sqlalchemy as sa
from sqlalchemy.orm import Session

from brandwatch.db.enums import EvidenceType, ScannerProfile
from brandwatch.db.models import Evidence, HtmlSnapshot, Observation
from brandwatch.detection.enrichment import CollectedEvidence

RISK_HIGH_THRESHOLD = 70

ACTIONS: dict[str, str] = {
    "favicon_changed": "deep_scan",
    "page_hash_changed": "screenshot",
    "login_form_appeared": "high_priority",
    "woke_up": "deep_scan",
    "went_offline": "watch",
    "risk_high": "reputation_refresh",
    "cloaking_suspected": "residential_probe",
}

PRIORITY_BUMP: dict[str, int] = {
    "login_form_appeared": 10,
    "woke_up": 6,
    "favicon_changed": 4,
    "page_hash_changed": 2,
}


@dataclass(frozen=True, slots=True)
class Trigger:
    name: str
    action: str
    detail: str


@dataclass(frozen=True, slots=True)
class PreviousState:
    """What the last observation looked like (None when this is the first look)."""

    content_hash: str | None
    alive: bool
    had_login_form: bool
    favicon_mmh3: int | None
    parked: bool

    @classmethod
    def load(cls, session: Session, candidate_id) -> PreviousState | None:
        obs = session.scalars(
            sa.select(Observation)
            .where(
                Observation.candidate_id == candidate_id,
                Observation.scanner_profile == ScannerProfile.DATACENTER,
            )
            .order_by(Observation.observed_at.desc())
        ).first()
        if obs is None:
            return None
        html_meta: dict[str, Any] = {}
        favicon_mmh3 = None
        parked = False
        # evidence written in the same run as that observation (same timestamp window)
        rows = session.scalars(
            sa.select(Evidence)
            .where(Evidence.candidate_id == candidate_id, Evidence.observed_at <= obs.observed_at)
            .order_by(Evidence.observed_at.desc())
            .limit(40)
        ).all()
        seen_types: set[EvidenceType] = set()
        for ev in rows:
            if ev.type in seen_types:
                continue
            seen_types.add(ev.type)
            if ev.type is EvidenceType.HTML:
                snap = session.get(HtmlSnapshot, ev.id)
                html_meta = (snap.meta or {}) if snap else {}
                parked = bool((ev.response_meta or {}).get("parked"))
            elif ev.type is EvidenceType.FAVICON:
                favicon_mmh3 = (ev.response_meta or {}).get("mmh3")
        return cls(
            content_hash=obs.content_hash,
            alive=obs.http_status is not None,
            had_login_form=bool(html_meta.get("credential_form")),
            favicon_mmh3=favicon_mmh3,
            parked=parked or (obs.http_status is not None and not obs.content_hash),
        )


def evaluate(
    prev: PreviousState | None, col: CollectedEvidence, *, risk_score: int | None = None
) -> list[Trigger]:
    out: list[Trigger] = []
    alive_now = col.liveness.alive and col.liveness.content_present
    has_login = bool(col.features and col.features.credential_form)

    if prev is not None:
        if (not prev.alive or prev.parked) and alive_now:
            out.append(
                Trigger(
                    "woke_up",
                    ACTIONS["woke_up"],
                    "candidate was dead/parked and now serves content",
                )
            )
        if prev.alive and not col.liveness.alive:
            out.append(
                Trigger("went_offline", ACTIONS["went_offline"], "candidate no longer resolves")
            )
        if prev.content_hash and col.content_sha256 and prev.content_hash != col.content_sha256:
            out.append(
                Trigger(
                    "page_hash_changed",
                    ACTIONS["page_hash_changed"],
                    f"content hash {prev.content_hash[:10]} → {col.content_sha256[:10]}",
                )
            )
        if not prev.had_login_form and has_login:
            out.append(
                Trigger(
                    "login_form_appeared",
                    ACTIONS["login_form_appeared"],
                    "a credential form appeared since the last observation",
                )
            )
        if (
            prev.favicon_mmh3 is not None
            and col.favicon_mmh3 is not None
            and prev.favicon_mmh3 != col.favicon_mmh3
        ):
            out.append(
                Trigger(
                    "favicon_changed",
                    ACTIONS["favicon_changed"],
                    f"favicon mmh3 {prev.favicon_mmh3} → {col.favicon_mmh3}",
                )
            )
    if risk_score is not None and risk_score >= RISK_HIGH_THRESHOLD:
        out.append(
            Trigger("risk_high", ACTIONS["risk_high"], f"risk {risk_score} ≥ {RISK_HIGH_THRESHOLD}")
        )
    if getattr(col, "cloaking_suspected", False):
        out.append(
            Trigger(
                "cloaking_suspected",
                ACTIONS["cloaking_suspected"],
                "scanner profile saw benign/empty content while red flags are present",
            )
        )
    return out


def priority_bump(triggers: list[Trigger]) -> int:
    return sum(PRIORITY_BUMP.get(t.name, 0) for t in triggers)
