"""Deep links for the How-it-works page: one real object per pipeline stage, resolved from the
workspace's own data so every "see it →" opens something interesting (a cloaked kit, a mapped
attacker, a sent takedown) instead of an empty list."""

from __future__ import annotations

from typing import Any

import sqlalchemy as sa
from sqlalchemy.orm import Session

from brandwatch.db.enums import FindingState, JobState
from brandwatch.db.models import Brand, Campaign, Finding, RiskScore, ScanJob, TakedownDraft, User


def tour_stops(session: Session, user: User) -> dict[str, str | None]:
    ws = user.workspace_id
    brand = session.scalars(
        sa.select(Brand).where(Brand.workspace_id == ws).order_by((Brand.name == "ShopNova").desc(), Brand.created_at)
    ).first()  # fmt: skip
    out: dict[str, Any] = {
        k: None
        for k in ("brand", "scan", "cloaked", "open", "confirmed", "intel", "campaign", "takedown")
    }
    if brand is None:
        return out
    out["brand"] = f"/ui/brands/{brand.id}"
    job = session.scalars(
        sa.select(ScanJob).where(ScanJob.brand_id == brand.id, ScanJob.kind == "brand_scan", ScanJob.state == JobState.DONE)
        .order_by(ScanJob.created_at.desc())
    ).first()  # fmt: skip
    out["scan"] = f"/ui/jobs/{job.id}" if job else None
    cur = (
        sa.select(Finding, RiskScore.signals)
        .join(
            RiskScore, sa.and_(RiskScore.finding_id == Finding.id, RiskScore.is_current.is_(True))
        )
        .where(Finding.brand_id == brand.id)
    )
    rows = session.execute(cur.order_by(RiskScore.score.desc())).all()
    for f, sigs in rows:
        if (
            out["cloaked"] is None
            and f.state is not FindingState.DISMISSED
            and any(k.startswith("cloaking_") for k in (sigs or {}))
        ):
            out["cloaked"] = f"/ui/findings/{f.id}"
        if out["open"] is None and f.state is FindingState.OPEN:
            out["open"] = f"/ui/findings/{f.id}"
        if out["confirmed"] is None and f.state is FindingState.CONFIRMED:
            out["confirmed"] = f"/ui/findings/{f.id}"
    pick = out["cloaked"] or out["open"] or out["confirmed"]
    out["intel"] = f"{pick}#reputation" if pick else None
    camp = session.scalars(
        sa.select(Campaign)
        .where(Campaign.brand_id == brand.id)
        .order_by(Campaign.created_at.desc())
    ).first()
    out["campaign"] = f"/ui/campaigns/{camp.id}" if camp else None
    td = session.scalars(
        sa.select(TakedownDraft).join(Finding, Finding.id == TakedownDraft.finding_id)
        .where(Finding.brand_id == brand.id).order_by(TakedownDraft.updated_at.desc())
    ).first()  # fmt: skip
    out["takedown"] = f"/ui/takedowns/{td.id}" if td else None
    return out
