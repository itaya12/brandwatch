"""Campaigns & Attribution API (spec §14 tab 5, §10 IOC export), Phase 4."""

from __future__ import annotations

import json
import uuid
from typing import Annotated, Any

import sqlalchemy as sa
from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response, status
from pydantic import BaseModel
from sqlalchemy.orm import Session

from brandwatch.api.auth import audit, current_user, require_analyst
from brandwatch.api.deps import get_session
from brandwatch.api.findings import _get_finding
from brandwatch.db.enums import FindingState, IocType, JobState
from brandwatch.db.models import (
    Brand,
    Campaign,
    CampaignEdge,
    CampaignNode,
    Candidate,
    Finding,
    Ioc,
    ScanJob,
    User,
)
from brandwatch.detection import investigation as inv
from brandwatch.detection import regions as regions_mod

router = APIRouter(prefix="/api", tags=["campaigns"])


def _get_campaign(session: Session, user: User, campaign_id: uuid.UUID) -> Campaign:
    c = session.get(Campaign, campaign_id)
    brand = session.get(Brand, c.brand_id) if c else None
    if c is None or brand is None or brand.workspace_id != user.workspace_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "campaign not found")
    return c


def latest_map_job(session: Session, finding_id: uuid.UUID) -> ScanJob | None:
    """The newest infrastructure-mapping job of a finding (any state)."""
    return session.scalars(
        sa.select(ScanJob)
        .where(
            ScanJob.kind == "investigate",
            ScanJob.payload["finding_id"].as_string() == str(finding_id),
        )
        .order_by(ScanJob.created_at.desc())
        .limit(1)
    ).first()


def start_map_job(
    session: Session, request: Request, user: User, f: Finding, *, auto: bool = False, defer: bool = False
) -> dict[str, Any]:
    """Enqueue the attack-infrastructure mapping of a confirmed finding; a job that is already
    queued/running for it is reused instead of started twice."""
    running = latest_map_job(session, f.id)
    if running is not None and running.state in (JobState.QUEUED, JobState.RUNNING):
        return {"job_id": str(running.id), "kind": "investigate", "reused": True}
    audit(session, workspace_id=user.workspace_id, actor_type="system" if auto else "analyst", actor_id=user.id,
          action="investigation.started", object_type="finding", object_id=f.id,
          new={"auto": auto})  # fmt: skip

    def go() -> dict[str, Any]:
        job_id = request.app.state.queue.enqueue(
            "investigate",
            {"finding_id": str(f.id), "requested_by": str(user.id), "auto": auto},
            workspace_id=user.workspace_id,
            brand_id=f.brand_id,
        )
        return {"job_id": str(job_id), "kind": "investigate"}

    if defer:  # see api.intel.start_intel_job
        return {"defer": go}
    session.commit()
    return go()


@router.post("/findings/{finding_id}/investigate", status_code=status.HTTP_202_ACCEPTED)
def investigate_finding(
    finding_id: uuid.UUID,
    request: Request,
    session: Annotated[Session, Depends(get_session, scope="function")],
    user: Annotated[User, Depends(require_analyst)],
) -> dict[str, Any]:
    """Analyst-triggered; also started automatically on confirm when the brand allows it."""
    f = _get_finding(session, user, finding_id)
    if f.state is not FindingState.CONFIRMED:
        raise HTTPException(
            status.HTTP_409_CONFLICT, "investigation starts from a confirmed finding"
        )
    return start_map_job(session, request, user, f)


def _confirmed(session: Session, user: User, brand_id: uuid.UUID | None) -> list[Finding]:
    q = (
        sa.select(Finding).join(Brand, Brand.id == Finding.brand_id)
        .where(Brand.workspace_id == user.workspace_id, Finding.state == FindingState.CONFIRMED, Finding.kind != "ai_answer")  # a contact is not a site
    )  # fmt: skip
    if brand_id:
        q = q.where(Finding.brand_id.in_(regions_mod.with_regions(session, brand_id)))
    return list(session.scalars(q.order_by(Finding.updated_at.desc())).all())


class AllRequest(BaseModel):
    brand_id: uuid.UUID | None = None
    remap: bool = False  # map the sites that already have a map again (infrastructure changes)


@router.post("/campaigns/map-all", status_code=status.HTTP_202_ACCEPTED)
def map_all(
    request: Request, session: Annotated[Session, Depends(get_session, scope="function")],
    user: Annotated[User, Depends(require_analyst)], body: AllRequest | None = None,
) -> dict[str, Any]:  # fmt: skip
    """MAP ALL: the attack-infrastructure map of every confirmed site that has none, one after the other, in one batch job. A
    batch that is already running is reused."""
    body = body or AllRequest()
    running = session.scalars(
        sa.select(ScanJob).where(ScanJob.workspace_id == user.workspace_id, ScanJob.kind == "map_all",
                                 ScanJob.state.in_([JobState.QUEUED, JobState.RUNNING])).order_by(ScanJob.created_at.desc())
    ).first()  # fmt: skip
    if running is not None:
        return {"job_id": str(running.id), "kind": "map_all", "reused": True, "count": len((running.payload or {}).get("finding_ids", []))}
    todo = []
    for f in _confirmed(session, user, body.brand_id):
        mj = latest_map_job(session, f.id)
        if mj is not None and mj.state in (JobState.QUEUED, JobState.RUNNING):
            continue  # being mapped right now
        if f.campaign_id is None or body.remap:
            todo.append(f)
    if not todo:
        return {"job_id": None, "kind": "map_all", "count": 0}
    audit(session, workspace_id=user.workspace_id, actor_type="analyst", actor_id=user.id, action="investigation.map_all",
          object_type="workspace", object_id=user.workspace_id, new={"count": len(todo), "remap": body.remap})  # fmt: skip
    session.commit()
    job_id = request.app.state.queue.enqueue(
        "map_all", {"finding_ids": [str(f.id) for f in todo], "requested_by": str(user.id), "remap": body.remap},
        workspace_id=user.workspace_id, brand_id=body.brand_id,
    )  # fmt: skip
    return {"job_id": str(job_id), "kind": "map_all", "count": len(todo)}


@router.post("/campaigns/investigate-all", status_code=status.HTTP_202_ACCEPTED)
def investigate_all(
    request: Request, session: Annotated[Session, Depends(get_session, scope="function")],
    user: Annotated[User, Depends(require_analyst)], body: AllRequest | None = None,
) -> dict[str, Any]:  # fmt: skip
    """INVESTIGATE ALL: "Investigate site and its network" (the quick one, with the evidence package at its end) for every confirmed
    site that has no investigation yet. They queue: three at a time, sharing VirusTotal's quota."""
    from brandwatch.api.intel import start_intel_job
    from brandwatch.detection import intel as intel_mod

    body = body or AllRequest()
    plans, hosts = [], []
    for f in _confirmed(session, user, body.brand_id):
        cand = session.get(Candidate, f.candidate_id)
        if not body.remap and intel_mod.intel_view(session, user.workspace_id, cand.hostname).get("fetched_at") is not None:
            continue  # already investigated
        plan = start_intel_job(session, request, user, f, light=True, package=True, auto=True, defer=True)
        if "defer" in plan:
            plans.append(plan["defer"])
            hosts.append(cand.hostname)
    session.commit()
    jobs = [go()["job_id"] for go in plans]
    return {"kind": "intel", "count": len(jobs), "job_ids": jobs, "hosts": hosts}


class ReverseRequest(BaseModel):
    kind: str
    value: str
    brand_id: uuid.UUID | None = None


@router.post("/campaigns/reverse-search")
def reverse_search(
    request: Request, body: ReverseRequest, session: Annotated[Session, Depends(get_session, scope="function")],
    user: Annotated[User, Depends(require_analyst)],
) -> dict[str, Any]:  # fmt: skip
    """"Search for more": who else uses this traffic-distribution campaign / sends data to this host? One urlscan.io search, cached 24 h."""
    import asyncio

    from brandwatch import keys as keystore
    from brandwatch.detection import reverse_search as rs
    from brandwatch.detection.baseline import brand_key_for
    from brandwatch.providers.registry import ProviderRegistry

    if body.kind not in rs.SEARCHABLE:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, "this kind of link cannot be searched backwards")
    settings = request.app.state.settings
    own = {c.hostname for c in (session.get(Candidate, f.candidate_id) for f in _confirmed(session, user, body.brand_id)) if c}
    brand = session.get(Brand, body.brand_id) if body.brand_id else None
    providers = ProviderRegistry(settings, key_overrides=keystore.load_keys(session, user.workspace_id, settings))
    session.commit()  # no write lock while urlscan.io answers
    result = asyncio.run(rs.search(providers, body.kind, body.value, own=own, brand_key=brand_key_for(brand, session) if brand else ""))
    rs.store(session, user.workspace_id, body.kind, body.value, result)
    audit(session, workspace_id=user.workspace_id, actor_type="analyst", actor_id=user.id, action="campaign.reverse_search",
          object_type="workspace", object_id=user.workspace_id, new={"kind": body.kind, "value": body.value, "found": len(result["sites"])})  # fmt: skip
    return result


class ExcludeRequest(BaseModel):
    kind: str
    value: str | None = None  # None: the whole kind
    exclude: bool = True  # False: bring it back


@router.post("/campaigns/map-exclude")
def map_exclude(
    body: ExcludeRequest, session: Annotated[Session, Depends(get_session, scope="function")], user: Annotated[User, Depends(require_analyst)],
) -> dict[str, Any]:  # fmt: skip
    """Exclude (or restore) a kind of link, or one value, from the map of all confirmed sites: "this is no evidence of a connection"."""
    from brandwatch.detection.all_map import set_map_exclude

    try:
        out = set_map_exclude(session, user.workspace_id, body.kind, body.value, body.exclude)
    except ValueError as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, str(exc)) from exc
    audit(session, workspace_id=user.workspace_id, actor_type="analyst", actor_id=user.id, action="campaign.map_exclude", object_type="workspace",
          object_id=user.workspace_id, new={"kind": body.kind, "value": body.value, "exclude": body.exclude})  # fmt: skip
    return out


class ReassessRequest(BaseModel):
    brand_id: uuid.UUID | None = None


@router.post("/campaigns/reassess-redirects")
def reassess_redirects(
    body: ReassessRequest, session: Annotated[Session, Depends(get_session, scope="function")], user: Annotated[User, Depends(require_analyst)],
) -> dict[str, Any]:  # fmt: skip
    """Look again, from the saved evidence only (nothing is fetched), at the confirmed sites whose visit ends on the brand's own site: they are not
    phishing pages, so the signals that came from the page being the real one go, and an affiliate id or a third-party redirect host in the chain
    is rated for what it is."""
    from brandwatch import tenancy
    from brandwatch.detection import redirects

    changed: list[dict[str, str]] = []
    for bid in sorted({f.brand_id for f in _confirmed(session, user, body.brand_id)}, key=str):
        cfg = tenancy.effective_brand_config(session, bid)
        changed += redirects.reassess(session, bid, cfg.scoring, actor=user)
    audit(session, workspace_id=user.workspace_id, actor_type="analyst", actor_id=user.id, action="campaign.reassess_redirects", object_type="workspace",
          object_id=user.workspace_id, new={"changed": len(changed)})  # fmt: skip
    return {"changed": changed, "count": len(changed)}


@router.get("/campaigns/all-map")
def all_map(
    session: Annotated[Session, Depends(get_session, scope="function")], user: Annotated[User, Depends(current_user)],
    brand_id: uuid.UUID | None = None,
) -> dict[str, Any]:  # fmt: skip
    """Every confirmed site on one map: which of them are connected, and by what (a shared server, certificate, analytics ID or registrant)."""
    from brandwatch.detection.all_map import build_all_map

    return build_all_map(session, user.workspace_id, _confirmed(session, user, brand_id))


@router.get("/campaigns")
def list_campaigns(
    session: Annotated[Session, Depends(get_session, scope="function")],
    user: Annotated[User, Depends(current_user)],
    brand_id: uuid.UUID | None = None,
    limit: int = Query(default=100, ge=1, le=500),
) -> list[dict[str, Any]]:
    q = (
        sa.select(Campaign)
        .join(Brand, Brand.id == Campaign.brand_id)
        .where(Brand.workspace_id == user.workspace_id)
    )
    if brand_id:
        q = q.where(Campaign.brand_id.in_(regions_mod.with_regions(session, brand_id)))
    rows = session.scalars(q.order_by(Campaign.created_at.desc()).limit(limit)).all()
    out = []
    for c in rows:
        d = inv.campaign_out(session, c)
        out.append(
            {k: d[k] for k in ("id", "brand_id", "name", "created_at", "stats", "findings")}
            | {"actor_profile": d["actor_profile"]}
        )
    return out


@router.get("/campaigns/{campaign_id}")
def get_campaign(
    campaign_id: uuid.UUID,
    session: Annotated[Session, Depends(get_session, scope="function")],
    user: Annotated[User, Depends(current_user)],
) -> dict[str, Any]:
    return inv.campaign_out(session, _get_campaign(session, user, campaign_id))


@router.delete("/campaigns/{campaign_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_campaign(
    campaign_id: uuid.UUID,
    session: Annotated[Session, Depends(get_session, scope="function")],
    user: Annotated[User, Depends(require_analyst)],
) -> Response:
    """Remove an infrastructure map. Findings and IOCs stay (they are unlinked), so the analyst
    can re-run the investigation from a confirmed finding and start the campaign over."""
    camp = session.get(Campaign, campaign_id)
    brand = session.get(Brand, camp.brand_id) if camp is not None else None
    if camp is None or brand is None or brand.workspace_id != user.workspace_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "campaign not found")
    unlinked = session.execute(
        sa.update(Finding).where(Finding.campaign_id == camp.id).values(campaign_id=None)
    ).rowcount
    session.execute(sa.update(Ioc).where(Ioc.campaign_id == camp.id).values(campaign_id=None))
    session.execute(sa.delete(CampaignEdge).where(CampaignEdge.campaign_id == camp.id))
    nodes = session.execute(
        sa.delete(CampaignNode).where(CampaignNode.campaign_id == camp.id)
    ).rowcount
    name = camp.name
    session.delete(camp)
    audit(
        session, workspace_id=user.workspace_id, actor_type="analyst", actor_id=user.id,
        action="campaign.deleted", object_type="campaign", object_id=campaign_id,
        old={"name": name, "nodes": int(nodes), "findings_unlinked": int(unlinked)},
    )  # fmt: skip
    session.flush()
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.get("/iocs")
def list_iocs(
    session: Annotated[Session, Depends(get_session, scope="function")],
    user: Annotated[User, Depends(current_user)],
    brand_id: uuid.UUID | None = None,
    campaign_id: uuid.UUID | None = None,
    finding_id: uuid.UUID | None = None,
    type: IocType | None = None,  # noqa: A002
    format: str = Query(default="json", pattern="^(json|csv|stix)$"),  # noqa: A002
    limit: int = Query(default=5000, ge=1, le=20000),
):
    q = sa.select(Ioc).where(Ioc.workspace_id == user.workspace_id)
    if campaign_id:
        q = q.where(Ioc.campaign_id == campaign_id)
    if finding_id:
        q = q.where(Ioc.finding_id == finding_id)
    if brand_id:
        q = q.join(Finding, Finding.id == Ioc.finding_id).where(Finding.brand_id.in_(regions_mod.with_regions(session, brand_id)))
    if type:
        q = q.where(Ioc.type == type)
    rows = session.scalars(q.order_by(Ioc.type, Ioc.value).limit(limit)).all()
    if format == "csv":
        return Response(
            inv.iocs_csv(rows),
            media_type="text/csv",
            headers={"Content-Disposition": 'attachment; filename="brandwatch-iocs.csv"'},
        )
    if format == "stix":
        campaign = session.get(Campaign, campaign_id) if campaign_id else None
        brand = session.get(Brand, campaign.brand_id) if campaign else None
        bundle = inv.stix_bundle(session, rows, campaign, brand)
        return Response(json.dumps(bundle, indent=2), media_type="application/stix+json",
                        headers={"Content-Disposition": 'attachment; filename="brandwatch-iocs.stix.json"'})  # fmt: skip
    return [
        {"id": str(i.id), "type": i.type.value, "value": i.value, "first_seen": i.first_seen.isoformat() if i.first_seen else None,
         "finding_id": str(i.finding_id) if i.finding_id else None, "campaign_id": str(i.campaign_id) if i.campaign_id else None,
         "source_evidence_id": str(i.source_evidence_id) if i.source_evidence_id else None}
        for i in rows
    ]  # fmt: skip
