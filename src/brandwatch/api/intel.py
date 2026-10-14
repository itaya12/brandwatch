"""Site & network intel API: start / read the VirusTotal-style investigation of a finding or an IP."""

from __future__ import annotations

import ipaddress
import uuid
from typing import Annotated, Any

import sqlalchemy as sa
from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from brandwatch.api.auth import audit, current_user, require_analyst
from brandwatch.api.deps import get_session
from brandwatch.api.findings import _get_finding
from brandwatch.db.enums import JobState
from brandwatch.db.models import Candidate, ScanJob, User
from brandwatch.detection import intel as intel_mod

router = APIRouter(prefix="/api", tags=["intel"])


def _latest_job(session: Session, ws: uuid.UUID, subject_key: str, subject: str) -> ScanJob | None:
    jobs = session.scalars(
        sa.select(ScanJob).where(ScanJob.workspace_id == ws, ScanJob.kind == "intel")
        .order_by(ScanJob.created_at.desc()).limit(25)
    ).all()  # fmt: skip
    return next((j for j in jobs if str((j.payload or {}).get(subject_key)) == subject), None)


def _job_out(job: ScanJob | None) -> dict[str, Any] | None:
    if job is None:
        return None
    return {"id": str(job.id), "state": job.state.value, "created_at": job.created_at.isoformat() if job.created_at else None,
            "finished_at": job.finished_at.isoformat() if job.finished_at else None, "error": job.error,
            "light": bool((job.payload or {}).get("light")), "package": bool((job.payload or {}).get("package"))}  # fmt: skip


def _running(job: ScanJob | None) -> bool:
    return job is not None and job.state in (JobState.QUEUED, JobState.RUNNING)


def start_intel_job(
    session: Session, request: Request, user: User, f: Any, *, force: bool = False, light: bool = False, package: bool = False,
    auto: bool = False, defer: bool = False,
) -> dict[str, Any]:  # fmt: skip
    """Start the investigation of a finding's site and network (or join the one that is running). ``light``: the quick one
    that follows a confirmation; ``package``: build the evidence package from it when it ends."""
    existing = _latest_job(session, user.workspace_id, "finding_id", str(f.id))
    if _running(existing):
        if package and not (existing.payload or {}).get("package"):  # it is running already: it gets the package step too
            existing.payload = {**(existing.payload or {}), "package": True}
            session.flush()
        return {"job_id": str(existing.id), "kind": "intel", "reused": True}
    audit(session, workspace_id=user.workspace_id, actor_type="system" if auto else "analyst", actor_id=None if auto else user.id,
          action="intel.started", object_type="finding", object_id=f.id,
          new={"force": force, "light": light, "package": package, "auto": auto})  # fmt: skip

    def go() -> dict[str, Any]:
        job_id = request.app.state.queue.enqueue(
            "intel", {"finding_id": str(f.id), "force": force, "light": light, "package": package, "requested_by": str(user.id)},
            workspace_id=user.workspace_id, brand_id=f.brand_id,
        )  # fmt: skip
        return {"job_id": str(job_id), "kind": "intel"}

    if defer:  # the caller starts several jobs: it commits once, then calls ``go`` for each (a job thread that is already writing
        return {"defer": go}  # would make a later commit of the request wait or fail)
    session.commit()
    return go()


@router.post("/findings/{finding_id}/intel", status_code=status.HTTP_202_ACCEPTED)
def start_finding_intel(
    finding_id: uuid.UUID, request: Request,
    session: Annotated[Session, Depends(get_session, scope="function")], user: Annotated[User, Depends(require_analyst)],
    force: bool = False,
) -> dict[str, Any]:  # fmt: skip
    return start_intel_job(session, request, user, _get_finding(session, user, finding_id), force=force)


@router.get("/findings/{finding_id}/intel")
def finding_intel(
    finding_id: uuid.UUID, session: Annotated[Session, Depends(get_session, scope="function")],
    user: Annotated[User, Depends(current_user)],
) -> dict[str, Any]:  # fmt: skip
    f = _get_finding(session, user, finding_id)
    cand = session.get(Candidate, f.candidate_id)
    view = intel_mod.intel_view(session, user.workspace_id, cand.hostname, url=cand.canonical_url)
    view["job"] = _job_out(_latest_job(session, user.workspace_id, "finding_id", str(f.id)))
    view["finding"] = {"id": str(f.id), "state": f.state.value, "severity": f.severity.value}
    if view["fetched_at"] is not None:
        view["fetched_at"] = view["fetched_at"].isoformat()
    for ip in view["ips"]:
        if ip.get("fetched_at") is not None:
            ip["fetched_at"] = ip["fetched_at"].isoformat()
    return view


_DOC_NETS = tuple(
    ipaddress.ip_network(n) for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")
)


def _check_ip(ip: str, demo_mode: bool = False) -> str:
    """Public IPs only (the SSRF block list). The demo fixtures live in the unroutable TEST-NET
    documentation ranges, which demo mode lets through — nothing is ever connected to in demo."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "not an IP address") from exc
    from brandwatch.security.fetcher_guard import is_blocked_ip

    if demo_mode and any(addr in n for n in _DOC_NETS):
        return str(addr)
    if is_blocked_ip(addr):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "only public IPs can be investigated")
    return str(addr)


@router.post("/intel/ip/{ip}", status_code=status.HTTP_202_ACCEPTED)
def start_ip_intel(
    ip: str, request: Request, session: Annotated[Session, Depends(get_session, scope="function")],
    user: Annotated[User, Depends(require_analyst)], force: bool = False,
) -> dict[str, Any]:  # fmt: skip
    ip = _check_ip(ip, request.app.state.settings.demo_mode)
    existing = _latest_job(session, user.workspace_id, "ip", ip)
    if _running(existing):
        return {"job_id": str(existing.id), "kind": "intel", "reused": True}
    audit(session, workspace_id=user.workspace_id, actor_type="analyst", actor_id=user.id,
          action="intel.started", object_type="ip", object_id=None, new={"ip": ip, "force": force})  # fmt: skip
    session.commit()
    job_id = request.app.state.queue.enqueue(
        "intel",
        {"ip": ip, "force": force, "requested_by": str(user.id)},
        workspace_id=user.workspace_id,
    )
    return {"job_id": str(job_id), "kind": "intel"}


@router.get("/intel/ip/{ip}")
def ip_intel(
    ip: str, request: Request, session: Annotated[Session, Depends(get_session, scope="function")],
    user: Annotated[User, Depends(current_user)],
) -> dict[str, Any]:  # fmt: skip
    ip = _check_ip(ip, request.app.state.settings.demo_mode)
    view = intel_mod.intel_view(session, user.workspace_id, None, [ip])
    view["job"] = _job_out(_latest_job(session, user.workspace_id, "ip", ip))
    for item in view["ips"]:
        if item.get("fetched_at") is not None:
            item["fetched_at"] = item["fetched_at"].isoformat()
    return view
