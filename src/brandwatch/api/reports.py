"""Reports & Takedowns API (spec §14, Phase 2): evidence packages and takedown drafts.

Human in the loop by construction: drafts are created only for **confirmed** findings, are fully
editable, move through the case-management state machine by explicit analyst actions, and the
system never sends anything.
"""

from __future__ import annotations

import uuid
from typing import Annotated, Any

import sqlalchemy as sa
from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from brandwatch.api.auth import current_user, require_analyst
from brandwatch.api.deps import get_session
from brandwatch.api.findings import _get_finding, finding_detail
from brandwatch.db.enums import FindingState, TakedownState
from brandwatch.db.models import Brand, Finding, Report, TakedownDraft, User
from brandwatch.detection import regions as regions_mod
from brandwatch.detection import reports as reports_svc

router = APIRouter(prefix="/api", tags=["reports"])


class TakedownEdit(BaseModel):
    body: str | None = Field(default=None, max_length=20000)
    abuse_contact: str | None = Field(default=None, max_length=320)


class TakedownTransition(BaseModel):
    to: TakedownState
    reason: str = Field(default="", max_length=2000)


def _report_out(r: Report) -> dict[str, Any]:
    return {
        "id": str(r.id),
        "finding_id": str(r.finding_id) if r.finding_id else None,
        "kind": r.kind,
        "format": r.format,
        "url": f"/api/reports/{r.id}",
        "created_at": r.created_at.isoformat(),
    }


# ------------------------------------------------------------------------------------------
# evidence packages
# ------------------------------------------------------------------------------------------
@router.post("/findings/{finding_id}/report", status_code=status.HTTP_201_CREATED)
def generate_report(
    finding_id: uuid.UUID,
    request: Request,
    session: Annotated[Session, Depends(get_session, scope="function")],
    user: Annotated[User, Depends(require_analyst)],
) -> dict[str, Any]:
    f = _get_finding(session, user, finding_id)
    detail = finding_detail(session, f)
    reports = reports_svc.build_evidence_package(
        session, f, detail, request.app.state.store, actor=user
    )
    for r in reports.values():
        r.finding_id = f.id
    session.flush()
    return {fmt: _report_out(r) for fmt, r in reports.items()}


@router.get("/findings/{finding_id}/reports")
def list_reports(
    finding_id: uuid.UUID,
    session: Annotated[Session, Depends(get_session, scope="function")],
    user: Annotated[User, Depends(current_user)],
) -> list[dict[str, Any]]:
    f = _get_finding(session, user, finding_id)
    rows = session.scalars(
        sa.select(Report).where(Report.finding_id == f.id).order_by(Report.created_at.desc())
    ).all()
    return [_report_out(r) for r in rows]


@router.get("/reports/{report_id}")
def download_report(
    report_id: uuid.UUID,
    request: Request,
    session: Annotated[Session, Depends(get_session, scope="function")],
    user: Annotated[User, Depends(current_user)],
) -> Response:
    r = session.get(Report, report_id)
    brand = session.get(Brand, r.brand_id) if r else None
    if r is None or brand is None or brand.workspace_id != user.workspace_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "report not found")
    store = request.app.state.store
    if not store.exists(r.path):
        raise HTTPException(status.HTTP_404_NOT_FOUND, "report artifact missing")
    media = {
        "html": "text/html; charset=utf-8",
        "json": "application/json",
        "md": "text/markdown",
    }.get(r.format, "application/octet-stream")
    name = f"brandwatch-{r.kind}-{str(r.finding_id or r.id)[:8]}.{r.format}"
    return Response(
        content=store.get(r.path), media_type=media,
        headers={"Content-Disposition": f'inline; filename="{name}"'},
    )  # fmt: skip


# ------------------------------------------------------------------------------------------
# takedown drafts
# ------------------------------------------------------------------------------------------
def _get_draft(session: Session, user: User, draft_id: uuid.UUID) -> TakedownDraft:
    d = session.get(TakedownDraft, draft_id)
    f = session.get(Finding, d.finding_id) if d else None
    brand = session.get(Brand, f.brand_id) if f else None
    if d is None or brand is None or brand.workspace_id != user.workspace_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "takedown draft not found")
    return d


@router.post("/findings/{finding_id}/takedown", status_code=status.HTTP_201_CREATED)
def create_takedown(
    finding_id: uuid.UUID,
    session: Annotated[Session, Depends(get_session, scope="function")],
    user: Annotated[User, Depends(require_analyst)],
) -> dict[str, Any]:
    f = _get_finding(session, user, finding_id)
    if f.state is not FindingState.CONFIRMED:
        raise HTTPException(
            status.HTTP_409_CONFLICT, "takedown drafts are created for confirmed findings only"
        )
    existing = session.scalars(
        sa.select(TakedownDraft)
        .where(TakedownDraft.finding_id == f.id, TakedownDraft.state.notin_([TakedownState.REJECTED, TakedownState.RESOLVED]))
    ).first()  # fmt: skip
    if existing is not None:
        return reports_svc.takedown_out(existing, session)
    draft = reports_svc.create_takedown_draft(session, f, finding_detail(session, f), actor=user)
    return reports_svc.takedown_out(draft, session)


@router.get("/findings/{finding_id}/takedowns")
def list_finding_takedowns(
    finding_id: uuid.UUID,
    session: Annotated[Session, Depends(get_session, scope="function")],
    user: Annotated[User, Depends(current_user)],
) -> list[dict[str, Any]]:
    f = _get_finding(session, user, finding_id)
    rows = session.scalars(
        sa.select(TakedownDraft)
        .where(TakedownDraft.finding_id == f.id)
        .order_by(TakedownDraft.created_at.desc())
    ).all()
    return [reports_svc.takedown_out(d, session) for d in rows]


@router.get("/takedowns")
def list_takedowns(
    session: Annotated[Session, Depends(get_session, scope="function")],
    user: Annotated[User, Depends(current_user)],
    brand_id: uuid.UUID | None = None,
    state: TakedownState | None = None,
    limit: int = Query(default=200, ge=1, le=1000),
) -> list[dict[str, Any]]:
    q = (
        sa.select(TakedownDraft)
        .join(Finding, Finding.id == TakedownDraft.finding_id)
        .join(Brand, Brand.id == Finding.brand_id)
        .where(Brand.workspace_id == user.workspace_id)
    )
    if brand_id:
        q = q.where(Finding.brand_id.in_(regions_mod.with_regions(session, brand_id)))
    if state:
        q = q.where(TakedownDraft.state == state)
    rows = session.scalars(q.order_by(TakedownDraft.updated_at.desc()).limit(limit)).all()
    return [reports_svc.takedown_out(d, session) for d in rows]


@router.get("/takedowns/{draft_id}")
def get_takedown(
    draft_id: uuid.UUID,
    session: Annotated[Session, Depends(get_session, scope="function")],
    user: Annotated[User, Depends(current_user)],
) -> dict[str, Any]:
    return reports_svc.takedown_out(_get_draft(session, user, draft_id), session)


@router.patch("/takedowns/{draft_id}")
def edit_takedown(
    draft_id: uuid.UUID,
    body: TakedownEdit,
    session: Annotated[Session, Depends(get_session, scope="function")],
    user: Annotated[User, Depends(require_analyst)],
) -> dict[str, Any]:
    d = _get_draft(session, user, draft_id)
    try:
        reports_svc.update_takedown_body(
            session, d, actor=user, body=body.body, abuse_contact=body.abuse_contact
        )
    except ValueError as exc:
        raise HTTPException(status.HTTP_409_CONFLICT, str(exc)) from exc
    return reports_svc.takedown_out(d, session)


@router.post("/takedowns/{draft_id}/transition")
def transition_takedown(
    draft_id: uuid.UUID,
    body: TakedownTransition,
    session: Annotated[Session, Depends(get_session, scope="function")],
    user: Annotated[User, Depends(require_analyst)],
) -> dict[str, Any]:
    d = _get_draft(session, user, draft_id)
    try:
        reports_svc.transition_takedown(session, d, body.to, actor=user, reason=body.reason)
    except ValueError as exc:
        raise HTTPException(status.HTTP_409_CONFLICT, str(exc)) from exc
    return reports_svc.takedown_out(d, session)


class ChannelUpdate(BaseModel):
    channel: str = Field(min_length=3, max_length=80)  # registrar | cdn | hosting:<ip>
    contact: str | None = Field(default=None, max_length=254)
    sent: bool = False


@router.post("/takedowns/{draft_id}/channels")
def update_takedown_channel(
    draft_id: uuid.UUID,
    body: ChannelUpdate,
    session: Annotated[Session, Depends(get_session, scope="function")],
    user: Annotated[User, Depends(require_analyst)],
) -> dict[str, Any]:
    """Save a channel's abuse contact and/or record that the request was sent to it."""
    from brandwatch.detection import takedown_channels as tc

    d = _get_draft(session, user, draft_id)
    try:
        tc.record_channel(
            session, d, actor=user, channel=body.channel, contact=body.contact, sent=body.sent
        )
    except ValueError as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, str(exc)) from exc
    return reports_svc.takedown_out(d, session)


@router.post("/takedowns/{draft_id}/reports/{portal}")
def toggle_takedown_report(
    draft_id: uuid.UUID,
    portal: str,
    session: Annotated[Session, Depends(get_session, scope="function")],
    user: Annotated[User, Depends(require_analyst)],
) -> dict[str, Any]:
    """Tick / untick "reported to <portal>" (Google Safe Browsing, Netcraft, ESET …)."""
    from brandwatch.detection import takedown_channels as tc

    d = _get_draft(session, user, draft_id)
    try:
        tc.toggle_report(session, d, actor=user, portal=portal)
    except ValueError as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, str(exc)) from exc
    return reports_svc.takedown_out(d, session)
