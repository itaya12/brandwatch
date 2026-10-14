"""UI: the server (IP) investigation page. A site's investigation lives on its finding page
(Reputation · Domain & registration · Hosting & network tabs); the old per-finding URL redirects there."""

from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import Depends, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlalchemy.orm import Session

from brandwatch.api import findings as findings_api
from brandwatch.api import intel as intel_api
from brandwatch.api.deps import get_session
from brandwatch.api.ui import _login_redirect, _render, router, templates, ui_user
from brandwatch.db.models import User
from brandwatch.detection import intel as intel_mod
from brandwatch.ui.flags import country_name, flag_img

templates.env.globals.update({"flag_img": flag_img, "country_name": country_name})


@router.get("/findings/{finding_id}/intel")
def finding_intel_page(
    finding_id: uuid.UUID, request: Request,
    session: Annotated[Session, Depends(get_session, scope="function")], user: Annotated[User | None, Depends(ui_user)],
):  # fmt: skip
    """Old links (bookmarks, evidence packages, the demo tour) land on the finding page's investigation tabs."""
    if user is None:
        return _login_redirect(request)
    f = findings_api._get_finding(session, user, finding_id)
    return RedirectResponse(f"/ui/findings/{f.id}#reputation", status_code=303)


@router.get("/intel/ip/{ip}", response_class=HTMLResponse)
def ip_intel_page(
    ip: str, request: Request,
    session: Annotated[Session, Depends(get_session, scope="function")], user: Annotated[User | None, Depends(ui_user)],
):  # fmt: skip
    if user is None:
        return _login_redirect(request)
    try:
        ip = intel_api._check_ip(ip, request.app.state.settings.demo_mode)
    except HTTPException as exc:
        raise HTTPException(404, exc.detail) from exc
    view = intel_mod.intel_view(session, user.workspace_id, None, [ip])
    job = intel_api._latest_job(session, user.workspace_id, "ip", ip)
    return _render(
        request, "intel.html", user, v=view, mode="ip", subject=ip,
        job=intel_api._job_out(job), job_running=intel_api._running(job),
        start_url=f"/api/intel/ip/{ip}", data_url=f"/api/intel/ip/{ip}",
        back_url=request.headers.get("referer") or "/ui/findings", active="findings",
    )  # fmt: skip
