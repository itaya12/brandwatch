"""ML classifier API (Phase 5): train on analyst labels (or the recorded golden labels in demo
mode) and inspect the current model. The model is advisory; it never changes a score."""

from __future__ import annotations

import uuid
from typing import Annotated, Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel
from sqlalchemy.orm import Session

from brandwatch.api.auth import audit, require_analyst
from brandwatch.api.deps import get_session
from brandwatch.db.models import User
from brandwatch.detection import ml

router = APIRouter(prefix="/api/ml", tags=["ml"])


class TrainRequest(BaseModel):
    source: Literal["analyst", "golden", "both"] = "analyst"
    brand_id: uuid.UUID | None = None


@router.get("/model")
def get_model(
    session: Annotated[Session, Depends(get_session, scope="function")],
    user: Annotated[User, Depends(require_analyst)],
) -> dict[str, Any]:
    model = ml.latest_model(session, user.workspace_id)
    labelled = {
        src: len(ml.training_set(session, user.workspace_id, source=src))
        for src in ("analyst", "golden")
    }
    return {"model": model, "labelled_candidates": labelled, "min_samples": ml.MIN_SAMPLES}


@router.post("/train", status_code=status.HTTP_201_CREATED)
def train_model(
    body: TrainRequest,
    request: Request,
    session: Annotated[Session, Depends(get_session, scope="function")],
    user: Annotated[User, Depends(require_analyst)],
) -> dict[str, Any]:
    if body.source in ("golden", "both") and not request.app.state.settings.demo_mode:
        raise HTTPException(
            status.HTTP_409_CONFLICT, "golden labels are only available in demo mode"
        )
    try:
        row = ml.train(session, user.workspace_id, source=body.source, brand_id=body.brand_id)
    except ValueError as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, str(exc)) from exc
    audit(
        session, workspace_id=user.workspace_id, actor_type="analyst", actor_id=user.id,
        action="ml.trained", object_type="rule_version", object_id=row.id,
        new={"version": row.version, "metrics": row.payload["metrics"], "n": row.payload["n_samples"], "source": body.source},
    )  # fmt: skip
    return {"version": row.version, **row.payload}
