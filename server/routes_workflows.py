"""Persistent agent-session history — the OPERATOR-only WORKFLOW_HISTORY
feature. Rows are written internally by the /agent/step handler (see
`record_step`, called from main.py) only when the caller already has the
feature; there is no client-writable "create workflow" endpoint, so a client
cannot fabricate history it didn't actually generate.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

import models
from db import get_db
from entitlements import require_feature

router = APIRouter(prefix="/workflows", tags=["workflows"])


def record_step(user: models.User, session_id: str, task_goal: str, page_url: str, done: bool, db: Session) -> None:
    row = (
        db.query(models.WorkflowRun)
        .filter(models.WorkflowRun.user_id == user.id, models.WorkflowRun.session_id == session_id)
        .first()
    )
    if row is None:
        row = models.WorkflowRun(user_id=user.id, session_id=session_id, task_goal=task_goal, page_url=page_url)
        db.add(row)
    row.step_count += 1
    row.done = row.done or done
    if task_goal:
        row.task_goal = task_goal
    if page_url:
        row.page_url = page_url
    db.commit()


@router.get("")
def list_workflows(user: models.User = Depends(require_feature("WORKFLOW_HISTORY")), db: Session = Depends(get_db)):
    rows = (
        db.query(models.WorkflowRun)
        .filter(models.WorkflowRun.user_id == user.id)
        .order_by(models.WorkflowRun.updated_at.desc())
        .limit(100)
        .all()
    )
    return {
        "workflows": [
            {
                "session_id": r.session_id,
                "task_goal": r.task_goal,
                "page_url": r.page_url,
                "step_count": r.step_count,
                "done": r.done,
                "created_at": r.created_at.isoformat(),
                "updated_at": r.updated_at.isoformat(),
            }
            for r in rows
        ]
    }
