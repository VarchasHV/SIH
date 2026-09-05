"""Read-only entitlement status for the current authenticated user only.

There is deliberately no way to pass a user id / plan / feature list as a
request parameter here — the identity comes exclusively from the verified
access token (`get_current_user`), so there is no IDOR surface to guard.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy.orm import Session

import models
from auth import get_current_user
from db import get_db
from entitlements import entitlement_snapshot
from usage import check_and_consume

router = APIRouter(prefix="/entitlements", tags=["entitlements"])


@router.get("/me")
def get_my_entitlements(user: models.User = Depends(get_current_user), db: Session = Depends(get_db)):
    return entitlement_snapshot(user, db)


class ConsumeRequest(BaseModel):
    operation: str = "agent_step"


@router.post("/consume")
def consume_usage(body: ConsumeRequest, user: models.User = Depends(get_current_user), db: Session = Depends(get_db)):
    """Metering checkpoint for operations that do NOT otherwise pass through
    a server-authoritative endpoint — specifically the extension's
    bring-your-own-key "direct to cloud VLM" path, which would otherwise
    bypass all usage accounting entirely. The client MUST call this and get
    a success response before making that direct call; the local-server path
    (/agent/step) meters itself and must NOT also call this for the same
    step, or usage would be double-counted.
    """
    return check_and_consume(user, body.operation, db)
