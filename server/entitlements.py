"""The entitlement authority.

`can_access(user, feature, db)` — and its stricter sibling `require_access`
— are the ONLY things allowed to decide whether a user may use a feature.
Nothing else in this codebase should ever branch on a plan name; call one of
these two functions instead, or use the `require_feature` FastAPI dependency
factory below.

How a plan is computed (`effective_plan`):
  1. Look at this user's Subscription rows.
  2. The active one is whichever has status in ("active", "trialing") AND
     current_period_end in the future — that is the plan.
  3. A subscription with cancel_at_period_end=True keeps access until
     current_period_end (standard SaaS semantics: you paid for the period).
  4. Anything else (no subscription, expired, past_due, incomplete,
     fully canceled and past its period) => EXPLORER (free).

`sync_entitlements` then materializes that plan's feature list from
plans.json into the Entitlement table (upsert), so `Entitlement` always
matches "features implied by the current, re-verified subscription state" —
never a client-supplied value, never a stale cache older than this request.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from fastapi import Depends, HTTPException
from sqlalchemy.orm import Session

import config
import models
from auth import get_current_user
from db import get_db

FEATURES = frozenset(
    feat for plan in config.PLAN_CONFIG.values() for feat in plan["features"]
)

# Usage-metered operation names (e.g. "agent_step") are a separate namespace
# from boolean FEATURES — every plan grants them, just at different caps.
METERED_OPERATIONS = frozenset(
    op for plan in config.PLAN_CONFIG.values() for op in plan.get("limits", {})
)

_ALL_KEYS = FEATURES | METERED_OPERATIONS


def _aware(dt: datetime) -> datetime:
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def effective_plan(user: models.User, db: Session) -> str:
    now = datetime.now(timezone.utc)
    subs = (
        db.query(models.Subscription)
        .filter(models.Subscription.user_id == user.id)
        .order_by(models.Subscription.current_period_end.desc())
        .all()
    )
    for sub in subs:
        if sub.status not in ("active", "trialing"):
            continue
        if _aware(sub.current_period_end) <= now:
            continue  # expired, even if the provider hasn't told us the status changed yet
        if sub.plan in config.PLAN_CONFIG:
            return sub.plan
    return config.FREE_PLAN


def _next_reset(period: str, now: datetime) -> datetime:
    if period == "day":
        return (now + timedelta(days=1)).replace(hour=0, minute=0, second=0, microsecond=0)
    if period == "month":
        year, month = (now.year, now.month + 1) if now.month < 12 else (now.year + 1, 1)
        return datetime(year, month, 1, tzinfo=timezone.utc)
    return now + timedelta(days=30)


def sync_entitlements(user: models.User, db: Session) -> dict[str, models.Entitlement]:
    plan = effective_plan(user, db)
    plan_cfg = config.PLAN_CONFIG[plan]
    granted = set(plan_cfg["features"])
    limits = plan_cfg.get("limits", {})
    now = datetime.now(timezone.utc)

    existing = {
        e.feature: e
        for e in db.query(models.Entitlement).filter(models.Entitlement.user_id == user.id).all()
    }

    result: dict[str, models.Entitlement] = {}
    for feature in _ALL_KEYS:
        limit_cfg = limits.get(feature)
        enabled = (feature in granted) or (limit_cfg is not None)
        usage_limit = limit_cfg["limit"] if limit_cfg else None
        reset_at = _next_reset(limit_cfg["period"], now) if limit_cfg else None

        row = existing.get(feature)
        if row is None:
            row = models.Entitlement(user_id=user.id, feature=feature)
            db.add(row)
        row.enabled = enabled
        row.usage_limit = usage_limit
        row.reset_at = reset_at
        result[feature] = row
    db.commit()
    return result


def can_access(user: models.User, feature: str, db: Session) -> bool:
    ents = sync_entitlements(user, db)
    row = ents.get(feature)
    return bool(row and row.enabled)


def require_access(user: models.User, feature: str, db: Session) -> None:
    if not can_access(user, feature, db):
        plan = effective_plan(user, db)
        raise HTTPException(
            status_code=403,
            detail={
                "error": "upgrade_required",
                "feature": feature,
                "plan": plan,
                "message": f"{feature.replace('_', ' ').title()} requires Operator Mode.",
            },
        )


def require_feature(feature: str):
    """FastAPI dependency factory: `Depends(require_feature('SECURITY_ANALYSIS'))`."""

    def _dep(user: models.User = Depends(get_current_user), db: Session = Depends(get_db)) -> models.User:
        require_access(user, feature, db)
        return user

    return _dep


def entitlement_snapshot(user: models.User, db: Session) -> dict:
    from usage import usage_snapshot  # local import: avoids a module cycle

    plan = effective_plan(user, db)
    ents = sync_entitlements(user, db)
    active_sub = (
        db.query(models.Subscription)
        .filter(models.Subscription.user_id == user.id, models.Subscription.status.in_(["active", "trialing"]))
        .order_by(models.Subscription.current_period_end.desc())
        .first()
    )
    return {
        "plan": plan,
        "plan_label": config.PLAN_CONFIG[plan]["label"],
        "features": {f: row.enabled for f, row in sorted(ents.items())},
        "usage": usage_snapshot(user, ents, db),
        "subscription": (
            {
                "status": active_sub.status,
                "provider": active_sub.provider,
                "current_period_end": active_sub.current_period_end.isoformat(),
                "cancel_at_period_end": active_sub.cancel_at_period_end,
            }
            if active_sub
            else None
        ),
    }
