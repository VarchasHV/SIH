"""Atomic usage accounting for metered operations (e.g. "agent_step").

`check_and_consume` is the only way a counter moves. It is race-safe under
concurrent requests for the same user because the increment is a single
`UPDATE ... WHERE count < :limit` statement — the database (SQLite here,
Postgres in production) serializes conflicting writes to the same row, so
two concurrent calls can never both succeed once the row is at the limit.
There is no read-then-write gap for a race to land in.
"""
from __future__ import annotations

from datetime import datetime, timezone

from fastapi import HTTPException
from sqlalchemy import text
from sqlalchemy.orm import Session

import config
import models
from entitlements import effective_plan


def _period_key(period: str, now: datetime) -> str:
    if period == "day":
        return now.strftime("%Y-%m-%d")
    if period == "month":
        return now.strftime("%Y-%m")
    return now.strftime("%Y-%m-%d")


def _limit_cfg(plan: str, operation: str) -> dict | None:
    return config.PLAN_CONFIG.get(plan, {}).get("limits", {}).get(operation)


def check_and_consume(user: models.User, operation: str, db: Session) -> dict:
    """Raises HTTP 402 if the user's current-period allowance is exhausted.
    Returns {"used": int, "limit": int|None, "period_key": str} on success."""
    plan = effective_plan(user, db)
    limit_cfg = _limit_cfg(plan, operation)
    if limit_cfg is None:
        return {"used": None, "limit": None, "period_key": None}  # unmetered on this plan

    limit = limit_cfg["limit"]
    period_key = _period_key(limit_cfg["period"], datetime.now(timezone.utc))

    # Ensure the row exists (races here are harmless: the unique constraint
    # lets only one INSERT win, everyone else is a no-op).
    db.execute(
        text(
            "INSERT OR IGNORE INTO usage_counters (id, user_id, feature, period_key, count, updated_at) "
            "VALUES (:id, :user_id, :feature, :period_key, 0, :now)"
        ),
        {"id": _new_id(), "user_id": user.id, "feature": operation, "period_key": period_key, "now": datetime.now(timezone.utc)},
    )
    db.commit()

    result = db.execute(
        text(
            "UPDATE usage_counters SET count = count + 1, updated_at = :now "
            "WHERE user_id = :user_id AND feature = :feature AND period_key = :period_key AND count < :limit"
        ),
        {"user_id": user.id, "feature": operation, "period_key": period_key, "limit": limit, "now": datetime.now(timezone.utc)},
    )
    db.commit()

    used = db.execute(
        text("SELECT count FROM usage_counters WHERE user_id = :user_id AND feature = :feature AND period_key = :period_key"),
        {"user_id": user.id, "feature": operation, "period_key": period_key},
    ).scalar_one()

    if result.rowcount == 0:
        raise HTTPException(
            status_code=402,
            detail={
                "error": "usage_limit_reached",
                "operation": operation,
                "plan": plan,
                "used": used,
                "limit": limit,
                "period": limit_cfg["period"],
                "message": f"You've used {used}/{limit} {operation.replace('_', ' ')} for this {limit_cfg['period']}. Upgrade to Operator for a higher limit.",
            },
        )
    return {"used": used, "limit": limit, "period_key": period_key}


def _new_id() -> str:
    import uuid

    return uuid.uuid4().hex


def usage_snapshot(user: models.User, entitlement_rows: dict[str, models.Entitlement], db: Session) -> dict:
    plan = effective_plan(user, db)
    out = {}
    for operation in config.PLAN_CONFIG[plan].get("limits", {}):
        limit_cfg = _limit_cfg(plan, operation)
        period_key = _period_key(limit_cfg["period"], datetime.now(timezone.utc))
        row = (
            db.query(models.UsageCounter)
            .filter(
                models.UsageCounter.user_id == user.id,
                models.UsageCounter.feature == operation,
                models.UsageCounter.period_key == period_key,
            )
            .first()
        )
        ent = entitlement_rows.get(operation)
        out[operation] = {
            "used": row.count if row else 0,
            "limit": limit_cfg["limit"],
            "period": limit_cfg["period"],
            "reset_at": ent.reset_at.isoformat() if ent and ent.reset_at else None,
        }
    return out
