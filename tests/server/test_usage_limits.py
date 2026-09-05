"""Server-side usage enforcement: limit reached (12) and concurrent
requests cannot trivially exceed the limit (13).

EXPLORER's agent_step limit is 15/day (server/plans.json) — small enough to
actually exhaust in a test.
"""
from __future__ import annotations

import threading

import helpers
import config
from db import SessionLocal
import models
from usage import check_and_consume


def _explorer_daily_limit() -> int:
    return config.PLAN_CONFIG["EXPLORER"]["limits"]["agent_step"]["limit"]


def _get_user(user_id: str) -> models.User:
    db = SessionLocal()
    try:
        return db.query(models.User).filter(models.User.id == user_id).first()
    finally:
        db.close()


# 12. Usage limit reached -> rejected
def test_usage_limit_reached_is_rejected():
    c = helpers.client()
    tokens = helpers.signup(c)
    user_id = helpers.user_id_from_token(tokens["access_token"])
    limit = _explorer_daily_limit()

    db = SessionLocal()
    try:
        user = _get_user(user_id)
        for i in range(limit):
            result = check_and_consume(user, "agent_step", db)
            assert result["used"] == i + 1

        from fastapi import HTTPException

        try:
            check_and_consume(user, "agent_step", db)
            assert False, "the (limit+1)th call must be rejected"
        except HTTPException as exc:
            assert exc.status_code == 402
            assert exc.detail["error"] == "usage_limit_reached"
            assert exc.detail["used"] == limit
            assert exc.detail["limit"] == limit
    finally:
        db.close()


def test_usage_limit_enforced_through_the_http_endpoint():
    c = helpers.client()
    tokens = helpers.signup(c)
    headers = helpers.auth_headers(tokens["access_token"])
    limit = _explorer_daily_limit()

    node = {
        "id": "el-1", "tag": "input", "type": "text", "label": "Full name",
        "state": "empty", "hasFill": True, "fillToken": "local:full name",
        "piiCategory": "full name", "bbox": {"x": 0, "y": 0, "w": 100, "h": 20},
    }
    body = {
        "taskGoal": "Fill this form from my local profile.",
        "step": 1,
        "skeleton": {"viewport": {"w": 1280, "h": 720}, "nodes": [node]},
    }

    statuses = [c.post("/agent/step", json=body, headers=headers).status_code for _ in range(limit)]
    assert all(s == 200 for s in statuses), statuses

    over_limit = c.post("/agent/step", json=body, headers=headers)
    assert over_limit.status_code == 402
    assert over_limit.json()["detail"]["error"] == "usage_limit_reached"


# 13. Concurrent usage requests cannot trivially exceed the limit
def test_concurrent_usage_cannot_exceed_limit():
    c = helpers.client()
    tokens = helpers.signup(c)
    user_id = helpers.user_id_from_token(tokens["access_token"])
    limit = _explorer_daily_limit()
    attempts = limit + 20  # deliberately over-subscribe

    successes = []
    failures = []
    lock = threading.Lock()

    def worker():
        db = SessionLocal()
        try:
            user = db.query(models.User).filter(models.User.id == user_id).first()
            try:
                check_and_consume(user, "agent_step", db)
                with lock:
                    successes.append(1)
            except Exception:
                with lock:
                    failures.append(1)
        finally:
            db.close()

    threads = [threading.Thread(target=worker) for _ in range(attempts)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert len(successes) == limit, f"expected exactly {limit} successes, got {len(successes)}"
    assert len(failures) == attempts - limit

    db = SessionLocal()
    try:
        from datetime import datetime, timezone

        period_key = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        row = (
            db.query(models.UsageCounter)
            .filter(
                models.UsageCounter.user_id == user_id,
                models.UsageCounter.feature == "agent_step",
                models.UsageCounter.period_key == period_key,
            )
            .one()
        )
        assert row.count == limit, "the stored counter itself must never exceed the limit"
    finally:
        db.close()
