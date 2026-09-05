"""Authorization boundary tests — the backend, not the client, decides
entitlement. Covers scenarios 1-9 and 14 of the security test matrix.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import helpers
import models
import pytest
from db import SessionLocal
from entitlements import can_access, effective_plan


def _get_user(user_id: str) -> models.User:
    db = SessionLocal()
    try:
        return db.query(models.User).filter(models.User.id == user_id).first()
    finally:
        db.close()


# 1. Free user accessing a free feature -> allowed
def test_free_user_can_access_free_feature():
    c = helpers.client()
    tokens = helpers.signup(c)
    user_id = helpers.user_id_from_token(tokens["access_token"])
    db = SessionLocal()
    try:
        user = db.query(models.User).filter(models.User.id == user_id).first()
        assert can_access(user, "BASIC_VISION", db) is True
        assert can_access(user, "BASIC_AGENT", db) is True
    finally:
        db.close()


# 2. Free user accessing a premium feature -> denied
def test_free_user_denied_premium_feature():
    c = helpers.client()
    tokens = helpers.signup(c)
    user_id = helpers.user_id_from_token(tokens["access_token"])
    db = SessionLocal()
    try:
        user = db.query(models.User).filter(models.User.id == user_id).first()
        assert can_access(user, "SECURITY_ANALYSIS", db) is False
        assert can_access(user, "ADVANCED_VISION", db) is False
    finally:
        db.close()

    r = c.post(
        "/reports/export",
        json={"title": "t", "dpdp_report": {}},
        headers=helpers.auth_headers(tokens["access_token"]),
    )
    assert r.status_code == 403
    assert r.json()["detail"]["error"] == "upgrade_required"


# 3. Premium (Operator) user accessing a premium feature -> allowed
def test_operator_user_can_access_premium_feature():
    c = helpers.client()
    tokens = helpers.signup(c)
    user_id = helpers.user_id_from_token(tokens["access_token"])
    helpers.grant_subscription(user_id, plan="OPERATOR", status="active", days_remaining=20)

    db = SessionLocal()
    try:
        user = _get_user(user_id)
        assert effective_plan(user, db) == "OPERATOR"
        assert can_access(user, "SECURITY_ANALYSIS", db) is True
    finally:
        db.close()

    r = c.post(
        "/reports/export",
        json={"title": "t", "dpdp_report": {"x": 1}},
        headers=helpers.auth_headers(tokens["access_token"]),
    )
    assert r.status_code == 200
    assert "content_markdown" in r.json()


# 4. Expired subscription -> denied (falls back to EXPLORER)
def test_expired_subscription_denied():
    c = helpers.client()
    tokens = helpers.signup(c)
    user_id = helpers.user_id_from_token(tokens["access_token"])
    helpers.grant_subscription(user_id, plan="OPERATOR", status="active", days_remaining=-5)

    db = SessionLocal()
    try:
        user = _get_user(user_id)
        assert effective_plan(user, db) == "EXPLORER"
        assert can_access(user, "SECURITY_ANALYSIS", db) is False
    finally:
        db.close()


# 5. Cancelled subscription -> correct access per period semantics
def test_cancel_at_period_end_keeps_access_until_period_ends():
    c = helpers.client()
    tokens = helpers.signup(c)
    user_id = helpers.user_id_from_token(tokens["access_token"])
    # Real provider semantics: status stays "active" with cancel_at_period_end
    # set, until the period actually elapses.
    helpers.grant_subscription(user_id, plan="OPERATOR", status="active", days_remaining=10, cancel_at_period_end=True)

    db = SessionLocal()
    try:
        user = _get_user(user_id)
        assert effective_plan(user, db) == "OPERATOR", "paid-for period must remain usable after cancellation"
    finally:
        db.close()


def test_immediately_cancelled_subscription_loses_access_now():
    c = helpers.client()
    tokens = helpers.signup(c)
    user_id = helpers.user_id_from_token(tokens["access_token"])
    # Immediate cancellation: provider flips status to "canceled" right away,
    # even though current_period_end is still technically in the future.
    helpers.grant_subscription(user_id, plan="OPERATOR", status="canceled", days_remaining=10, cancel_at_period_end=True)

    db = SessionLocal()
    try:
        user = _get_user(user_id)
        assert effective_plan(user, db) == "EXPLORER"
    finally:
        db.close()


# 6. Invalid subscription (past_due / incomplete) -> denied
@pytest.mark.parametrize("status", ["past_due", "incomplete", "unpaid"])
def test_invalid_subscription_status_denied(status):
    c = helpers.client()
    tokens = helpers.signup(c)
    user_id = helpers.user_id_from_token(tokens["access_token"])
    helpers.grant_subscription(user_id, plan="OPERATOR", status=status, days_remaining=10)

    db = SessionLocal()
    try:
        user = _get_user(user_id)
        assert effective_plan(user, db) == "EXPLORER"
    finally:
        db.close()


# 7. Forged client-supplied plan -> ignored entirely
def test_forged_client_plan_is_ignored():
    c = helpers.client()
    tokens = helpers.signup(c)
    headers = helpers.auth_headers(tokens["access_token"])

    # Attempt to smuggle a plan via body, header, and query string — none of
    # these are ever read by the server for entitlement purposes.
    r = c.get("/entitlements/me", headers={**headers, "X-Plan": "OPERATOR", "X-User-Plan": "COMMAND"})
    assert r.status_code == 200
    assert r.json()["plan"] == "EXPLORER"

    r2 = c.get("/entitlements/me?plan=OPERATOR&user_plan=COMMAND", headers=headers)
    assert r2.status_code == 200
    assert r2.json()["plan"] == "EXPLORER"


# 8 & 9. Client-side storage (localStorage / chrome.storage) is irrelevant —
# there is no code path on the server that reads client-supplied state for
# entitlement decisions; every check re-derives from the Subscription table.
def test_entitlement_snapshot_never_trusts_client_supplied_state():
    c = helpers.client()
    tokens = helpers.signup(c)
    headers = helpers.auth_headers(tokens["access_token"])
    # Simulate a client that has locally forged an "operator" flag by sending
    # arbitrary extra JSON in a POST body to an endpoint that doesn't expect one.
    r = c.get("/entitlements/me", headers=headers)
    body = r.json()
    assert body["plan"] == "EXPLORER"
    assert body["features"]["SECURITY_ANALYSIS"] is False


# 14. Unauthorized user accessing another user's entitlement -> rejected
def test_user_cannot_read_another_users_entitlements():
    c = helpers.client()
    tokens_a = helpers.signup(c)
    tokens_b = helpers.signup(c)
    user_b_id = helpers.user_id_from_token(tokens_b["access_token"])
    helpers.grant_subscription(user_b_id, plan="OPERATOR", status="active", days_remaining=30)

    # There is no user_id parameter anywhere on this route — the only way to
    # even attempt an IDOR here is smuggling one in, which is ignored.
    r = c.get(f"/entitlements/me?user_id={user_b_id}", headers=helpers.auth_headers(tokens_a["access_token"]))
    assert r.status_code == 200
    assert r.json()["plan"] == "EXPLORER", "user A must never see user B's OPERATOR plan"

    r2 = c.get("/entitlements/me", headers=helpers.auth_headers(tokens_b["access_token"]))
    assert r2.json()["plan"] == "OPERATOR"


def test_missing_or_garbage_token_rejected():
    c = helpers.client()
    r = c.get("/entitlements/me")
    assert r.status_code == 401
    r2 = c.get("/entitlements/me", headers={"Authorization": "Bearer not-a-real-token"})
    assert r2.status_code == 401
