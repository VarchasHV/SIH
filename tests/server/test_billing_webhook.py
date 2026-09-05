"""Webhook idempotency + signature verification, and the full mock
checkout -> webhook -> entitlement pipeline. Covers scenarios 10 & 11.
"""
from __future__ import annotations

import json

import helpers
from db import SessionLocal
import models


def test_full_mock_checkout_unlocks_operator():
    c = helpers.client()
    tokens = helpers.signup(c)
    headers = helpers.auth_headers(tokens["access_token"])

    # Before paying: EXPLORER.
    assert c.get("/entitlements/me", headers=headers).json()["plan"] == "EXPLORER"

    checkout = c.post("/billing/checkout", json={"plan": "OPERATOR"}, headers=headers)
    assert checkout.status_code == 200
    session_id = checkout.json()["session_id"]

    # Merely "returning" from a checkout URL must not unlock anything by
    # itself — hitting the checkout page (GET) does nothing.
    page = c.get(f"/billing/mock/checkout/{session_id}")
    assert page.status_code == 200
    assert c.get("/entitlements/me", headers=headers).json()["plan"] == "EXPLORER"

    # Only the (signed, webhook-verified) completion actually flips state.
    complete = c.post("/billing/mock/complete", data={"session_id": session_id})
    assert complete.status_code == 200

    assert c.get("/entitlements/me", headers=headers).json()["plan"] == "OPERATOR"


def test_replayed_webhook_does_not_duplicate_state():
    c = helpers.client()
    tokens = helpers.signup(c)
    user_id = helpers.user_id_from_token(tokens["access_token"])

    from billing.mock_provider import MockBillingProvider

    provider = MockBillingProvider()
    db = SessionLocal()
    try:
        user = db.query(models.User).filter(models.User.id == user_id).first()
        session = provider.create_checkout_session(user, "OPERATOR", db)
    finally:
        db.close()

    payload, headers_ = provider.build_completion_webhook(session.session_id)

    r1 = c.post("/billing/webhook", content=payload, headers=headers_)
    assert r1.status_code == 200
    assert r1.json()["applied"] is True

    r2 = c.post("/billing/webhook", content=payload, headers=headers_)
    assert r2.status_code == 200
    assert r2.json()["applied"] is False, "a replayed event id must be a no-op, not a second update"

    db = SessionLocal()
    try:
        count = db.query(models.Subscription).filter(models.Subscription.user_id == user_id).count()
        assert count == 1, "the subscription must only be created once, not once per delivery"
    finally:
        db.close()


def test_invalid_webhook_signature_rejected():
    c = helpers.client()
    tokens = helpers.signup(c)
    user_id = helpers.user_id_from_token(tokens["access_token"])

    from billing.mock_provider import MockBillingProvider

    provider = MockBillingProvider()
    db = SessionLocal()
    try:
        user = db.query(models.User).filter(models.User.id == user_id).first()
        session = provider.create_checkout_session(user, "OPERATOR", db)
    finally:
        db.close()

    payload, headers_ = provider.build_completion_webhook(session.session_id)
    tampered_headers = {**headers_, "x-mock-signature": "sha256=" + "0" * 64}

    r = c.post("/billing/webhook", content=payload, headers=tampered_headers)
    assert r.status_code == 400

    assert c.get("/entitlements/me", headers=helpers.auth_headers(tokens["access_token"])).json()["plan"] == "EXPLORER"


def test_tampered_payload_with_stale_signature_rejected():
    c = helpers.client()
    tokens = helpers.signup(c)
    user_id = helpers.user_id_from_token(tokens["access_token"])

    from billing.mock_provider import MockBillingProvider

    provider = MockBillingProvider()
    db = SessionLocal()
    try:
        user = db.query(models.User).filter(models.User.id == user_id).first()
        session = provider.create_checkout_session(user, "OPERATOR", db)
    finally:
        db.close()

    payload, headers_ = provider.build_completion_webhook(session.session_id)
    body = json.loads(payload)
    body["data"]["plan"] = "COMMAND"  # try to upgrade further than paid for
    tampered_payload = json.dumps(body).encode("utf-8")

    # signature was computed over the ORIGINAL payload — it must not verify
    # against the tampered one.
    r = c.post("/billing/webhook", content=tampered_payload, headers=headers_)
    assert r.status_code == 400


def test_webhook_cannot_reassign_subscription_owner():
    """A forged/duplicated subscription_id from a different user must never
    let one user's webhook event reassign an existing subscription to
    themselves."""
    c = helpers.client()
    tokens_a = helpers.signup(c)
    tokens_b = helpers.signup(c)
    user_a_id = helpers.user_id_from_token(tokens_a["access_token"])
    user_b_id = helpers.user_id_from_token(tokens_b["access_token"])

    from billing import NormalizedSubscriptionEvent, apply_subscription_event
    from datetime import datetime, timedelta, timezone

    now = datetime.now(timezone.utc)
    db = SessionLocal()
    try:
        event = NormalizedSubscriptionEvent(
            event_id="evt_owner_1",
            event_type="checkout.session.completed",
            provider="mock",
            user_id=user_a_id,
            customer_id="cus_a",
            subscription_id="sub_shared",
            plan="OPERATOR",
            status="active",
            current_period_start=now,
            current_period_end=now + timedelta(days=30),
            cancel_at_period_end=False,
        )
        apply_subscription_event(event, db)

        hijack_event = NormalizedSubscriptionEvent(
            event_id="evt_owner_2",
            event_type="customer.subscription.updated",
            provider="mock",
            user_id=user_b_id,  # attacker claims ownership on the "update"
            customer_id="cus_a",
            subscription_id="sub_shared",  # same subscription id
            plan="OPERATOR",
            status="active",
            current_period_start=now,
            current_period_end=now + timedelta(days=60),
            cancel_at_period_end=False,
        )
        apply_subscription_event(hijack_event, db)

        sub = (
            db.query(models.Subscription)
            .filter(models.Subscription.provider == "mock", models.Subscription.subscription_id == "sub_shared")
            .one()
        )
        assert sub.user_id == user_a_id, "ownership must not change via a later webhook event"
    finally:
        db.close()
