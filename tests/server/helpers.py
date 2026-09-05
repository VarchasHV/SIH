"""Shared test helpers for the auth/entitlements/billing suite."""
from __future__ import annotations

import sys
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(ROOT / "server"))

from fastapi.testclient import TestClient  # noqa: E402

import main  # noqa: E402
import models  # noqa: E402
from db import SessionLocal  # noqa: E402


def client() -> TestClient:
    return TestClient(main.app, raise_server_exceptions=False)


def unique_email() -> str:
    return f"user_{uuid.uuid4().hex[:12]}@example.com"


def signup(c: TestClient, email: str | None = None, password: str = "correct horse battery staple") -> dict:
    email = email or unique_email()
    r = c.post("/auth/signup", json={"email": email, "password": password})
    assert r.status_code == 201, r.text
    body = r.json()
    body["email"] = email
    body["password"] = password
    return body


def auth_headers(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


def user_id_from_token(token: str) -> str:
    import security

    payload = security.decode_access_token(token)
    return payload["sub"]


def db_session():
    return SessionLocal()


def grant_subscription(
    user_id: str,
    plan: str = "OPERATOR",
    status: str = "active",
    days_remaining: int = 30,
    cancel_at_period_end: bool = False,
    provider: str = "mock",
) -> models.Subscription:
    """Directly inserts a Subscription row — bypasses billing entirely, for
    tests that only care about entitlement logic given a subscription state."""
    db = db_session()
    try:
        now = datetime.now(timezone.utc)
        sub = models.Subscription(
            user_id=user_id,
            provider=provider,
            customer_id=f"cus_{uuid.uuid4().hex[:10]}",
            subscription_id=f"sub_{uuid.uuid4().hex[:10]}",
            plan=plan,
            status=status,
            current_period_start=now - timedelta(days=30 - days_remaining),
            current_period_end=now + timedelta(days=days_remaining),
            cancel_at_period_end=cancel_at_period_end,
        )
        db.add(sub)
        db.commit()
        db.refresh(sub)
        return sub
    finally:
        db.close()
