"""Development/local-demo billing provider.

This is NOT production payment infrastructure. No money moves, there is no
external processor, and pending checkout state lives in an in-process dict
that is lost on restart. It exists so the full checkout -> webhook ->
entitlement pipeline can be built, demoed, and tested end-to-end without
requiring a real Stripe (or other) account.

It deliberately exercises the *exact same* signature-verification and
idempotent-apply code path a real provider would (`verify_and_parse_webhook`
-> `apply_subscription_event`) — the only thing "mocked" is who is allowed to
trigger the webhook call (here: our own /billing/mock/complete route, guarded
by a session the checkout page itself created; in production, only Stripe's
IP + signature would be trusted).
"""
from __future__ import annotations

import hashlib
import hmac
import json
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from sqlalchemy.orm import Session

import config
import models
from billing import BillingProvider, BillingProviderError, CheckoutSession, NormalizedSubscriptionEvent, apply_subscription_event

PLAN_PRICES_USD = {plan: cfg.get("price_monthly_usd") for plan, cfg in config.PLAN_CONFIG.items()}


@dataclass
class _PendingCheckout:
    session_id: str
    user_id: str
    plan: str
    created_at: datetime


# In-memory only — mock infra, not a durable store. See module docstring.
_PENDING: dict[str, _PendingCheckout] = {}
_PENDING_TTL = timedelta(minutes=30)


def _sign(payload: bytes) -> str:
    return hmac.new(config.BILLING_WEBHOOK_SECRET.encode("utf-8"), payload, hashlib.sha256).hexdigest()


class MockBillingProvider(BillingProvider):
    name = "mock"

    def create_checkout_session(self, user: models.User, plan: str, db: Session) -> CheckoutSession:
        if plan not in config.PLAN_CONFIG or plan == config.FREE_PLAN:
            raise BillingProviderError(f"cannot checkout for plan '{plan}'")
        session_id = f"mock_cs_{uuid.uuid4().hex}"
        _PENDING[session_id] = _PendingCheckout(session_id, user.id, plan, datetime.now(timezone.utc))
        url = f"{config.PUBLIC_APP_URL.rstrip('/')}/billing/mock/checkout/{session_id}"
        return CheckoutSession(checkout_url=url, session_id=session_id, provider=self.name)

    def get_pending(self, session_id: str) -> _PendingCheckout | None:
        p = _PENDING.get(session_id)
        if p and datetime.now(timezone.utc) - p.created_at > _PENDING_TTL:
            _PENDING.pop(session_id, None)
            return None
        return p

    def build_completion_webhook(self, session_id: str) -> tuple[bytes, dict[str, str]]:
        """Simulates "the provider calling our webhook after payment" —
        builds the exact wire payload + signature header a real delivery
        would send, so it can be POSTed through the normal /billing/webhook
        verification path instead of trusting the browser's return."""
        pending = self.get_pending(session_id)
        if pending is None:
            raise BillingProviderError("checkout session not found or expired")
        now = datetime.now(timezone.utc)
        body = {
            "id": f"evt_{uuid.uuid4().hex}",
            "type": "checkout.session.completed",
            "data": {
                "user_id": pending.user_id,
                "customer_id": f"mock_cus_{pending.user_id[:12]}",
                "subscription_id": f"mock_sub_{uuid.uuid4().hex}",
                "plan": pending.plan,
                "status": "active",
                "current_period_start": now.isoformat(),
                "current_period_end": (now + timedelta(days=30)).isoformat(),
                "cancel_at_period_end": False,
            },
        }
        payload = json.dumps(body).encode("utf-8")
        headers = {"x-mock-signature": f"sha256={_sign(payload)}"}
        _PENDING.pop(session_id, None)
        return payload, headers

    def get_subscription(self, subscription: models.Subscription) -> dict:
        # The mock has no provider-side state independent of our own DB row —
        # a real provider adapter would call out to the API here instead.
        return {
            "subscription_id": subscription.subscription_id,
            "status": subscription.status,
            "current_period_end": subscription.current_period_end.isoformat(),
        }

    def cancel_subscription(self, subscription: models.Subscription, db: Session) -> None:
        now = datetime.now(timezone.utc)
        event = NormalizedSubscriptionEvent(
            event_id=f"evt_{uuid.uuid4().hex}",
            event_type="subscription.canceled",
            provider=self.name,
            customer_id=subscription.customer_id,
            subscription_id=subscription.subscription_id,
            plan=subscription.plan,
            status=subscription.status,  # stays active until period end
            current_period_start=subscription.current_period_start,
            current_period_end=subscription.current_period_end,
            cancel_at_period_end=True,
        )
        apply_subscription_event(event, db)

    def verify_and_parse_webhook(self, payload: bytes, headers: dict) -> NormalizedSubscriptionEvent:
        sig_header = headers.get("x-mock-signature", "")
        if not sig_header.startswith("sha256="):
            raise BillingProviderError("missing or malformed signature header")
        expected = _sign(payload)
        provided = sig_header.split("=", 1)[1]
        if not hmac.compare_digest(expected, provided):
            raise BillingProviderError("signature mismatch")

        try:
            body = json.loads(payload)
            data = body["data"]
        except (json.JSONDecodeError, KeyError) as exc:
            raise BillingProviderError(f"malformed webhook payload: {exc}") from exc

        return NormalizedSubscriptionEvent(
            event_id=body["id"],
            event_type=body["type"],
            provider=self.name,
            user_id=data.get("user_id"),
            customer_id=data["customer_id"],
            subscription_id=data["subscription_id"],
            plan=data["plan"],
            status=data["status"],
            current_period_start=datetime.fromisoformat(data["current_period_start"]),
            current_period_end=datetime.fromisoformat(data["current_period_end"]),
            cancel_at_period_end=bool(data.get("cancel_at_period_end", False)),
        )
