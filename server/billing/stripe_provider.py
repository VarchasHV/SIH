"""Stripe adapter — demonstrates how a real provider plugs into the same
`BillingProvider` interface the mock uses. This repository has no Stripe
account configured, so this class is UNTESTED against a live Stripe API; it
is included to show the abstraction is not mock-specific, not as a claim
that Stripe billing is production-ready here.

To actually use it:
  1. `pip install stripe`
  2. Set STRIPE_SECRET_KEY, STRIPE_WEBHOOK_SECRET, STRIPE_PRICE_OPERATOR,
     STRIPE_PRICE_COMMAND in the environment.
  3. Set BILLING_PROVIDER=stripe.
  4. Point a real Stripe webhook endpoint at POST /billing/webhook.
  5. Test against Stripe's test-mode keys and the Stripe CLI's
     `stripe listen --forward-to localhost:8000/billing/webhook` before ever
     using live keys.
"""
from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy.orm import Session

import config
import models
from billing import BillingProvider, BillingProviderError, CheckoutSession, NormalizedSubscriptionEvent


def _require_stripe():
    try:
        import stripe  # noqa: F401
    except ImportError as exc:
        raise BillingProviderError(
            "BILLING_PROVIDER=stripe requires `pip install stripe` and STRIPE_SECRET_KEY to be set."
        ) from exc
    if not config.STRIPE_SECRET_KEY:
        raise BillingProviderError("STRIPE_SECRET_KEY is not configured.")
    return stripe


class StripeBillingProvider(BillingProvider):
    name = "stripe"

    def create_checkout_session(self, user: models.User, plan: str, db: Session) -> CheckoutSession:
        stripe = _require_stripe()
        stripe.api_key = config.STRIPE_SECRET_KEY
        price_id = config.STRIPE_PRICE_IDS.get(plan)
        if not price_id:
            raise BillingProviderError(f"No STRIPE_PRICE_ID configured for plan '{plan}'.")

        session = stripe.checkout.Session.create(
            mode="subscription",
            line_items=[{"price": price_id, "quantity": 1}],
            client_reference_id=user.id,
            customer_email=user.email,
            metadata={"user_id": user.id, "plan": plan},
            success_url=f"{config.PUBLIC_APP_URL}/billing/return?status=success",
            cancel_url=f"{config.PUBLIC_APP_URL}/billing/return?status=cancelled",
        )
        return CheckoutSession(checkout_url=session.url, session_id=session.id, provider=self.name)

    def get_subscription(self, subscription: models.Subscription) -> dict:
        stripe = _require_stripe()
        stripe.api_key = config.STRIPE_SECRET_KEY
        return stripe.Subscription.retrieve(subscription.subscription_id)

    def cancel_subscription(self, subscription: models.Subscription, db: Session) -> None:
        stripe = _require_stripe()
        stripe.api_key = config.STRIPE_SECRET_KEY
        # Cancel at period end — the user keeps access through what they paid
        # for. The resulting `customer.subscription.updated` webhook is what
        # actually updates our Subscription row; this call does not.
        stripe.Subscription.modify(subscription.subscription_id, cancel_at_period_end=True)

    def verify_and_parse_webhook(self, payload: bytes, headers: dict) -> NormalizedSubscriptionEvent:
        stripe = _require_stripe()
        if not config.STRIPE_WEBHOOK_SECRET:
            raise BillingProviderError("STRIPE_WEBHOOK_SECRET is not configured.")
        sig_header = headers.get("stripe-signature", "")
        try:
            event = stripe.Webhook.construct_event(payload, sig_header, config.STRIPE_WEBHOOK_SECRET)
        except (ValueError, stripe.error.SignatureVerificationError) as exc:
            raise BillingProviderError(f"Stripe signature verification failed: {exc}") from exc

        obj = event["data"]["object"]
        plan = (obj.get("metadata") or {}).get("plan", "OPERATOR")
        user_id = (obj.get("metadata") or {}).get("user_id") or obj.get("client_reference_id")

        return NormalizedSubscriptionEvent(
            event_id=event["id"],
            event_type=event["type"],
            provider=self.name,
            user_id=user_id,
            customer_id=obj.get("customer", ""),
            subscription_id=obj.get("subscription") or obj.get("id", ""),
            plan=plan,
            status=obj.get("status", "active"),
            current_period_start=datetime.fromtimestamp(obj.get("current_period_start", 0), tz=timezone.utc),
            current_period_end=datetime.fromtimestamp(obj.get("current_period_end", 0), tz=timezone.utc),
            cancel_at_period_end=bool(obj.get("cancel_at_period_end", False)),
        )
