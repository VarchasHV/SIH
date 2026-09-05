"""Billing provider abstraction.

`BillingProvider` is the seam that lets the real payment processor be
swapped later without touching routes_billing.py, entitlements.py, or the
extension: implement the four methods, register the class in `_PROVIDERS`,
and set `BILLING_PROVIDER=<name>`.

Everything downstream of a webhook works on the provider-agnostic
`NormalizedSubscriptionEvent` — providers only have to translate their own
wire format into that shape.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime

from sqlalchemy.orm import Session

import models


@dataclass
class CheckoutSession:
    checkout_url: str
    session_id: str
    provider: str


@dataclass
class NormalizedSubscriptionEvent:
    event_id: str
    event_type: str
    provider: str
    customer_id: str
    subscription_id: str
    plan: str
    status: str
    current_period_start: datetime
    current_period_end: datetime
    cancel_at_period_end: bool
    user_id: str | None = None  # only present/required when creating a new Subscription row


class BillingProviderError(Exception):
    """Raised on invalid webhook signatures, malformed payloads, etc."""


class BillingProvider(ABC):
    name: str

    @abstractmethod
    def create_checkout_session(self, user: models.User, plan: str, db: Session) -> CheckoutSession: ...

    @abstractmethod
    def get_subscription(self, subscription: models.Subscription) -> dict:
        """Read the live subscription state directly from the provider (for
        reconciliation / manual refresh), bypassing our local cache."""

    @abstractmethod
    def cancel_subscription(self, subscription: models.Subscription, db: Session) -> None: ...

    @abstractmethod
    def verify_and_parse_webhook(self, payload: bytes, headers: dict) -> NormalizedSubscriptionEvent:
        """Verify the request actually came from the provider (signature
        check) and translate it to a NormalizedSubscriptionEvent. Raise
        BillingProviderError if verification fails — callers must treat that
        as a hard rejection, never a soft/ignorable warning."""


def apply_subscription_event(event: NormalizedSubscriptionEvent, db: Session) -> bool:
    """Idempotently applies a normalized event to Subscription state.

    Returns True if this call actually changed state, False if the event had
    already been processed (replay) — either way the webhook endpoint should
    respond 200, since a replay is not an error from the provider's view.
    """
    existing_event = (
        db.query(models.WebhookEvent)
        .filter(models.WebhookEvent.provider == event.provider, models.WebhookEvent.event_id == event.event_id)
        .first()
    )
    if existing_event is not None:
        return False  # already processed — idempotent no-op

    db.add(models.WebhookEvent(provider=event.provider, event_id=event.event_id, event_type=event.event_type))

    sub = (
        db.query(models.Subscription)
        .filter(models.Subscription.provider == event.provider, models.Subscription.subscription_id == event.subscription_id)
        .first()
    )
    if sub is None:
        if not event.user_id:
            raise BillingProviderError(f"unknown subscription {event.subscription_id} and event carries no user_id")
        sub = models.Subscription(
            user_id=event.user_id,
            provider=event.provider,
            customer_id=event.customer_id,
            subscription_id=event.subscription_id,
            plan=event.plan,
            status=event.status,
            current_period_start=event.current_period_start,
            current_period_end=event.current_period_end,
            cancel_at_period_end=event.cancel_at_period_end,
        )
        db.add(sub)
    else:
        # A webhook can update status/period/plan but can NEVER reassign
        # ownership — that would be a subscription-hijack vector.
        sub.status = event.status
        sub.plan = event.plan
        sub.current_period_start = event.current_period_start
        sub.current_period_end = event.current_period_end
        sub.cancel_at_period_end = event.cancel_at_period_end

    db.commit()
    return True


def get_billing_provider() -> BillingProvider:
    import config

    from billing.mock_provider import MockBillingProvider
    from billing.stripe_provider import StripeBillingProvider

    providers: dict[str, type[BillingProvider]] = {
        "mock": MockBillingProvider,
        "stripe": StripeBillingProvider,
    }
    cls = providers.get(config.BILLING_PROVIDER)
    if cls is None:
        raise RuntimeError(f"Unknown BILLING_PROVIDER '{config.BILLING_PROVIDER}' (expected one of: {', '.join(providers)})")
    return cls()
