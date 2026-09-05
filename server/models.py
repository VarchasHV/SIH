"""ORM models: users, subscriptions, entitlements, usage, webhooks, workflow history.

Design notes:
  - User.id is a random UUID (not sequential) so it is not guessable/enumerable
    even though no endpoint ever accepts a client-supplied user id.
  - Subscription is the billing-provider-facing table (what Stripe/etc. calls
    "the subscription"). Entitlement is the application-facing materialized
    view of "what can this user do right now" — it is re-synced from
    Subscription on every access check (see entitlements.py), so it can never
    drift stale, but still matches the {user_id, feature, enabled,
    usage_limit, reset_at} shape asked for.
  - UsageCounter is separate from Entitlement: Entitlement says what the
    *limit* is, UsageCounter tracks *consumption* for the current period via
    an atomic UPDATE ... WHERE count < limit (see usage.py). Keeping them
    separate is what makes concurrent usage checks race-free.
  - RefreshToken is an opaque, hashed, DB-backed token (not a JWT) so a
    session can actually be revoked (logout, compromise) — a stateless JWT
    refresh token cannot be revoked before it expires.
  - WebhookEvent gives webhook processing idempotency: the provider's event id
    is unique; a replay is detected and a no-op before any state changes.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy import (
    Boolean,
    DateTime,
    ForeignKey,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from db import Base


def _uuid() -> str:
    return uuid.uuid4().hex


def _now() -> datetime:
    return datetime.now(timezone.utc)


class User(Base):
    __tablename__ = "users"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_uuid)
    email: Mapped[str] = mapped_column(String(320), unique=True, index=True, nullable=False)
    password_hash: Mapped[str] = mapped_column(String(200), nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now, nullable=False)

    subscriptions: Mapped[list["Subscription"]] = relationship(back_populates="user", cascade="all, delete-orphan")
    entitlements: Mapped[list["Entitlement"]] = relationship(back_populates="user", cascade="all, delete-orphan")


class Subscription(Base):
    """Mirrors the billing provider's subscription object. There can be more
    than one row per user over time (upgrades, re-subscribes); the "active"
    one for entitlement purposes is picked by entitlements.effective_plan()."""

    __tablename__ = "subscriptions"
    __table_args__ = (UniqueConstraint("provider", "subscription_id", name="uq_provider_subscription"),)

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_uuid)
    user_id: Mapped[str] = mapped_column(String(32), ForeignKey("users.id"), nullable=False, index=True)
    provider: Mapped[str] = mapped_column(String(40), nullable=False)  # "mock" | "stripe" | ...
    customer_id: Mapped[str] = mapped_column(String(200), nullable=False)
    subscription_id: Mapped[str] = mapped_column(String(200), nullable=False)
    plan: Mapped[str] = mapped_column(String(40), nullable=False)  # OPERATOR | COMMAND
    status: Mapped[str] = mapped_column(String(40), nullable=False)  # active|trialing|past_due|canceled|incomplete
    current_period_start: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    current_period_end: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    cancel_at_period_end: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now, onupdate=_now, nullable=False)

    user: Mapped["User"] = relationship(back_populates="subscriptions")


class Entitlement(Base):
    __tablename__ = "entitlements"
    __table_args__ = (UniqueConstraint("user_id", "feature", name="uq_user_feature"),)

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_uuid)
    user_id: Mapped[str] = mapped_column(String(32), ForeignKey("users.id"), nullable=False, index=True)
    feature: Mapped[str] = mapped_column(String(60), nullable=False)
    enabled: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    usage_limit: Mapped[int | None] = mapped_column(Integer, nullable=True)
    reset_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now, onupdate=_now, nullable=False)

    user: Mapped["User"] = relationship(back_populates="entitlements")


class UsageCounter(Base):
    """Atomic per-period consumption counter. period_key encodes the window
    ("2026-09-05" for a daily feature, "2026-09" for monthly) so a new period
    is just a new row — no cron-driven reset job needed."""

    __tablename__ = "usage_counters"
    __table_args__ = (UniqueConstraint("user_id", "feature", "period_key", name="uq_user_feature_period"),)

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_uuid)
    user_id: Mapped[str] = mapped_column(String(32), ForeignKey("users.id"), nullable=False, index=True)
    feature: Mapped[str] = mapped_column(String(60), nullable=False)
    period_key: Mapped[str] = mapped_column(String(20), nullable=False)
    count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now, onupdate=_now, nullable=False)


class WebhookEvent(Base):
    """One row per processed provider event id. The unique constraint is the
    idempotency guard: a replayed webhook hits it and is a no-op."""

    __tablename__ = "webhook_events"
    __table_args__ = (UniqueConstraint("provider", "event_id", name="uq_provider_event"),)

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_uuid)
    provider: Mapped[str] = mapped_column(String(40), nullable=False)
    event_id: Mapped[str] = mapped_column(String(200), nullable=False)
    event_type: Mapped[str] = mapped_column(String(80), nullable=False)
    received_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now, nullable=False)


class RefreshToken(Base):
    __tablename__ = "refresh_tokens"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_uuid)
    user_id: Mapped[str] = mapped_column(String(32), ForeignKey("users.id"), nullable=False, index=True)
    token_hash: Mapped[str] = mapped_column(String(128), nullable=False, unique=True, index=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    revoked: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now, nullable=False)


class WorkflowRun(Base):
    """Backs the OPERATOR-only WORKFLOW_HISTORY feature. Stores only the
    already-DLP-scrubbed task goal (never raw form values, never
    screenshots) — same privacy bar as everything else in this system."""

    __tablename__ = "workflow_runs"
    __table_args__ = (UniqueConstraint("user_id", "session_id", name="uq_user_session"),)

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_uuid)
    user_id: Mapped[str] = mapped_column(String(32), ForeignKey("users.id"), nullable=False, index=True)
    session_id: Mapped[str] = mapped_column(String(80), nullable=False)
    task_goal: Mapped[str] = mapped_column(Text, nullable=False, default="")
    page_url: Mapped[str] = mapped_column(String(500), nullable=False, default="")
    step_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    done: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now, onupdate=_now, nullable=False)
