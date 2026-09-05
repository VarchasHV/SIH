"""Central runtime configuration for auth, billing and entitlements.

Everything here is env-driven so the same code runs in dev (SQLite + mock
billing) and production (Postgres + a real billing provider) without code
changes. See server/.env.example for the full list of variables.
"""
from __future__ import annotations

import json
import os
import secrets
from pathlib import Path

SERVER_DIR = Path(__file__).parent

# --- auth / tokens ----------------------------------------------------------
# In dev, fall back to a random-per-process secret so nothing "works by
# accident" with a shared default — but this means restarting the server
# invalidates all sessions. Production MUST set JWT_SECRET explicitly.
JWT_SECRET = os.environ.get("JWT_SECRET") or secrets.token_urlsafe(32)
JWT_SECRET_IS_EPHEMERAL = "JWT_SECRET" not in os.environ
JWT_ALGORITHM = "HS256"
ACCESS_TOKEN_TTL_MINUTES = int(os.environ.get("ACCESS_TOKEN_TTL_MINUTES", "15"))
REFRESH_TOKEN_TTL_DAYS = int(os.environ.get("REFRESH_TOKEN_TTL_DAYS", "30"))

# --- database ----------------------------------------------------------------
DATABASE_URL = os.environ.get("DATABASE_URL", f"sqlite:///{SERVER_DIR / 'connor.db'}")

# Dev convenience only: create tables on boot if they don't exist yet, so
# `npm run server` works without a manual migration step. This NEVER alters
# existing tables — `alembic upgrade head` is the only supported way to
# change schema, and is required in production.
AUTO_CREATE_DB = os.environ.get("AUTO_CREATE_DB", "true").lower() in ("1", "true", "yes")

# --- billing -------------------------------------------------------------
BILLING_PROVIDER = os.environ.get("BILLING_PROVIDER", "mock").lower()
BILLING_WEBHOOK_SECRET = os.environ.get("BILLING_WEBHOOK_SECRET", "dev-mock-webhook-secret")
PUBLIC_APP_URL = os.environ.get("PUBLIC_APP_URL", "http://localhost:8000")

STRIPE_SECRET_KEY = os.environ.get("STRIPE_SECRET_KEY", "")
STRIPE_WEBHOOK_SECRET = os.environ.get("STRIPE_WEBHOOK_SECRET", "")
STRIPE_PRICE_IDS = {
    "OPERATOR": os.environ.get("STRIPE_PRICE_OPERATOR", ""),
    "COMMAND": os.environ.get("STRIPE_PRICE_COMMAND", ""),
}

# --- rate limiting (in-process; see rate_limit.py for the multi-instance caveat) --
RATE_LIMIT_AUTH_PER_MIN = int(os.environ.get("RATE_LIMIT_AUTH_PER_MIN", "10"))
RATE_LIMIT_WEBHOOK_PER_MIN = int(os.environ.get("RATE_LIMIT_WEBHOOK_PER_MIN", "120"))
RATE_LIMIT_STEP_PER_MIN = int(os.environ.get("RATE_LIMIT_STEP_PER_MIN", "30"))

# --- plan / feature map -------------------------------------------------------
_PLANS_PATH = Path(os.environ.get("PLANS_CONFIG_PATH", SERVER_DIR / "plans.json"))
with open(_PLANS_PATH, "r", encoding="utf-8") as f:
    PLAN_CONFIG: dict = json.load(f)

PLAN_NAMES = list(PLAN_CONFIG.keys())
FREE_PLAN = "EXPLORER"

assert FREE_PLAN in PLAN_CONFIG, "plans.json must define the EXPLORER (free) plan"
