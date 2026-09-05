"""Password hashing, JWT access tokens, and opaque refresh tokens.

Access tokens are short-lived JWTs (HS256) used only as a bearer credential —
they are never trusted for plan/entitlement claims; every request that needs
entitlement data re-reads it from the database (see entitlements.py). This is
the core "backend is authoritative" guarantee: a forged or replayed JWT with
a tampered payload still only identifies *a user id*, and that id's plan is
looked up server-side, not read from the token.

Refresh tokens are opaque random strings, stored server-side only as a
SHA-256 hash (so a DB read doesn't leak usable tokens), and rotated on every
use — this bounds the blast radius of a leaked refresh token and makes
logout/revocation actually work, which a stateless JWT refresh token cannot.
"""
from __future__ import annotations

import hashlib
import secrets
from datetime import datetime, timedelta, timezone
from typing import Any

import bcrypt
import jwt

import config

TOKEN_TYPE_ACCESS = "access"

# A fixed, valid bcrypt hash of a random value nobody knows — used to make the
# login path do a constant-shape bcrypt comparison even when no such user
# exists, so response timing can't be used to enumerate registered emails.
DUMMY_HASH = bcrypt.hashpw(b"connor-dummy-hash-for-timing-safety", bcrypt.gensalt()).decode("utf-8")


def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


def verify_password(password: str, password_hash: str) -> bool:
    try:
        return bcrypt.checkpw(password.encode("utf-8"), password_hash.encode("utf-8"))
    except ValueError:
        return False


def create_access_token(user_id: str) -> tuple[str, datetime]:
    now = datetime.now(timezone.utc)
    expires_at = now + timedelta(minutes=config.ACCESS_TOKEN_TTL_MINUTES)
    payload = {
        "sub": user_id,
        "type": TOKEN_TYPE_ACCESS,
        "iat": int(now.timestamp()),
        "exp": int(expires_at.timestamp()),
    }
    token = jwt.encode(payload, config.JWT_SECRET, algorithm=config.JWT_ALGORITHM)
    return token, expires_at


def decode_access_token(token: str) -> dict[str, Any] | None:
    try:
        payload = jwt.decode(token, config.JWT_SECRET, algorithms=[config.JWT_ALGORITHM])
    except jwt.PyJWTError:
        return None
    if payload.get("type") != TOKEN_TYPE_ACCESS:
        return None
    return payload


def new_refresh_token() -> tuple[str, str, datetime]:
    """Returns (raw_token_to_send_to_client, sha256_hash_to_store, expires_at)."""
    raw = secrets.token_urlsafe(48)
    token_hash = hashlib.sha256(raw.encode("utf-8")).hexdigest()
    expires_at = datetime.now(timezone.utc) + timedelta(days=config.REFRESH_TOKEN_TTL_DAYS)
    return raw, token_hash, expires_at


def hash_refresh_token(raw: str) -> str:
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()
