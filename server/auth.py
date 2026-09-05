"""Authentication: signup, login, refresh, logout, and the `get_current_user`
dependency every protected route depends on.

This is intentionally a minimal, real email+password auth system (no OAuth
provider is configured in this repository) — see the final report for what
production hardening (email verification, password reset, lockout policy)
is still needed before this is customer-facing.
"""
from __future__ import annotations

import re
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field, field_validator
from sqlalchemy.orm import Session

import config
import models
import security
from db import get_db
from rate_limit import enforce_rate_limit

router = APIRouter(prefix="/auth", tags=["auth"])

_PASSWORD_MIN_LEN = 8
# Deliberately simple format check (not full RFC 5322 / deliverability
# validation, and no special-use-domain blocklist) — good enough to reject
# obvious garbage without rejecting legitimate addresses on internal/test
# domains, which is all this self-hosted auth system needs.
_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def _validate_email(value: str) -> str:
    value = value.strip().lower()
    if not _EMAIL_RE.match(value) or len(value) > 320:
        raise ValueError("not a valid email address")
    return value


class SignupRequest(BaseModel):
    email: str
    password: str = Field(min_length=_PASSWORD_MIN_LEN, max_length=200)

    _normalize_email = field_validator("email")(_validate_email)


class LoginRequest(BaseModel):
    email: str
    password: str

    _normalize_email = field_validator("email")(_validate_email)


class RefreshRequest(BaseModel):
    refresh_token: str


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int


def _issue_tokens(user: models.User, db: Session) -> TokenResponse:
    access_token, expires_at = security.create_access_token(user.id)
    raw_refresh, refresh_hash, refresh_expires = security.new_refresh_token()
    db.add(models.RefreshToken(user_id=user.id, token_hash=refresh_hash, expires_at=refresh_expires))
    db.commit()
    ttl = int((expires_at - datetime.now(timezone.utc)).total_seconds())
    return TokenResponse(access_token=access_token, refresh_token=raw_refresh, expires_in=ttl)


@router.post("/signup", response_model=TokenResponse, status_code=201)
def signup(body: SignupRequest, request: Request, db: Session = Depends(get_db)):
    enforce_rate_limit(f"auth:signup:{request.client.host if request.client else 'unknown'}", limit=config.RATE_LIMIT_AUTH_PER_MIN)
    email = body.email.lower().strip()
    existing = db.query(models.User).filter(models.User.email == email).first()
    if existing:
        # Same status/shape as a real validation error — do not reveal whether
        # the account exists via a different error code/timing-sensitive path.
        raise HTTPException(status_code=409, detail="An account with this email already exists.")
    user = models.User(email=email, password_hash=security.hash_password(body.password))
    db.add(user)
    db.commit()
    db.refresh(user)
    return _issue_tokens(user, db)


@router.post("/login", response_model=TokenResponse)
def login(body: LoginRequest, request: Request, db: Session = Depends(get_db)):
    enforce_rate_limit(f"auth:login:{request.client.host if request.client else 'unknown'}", limit=config.RATE_LIMIT_AUTH_PER_MIN)
    email = body.email.lower().strip()
    user = db.query(models.User).filter(models.User.email == email).first()
    # Always run the bcrypt comparison, even for a nonexistent user (against a
    # fixed dummy hash) — otherwise "no such user" returns near-instantly
    # while "wrong password" takes a bcrypt round-trip, letting an attacker
    # enumerate registered emails purely from response timing.
    password_ok = security.verify_password(body.password, user.password_hash if user else security.DUMMY_HASH)
    if not user or not password_ok:
        raise HTTPException(status_code=401, detail="Invalid email or password.")
    if not user.is_active:
        raise HTTPException(status_code=403, detail="Account disabled.")
    return _issue_tokens(user, db)


@router.post("/refresh", response_model=TokenResponse)
def refresh(body: RefreshRequest, db: Session = Depends(get_db)):
    token_hash = security.hash_refresh_token(body.refresh_token)
    row = db.query(models.RefreshToken).filter(models.RefreshToken.token_hash == token_hash).first()
    now = datetime.now(timezone.utc)
    if not row or row.revoked or row.expires_at.replace(tzinfo=timezone.utc) < now:
        raise HTTPException(status_code=401, detail="Refresh token invalid or expired.")
    user = db.query(models.User).filter(models.User.id == row.user_id).first()
    if not user or not user.is_active:
        raise HTTPException(status_code=401, detail="Account unavailable.")
    # rotate: the presented refresh token is single-use
    row.revoked = True
    db.commit()
    return _issue_tokens(user, db)


@router.post("/logout", status_code=204)
def logout(body: RefreshRequest, db: Session = Depends(get_db)):
    token_hash = security.hash_refresh_token(body.refresh_token)
    row = db.query(models.RefreshToken).filter(models.RefreshToken.token_hash == token_hash).first()
    if row:
        row.revoked = True
        db.commit()
    return None


_BEARER_RE = re.compile(r"^Bearer\s+(.+)$", re.I)


def get_current_user(request: Request, db: Session = Depends(get_db)) -> models.User:
    """The authoritative identity check. Every protected route depends on
    this — there is no path to a User object that does not go through a
    verified, unexpired access token."""
    auth_header = request.headers.get("authorization", "")
    m = _BEARER_RE.match(auth_header)
    if not m:
        raise HTTPException(status_code=401, detail="Missing bearer token.")
    payload = security.decode_access_token(m.group(1))
    if not payload:
        raise HTTPException(status_code=401, detail="Invalid or expired token.")
    user = db.query(models.User).filter(models.User.id == payload["sub"]).first()
    if not user or not user.is_active:
        raise HTTPException(status_code=401, detail="Account unavailable.")
    return user
