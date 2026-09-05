"""Auth flow: signup, login, refresh rotation, logout revocation."""
from __future__ import annotations

import helpers


def test_signup_then_use_access_token():
    c = helpers.client()
    tokens = helpers.signup(c)
    r = c.get("/entitlements/me", headers=helpers.auth_headers(tokens["access_token"]))
    assert r.status_code == 200


def test_duplicate_signup_rejected():
    c = helpers.client()
    email = helpers.unique_email()
    helpers.signup(c, email=email)
    r = c.post("/auth/signup", json={"email": email, "password": "another password"})
    assert r.status_code == 409


def test_login_wrong_password_rejected():
    c = helpers.client()
    tokens = helpers.signup(c)
    r = c.post("/auth/login", json={"email": tokens["email"], "password": "wrong password entirely"})
    assert r.status_code == 401


def test_login_correct_password_succeeds():
    c = helpers.client()
    tokens = helpers.signup(c)
    r = c.post("/auth/login", json={"email": tokens["email"], "password": tokens["password"]})
    assert r.status_code == 200
    assert "access_token" in r.json()


def test_refresh_rotates_and_old_token_becomes_invalid():
    c = helpers.client()
    tokens = helpers.signup(c)
    r1 = c.post("/auth/refresh", json={"refresh_token": tokens["refresh_token"]})
    assert r1.status_code == 200
    new_tokens = r1.json()
    assert new_tokens["refresh_token"] != tokens["refresh_token"]

    # the original refresh token was single-use; reusing it must fail
    r2 = c.post("/auth/refresh", json={"refresh_token": tokens["refresh_token"]})
    assert r2.status_code == 401


def test_logout_revokes_refresh_token():
    c = helpers.client()
    tokens = helpers.signup(c)
    r = c.post("/auth/logout", json={"refresh_token": tokens["refresh_token"]})
    assert r.status_code == 204
    r2 = c.post("/auth/refresh", json={"refresh_token": tokens["refresh_token"]})
    assert r2.status_code == 401


def test_password_is_never_stored_in_plaintext():
    c = helpers.client()
    tokens = helpers.signup(c)
    user_id = helpers.user_id_from_token(tokens["access_token"])
    db = helpers.db_session()
    try:
        import models

        user = db.query(models.User).filter(models.User.id == user_id).first()
        assert user.password_hash != tokens["password"]
        assert user.password_hash.startswith("$2b$")  # bcrypt
    finally:
        db.close()
