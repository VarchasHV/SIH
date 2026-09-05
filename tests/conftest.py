"""Session-wide test setup for the Python (pytest) suite.

Runs before any test module in tests/ is imported (conftest.py files are
always loaded first), so environment variables set here are visible the
first time anything imports server/config.py — regardless of which test
file happens to trigger that import first.

Uses a throwaway temp-file SQLite database, a fixed (non-random) JWT secret,
and the mock billing provider — never the developer's real server/.env.
"""
from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SERVER_DIR = ROOT / "server"
sys.path.insert(0, str(SERVER_DIR))

_db_fd, _db_path = tempfile.mkstemp(prefix="connor_test_", suffix=".db")
os.close(_db_fd)

os.environ["DATABASE_URL"] = f"sqlite:///{_db_path}"
os.environ["JWT_SECRET"] = "test-only-secret-do-not-use-in-production"
os.environ["BILLING_PROVIDER"] = "mock"
os.environ["BILLING_WEBHOOK_SECRET"] = "test-webhook-secret"
os.environ["AUTO_CREATE_DB"] = "true"
os.environ["ACCESS_TOKEN_TTL_MINUTES"] = "15"
os.environ.setdefault("VLM_MODE", "mock")

import db as _db  # noqa: E402

_db.init_db()

import pytest  # noqa: E402
import rate_limit as _rate_limit  # noqa: E402


@pytest.fixture(autouse=True)
def _reset_rate_limits():
    # TestClient requests all share one fake source IP, so the in-memory
    # rate limiter (see rate_limit.py) would otherwise accumulate hits
    # across unrelated tests and start rejecting legitimate signups/logins
    # partway through the suite. Real deployments don't have this problem —
    # real clients have distinct IPs.
    _rate_limit.reset_all()
    yield


def pytest_sessionfinish(session, exitstatus):  # noqa: ARG001
    for suffix in ("", "-wal", "-shm"):
        try:
            os.remove(_db_path + suffix)
        except OSError:
            pass
