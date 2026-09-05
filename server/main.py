"""CONNOR agent server.

POST /agent/step  - authenticated, sanitized context in, validated action plan out.
GET  /health      - liveness + current VLM mode.
GET  /privacy     - the redaction/token scheme the client and server share.

Auth, billing, entitlements and usage accounting live in auth.py,
billing/, entitlements.py and usage.py respectively — see those modules for
the actual authorization logic. This file only wires routers together and
applies the entitlement/usage gate in front of /agent/step.
"""
from __future__ import annotations

import os
from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session

import models
import routes_billing
import routes_entitlements
import routes_reports
import routes_workflows
from auth import get_current_user
from auth import router as auth_router
from db import get_db, init_db
from entitlements import FEATURES, can_access
from rate_limit import enforce_rate_limit
from schema import StepRequest, StepResponse
from usage import check_and_consume
from vlm import VLMUnavailable, run_step

import config
from pathlib import Path

try:
    from dotenv import load_dotenv

    load_dotenv(Path(__file__).parent / ".env")
    load_dotenv()
except Exception:  # noqa: BLE001
    pass

@asynccontextmanager
async def _lifespan(_app: FastAPI):
    if config.AUTO_CREATE_DB:
        init_db()
    if config.JWT_SECRET_IS_EPHEMERAL:
        print("WARNING: JWT_SECRET not set — using a random per-process secret. "
              "All sessions will be invalidated on restart. Set JWT_SECRET in production.")
    yield


app = FastAPI(title="CONNOR Agent", version="0.3.0", lifespan=_lifespan)

# Bearer-token auth (not cookies) means there is no ambient credential a
# cross-site page could ride along on CSRF-style — every request must
# explicitly attach an Authorization header, which cross-origin JS cannot do
# to a third party without already having the token. That is why a wide-open
# CORS origin list is an acceptable choice here (it is NOT for cookie-auth'd
# APIs) — see the security review for the full argument.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # chrome-extension:// origins; fine for a bearer-token API
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(auth_router)
app.include_router(routes_entitlements.router)
app.include_router(routes_billing.router)
app.include_router(routes_workflows.router)
app.include_router(routes_reports.router)


@app.get("/health")
def health() -> dict:
    mode = os.environ.get("VLM_MODE", "gemini")
    return {"ok": True, "vlm_mode": mode,
            "model": os.environ.get("VLM_MODEL", "mock" if mode == "mock" else "unset"),
            "mock_fallback": False}


@app.get("/privacy")
def privacy() -> dict:
    return {
        "scheme": "blackout-redaction",
        "redaction_mode": "blackout (solid black boxes)",
        "server_sees": ["redacted screenshot (all PII blacked out with solid boxes)",
                        "accessibility skeleton (values reduced to empty/filled/readonly)"],
        "server_never_sees": ["any real PII value", "raw screenshot", "field contents", "tokens"],
        "note": "No tokenization. The client resolves PII categories to real values locally, immediately before typing.",
    }


@app.get("/features")
def list_features() -> dict:
    """Static feature catalogue (no auth needed — this is not per-user data),
    so the extension can render plan comparison UI without hardcoding the
    feature list in JS."""
    return {"plans": config.PLAN_CONFIG, "features": sorted(FEATURES)}


@app.post("/agent/step", response_model=StepResponse)
def agent_step(
    req: StepRequest,
    request: Request,
    user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> StepResponse:
    enforce_rate_limit(f"step:{user.id}", limit=config.RATE_LIMIT_STEP_PER_MIN)
    # Authoritative usage gate: raises HTTP 402 with structured upgrade info
    # if this user's current-period allowance is exhausted. This is the ONE
    # place agent_step calls are metered for the local-server path — the
    # direct-to-cloud (BYOK) path meters itself via POST /entitlements/consume
    # instead (see routes_entitlements.py) so it can never double-count.
    check_and_consume(user, "agent_step", db)

    try:
        resp = run_step(req)
    except VLMUnavailable as exc:
        # 503 -> the client stops the agent and offers a retry. No mock fallback.
        raise HTTPException(status_code=503, detail=f"AI unavailable — {exc}") from exc

    if can_access(user, "WORKFLOW_HISTORY", db):
        import routes_workflows

        session_id = request.headers.get("x-session-id") or "default"
        routes_workflows.record_step(user, session_id, req.taskGoal, req.skeleton.url, resp.done, db)

    return resp
