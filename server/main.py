"""CONNOR agent server.

POST /agent/step  - sanitized context in, validated action plan out.
GET  /health      - liveness + current VLM mode.
GET  /privacy     - the redaction/token scheme the client and server share.
"""
from __future__ import annotations

import os

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware

from schema import StepRequest, StepResponse
from vlm import VLMUnavailable, run_step

from pathlib import Path

try:
    from dotenv import load_dotenv

    load_dotenv(Path(__file__).parent / ".env")
    load_dotenv()
except Exception:  # noqa: BLE001
    pass

app = FastAPI(title="CONNOR Agent", version="0.2.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # chrome-extension:// origins; fine for a local demo
    allow_methods=["*"],
    allow_headers=["*"],
)


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


@app.post("/agent/step", response_model=StepResponse)
def agent_step(req: StepRequest) -> StepResponse:
    try:
        return run_step(req)
    except VLMUnavailable as exc:
        # 503 -> the client stops the agent and offers a retry. No mock fallback.
        raise HTTPException(status_code=503, detail=f"AI unavailable — {exc}") from exc
