"""VLM adapters.

Modes (env VLM_MODE):
  gemini - Google Gemini (default here). Set GEMINI_API_KEY + VLM_MODEL
           (e.g. gemini-3.6-flash). The redacted screenshot is sent as inline
           image data so the model uses real visual context.
  openai - any OpenAI-compatible chat/vision endpoint (vLLM / Ollama / OpenRouter
           hosting Qwen2.5-VL, Llama-3.2-Vision, InternVL2, ...).
  mock   - deterministic agent, no network. Reads the sanitized skeleton and
           fills PII fields with their fillToken. Offline fallback.

Any adapter error falls back to `mock` so a demo never hard-stops.
"""
from __future__ import annotations

import json
import os
import re
import time
from pathlib import Path

from schema import Action, StepRequest, StepResponse

SYSTEM_PROMPT = (Path(__file__).parent / "prompts" / "system.md").read_text()

_SUBMIT_WORDS = re.compile(r"\b(submit|send the form|complete and submit|and submit)\b", re.I)
_NO_SUBMIT_WORDS = re.compile(r"\b(don'?t submit|do not submit|stop before submit|without submitting|no submit)\b", re.I)


def _context_json(req: StepRequest) -> str:
    return json.dumps({
        "taskGoal": req.taskGoal,
        "step": req.step,
        "skeleton": req.skeleton.model_dump(exclude_none=True),
        "tokenMap": req.tokenMap,
        "availableTokens": req.availableTokens,
        "visionDetections": [d.model_dump() for d in req.visionDetections],
        "history": [h.model_dump(exclude_none=True) for h in req.history],
    })


def _split_data_url(data_url: str) -> tuple[str, str] | None:
    m = re.match(r"data:([^;]+);base64,(.*)", data_url or "", re.S)
    return (m.group(1), m.group(2)) if m else None


def _extract_json(text: str) -> dict:
    t = re.sub(r"^```(?:json)?\s*|\s*```$", "", (text or "").strip(), flags=re.S)
    return json.loads(t)


def _to_response(data: dict, model: str) -> StepResponse:
    return StepResponse(
        actions=[Action(**a) for a in data.get("actions", []) if isinstance(a, dict)],
        rationale=data.get("rationale", ""),
        done=bool(data.get("done", False)),
        model=model,
    )


# --------------------------------------------------------------------------
# Gemini
# --------------------------------------------------------------------------
def _gemini(req: StepRequest) -> StepResponse:
    import httpx

    key = os.environ.get("GEMINI_API_KEY") or os.environ.get("VLM_API_KEY")
    if not key:
        raise RuntimeError("GEMINI_API_KEY not set")
    model = os.environ.get("VLM_MODEL", "gemini-3.6-flash")

    parts: list[dict] = [{"text": _context_json(req)}]
    img = _split_data_url(req.screenshot) if req.screenshot else None
    if img:
        parts.append({"inlineData": {"mimeType": img[0], "data": img[1]}})

    body = {
        "systemInstruction": {"parts": [{"text": SYSTEM_PROMPT}]},
        "contents": [{"role": "user", "parts": parts}],
        "generationConfig": {
            "temperature": 0,
            "maxOutputTokens": 4096,
            "responseMimeType": "application/json",
            # gemini-3.x flash cannot disable thinking; keep it minimal
            "thinkingConfig": {"thinkingLevel": "low"},
        },
    }
    url = f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent"
    r = httpx.post(url, json=body, headers={"x-goog-api-key": key}, timeout=90)
    payload = r.json()
    if "error" in payload:
        raise RuntimeError(f"gemini {payload['error'].get('code')}: {payload['error'].get('message')}")
    cand = payload["candidates"][0]
    finish = cand.get("finishReason")
    text = "".join(p.get("text", "") for p in cand.get("content", {}).get("parts", []) if not p.get("thought"))
    if not text:
        raise RuntimeError(f"gemini returned no text (finishReason={finish})")
    return _to_response(_extract_json(text), model)


# --------------------------------------------------------------------------
# OpenAI-compatible VLM
# --------------------------------------------------------------------------
def _openai(req: StepRequest) -> StepResponse:
    from openai import OpenAI

    client = OpenAI(
        base_url=os.environ.get("VLM_BASE_URL", "https://openrouter.ai/api/v1"),
        api_key=os.environ.get("VLM_API_KEY", "not-set"),
    )
    model = os.environ.get("VLM_MODEL", "qwen/qwen-2.5-vl-7b-instruct")

    content: list[dict] = [{"type": "text", "text": _context_json(req)}]
    if req.screenshot and req.screenshot.startswith("data:image"):
        content.append({"type": "image_url", "image_url": {"url": req.screenshot}})

    resp = client.chat.completions.create(
        model=model,
        messages=[{"role": "system", "content": SYSTEM_PROMPT}, {"role": "user", "content": content}],
        temperature=0,
        max_tokens=900,
    )
    return _to_response(_extract_json(resp.choices[0].message.content or "{}"), model)


# --------------------------------------------------------------------------
# mock agent
# --------------------------------------------------------------------------
def _mock(req: StepRequest) -> StepResponse:
    actions: list[Action] = []
    handled = {h.action.get("targetId") for h in req.history if h.action}
    for node in req.skeleton.nodes:
        if len(actions) >= 4:
            break
        if not node.visible or node.state in ("filled", "readonly", "disabled") or node.id in handled:
            continue
        token = node.fillToken or (req.availableTokens.get(node.piiCategory or "") if node.piiCategory else None)
        if node.tag in ("input", "textarea") and token:
            actions.append(Action(action="type", targetId=node.id, valueToken=token,
                                  reason=f"fill {node.piiCategory} from local vault"))
        elif node.tag == "select" and node.options and "country" in (node.label or node.name or "").lower():
            opt = next((o for o in node.options if o["label"].strip().lower() in ("india", "in")), None)
            if opt:
                actions.append(Action(action="select", targetId=node.id, literalValue=opt["value"], reason="country = India"))
        elif node.type == "checkbox" and re.search(r"agree|terms|consent", (node.label or ""), re.I):
            actions.append(Action(action="click", targetId=node.id, reason="accept terms"))

    goal = req.taskGoal or ""
    wants_submit = bool(_SUBMIT_WORDS.search(goal)) and not _NO_SUBMIT_WORDS.search(goal)
    if not actions:
        if wants_submit:
            btn = next((n for n in req.skeleton.nodes
                        if (n.isSubmit or n.tag == "button" or n.role == "button")
                        and re.search(r"submit|apply|continue|pay|save|verify", (n.text or ""), re.I)), None)
            if btn:
                return StepResponse(actions=[Action(action="submit", targetId=btn.id)],
                                    rationale="All visible fields handled; submitting.", model="mock")
        return StepResponse(actions=[Action(action="done")], rationale="Nothing left to fill.", done=True, model="mock")
    return StepResponse(actions=actions, rationale=f"Filling {len(actions)} field(s) from the local vault.", model="mock")


_ADAPTERS = {"gemini": _gemini, "openai": _openai, "mock": _mock}


def run_step(req: StepRequest) -> StepResponse:
    mode = os.environ.get("VLM_MODE", "gemini").lower()
    fn = _ADAPTERS.get(mode, _mock)
    t0 = time.time()
    try:
        resp = fn(req)
        if not resp.actions:
            raise RuntimeError("empty action list")
    except Exception as exc:  # noqa: BLE001
        resp = _mock(req)
        resp.rationale = f"[{mode} fell back to mock: {exc}] " + resp.rationale
    resp.latency_ms = int((time.time() - t0) * 1000)
    return resp
