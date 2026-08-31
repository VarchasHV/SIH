"""
Tier1_FastPath: Zero-Gravity Local PII Detection Engine & Hybrid Router.
Part of the Two-Tier Privacy Lens Architecture ("Project Antigravity").
"""

from __future__ import annotations

import os
import time
from typing import Any, Dict, List, Optional, Set, Tuple

try:
    import regex as re
except ImportError:
    import re

# -----------------------------------------------------------------------------
# 1. Verhoeff Checksum Algorithm (D5 Dihedral Group)
# -----------------------------------------------------------------------------

VERHOEFF_D = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
    [1, 2, 3, 4, 0, 6, 7, 8, 9, 5],
    [2, 3, 4, 0, 1, 7, 8, 9, 5, 6],
    [3, 4, 0, 1, 2, 8, 9, 5, 6, 7],
    [4, 0, 1, 2, 3, 9, 5, 6, 7, 8],
    [5, 9, 8, 7, 6, 0, 4, 3, 2, 1],
    [6, 5, 9, 8, 7, 1, 0, 4, 3, 2],
    [7, 6, 5, 9, 8, 2, 1, 0, 4, 3],
    [8, 7, 6, 5, 9, 3, 2, 1, 0, 4],
    [9, 8, 7, 6, 5, 4, 3, 2, 1, 0],
]

VERHOEFF_P = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
    [1, 5, 7, 6, 2, 8, 3, 0, 9, 4],
    [5, 8, 0, 3, 7, 9, 6, 1, 4, 2],
    [8, 9, 1, 6, 0, 4, 3, 5, 2, 7],
    [9, 4, 5, 3, 1, 2, 6, 8, 7, 0],
    [4, 2, 8, 6, 5, 7, 3, 9, 0, 1],
    [2, 7, 9, 3, 8, 0, 6, 4, 1, 5],
    [7, 0, 4, 6, 9, 1, 3, 2, 5, 8],
]


def verhoeff_valid(digits: Any) -> bool:
    """Validate 12-digit numbers using the Verhoeff algorithm."""
    s = re.sub(r"\D", "", str(digits))
    if len(s) != 12:
        return False
    c = 0
    for i, ch in enumerate(reversed(s)):
        c = VERHOEFF_D[c][VERHOEFF_P[i % 8][int(ch)]]
    return c == 0


def luhn_valid(digits: Any) -> bool:
    """Validate payment card numbers using the Luhn checksum."""
    s = re.sub(r"\D", "", str(digits))
    if not (12 <= len(s) <= 19):
        return False
    total = 0
    dbl = False
    for ch in reversed(s):
        d = int(ch)
        if dbl:
            d *= 2
            if d > 9:
                d -= 9
        total += d
        dbl = not dbl
    return total % 10 == 0


# -----------------------------------------------------------------------------
# 2. Tier 1 Fast-Path Engine
# -----------------------------------------------------------------------------

class Tier1_FastPath:
    """
    Sub-10ms PII detection engine with lookbehind negative gating
    and mathematical checksum validation.
    """

    PATTERNS = [
        # [FIX 1: Aadhaar] - unspaced, spaces, or dashes + Verhoeff validation
        {
            "category": "aadhaar",
            "regex": re.compile(r"\b\d{4}[\s-]?\d{4}[\s-]?\d{4}\b"),
            "validator": lambda m: verhoeff_valid(re.sub(r"[\s-]", "", m)),
            "confidence": 0.99,
        },
        # [FIX 2: Phone (IN)] - Strict non-digit prefix boundary gating
        {
            "category": "phone-in",
            "regex": re.compile(r"(?<!\d)(?:\+?91[\s-]?)?[6-9]\d{9}\b"),
            "validator": None,
            "confidence": 0.85,
        },
        # [FIX 3: SSN] - Negative lookbehind to ignore Order/Ref/ID prefixes
        {
            "category": "ssn",
            "regex": re.compile(
                r"(?<!(?:order|ref|id|batch|serial|part)[:\s-]*)\b\d{3}-\d{2}-\d{4}\b",
                re.IGNORECASE,
            ),
            "validator": None,
            "confidence": 0.92,
        },
        # [FIX 4: IPv4] - Negative lookbehind to ignore software version identifiers
        {
            "category": "ipv4",
            "regex": re.compile(
                r"(?<![vV](?:ersion)?\.?\s*)\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"
            ),
            "validator": None,
            "confidence": 0.85,
        },
        # Standard PII Categories
        {
            "category": "email",
            "regex": re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
            "validator": None,
            "confidence": 0.98,
        },
        {
            "category": "pan",
            "regex": re.compile(r"\b[A-Z]{5}[0-9]{4}[A-Z]\b"),
            "validator": None,
            "confidence": 0.97,
        },
        {
            "category": "gstin",
            "regex": re.compile(r"\b\d{2}[A-Z]{5}\d{4}[A-Z][A-Z0-9]Z[A-Z0-9]\b"),
            "validator": None,
            "confidence": 0.97,
        },
        {
            "category": "ifsc",
            "regex": re.compile(r"\b[A-Z]{4}0[A-Z0-9]{6}\b"),
            "validator": None,
            "confidence": 0.90,
        },
        {
            "category": "upi-vpa",
            "regex": re.compile(r"\b[A-Za-z0-9.\-_]{2,}@(?:oksbi|okhdfcbank|okicici|okaxis|paytm|ybl|apl|ibl|axl|upi)\b", re.IGNORECASE),
            "validator": None,
            "confidence": 0.90,
        },
        {
            "category": "voter-id",
            "regex": re.compile(r"\b[A-Z]{3}[0-9]{7}\b"),
            "validator": None,
            "confidence": 0.75,
        },
        {
            "category": "vehicle-reg",
            "regex": re.compile(r"\b[A-Z]{2}[ -]?\d{1,2}[ -]?[A-Z]{1,3}[ -]?\d{4}\b"),
            "validator": None,
            "confidence": 0.75,
        },
        {
            "category": "passport-in",
            "regex": re.compile(r"\b[A-PR-WY][1-9]\d\s?\d{4}[1-9]\b"),
            "validator": None,
            "confidence": 0.80,
        },
        {
            "category": "credit-card",
            "regex": re.compile(r"\b(?:\d[\s-]?){12,19}\b"),
            "validator": lambda m: luhn_valid(m),
            "confidence": 0.95,
        },
        {
            "category": "dob",
            "regex": re.compile(r"\b(?:0?[1-9]|[12]\d|3[01])[/\-.](?:0?[1-9]|1[0-2])[/\-.](?:19|20)\d{2}\b"),
            "validator": None,
            "confidence": 0.60,
        },
    ]

    @classmethod
    def detect(cls, text: str) -> List[Dict[str, Any]]:
        """Run Tier 1 detection over raw text in <10ms."""
        if not text or not isinstance(text, str):
            return []

        hits: List[Dict[str, Any]] = []
        for rule in cls.PATTERNS:
            for match in rule["regex"].finditer(text):
                val = match.group(0)
                validator = rule["validator"]
                if validator and not validator(val):
                    continue
                hits.append({
                    "category": rule["category"],
                    "value": val,
                    "start": match.start(),
                    "end": match.end(),
                    "confidence": rule["confidence"],
                })

        # Deduplicate & resolve overlapping spans (longer/higher confidence wins)
        hits.sort(key=lambda h: (h["start"], -h["confidence"], -(h["end"] - h["start"])))
        resolved: List[Dict[str, Any]] = []
        for h in hits:
            conflict = any(h["start"] < r["end"] and r["start"] < h["end"] for r in resolved)
            if not conflict:
                resolved.append(h)

        return resolved


# -----------------------------------------------------------------------------
# 3. Two-Tier Routing & Payload Analysis
# -----------------------------------------------------------------------------

def invoke_tier2_vlm(payload: Dict[str, Any]) -> Dict[str, Any]:
    """Tier 2 Heavy-Lift VLM: Invoked for image payloads with Gemini 3.6 Flash."""
    model = os.environ.get("VLM_MODEL", "gemini-3.6-flash")
    api_key = os.environ.get("GEMINI_API_KEY") or os.environ.get("VLM_API_KEY")

    image_data = payload.get("image") or payload.get("screenshot") or ""
    mime_type = "image/png"
    if image_data.startswith("data:"):
        match = re.match(r"data:([^;]+);base64,(.*)", image_data)
        if match:
            mime_type, image_data = match.group(1), match.group(2)

    if not api_key:
        return {
            "tier": 2,
            "engine": model,
            "status": "simulated",
            "detections": payload.get("mockDetections", []),
            "boundingBoxes": [{"x": 10, "y": 20, "width": 100, "height": 30, "label": "face"}],
        }

    import httpx
    body = {
        "contents": [{
            "role": "user",
            "parts": [
                {"text": "Locate all PII bounding boxes and redaction regions in this image."},
                {"inlineData": {"mimeType": mime_type, "data": image_data}},
            ],
        }],
        "generationConfig": {
            "temperature": 0,
            "responseMimeType": "application/json",
            "thinkingConfig": {"thinkingLevel": "low"},
        },
    }
    url = f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent"
    resp = httpx.post(url, json=body, headers={"x-goog-api-key": api_key}, timeout=30)
    return {
        "tier": 2,
        "engine": model,
        "raw": resp.json(),
    }


def analyzePayload(data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Route payload through Two-Tier Architecture:
    - Text: Immediately processed via Tier 1 (<10ms local regex).
    - Image: Routed to Tier 2 VLM (Gemini 3.6 Flash).
    """
    t0 = time.perf_counter()
    payload_type = data.get("type", "text")

    if payload_type == "image":
        # Tier 2 Heavy-Lift VLM
        vlm_res = invoke_tier2_vlm(data)
        latency_ms = (time.perf_counter() - t0) * 1000
        return {
            "tier": 2,
            "latencyMs": latency_ms,
            "results": vlm_res,
        }

    # Tier 1 Fast-Path
    text = data.get("text", "")
    detections = Tier1_FastPath.detect(text)
    latency_ms = (time.perf_counter() - t0) * 1000

    return {
        "tier": 1,
        "latencyMs": latency_ms,
        "sub10ms": latency_ms < 10.0,
        "detections": detections,
    }


analyze_payload = analyzePayload
