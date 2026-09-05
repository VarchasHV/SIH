"""Minimal in-process rate limiting.

Fixed-window counters keyed by an arbitrary string (caller composes
"auth:login:<ip>", "webhook:<provider>", "step:<user_id>", ...). This is
enough to blunt credential-stuffing / brute-force / webhook-flood attempts on
a single-process deployment.

Production caveat (documented, not hidden): this state is per-process and
resets on restart. A horizontally-scaled deployment needs a shared store
(Redis INCR + EXPIRE is the standard choice) — swapping the implementation
here is a one-file change; every caller already goes through
`enforce_rate_limit`, so nothing else needs to change.
"""
from __future__ import annotations

import time
from collections import defaultdict, deque

from fastapi import HTTPException

_WINDOW_SECONDS = 60
_hits: dict[str, deque] = defaultdict(deque)


def enforce_rate_limit(key: str, limit: int, window_seconds: int = _WINDOW_SECONDS) -> None:
    now = time.monotonic()
    q = _hits[key]
    cutoff = now - window_seconds
    while q and q[0] < cutoff:
        q.popleft()
    if len(q) >= limit:
        raise HTTPException(status_code=429, detail="Too many requests. Please slow down.")
    q.append(now)


def reset_all() -> None:
    """Test-only helper."""
    _hits.clear()
