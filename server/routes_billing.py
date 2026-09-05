"""Checkout, subscription status, cancellation, and the webhook endpoint.

Nothing in this file ever grants access directly. `/billing/checkout` only
returns a URL to go pay at; only a verified webhook (`/billing/webhook`, or
the mock's equivalent `/billing/mock/complete`) ever calls
`apply_subscription_event`, which is the only function that writes
Subscription rows. Returning from the checkout URL does nothing by itself —
the extension re-fetches /entitlements/me and that reflects the truth only
once the webhook has landed.
"""
from __future__ import annotations

import html

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import HTMLResponse
from pydantic import BaseModel
from sqlalchemy.orm import Session

import config
import models
from auth import get_current_user
from billing import BillingProviderError, apply_subscription_event, get_billing_provider
from db import get_db
from rate_limit import enforce_rate_limit

router = APIRouter(tags=["billing"])


class CheckoutRequest(BaseModel):
    plan: str


class CheckoutResponse(BaseModel):
    checkout_url: str
    session_id: str
    provider: str


@router.post("/billing/checkout", response_model=CheckoutResponse)
def create_checkout(body: CheckoutRequest, user: models.User = Depends(get_current_user), db: Session = Depends(get_db)):
    plan = body.plan.upper().strip()
    if plan not in config.PLAN_CONFIG or plan == config.FREE_PLAN:
        raise HTTPException(status_code=400, detail=f"Cannot check out for plan '{plan}'.")
    provider = get_billing_provider()
    try:
        session = provider.create_checkout_session(user, plan, db)
    except BillingProviderError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return CheckoutResponse(checkout_url=session.checkout_url, session_id=session.session_id, provider=session.provider)


@router.get("/billing/subscription")
def get_subscription(user: models.User = Depends(get_current_user), db: Session = Depends(get_db)):
    sub = (
        db.query(models.Subscription)
        .filter(models.Subscription.user_id == user.id)
        .order_by(models.Subscription.current_period_end.desc())
        .first()
    )
    if not sub:
        return {"subscription": None}
    return {
        "subscription": {
            "provider": sub.provider,
            "plan": sub.plan,
            "status": sub.status,
            "current_period_start": sub.current_period_start.isoformat(),
            "current_period_end": sub.current_period_end.isoformat(),
            "cancel_at_period_end": sub.cancel_at_period_end,
        }
    }


@router.post("/billing/cancel")
def cancel_subscription(user: models.User = Depends(get_current_user), db: Session = Depends(get_db)):
    sub = (
        db.query(models.Subscription)
        .filter(models.Subscription.user_id == user.id, models.Subscription.status.in_(["active", "trialing"]))
        .order_by(models.Subscription.current_period_end.desc())
        .first()
    )
    if not sub:
        raise HTTPException(status_code=404, detail="No active subscription to cancel.")
    provider = get_billing_provider()
    provider.cancel_subscription(sub, db)
    return {"ok": True, "cancel_at_period_end": True, "access_until": sub.current_period_end.isoformat()}


@router.post("/billing/webhook")
async def billing_webhook(request: Request, db: Session = Depends(get_db)):
    enforce_rate_limit("webhook:global", limit=config.RATE_LIMIT_WEBHOOK_PER_MIN)
    payload = await request.body()
    provider = get_billing_provider()
    try:
        event = provider.verify_and_parse_webhook(payload, dict(request.headers))
    except BillingProviderError as exc:
        # Deliberately generic + logged server-side only — do not leak *why*
        # verification failed (aids signature-forgery brute-forcing).
        raise HTTPException(status_code=400, detail="Webhook rejected.") from exc

    try:
        changed = apply_subscription_event(event, db)
    except BillingProviderError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    return {"ok": True, "applied": changed}


# ---------------------------------------------------------------------------
# Mock-provider-only demo routes. Registered unconditionally so /docs is
# stable, but they only do anything meaningful when BILLING_PROVIDER=mock;
# real providers deliver their webhook straight to /billing/webhook.
# ---------------------------------------------------------------------------


@router.get("/billing/mock/checkout/{session_id}", response_class=HTMLResponse)
def mock_checkout_page(session_id: str):
    from billing.mock_provider import MockBillingProvider

    provider = MockBillingProvider()
    pending = provider.get_pending(session_id)
    if pending is None:
        return HTMLResponse("<h1>Checkout session expired or not found.</h1>", status_code=404)
    plan_cfg = config.PLAN_CONFIG.get(pending.plan, {})
    safe_session_id = html.escape(session_id)
    safe_plan = html.escape(pending.plan)
    price = plan_cfg.get("price_monthly_usd")
    return HTMLResponse(f"""
<!doctype html><html><head><meta charset="utf-8"><title>CONNOR — Mock Checkout</title>
<style>
body{{background:#0b0d0f;color:#e6e8eb;font-family:ui-monospace,Menlo,monospace;display:flex;
     align-items:center;justify-content:center;height:100vh;margin:0}}
.card{{border:1px solid #2a2f36;border-radius:10px;padding:32px;max-width:360px;background:#111418}}
h1{{font-size:15px;letter-spacing:.08em;text-transform:uppercase;color:#7dd3fc;margin:0 0 6px}}
p{{color:#9aa4af;font-size:13px;line-height:1.5}}
button{{margin-top:20px;width:100%;padding:12px;background:#7dd3fc;color:#06171f;border:none;
       border-radius:6px;font-weight:600;cursor:pointer;font-family:inherit}}
.note{{margin-top:14px;font-size:11px;color:#5b6572}}
</style></head><body>
<div class="card">
  <h1>OPERATOR MODE</h1>
  <p>Plan: <b>{safe_plan}</b>{f" — ${price}/mo" if price else ""}</p>
  <p>This is a local development checkout simulator. No payment is processed.
     Clicking below fires a signed webhook exactly as a real provider would —
     this page's own return does not grant access.</p>
  <form method="post" action="/billing/mock/complete">
    <input type="hidden" name="session_id" value="{safe_session_id}" />
    <button type="submit">Simulate successful payment</button>
  </form>
  <div class="note">DEV MOCK PROVIDER — not production payment infrastructure.</div>
</div>
</body></html>
""")


@router.post("/billing/mock/complete", response_class=HTMLResponse)
async def mock_checkout_complete(request: Request, db: Session = Depends(get_db)):
    if config.BILLING_PROVIDER != "mock":
        raise HTTPException(status_code=404, detail="Mock billing is not enabled.")
    form = await request.form()
    session_id = form.get("session_id", "")
    from billing.mock_provider import MockBillingProvider

    provider = MockBillingProvider()
    try:
        payload, headers = provider.build_completion_webhook(str(session_id))
    except BillingProviderError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    # Deliver through the exact same verify -> apply path a real webhook uses.
    event = provider.verify_and_parse_webhook(payload, headers)
    apply_subscription_event(event, db)

    return HTMLResponse("""
<!doctype html><html><head><meta charset="utf-8"><title>CONNOR — Payment complete</title>
<style>body{background:#0b0d0f;color:#e6e8eb;font-family:ui-monospace,Menlo,monospace;
display:flex;align-items:center;justify-content:center;height:100vh;margin:0;text-align:center}
h1{color:#86efac;font-size:16px;letter-spacing:.06em;text-transform:uppercase}
p{color:#9aa4af;font-size:13px}</style></head><body>
<div><h1>&#10003; Operator Mode activated</h1>
<p>You can close this tab and return to the extension.<br/>It will refresh your entitlements automatically.</p></div>
</body></html>
""")
