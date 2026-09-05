// Entitlement/billing client. Every value here is a cached READ of what the
// server last reported — it is used only to render UI (plan badge, usage
// meter, upgrade prompts). It is never consulted to decide whether an
// operation is allowed; that decision is always the server's response to
// the actual operation (see agent-client.mjs's 402/403 handling). Treat this
// module as "what should we show the user", not "what should we allow".

import { authFetch } from "./auth-client.mjs";

export async function fetchEntitlements(serverUrl) {
  const res = await authFetch(serverUrl, "/entitlements/me");
  if (!res.ok) throw Object.assign(new Error(`HTTP ${res.status}`), { status: res.status });
  return res.json();
}

/**
 * Metering checkpoint for the direct-to-cloud (BYOK) agent path, which does
 * not otherwise touch the local server at all. Must be called — and must
 * succeed — before every direct cloud VLM call, or usage limits would be
 * trivially bypassed by switching AI provider mode. Throws (with
 * err.status === 402) when the caller's allowance is exhausted.
 */
export async function consumeUsage(serverUrl, operation = "agent_step") {
  const res = await authFetch(serverUrl, "/entitlements/consume", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ operation }),
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    const err = new Error(data?.detail?.message || `HTTP ${res.status}`);
    err.status = res.status;
    err.detail = data.detail;
    throw err;
  }
  return data;
}

export async function startCheckout(serverUrl, plan) {
  const res = await authFetch(serverUrl, "/billing/checkout", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ plan }),
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data?.detail || `HTTP ${res.status}`);
  return data; // { checkout_url, session_id, provider }
}

export async function cancelSubscription(serverUrl) {
  const res = await authFetch(serverUrl, "/billing/cancel", { method: "POST" });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data?.detail || `HTTP ${res.status}`);
  return data;
}

export default { fetchEntitlements, consumeUsage, startCheckout, cancelSubscription };
