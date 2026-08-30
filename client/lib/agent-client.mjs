// Talks to the server-side VLM agent. Sends only sanitized context; validates
// every action that comes back before the executor is allowed to touch it.

export const ACTIONS = ["click", "type", "select", "scroll", "submit", "wait", "done"];

/**
 * @param {object} action
 * @param {Set<string>} knownIds     - skeleton element ids
 */
export function validateAction(action, knownIds) {
  if (!action || typeof action !== "object") return "not an object";
  if (!ACTIONS.includes(action.action)) return `unknown action "${action.action}"`;
  if (["click", "type", "select"].includes(action.action)) {
    if (!action.targetId) return `${action.action} needs targetId`;
    if (knownIds && !knownIds.has(action.targetId)) return `unknown targetId "${action.targetId}"`;
  }
  if (["type", "select"].includes(action.action)) {
    const hasVal = action.piiCategory != null || action.fillToken != null || action.literalValue != null;
    if (!hasVal) return `${action.action} needs piiCategory, fillToken or literalValue`;
  }
  return null; // ok
}

export function validatePlan(actions, knownIds) {
  if (!Array.isArray(actions)) return { ok: false, error: "actions is not an array", actions: [] };
  const clean = [];
  for (const a of actions) {
    const err = validateAction(a, knownIds);
    if (err) return { ok: false, error: err, actions: clean };
    clean.push(a);
    if (a.action === "done") break;
  }
  return { ok: true, actions: clean };
}

/**
 * @param {string} serverUrl  - e.g. http://localhost:8000
 * @param {object} payload    - { taskGoal, step, skeleton, tokenMap, screenshot, history }
 * @param {{timeoutMs?:number}} opts
 */
export async function requestStep(serverUrl, payload, opts = {}) {
  const { timeoutMs = 45000 } = opts;
  const ctl = new AbortController();
  const t = setTimeout(() => ctl.abort(), timeoutMs);
  const started = performance.now();
  try {
    const res = await fetch(`${serverUrl.replace(/\/$/, "")}/agent/step`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(payload),
      signal: ctl.signal,
    });
    if (!res.ok) {
      const errText = (await res.text()).slice(0, 200);
      const err = new Error(`HTTP ${res.status}: ${errText}`);
      err.isServerError = true;
      err.status = res.status;
      throw err;
    }
    const data = await res.json();
    return {
      actions: data.actions || [],
      rationale: data.rationale || "",
      done: !!data.done,
      serverLatencyMs: data.latency_ms ?? null,
      roundTripMs: performance.now() - started,
    };
  } catch (err) {
    if (err.name === "AbortError") {
      const timeoutErr = new Error(`Server request timed out after ${timeoutMs}ms`);
      timeoutErr.isTimeout = true;
      throw timeoutErr;
    }
    if (!err.isServerError) {
      err.isNetworkError = true;
    }
    throw err;
  } finally {
    clearTimeout(t);
  }
}

export default { requestStep, validatePlan, validateAction, ACTIONS };
