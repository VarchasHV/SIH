// Universal background service worker & event script: orchestrates the privacy-preserving agent loop.
// Compatible with both Google Chrome (MV3 offscreen document) and Mozilla Firefox (Gecko MV3).
//
//   content (PL_PREPARE)  -> skeleton + domPiiBoxes + profile values   [PII stays local]
//   captureVisibleTab     -> raw screenshot
//   vision (PL_VISION)    -> redacted screenshot (blackout) + vision detections
//   filter                -> ALL redacted/sensitive fields are REMOVED from the skeleton
//   goal    -> free-form task goal is DLP-scrubbed (sanitizeTaskGoal) before egress
//   server  (/agent/step) -> receives ONLY unredacted skeleton + blacked-out screenshot + scrubbed goal
//   content (PL_EXECUTE)  -> performs actions on unredacted fields only; strictly blocks censored fields
//
// The popup receives PL_PROGRESS events (including the exact egress payload) and
// can gate each server call / the final submit.

import { requestStep, validatePlan } from "./lib/agent-client.mjs";
import { SENSITIVE_PATTERNS, CENSORED_CATEGORIES, isRestrictedCategory, isSensitiveCategory } from "./lib/sensitive-fields.mjs";
import { generateDPDPAuditReport } from "./lib/dpdp-audit.mjs";
import { sanitizeTaskGoal } from "./lib/dlp-heuristics.mjs";
import { assertNoSensitivePayload } from "./lib/egress-guard.mjs";
import { enforceEgressPolicy } from "./lib/security-policy.mjs";
import { classifyAction } from "./lib/action-firewall.mjs";

const isChromeOffscreenSupported = typeof chrome !== "undefined" &&
  typeof chrome.offscreen !== "undefined" &&
  typeof chrome.runtime?.getContexts === "function";

const DEFAULTS = {
  serverUrl: "http://localhost:8000",
  redactionMode: "blackout",
  maxSteps: 8,
  confirmEachSend: false,
  confirmBeforeSubmit: true,
};

// Loop-termination tuning. The agent must converge, not spin.
const MAX_FIELD_ATTEMPTS = 2;   // give up on a field after this many failed fills
const MAX_STAGNANT_STEPS = 2;   // stop after this many steps with zero new fills

const wantsSubmit = (goal) =>
  /\b(submit|and submit|complete and submit|send the form)\b/i.test(goal) &&
  !/\b(don'?t submit|do not submit|stop before submit(ting)?|without submitting|no submit)\b/i.test(goal);

const planSignature = (actions) =>
  (actions || []).map((a) => `${a.action}:${a.targetId || a.ms || ""}`).join("|");

// Can the agent actually act on this node? (empty, on-screen, and we have a way to fill it)
function isActionable(n, isDead) {
  if (!n.visible || n.state !== "empty" || n.skip || isDead(n.id)) return false;
  if (["input", "textarea"].includes(n.tag)) return !!(n.hasFill || n.fillToken);
  if (n.tag === "select") return Array.isArray(n.options) && n.options.length > 0;
  return false;
}

// ---- legacy "scan" path (unchanged behaviour for the old popup button) ----
async function scanActiveTab() {
  const [tab] = await chrome.tabs.query({ active: true, lastFocusedWindow: true });
  if (!tab?.id) throw new Error("No active tab found.");
  try {
    return await chrome.tabs.sendMessage(tab.id, { action: "GET_PII_BOXES" });
  } catch {
    await chrome.scripting.executeScript({ target: { tabId: tab.id }, files: ["content.js"] });
    return await chrome.tabs.sendMessage(tab.id, { action: "GET_PII_BOXES" });
  }
}

// ---- vision engine dispatcher (Chrome Offscreen vs Firefox in-context) ----
let offscreenReady = false;
let visionPipelineModule = null;

async function ensureVisionEngine() {
  if (isChromeOffscreenSupported) {
    const existing = await chrome.runtime.getContexts({ contextTypes: ["OFFSCREEN_DOCUMENT"] });
    if (existing.length) { offscreenReady = true; return; }
    offscreenReady = false;
    await chrome.offscreen.createDocument({
      url: "offscreen.html",
      reasons: ["WORKERS", "BLOBS"],
      justification: "Runs on-device OCR + face detection and redacts the screenshot before any network call.",
    });
    // wait for the module to register its message listener
    for (let i = 0; i < 40 && !offscreenReady; i++) await new Promise((r) => setTimeout(r, 100));
  } else {
    // Firefox / environments without chrome.offscreen
    if (!visionPipelineModule) {
      visionPipelineModule = await import("./lib/vision-pipeline.mjs");
    }
    offscreenReady = true;
  }
}

async function executeVision(payload, tries = 3) {
  if (isChromeOffscreenSupported) {
    for (let i = 0; i < tries; i++) {
      try {
        return await chrome.runtime.sendMessage({ action: "PL_VISION", payload });
      } catch (e) {
        if (i === tries - 1) throw e;
        await new Promise((r) => setTimeout(r, 250));
      }
    }
  } else {
    // Firefox native path
    if (!visionPipelineModule) {
      visionPipelineModule = await import("./lib/vision-pipeline.mjs");
    }
    const res = await visionPipelineModule.processVision(payload);
    return { ok: true, ...res };
  }
}

async function injectAgentScripts(tabId) {
  await chrome.scripting.executeScript({
    target: { tabId },
    files: ["lib/sensitive-fields.js", "lib/adversarial-guard.js", "dlp-content-script.js", "content.js", "skeleton.js", "executor.js", "agent-bridge.js", "dom-redactor.js"],
  });
}

function send(tabId, message) {
  return chrome.tabs.sendMessage(tabId, message);
}

async function prepare(tabId) {
  try {
    return await send(tabId, { action: "PL_PREPARE" });
  } catch {
    await injectAgentScripts(tabId);
    return await send(tabId, { action: "PL_PREPARE" });
  }
}

// ---- progress fan-out to popup ----------------------------------------
function emit(evt) {
  chrome.runtime.sendMessage({ action: "PL_PROGRESS", evt }).catch(() => {});
}

// popup can resolve a gate (send / submit) via PL_GATE_RESOLVE
const gates = new Map();
function waitForGate(id, kind, meta = null) {
  emit({ type: "gate", id, kind, meta });
  return new Promise((resolve) => {
    const t = setTimeout(() => { gates.delete(id); resolve(false); }, 90000); // auto-deny if popup is gone
    gates.set(id, (approved) => { clearTimeout(t); resolve(approved); });
  });
}

// { "pii:email": 2, "secret:aws...": 1 } -> { email: 2 }
function countsToByCategory(counts) {
  const out = {};
  for (const [k, v] of Object.entries(counts || {})) {
    const cat = k.includes(":") ? k.split(":").slice(1).join(":") : k;
    out[cat] = (out[cat] || 0) + v;
  }
  return out;
}

// ---- the loop --------------------------------------------------------
let running = null;

async function runAgentTask(opts) {
  const cfg = { ...DEFAULTS, ...opts };

  // DLP egress guard: the goal is free-form user text and is a common place for
  // literal PII to leak to the remote VLM. Scrub it once, up front, and only
  // ever transmit the sanitized form.
  const safeGoal = sanitizeTaskGoal(cfg.goal);
  if (safeGoal.redacted) {
    emit({ type: "goal-redacted", original: cfg.goal, sanitized: safeGoal.text, hits: safeGoal.hits });
  }

  const [tab] = await chrome.tabs.query({ active: true, lastFocusedWindow: true });
  if (!tab?.id) throw new Error("No active tab.");
  const tabId = tab.id;
  running = { cancel: false };

  await ensureVisionEngine();
  const history = [];
  let sanitizedPayloadForPreview = null;

  // ---- convergence trackers ----
  const filledOk = new Set();          // targetIds we successfully filled + verified
  const failedAttempts = new Map();    // targetId -> failed fill count
  const isDead = (id) => (failedAttempts.get(id) || 0) >= MAX_FIELD_ATTEMPTS;
  let stagnantSteps = 0;
  let prevPlanSig = null;
  let didSubmit = false;
  const goalWantsSubmit = wantsSubmit(safeGoal.text);

  const stop = (step, reason) => { emit({ type: "done", step, reason }); };

  for (let step = 1; step <= cfg.maxSteps; step++) {
    if (running.cancel) { emit({ type: "cancelled", step }); break; }
    emit({ type: "step-start", step });

    // 1. page context
    const prep = await prepare(tabId);
    if (!prep?.ok) throw new Error(prep?.error || "prepare failed");

    // 2. raw screenshot
    const shot = await chrome.tabs.captureVisibleTab(tab.windowId, { format: "png" });

    // 3. on-device vision + blackout redaction
    const fields = prep.skeleton.nodes
      .filter((n) => ["input", "textarea", "select"].includes(n.tag) && n.visible)
      .map((n) => ({ id: n.id, piiCategory: n.piiCategory, bbox: n.bbox }));
    const vis = await executeVision({
      screenshot: shot,
      domPiiBoxes: prep.domPiiBoxes,
      fields,
      dpr: prep.skeleton.viewport.dpr,
      mode: "blackout",
      a11yStats: prep.skeleton.a11yStats,
    });
    if (!vis?.ok) throw new Error("vision failed: " + (vis?.error || "unknown"));

    // 3b. REDACTION VERIFICATION GATE — re-OCR of the masked screenshot found
    //     PII/secrets still readable after one re-mask pass. Do NOT send a
    //     partially-redacted image to the VLM.
    emit({
      type: "redaction-verified", step,
      verified: vis.redactionVerified !== false,
      status: vis.redactionStatus || "SKIPPED",
      repasses: vis.stats?.redaction?.repasses ?? 0,
      residualCategories: vis.redactionResidual ? [...new Set(vis.redactionResidual.map((r) => r.category || r.subtype || r.kind))] : [],
    });
    if (vis.redactionVerified === false) {
      emit({
        type: "error", step, where: "redaction verification", retryable: false,
        message: `BLOCKED: the screenshot still shows ${(vis.stats?.redaction?.residualCategories || ["PII"]).join(", ")} after re-masking. Nothing was sent.`,
      });
      history.push({ step, error: `redaction verification failed: ${(vis.stats?.redaction?.residualCategories || []).join(",")}` });
      break;
    }

    // show the user what was redacted, on the page
    send(tabId, { action: "PL_HIGHLIGHT", regions: vis.redactedRegions.map((r) => ({ ...r, deviceCoords: true })), kind: "redact" }).catch(() => {});

    // Generate India DPDP Act 2023 Compliance Audit Report
    const dpdpReport = generateDPDPAuditReport({
      url: prep.skeleton.url,
      step,
      detections: prep.domPiiBoxes,
      securityAlerts: prep.securityAlerts || [],
      hybridStats: vis.timings || {},
    });

    // 4. SANITIZE SKELETON: PRESERVE CENSORED NODES WITH LOCAL FILL TOKENS, STRIP REAL DATA LEAKS
    const sanitizedNodes = prep.skeleton.nodes.map((node) => {
      if (node.isCensored) {
        return {
          id: node.id,
          tag: node.tag,
          type: node.type,
          role: node.role,
          visible: node.visible,
          bbox: node.bbox,
          isCensored: true,
          hasFill: !!node.hasFill,
          fillToken: node.fillToken || (node.piiCategory ? `local:${node.piiCategory}` : null),
          piiCategory: node.piiCategory || null,
          label: "", // Strip label text to prevent raw PII text leakage
          name: null,
          state: node.state === "filled" ? "filled" : "empty",
        };
      }
      return {
        ...node,
        state: node.state === "filled" ? "filled" : "empty",
      };
    });

    // 4b. Retire fields we've already tried and failed to fill, so the model
    //     stops proposing them every step (the #1 cause of the loop spinning).
    for (const n of sanitizedNodes) {
      if (n.state === "empty" && isDead(n.id)) {
        n.state = "readonly";
        n.skip = true;
      }
    }

    const sanitizedSkeleton = {
      ...prep.skeleton,
      nodes: sanitizedNodes,
    };

    // 4c. Local completion check — if there is nothing the agent can still do,
    //     stop now instead of burning steps asking the model to invent work.
    const actionable = sanitizedNodes.filter((n) => isActionable(n, isDead));
    const submitBtn = sanitizedNodes.find(
      (n) => n.visible && (n.isSubmit || n.tag === "button" || n.role === "button"),
    );
    if (actionable.length === 0) {
      if (goalWantsSubmit && submitBtn && !didSubmit) {
        // fall through — let the agent press submit this step
      } else if (filledOk.size === 0 && step === 1) {
        // page may still be mounting (SPA); give it one grace cycle before giving up
        emit({ type: "step-start", step: step + 0.5 });
        await new Promise((resolve) => setTimeout(resolve, 800));
        continue;
      } else {
        stop(step, filledOk.size
          ? "all fillable fields handled"
          : "no fields could be filled — add values in the Profile tab");
        break;
      }
    }

    // 5. Sanitized payload sent to server — zero PII, zero raw secret values
    let payload = {
      taskGoal: safeGoal.text,
      step,
      skeleton: sanitizedSkeleton,
      visionDetections: [], // Never send PII category names/locations to the LLM
      screenshot: vis.redactedDataURL,
      history: history.slice(-8),
    };

    // 5b. SECURITY POLICY ENGINE — the egress choke point. Walks the exact bytes
    //     about to leave the browser: PII, secrets/credentials, canary tokens,
    //     raw profile values. Decision: ALLOW / SANITIZE / BLOCK / REQUIRE_APPROVAL.
    const gate = enforceEgressPolicy(payload, {
      profile: prep.profileValues || {},
      destination: cfg.serverUrl,
      destinationTrust: /^https:\/\/(localhost|127\.0\.0\.1)/.test(cfg.serverUrl) || /^http:\/\/(localhost|127\.0\.0\.1)/.test(cfg.serverUrl) ? 1 : 0.6,
    });
    emit({ type: "security-classification", step, decision: gate.result.decision, classification: gate.result.classification, counts: gate.result.summary.counts });
    if (gate.blocked) {
      emit({ type: "error", step, where: "security policy", retryable: false,
             message: `BLOCKED: ${gate.result.reasons.join("; ")}. Nothing was sent to the server.` });
      history.push({ step, error: `egress blocked: ${gate.result.classification}` });
      break;
    }
    if (gate.needsApproval) {
      const ok = await waitForGate(`approve-egress-${step}`, "approval", {
        title: "Send this context to the AI?",
        risk: gate.result.classification,
        reasons: gate.result.reasons,
        counts: gate.result.summary.counts,
        destination: gate.result.summary.destination,
      });
      if (!ok) { emit({ type: "cancelled", step, reason: "egress not approved" }); break; }
    }
    if (gate.result.decision === "SANITIZE") {
      emit({ type: "egress-redacted", step, byCategory: countsToByCategory(gate.result.summary.counts), total: gate.result.findings.length });
    }
    payload = gate.payload;

    sanitizedPayloadForPreview = { ...payload, screenshot: "<blacked-out image, " + Math.round(vis.redactedDataURL.length / 1024) + " KB>" };

    emit({
      type: "egress",
      step,
      payloadPreview: sanitizedPayloadForPreview,
      rawImage: shot,
      redactedImage: vis.redactedDataURL,
      securityAlerts: prep.securityAlerts || [],
      dpdpReport,
      a11yStats: prep.skeleton.a11yStats,
      visionStats: vis.stats,
      timings: vis.timings,
    });

    // 6. optional human gate before the network call
    if (cfg.confirmEachSend) {
      const ok = await waitForGate(`send-${step}`, "send");
      if (!ok) { emit({ type: "cancelled", step }); break; }
    }

    // 7. server round-trip
    let plan;
    try {
      plan = await requestStep(cfg.serverUrl, payload);
    } catch (e) {
      const aiDown = e.status === 503;
      const where = e.isNetworkError ? "network (server offline)"
        : e.isTimeout ? "AI timed out"
        : aiDown ? "AI unavailable"
        : `server (HTTP ${e.status || "error"})`;
      // The server no longer falls back to a mock agent — a model failure
      // stops the run and the user retries.
      emit({ type: "error", step, where, message: e.message, retryable: true, aiUnavailable: aiDown || e.isTimeout || e.isNetworkError });
      break;
    }
    emit({ type: "plan", step, rationale: plan.rationale, actions: plan.actions, serverLatencyMs: plan.serverLatencyMs, roundTripMs: Math.round(plan.roundTripMs) });

    // 8. validate: ensure actions ONLY target known nodes in skeleton
    const allowedIds = new Set(sanitizedNodes.map((n) => n.id));
    const v = validatePlan(plan.actions, allowedIds);
    if (!v.ok) {
      emit({ type: "error", step, where: "validation", message: v.error });
      history.push({ step, error: `invalid action: ${v.error}` });
      continue;
    }

    // 8b. Repeat-plan guard: if the model returns the exact same non-terminal
    //     plan two steps running, it is stuck — stop rather than spin.
    const planSig = planSignature(v.actions);
    const terminalPlan = v.actions.some((a) => a.action === "submit" || a.action === "done");
    if (planSig && planSig === prevPlanSig && !terminalPlan) {
      stop(step, "agent repeated the same plan with no progress");
      break;
    }
    prevPlanSig = planSig;

    // 9. execute
    let doneFlag = false;
    let progressed = false; // any state-changing action landed this step
    const pageMalicious = (prep.securityAlerts || []).some((s) => /INJECTION|ADVERSARIAL|MALICIOUS/i.test(s.type || ""));
    for (const act of v.actions) {
      const targetNode = sanitizedNodes.find((n) => n.id === act.targetId)
        || prep.skeleton.nodes.find((n) => n.id === act.targetId);

      // 9a. ACTION FIREWALL — classify risk before the action touches the page.
      const fw = classifyAction(act, {
        targetNode,
        pageOrigin: (() => { try { return new URL(prep.skeleton.url).origin; } catch { return null; } })(),
        pageMalicious,
      });
      emit({ type: "action-risk", step, action: sanitizeAction(act), risk: fw.risk, decision: fw.decision, reasons: fw.reasons, exfil: fw.exfil ? { channel: fw.exfil.channel, categories: fw.exfil.categories } : null });
      if (fw.decision === "BLOCK") {
        emit({ type: "error", step, where: "action firewall", retryable: false,
               message: `BLOCKED (${fw.risk}): ${fw.reasons.join("; ")}` });
        history.push({ step, action: sanitizeAction(act), error: `action firewall blocked: ${fw.risk}` });
        if (fw.exfil) { stop(step, "data-exfiltration attempt blocked"); doneFlag = true; }
        continue;
      }
      if (fw.decision === "REQUIRE_APPROVAL") {
        const ok = await waitForGate(`approve-action-${step}-${act.targetId || act.action}`, "approval", {
          title: `The agent wants to ${describeAction(act, targetNode)}`,
          risk: fw.risk,
          reasons: fw.reasons,
          counts: fw.exfil ? Object.fromEntries((fw.exfil.categories || []).map((c) => [c, 1])) : {},
          destination: targetNode?.formOrigin || targetNode?.href || null,
        });
        if (!ok) { emit({ type: "action", step, action: act, result: { ok: false, note: "not approved by user" } }); continue; }
      }
      if (act.action === "submit" && cfg.confirmBeforeSubmit && fw.decision !== "REQUIRE_APPROVAL") {
        const ok = await waitForGate(`submit-${step}`, "submit");
        if (!ok) { emit({ type: "submit-skipped", step }); doneFlag = true; break; }
      }
      if (targetNode?.isCensored && !targetNode?.hasFill && !targetNode?.fillToken) {
        emit({ type: "error", step, message: `Action blocked on censored node ${act.targetId}: no local profile data to fill` });
        continue;
      }
      if (targetNode?.piiCategory) {
        act.piiCategory = targetNode.piiCategory;
      }
      if (targetNode?.fillToken) {
        act.fillToken = targetNode.fillToken;
      }
      send(tabId, { action: "PL_HIGHLIGHT", regions: targetNode ? [targetNode.bbox] : [], kind: "target" }).catch(() => {});
      const res = await send(tabId, { action: "PL_EXECUTE", step: act });
      const r = res?.result || {};
      emit({ type: "action", step, action: act, result: r });
      history.push({ step, action: sanitizeAction(act), result: r });

      // track per-field success/failure so we can retire dead fields
      if (["type", "select"].includes(act.action) && act.targetId) {
        if (r.ok && r.verified !== false) {
          filledOk.add(act.targetId);
          failedAttempts.delete(act.targetId);
          progressed = true;
        } else {
          failedAttempts.set(act.targetId, (failedAttempts.get(act.targetId) || 0) + 1);
        }
      }
      if (["click", "scroll"].includes(act.action) && r.ok) progressed = true;
      if (act.action === "submit" && r.ok) didSubmit = true;

      if (act.action === "done" || r.done) { doneFlag = true; break; }
      await new Promise((resolve) => setTimeout(resolve, 350));
    }

    if (doneFlag || plan.done) { emit({ type: "done", step }); break; }
    if (didSubmit) { stop(step, "form submitted"); break; }

    // 10. Stagnation guard: nothing changed on the page this step.
    stagnantSteps = progressed ? 0 : stagnantSteps + 1;
    if (stagnantSteps >= MAX_STAGNANT_STEPS) {
      stop(step, "no progress over consecutive steps");
      break;
    }
  }

  running = null;
  emit({ type: "finished", history });
  return { history };
}

// strip any PII-related data from action for history
const sanitizeAction = (a) => ({ action: a.action, targetId: a.targetId, piiCategory: a.piiCategory, hadLiteral: a.literalValue != null });

// short human phrase for the approval gate — no raw values
function describeAction(a, node) {
  const what = (node?.text || node?.label || node?.name || a.targetId || "").toString().slice(0, 40);
  switch (a.action) {
    case "submit": return `submit the form${what ? ` (${what})` : ""}`;
    case "click": return node?.href ? `open ${(() => { try { return new URL(node.href).host; } catch { return "a link"; } })()}` : `click "${what}"`;
    case "type": case "select": return `fill the ${node?.piiCategory || what || "field"}`;
    default: return `${a.action} ${what}`.trim();
  }
}

// ---- message routing -------------------------------------------------
chrome.runtime.onMessage.addListener((request, _sender, sendResponse) => {
  switch (request.action) {
    case "PL_OFFSCREEN_READY":
      offscreenReady = true;
      return false;
    case "SCAN_ACTIVE_TAB":
      scanActiveTab().then((r) => sendResponse({ ok: true, ...r })).catch((e) => sendResponse({ ok: false, error: e.message }));
      return true;
    case "PL_RUN_TASK":
      if (running) { sendResponse({ ok: false, error: "a task is already running" }); return false; }
      sendResponse({ ok: true, started: true });
      runAgentTask(request.opts).catch((e) => { running = null; emit({ type: "error", message: e.message }); emit({ type: "finished", history: [] }); });
      return false;
    case "PL_CANCEL_TASK":
      if (running) running.cancel = true;
      sendResponse({ ok: true });
      return false;
    case "PL_GATE_RESOLVE": {
      const r = gates.get(request.id);
      if (r) { gates.delete(request.id); r(request.approved); }
      sendResponse({ ok: true });
      return false;
    }
    default:
      return false;
  }
});

chrome.action.onClicked.addListener(() => {
  scanActiveTab().catch(() => undefined);
});
