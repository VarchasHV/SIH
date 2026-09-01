// Service worker: orchestrates the privacy-preserving agent loop.
//
//   content (PL_PREPARE)  -> skeleton + domPiiBoxes + profile values   [PII stays local]
//   captureVisibleTab     -> raw screenshot
//   offscreen (PL_VISION) -> redacted screenshot (blackout) + vision detections
//   filter                -> ALL redacted/sensitive fields are REMOVED from the skeleton
//   server  (/agent/step) -> receives ONLY unredacted skeleton + blacked-out screenshot
//   content (PL_EXECUTE)  -> performs actions on unredacted fields only; strictly blocks censored fields
//
// The popup receives PL_PROGRESS events (including the exact egress payload) and
// can gate each server call / the final submit.

import { requestStep, validatePlan } from "./lib/agent-client.mjs";
import { SENSITIVE_PATTERNS, CENSORED_CATEGORIES, isRestrictedCategory, isSensitiveCategory } from "./lib/sensitive-fields.mjs";

const DEFAULTS = {
  serverUrl: "http://localhost:8000",
  redactionMode: "blackout",
  maxSteps: 12,
  confirmEachSend: false,
  confirmBeforeSubmit: true,
};

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

// ---- offscreen lifecycle -------------------------------------------------
let offscreenReady = false;
async function ensureOffscreen() {
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
}

async function callOffscreen(message, tries = 3) {
  for (let i = 0; i < tries; i++) {
    try {
      return await chrome.runtime.sendMessage(message);
    } catch (e) {
      if (i === tries - 1) throw e;
      await new Promise((r) => setTimeout(r, 250));
    }
  }
}

async function injectAgentScripts(tabId) {
  await chrome.scripting.executeScript({
    target: { tabId },
    files: ["lib/sensitive-fields.js", "dlp-content-script.js", "content.js", "skeleton.js", "executor.js", "agent-bridge.js", "dom-redactor.js"],
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
function waitForGate(id, kind) {
  emit({ type: "gate", id, kind });
  return new Promise((resolve) => {
    const t = setTimeout(() => { gates.delete(id); resolve(false); }, 90000); // auto-deny if popup is gone
    gates.set(id, (approved) => { clearTimeout(t); resolve(approved); });
  });
}

// ---- the loop --------------------------------------------------------
let running = null;

async function runAgentTask(opts) {
  const cfg = { ...DEFAULTS, ...opts };
  const [tab] = await chrome.tabs.query({ active: true, lastFocusedWindow: true });
  if (!tab?.id) throw new Error("No active tab.");
  const tabId = tab.id;
  running = { cancel: false };

  await ensureOffscreen();
  const history = [];
  let sanitizedPayloadForPreview = null;

  for (let step = 1; step <= cfg.maxSteps; step++) {
    if (running.cancel) { emit({ type: "cancelled", step }); break; }
    emit({ type: "step-start", step });

    // 1. page context
    const prep = await prepare(tabId);
    if (!prep?.ok) throw new Error(prep?.error || "prepare failed");

    // 2. raw screenshot strictly scoped to active tab & window (credential/session scope isolation)
    const currentTab = await chrome.tabs.get(tabId).catch(() => null);
    if (!currentTab || !currentTab.active) {
      throw new Error("Active tab focus lost: session scope isolation prevented background capture.");
    }
    const shot = await chrome.tabs.captureVisibleTab(tab.windowId, { format: "png" });

    // 3. on-device vision + blackout redaction
    const fields = prep.skeleton.nodes
      .filter((n) => ["input", "textarea", "select"].includes(n.tag) && n.visible)
      .map((n) => ({ id: n.id, piiCategory: n.piiCategory, bbox: n.bbox, alwaysRedact: n.alwaysRedact }));
    const vis = await callOffscreen({
      action: "PL_VISION",
      payload: { screenshot: shot, domPiiBoxes: prep.domPiiBoxes, fields, dpr: prep.skeleton.viewport.dpr, mode: "blackout" },
    });
    if (!vis?.ok) throw new Error("vision failed: " + (vis?.error || "unknown"));

    // show the user what was redacted, on the page
    send(tabId, { action: "PL_HIGHLIGHT", regions: vis.redactedRegions.map((r) => ({ ...r, deviceCoords: true })), kind: "redact" }).catch(() => {});

    // 4. SANITIZE SKELETON: PRESERVE CENSORED/ALWAYS-REDACT NODES WITH LOCAL FILL TOKENS, STRIP REAL DATA LEAKS
    // The server sees element structure + isCensored: true + fillToken ("local:category"), with ZERO real values or label text.
    const sanitizedNodes = prep.skeleton.nodes.map((node) => {
      if (node.isCensored || node.alwaysRedact) {
        return {
          id: node.id,
          tag: node.tag,
          type: node.type,
          role: node.role,
          visible: node.visible,
          bbox: node.bbox,
          isCensored: true,
          alwaysRedact: true,
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

    const sanitizedSkeleton = {
      ...prep.skeleton,
      nodes: sanitizedNodes,
    };

    // 5. Sanitized payload sent to server — zero PII, zero raw secret values
    const payload = {
      taskGoal: cfg.goal,
      step,
      skeleton: sanitizedSkeleton,
      visionDetections: [], // Never send PII category names/locations to the LLM
      screenshot: vis.redactedDataURL,
      history: history.slice(-4),
    };
    sanitizedPayloadForPreview = { ...payload, screenshot: "<blacked-out image, " + Math.round(vis.redactedDataURL.length / 1024) + " KB>" };

    emit({
      type: "egress",
      step,
      payloadPreview: sanitizedPayloadForPreview,
      redactedImage: vis.redactedDataURL,
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
      const where = e.isNetworkError ? "network (server offline)" : `server (HTTP ${e.status || "error"})`;
      emit({ type: "error", step, where, message: e.message });
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

    // 9. execute
    let doneFlag = false;
    for (const act of v.actions) {
      if (act.action === "submit" && cfg.confirmBeforeSubmit) {
        const ok = await waitForGate(`submit-${step}`, "submit");
        if (!ok) { emit({ type: "submit-skipped", step }); doneFlag = true; break; }
      }
      const targetNode = sanitizedNodes.find((n) => n.id === act.targetId);
      // Double check guard: only block if targetNode is censored AND has no local fill data available
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
      emit({ type: "action", step, action: act, result: res?.result });
      history.push({ step, action: sanitizeAction(act), result: res?.result });
      if (act.action === "done" || res?.result?.done) { doneFlag = true; break; }
      await new Promise((r) => setTimeout(r, 350));
    }
    if (doneFlag || plan.done) { emit({ type: "done", step }); break; }
  }

  running = null;
  emit({ type: "finished", history });
  return { history };
}

// strip any PII-related data from action for history
const sanitizeAction = (a) => ({ action: a.action, targetId: a.targetId, piiCategory: a.piiCategory, hadLiteral: a.literalValue != null });

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
