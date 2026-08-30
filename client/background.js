// Service worker: orchestrates the privacy-preserving agent loop.
//
//   content (PL_PREPARE)  -> skeleton + domPiiBoxes + token context   [PII stays here]
//   captureVisibleTab     -> raw screenshot
//   offscreen (PL_VISION) -> redacted screenshot + vision detections
//   server  (/agent/step) -> validated action plan                    [sees only tokens]
//   content (PL_EXECUTE)  -> performs each action, resolving tokens locally
//
// The popup receives PL_PROGRESS events (including the exact egress payload) and
// can gate each server call / the final submit.

import { requestStep, validatePlan } from "./lib/agent-client.mjs";

const DEFAULTS = {
  serverUrl: "http://localhost:8000",
  redactionMode: "blur",
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
    files: ["content.js", "skeleton.js", "executor.js", "agent-bridge.js"],
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

    // 1. page context (tokenized already)
    const prep = await prepare(tabId);
    if (!prep?.ok) throw new Error(prep?.error || "prepare failed");

    // 2. raw screenshot
    const shot = await chrome.tabs.captureVisibleTab(tab.windowId, { format: "png" });

    // 3. on-device vision + redaction
    const fields = prep.skeleton.nodes
      .filter((n) => ["input", "textarea", "select"].includes(n.tag) && n.visible)
      .map((n) => ({ id: n.id, piiCategory: n.piiCategory, bbox: n.bbox }));
    const vis = await callOffscreen({
      action: "PL_VISION",
      payload: { screenshot: shot, domPiiBoxes: prep.domPiiBoxes, fields, dpr: prep.skeleton.viewport.dpr, mode: cfg.redactionMode },
    });
    if (!vis?.ok) throw new Error("vision failed: " + (vis?.error || "unknown"));

    // 3b. enrich the skeleton with fields the vision channel could name
    for (const [fid, cat] of Object.entries(vis.fieldCategories || {})) {
      const node = prep.skeleton.nodes.find((n) => n.id === fid);
      if (node && !node.piiCategory) {
        node.piiCategory = cat;
        node.fillToken = prep.profileTokens[cat] || node.fillToken;
        node.labelSource = "vision";
      }
    }

    // show the user what was redacted, on the page
    send(tabId, { action: "PL_HIGHLIGHT", regions: vis.redactedRegions.map((r) => ({ ...r, deviceCoords: true })), kind: "redact" }).catch(() => {});

    // 4. sanitized payload
    const payload = {
      taskGoal: cfg.goal,
      step,
      skeleton: prep.skeleton,
      tokenMap: prep.tokenContext,          // token -> category  (NO values)
      availableTokens: prep.profileTokens,  // category -> token the client can fill
      visionDetections: vis.detections,
      screenshot: vis.redactedDataURL,
      history: history.slice(-4),
    };
    sanitizedPayloadForPreview = { ...payload, screenshot: "<redacted image, " + Math.round(vis.redactedDataURL.length / 1024) + " KB>" };

    emit({
      type: "egress",
      step,
      payloadPreview: sanitizedPayloadForPreview,
      redactedImage: vis.redactedDataURL,
      visionStats: vis.stats,
      timings: vis.timings,
    });

    // 5. optional human gate before the network call
    if (cfg.confirmEachSend) {
      const ok = await waitForGate(`send-${step}`, "send");
      if (!ok) { emit({ type: "cancelled", step }); break; }
    }

    // 6. server round-trip
    let plan;
    try {
      plan = await requestStep(cfg.serverUrl, payload);
    } catch (e) {
      emit({ type: "error", step, where: "server", message: e.message });
      break;
    }
    emit({ type: "plan", step, rationale: plan.rationale, actions: plan.actions, serverLatencyMs: plan.serverLatencyMs, roundTripMs: Math.round(plan.roundTripMs) });

    // 7. validate
    const knownIds = new Set(prep.skeleton.nodes.map((n) => n.id));
    const knownTokens = new Set(Object.keys(prep.tokenContext));
    const v = validatePlan(plan.actions, knownIds, knownTokens);
    if (!v.ok) {
      emit({ type: "error", step, where: "validation", message: v.error });
      history.push({ step, error: `invalid action: ${v.error}` });
      continue;
    }

    // 8. execute
    let doneFlag = false;
    for (const act of v.actions) {
      if (act.action === "submit" && cfg.confirmBeforeSubmit) {
        const ok = await waitForGate(`submit-${step}`, "submit");
        if (!ok) { emit({ type: "submit-skipped", step }); doneFlag = true; break; }
      }
      const targetNode = prep.skeleton.nodes.find((n) => n.id === act.targetId);
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

// keep tokens, drop any literalValue that might carry data
const sanitizeAction = (a) => ({ action: a.action, targetId: a.targetId, valueToken: a.valueToken, hadLiteral: a.literalValue != null });

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
      // respond immediately; the run is driven entirely through PL_PROGRESS events
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
