// Popup: profile editor (non-sensitive only) + agent control + activity/egress view.

const $ = (s) => document.querySelector(s);
const statusDot = $("#status-dot");

// ---- tabs -----------------------------------------------------------
document.querySelectorAll(".tab").forEach((t) => {
  t.addEventListener("click", () => {
    document.querySelectorAll(".tab").forEach((x) => x.classList.toggle("is-active", x === t));
    document.querySelectorAll(".panel").forEach((p) => p.classList.toggle("is-active", p.id === `tab-${t.dataset.tab}`));
  });
});

// ---- profile (Identity & contact fields; stored strictly on-device) ----
// [key, placeholder, kind?]. `kind: "date"` is stored canonically as an ISO
// yyyy-MM-dd string but shown to the user as "14 Mar 1998" to kill the
// DD/MM vs MM/DD ambiguity.
const PROFILE_FIELDS = [
  ["full name", "Aditi Sharma"],
  ["first name", "Aditi"],
  ["last name", "Sharma"],
  ["email", "aditi.sharma@example.com"],
  ["phone number", "9876543210"],
  ["date of birth", "14 Mar 1998", "date"],
  ["address", "42 Nehru Road, Bengaluru"],
  ["postal/ZIP code", "560001"],
  ["Aadhaar number", "2345 6789 0123"],
  ["PAN", "ABCDE1234F"],
  ["Passport number", "A1234567"],
  ["Voter ID", "ABC1234567"],
];
const DATE_KEYS = new Set(PROFILE_FIELDS.filter(([, , k]) => k === "date").map(([key]) => key));

const MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];

// Parse free-text (14 Mar 1998, 14/03/1998, 14-03-1998, 1998-03-14) → yyyy-MM-dd, else null.
function toISODate(raw) {
  const v = String(raw || "").trim();
  if (!v) return "";
  if (/^\d{4}-\d{2}-\d{2}$/.test(v)) return v;
  let m = v.match(/^(\d{1,2})[/\s.\-]([A-Za-z]{3,}|\d{1,2})[/\s.\-](\d{4})$/);
  if (m) {
    let mo = /^\d+$/.test(m[2]) ? +m[2] : MONTHS.findIndex((x) => m[2].toLowerCase().startsWith(x.toLowerCase())) + 1;
    const d = +m[1], y = +m[3];
    if (mo >= 1 && mo <= 12 && d >= 1 && d <= 31) return `${y}-${String(mo).padStart(2, "0")}-${String(d).padStart(2, "0")}`;
  }
  const t = Date.parse(v);
  if (!Number.isNaN(t)) {
    const dt = new Date(t);
    return `${dt.getFullYear()}-${String(dt.getMonth() + 1).padStart(2, "0")}-${String(dt.getDate()).padStart(2, "0")}`;
  }
  return null;
}

// yyyy-MM-dd → "14 Mar 1998" for display; passthrough if not ISO.
function formatDateHuman(iso) {
  const m = String(iso || "").match(/^(\d{4})-(\d{2})-(\d{2})$/);
  if (!m) return iso || "";
  return `${+m[3]} ${MONTHS[+m[2] - 1]} ${m[1]}`;
}

async function loadProfile() {
  const { profile = {} } = await chrome.storage.local.get("profile");
  const box = $("#profile-fields");
  if (!box) return;
  box.replaceChildren();
  for (const [key, ph] of PROFILE_FIELDS) {
    const wrap = document.createElement("label");
    wrap.className = "field";
    wrap.innerHTML = `<span>${key}</span><input data-key="${key}" type="text" placeholder="${ph}" />`;
    const stored = profile[key] || "";
    wrap.querySelector("input").value = DATE_KEYS.has(key) ? formatDateHuman(stored) : stored;
    box.appendChild(wrap);
  }
}

const saveBtn = $("#save-profile");
if (saveBtn) {
  saveBtn.addEventListener("click", async () => {
    const profile = {};
    let badDate = null;
    document.querySelectorAll("#profile-fields input").forEach((i) => {
      const raw = i.value.trim();
      if (!raw) return;
      const key = i.dataset.key;
      if (DATE_KEYS.has(key)) {
        const iso = toISODate(raw);
        if (iso === null) { badDate = key; return; }
        if (iso) {
          profile[key] = iso;
          i.value = formatDateHuman(iso); // reflect the canonical value back
        }
      } else {
        const val = ["PAN", "Passport number", "Voter ID"].includes(key) ? raw.toUpperCase() : raw;
        profile[key] = val;
        i.value = val;
      }
    });
    if (badDate) {
      $("#saved-note").textContent = `Couldn't read "${badDate}" — try a format like 14 Mar 1998.`;
      return;
    }
    await chrome.storage.local.set({ profile });
    $("#saved-note").textContent = `Saved ${Object.keys(profile).length} values locally.`;
    setTimeout(() => ($("#saved-note").textContent = ""), 2500);
  });
}

// ---- guided goal builder --------------------------------------
// Composes an intent-only task string. Field *names* only — never any value —
// so nothing sensitive can reach the agent through the goal. (The composed
// string is still DLP-scrubbed in the background as defense in depth.)
const guidedWrap = $("#goal-guided");
const customWrap = $("#goal-custom");
const modeGuidedBtn = $("#mode-guided");
const modeCustomBtn = $("#mode-custom");
let goalMode = "guided";

function setGoalMode(mode) {
  goalMode = mode;
  modeGuidedBtn.classList.toggle("is-active", mode === "guided");
  modeCustomBtn.classList.toggle("is-active", mode === "custom");
  guidedWrap.hidden = mode !== "guided";
  customWrap.hidden = mode !== "custom";
}
modeGuidedBtn.addEventListener("click", () => { setGoalMode("guided"); saveSettings(); });
modeCustomBtn.addEventListener("click", () => { setGoalMode("custom"); saveSettings(); });

// field chips come from the same non-sensitive profile keys
const gbFieldList = $("#gb-field-list");
PROFILE_FIELDS.forEach(([key]) => {
  const l = document.createElement("label");
  l.className = "check";
  l.innerHTML = `<input type="checkbox" data-field="${key}" /> ${key}`;
  gbFieldList.appendChild(l);
});

function listPhrase(items) {
  if (items.length === 1) return `${items[0]} field`;
  return `${items.slice(0, -1).join(", ")} and ${items[items.length - 1]} fields`;
}

function composeGuidedGoal() {
  const scope = document.querySelector('input[name="gb-scope"]:checked')?.value || "all";
  const submit = document.querySelector('input[name="gb-submit"]:checked')?.value || "stop";
  let s = "Fill this form using my saved local profile.";
  if (scope === "pick") {
    const picked = [...gbFieldList.querySelectorAll("input:checked")].map((i) => i.dataset.field);
    if (picked.length) s = `Fill this form using my saved local profile, but only the ${listPhrase(picked)}.`;
  }
  s += submit === "submit"
    ? " Submit the form after every field has been filled."
    : " Stop before submitting so I can review.";
  return s;
}

function refreshGuided() {
  const pickMode = document.querySelector('input[name="gb-scope"]:checked')?.value === "pick";
  $("#gb-fields").hidden = !pickMode;
  $("#gb-preview").textContent = composeGuidedGoal();
}
guidedWrap.addEventListener("change", refreshGuided);
refreshGuided();

// ---- presets ----------------------------------------------------
const PRESETS = [
  "Fill this job application with my basic contact info. Stop before submitting.",
  "Fill the shipping address form with my profile details.",
  "Fill name and email in this contact form.",
];
const presetRow = $("#presets");
PRESETS.forEach((p) => {
  const b = document.createElement("button");
  b.className = "preset";
  b.textContent = p.slice(0, 34) + "…";
  b.title = p;
  b.addEventListener("click", () => { setGoalMode("custom"); $("#goal").value = p; });
  presetRow.appendChild(b);
});

// ---- activity log ---------------------------------------------
const logEl = $("#log");
function log(text, cls = "") {
  if (logEl.querySelector(".empty")) logEl.replaceChildren();
  const li = document.createElement("li");
  if (cls) li.className = cls;
  li.textContent = text;
  logEl.prepend(li);
}

const egress = $("#egress");
const securityHud = $("#security-hud");
const threatsList = $("#security-threats");
const viewSingleBtn = $("#view-single");
const viewDiffBtn = $("#view-diff");
const singleView = $("#egress-single-view");
const diffView = $("#egress-diff-view");

viewSingleBtn.addEventListener("click", () => {
  viewSingleBtn.classList.add("is-active");
  viewDiffBtn.classList.remove("is-active");
  singleView.hidden = false;
  diffView.hidden = true;
});

viewDiffBtn.addEventListener("click", () => {
  viewDiffBtn.classList.add("is-active");
  viewSingleBtn.classList.remove("is-active");
  singleView.hidden = true;
  diffView.hidden = false;
});

const hybridHud = $("#hybrid-hud");
const hybridBadge = $("#hybrid-badge");
const hybridDesc = $("#hybrid-desc");
const exportDpdpBtn = $("#export-dpdp-btn");
let lastDpdpReport = null;

exportDpdpBtn.addEventListener("click", () => {
  if (!lastDpdpReport) return;
  const jsonStr = JSON.stringify(lastDpdpReport, null, 2);
  const blob = new Blob([jsonStr], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `dpdp-audit-log-step${lastDpdpReport.step || 1}.json`;
  a.click();
  URL.revokeObjectURL(url);
});

function showEgress(evt) {
  egress.hidden = false;
  $("#egress-img").src = evt.redactedImage;
  $("#diff-redacted-img").src = evt.redactedImage;
  if (evt.rawImage) {
    $("#diff-raw-img").src = evt.rawImage;
  }

  // Render Security Alert HUD if any adversarial injections were detected and blocked
  const alerts = evt.securityAlerts || [];
  if (alerts.length > 0) {
    securityHud.hidden = false;
    $("#security-title").textContent = `🛡️ ${alerts.length} ADVERSARIAL INJECTION${alerts.length > 1 ? "S" : ""} BLOCKED`;
    threatsList.replaceChildren();
    alerts.forEach((a) => {
      const li = document.createElement("li");
      li.textContent = `[${a.type}] ${a.reason || a.text || "Malicious instruction quarantined"}`;
      threatsList.appendChild(li);
    });
    log(`🛡️ Blocked ${alerts.length} adversarial injection vector(s)`, "err");
  } else {
    securityHud.hidden = true;
  }

  // Render Hybrid Engine HUD
  const t = evt.timings || {};
  const a11y = evt.a11yStats || {};
  if (t.a11yBypassed) {
    hybridHud.hidden = false;
    hybridBadge.textContent = "⚡ HYBRID A11Y FAST-PATH";
    const baseline = typeof t.visionStageBaselineMs === "number"
      ? ` — vision stage (~${t.visionStageBaselineMs}ms measured) skipped`
      : ` — this step ${t.totalMs ?? "?"}ms vs a vision-fallback step`;
    hybridDesc.textContent = `ViT/OCR bypassed (${Math.round((a11y.confidence || 1) * 100)}% structured A11y tree confidence)${baseline}`;
  } else if (a11y.totalNodes > 0) {
    hybridHud.hidden = false;
    hybridBadge.textContent = "👁️ VISION FALLBACK ACTIVE";
    hybridDesc.textContent = `Multimodal ViT + OCR triggered (Visual controls/canvas detected)`;
  } else {
    hybridHud.hidden = true;
  }

  // Configure DPDP Compliance Audit Log
  if (evt.dpdpReport) {
    lastDpdpReport = evt.dpdpReport;
    exportDpdpBtn.hidden = false;
  }

  const s = evt.visionStats || {};
  const v = s.vit || {};
  const engine = v.engine || (v.backend === "wasm" ? "WASM · CPU" : v.backend === "webgpu" ? "WebGPU · GPU" : v.backend || "?");
  const vitLine = v.available
    ? `Vision engine: ${engine}` +
      `${v.gpu?.available && v.gpu.vendor ? ` (${v.gpu.vendor}${v.gpu.architecture ? " " + v.gpu.architecture : ""})` : ""}` +
      ` · ViT ${v.modelId || "yolos-tiny"} · ${t.vitMs ?? "?"}ms${v.loadMs != null ? ` (load ${v.loadMs}ms)` : ""}` +
      ` · saw ${v.objects ?? 0} object(s)${v.labels?.length ? ": " + v.labels.slice(0, 6).join(", ") : ""}`
    : `Vision engine: unavailable${v.error ? ` — ${v.error}` : ""}`;
  $("#egress-stats").textContent =
    `step ${evt.step} · OCR ${t.ocrMs ?? "?"}ms · faces ${t.faceMs ?? "?"}ms · ViT ${t.vitMs ?? "?"}ms · blackout ${t.redactMs ?? "?"}ms · total ${t.totalMs ?? "?"}ms\n` +
    `hybrid mode: ${t.a11yBypassed ? "A11y Fast-Path" : "Vision Fallback"} · regions blacked out: ${s.total ?? 0} · ocr lines: ${s.ocrLines ?? 0}\n` +
    `redaction: ${s.redaction ? (s.redaction.verified ? `verified${s.redaction.repasses ? ` (+${s.redaction.addedRegions} residual box${s.redaction.addedRegions === 1 ? "" : "es"})` : ""}` : `FAILED — ${(s.redaction.residualCategories || []).join(", ")}`) : "not verified"} · verify ${t.verifyMs ?? "?"}ms\n` +
    `fields named by vision: ${s.visionLabelledFields ?? 0} · face model: ${s.faceDetectorAvailable ? "on" : "off"}${alerts.length ? ` · 🛡️ threats quarantined: ${alerts.length}` : ""}\n` +
    vitLine;
  $("#egress-json").textContent = JSON.stringify(evt.payloadPreview, null, 1);
}

// ---- gates ---------------------------------------------------
const gate = $("#gate");
let pendingGateId = null;
function showGate(id, kind, meta) {
  pendingGateId = id;
  gate.hidden = false;
  if (kind === "approval" && meta) {
    // structured security-approval explanation — categories only, never values
    const cats = Object.keys(meta.counts || {}).map((k) => k.replace(/^(pii|secret):/, "")).filter(Boolean);
    $("#gate-text").innerHTML =
      `<strong>⚠️ SECURITY APPROVAL REQUIRED</strong><br>` +
      `${meta.title || "Send this context to the AI?"}<br><br>` +
      `<b>Risk:</b> ${meta.risk || "?"}<br>` +
      (meta.destination ? `<b>Destination:</b> ${escapeHtml(meta.destination)}<br>` : "") +
      (cats.length ? `<b>Detected:</b> ${cats.map(escapeHtml).join(", ")}<br>` : "") +
      (meta.reasons?.length ? `<br>${meta.reasons.map(escapeHtml).join("<br>")}` : "");
  } else {
    $("#gate-text").textContent = kind === "submit"
      ? "The agent wants to SUBMIT the form. Allow?"
      : "Send this blacked-out context to the server?";
  }
}
function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}
function resolveGate(approved) {
  if (!pendingGateId) return;
  chrome.runtime.sendMessage({ action: "PL_GATE_RESOLVE", id: pendingGateId, approved });
  pendingGateId = null;
  gate.hidden = true;
}
$("#gate-approve").addEventListener("click", () => resolveGate(true));
$("#gate-deny").addEventListener("click", () => resolveGate(false));

// ---- progress stream ---------------------------------------
chrome.runtime.onMessage.addListener((m) => {
  if (m.action !== "PL_PROGRESS") return;
  const e = m.evt;
  switch (e.type) {
    case "step-start": log(`— step ${e.step} —`); break;
    case "goal-redacted":
      log(`goal scrubbed before egress (${e.hits.join(", ")}); sent: "${e.sanitized}"`, "err");
      break;
    case "egress": showEgress(e); log(`censored with black boxes (step ${e.step})`); break;
    case "redaction-verified":
      if (e.verified) {
        log(`✓ redaction verified${e.repasses ? ` (re-masked ${e.repasses}× to clear residual ${e.residualCategories.join(", ")})` : ""}`, "ok");
      } else {
        log(`🚨 redaction FAILED — screenshot still shows ${e.residualCategories.join(", ") || "PII"} after re-masking · image NOT sent`, "err");
      }
      break;
    case "egress-redacted":
      log(`🛡️ egress gate redacted ${e.total} PII item(s) before sending: ${Object.entries(e.byCategory).map(([k, v]) => `${k}×${v}`).join(", ")}`, "err");
      break;
    case "gate": showGate(e.id, e.kind, e.meta); break;
    case "security-classification":
      log(`security: ${e.decision} · ${e.classification}${Object.keys(e.counts || {}).length ? " · " + Object.entries(e.counts).map(([k, v]) => `${k}×${v}`).join(", ") : ""}`, e.decision === "ALLOW" ? "ok" : "err");
      break;
    case "plan":
      log(`server: ${e.rationale || "(plan)"} · ${e.actions.length} action(s) · ${e.roundTripMs}ms`);
      break;
    case "action": {
      const r = e.result || {};
      log(`${e.action.action} ${e.action.targetId || ""} → ${r.note || "?"}${r.verified === false ? " (unverified)" : ""}`, r.ok ? "ok" : "err");
      break;
    }
    case "action-risk": {
      const cls = e.risk === "CRITICAL" || e.risk === "HIGH" ? "err" : e.risk === "MEDIUM" ? "" : "ok";
      log(`action firewall: ${e.action.action} ${e.action.targetId || ""} → ${e.risk} (${e.decision})${e.exfil ? ` · ⚠ exfil via ${e.exfil.channel}: ${e.exfil.categories.join(",")}` : ""}${e.reasons?.length ? " · " + e.reasons[0] : ""}`, cls);
      break;
    }
    case "error":
      log(`error [${e.where || ""}]: ${e.message}`, "err");
      if (e.retryable) {
        pendingRetry = true;
        showAiBanner(e.aiUnavailable
          ? `${e.where || "AI unavailable"} — the agent stopped. It will not guess with an offline fallback. Retry when the model is back.`
          : `${e.where || "Error"} — ${e.message}`);
      }
      break;
    case "submit-skipped": log("submit skipped by user"); break;
    case "done": log(`✔ task complete (step ${e.step})${e.reason ? ` — ${e.reason}` : ""}`, "ok"); break;
    case "cancelled": log("cancelled", "err"); break;
    case "finished":
      setBusy(false);
      log("agent stopped");
      if (pendingRetry && lastRunOpts) $("#retry-button").hidden = false;
      break;
  }
});

// ---- run / cancel / retry ---------------------------------
let lastRunOpts = null;
let pendingRetry = false;

function setBusy(b) {
  statusDot.classList.toggle("busy", b);
  $("#run-button").hidden = b;
  $("#cancel-button").hidden = !b;
  if (b) $("#retry-button").hidden = true;
}

function showAiBanner(text) {
  $("#ai-banner-text").textContent = text;
  $("#ai-banner").hidden = false;
}
function hideAiBanner() { $("#ai-banner").hidden = true; }

function startTask(opts) {
  lastRunOpts = opts;
  pendingRetry = false;
  hideAiBanner();
  logEl.replaceChildren();
  egress.hidden = true;
  setBusy(true);
  document.querySelector('.tab[data-tab="activity"]').click();
  chrome.runtime.sendMessage({ action: "PL_RUN_TASK", opts }, (res) => {
    if (chrome.runtime.lastError || !res?.ok) {
      log(`could not start: ${res?.error || chrome.runtime.lastError?.message}`, "err");
      setBusy(false);
    }
  });
}

// ---- settings persistence --------------------------------
function updateCustomEndpointVisibility() {
  const isCustom = $("#aiProvider")?.value === "custom";
  const customField = $("#aiCustomEndpointField");
  if (customField) customField.hidden = !isCustom;
}

const toggleApiKeyBtn = $("#toggleApiKey");
const apiKeyInput = $("#aiApiKey");
if (toggleApiKeyBtn && apiKeyInput) {
  toggleApiKeyBtn.addEventListener("click", () => {
    const isPassword = apiKeyInput.type === "password";
    apiKeyInput.type = isPassword ? "text" : "password";
    toggleApiKeyBtn.textContent = isPassword ? "Hide" : "Show";
  });
}

const testApiKeyBtn = $("#testApiKey");
const testApiKeyResult = $("#testApiKeyResult");
if (testApiKeyBtn && testApiKeyResult) {
  testApiKeyBtn.addEventListener("click", async () => {
    testApiKeyBtn.disabled = true;
    testApiKeyBtn.textContent = "Testing…";
    testApiKeyResult.textContent = "";
    testApiKeyResult.classList.remove("is-ok", "is-err");

    try {
      const { testConnection } = await import("./lib/cloud-agent-client.mjs");
      const currentSettings = {
        aiProvider: $("#aiProvider")?.value || "gemini",
        aiModel: $("#aiModel")?.value.trim() || "",
        aiApiKey: $("#aiApiKey")?.value.trim() || "",
        aiCustomEndpoint: $("#aiCustomEndpoint")?.value.trim() || "",
      };
      const res = await testConnection(currentSettings);
      testApiKeyResult.textContent = res.message;
      testApiKeyResult.classList.add(res.ok ? "is-ok" : "is-err");
    } catch (err) {
      testApiKeyResult.textContent = err.message || "Test failed";
      testApiKeyResult.classList.add("is-err");
    } finally {
      testApiKeyBtn.disabled = false;
      testApiKeyBtn.textContent = "Test";
    }
  });
}

$("#aiProvider")?.addEventListener("change", updateCustomEndpointVisibility);

async function loadSettings() {
  const { settings = {} } = await chrome.storage.local.get("settings");
  if (settings.serverUrl !== undefined && $("#serverUrl")) $("#serverUrl").value = settings.serverUrl;
  if ($("#aiProvider")) $("#aiProvider").value = settings.aiProvider || "gemini";
  if (settings.aiModel !== undefined && $("#aiModel")) $("#aiModel").value = settings.aiModel;
  if (settings.aiApiKey !== undefined && $("#aiApiKey")) $("#aiApiKey").value = settings.aiApiKey;
  if (settings.aiCustomEndpoint !== undefined && $("#aiCustomEndpoint")) $("#aiCustomEndpoint").value = settings.aiCustomEndpoint;
  updateCustomEndpointVisibility();

  if (settings.redactionMode !== undefined && $("#redactionMode")) $("#redactionMode").value = settings.redactionMode;
  if (settings.autoApprove !== undefined && $("#autoApprove")) $("#autoApprove").checked = Boolean(settings.autoApprove);
  if (settings.confirmEachSend !== undefined && $("#confirmEachSend")) $("#confirmEachSend").checked = Boolean(settings.confirmEachSend);
  if (settings.confirmBeforeSubmit !== undefined && $("#confirmBeforeSubmit")) $("#confirmBeforeSubmit").checked = Boolean(settings.confirmBeforeSubmit);
  if (settings.goalMode && (settings.goalMode === "guided" || settings.goalMode === "custom")) {
    setGoalMode(settings.goalMode);
  }
  if (settings.goal !== undefined && $("#goal")) $("#goal").value = settings.goal;
  refreshAiStatus();
}

async function saveSettings() {
  const settings = {
    serverUrl: $("#serverUrl")?.value.trim() || "http://localhost:8000",
    aiProvider: $("#aiProvider")?.value || "gemini",
    aiModel: $("#aiModel")?.value.trim() || "",
    aiApiKey: $("#aiApiKey")?.value || "",
    aiCustomEndpoint: $("#aiCustomEndpoint")?.value.trim() || "",
    redactionMode: $("#redactionMode")?.value || "blackout",
    autoApprove: Boolean($("#autoApprove")?.checked),
    confirmEachSend: Boolean($("#confirmEachSend")?.checked),
    confirmBeforeSubmit: Boolean($("#confirmBeforeSubmit")?.checked),
    goalMode: goalMode,
    goal: $("#goal")?.value || "",
  };
  await chrome.storage.local.set({ settings });
}

["#serverUrl", "#aiProvider", "#aiCustomEndpoint", "#aiModel", "#aiApiKey", "#redactionMode", "#autoApprove", "#confirmEachSend", "#confirmBeforeSubmit", "#goal"].forEach((sel) => {
  const el = $(sel);
  if (el) {
    el.addEventListener("change", saveSettings);
    if ((el.tagName === "INPUT" && el.type !== "checkbox" && el.type !== "radio") || el.tagName === "TEXTAREA") {
      el.addEventListener("input", saveSettings);
    }
  }
});

$("#run-button").addEventListener("click", () => {
  const goal = goalMode === "guided" ? composeGuidedGoal() : $("#goal").value.trim();
  if (!goal) { $("#goal").focus(); return; }
  saveSettings();
  startTask({
    goal,
    serverUrl: $("#serverUrl").value.trim() || "http://localhost:8000",
    redactionMode: $("#redactionMode")?.value || "blackout",
    autoApprove: $("#autoApprove")?.checked ?? false,
    confirmEachSend: $("#confirmEachSend").checked,
    confirmBeforeSubmit: $("#confirmBeforeSubmit").checked,
  });
});

$("#retry-button").addEventListener("click", () => {
  if (lastRunOpts) startTask(lastRunOpts);
});

$("#cancel-button").addEventListener("click", () => {
  chrome.runtime.sendMessage({ action: "PL_CANCEL_TASK" });
  setBusy(false);
});

// ---- model status ----------------------------------------
async function refreshAiStatus() {
  const el = $("#ai-status");
  if (!el) return;

  const cloudKey = ($("#aiApiKey")?.value || "").trim();
  if (cloudKey) {
    const provider = $("#aiProvider")?.value || "gemini";
    const defaultModel = provider === "gemini" ? "gemini-2.0-flash" : provider === "openai" ? "gpt-4o-mini" : "default";
    const model = ($("#aiModel")?.value || "").trim() || defaultModel;
    el.textContent = `cloud: ${provider}/${model}`;
    el.title = `Direct Cloud Mode (${provider}) · Model: ${model} · API key configured`;
    el.classList.remove("is-offline");
    return;
  }

  const url = ($("#serverUrl")?.value.trim() || "http://localhost:8000").replace(/\/$/, "");
  try {
    const r = await fetch(`${url}/health`, { signal: AbortSignal.timeout(3000) });
    if (!r.ok) throw new Error(`HTTP ${r.status}`);
    const h = await r.json();
    const model = h.model && h.model !== "unset" ? h.model : h.vlm_mode;
    el.textContent = `AI: ${model}`;
    el.title = `VLM mode: ${h.vlm_mode} · model: ${h.model} · mock fallback: ${h.mock_fallback ? "on" : "off"}`;
    el.classList.toggle("is-offline", h.vlm_mode === "mock");
  } catch (e) {
    el.textContent = "AI: offline";
    el.title = `Server not reachable at ${url} (${e.message})`;
    el.classList.add("is-offline");
  }
}
refreshAiStatus();
$("#serverUrl")?.addEventListener("change", refreshAiStatus);
$("#aiApiKey")?.addEventListener("input", refreshAiStatus);
$("#aiApiKey")?.addEventListener("change", refreshAiStatus);
$("#aiProvider")?.addEventListener("change", refreshAiStatus);
$("#aiModel")?.addEventListener("input", refreshAiStatus);
$("#aiModel")?.addEventListener("change", refreshAiStatus);

// ---- legacy quick scan ------------------------------------
$("#scan-button").addEventListener("click", () => {
  const list = $("#box-list");
  list.replaceChildren(Object.assign(document.createElement("li"), { textContent: "scanning…", className: "empty" }));
  chrome.runtime.sendMessage({ action: "SCAN_ACTIVE_TAB" }, (res) => {
    if (chrome.runtime.lastError || !res?.ok) {
      list.replaceChildren(Object.assign(document.createElement("li"), { textContent: res?.error || "cannot inspect this page", className: "empty" }));
      return;
    }
    const boxes = res.boxes || [];
    list.replaceChildren();
    if (!boxes.length) { list.innerHTML = '<li class="empty">Nothing sensitive detected.</li>'; return; }
    boxes.forEach((b) => {
      const li = document.createElement("li");
      li.textContent = `${b.category} (${Math.round((b.confidence || 1) * 100)}%) · ${b.w}×${b.h} @ ${b.x},${b.y}`;
      list.appendChild(li);
    });
  });
});

loadProfile();
loadSettings();
