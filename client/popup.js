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

// ---- profile (ONLY non-sensitive fields; all censored fields stripped) ----
const PROFILE_FIELDS = [
  ["full name", "Aditi Sharma"],
  ["first name", "Aditi"],
  ["last name", "Sharma"],
  ["email", "aditi.sharma@example.com"],
  ["phone number", "9876543210"],
  ["date of birth", "14/03/1998"],
  ["address", "42 Nehru Road, Bengaluru"],
  ["postal/ZIP code", "560001"],
];

async function loadProfile() {
  const { profile = {} } = await chrome.storage.local.get("profile");
  const box = $("#profile-fields");
  if (!box) return;
  box.replaceChildren();
  for (const [key, ph] of PROFILE_FIELDS) {
    const wrap = document.createElement("label");
    wrap.className = "field";
    wrap.innerHTML = `<span>${key}</span><input data-key="${key}" type="text" placeholder="${ph}" />`;
    wrap.querySelector("input").value = profile[key] || "";
    box.appendChild(wrap);
  }
}

const saveBtn = $("#save-profile");
if (saveBtn) {
  saveBtn.addEventListener("click", async () => {
    const profile = {};
    document.querySelectorAll("#profile-fields input").forEach((i) => {
      if (i.value.trim()) profile[i.dataset.key] = i.value.trim();
    });
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
modeGuidedBtn.addEventListener("click", () => setGoalMode("guided"));
modeCustomBtn.addEventListener("click", () => setGoalMode("custom"));

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
    hybridDesc.textContent = `ViT/OCR bypassed (${Math.round((a11y.confidence || 1) * 100)}% structured A11y tree confidence — saved ~${t.latencySavingsMs || 280}ms)`;
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
  const vitLine = v.available
    ? `ViT ${v.modelId || "yolos-tiny"} on ${String(v.backend || "?").toUpperCase()}` +
      `${v.gpu?.available && v.gpu.vendor ? ` (${v.gpu.vendor}${v.gpu.architecture ? " " + v.gpu.architecture : ""})` : ""}` +
      ` · ${t.vitMs ?? "?"}ms${v.loadMs != null ? ` (load ${v.loadMs}ms)` : ""}` +
      ` · saw ${v.objects ?? 0} object(s)${v.labels?.length ? ": " + v.labels.slice(0, 6).join(", ") : ""}`
    : `ViT unavailable${v.error ? ` — ${v.error}` : ""}`;
  $("#egress-stats").textContent =
    `step ${evt.step} · OCR ${t.ocrMs ?? "?"}ms · faces ${t.faceMs ?? "?"}ms · ViT ${t.vitMs ?? "?"}ms · blackout ${t.redactMs ?? "?"}ms · total ${t.totalMs ?? "?"}ms\n` +
    `hybrid mode: ${t.a11yBypassed ? "A11y Fast-Path" : "Vision Fallback"} · regions blacked out: ${s.total ?? 0} · ocr lines: ${s.ocrLines ?? 0}\n` +
    `fields named by vision: ${s.visionLabelledFields ?? 0} · face model: ${s.faceDetectorAvailable ? "on" : "off"}${alerts.length ? ` · 🛡️ threats quarantined: ${alerts.length}` : ""}\n` +
    vitLine;
  $("#egress-json").textContent = JSON.stringify(evt.payloadPreview, null, 1);
}

// ---- gates ---------------------------------------------------
const gate = $("#gate");
let pendingGateId = null;
function showGate(id, kind) {
  pendingGateId = id;
  gate.hidden = false;
  $("#gate-text").textContent = kind === "submit"
    ? "The agent wants to SUBMIT the form. Allow?"
    : "Send this blacked-out context to the server?";
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
    case "gate": showGate(e.id, e.kind); break;
    case "plan":
      log(`server: ${e.rationale || "(plan)"} · ${e.actions.length} action(s) · ${e.roundTripMs}ms`);
      break;
    case "action": {
      const r = e.result || {};
      log(`${e.action.action} ${e.action.targetId || ""} → ${r.note || "?"}${r.verified === false ? " (unverified)" : ""}`, r.ok ? "ok" : "err");
      break;
    }
    case "error": log(`error [${e.where || ""}]: ${e.message}`, "err"); break;
    case "submit-skipped": log("submit skipped by user"); break;
    case "done": log(`✔ task complete (step ${e.step})${e.reason ? ` — ${e.reason}` : ""}`, "ok"); break;
    case "cancelled": log("cancelled", "err"); break;
    case "finished":
      setBusy(false);
      log("agent stopped");
      break;
  }
});

// ---- run / cancel ------------------------------------------
function setBusy(b) {
  statusDot.classList.toggle("busy", b);
  $("#run-button").hidden = b;
  $("#cancel-button").hidden = !b;
}

$("#run-button").addEventListener("click", () => {
  const goal = goalMode === "guided" ? composeGuidedGoal() : $("#goal").value.trim();
  if (!goal) { $("#goal").focus(); return; }
  logEl.replaceChildren();
  egress.hidden = true;
  setBusy(true);
  document.querySelector('.tab[data-tab="activity"]').click();
  chrome.runtime.sendMessage({
    action: "PL_RUN_TASK",
    opts: {
      goal,
      serverUrl: $("#serverUrl").value.trim() || "http://localhost:8000",
      redactionMode: "blackout",
      confirmEachSend: $("#confirmEachSend").checked,
      confirmBeforeSubmit: $("#confirmBeforeSubmit").checked,
    },
  }, (res) => {
    if (chrome.runtime.lastError || !res?.ok) {
      log(`could not start: ${res?.error || chrome.runtime.lastError?.message}`, "err");
      setBusy(false);
    }
  });
});

$("#cancel-button").addEventListener("click", () => {
  chrome.runtime.sendMessage({ action: "PL_CANCEL_TASK" });
  setBusy(false);
});

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
