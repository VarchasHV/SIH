// Popup: profile/vault editor + agent control + activity/egress view.

const $ = (s) => document.querySelector(s);
const statusDot = $("#status-dot");

// ---- tabs -----------------------------------------------------------
document.querySelectorAll(".tab").forEach((t) => {
  t.addEventListener("click", () => {
    document.querySelectorAll(".tab").forEach((x) => x.classList.toggle("is-active", x === t));
    document.querySelectorAll(".panel").forEach((p) => p.classList.toggle("is-active", p.id === `tab-${t.dataset.tab}`));
  });
});

// ---- profile ------------------------------------------------------
const PROFILE_FIELDS = [
  ["full name", "Aditi Sharma"],
  ["first name", "Aditi"],
  ["last name", "Sharma"],
  ["email", "aditi.sharma@example.com"],
  ["phone number", "9876543210"],
  ["date of birth", "14/03/1998"],
  ["address", "42 Nehru Road, Bengaluru"],
  ["postal/ZIP code", "560001"],
  ["Aadhaar", "2234 5678 9012"],
  ["PAN", "ABCPS1234K"],
  ["passport number", "P1234567"],
  ["credit/debit card number", "4111 1111 1111 1111"],
  ["CVV/security code", "123"],
  ["card expiry", "08/29"],
  ["bank account information", "50100123456789"],
];

async function loadProfile() {
  const { profile = {} } = await chrome.storage.local.get("profile");
  const box = $("#profile-fields");
  box.replaceChildren();
  for (const [key, ph] of PROFILE_FIELDS) {
    const wrap = document.createElement("label");
    wrap.className = "field";
    wrap.innerHTML = `<span>${key}</span><input data-key="${key}" type="text" placeholder="${ph}" />`;
    wrap.querySelector("input").value = profile[key] || "";
    box.appendChild(wrap);
  }
}

$("#save-profile").addEventListener("click", async () => {
  const profile = {};
  document.querySelectorAll("#profile-fields input").forEach((i) => {
    if (i.value.trim()) profile[i.dataset.key] = i.value.trim();
  });
  await chrome.storage.local.set({ profile });
  $("#saved-note").textContent = `Saved ${Object.keys(profile).length} values locally.`;
  setTimeout(() => ($("#saved-note").textContent = ""), 2500);
});

// ---- presets ----------------------------------------------------
const PRESETS = [
  "Fill this job application from my profile. Stop before submitting.",
  "Complete the checkout shipping + payment form with my details.",
  "Fill the KYC form (Aadhaar, PAN, address). Do not submit.",
];
const presetRow = $("#presets");
PRESETS.forEach((p) => {
  const b = document.createElement("button");
  b.className = "preset";
  b.textContent = p.slice(0, 34) + "…";
  b.title = p;
  b.addEventListener("click", () => ($("#goal").value = p));
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
function showEgress(evt) {
  egress.hidden = false;
  $("#egress-img").src = evt.redactedImage;
  const s = evt.visionStats || {};
  const t = evt.timings || {};
  $("#egress-stats").textContent =
    `step ${evt.step} · OCR ${t.ocrMs ?? "?"}ms · faces ${t.faceMs ?? "?"}ms · redact ${t.redactMs ?? "?"}ms · total ${t.totalMs ?? "?"}ms\n` +
    `regions redacted: ${s.total ?? 0} (dom+vision: ${s.both ?? 0}, vision-only: ${s.visionOnly ?? 0}) · ocr lines: ${s.ocrLines ?? 0}\n` +
    `fields named by vision: ${s.visionLabelledFields ?? 0} · face model: ${s.faceDetectorAvailable ? "on" : "off"}`;
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
    : "Send this redacted context to the server?";
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
    case "egress": showEgress(e); log(`redacted & packaged (step ${e.step})`); break;
    case "gate": showGate(e.id, e.kind); break;
    case "plan":
      log(`server: ${e.rationale || "(plan)"} · ${e.actions.length} action(s) · ${e.roundTripMs}ms`);
      break;
    case "action": {
      const r = e.result || {};
      log(`${e.action.action} ${e.action.targetId || ""} ${e.action.valueToken || ""} → ${r.note || "?"}${r.verified === false ? " (unverified)" : ""}`, r.ok ? "ok" : "err");
      break;
    }
    case "error": log(`error [${e.where || ""}]: ${e.message}`, "err"); break;
    case "submit-skipped": log("submit skipped by user"); break;
    case "done": log(`✔ task complete (step ${e.step})`, "ok"); break;
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
  const goal = $("#goal").value.trim();
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
      redactionMode: $("#redactionMode").value,
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
