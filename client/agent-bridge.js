// Content-script side of the agent loop. No tokenization — profile values are
// passed directly to the executor. All censored/sensitive fields are strictly
// blocked from being filled.

(function () {
  if (window.__plAgentBridgeLoaded) return; // guard against double injection
  window.__plAgentBridgeLoaded = true;

  const CENSORED_CATEGORIES = new Set([
    "aadhaar", "Aadhaar",
    "pan", "PAN",
    "ssn", "SSN",
    "credit-card", "credit/debit card number", "credit_card",
    "cvv", "CVV/security code",
    "card expiry",
    "bank account information",
    "passport number",
    "government ID",
    "password",
    "ifsc",
    "upi-vpa",
  ]);

  async function prepare() {
    const { profile = {} } = await chrome.storage.local.get("profile");
    // Strip any sensitive/censored fields that might have been saved in legacy storage
    for (const key of Object.keys(profile)) {
      if (CENSORED_CATEGORIES.has(key)) {
        delete profile[key];
      }
    }

    const skeleton = window.__PL.buildSkeleton();
    const domPiiBoxes = window.__PL.domPiiBoxes();

    // Annotate nodes: only non-censored fields with profile data can be filled
    for (const node of skeleton.nodes) {
      if (node.piiCategory && CENSORED_CATEGORIES.has(node.piiCategory)) {
        node.isCensored = true;
        node.hasFill = false; // strictly prohibited from filling
      } else if (node.piiCategory && profile[node.piiCategory]) {
        node.isCensored = false;
        node.hasFill = true;
      }
    }
    return { skeleton, domPiiBoxes, profileValues: profile, profileKeys: Object.keys(profile) };
  }

  async function execute(action) {
    const { profile = {} } = await chrome.storage.local.get("profile");

    // Guard: strictly block filling any censored/sensitive category
    if (action.piiCategory && CENSORED_CATEGORIES.has(action.piiCategory)) {
      return { ok: false, note: `Blocked: censored category '${action.piiCategory}' cannot be filled` };
    }

    // Resolve non-sensitive profile value
    let value = null;
    if (action.piiCategory && profile[action.piiCategory]) {
      value = profile[action.piiCategory];
    } else if (action.literalValue != null) {
      value = action.literalValue;
    }

    const result = await window.__PL.executeAction(action, value);
    // local read-back check (never leaves the page)
    if (result.ok && action.action === "type" && value != null) {
      result.verified = window.__PL.verifyField(action.targetId, value);
    }
    return result;
  }

  // simple on-page overlay so the demo shows what was redacted / targeted
  function highlight(regions, kind = "redact") {
    let layer = document.getElementById("__pl_overlay");
    if (!layer) {
      layer = document.createElement("div");
      layer.id = "__pl_overlay";
      layer.style.cssText = "position:fixed;inset:0;pointer-events:none;z-index:2147483647";
      document.documentElement.appendChild(layer);
    }
    layer.replaceChildren();
    const dpr = window.devicePixelRatio || 1;
    for (const r of regions || []) {
      const d = document.createElement("div");
      const x = (r.x ?? r.bbox?.x ?? 0) / (r.deviceCoords ? dpr : 1);
      const y = (r.y ?? r.bbox?.y ?? 0) / (r.deviceCoords ? dpr : 1);
      const w = (r.w ?? r.bbox?.w ?? 0) / (r.deviceCoords ? dpr : 1);
      const h = (r.h ?? r.bbox?.h ?? 0) / (r.deviceCoords ? dpr : 1);
      d.style.cssText = `position:absolute;left:${x}px;top:${y}px;width:${w}px;height:${h}px;` +
        (kind === "redact"
          ? "background:#0a0a0a;outline:1.5px solid #0a0a0a"
          : "outline:2px solid #48b873;background:rgba(72,184,115,.12)");
      layer.appendChild(d);
    }
    setTimeout(() => layer && layer.replaceChildren(), 6000);
  }

  chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
    if (msg.action === "PL_PREPARE") {
      prepare().then((r) => sendResponse({ ok: true, ...r })).catch((e) => sendResponse({ ok: false, error: e.message }));
      return true;
    }
    if (msg.action === "PL_EXECUTE") {
      execute(msg.step).then((result) => sendResponse({ ok: true, result })).catch((e) => sendResponse({ ok: false, error: e.message }));
      return true;
    }
    if (msg.action === "PL_HIGHLIGHT") {
      highlight(msg.regions, msg.kind);
      sendResponse({ ok: true });
      return true;
    }
    if (msg.action === "PL_RESCAN") {
      sendResponse({ ok: true, skeleton: window.__PL.buildSkeleton(), domPiiBoxes: window.__PL.domPiiBoxes() });
      return true;
    }
  });
})();
