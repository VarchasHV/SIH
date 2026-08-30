// Content-script side of the agent loop.
// 1. Profile values stay strictly local on the user's machine (chrome.storage.local).
// 2. High-risk secret categories (RESTRICTED_PII_CATEGORIES) are marked isCensored: true and blocked.
// 3. For non-secret profile categories (e.g. name, email, phone, address), when the VLM emits
//    an action (type targetId, piiCategory), agent-bridge looks up profile[piiCategory] LOCALLY
//    and passes the value directly to the executor to type into the page.

(function () {
  if (window.__plAgentBridgeLoaded) return; // guard against double injection
  window.__plAgentBridgeLoaded = true;

  const RESTRICTED_PII_CATEGORIES = window.__PL.RESTRICTED_PII_CATEGORIES || window.__PL.CENSORED_CATEGORIES;

  async function prepare() {
    const { profile = {} } = await chrome.storage.local.get("profile");

    const skeleton = window.__PL.buildSkeleton();
    const domPiiBoxes = window.__PL.domPiiBoxes();

    // Annotate nodes:
    // - High-risk secrets (password, aadhaar, ssn, card number) are marked isCensored: true
    // - Profile fields (first name, email, address, phone) have isCensored: false and hasFill: true if profile has data
    for (const node of skeleton.nodes) {
      if (node.piiCategory && RESTRICTED_PII_CATEGORIES.has(node.piiCategory)) {
        node.isCensored = true;
        node.hasFill = false;
      } else if (node.piiCategory && profile[node.piiCategory]) {
        node.isCensored = false;
        node.hasFill = true;
      } else {
        node.hasFill = false;
      }
    }
    return { skeleton, domPiiBoxes, profileValues: profile, profileKeys: Object.keys(profile) };
  }

  async function execute(action) {
    const { profile = {} } = await chrome.storage.local.get("profile");

    // Guard: strictly block filling any restricted secret category
    if (action.piiCategory && RESTRICTED_PII_CATEGORIES.has(action.piiCategory)) {
      return { ok: false, note: `Blocked: restricted category '${action.piiCategory}' cannot be auto-filled` };
    }

    // Resolve profile value LOCALLY from chrome.storage.local
    let value = null;
    if (action.piiCategory && profile[action.piiCategory]) {
      value = profile[action.piiCategory];
    } else if (action.literalValue != null) {
      value = action.literalValue;
    }

    // Pass resolved value directly to the local DOM executor
    const result = await window.__PL.executeAction(action, value);
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

      let border = "2px solid #ef4444";
      let bg = "rgba(239, 68, 68, 0.2)";
      if (kind === "target") {
        border = "2px solid #22c55e";
        bg = "rgba(34, 197, 94, 0.25)";
      } else if (kind === "hover") {
        border = "2px dashed #3b82f6";
        bg = "rgba(59, 130, 246, 0.15)";
      }

      d.style.cssText = `position:absolute;left:${x}px;top:${y}px;width:${w}px;height:${h}px;border:${border};background:${bg};box-sizing:border-box;border-radius:3px;transition:all 0.15s ease`;
      layer.appendChild(d);
    }
    if (kind === "target") {
      setTimeout(() => {
        layer.replaceChildren();
      }, 1200);
    }
  }

  chrome.runtime.onMessage.addListener((request, _sender, sendResponse) => {
    if (request.action === "PL_PREPARE") {
      prepare()
        .then((res) => sendResponse({ ok: true, ...res }))
        .catch((err) => sendResponse({ ok: false, error: err.message }));
      return true;
    }
    if (request.action === "PL_EXECUTE") {
      execute(request.step)
        .then((res) => sendResponse({ ok: true, result: res }))
        .catch((err) => sendResponse({ ok: false, error: err.message }));
      return true;
    }
    if (request.action === "PL_HIGHLIGHT") {
      highlight(request.regions, request.kind);
      sendResponse({ ok: true });
      return true;
    }
  });
})();
