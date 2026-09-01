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

  function resolveProfileValue(profile = {}, category = "") {
    if (!category || !profile) return null;
    if (profile[category]) return profile[category];
    const normCat = String(category).toLowerCase().replace(/[^a-z0-9]/g, "");
    for (const k of Object.keys(profile)) {
      if (String(k).toLowerCase().replace(/[^a-z0-9]/g, "") === normCat) {
        return profile[k];
      }
    }
    return null;
  }

  async function prepare() {
    const { profile = {} } = await chrome.storage.local.get("profile");

    const skeleton = window.__PL.buildSkeleton();
    const domPiiBoxes = window.__PL.domPiiBoxes();

    // Adversarial & Indirect Prompt Injection Scanning
    const securityAlerts = [];
    if (window.AdversarialGuard && typeof window.AdversarialGuard.scanAdversarialVectors === "function") {
      const threats = window.AdversarialGuard.scanAdversarialVectors(document);
      for (const t of threats) {
        securityAlerts.push({
          type: t.type,
          reason: t.reason,
          text: t.text,
          bbox: t.bbox,
        });
        // Quarantine: Add threat bbox to domPiiBoxes so it is 100% blacked out in offscreen vision
        domPiiBoxes.push({
          fieldId: null,
          category: "adversarial_injection",
          confidence: t.confidence || 1.0,
          bbox: t.bbox,
        });
      }
    }

    // Annotate nodes:
    // - High-risk secrets (password, aadhaar, ssn, card number) are marked isCensored: true
    // - If profile has local data for piiCategory, node.hasFill = true and node.fillToken = "local:<category>"
    for (const node of skeleton.nodes) {
      // Quarantine adversarial text that may be in button/link/label text
      if (window.AdversarialGuard?.detectPromptInjection) {
        const textToCheck = `${node.label || ""} ${node.text || ""} ${node.name || ""}`;
        const inj = window.AdversarialGuard.detectPromptInjection(textToCheck);
        if (inj.isInjection) {
          node.label = "[QUARANTINED_ADVERSARIAL_TEXT]";
          node.text = "[QUARANTINED_ADVERSARIAL_TEXT]";
          node.isCensored = true;
          securityAlerts.push({
            type: inj.threat || "INDIRECT_PROMPT_INJECTION",
            reason: `Target ${node.id} text contained prompt injection: "${inj.match}"`,
            bbox: node.bbox,
          });
        }
      }

      const piiCat = node.piiCategory;
      const profileVal = piiCat ? resolveProfileValue(profile, piiCat) : null;

      if (piiCat && RESTRICTED_PII_CATEGORIES.has(piiCat)) {
        node.isCensored = true;
        if (profileVal != null) {
          node.hasFill = true;
          node.fillToken = `local:${piiCat}`;
        } else {
          node.hasFill = false;
          node.fillToken = null;
        }
      } else if (piiCat && profileVal != null) {
        node.isCensored = false;
        node.hasFill = true;
        node.fillToken = `local:${piiCat}`;
      } else {
        node.isCensored = false;
        node.hasFill = false;
        node.fillToken = null;
      }
    }
    return { skeleton, domPiiBoxes, profileValues: profile, profileKeys: Object.keys(profile), securityAlerts };
  }

  async function execute(action) {
    const { profile = {} } = await chrome.storage.local.get("profile");

    let category = action.piiCategory;
    if (!category && action.fillToken) {
      category = action.fillToken.replace(/^local:/, "");
    }

    // Resolve profile value LOCALLY on device
    let value = category ? resolveProfileValue(profile, category) : null;
    if (value == null && action.literalValue != null) {
      value = action.literalValue;
    }

    // Guard: only block if there is genuinely no local profile value for a censored field
    if (value == null && category && RESTRICTED_PII_CATEGORIES.has(category)) {
      return { ok: false, note: `Blocked: no local profile data available to fill censored category '${category}'` };
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
