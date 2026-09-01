// Builds the sanitized "accessibility skeleton" of the page - the cheap,
// high-signal channel sent to the server alongside the blacked-out screenshot.
// Never carries a field's actual typed value: only empty / filled / readonly.
//
// Strictly scoped to the active viewport only (no background windows or off-screen ghost nodes).
// Autofilled credential fields are treated as always-redact and censored.

(function () {
  const INTERACTABLE = "input, textarea, select, button, a[href], [contenteditable], [role=button], [role=textbox], [role=combobox], [role=checkbox], [role=radio], [role=link]";
  let seq = 0;

  const SENSITIVE_PATTERNS = window.__PL.SENSITIVE_PATTERNS;
  const CENSORED_CATEGORIES = window.__PL.CENSORED_CATEGORIES;
  const ALWAYS_REDACT_CATEGORIES = window.__PL.ALWAYS_REDACT_CATEGORIES || CENSORED_CATEGORIES;

  function stamp(el) {
    let id = el.getAttribute("data-pl-id");
    if (!id) {
      id = `el-${++seq}`;
      el.setAttribute("data-pl-id", id);
    }
    return id;
  }

  function labelFor(el) {
    try {
      const s = getElementSignals(el);
      return (s.labelText || s.ariaLabel || s.placeholder || "").trim().slice(0, 120);
    } catch {
      return (el.getAttribute("aria-label") || el.getAttribute("placeholder") || el.textContent || "").trim().slice(0, 120);
    }
  }

  function valueState(el) {
    const tag = el.tagName.toLowerCase();
    if (el.disabled) return "disabled";
    if (el.readOnly) return "readonly";
    if (tag === "select") return el.value ? "filled" : "empty";
    if (tag === "input" || tag === "textarea") return (el.value || "").trim() ? "filled" : "empty";
    if (el.isContentEditable) return (el.textContent || "").trim() ? "filled" : "empty";
    return "n/a";
  }

  function isVisibleInViewport(el, rect) {
    if (rect.width <= 1 || rect.height <= 1) return false;
    const st = getComputedStyle(el);
    if (st.visibility === "hidden" || st.display === "none" || Number(st.opacity) === 0) return false;

    // Viewport scope isolation: ensure node is within or intersecting visible viewport
    const vpW = window.innerWidth;
    const vpH = window.innerHeight;
    if (rect.bottom <= 0 || rect.right <= 0 || rect.top >= vpH || rect.left >= vpW) return false;

    return true;
  }

  function detectPiiCategory(el) {
    const gt = el.getAttribute("data-gt") || el.getAttribute("data-pl-pii");
    if (gt && gt !== "safe") return gt;

    // Check autofill
    const isAutofill = typeof isAutofilled === "function" ? isAutofilled(el) : false;
    if (isAutofill) {
      const type = (el.getAttribute("type") || "").toLowerCase();
      const auto = (el.getAttribute("autocomplete") || "").toLowerCase();
      if (auto === "one-time-code") return "otp";
      if (type === "password" || auto.includes("password")) return "password";
      return "credential";
    }

    try {
      if (typeof classifyElement === "function") {
        const c = classifyElement(el);
        if (c?.category) return c.category;
      }
    } catch {}

    const type = (el.getAttribute("type") || "").toLowerCase();
    if (type === "password") return "password";

    const textToMatch = [
      el.getAttribute("name") || "",
      el.getAttribute("id") || "",
      el.getAttribute("placeholder") || "",
      el.getAttribute("aria-label") || "",
      type,
    ].join(" ");

    if (SENSITIVE_PATTERNS.test(textToMatch)) {
      return "sensitive";
    }
    return null;
  }

  function buildSkeleton(opts = {}) {
    const includeHidden = !!opts.includeHidden;
    const dpr = window.devicePixelRatio || 1;
    const vpW = window.innerWidth;
    const vpH = window.innerHeight;
    const nodes = [];

    document.querySelectorAll(INTERACTABLE).forEach((el) => {
      const rect = el.getBoundingClientRect();
      const vis = isVisibleInViewport(el, rect);
      if (!vis && !includeHidden) return;
      const tag = el.tagName.toLowerCase();
      const isAutofill = typeof isAutofilled === "function" ? isAutofilled(el) : false;
      const piiCategory = detectPiiCategory(el);

      // Credential/Autofill Always-Redact isolation:
      const isAlwaysRedactField = isAutofill || (piiCategory && ALWAYS_REDACT_CATEGORIES.has(piiCategory));
      const isCensored = isAlwaysRedactField || (piiCategory ? CENSORED_CATEGORIES.has(piiCategory) : false);

      // Mark DOM element as redacted
      if (isCensored) {
        el.setAttribute("data-pl-redacted", "1");
      }

      // Viewport-clamped coordinates
      const clampLeft = Math.max(0, Math.min(vpW, rect.left));
      const clampTop = Math.max(0, Math.min(vpH, rect.top));
      const clampRight = Math.max(0, Math.min(vpW, rect.right));
      const clampBottom = Math.max(0, Math.min(vpH, rect.bottom));
      const clampW = clampRight - clampLeft;
      const clampH = clampBottom - clampTop;

      const node = {
        id: stamp(el),
        tag,
        type: (el.getAttribute("type") || "").toLowerCase() || null,
        role: el.getAttribute("role") || null,
        label: isCensored ? "" : labelFor(el), // Strip label text for censored secrets
        name: isCensored ? null : (el.getAttribute("name") || null),
        required: el.required || el.getAttribute("aria-required") === "true",
        state: isAutofill ? "filled" : valueState(el),
        piiCategory,
        isCensored,
        alwaysRedact: isAlwaysRedactField,
        isAutofilled: isAutofill,
        visible: vis,
        // viewport CSS px; multiply by dpr for screenshot-pixel coords
        bbox: { x: Math.round(clampLeft), y: Math.round(clampTop), w: Math.round(clampW), h: Math.round(clampH) },
        bboxDevice: { x: Math.round(clampLeft * dpr), y: Math.round(clampTop * dpr), w: Math.round(clampW * dpr), h: Math.round(clampH * dpr) },
      };
      if (tag === "select") {
        node.options = [...el.options].slice(0, 60).map((o) => ({ value: o.value, label: (o.textContent || "").trim().slice(0, 60) }));
      }
      if (tag === "button" || node.role === "button" || tag === "a") {
        node.text = (el.textContent || el.value || "").trim().slice(0, 60);
        node.isSubmit = tag === "button" ? (el.type === "submit" || !el.type) : false;
      }
      nodes.push(node);
    });

    return {
      url: location.href.split(/[?#]/)[0],
      title: document.title,
      viewport: { w: vpW, h: vpH, dpr, isScopedToViewport: true },
      scroll: { x: Math.round(window.scrollX), y: Math.round(window.scrollY) },
      nodes,
    };
  }

  // DOM PII boxes, keyed to skeleton ids with viewport boundary clamping
  function domPiiBoxes() {
    const out = [];
    const vpW = window.innerWidth;
    const vpH = window.innerHeight;

    document.querySelectorAll("input, textarea, select, [contenteditable]").forEach((el) => {
      const cat = detectPiiCategory(el);
      if (!cat) return;
      const rect = el.getBoundingClientRect();
      if (rect.width <= 0 || rect.height <= 0) return;
      if (rect.bottom <= 0 || rect.right <= 0 || rect.top >= vpH || rect.left >= vpW) return;

      const clampLeft = Math.max(0, Math.min(vpW, rect.left));
      const clampTop = Math.max(0, Math.min(vpH, rect.top));
      const clampRight = Math.max(0, Math.min(vpW, rect.right));
      const clampBottom = Math.max(0, Math.min(vpH, rect.bottom));
      const clampW = clampRight - clampLeft;
      const clampH = clampBottom - clampTop;

      if (clampW <= 0 || clampH <= 0) return;

      const isAutofill = typeof isAutofilled === "function" ? isAutofilled(el) : false;
      const isAlwaysRedact = isAutofill || ALWAYS_REDACT_CATEGORIES.has(cat);

      out.push({
        fieldId: stamp(el),
        category: cat,
        confidence: 1.0,
        alwaysRedact: isAlwaysRedact,
        isAutofilled: isAutofill,
        bbox: { x: clampLeft, y: clampTop, w: clampW, h: clampH },
      });
    });
    return out;
  }

  window.__PL = window.__PL || {};
  window.__PL.CENSORED_CATEGORIES = CENSORED_CATEGORIES;
  window.__PL.ALWAYS_REDACT_CATEGORIES = ALWAYS_REDACT_CATEGORIES;
  window.__PL.SENSITIVE_PATTERNS = SENSITIVE_PATTERNS;
  window.__PL.detectPiiCategory = detectPiiCategory;
  window.__PL.buildSkeleton = buildSkeleton;
  window.__PL.domPiiBoxes = domPiiBoxes;
})();
