// Builds the sanitized "accessibility skeleton" of the page - the cheap,
// high-signal channel sent to the server alongside the blacked-out screenshot.
// Never carries a field's actual typed value: only empty / filled / readonly.
//
// Shares scope with content.js (same content_scripts entry), so it reuses
// classifyElement() defined there.

(function () {
  const INTERACTABLE = "input, textarea, select, button, a[href], [contenteditable], [role=button], [role=textbox], [role=combobox], [role=checkbox], [role=radio], [role=link]";
  let seq = 0;

  const SENSITIVE_PATTERNS = window.__PL.SENSITIVE_PATTERNS;
  const CENSORED_CATEGORIES = window.__PL.CENSORED_CATEGORIES;

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

  function isVisible(el, rect) {
    if (rect.width <= 1 || rect.height <= 1) return false;
    const st = getComputedStyle(el);
    if (st.visibility === "hidden" || st.display === "none" || Number(st.opacity) === 0) return false;
    return true;
  }

  function detectPiiCategory(el) {
    const gt = el.getAttribute("data-gt") || el.getAttribute("data-pl-pii");
    if (gt && gt !== "safe") return gt;

    try {
      if (typeof classifyElement === "function") {
        const c = classifyElement(el);
        if (c?.category) return c.category;
      }
    } catch {}

    const textToMatch = [
      el.getAttribute("name") || "",
      el.getAttribute("id") || "",
      el.getAttribute("placeholder") || "",
      el.getAttribute("aria-label") || "",
      el.getAttribute("type") || "",
    ].join(" ");

    if (SENSITIVE_PATTERNS.test(textToMatch)) {
      return "sensitive";
    }
    return null;
  }

  function buildSkeleton(opts = {}) {
    const includeHidden = !!opts.includeHidden;
    const dpr = window.devicePixelRatio || 1;
    const nodes = [];
    document.querySelectorAll(INTERACTABLE).forEach((el) => {
      const rect = el.getBoundingClientRect();
      const vis = isVisible(el, rect);
      if (!vis && !includeHidden) return;
      const tag = el.tagName.toLowerCase();
      const piiCategory = detectPiiCategory(el);
      const isCensored = piiCategory ? CENSORED_CATEGORIES.has(piiCategory) || SENSITIVE_PATTERNS.test(piiCategory) : false;

      // Mark the DOM element as redacted if censored
      if (isCensored) {
        el.setAttribute("data-pl-redacted", "1");
      }

      const node = {
        id: stamp(el),
        tag,
        type: (el.getAttribute("type") || "").toLowerCase() || null,
        role: el.getAttribute("role") || null,
        label: labelFor(el),
        name: el.getAttribute("name") || null,
        required: el.required || el.getAttribute("aria-required") === "true",
        state: valueState(el),
        piiCategory,
        isCensored,
        visible: vis,
        // viewport CSS px; multiply by dpr for screenshot-pixel coords
        bbox: { x: Math.round(rect.left), y: Math.round(rect.top), w: Math.round(rect.width), h: Math.round(rect.height) },
        bboxDevice: { x: Math.round(rect.left * dpr), y: Math.round(rect.top * dpr), w: Math.round(rect.width * dpr), h: Math.round(rect.height * dpr) },
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
      viewport: { w: window.innerWidth, h: window.innerHeight, dpr },
      scroll: { x: Math.round(window.scrollX), y: Math.round(window.scrollY) },
      nodes,
    };
  }

  // DOM PII boxes, keyed to skeleton ids
  function domPiiBoxes() {
    const out = [];
    document.querySelectorAll("input, textarea, select, [contenteditable]").forEach((el) => {
      const cat = detectPiiCategory(el);
      if (!cat) return;
      const rect = el.getBoundingClientRect();
      if (rect.width <= 0 || rect.height <= 0) return;
      out.push({
        fieldId: stamp(el),
        category: cat,
        confidence: 1.0,
        bbox: { x: rect.left, y: rect.top, w: rect.width, h: rect.height },
      });
    });
    return out;
  }

  window.__PL = window.__PL || {};
  window.__PL.CENSORED_CATEGORIES = CENSORED_CATEGORIES;
  window.__PL.SENSITIVE_PATTERNS = SENSITIVE_PATTERNS;
  window.__PL.detectPiiCategory = detectPiiCategory;
  window.__PL.buildSkeleton = buildSkeleton;
  window.__PL.domPiiBoxes = domPiiBoxes;
})();
