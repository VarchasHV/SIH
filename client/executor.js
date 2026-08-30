// Executes one validated action from the server.
// Whatever is redacted/censored is strictly prohibited from being filled.

(function () {
  const byId = (id) => document.querySelector(`[data-pl-id="${CSS.escape(id)}"]`);

  const SENSITIVE_PATTERNS = window.__PL.SENSITIVE_PATTERNS;
  const CENSORED_CATEGORIES = window.__PL.CENSORED_CATEGORIES;

  // ═══════════════════════════════════════════════════════════════════════
  // Check if an element is a redacted / censored / sensitive field
  // ═══════════════════════════════════════════════════════════════════════

  function isElementCensored(el) {
    if (!el) return false;

    // 1. Check if marked by dom-redactor or skeleton
    if (el.hasAttribute("data-pl-redacted") || el.closest("[data-pl-redacted]")) {
      return true;
    }

    // 2. Check data attributes
    const gt = el.getAttribute("data-gt") || el.getAttribute("data-pl-pii");
    if (gt && (CENSORED_CATEGORIES.has(gt) || SENSITIVE_PATTERNS.test(gt))) {
      return true;
    }

    // 3. Check classifyElement
    try {
      if (typeof classifyElement === "function") {
        const c = classifyElement(el);
        if (c?.category && (CENSORED_CATEGORIES.has(c.category) || SENSITIVE_PATTERNS.test(c.category))) {
          return true;
        }
      }
    } catch {}

    // 4. Check element attributes (name, id, placeholder, label, type)
    const text = [
      el.getAttribute("name") || "",
      el.getAttribute("id") || "",
      el.getAttribute("placeholder") || "",
      el.getAttribute("aria-label") || "",
      el.getAttribute("type") || "",
      el.closest("label")?.textContent || "",
    ].join(" ");

    if (SENSITIVE_PATTERNS.test(text)) {
      return true;
    }

    if (el.type === "password") return true;

    return false;
  }

  // ═══════════════════════════════════════════════════════════════════════
  // DOM helpers
  // ═══════════════════════════════════════════════════════════════════════

  function setNativeValue(el, value) {
    const proto = el instanceof HTMLTextAreaElement ? HTMLTextAreaElement.prototype
      : el instanceof HTMLSelectElement ? HTMLSelectElement.prototype
      : HTMLInputElement.prototype;
    const setter = Object.getOwnPropertyDescriptor(proto, "value")?.set;
    if (setter) setter.call(el, value);
    else el.value = value;
  }

  function fireInput(el) {
    el.dispatchEvent(new Event("input", { bubbles: true }));
    el.dispatchEvent(new Event("change", { bubbles: true }));
    el.dispatchEvent(new KeyboardEvent("keyup", { bubbles: true }));
  }

  // ═══════════════════════════════════════════════════════════════════════
  // Select handler
  // ═══════════════════════════════════════════════════════════════════════

  function handleSelect(el, value) {
    const options = [...(el.options || [])];
    if (options.length === 0) return { ok: false, note: "select has no options" };

    if (value != null && value !== "") {
      const valStr = String(value);
      const exact = options.find(
        (o) => o.value === valStr || o.textContent.trim().toLowerCase() === valStr.toLowerCase()
      );
      if (exact) {
        setNativeValue(el, exact.value);
        fireInput(el);
        return { ok: true, note: `selected "${exact.textContent.trim()}"` };
      }

      const fuzzy = options.find((o) => {
        const text = o.textContent.trim().toLowerCase();
        const val = o.value.toLowerCase();
        const needle = valStr.toLowerCase();
        return text.includes(needle) || val.includes(needle)
          || needle.includes(text) || needle.includes(val);
      });
      if (fuzzy) {
        setNativeValue(el, fuzzy.value);
        fireInput(el);
        return { ok: true, note: `fuzzy-selected "${fuzzy.textContent.trim()}"` };
      }
    }

    const fallbackIdx = options.length > 1 ? 1 : 0;
    const fallback = options[fallbackIdx];
    setNativeValue(el, fallback.value);
    fireInput(el);
    return { ok: true, note: `default-selected index ${fallbackIdx}: "${fallback.textContent.trim()}"` };
  }

  // ═══════════════════════════════════════════════════════════════════════
  // Main action executor
  // ═══════════════════════════════════════════════════════════════════════

  async function executeAction(action, resolvedValue) {
    const a = action || {};
    if (a.action === "wait") {
      await new Promise((r) => setTimeout(r, Math.min(3000, a.ms || 500)));
      return { ok: true, note: "waited" };
    }
    if (a.action === "scroll") {
      const el = a.targetId && byId(a.targetId);
      if (el) el.scrollIntoView({ behavior: "instant", block: "center" });
      else window.scrollBy({ top: a.dy || window.innerHeight * 0.8, behavior: "instant" });
      return { ok: true, note: "scrolled" };
    }
    if (a.action === "done") return { ok: true, note: "done", done: true };

    const el = byId(a.targetId);
    if (!el) return { ok: false, note: `no element ${a.targetId}` };
    el.scrollIntoView?.({ behavior: "instant", block: "center" });

    // STRICT GUARD: If element is redacted or censored, NEVER touch or fill it!
    if (isElementCensored(el)) {
      return { ok: false, note: `Blocked: element ${a.targetId} is redacted/censored and cannot be filled` };
    }
    if (a.piiCategory && (CENSORED_CATEGORIES.has(a.piiCategory) || SENSITIVE_PATTERNS.test(a.piiCategory))) {
      return { ok: false, note: `Blocked: category ${a.piiCategory} is redacted/censored and cannot be filled` };
    }

    if (a.action === "click") {
      el.focus?.();
      el.click();
      return { ok: true, note: `clicked ${a.targetId}` };
    }

    if (a.action === "submit") {
      const form = el.form || el.closest("form");
      if (!form) return { ok: false, note: "no form to submit" };
      if (typeof form.requestSubmit === "function") form.requestSubmit(el.tagName === "BUTTON" ? el : undefined);
      else form.submit();
      return { ok: true, note: "submitted", done: true };
    }

    // ── Resolve the value to inject ───────────────────────────────────
    let value = resolvedValue != null ? String(resolvedValue) : (a.literalValue != null ? String(a.literalValue) : "");

    // ── SELECT elements ──────────────────────────────────────────────
    if (a.action === "select" || (a.action === "type" && el.tagName === "SELECT")) {
      return handleSelect(el, value || a.literalValue || resolvedValue);
    }

    if (el.tagName === "SELECT") {
      return handleSelect(el, value);
    }

    // ── TYPE action ──────────────────────────────────────────────────
    if (a.action === "type") {
      if (!value) {
        return { ok: false, note: `no value to type into ${a.targetId}` };
      }
      el.focus?.();
      if (el.isContentEditable) {
        el.textContent = value;
        el.dispatchEvent(new InputEvent("input", { bubbles: true }));
      } else {
        setNativeValue(el, "");
        setNativeValue(el, value);
        fireInput(el);
      }
      el.blur?.();
      return { ok: true, note: `typed into ${a.targetId} (${value.length} chars)` };
    }

    return { ok: false, note: `unhandled action ${a.action}` };
  }

  function verifyField(targetId, expected) {
    const el = byId(targetId);
    if (!el) return false;
    const got = (el.value ?? el.textContent ?? "").trim();
    return got.replace(/\s+/g, "") === String(expected).trim().replace(/\s+/g, "");
  }

  window.__PL = window.__PL || {};
  window.__PL.executeAction = executeAction;
  window.__PL.verifyField = verifyField;
  window.__PL.isElementCensored = isElementCensored;
})();
