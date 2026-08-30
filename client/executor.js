// Executes one validated action from the server. Values are passed directly
// from the non-sensitive profile — no tokenization.
// Censored/sensitive fields are strictly blocked from being filled.

(function () {
  const byId = (id) => document.querySelector(`[data-pl-id="${CSS.escape(id)}"]`);

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

  // ═══════════════════════════════════════════════════════════════════════
  // Check if an element is a censored / sensitive field
  // ═══════════════════════════════════════════════════════════════════════

  function isElementCensored(el) {
    if (!el) return false;
    const cat = el.getAttribute("data-pl-pii") || el.getAttribute("data-gt");
    if (cat && CENSORED_CATEGORIES.has(cat)) return true;

    try {
      if (typeof classifyElement === "function") {
        const c = classifyElement(el);
        if (c?.category && CENSORED_CATEGORIES.has(c.category)) return true;
      }
    } catch {}

    // Check type / autocomplete / attributes
    const type = (el.getAttribute("type") || "").toLowerCase();
    if (type === "password") return true;

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

    // Guard: Block typing or filling into any censored / sensitive field
    if ((a.action === "type" || a.action === "select") && isElementCensored(el)) {
      return { ok: false, note: `Blocked: element ${a.targetId} is a censored/sensitive field and will not be filled` };
    }
    if (a.piiCategory && CENSORED_CATEGORIES.has(a.piiCategory)) {
      return { ok: false, note: `Blocked: ${a.piiCategory} is a censored category and will not be filled` };
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
