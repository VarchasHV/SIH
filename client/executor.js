// Executes one validated action from the server. Token -> real-value resolution
// happens in the caller (agent-bridge) so real PII only ever appears here, in
// the page context that is about to receive it anyway.

(function () {
  const byId = (id) => document.querySelector(`[data-pl-id="${CSS.escape(id)}"]`);

  // ═══════════════════════════════════════════════════════════════════════
  // Synthetic tokens: safe placeholder values injected when no real profile
  // value exists.  The agent NEVER asks the user for PII — these pass basic
  // frontend validation while being obviously non-real.
  // ═══════════════════════════════════════════════════════════════════════

  const SYNTHETIC_TOKENS = {
    first_name: "Privacy",
    "first name": "Privacy",
    last_name: "User",
    "last name": "User",
    "full name": "Privacy User",
    email: "redacted@privacylens.local",
    phone: "9999999999",
    "phone number": "9999999999",
    "phone-in": "9999999999",
    aadhaar: "000000000000",
    Aadhaar: "000000000000",
    pan: "XXXXX0000X",
    PAN: "XXXXX0000X",
    credit_card: "4000000000000000",
    "credit/debit card number": "4000000000000000",
    "credit-card": "4000000000000000",
    cvv: "000",
    "CVV/security code": "000",
    "card expiry": "12/2030",
    ssn: "000-00-0000",
    SSN: "000-00-0000",
    username: "privacyuser",
    password: "••••••••",
    address: "Privacy Street, Redacted City",
    "postal/ZIP code": "000000",
    "date of birth": "2000-01-01",
    "bank account information": "0000000000",
    "passport number": "X0000000",
    "government ID": "REDACTED",
    ifsc: "XXXX0000000",
    "upi-vpa": "redacted@upi",
  };

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
  // Resolve PII category for an element — check data-pl-pii attr,
  // data-gt, or classifyElement from content.js
  // ═══════════════════════════════════════════════════════════════════════

  function getPiiCategory(el) {
    if (!el) return null;
    const attr = el.getAttribute("data-pl-pii") || el.getAttribute("data-gt");
    if (attr) return attr;
    try {
      if (typeof classifyElement === "function") {
        return classifyElement(el)?.category || null;
      }
    } catch {}
    return null;
  }

  // ═══════════════════════════════════════════════════════════════════════
  // Select handler — proper <select> interaction (Objective 3)
  // ═══════════════════════════════════════════════════════════════════════

  function handleSelect(el, value) {
    const options = [...(el.options || [])];
    if (options.length === 0) return { ok: false, note: "select has no options" };

    // 1. Try exact match by value or text
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

      // 2. Fuzzy match — substring or includes
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

    // 3. Default: select index 1 (skip the empty placeholder at index 0)
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
    let value = a.valueToken != null || a.literalValue != null
      ? String(resolvedValue ?? a.literalValue ?? "")
      : "";

    // Synthetic fallback: if no resolved value, use a safe placeholder
    // based on the element's PII category
    if (!value && a.action === "type") {
      const piiCat = getPiiCategory(el);
      if (piiCat && SYNTHETIC_TOKENS[piiCat]) {
        value = SYNTHETIC_TOKENS[piiCat];
      }
    }

    // ── SELECT elements ──────────────────────────────────────────────
    if (a.action === "select" || (a.action === "type" && el.tagName === "SELECT")) {
      return handleSelect(el, value || a.literalValue || resolvedValue);
    }

    // Guard: do NOT attempt text injection on <select> elements
    if (el.tagName === "SELECT") {
      return handleSelect(el, value);
    }

    // ── TYPE action ──────────────────────────────────────────────────
    if (a.action === "type") {
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

  // read-back: does the field now hold the value we intended? (loop early-stop)
  function verifyField(targetId, expected) {
    const el = byId(targetId);
    if (!el) return false;
    const got = (el.value ?? el.textContent ?? "").trim();
    return got.replace(/\s+/g, "") === String(expected).trim().replace(/\s+/g, "");
  }

  window.__PL = window.__PL || {};
  window.__PL.executeAction = executeAction;
  window.__PL.verifyField = verifyField;
  window.__PL.SYNTHETIC_TOKENS = SYNTHETIC_TOKENS;
})();
