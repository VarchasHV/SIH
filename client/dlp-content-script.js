// Client-Side Data Loss Prevention (DLP) Content Script
// Attached to window.__PL for synchronous in-page sanitization before LLM network requests.

(function () {
  if (window.__plDlpContentScriptLoaded) return;
  window.__plDlpContentScriptLoaded = true;

  // ═══════════════════════════════════════════════════════════════════════════
  // 1. DLP RULE DICTIONARY & SEMANTIC TOKENS
  // ═══════════════════════════════════════════════════════════════════════════
  const DLP_RULES = [
    // ── Authentication, Credentials & Secrets ──
    { category: "password", token: "[TOKEN_PASSWORD]", attrRegex: /\b(password|passwd|passcode|secret|pwd|pin|auth_key|api_key)\b/i, textRegex: null },
    { category: "credential", token: "[TOKEN_CREDENTIAL]", attrRegex: /\b(credential|credentials|auth_token|token|session_token|access_token|security_key|auth_key|secret_key)\b/i, textRegex: /\b(Bearer\s+[A-Za-z0-9._~+/-]+=*|eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})\b/ },
    { category: "otp", token: "[TOKEN_OTP_2FA]", attrRegex: /\b(otp|2fa|mfa|totp|auth_code|verification_code|one_time_code|sms_code)\b/i, textRegex: /(?:\b(?:otp|2fa|code|verification|totp)[^0-9\n]{0,15}?)\b\d{4,8}\b/i },
    { category: "ssh_key", token: "[TOKEN_SSH_KEY]", attrRegex: /\b(ssh[_\s]?key|private[_\s]?key|id_rsa|id_ed25519)\b/i, textRegex: /-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----/ },
    { category: "api_key", token: "[TOKEN_API_KEY]", attrRegex: /\b(api[_\s]?key|apikey|secret[_\s]?key|client[_\s]?secret)\b/i, textRegex: /\b(?:sk-[a-zA-Z0-9]{20,}|ghp_[a-zA-Z0-9]{20,}|AKIA[0-9A-Z]{16})\b/ },

    // ── Government & National Identifiers ──
    { category: "ssn", token: "[TOKEN_SSN]", attrRegex: /\b(ssn|social[_\s]?security|soc[_\s]?sec|national[_\s]?insurance|sin[_\s]?number)\b/i, textRegex: /\b\d{3}-\d{2}-\d{4}\b/ },
    { category: "gstin", token: "[TOKEN_GSTIN]", attrRegex: /\b(gstin|gst[_\s]?num(ber)?|gst[_\s]?no)\b/i, textRegex: /\b\d{2}[A-Z]{5}\d{4}[A-Z][A-Z0-9]Z[A-Z0-9]\b/ },
    { category: "passport", token: "[TOKEN_PASSPORT]", attrRegex: /\b(passport|passport[_\s]?no|passport[_\s]?num(ber)?)\b/i, textRegex: /\b[A-PR-WYa-pr-wy][1-9]\d\s?\d{4}[1-9]\b/ },
    { category: "pan", token: "[TOKEN_PAN]", attrRegex: /\b(pan[_\s]?card|pan[_\s]?number|permanent[_\s]?account)\b|(?<![a-z])pan(?![a-z])/i, textRegex: /\b[A-Z]{5}[0-9]{4}[A-Z]\b/ },
    { category: "driver_license", token: "[TOKEN_DRIVER_LICENSE]", attrRegex: /\b(driver[_\s]?license|drivers[_\s]?license|driving[_\s]?licen[sc]e|dl[_\s]?num(ber)?|licen[sc]e[_\s]?no)\b/i, textRegex: null },
    { category: "voter_id", token: "[TOKEN_VOTER_ID]", attrRegex: /\b(voter[_\s]?id|epic[_\s]?no|electoral[_\s]?id)\b/i, textRegex: /\b[A-Z]{3}[0-9]{7}\b/ },

    // ── Financial: Cards & Banking ──
    { category: "credit_card", token: "[TOKEN_CREDIT_CARD]", attrRegex: /\b(card[_\s]?num(ber)?|credit[_\s]?card|debit[_\s]?card|cc[_\s]?num(ber)?|cardno|pan[_\s]?num|cc[_\s]?number)\b/i, textRegex: /(?<!\d)\b(?:\d[\s-]?){13,19}\b(?!\d)/ },
    { category: "aadhaar", token: "[TOKEN_AADHAAR]", attrRegex: /\b(aadhaar|aadhar|uidai|uid[_\s]?number)\b/i, textRegex: /(?<!\d)\b\d{4}[\s-]?\d{4}[\s-]?\d{4}\b(?!\d)/ },
    { category: "card_expiry", token: "[TOKEN_CARD_EXPIRY]", attrRegex: /\b(card[_\s]?exp(ir(y|ation))?|exp[_\s]?date|cc[_\s]?exp|ccexp)\b/i, textRegex: /\b(0[1-9]|1[0-2])[/-](\d{2}|\d{4})\b/ },
    { category: "card_holder", token: "[TOKEN_CARD_HOLDER]", attrRegex: /\b(card[_\s]?holder|card[_\s]?user|name[_\s]?on[_\s]?card|cc[_\s]?name)\b/i, textRegex: null },
    { category: "cvv", token: "[TOKEN_CVV]", attrRegex: /\b(cvv\d?|cvc\d?|security[_\s]?code|card[_\s]?sec|csc|card[_\s]?verification)\b/i, textRegex: /(?<![\d-])\b\d{3,4}\b(?![\d-])/ },
    { category: "bank_account", token: "[TOKEN_BANK_ACCOUNT]", attrRegex: /\b(bank[_\s]?account|account[_\s]?no|account[_\s]?number|routing[_\s]?num(ber)?|iban|swift|bic|aba[_\s]?routing)\b/i, textRegex: /\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b|\b\d{9,18}\b/ },
    { category: "ifsc", token: "[TOKEN_IFSC]", attrRegex: /\b(ifsc|ifsc[_\s]?code)\b/i, textRegex: /\b[A-Z]{4}0[A-Z0-9]{6}\b/ },
    { category: "upi", token: "[TOKEN_UPI_VPA]", attrRegex: /\b(upi|vpa|upi[_\s]?id|pay[_\s]?to)\b/i, textRegex: /\b[a-zA-Z0-9.\-_]{2,49}@(okhdfcbank|oksbi|okaxis|okicici|paytm|ybl|upi|sbi|icici|axisbank|gpay)\b/i },
    { category: "income", token: "[TOKEN_INCOME]", attrRegex: /\b(income|salary|annual[_\s]?income|monthly[_\s]?income|compensation|net[_\s]?worth)\b/i, textRegex: null },

    // ── Contact & Location ──
    { category: "email", token: "[TOKEN_EMAIL]", attrRegex: /\b(email|e-mail|mail[_\s]?addr(ess)?)\b/i, textRegex: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/ },
    { category: "phone", token: "[TOKEN_PHONE]", attrRegex: /\b(phone|mobile|cell|telephone|tel[_\s]?no|contact[_\s]?no|fax|home[_\s]?phone|work[_\s]?phone)\b/i, textRegex: /(?:\+?\d{1,3}[ -]?)?\(?\d{3}\)?[ -]?\d{3}[ -]?\d{4}|\b(?:\+?91[\s-]?)?[6-9]\d{9}\b/ },
    { category: "address", token: "[TOKEN_ADDRESS]", attrRegex: /\b(address|street|addr1|addr2|residence|street[_\s]?address|address[_\s]?line)\b/i, textRegex: null },
    { category: "zip_code", token: "[TOKEN_ZIP_CODE]", attrRegex: /\b(zip|zip[_\s]?code|postal|postal[_\s]?code|pincode|pin[_\s]?code|postcode)\b/i, textRegex: /\b\d{5}(?:-\d{4})?\b|\b\d{6}\b/ },
    { category: "city", token: "[TOKEN_CITY]", attrRegex: /\b(city|town|municipality)\b/i, textRegex: null },
    { category: "state", token: "[TOKEN_STATE]", attrRegex: /\b(state|province|region|state[_\s]?province)\b/i, textRegex: null },
    { category: "country", token: "[TOKEN_COUNTRY]", attrRegex: /\b(country|nation|country[_\s]?code)\b/i, textRegex: null },

    // ── Personal Demographics ──
    { category: "dob", token: "[TOKEN_DOB]", attrRegex: /\b(dob|birth[_\s]?date|date[_\s]?of[_\s]?birth|bday|born[_\s]?on)\b/i, textRegex: /\b(0?[1-9]|[12]\d|3[01])[/\-.](0?[1-9]|1[0-2])[/\-.](\d{4})\b/ },
    { category: "first_name", token: "[TOKEN_FIRST_NAME]", attrRegex: /\b(first[_\s]?name|fname|given[_\s]?name|forename)\b/i, textRegex: null },
    { category: "middle_name", token: "[TOKEN_MIDDLE_NAME]", attrRegex: /\b(middle[_\s]?name|middle[_\s]?initial|mname|mid[_\s]?init)\b/i, textRegex: null },
    { category: "last_name", token: "[TOKEN_LAST_NAME]", attrRegex: /\b(last[_\s]?name|lname|surname|family[_\s]?name)\b/i, textRegex: null },
    { category: "full_name", token: "[TOKEN_FULL_NAME]", attrRegex: /\b(full[_\s]?name|your[_\s]?name|contact[_\s]?name|applicant[_\s]?name)\b/i, textRegex: null },
    { category: "gender", token: "[TOKEN_GENDER]", attrRegex: /\b(gender|sex|user[_\s]?gender)\b/i, textRegex: null },

    // ── Employment & Digital ──
    { category: "company", token: "[TOKEN_COMPANY]", attrRegex: /\b(company|organization|employer|workplace|company[_\s]?name)\b/i, textRegex: null },
    { category: "position", token: "[TOKEN_POSITION]", attrRegex: /\b(position|job[_\s]?title|occupation|designation|role)\b/i, textRegex: null },
    { category: "website", token: "[TOKEN_WEBSITE]", attrRegex: /\b(website|web[_\s]?site|homepage|url)\b/i, textRegex: /\bhttps?:\/\/[^\s/$.?#].[^\s]*\b/i },
    { category: "username", token: "[TOKEN_USERNAME]", attrRegex: /\b(username|user[_\s]?id|login[_\s]?id|user[_\s]?name|userid|loginid)\b/i, textRegex: null },
  ];

  const SENSITIVE_MEDIA_REGEX = /\b(upload[_\s]?(id|doc|photo|file)|passport|driver[_\s]?license|govt[_\s]?id|identity|aadhaar|ssn|id[_\s]?card|proof[_\s]?of[_\s]?id|selfie|signature|profile[_\s]?photo)\b/i;
  const GENERIC_TEXT_PII_REGEX = [
    /-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----/g,
    /\b(?:Bearer\s+[A-Za-z0-9._~+/-]+=*|sk-[a-zA-Z0-9]{20,}|ghp_[a-zA-Z0-9]{20,}|AKIA[0-9A-Z]{16})\b/g,
    /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g,
    /\b\d{3}-\d{2}-\d{4}\b/g,
    /(?<!\d)\b(?:\d[\s-]?){13,19}\b(?!\d)/g,
    /(?<!\d)\b\d{4}\s?\d{4}\s?\d{4}\b(?!\d)/g,
    /\b[A-Z]{5}\d{4}[A-Z]\b/g,
    /(?<!\w)(?:\+?91[\s-]?)?[6-9]\d{9}\b/g,
  ];

  // ═══════════════════════════════════════════════════════════════════════════
  // 2. HEURISTIC FUNCTIONS
  // ═══════════════════════════════════════════════════════════════════════════
  function classifyField(signals) {
    const isAutofill = !!(signals.isAutofilled || signals.autofilled);
    const type = (signals.type || "").toLowerCase();
    const auto = (signals.autocomplete || "").toLowerCase();

    if (isAutofill || type === "password" || /(password|one-time-code|webauthn|credential)/i.test(auto)) {
      let cat = "password";
      let tok = "[TOKEN_PASSWORD]";
      if (auto === "one-time-code" || /\b(otp|2fa|mfa|totp)\b/i.test((signals.id || "") + " " + (signals.name || ""))) {
        cat = "otp";
        tok = "[TOKEN_OTP_2FA]";
      } else if (/\b(token|key|secret|credential)\b/i.test((signals.id || "") + " " + (signals.name || ""))) {
        cat = "credential";
        tok = "[TOKEN_CREDENTIAL]";
      }
      return { isSensitive: true, category: cat, token: tok, alwaysRedact: true, isAutofilled: isAutofill };
    }

    if (type === "email") {
      return { isSensitive: true, category: "email", token: "[TOKEN_EMAIL]" };
    }
    if (type === "tel") {
      return { isSensitive: true, category: "phone", token: "[TOKEN_PHONE]" };
    }
    const combined = [
      signals.id || "",
      signals.name || "",
      signals.className || "",
      type,
      auto,
      signals.placeholder || "",
      signals.ariaLabel || "",
      signals.labelText || "",
    ].join(" ");

    for (const rule of DLP_RULES) {
      if (rule.attrRegex && rule.attrRegex.test(combined)) {
        const isCred = ["password", "credential", "otp", "ssh_key", "api_key", "credit_card", "cvv", "ssn", "aadhaar", "pan"].includes(rule.category);
        return { isSensitive: true, category: rule.category, token: rule.token, alwaysRedact: isCred };
      }
    }
    return { isSensitive: false, category: null, token: null };
  }

  function sanitizeText(text) {
    if (!text) return "";
    let s = text;
    for (const rule of DLP_RULES) {
      if (rule.textRegex) s = s.replace(new RegExp(rule.textRegex, "g"), rule.token);
    }
    for (const re of GENERIC_TEXT_PII_REGEX) {
      s = s.replace(re, "[TEXT_REDACTED]");
    }
    return s;
  }

  function resolveLabel(el) {
    if (!el) return "";
    const id = el.getAttribute("id");
    if (id) {
      try {
        const explicit = document.querySelector(`label[for="${CSS.escape(id)}"]`);
        if (explicit && explicit.textContent.trim()) return explicit.textContent.trim();
      } catch (e) {}
    }
    const enclosing = el.closest("label");
    if (enclosing) {
      const clone = enclosing.cloneNode(true);
      const childInput = clone.querySelector("input, select, textarea");
      if (childInput) childInput.remove();
      if (clone.textContent.trim()) return clone.textContent.trim();
    }
    const labelledBy = el.getAttribute("aria-labelledby");
    if (labelledBy) {
      const ref = document.getElementById(labelledBy);
      if (ref && ref.textContent.trim()) return ref.textContent.trim();
    }
    const ariaLabel = el.getAttribute("aria-label");
    if (ariaLabel) return ariaLabel.trim();
    const placeholder = el.getAttribute("placeholder");
    if (placeholder) return placeholder.trim();

    let prev = el.previousElementSibling;
    while (prev) {
      if (["LABEL", "SPAN", "P", "DIV", "B", "STRONG"].includes(prev.tagName)) {
        const t = prev.textContent.trim();
        if (t && t.length <= 80) return t;
      }
      prev = prev.previousElementSibling;
    }
    const td = el.closest("td");
    if (td && td.previousElementSibling) {
      const t = td.previousElementSibling.textContent.trim();
      if (t && t.length <= 80) return t;
    }
    return "";
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // 3. SANITIZATION CORE
  // ═══════════════════════════════════════════════════════════════════════════
  function sanitizeElement(el) {
    const tagName = el.tagName.toLowerCase();
    const type = (el.getAttribute("type") || (tagName === "textarea" ? "textarea" : tagName === "select" ? "select" : "text")).toLowerCase();
    const id = el.getAttribute("id") || "";
    const name = el.getAttribute("name") || "";
    const className = el.getAttribute("class") || "";
    const autocomplete = el.getAttribute("autocomplete") || "";
    const placeholder = el.getAttribute("placeholder") || "";
    const ariaLabel = el.getAttribute("aria-label") || "";
    const required = el.required || el.getAttribute("aria-required") === "true";
    const label = resolveLabel(el);

    const isAutofill = !!(
      (typeof isAutofilled === "function" && isAutofilled(el)) ||
      (el.hasAttribute && (
        el.hasAttribute("data-com-onepassword-filled") ||
        el.hasAttribute("data-bitwarden-filled") ||
        el.hasAttribute("data-lastpass-filled") ||
        el.hasAttribute("data-pl-autofill") ||
        el.hasAttribute("autofilled")
      ))
    );

    const classification = classifyField({
      id, name, className, type, autocomplete, placeholder, ariaLabel, labelText: label, isAutofilled: isAutofill
    });

    let sanitizedValue = "";
    if (classification.isSensitive) {
      sanitizedValue = classification.token;
    } else if (type === "checkbox" || type === "radio") {
      sanitizedValue = el.checked ? "checked" : "unchecked";
    }

    const isAlwaysRedact = !!(classification.alwaysRedact || isAutofill);

    const field = {
      tag: tagName,
      type,
      id: id || undefined,
      name: isAlwaysRedact ? undefined : (name || undefined),
      label: isAlwaysRedact ? undefined : (label || undefined),
      required: required ? true : undefined,
      isSensitive: classification.isSensitive,
      alwaysRedact: isAlwaysRedact || undefined,
      category: classification.category || undefined,
      value: sanitizedValue,
    };

    if (tagName === "select" && el.options) {
      field.options = Array.from(el.options).slice(0, 30).map((o) => ({
        value: o.value,
        text: o.textContent.trim(),
        selected: o.selected || undefined,
      }));
    }
    return field;
  }

  function extractCleanStructure(root = document) {
    const forms = [];
    const processed = new Set();

    root.querySelectorAll("form").forEach((form, idx) => {
      const formId = form.getAttribute("id") || `form-${idx + 1}`;
      const fields = [];
      form.querySelectorAll("input, select, textarea").forEach((ctrl) => {
        processed.add(ctrl);
        fields.push(sanitizeElement(ctrl));
      });
      forms.push({ formId, fields });
    });

    const looseFields = [];
    root.querySelectorAll("input, select, textarea").forEach((ctrl) => {
      if (!processed.has(ctrl)) looseFields.push(sanitizeElement(ctrl));
    });

    const paragraphs = [];
    root.querySelectorAll("p").forEach((p) => {
      const text = p.textContent.trim();
      if (text) paragraphs.push(sanitizeText(text));
    });

    const images = [];
    root.querySelectorAll("img").forEach((img) => {
      const src = img.getAttribute("src") || "";
      const alt = img.getAttribute("alt") || "";
      const nearby = (img.parentElement?.textContent || "").slice(0, 150);
      const isSensitive = src.startsWith("data:") || SENSITIVE_MEDIA_REGEX.test([src, alt, nearby].join(" "));
      images.push({
        tag: "img",
        alt: isSensitive ? "[SENSITIVE_IMAGE_REDACTED]" : alt || undefined,
        src: isSensitive ? "[SENSITIVE_IMAGE_REDACTED]" : src,
        isSensitive,
      });
    });

    return { forms, looseFields, paragraphs, images };
  }

  function getCleanHtml(root = document) {
    const tree = extractCleanStructure(root);
    const parts = [];

    const formatAttrs = (f) => {
      const attrs = [`type="${f.type}"`];
      if (f.id) attrs.push(`id="${f.id}"`);
      if (f.name) attrs.push(`name="${f.name}"`);
      if (f.required) attrs.push("required");
      if (f.value) attrs.push(`value="${f.value}"`);
      return attrs.join(" ");
    };

    const renderFieldHtml = (f) => {
      const labelPrefix = f.label ? `<label>${f.label}</label>` : "";
      if (f.tag === "textarea") {
        return `${labelPrefix}<textarea ${f.id ? `id="${f.id}"` : ""} ${f.name ? `name="${f.name}"` : ""}>${f.value || ""}</textarea>`;
      }
      if (f.tag === "select") {
        const opts = (f.options || []).map((o) => `<option value="${o.value}">${o.text}</option>`).join("");
        return `${labelPrefix}<select ${f.id ? `id="${f.id}"` : ""} ${f.name ? `name="${f.name}"` : ""}>${opts}</select>`;
      }
      return `${labelPrefix}<input ${formatAttrs(f)}/>`;
    };

    for (const form of tree.forms) {
      const fieldsHtml = form.fields.map(renderFieldHtml).join("");
      parts.push(`<form id="${form.formId}">${fieldsHtml}</form>`);
    }

    if (tree.looseFields.length > 0) {
      const looseHtml = tree.looseFields.map(renderFieldHtml).join("");
      parts.push(`<div class="loose-fields">${looseHtml}</div>`);
    }

    for (const p of tree.paragraphs) {
      if (p.includes("[TOKEN_") || p.includes("[TEXT_REDACTED]")) {
        parts.push(`<p>${p}</p>`);
      }
    }

    for (const img of tree.images) {
      if (img.isSensitive) {
        parts.push(`<img alt="[SENSITIVE_IMAGE_REDACTED]" src="[SENSITIVE_IMAGE_REDACTED]"/>`);
      }
    }

    return parts.join("");
  }

  window.__PL = window.__PL || {};
  window.__PL.DLP = {
    DLP_RULES,
    classifyField,
    sanitizeText,
    sanitizeElement,
    extractCleanStructure,
    getCleanHtml,
  };
})();
