/**
 * Client-side Data Loss Prevention (DLP) - Heuristics & Tokenization Engine
 * Part of Privacy Lens Secure Form-Filling Agent.
 *
 * This module provides the regex rules, attribute scanners, and token mappings
 * used to identify and sanitize sensitive PII, credentials, 2FA/OTP codes, and
 * confidential media before sending the DOM structure to an external LLM.
 */

// ═══════════════════════════════════════════════════════════════════════════
// 1. PII RULE DICTIONARY & SEMANTIC TOKENS
// ═══════════════════════════════════════════════════════════════════════════

export const DLP_RULES = [
  // ── Authentication, Credentials & Secrets ──
  {
    category: "password",
    token: "[TOKEN_PASSWORD]",
    attrRegex: /\b(password|passwd|passcode|secret|pwd|pin|auth_key|api_key)\b/i,
    textRegex: null,
  },
  {
    category: "credential",
    token: "[TOKEN_CREDENTIAL]",
    attrRegex: /\b(credential|credentials|auth_token|token|session_token|access_token|security_key|auth_key|secret_key)\b/i,
    textRegex: /\b(Bearer\s+[A-Za-z0-9._~+/-]+=*|eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})\b/,
  },
  {
    category: "otp",
    token: "[TOKEN_OTP_2FA]",
    attrRegex: /\b(otp|2fa|mfa|totp|auth_code|verification_code|one_time_code|sms_code)\b/i,
    textRegex: /(?:\b(?:otp|2fa|code|verification|totp)[^0-9\n]{0,15}?)\b\d{4,8}\b/i,
  },
  {
    category: "ssh_key",
    token: "[TOKEN_SSH_KEY]",
    attrRegex: /\b(ssh[_\s]?key|private[_\s]?key|id_rsa|id_ed25519)\b/i,
    textRegex: /-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----/,
  },
  {
    category: "api_key",
    token: "[TOKEN_API_KEY]",
    attrRegex: /\b(api[_\s]?key|apikey|secret[_\s]?key|client[_\s]?secret)\b/i,
    textRegex: /\b(?:sk-[a-zA-Z0-9]{20,}|ghp_[a-zA-Z0-9]{20,}|AKIA[0-9A-Z]{16})\b/,
  },

  // ── Government & National Identifiers (Ordered longest first) ──
  {
    category: "ssn",
    token: "[TOKEN_SSN]",
    attrRegex: /\b(ssn|social[_\s]?security|soc[_\s]?sec|national[_\s]?insurance|sin[_\s]?number)\b/i,
    textRegex: /\b\d{3}-\d{2}-\d{4}\b/,
  },
  {
    category: "gstin",
    token: "[TOKEN_GSTIN]",
    attrRegex: /\b(gstin|gst[_\s]?num(ber)?|gst[_\s]?no)\b/i,
    textRegex: /\b\d{2}[A-Z]{5}\d{4}[A-Z][A-Z0-9]Z[A-Z0-9]\b/,
  },
  {
    category: "passport",
    token: "[TOKEN_PASSPORT]",
    attrRegex: /\b(passport|passport[_\s]?no|passport[_\s]?num(ber)?)\b/i,
    textRegex: /\b[A-PR-WYa-pr-wy][1-9]\d\s?\d{4}[1-9]\b/,
  },
  {
    category: "pan",
    token: "[TOKEN_PAN]",
    attrRegex: /\b(pan[_\s]?card|pan[_\s]?number|permanent[_\s]?account)\b|(?<![a-z])pan(?![a-z])/i,
    textRegex: /\b[A-Z]{5}[0-9]{4}[A-Z]\b/,
  },
  {
    category: "driver_license",
    token: "[TOKEN_DRIVER_LICENSE]",
    attrRegex: /\b(driver[_\s]?license|drivers[_\s]?license|driving[_\s]?licen[sc]e|dl[_\s]?num(ber)?|licen[sc]e[_\s]?no)\b/i,
    textRegex: null,
  },
  {
    category: "voter_id",
    token: "[TOKEN_VOTER_ID]",
    attrRegex: /\b(voter[_\s]?id|epic[_\s]?no|electoral[_\s]?id)\b/i,
    textRegex: /\b[A-Z]{3}[0-9]{7}\b/,
  },

  // ── Financial: Cards & Banking ──
  {
    category: "credit_card",
    token: "[TOKEN_CREDIT_CARD]",
    attrRegex: /\b(card[_\s]?num(ber)?|credit[_\s]?card|debit[_\s]?card|cc[_\s]?num(ber)?|cardno|pan[_\s]?num|cc[_\s]?number)\b/i,
    textRegex: /(?<!\d)\b(?:\d[\s-]?){13,19}\b(?!\d)/,
  },
  {
    category: "aadhaar",
    token: "[TOKEN_AADHAAR]",
    attrRegex: /\b(aadhaar|aadhar|uidai|uid[_\s]?number)\b/i,
    textRegex: /(?<!\d)\b\d{4}[\s-]?\d{4}[\s-]?\d{4}\b(?!\d)/,
  },
  {
    category: "card_expiry",
    token: "[TOKEN_CARD_EXPIRY]",
    attrRegex: /\b(card[_\s]?exp(ir(y|ation))?|exp[_\s]?date|cc[_\s]?exp|ccexp)\b/i,
    textRegex: /\b(0[1-9]|1[0-2])[/-](\d{2}|\d{4})\b/,
  },
  {
    category: "card_holder",
    token: "[TOKEN_CARD_HOLDER]",
    attrRegex: /\b(card[_\s]?holder|card[_\s]?user|name[_\s]?on[_\s]?card|cc[_\s]?name)\b/i,
    textRegex: null,
  },
  {
    category: "cvv",
    token: "[TOKEN_CVV]",
    attrRegex: /\b(cvv\d?|cvc\d?|security[_\s]?code|card[_\s]?sec|csc|card[_\s]?verification)\b/i,
    textRegex: /(?<![\d-])\b\d{3,4}\b(?![\d-])/,
  },
  {
    category: "bank_account",
    token: "[TOKEN_BANK_ACCOUNT]",
    attrRegex: /\b(bank[_\s]?account|account[_\s]?no|account[_\s]?number|routing[_\s]?num(ber)?|iban|swift|bic|aba[_\s]?routing)\b/i,
    textRegex: /\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b|\b\d{9,18}\b/,
  },
  {
    category: "ifsc",
    token: "[TOKEN_IFSC]",
    attrRegex: /\b(ifsc|ifsc[_\s]?code)\b/i,
    textRegex: /\b[A-Z]{4}0[A-Z0-9]{6}\b/,
  },
  {
    category: "upi",
    token: "[TOKEN_UPI_VPA]",
    attrRegex: /\b(upi|vpa|upi[_\s]?id|pay[_\s]?to)\b/i,
    textRegex: /\b[a-zA-Z0-9.\-_]{2,49}@(okhdfcbank|oksbi|okaxis|okicici|paytm|ybl|upi|sbi|icici|axisbank|gpay)\b/i,
  },
  {
    category: "income",
    token: "[TOKEN_INCOME]",
    attrRegex: /\b(income|salary|annual[_\s]?income|monthly[_\s]?income|compensation|net[_\s]?worth)\b/i,
    textRegex: null,
  },

  // ── Contact & Location ──
  {
    category: "email",
    token: "[TOKEN_EMAIL]",
    attrRegex: /\b(email|e-mail|mail[_\s]?addr(ess)?)\b/i,
    textRegex: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/,
  },
  {
    category: "phone",
    token: "[TOKEN_PHONE]",
    attrRegex: /\b(phone|mobile|cell|telephone|tel[_\s]?no|contact[_\s]?no|fax|home[_\s]?phone|work[_\s]?phone)\b/i,
    textRegex: /(?:\+?\d{1,3}[ -]?)?\(?\d{3}\)?[ -]?\d{3}[ -]?\d{4}|\b(?:\+?91[\s-]?)?[6-9]\d{9}\b/,
  },
  {
    category: "address",
    token: "[TOKEN_ADDRESS]",
    attrRegex: /\b(address|street|addr1|addr2|residence|street[_\s]?address|address[_\s]?line)\b/i,
    textRegex: null,
  },
  {
    category: "zip_code",
    token: "[TOKEN_ZIP_CODE]",
    attrRegex: /\b(zip|zip[_\s]?code|postal|postal[_\s]?code|pincode|pin[_\s]?code|postcode)\b/i,
    textRegex: /\b\d{5}(?:-\d{4})?\b|\b\d{6}\b/,
  },
  {
    category: "city",
    token: "[TOKEN_CITY]",
    attrRegex: /\b(city|town|municipality)\b/i,
    textRegex: null,
  },
  {
    category: "state",
    token: "[TOKEN_STATE]",
    attrRegex: /\b(state|province|region|state[_\s]?province)\b/i,
    textRegex: null,
  },
  {
    category: "country",
    token: "[TOKEN_COUNTRY]",
    attrRegex: /\b(country|nation|country[_\s]?code)\b/i,
    textRegex: null,
  },

  // ── Personal Demographics ──
  {
    category: "dob",
    token: "[TOKEN_DOB]",
    attrRegex: /\b(dob|birth[_\s]?date|date[_\s]?of[_\s]?birth|bday|born[_\s]?on)\b/i,
    textRegex: /\b(0?[1-9]|[12]\d|3[01])[/\-.](0?[1-9]|1[0-2])[/\-.](\d{4})\b/,
  },
  {
    category: "first_name",
    token: "[TOKEN_FIRST_NAME]",
    attrRegex: /\b(first[_\s]?name|fname|given[_\s]?name|forename)\b/i,
    textRegex: null,
  },
  {
    category: "middle_name",
    token: "[TOKEN_MIDDLE_NAME]",
    attrRegex: /\b(middle[_\s]?name|middle[_\s]?initial|mname|mid[_\s]?init)\b/i,
    textRegex: null,
  },
  {
    category: "last_name",
    token: "[TOKEN_LAST_NAME]",
    attrRegex: /\b(last[_\s]?name|lname|surname|family[_\s]?name)\b/i,
    textRegex: null,
  },
  {
    category: "full_name",
    token: "[TOKEN_FULL_NAME]",
    attrRegex: /\b(full[_\s]?name|your[_\s]?name|contact[_\s]?name|applicant[_\s]?name)\b/i,
    textRegex: null,
  },
  {
    category: "gender",
    token: "[TOKEN_GENDER]",
    attrRegex: /\b(gender|sex|user[_\s]?gender)\b/i,
    textRegex: null,
  },

  // ── Employment & Digital ──
  {
    category: "company",
    token: "[TOKEN_COMPANY]",
    attrRegex: /\b(company|organization|employer|workplace|company[_\s]?name)\b/i,
    textRegex: null,
  },
  {
    category: "position",
    token: "[TOKEN_POSITION]",
    attrRegex: /\b(position|job[_\s]?title|occupation|designation|role)\b/i,
    textRegex: null,
  },
  {
    category: "website",
    token: "[TOKEN_WEBSITE]",
    attrRegex: /\b(website|web[_\s]?site|homepage|url)\b/i,
    textRegex: /\bhttps?:\/\/[^\s/$.?#].[^\s]*\b/i,
  },
  {
    category: "username",
    token: "[TOKEN_USERNAME]",
    attrRegex: /\b(username|user[_\s]?id|login[_\s]?id|user[_\s]?name|userid|loginid)\b/i,
    textRegex: null,
  },
];

// ═══════════════════════════════════════════════════════════════════════════
// 2. MEDIA & IMAGE QUARANTINE HEURISTICS
// ═══════════════════════════════════════════════════════════════════════════

export const SENSITIVE_MEDIA_REGEX = /\b(upload[_\s]?(id|doc|photo|file)|passport|driver[_\s]?license|govt[_\s]?id|identity|aadhaar|ssn|id[_\s]?card|proof[_\s]?of[_\s]?id|selfie|signature|profile[_\s]?photo)\b/i;

export const GENERIC_TEXT_PII_REGEX = [
  /-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----/g,
  /\b(?:Bearer\s+[A-Za-z0-9._~+/-]+=*|sk-[a-zA-Z0-9]{20,}|ghp_[a-zA-Z0-9]{20,}|AKIA[0-9A-Z]{16})\b/g,
  /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g, // Emails
  /\b\d{3}-\d{2}-\d{4}\b/g,                               // SSNs
  /(?<!\d)\b(?:\d[\s-]?){13,19}\b(?!\d)/g,                // Card numbers
  /(?<!\d)\b\d{4}\s?\d{4}\s?\d{4}\b(?!\d)/g,              // Aadhaar
  /\b[A-Z]{5}\d{4}[A-Z]\b/g,                             // PAN
  /(?<!\w)(?:\+?91[\s-]?)?[6-9]\d{9}\b/g,                // Phone numbers
];

// ═══════════════════════════════════════════════════════════════════════════
// 3. HEURISTICS CLASSIFICATION FUNCTIONS
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Checks an element's attributes and signals to determine if it is a sensitive/credential field.
 * Deterministically treats autofilled and credential fields as always sensitive.
 *
 * @param {Object} signals - Extracted field signals
 * @returns {{isSensitive: boolean, category: string|null, token: string|null, alwaysRedact?: boolean, isAutofilled?: boolean}}
 */
export function classifyFieldHeuristics(signals = {}) {
  const isAutofill = !!(signals.isAutofilled || signals.autofilled);
  const type = (signals.type || "").toLowerCase();
  const auto = (signals.autocomplete || "").toLowerCase();

  // 1. Deterministic always-redact for credentials and autofilled fields
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
    return {
      isSensitive: true,
      category: cat,
      token: tok,
      alwaysRedact: true,
      isAutofilled: isAutofill,
    };
  }

  if (type === "email") {
    return { isSensitive: true, category: "email", token: "[TOKEN_EMAIL]" };
  }
  if (type === "tel") {
    return { isSensitive: true, category: "phone", token: "[TOKEN_PHONE]" };
  }

  const combinedAttributes = [
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
    if (rule.attrRegex && rule.attrRegex.test(combinedAttributes)) {
      const isCred = ["password", "credential", "otp", "ssh_key", "api_key", "credit_card", "cvv", "ssn", "aadhaar", "pan"].includes(rule.category);
      return {
        isSensitive: true,
        category: rule.category,
        token: rule.token,
        alwaysRedact: isCred,
      };
    }
  }

  return { isSensitive: false, category: null, token: null };
}

/**
 * Checks a paragraph or text node for sensitive formatted strings (e.g. emails,
 * account numbers, card numbers, OTPs, credentials, SSH keys) and redacts them.
 *
 * @param {string} text
 * @returns {string} Sanitized text
 */
export function sanitizeParagraphText(text) {
  if (!text || typeof text !== "string") return "";
  let sanitized = text;

  // Check specific rules with text regexes
  for (const rule of DLP_RULES) {
    if (rule.textRegex) {
      sanitized = sanitized.replace(new RegExp(rule.textRegex, "g"), rule.token);
    }
  }

  // Fallback generic scanner
  for (const re of GENERIC_TEXT_PII_REGEX) {
    sanitized = sanitized.replace(re, "[TEXT_REDACTED]");
  }

  return sanitized;
}

/**
 * Sanitizes a free-form task goal typed by the user before it is transmitted to
 * the remote VLM. The goal is *not* structured input we control, so users can
 * (and do) paste literal PII into it — e.g. "Fill the form with John Smith,
 * john@example.com, Aadhaar 1234 5678 9012". This is a DLP egress point and must
 * be scrubbed like any other.
 *
 * Strategy:
 *  1. Redact formatted PII (emails, phones, Aadhaar, PAN, cards, …) via the
 *     shared paragraph scanner.
 *  2. Redact value-carrying clauses. A goal only needs to express *intent*
 *     ("fill the form using my local profile"); any concrete value that follows
 *     a filler verb / assignment / quote is a literal the model must never see.
 *  3. Hard length cap so a goal can't smuggle a large blob past the scanners.
 *
 * @param {string} goal
 * @returns {{ text: string, redacted: boolean, hits: string[] }}
 */
export function sanitizeTaskGoal(goal) {
  const hits = [];
  if (!goal || typeof goal !== "string") {
    return { text: "", redacted: false, hits };
  }

  let text = goal.replace(/\s+/g, " ").trim().slice(0, 600);
  const before = text;

  // 1. Formatted PII (emails, SSN, cards, Aadhaar, PAN, phones, …)
  const afterPii = sanitizeParagraphText(text);
  if (afterPii !== text) hits.push("formatted-pii");
  text = afterPii;

  // 2. Quoted literals — "John Smith", 'Flat 4B, MG Road'
  text = text.replace(/(['"“”‘’])(.{1,120}?)\1/g, (_m) => {
    hits.push("quoted-literal");
    return "[TOKEN_VALUE]";
  });

  // 3. Values after a filler verb or assignment.
  //    "fill name with John Smith" / "set email = x" / "DOB: 01/01/1990"
  //    Capture up to the next clause boundary (comma / "and" / ";" / end).
  const valueClause =
    /\b(?:with|using|as|to|is|=|:)\s+(?!(?:my|the|a|an|your|this|that|it|local|profile|saved|stored|filled|empty|blank|complete|completed|done|possible|shown|visible|required|optional|needed)\b)([^,;]+?)(?=(?:,|;|\.|\band\b|\bthen\b|$))/gi;
  text = text.replace(valueClause, (m, val) => {
    // keep the connective word ("with" / "to" / ":"), redact only the value
    const connective = m.slice(0, m.length - val.length);
    hits.push("value-clause");
    return `${connective}[TOKEN_VALUE]`;
  });

  // Tidy spacing left by clause-boundary lookaheads (e.g. "]and" -> "] and").
  text = text.replace(/\](?=[A-Za-z0-9])/g, "] ").replace(/\s+/g, " ").trim();

  const redacted = text !== before || hits.length > 0;
  return { text, redacted, hits: [...new Set(hits)] };
}

/**
 * Checks if an image or file upload is sensitive based on attributes and nearby text.
 *
 * @param {Object} mediaSignals
 * @returns {boolean}
 */
export function isSensitiveMedia(mediaSignals = {}) {
  const combined = [
    mediaSignals.src || "",
    mediaSignals.alt || "",
    mediaSignals.title || "",
    mediaSignals.nearbyText || "",
  ].join(" ");

  if ((mediaSignals.src && mediaSignals.src.startsWith("data:")) || SENSITIVE_MEDIA_REGEX.test(combined)) {
    return true;
  }
  return false;
}

export default {
  DLP_RULES,
  SENSITIVE_MEDIA_REGEX,
  GENERIC_TEXT_PII_REGEX,
  classifyFieldHeuristics,
  sanitizeParagraphText,
  isSensitiveMedia,
};
