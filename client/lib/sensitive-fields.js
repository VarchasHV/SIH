// Single source of truth for "is this field sensitive?" across the entire
// Privacy Lens pipeline. Every call site — skeleton filtering, executor guard,
// agent-bridge profile sanitisation, and screenshot redaction — MUST use these
// definitions so there is zero drift.
//
// Dual-mode module:
//   • Content scripts (MV3, no ESM): loaded first via manifest.json
//     content_scripts, attaches to window.__PL.
//   • Service worker / offscreen (ESM): imported via `import { … }`.

// ═══════════════════════════════════════════════════════════════════════════
// SENSITIVE_PATTERNS — field-name / attribute regex
// ═══════════════════════════════════════════════════════════════════════════
// Every token ≤ 5 chars or that is a common English substring gets \b word
// boundaries to avoid false-positives (e.g. "Company" matching `pan`).

const SENSITIVE_PATTERNS = /password|passcode|passwd|aadhaar|aadhar|uidai|\bpan\b|pannumber|pancard|\bssn\b|social[_\s]?security|credit[_\s]?card|debit[_\s]?card|card[_\s]?num|\bcvv\b|\bcvc\b|card[_\s]?expir|\bbank\b|account[_\s]?no|routing|\bifsc\b|\bupi\b|passport|govt[_\s]?id|national[_\s]?id|voter[_\s]?id|\bepic\b|\bdriver\b|\blicense\b/i;

// ═══════════════════════════════════════════════════════════════════════════
// CENSORED_CATEGORIES — the canonical set of PII category strings that must
// NEVER leave the client (not in the skeleton, not filled, not in the
// screenshot label).
// ═══════════════════════════════════════════════════════════════════════════

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
  "sensitive",
]);

// ═══════════════════════════════════════════════════════════════════════════
// Helpers
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Returns true if `cat` is a censored/sensitive PII category.
 * Checks both the canonical set and the regex (for ad-hoc category strings
 * that aren't in the set but contain sensitive keywords).
 */
function isSensitiveCategory(cat) {
  if (!cat) return false;
  return CENSORED_CATEGORIES.has(cat) || SENSITIVE_PATTERNS.test(cat);
}

/**
 * Returns true if a concatenated field-text string (name + id + placeholder
 * + aria-label + type + label) matches the sensitive-field regex.
 */
function isSensitiveText(text) {
  if (!text) return false;
  return SENSITIVE_PATTERNS.test(text);
}

// ═══════════════════════════════════════════════════════════════════════════
// Dual-mode export
// ═══════════════════════════════════════════════════════════════════════════

// Content-script path: attach to window.__PL (available when loaded via
// manifest.json content_scripts before skeleton.js / executor.js / etc.)
if (typeof window !== "undefined") {
  window.__PL = window.__PL || {};
  window.__PL.SENSITIVE_PATTERNS = SENSITIVE_PATTERNS;
  window.__PL.CENSORED_CATEGORIES = CENSORED_CATEGORIES;
  window.__PL.isSensitiveCategory = isSensitiveCategory;
  window.__PL.isSensitiveText = isSensitiveText;
}

// ESM path: for background.js (service worker) and offscreen.js
export { SENSITIVE_PATTERNS, CENSORED_CATEGORIES, isSensitiveCategory, isSensitiveText };
