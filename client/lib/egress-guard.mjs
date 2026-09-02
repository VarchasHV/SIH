// Phase 10 — automated pre-egress privacy gate.
//
// Nothing goes to the server until assertNoSensitivePayload() has walked the
// EXACT bytes about to be sent and confirmed they carry no raw PII. Two signals:
//
//   1. exact-match against the user's own profile values (the strongest signal —
//      if "Aditi Sharma" or "9876543210" appears verbatim in the payload, that
//      is a leak, full stop);
//   2. structural PII detection (detectPII from pii-rules.mjs) over every string
//      in the payload, so PII that isn't in the profile (a name on the page, an
//      order number that is really an Aadhaar) is still caught.
//
// On a hit: the payload is sanitized in place (offending substrings replaced
// with [REDACTED:<category>]) and a metadata-only finding list is returned —
// the actual values are NEVER put in the finding, the log, or an event.
// A RESTRICTED category (password / aadhaar / PAN / card / bank / SSN) is a hard
// block; everything else is redacted-and-continue.

import { detectPII } from "./pii-rules.mjs";

const RESTRICTED = new Set(["password", "aadhaar", "pan", "credit-card", "ssn", "cvv", "bank-account", "ifsc"]);

// Fields whose string content is structural, not user data — skip them.
const SKIP_KEYS = new Set(["screenshot", "id", "tag", "type", "role", "state", "fillToken", "piiCategory", "action", "targetId", "url"]);

/** Collect { path, value } for every non-trivial string in an object graph. */
function* walkStrings(node, path = "") {
  if (node == null) return;
  if (typeof node === "string") {
    if (node.length >= 3) yield { path, value: node };
    return;
  }
  if (Array.isArray(node)) {
    for (let i = 0; i < node.length; i++) yield* walkStrings(node[i], `${path}[${i}]`);
    return;
  }
  if (typeof node === "object") {
    for (const [k, v] of Object.entries(node)) {
      if (SKIP_KEYS.has(k)) continue;
      yield* walkStrings(v, path ? `${path}.${k}` : k);
    }
  }
}

/** Escape a string for use as a literal in a RegExp. */
const reEscape = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

/**
 * @param {object} payload           the exact object about to be JSON-serialized to the server
 * @param {object} [opts]
 * @param {Record<string,string>} [opts.profile]  the user's local profile (real values)
 * @param {number} [opts.minConfidence]           detectPII threshold (default 0.5)
 * @returns {{ ok:boolean, blocked:boolean, findings:Array, sanitized:object, summary:object }}
 *   findings: [{ category, source:"profile"|"detector", path, count }]  — NO values.
 */
export function assertNoSensitivePayload(payload, opts = {}) {
  const { profile = {}, minConfidence = 0.5 } = opts;
  const findings = [];
  let blocked = false;

  // deep clone so the caller's object is only replaced if we return sanitized
  const sanitized = JSON.parse(JSON.stringify(payload));

  const profileValues = Object.values(profile)
    .filter((v) => typeof v === "string" && v.trim().length >= 3)
    .map((v) => v.trim());

  for (const { path, value } of walkStrings(sanitized)) {
    let replacement = value;

    // 1. exact profile-value match
    for (const pv of profileValues) {
      if (replacement.includes(pv)) {
        const cat = keyFor(profile, pv) || "profile-value";
        findings.push({ category: cat, source: "profile", path, count: countOccurrences(replacement, pv) });
        if (RESTRICTED.has(cat)) blocked = true;
        replacement = replacement.split(pv).join(`[REDACTED:${cat}]`);
      }
    }

    // 2. structural detection
    const hits = detectPII(replacement, { minConfidence });
    if (hits.length) {
      // redact right-to-left so offsets stay valid
      for (const h of [...hits].sort((a, b) => b.start - a.start)) {
        findings.push({ category: h.category, source: "detector", path, count: 1 });
        if (RESTRICTED.has(h.category)) blocked = true;
        replacement = replacement.slice(0, h.start) + `[REDACTED:${h.category}]` + replacement.slice(h.end);
      }
    }

    if (replacement !== value) setByPath(sanitized, path, replacement);
  }

  const byCategory = {};
  for (const f of findings) byCategory[f.category] = (byCategory[f.category] || 0) + f.count;

  return {
    ok: findings.length === 0,
    blocked,
    findings,
    sanitized,
    summary: { totalFindings: findings.reduce((n, f) => n + f.count, 0), byCategory, restrictedHit: blocked },
  };
}

function keyFor(profile, value) {
  for (const [k, v] of Object.entries(profile)) if (v === value) return normalizeKey(k);
  return null;
}
function normalizeKey(k) {
  const s = String(k).toLowerCase();
  if (/aadhaar|aadhar|uid/.test(s)) return "aadhaar";
  if (/\bpan\b/.test(s)) return "pan";
  if (/card/.test(s)) return "credit-card";
  if (/ssn|social security/.test(s)) return "ssn";
  if (/password|passcode/.test(s)) return "password";
  if (/ifsc/.test(s)) return "ifsc";
  if (/account|bank/.test(s)) return "bank-account";
  if (/phone|mobile/.test(s)) return "phone-in";
  if (/email/.test(s)) return "email";
  if (/name/.test(s)) return "name";
  if (/address/.test(s)) return "address";
  if (/dob|birth/.test(s)) return "dob";
  return s.replace(/[^a-z0-9]+/g, "-");
}
function countOccurrences(haystack, needle) {
  if (!needle) return 0;
  let n = 0, i = 0;
  while ((i = haystack.indexOf(needle, i)) !== -1) { n++; i += needle.length; }
  return n;
}
function setByPath(root, path, value) {
  const parts = path.replace(/\[(\d+)\]/g, ".$1").split(".").filter(Boolean);
  let cur = root;
  for (let i = 0; i < parts.length - 1; i++) cur = cur[parts[i]];
  cur[parts[parts.length - 1]] = value;
}

export default { assertNoSensitivePayload };
