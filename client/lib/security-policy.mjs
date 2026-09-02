// SecurityPolicyEngine (Phases 2 + 12) — one decision point for everything
// leaving the browser.
//
//   classifyPayload(payload, ctx) -> {
//     decision:        "ALLOW" | "SANITIZE" | "BLOCK" | "REQUIRE_APPROVAL"
//     classification:  "PUBLIC" | "INTERNAL" | "PERSONAL" | "SENSITIVE" | "SECRET"
//     findings:        [{ type, subtype, category?, confidence, risk, action,
//                         source, path, evidence /* masked, never raw */ }]
//     sanitized:       a copy of `payload` with offending substrings replaced
//     reasons:         string[]  (explainable, no raw values)
//   }
//
// Signals: PII (pii-rules.mjs), secrets (secret-scanner.mjs), the user's own
// profile values (exact match), canary tokens. Destination trust is supplied by
// the caller (url-risk.mjs in S4) and only tightens the decision.
//
// Policy (most-severe wins):
//   canary present                       -> BLOCK
//   secret finding, action "block"       -> BLOCK
//   RESTRICTED PII category               -> BLOCK
//   secret finding, action "require_...". -> REQUIRE_APPROVAL
//   destination low-trust + any PERSONAL+ -> REQUIRE_APPROVAL
//   any other PII / profile-value match  -> SANITIZE
//   nothing                              -> ALLOW

import { detectPII } from "./pii-rules.mjs";
import { scanSecrets } from "./secret-scanner.mjs";
import { findCanaries } from "./canary.mjs";
import { isRestrictedCategory } from "./sensitive-fields.mjs";

const SKIP_KEYS = new Set(["screenshot", "id", "tag", "type", "role", "state", "fillToken", "piiCategory", "action", "targetId"]);

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

function setByPath(root, path, value) {
  const parts = path.replace(/\[(\d+)\]/g, ".$1").split(".").filter(Boolean);
  let cur = root;
  for (let i = 0; i < parts.length - 1; i++) cur = cur[parts[i]];
  cur[parts[parts.length - 1]] = value;
}

function profileKeyCategory(key) {
  const s = String(key).toLowerCase();
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

const SEVERITY = { PUBLIC: 0, INTERNAL: 1, PERSONAL: 2, SENSITIVE: 3, SECRET: 4 };
const rank = (a, b) => (SEVERITY[a] >= SEVERITY[b] ? a : b);

const PERSONAL_CATS = new Set(["email", "phone-in", "dob", "name", "address"]);

/**
 * @param {object|string} payload
 * @param {{ profile?: Record<string,string>, destinationTrust?: number,
 *           destination?: string, minSecretConfidence?: number }} [ctx]
 *   destinationTrust in [0,1]; < 0.5 is "low trust" and tightens the decision.
 */
export function classifyPayload(payload, ctx = {}) {
  const { profile = {}, destinationTrust = 1, destination = null, minSecretConfidence = 0.5 } = ctx;
  const isStr = typeof payload === "string";
  const sanitized = isStr ? { _: payload } : JSON.parse(JSON.stringify(payload));
  const findings = [];
  let classification = "PUBLIC";

  const profileValues = Object.entries(profile)
    .filter(([, v]) => typeof v === "string" && v.trim().length >= 3)
    .map(([k, v]) => ({ cat: profileKeyCategory(k), value: v.trim() }));

  for (const { path, value } of walkStrings(sanitized)) {
    let repl = value;

    for (const c of findCanaries(repl)) {
      findings.push({ type: "canary", subtype: c.kind.toLowerCase(), confidence: 1, risk: 1, action: "block", source: "payload", path, evidence: `CANARY-${c.kind}-****` });
      classification = "SECRET";
      repl = repl.split(c.value).join("[BLOCKED:canary]");
    }

    for (const s of scanSecrets(repl, { source: "payload", minConfidence: minSecretConfidence })
      .sort((a, b) => b.start - a.start)) {
      findings.push({ type: "secret", subtype: s.subtype, confidence: s.confidence, risk: s.risk, action: s.action, source: "payload", path, evidence: s.evidence });
      classification = "SECRET";
      repl = repl.slice(0, s.start) + "[REDACTED:secret]" + repl.slice(s.end);
    }

    for (const pv of profileValues) {
      if (!repl.includes(pv.value)) continue;
      const restricted = isRestrictedCategory(pv.cat);
      findings.push({ type: "pii", subtype: "profile_value", category: pv.cat, confidence: 1, risk: restricted ? 0.99 : 0.7, action: restricted ? "block" : "sanitize", source: "profile", path, evidence: `[${pv.cat}]` });
      classification = rank(classification, restricted ? "SECRET" : "SENSITIVE");
      repl = repl.split(pv.value).join(`[REDACTED:${pv.cat}]`);
    }

    for (const h of [...detectPII(repl)].sort((a, b) => b.start - a.start)) {
      const restricted = isRestrictedCategory(h.category);
      findings.push({ type: "pii", subtype: "structural", category: h.category, confidence: h.confidence, risk: restricted ? 0.95 : 0.55, action: restricted ? "block" : "sanitize", source: "payload", path, evidence: `[${h.category}]` });
      classification = rank(classification, restricted ? "SENSITIVE" : PERSONAL_CATS.has(h.category) ? "PERSONAL" : "INTERNAL");
      repl = repl.slice(0, h.start) + `[REDACTED:${h.category}]` + repl.slice(h.end);
    }

    if (repl !== value) setByPath(sanitized, path, repl);
  }

  return decide({ findings, classification, sanitized: isStr ? sanitized._ : sanitized, destinationTrust, destination });
}

function decide(s) {
  const { findings, destinationTrust, destination } = s;
  const classification = s.classification;
  const reasons = [];
  const has = (pred) => findings.some(pred);

  let decision = "ALLOW";
  if (has((f) => f.type === "canary")) { decision = "BLOCK"; reasons.push("canary token in payload"); }
  else if (has((f) => f.type === "secret" && f.action === "block")) { decision = "BLOCK"; reasons.push(`credential material detected (${uniq(findings.filter((f) => f.type === "secret").map((f) => f.subtype)).join(", ")})`); }
  else if (has((f) => f.type === "pii" && f.action === "block")) { decision = "BLOCK"; reasons.push(`restricted PII: ${uniq(findings.filter((f) => f.action === "block" && f.type === "pii").map((f) => f.category)).join(", ")}`); }
  else if (has((f) => f.type === "secret" && f.action === "require_approval")) { decision = "REQUIRE_APPROVAL"; reasons.push("possible credential material — needs review"); }
  else if (destinationTrust < 0.5 && SEVERITY[classification] >= SEVERITY.PERSONAL) { decision = "REQUIRE_APPROVAL"; reasons.push(`personal data to a low-trust destination${destination ? ` (${destination})` : ""}`); }
  else if (findings.length) { decision = "SANITIZE"; reasons.push(`PII redacted: ${uniq(findings.filter((f) => f.type === "pii").map((f) => f.category)).join(", ")}`); }

  return {
    decision,
    classification,
    findings,
    reasons,
    sanitized: s.sanitizedStr ?? s.sanitized,
    summary: {
      counts: countBy(findings),
      classification,
      destination: destination || null,
      destinationTrust,
    },
  };
}

const uniq = (a) => [...new Set(a)].filter(Boolean);
function countBy(findings) {
  const c = {};
  for (const f of findings) {
    const k = f.type === "pii" ? `pii:${f.category}` : f.type === "secret" ? `secret:${f.subtype}` : f.type;
    c[k] = (c[k] || 0) + 1;
  }
  return c;
}

/**
 * Convenience for the egress choke point: apply the decision.
 * @returns {{ ok:boolean, blocked:boolean, needsApproval:boolean, payload:any, result:object }}
 */
export function enforceEgressPolicy(payload, ctx = {}) {
  const result = classifyPayload(payload, ctx);
  return {
    ok: result.decision === "ALLOW",
    blocked: result.decision === "BLOCK",
    needsApproval: result.decision === "REQUIRE_APPROVAL",
    payload: result.decision === "BLOCK" ? null : result.sanitized,
    result,
  };
}

export default { classifyPayload, enforceEgressPolicy };
