// Pre-egress privacy gate — thin wrapper over the SecurityPolicyEngine.
//
// History: this file was the Phase-10 gate. In the security cycle its logic
// moved into client/lib/security-policy.mjs (which also does secret + canary
// detection and a full ALLOW/SANITIZE/BLOCK/REQUIRE_APPROVAL decision).
// assertNoSensitivePayload() is kept as the stable, narrow API that
// background.js and tests already use — it forwards to classifyPayload().

import { classifyPayload } from "./security-policy.mjs";

/**
 * @param {object} payload   the exact object about to be JSON-serialized to the server
 * @param {{ profile?: Record<string,string>, minConfidence?: number }} [opts]
 * @returns {{ ok:boolean, blocked:boolean, findings:Array, sanitized:object, summary:object }}
 *   findings: [{ category, source:"profile"|"detector", path, count }] — NO raw values.
 */
export function assertNoSensitivePayload(payload, opts = {}) {
  const res = classifyPayload(payload, {
    profile: opts.profile || {},
    minSecretConfidence: opts.minConfidence ?? 0.5,
  });

  const findings = res.findings.map((f) => ({
    category: f.category || f.subtype || f.type,
    source: f.source === "profile" ? "profile" : "detector",
    path: f.path,
    count: 1,
  }));
  const blocked = res.decision === "BLOCK";
  const byCategory = {};
  for (const f of findings) byCategory[f.category] = (byCategory[f.category] || 0) + f.count;

  return {
    ok: findings.length === 0,
    blocked,
    decision: res.decision,
    classification: res.classification,
    findings,
    sanitized: res.sanitized,
    summary: { totalFindings: findings.length, byCategory, restrictedHit: blocked, reasons: res.reasons },
  };
}

export default { assertNoSensitivePayload };
