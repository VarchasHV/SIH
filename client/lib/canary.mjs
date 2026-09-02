// Canary / honeytoken mode (Phase 16).
//
// A test-only capability: seed uniquely-shaped synthetic secrets, then assert
// they are (a) detected, (b) redacted, (c) never present in any outbound
// payload. If a canary ever reaches the network, egress protection has a hole.
//
// Canary tokens are deliberately shaped so the secret scanner recognises them
// with confidence 1.0 and the policy engine always BLOCKs — see
// secret-scanner.mjs PATTERNS `canary`.

const CANARY_RE = /\bCANARY-(AWS|PII|TOKEN|SECRET)-[A-Za-z0-9]{4,}\b/;
const CANARY_RE_G = /\bCANARY-(AWS|PII|TOKEN|SECRET)-[A-Za-z0-9]{4,}\b/g;

export function isCanary(str) {
  return typeof str === "string" && CANARY_RE.test(str);
}

export function findCanaries(str) {
  if (typeof str !== "string") return [];
  return [...str.matchAll(CANARY_RE_G)].map((m) => ({ kind: m[1], value: m[0], start: m.index, end: m.index + m[0].length }));
}

function rand(n) {
  const chars = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
  let s = "";
  const arr = (typeof crypto !== "undefined" && crypto.getRandomValues)
    ? crypto.getRandomValues(new Uint32Array(n))
    : Array.from({ length: n }, () => Math.floor(Math.random() * 1e9));
  for (let i = 0; i < n; i++) s += chars[arr[i] % chars.length];
  return s;
}

/**
 * @param {string} [runId]  a tag so a specific test run's canaries are identifiable
 * @returns {{ aws:string, pii:string, token:string, secret:string, all:string[] }}
 */
export function generateCanaries(runId = "") {
  const tag = (runId ? runId.replace(/[^A-Za-z0-9]/g, "").slice(0, 4).toUpperCase() : "") + rand(8);
  const c = {
    aws: `CANARY-AWS-${tag}`,
    pii: `CANARY-PII-${tag}`,
    token: `CANARY-TOKEN-${tag}`,
    secret: `CANARY-SECRET-${tag}`,
  };
  c.all = [c.aws, c.pii, c.token, c.secret];
  return c;
}

/**
 * Assert none of `canaries` appear in the serialised payload.
 * @returns {{ ok:boolean, leaked:string[] }}
 */
export function assertNoCanaryEgress(payload, canaries) {
  const s = typeof payload === "string" ? payload : JSON.stringify(payload);
  const leaked = (canaries.all || canaries).filter((c) => s.includes(c));
  return { ok: leaked.length === 0, leaked };
}

export default { isCanary, findCanaries, generateCanaries, assertNoCanaryEgress };
