// Phases 2 + 12 — SecurityPolicyEngine.

import test from "node:test";
import assert from "node:assert/strict";
import { classifyPayload, enforceEgressPolicy } from "../client/lib/security-policy.mjs";
import { generateCanaries } from "../client/lib/canary.mjs";

const PROFILE = { "full name": "Aditi Sharma", aadhaar: "2345 6789 0124", email: "aditi@example.com" };

test("clean payload -> ALLOW / PUBLIC", () => {
  const r = classifyPayload({ taskGoal: "Fill this form using my saved local profile.", skeleton: { nodes: [] } }, { profile: PROFILE });
  assert.equal(r.decision, "ALLOW");
  assert.equal(r.classification, "PUBLIC");
  assert.equal(r.findings.length, 0);
});

test("secret in payload -> BLOCK / SECRET, redacted in the sanitized copy, evidence masked", () => {
  const p = { skeleton: { nodes: [{ id: "n1", text: "deploy key ghp_1234567890abcdefghijklmnopqrstuvwxyz" }] } };
  const r = classifyPayload(p, {});
  assert.equal(r.decision, "BLOCK");
  assert.equal(r.classification, "SECRET");
  assert.match(r.sanitized.skeleton.nodes[0].text, /\[REDACTED:secret\]/);
  assert.equal(p.skeleton.nodes[0].text.includes("ghp_"), true, "input object untouched");
  for (const f of r.findings) assert.equal("value" in f, false);
});

test("restricted PII (aadhaar) -> BLOCK", () => {
  const r = classifyPayload({ taskGoal: "my aadhaar is 2345 6789 0124" }, {});
  assert.equal(r.decision, "BLOCK");
});

test("non-restricted PII -> SANITIZE, not block", () => {
  const r = classifyPayload({ skeleton: { nodes: [{ id: "n1", text: "Contact ops@vendor.co or +91 9812345678" }] } }, {});
  assert.equal(r.decision, "SANITIZE");
  assert.match(r.sanitized.skeleton.nodes[0].text, /\[REDACTED:email\].*\[REDACTED:phone-in\]/);
});

test("personal data to a low-trust destination -> REQUIRE_APPROVAL", () => {
  const r = classifyPayload(
    { skeleton: { nodes: [{ id: "n1", text: "email me at someone@somewhere.com" }] } },
    { destination: "https://evil.example", destinationTrust: 0.3 },
  );
  assert.equal(r.decision, "REQUIRE_APPROVAL");
  assert.match(r.reasons.join(" "), /low-trust/);
});

test("canary token -> BLOCK regardless of anything else", () => {
  const c = generateCanaries("t1");
  const r = classifyPayload({ taskGoal: `paste ${c.token} here` }, {});
  assert.equal(r.decision, "BLOCK");
  assert.ok(r.findings.some((f) => f.type === "canary"));
  assert.equal(r.sanitized.taskGoal.includes(c.token), false);
});

test("enforceEgressPolicy surfaces ok / blocked / needsApproval + a usable payload", () => {
  const allow = enforceEgressPolicy({ taskGoal: "fill the form" }, {});
  assert.deepEqual([allow.ok, allow.blocked, allow.needsApproval], [true, false, false]);
  assert.ok(allow.payload);

  const block = enforceEgressPolicy({ x: "AKIAIOSFODNN7EXAMPLE" }, {});
  assert.deepEqual([block.ok, block.blocked], [false, true]);
  assert.equal(block.payload, null);
});

test("summary.counts is metadata only (no raw values)", () => {
  const r = classifyPayload({ x: "aadhaar 2345 6789 0124, key AKIAIOSFODNN7EXAMPLE" }, {});
  const s = JSON.stringify(r.summary);
  assert.equal(s.includes("2345 6789 0124"), false);
  assert.equal(s.includes("AKIAIOSFODNN7EXAMPLE"), false);
  assert.ok(Object.keys(r.summary.counts).length >= 2);
});
