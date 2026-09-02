// Phase 16 — canary / honeytoken mode.

import test from "node:test";
import assert from "node:assert/strict";
import { generateCanaries, isCanary, findCanaries, assertNoCanaryEgress } from "../client/lib/canary.mjs";
import { scanSecrets } from "../client/lib/secret-scanner.mjs";
import { classifyPayload } from "../client/lib/security-policy.mjs";

test("generateCanaries produces 4 distinct, recognisable tokens", () => {
  const c = generateCanaries("run42");
  assert.equal(c.all.length, 4);
  for (const t of c.all) {
    assert.ok(isCanary(t), t);
    assert.match(t, /^CANARY-(AWS|PII|TOKEN|SECRET)-/);
  }
  assert.notEqual(generateCanaries().aws, generateCanaries().aws);
});

test("the secret scanner flags a canary at confidence 1.0 / action block", () => {
  const c = generateCanaries();
  const [f] = scanSecrets(`here is the key: ${c.aws}`);
  assert.ok(f);
  assert.equal(f.subtype, "canary");
  assert.equal(f.confidence, 1);
  assert.equal(f.action, "block");
});

test("the policy engine BLOCKs any payload containing a canary", () => {
  const c = generateCanaries();
  for (const t of c.all) {
    const r = classifyPayload({ deep: { nested: [`value ${t}`] } }, {});
    assert.equal(r.decision, "BLOCK", t);
  }
});

test("assertNoCanaryEgress detects a leak and names which canary leaked", () => {
  const c = generateCanaries();
  const clean = assertNoCanaryEgress({ a: "nothing here" }, c);
  assert.deepEqual([clean.ok, clean.leaked.length], [true, 0]);

  const leak = assertNoCanaryEgress({ a: `oops ${c.pii} slipped through` }, c);
  assert.equal(leak.ok, false);
  assert.deepEqual(leak.leaked, [c.pii]);
});

test("findCanaries returns positions + kind", () => {
  const c = generateCanaries();
  const hits = findCanaries(`x ${c.token} y ${c.aws} z`);
  assert.equal(hits.length, 2);
  assert.deepEqual(hits.map((h) => h.kind).sort(), ["AWS", "TOKEN"]);
});
