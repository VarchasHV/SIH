// Phase 17/19 — security lab + benchmark integrity.

import test from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";

const ROOT = new URL("..", import.meta.url).pathname;

test("gen-lab is deterministic and every attack page has a preventionLayer", () => {
  execFileSync("node", ["security-lab/gen-lab.mjs", "--seed", "20260902"], { cwd: ROOT, stdio: "pipe" });
  const a = readFileSync(`${ROOT}/security-lab/manifest.json`, "utf8");
  execFileSync("node", ["security-lab/gen-lab.mjs", "--seed", "20260902"], { cwd: ROOT, stdio: "pipe" });
  const b = readFileSync(`${ROOT}/security-lab/manifest.json`, "utf8");
  // only the generatedAt timestamp differs
  assert.equal(a.replace(/"generatedAt":\s*"[^"]+"/g, ""), b.replace(/"generatedAt":\s*"[^"]+"/g, ""));

  const m = JSON.parse(b);
  assert.ok(m.pages.length >= 12);
  for (const p of m.pages.filter((x) => x.isAttack)) {
    assert.ok(p.preventionLayer, `${p.slug} missing preventionLayer`);
  }
});

test("the benchmark: content + egress layers prevent 100%, zero control FP, zero canary leaks", () => {
  execFileSync("node", ["eval/security/run.mjs"], { cwd: ROOT, stdio: "pipe" });
  const r = JSON.parse(readFileSync(`${ROOT}/eval/security/security-lab.results.json`, "utf8"));

  assert.equal(r.totals.controlFalsePositiveRate, 0, "a control page was flagged as an attack");
  assert.equal(r.totals.canaryLeaks, 0, "a canary token reached the egress payload");
  assert.equal(r.totals.threatDetectionRate, 1, "an implemented threat type was missed");

  // built layers must be perfect; unbuilt layers are honestly 0
  const built = r.totals.attackPreventionForBuiltLayers.split("/").map(Number);
  assert.equal(built[0], built[1], `built-layer attack prevention is ${r.totals.attackPreventionForBuiltLayers}, expected N/N`);
  assert.ok(built[1] >= 4);
});

test("every attack page's synthetic payload is either not-ALLOWed or flagged MALICIOUS", () => {
  const r = JSON.parse(readFileSync(`${ROOT}/eval/security/security-lab.results.json`, "utf8"));
  for (const row of r.rows.filter((x) => x.isAttack && ["content", "egress"].includes(x.layer))) {
    assert.ok(row.policyDecision !== "ALLOW" || row.injection, `${row.slug} (${row.layer}) was ALLOWed without an injection flag`);
  }
});
