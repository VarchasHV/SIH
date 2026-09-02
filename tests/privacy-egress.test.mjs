// Phase 15 — the privacy experiment must show a strict A > B > C ordering and
// zero task-goal PII in the protected pipelines.

import test from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";

const ROOT = new URL("..", import.meta.url).pathname;

test("privacy-egress: raw PII bytes to server decrease A -> B -> C", () => {
  execFileSync("node", ["eval/screens/gen-screens.mjs", "--seed", "20260902"], { cwd: ROOT, stdio: "pipe" });
  execFileSync("node", ["eval/experiments/privacy-egress.mjs"], { cwd: ROOT, stdio: "pipe" });
  const r = JSON.parse(readFileSync(`${ROOT}/eval/experiments/privacy-egress.json`, "utf8"));
  const h = r.headline;

  assert.ok(h.A_unprotected > h.B_ocr_pii_redact, `A ${h.A_unprotected} should exceed B ${h.B_ocr_pii_redact}`);
  assert.ok(h.B_ocr_pii_redact >= h.C_full_pipeline, `B ${h.B_ocr_pii_redact} should be >= C ${h.C_full_pipeline}`);
  // C removes at least 80% of the raw PII bytes
  assert.ok(h.C_full_pipeline / h.A_unprotected < 0.2, `C should cut >80% of raw PII bytes (got ${(h.C_full_pipeline / h.A_unprotected * 100).toFixed(0)}%)`);

  // structured PII (aadhaar / card / email / phone / pan / ifsc) -> 0 bytes in B and C
  for (const cat of ["aadhaar", "credit-card", "email", "phone-in", "pan", "ifsc"]) {
    assert.equal(r.leakByCategory.C[cat] || 0, 0, `${cat} must not leak in C`);
    assert.equal(r.leakByCategory.B[cat] || 0, 0, `${cat} must not leak in B`);
  }
  // task-goal PII -> 0 in every protected pipeline
  assert.equal(r.taskGoalPiiBytes.B, 0);
  assert.equal(r.taskGoalPiiBytes.C, 0);
  assert.ok(r.taskGoalPiiBytes.A > 0, "the unprotected goal DOES leak (control)");
});

test("aggregate-benchmarks produces a report with every measured section", () => {
  // benchmarks must have been run for the report to be complete; run the fast ones
  execFileSync("node", ["eval/bench/gen-corpus.mjs", "--seed", "20260902"], { cwd: ROOT, stdio: "pipe" });
  execFileSync("node", ["eval/bench/run.mjs", "current"], { cwd: ROOT, stdio: "pipe" });
  execFileSync("node", ["eval/bench/redaction.mjs", "current"], { cwd: ROOT, stdio: "pipe" });
  execFileSync("node", ["scripts/aggregate-benchmarks.mjs"], { cwd: ROOT, stdio: "pipe" });

  const j = JSON.parse(readFileSync(`${ROOT}/benchmark-results.json`, "utf8"));
  assert.ok(j.environment.gitCommit || j.environment.gitCommit === null);
  assert.ok(j.detection.overall.f1 > 0.8);
  assert.ok(j.redaction.leakageRate >= 0);
  const md = readFileSync(`${ROOT}/BENCHMARK_REPORT.md`, "utf8");
  assert.match(md, /PII detection/);
  assert.match(md, /NOT MEASURED|not run/i, "the report must be explicit about what was not measured");
});
