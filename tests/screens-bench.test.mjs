// Phase 8 — the synthetic screen corpus + geometry scorer sanity.

import test from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";

const ROOT = new URL("..", import.meta.url).pathname;

test("gen-screens is deterministic and every box is inside its viewport", () => {
  execFileSync("node", ["eval/screens/gen-screens.mjs", "--seed", "20260902"], { cwd: ROOT, stdio: "pipe" });
  const a = readFileSync(`${ROOT}/eval/screens/screens.jsonl`, "utf8");
  execFileSync("node", ["eval/screens/gen-screens.mjs", "--seed", "20260902"], { cwd: ROOT, stdio: "pipe" });
  const b = readFileSync(`${ROOT}/eval/screens/screens.jsonl`, "utf8");
  assert.equal(a, b, "same seed -> identical corpus");

  const manifest = JSON.parse(readFileSync(`${ROOT}/eval/screens/screens.manifest.json`, "utf8"));
  assert.equal(manifest.boxErrors, 0);
  assert.ok(manifest.piiElements >= 30);
});

test("scorer: form-field PII is covered, adversarial look-alikes are not redacted", () => {
  execFileSync("node", ["eval/screens/score.mjs"], { cwd: ROOT, stdio: "pipe" });
  const res = JSON.parse(readFileSync(`${ROOT}/eval/screens/screens.results.json`, "utf8"));

  // precision must be perfect on this corpus (regions only land on PII)
  assert.equal(res.overall.visualPrecision, 1);
  // zero adversarial false-redactions (order id / SKU / IPv4 / build number)
  assert.equal(res.overall.totalAdversarialFP, 0);
  // login/checkout screens (pure form fields) -> full recall
  const login = res.rows.find((r) => r.name === "login-light");
  assert.equal(login.visualRecall, 1);
  const checkout = res.rows.find((r) => r.name === "checkout-payment");
  assert.equal(checkout.visualRecall, 1);
  // the clean dashboard produces no redaction regions
  const clean = res.rows.find((r) => r.type === "dashboard");
  assert.equal(clean.regions, 0);
});
