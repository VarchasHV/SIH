// Phase 7 — redaction scoring must penalise MISSED PII (the audit's finding
// about client/lib/redact.mjs::leakScore, which only inspects detected regions).

import test from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtempSync, writeFileSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const ROOT = new URL("..", import.meta.url).pathname;

function runRedaction(samples, detectorName) {
  const dir = mkdtempSync(join(tmpdir(), "redbench-"));
  const corpus = join(dir, "c.jsonl");
  writeFileSync(corpus, samples.map((s) => JSON.stringify(s)).join("\n") + "\n");
  execFileSync("node", ["eval/bench/redaction.mjs", detectorName, "--corpus", corpus], { cwd: ROOT, stdio: "pipe" });
  return JSON.parse(readFileSync(join(dir, "c.redaction.json"), "utf8"));
}

test("a detector that finds every span -> 0% leakage; missing a span -> that span leaks 100%", () => {
  // "current" detects keyworded aadhaar; it does NOT detect a bare voter-id.
  const samples = [
    { id: "s1", text: "Aadhaar 2345 6789 0124 on file", spans: [{ category: "aadhaar", value: "2345 6789 0124", start: 8, end: 22 }], kind: "pos:aadhaar:kw", form: "ascii" },
    { id: "s2", text: "Here it is: ABC1234567", spans: [{ category: "voter-id", value: "ABC1234567", start: 12, end: 22 }], kind: "pos:voter-id:bare", form: "ascii" },
  ];
  const { rows } = runRedaction(samples, "current");
  const r = rows[0];
  // aadhaar span (14 chars) fully covered, voter-id span (10 chars) fully leaked
  assert.ok(r.leakageRate > 0.3 && r.leakageRate < 0.55, `leakage ${r.leakageRate}`);
  assert.equal(r.leakageByClass["A-contextual"].leakageRate, 0, "keyworded aadhaar fully redacted");
  assert.equal(r.leakageByClass["B-unlabelled"].leakageRate, 1, "bare voter-id fully leaked");
  assert.equal(r.fullyRedactedRate, 0.5);
  assert.equal(r.partialLeakRate, 0.5);
});

test("clean negatives contribute no gold chars and no leakage", () => {
  const samples = [
    { id: "s1", text: "The quarterly review meeting is next Tuesday.", spans: [], kind: "neg:clean" },
  ];
  const { rows } = runRedaction(samples, "current");
  assert.equal(rows[0].goldChars, 0);
  assert.equal(rows[0].leakageRate, 0);
});
