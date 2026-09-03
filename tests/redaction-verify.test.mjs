// Redaction verification gate (S4 / item 11).

import test from "node:test";
import assert from "node:assert/strict";
import { verifyRedaction } from "../client/lib/redaction-verify.mjs";

// minimal canvas mock — records the fillRect calls so we can assert on masking
function mockCanvas(w = 1200, h = 800) {
  const fills = [];
  return {
    width: w, height: h, fills,
    getContext: () => ({
      save() {}, restore() {}, set fillStyle(_v) {}, get fillStyle() { return "#000"; },
      fillRect(x, y, ww, hh) { fills.push({ x, y, w: ww, h: hh }); },
    }),
  };
}

const line = (text, x0 = 100, y0 = 200, x1 = 500, y1 = 220) => ({ text, bbox: { x0, y0, x1, y1 } });

test("clean: masked canvas re-OCRs to non-sensitive text -> VERIFIED", async () => {
  const canvas = mockCanvas();
  const r = await verifyRedaction(canvas, [], {
    ocr: async () => [line("Welcome. Please fill in the form below.")],
  });
  assert.equal(r.verified, true);
  assert.equal(r.status, "VERIFIED");
  assert.equal(r.passes, 0);
  assert.equal(r.residual.length, 0);
  assert.equal(canvas.fills.length, 0, "nothing extra was masked");
});

test("recoverable: residual PII on the first re-OCR -> grown + re-masked -> clean", async () => {
  const canvas = mockCanvas();
  let call = 0;
  const r = await verifyRedaction(canvas, [], {
    // 1st re-OCR still shows a bare Aadhaar; after the re-mask the 2nd re-OCR is clean
    ocr: async () => (call++ === 0 ? [line("id 2345 6789 0124 on file")] : [line("id on file")]),
  });
  assert.equal(r.verified, true);
  assert.equal(r.status, "VERIFIED_AFTER_REMASK");
  assert.equal(r.passes, 1);
  assert.ok(canvas.fills.length >= 1, "the residual region was masked");
  assert.deepEqual(r.residualCategories, []);
});

test("unrecoverable: still leaking after the one retry -> REDACTION_FAILED", async () => {
  const canvas = mockCanvas();
  const r = await verifyRedaction(canvas, [], {
    ocr: async () => [line("PAN ABCPS1234K and card 4111 1111 1111 1111")], // never clears
  });
  assert.equal(r.verified, false);
  assert.equal(r.status, "REDACTION_FAILED");
  assert.equal(r.passes, 1, "exactly one re-mask attempt, never loops");
  assert.ok(r.residual.length > 0);
  for (const x of r.residual) assert.equal("value" in x, false, "residual carries no raw value");
  assert.ok(r.residualCategories.includes("credit-card") || r.residualCategories.includes("pan"));
});

test("secrets in the re-OCR'd text also trigger the gate; evidence is masked", async () => {
  const canvas = mockCanvas();
  const key = "AKIA" + "EXAMPLEKEY0000AB";
  const r = await verifyRedaction(canvas, [], { ocr: async () => [line(`deploy key ${key}`)] });
  assert.equal(r.verified, false);
  assert.equal(r.status, "REDACTION_FAILED");
  for (const x of r.residual) {
    assert.equal(x.evidence.includes(key), false);
  }
});

test("bounded to exactly one re-pass — an always-dirty OCR does not loop", async () => {
  const canvas = mockCanvas();
  let calls = 0;
  await verifyRedaction(canvas, [], { ocr: async () => { calls++; return [line("ssn 123-45-6789 here")]; } });
  // 1 initial scan + 1 scan after the single re-mask = 2 OCR calls, never more
  assert.equal(calls, 2);
});

test("OCR unavailable -> SKIPPED (not a hard block)", async () => {
  const canvas = mockCanvas();
  const r = await verifyRedaction(canvas, [], { ocr: async () => { throw new Error("Tesseract runtime is unavailable"); } });
  assert.equal(r.verified, true);
  assert.equal(r.status, "SKIPPED");
  assert.match(r.reason, /ocr unavailable/);
});

test("no ocr function -> SKIPPED", async () => {
  const r = await verifyRedaction(mockCanvas(), []);
  assert.equal(r.status, "SKIPPED");
  assert.equal(r.verified, true);
});

// ── the pipeline contract: processVision surfaces the verdict, background blocks on it ──

test("processVision returns redactionVerified / redactionStatus / redactionResidual", async () => {
  const { processVision } = await import("../client/lib/vision-pipeline.mjs");
  const res = await processVision({
    screenshot: "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==",
    domPiiBoxes: [], fields: [], dpr: 1, mode: "blackout",
    a11yStats: { totalNodes: 5, labeledNodes: 5, unlabeledNodes: 0, hasCanvas: false, confidence: 1, fastPathEligible: true },
  });
  // fast-path with zero regions -> verification skipped, still reported
  assert.equal(typeof res.redactionVerified, "boolean");
  assert.ok(["VERIFIED", "VERIFIED_AFTER_REMASK", "REDACTION_FAILED", "SKIPPED"].includes(res.redactionStatus));
  assert.ok(Array.isArray(res.redactionResidual));
  assert.ok(res.stats.redaction);
});

test("background.js blocks the /agent/step call when redactionVerified is false", async () => {
  // background.js is an MV3 module that registers listeners on import; assert the
  // guard exists in-source between the vision call and the network round-trip.
  const { readFileSync } = await import("node:fs");
  const src = readFileSync(new URL("../client/background.js", import.meta.url), "utf8");
  const guardIdx = src.indexOf("vis.redactionVerified === false");
  const requestStepIdx = src.indexOf("requestStep(cfg.serverUrl, payload)");
  assert.ok(guardIdx > -1, "no redactionVerified guard in background.js");
  assert.ok(requestStepIdx > -1);
  assert.ok(guardIdx < requestStepIdx, "the guard must come before the network call");
  const between = src.slice(guardIdx, requestStepIdx);
  assert.match(between, /\bbreak\b/, "the guard must break out of the step loop before sending");
  assert.match(between, /BLOCKED[\s\S]*Nothing was sent/, "must surface a clear blocked status");
});
