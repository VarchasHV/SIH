import test from "node:test";
import assert from "node:assert/strict";
import { mergeDetections, redundancyStats, iou } from "../client/lib/merge.mjs";

const box = (x, y, w, h) => ({ x, y, w, h });

test("iou is 1 for identical boxes, 0 for disjoint", () => {
  assert.equal(iou(box(0, 0, 10, 10), box(0, 0, 10, 10)), 1);
  assert.equal(iou(box(0, 0, 10, 10), box(100, 100, 10, 10)), 0);
});

test("overlapping same-family DOM + OCR hit merge into one item with two sources", () => {
  const dom = [{ category: "email", confidence: 0.95, bbox: box(10, 10, 200, 30), fieldId: "el-1" }];
  const vision = [{ category: "email", confidence: 0.9, source: "ocr", bbox: box(20, 12, 180, 26) }];
  const merged = mergeDetections(dom, vision, 0.3);
  assert.equal(merged.length, 1);
  assert.deepEqual(merged[0].sources.sort(), ["dom", "ocr"]);
  assert.equal(merged[0].fieldId, "el-1");
});

test("vision-only detection (face) is kept as its own item", () => {
  const merged = mergeDetections([], [{ category: "face", confidence: 0.99, source: "face", bbox: box(0, 0, 50, 50) }]);
  assert.equal(merged.length, 1);
  assert.deepEqual(merged[0].sources, ["face"]);
});

// ---- Phase 9: documented privacy-risk fusion --------------------------

test("restricted category always redacts, even from one weak source", () => {
  const merged = mergeDetections([], [{ category: "aadhaar", confidence: 0.5, source: "ocr", bbox: box(0, 0, 100, 20) }]);
  assert.equal(merged[0].redact, true);
  assert.ok(merged[0].privacyRisk >= 0.5);
  assert.match(merged[0].reason, /base .* \(aadhaar\)/);
});

test("DOM password field + OCR corroboration -> risk 1.0", () => {
  const merged = mergeDetections(
    [{ category: "password", confidence: 0.9, bbox: box(0, 0, 100, 20), fieldId: "pw" }],
    [{ category: "password", confidence: 0.8, source: "ocr", bbox: box(1, 1, 98, 18) }],
    0.3,
  );
  assert.equal(merged.length, 1);
  assert.equal(merged[0].privacyRisk, 1);
  assert.equal(merged[0].redact, true);
});

test("lone OCR hit contradicted by the DOM's non-sensitive field classification is de-rated and NOT redacted", () => {
  // OCR thinks it saw an aadhaar-ish number; DOM says that field is an order id.
  const merged = mergeDetections(
    [{ category: "order-id", confidence: 0.9, bbox: box(0, 0, 100, 20), fieldId: "el-9" }],
    [{ category: "ipv4", confidence: 0.6, source: "ocr", bbox: box(0, 0, 100, 20) }],
    0.3,
    { domFieldCategories: { "el-9": "order-id" } },
  );
  const ocrItem = merged.find((m) => m.sources.length === 1 && m.sources[0] === "ocr");
  assert.ok(ocrItem);
  assert.equal(ocrItem.redact, false);
  assert.match(ocrItem.reason, /x0\.5|x0\.7/);
});

test("two agreeing channels raise a profile-PII detection above the redact threshold", () => {
  const merged = mergeDetections(
    [{ category: "email", confidence: 0.7, bbox: box(0, 0, 100, 20), fieldId: "el-1" }],
    [{ category: "email", confidence: 0.7, source: "ocr", bbox: box(1, 1, 98, 18) }],
    0.3,
  );
  assert.equal(merged[0].redact, true);
  assert.match(merged[0].reason, /corroboration/);
});

test("every merged detection carries the risk decision fields", () => {
  const merged = mergeDetections([{ category: "email", confidence: 0.8, bbox: box(0, 0, 10, 10), fieldId: "e" }], []);
  for (const m of merged) {
    assert.equal(typeof m.privacyRisk, "number");
    assert.equal(typeof m.redact, "boolean");
    assert.equal(typeof m.reason, "string");
  }
});

test("redundancyStats reports the vision-unique rate", () => {
  const merged = mergeDetections(
    [{ category: "email", confidence: 0.9, bbox: box(0, 0, 100, 20), fieldId: "el-1" }],
    [
      { category: "email", confidence: 0.9, source: "ocr", bbox: box(2, 1, 96, 18) },
      { category: "face", confidence: 0.9, source: "face", bbox: box(300, 300, 40, 40) },
    ],
    0.3
  );
  const s = redundancyStats(merged);
  assert.equal(s.total, 2);
  assert.equal(s.both, 1);
  assert.equal(s.visionOnly, 1);
  assert.equal(s.visionUniqueRate, 0.5);
});
