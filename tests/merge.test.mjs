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
