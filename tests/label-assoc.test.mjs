import test from "node:test";
import assert from "node:assert/strict";
import { associateLabels } from "../client/lib/label-assoc.mjs";

// OCR line boxes are {x0,y0,x1,y1} in device px; field boxes {x,y,w,h} in CSS px.
const line = (text, x0, y0, x1, y1) => ({ text, bbox: { x0, y0, x1, y1 } });
const field = (id, x, y, w, h, piiCategory = null) => ({ id, piiCategory, bbox: { x, y, w, h } });

test("pairs a caption to the LEFT of a field and classifies it", () => {
  const lines = [line("First Name", 20, 100, 110, 118)];
  const fields = [field("el-1", 130, 96, 200, 26)]; // dpr 1
  const out = associateLabels(lines, fields, 1);
  assert.equal(out.length, 1);
  assert.equal(out[0].category, "first name");
  assert.equal(out[0].fieldId, "el-1");
  assert.equal(out[0].source, "ocr-label");
});

test("pairs a caption ABOVE a field", () => {
  const lines = [line("Aadhaar number", 40, 60, 180, 78)];
  const fields = [field("el-4", 40, 84, 300, 30)];
  const out = associateLabels(lines, fields, 1);
  assert.equal(out[0]?.category, "Aadhaar");
});

test("skips fields the DOM already classified", () => {
  const lines = [line("Email", 0, 0, 60, 16)];
  const fields = [field("el-2", 70, 0, 200, 20, "email")];
  assert.deepEqual(associateLabels(lines, fields, 1), []);
});

test("respects devicePixelRatio when scaling field boxes", () => {
  const lines = [line("Last Name", 40, 200, 200, 236)]; // device px
  const fields = [field("el-3", 110, 100, 150, 18)]; // CSS px -> *2 = 220..250 y
  const out = associateLabels(lines, fields, 2);
  assert.equal(out[0]?.category, "last name");
});

test("no caption nearby -> no detection", () => {
  const lines = [line("Totally unrelated footer text", 0, 900, 400, 918)];
  const fields = [field("el-9", 40, 100, 200, 24)];
  assert.deepEqual(associateLabels(lines, fields, 1), []);
});
