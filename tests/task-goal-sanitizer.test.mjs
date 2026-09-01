import test from "node:test";
import assert from "node:assert/strict";
import { sanitizeTaskGoal } from "../client/lib/dlp-heuristics.mjs";

test("redacts formatted PII pasted into the goal", () => {
  const r = sanitizeTaskGoal("Fill my form with John Smith, john@example.com, Aadhaar 1234 5678 9012");
  assert.ok(r.redacted);
  assert.doesNotMatch(r.text, /john@example\.com/);
  assert.doesNotMatch(r.text, /1234 5678 9012/);
  assert.doesNotMatch(r.text, /John Smith/);
  assert.match(r.text, /\[TOKEN_EMAIL\]/);
  assert.match(r.text, /\[TOKEN_AADHAAR\]/);
});

test("leaves an intent-only goal untouched", () => {
  const r = sanitizeTaskGoal("Fill the form using my local profile");
  assert.equal(r.redacted, false);
  assert.equal(r.text, "Fill the form using my local profile");
});

test("redacts quoted literals and value-carrying clauses", () => {
  const r = sanitizeTaskGoal('Enter name "Priya Sharma" and set DOB to 01/01/1990');
  assert.doesNotMatch(r.text, /Priya Sharma/);
  assert.doesNotMatch(r.text, /01\/01\/1990/);
  assert.ok(r.hits.includes("quoted-literal") || r.hits.includes("value-clause"));
});

test("does not redact common intent connectives (my/the/local/profile)", () => {
  const r = sanitizeTaskGoal("Set the address to my saved profile value and then submit");
  assert.match(r.text, /submit/);
  assert.equal(r.redacted, false);
});

test("caps goal length", () => {
  const r = sanitizeTaskGoal("x ".repeat(1000));
  assert.ok(r.text.length <= 600);
});

test("guided-builder goal shapes pass through untouched", () => {
  const guided = [
    "Fill this form using my saved local profile. Stop before submitting so I can review.",
    "Fill this form using my saved local profile. Submit the form after every field has been filled.",
    "Fill this form using my saved local profile, but only the full name, email and phone number fields. Stop before submitting so I can review.",
    "Fill this form using my saved local profile, but only the address field. Submit the form after every field has been filled.",
  ];
  for (const g of guided) {
    const r = sanitizeTaskGoal(g);
    assert.equal(r.redacted, false, `should not redact: ${g}`);
    assert.equal(r.text, g);
  }
});

test("handles non-string input", () => {
  assert.deepEqual(sanitizeTaskGoal(undefined), { text: "", redacted: false, hits: [] });
  assert.deepEqual(sanitizeTaskGoal(null), { text: "", redacted: false, hits: [] });
});
