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

// ---- Phase 11: semantic preservation ---------------------------------

test("Phase 11: identity removed, action + object intent preserved", () => {
  const cases = [
    // [goal, must-still-contain (intent), must-not-contain (identity)]
    ["Find John Smith's account and transfer 500 rupees", ["Find", "account", "transfer", "500"], ["John", "Smith"]],
    ["Log into Priya's dashboard and download the report", ["Log into", "dashboard", "download", "report"], ["Priya"]],
    ["Book a ticket for Mr. Arjun Nair", ["Book", "ticket"], ["Arjun", "Nair"]],
    ["Fill the checkout form for Aditi Sharma", ["Fill", "checkout", "form"], ["Aditi", "Sharma"]],
    ["Update the shipping address to my saved profile value", ["Update", "shipping address"], []],
  ];
  for (const [goal, keep, drop] of cases) {
    const { text } = sanitizeTaskGoal(goal);
    for (const k of keep) assert.ok(text.includes(k), `"${goal}" -> "${text}" should keep "${k}"`);
    for (const d of drop) assert.ok(!text.includes(d), `"${goal}" -> "${text}" should drop "${d}"`);
    assert.ok(text.trim().length > 0);
  }
});

test("Phase 11: directional 'to' and navigation verbs are NOT treated as value clauses", () => {
  for (const g of [
    "Search for the cheapest flight to Delhi",
    "Go to checkout and pay",
    "Navigate to the settings page",
    "Scroll to the bottom and click submit",
  ]) {
    const r = sanitizeTaskGoal(g);
    assert.equal(r.redacted, false, `should not redact: "${g}" -> "${r.text}"`);
    assert.equal(r.text, g);
  }
});

test("Phase 11: a bare number in the goal is not mistaken for a CVV / account / zip", () => {
  for (const g of [
    "Pay the electricity bill of 1240 rupees",
    "Add 3 items to the cart",
    "Set the quantity to 12",
    "Go to page 500",
  ]) {
    const r = sanitizeTaskGoal(g);
    assert.doesNotMatch(r.text, /\[TOKEN_(CVV|BANK_ACCOUNT|ZIP_CODE)\]/, g);
  }
});

test("Phase 11: dates in the goal - a DD/MM/YYYY is one token, not sliced into MM/YY", () => {
  const r = sanitizeTaskGoal("set date of birth to 01/01/1990");
  assert.match(r.text, /\[TOKEN_DOB\]/);
  assert.doesNotMatch(r.text, /\[TOKEN_CARD_EXPIRY\]/);
  assert.doesNotMatch(r.text, /1990/);
});

test("handles non-string input", () => {
  assert.deepEqual(sanitizeTaskGoal(undefined), { text: "", redacted: false, hits: [] });
  assert.deepEqual(sanitizeTaskGoal(null), { text: "", redacted: false, hits: [] });
});
