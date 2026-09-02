// Phase 10 — the pre-egress privacy gate.

import test from "node:test";
import assert from "node:assert/strict";
import { assertNoSensitivePayload } from "../client/lib/egress-guard.mjs";

const PROFILE = {
  "full name": "Aditi Sharma",
  "phone number": "9876543210",
  aadhaar: "2345 6789 0124",
  email: "aditi.sharma@example.com",
};

test("clean structural payload passes", () => {
  const payload = {
    taskGoal: "Fill this form using my saved local profile. Stop before submitting.",
    step: 1,
    skeleton: { url: "x", nodes: [{ id: "el-1", tag: "input", type: "text", label: "First name", state: "empty" }] },
    screenshot: "data:image/png;base64,AAAA",
    history: [],
  };
  const r = assertNoSensitivePayload(payload, { profile: PROFILE });
  assert.equal(r.ok, true);
  assert.equal(r.blocked, false);
});

test("blocks + redacts a raw profile value that leaked into a skeleton label", () => {
  const payload = {
    taskGoal: "fill the form",
    skeleton: { nodes: [{ id: "el-1", tag: "input", label: "Account holder: Aditi Sharma", state: "filled" }] },
    screenshot: "data:image/png;base64,AAAA",
  };
  const r = assertNoSensitivePayload(payload, { profile: PROFILE });
  assert.equal(r.ok, false);
  assert.ok(r.findings.some((f) => f.source === "profile" && f.category === "name"));
  assert.equal(r.sanitized.skeleton.nodes[0].label, "Account holder: [REDACTED:name]");
  // findings carry NO value
  for (const f of r.findings) assert.equal("value" in f, false);
});

test("RESTRICTED category (aadhaar) is a hard block", () => {
  const payload = {
    taskGoal: "my aadhaar is 2345 6789 0124 please fill it",
    skeleton: { nodes: [] },
    screenshot: "data:image/png;base64,AAAA",
  };
  const r = assertNoSensitivePayload(payload, { profile: PROFILE });
  assert.equal(r.ok, false);
  assert.equal(r.blocked, true);
  assert.equal(r.summary.restrictedHit, true);
  assert.match(r.sanitized.taskGoal, /\[REDACTED:aadhaar\]/);
});

test("catches structural PII that is NOT in the profile (a name/number on the page)", () => {
  const payload = {
    taskGoal: "fill it",
    skeleton: { nodes: [{ id: "n1", tag: "div", text: "Contact support at ops@vendor.co or +91 9812345678" }] },
    screenshot: "data:image/png;base64,AAAA",
  };
  const r = assertNoSensitivePayload(payload, { profile: PROFILE });
  assert.equal(r.ok, false);
  const cats = r.findings.map((f) => f.category);
  assert.ok(cats.includes("email"));
  assert.ok(cats.includes("phone-in"));
  assert.equal(r.sanitized.skeleton.nodes[0].text.includes("ops@vendor.co"), false);
});

test("does not scan the screenshot data URL or structural id/type fields", () => {
  const payload = {
    taskGoal: "fill it",
    skeleton: { nodes: [{ id: "aditi.sharma@example.com", tag: "input", type: "email", state: "empty" }] },
    screenshot: "data:image/png;base64," + "QUJD".repeat(50),
  };
  const r = assertNoSensitivePayload(payload, { profile: PROFILE });
  // id is in SKIP_KEYS — an email-shaped id must not trip the gate
  assert.equal(r.ok, true);
});

test("sanitized payload is a copy — the input object is untouched", () => {
  const payload = {
    taskGoal: "my email is aditi.sharma@example.com",
    skeleton: { nodes: [] },
    screenshot: "data:image/png;base64,AAAA",
  };
  const r = assertNoSensitivePayload(payload, { profile: PROFILE });
  assert.equal(payload.taskGoal, "my email is aditi.sharma@example.com", "input unchanged");
  assert.match(r.sanitized.taskGoal, /\[REDACTED:/);
});
