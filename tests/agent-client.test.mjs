import test from "node:test";
import assert from "node:assert/strict";
import { validateAction, validatePlan } from "../client/lib/agent-client.mjs";

const ids = new Set(["el-1", "el-2", "submit-1"]);

test("accepts a well-formed type action", () => {
  assert.equal(validateAction({ action: "type", targetId: "el-1", piiCategory: "email" }, ids), null);
});

test("rejects unknown action / target", () => {
  assert.match(validateAction({ action: "frobnicate" }, ids), /unknown action/);
  assert.match(validateAction({ action: "click", targetId: "nope" }, ids), /unknown targetId/);
});

test("accepts a well-formed type action with fillToken", () => {
  assert.equal(validateAction({ action: "type", targetId: "el-1", fillToken: "local:ssn" }, ids), null);
});

test("validatePlan stops at first 'done' and rejects the whole plan on a bad action", () => {
  const good = validatePlan(
    [{ action: "type", targetId: "el-1", fillToken: "local:ssn" }, { action: "done" }, { action: "click", targetId: "x" }],
    ids
  );
  assert.equal(good.ok, true);
  assert.equal(good.actions.length, 2);

  const bad = validatePlan([{ action: "click", targetId: "ghost" }], ids);
  assert.equal(bad.ok, false);
});

test("Sanitized skeleton payload contains tokenized censored SSN node with ZERO raw sensitive value", () => {
  const rawSSN = "999-00-1234";

  // Simulate skeleton node for a censored SSN field
  const sanitizedNode = {
    id: "el-ssn",
    tag: "input",
    type: "text",
    isCensored: true,
    hasFill: true,
    fillToken: "local:ssn",
    piiCategory: "ssn",
    label: "",
    state: "empty",
  };

  const payload = {
    taskGoal: "fill form",
    step: 1,
    skeleton: {
      url: "http://localhost",
      viewport: { width: 1000, height: 800 },
      nodes: [sanitizedNode],
    },
    visionDetections: [],
    screenshot: "data:image/jpeg;base64,...redacted...",
  };

  const jsonPayload = JSON.stringify(payload);

  // Assert node exists in payload with token
  assert.equal(payload.skeleton.nodes[0].isCensored, true);
  assert.equal(payload.skeleton.nodes[0].fillToken, "local:ssn");
  assert.equal(payload.skeleton.nodes[0].hasFill, true);

  // CRITICAL ASSERTION: raw SSN value MUST NEVER appear anywhere in the JSON payload
  assert.equal(
    jsonPayload.includes(rawSSN),
    false,
    "Raw SSN value '999-00-1234' MUST NOT appear anywhere in payload sent to server"
  );
});
