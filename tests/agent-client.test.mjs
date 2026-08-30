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

test("rejects type without any value or piiCategory", () => {
  assert.match(validateAction({ action: "type", targetId: "el-1" }, ids), /needs piiCategory or literalValue/);
});

test("validatePlan stops at first 'done' and rejects the whole plan on a bad action", () => {
  const good = validatePlan(
    [{ action: "type", targetId: "el-1", piiCategory: "email" }, { action: "done" }, { action: "click", targetId: "x" }],
    ids
  );
  assert.equal(good.ok, true);
  assert.equal(good.actions.length, 2);

  const bad = validatePlan([{ action: "click", targetId: "ghost" }], ids);
  assert.equal(bad.ok, false);
});
