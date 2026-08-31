import test from "node:test";
import assert from "node:assert/strict";
import { Vault } from "../client/lib/tokenizer.mjs";

test("profile values get stable category-prefixed tokens", () => {
  const v = new Vault();
  const map = v.addProfile({ Aadhaar: "2345 6789 0124", email: "a@b.com", "first name": "Aditi" });
  assert.equal(map.Aadhaar, "[AADHAAR_1]");
  assert.equal(map.email, "[EMAIL_1]");
  assert.equal(v.resolve("[AADHAAR_1]"), "2345 6789 0124");
});

test("same value returns the same token", () => {
  const v = new Vault();
  const a = v.add("a@b.com", "email");
  const b = v.add("A@B.COM ", "email");
  assert.equal(a, b);
});

test("redactText swaps every known value, tolerating whitespace", () => {
  const v = new Vault();
  v.addProfile({ Aadhaar: "234567890124", email: "a@b.com" });
  const out = v.redactText("uid 2345 6789 0124 mail a@b.com");
  assert.equal(out, "uid [AADHAAR_1] mail [EMAIL_1]");
});

test("exportContext leaks category only, never the value", () => {
  const v = new Vault();
  v.addProfile({ PAN: "ABCPS1234K" });
  const ctx = v.exportContext();
  assert.deepEqual(ctx, { "[PAN_1]": "PAN" });
  assert.equal(JSON.stringify(ctx).includes("ABCPS1234K"), false);
});

test("serialize / deserialize round-trips", () => {
  const v = new Vault();
  v.addProfile({ email: "a@b.com" });
  const v2 = Vault.deserialize(JSON.parse(JSON.stringify(v.serialize())));
  assert.equal(v2.resolve("[EMAIL_1]"), "a@b.com");
  assert.equal(v2.tokenForValue("a@b.com"), "[EMAIL_1]");
});
