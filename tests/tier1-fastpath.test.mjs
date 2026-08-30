import test from "node:test";
import assert from "node:assert/strict";
import { Tier1_FastPath, verhoeffValid, analyzePayload } from "../client/lib/tier1-fastpath.mjs";

test("Tier 1 - Aadhaar validation (unspaced, spaced, dashes)", () => {
  // Valid Verhoeff 2345 6789 0124
  assert.equal(verhoeffValid("234567890124"), true);
  assert.equal(verhoeffValid("234567890123"), false);

  const spaced = Tier1_FastPath.detect("Aadhaar 2345 6789 0124 on file");
  assert.equal(spaced.some((h) => h.category === "aadhaar"), true);

  const unspaced = Tier1_FastPath.detect("Aadhaar 234567890124 on file");
  assert.equal(unspaced.some((h) => h.category === "aadhaar"), true);

  const dashed = Tier1_FastPath.detect("Aadhaar 2345-6789-0124 on file");
  assert.equal(dashed.some((h) => h.category === "aadhaar"), true);

  const invalid = Tier1_FastPath.detect("Fake 2345-6789-0123 is bad");
  assert.equal(invalid.some((h) => h.category === "aadhaar"), false);
});

test("Tier 1 - Phone (IN) boundary and timestamp gating", () => {
  const valid = Tier1_FastPath.detect("Call +91 9876543210 now");
  assert.equal(valid.some((h) => h.category === "phone-in"), true);

  const timestamp = Tier1_FastPath.detect("Timestamp 1698765432100 log");
  assert.equal(timestamp.some((h) => h.category === "phone-in"), false);
});

test("Tier 1 - SSN negative lookbehind for ID prefixes", () => {
  const standalone = Tier1_FastPath.detect("SSN 123-45-6789 registered");
  assert.equal(standalone.some((h) => h.category === "ssn"), true);

  const orderPrefix = Tier1_FastPath.detect("Order: 123-45-6789 placed");
  assert.equal(orderPrefix.some((h) => h.category === "ssn"), false);

  const refPrefix = Tier1_FastPath.detect("Ref-123-45-6789 created");
  assert.equal(refPrefix.some((h) => h.category === "ssn"), false);
});

test("Tier 1 - IPv4 negative lookbehind for versions", () => {
  const validIp = Tier1_FastPath.detect("Host 192.168.1.1 online");
  assert.equal(validIp.some((h) => h.category === "ipv4"), true);

  const version = Tier1_FastPath.detect("Release v1.2.3.4 ready");
  assert.equal(version.some((h) => h.category === "ipv4"), false);

  const fullVersion = Tier1_FastPath.detect("Version 1.2.3.4 published");
  assert.equal(fullVersion.some((h) => h.category === "ipv4"), false);
});

test("Two-Tier Router - Text payload executes sub-10ms in Tier 1", async () => {
  const res = await analyzePayload({
    type: "text",
    text: "Contact user at test@example.com or Aadhaar 2345-6789-0124",
  });
  assert.equal(res.tier, 1);
  assert.equal(res.sub10ms, true);
  assert.equal(res.detections.length >= 2, true);
});

test("Two-Tier Router - Image payload routes to Tier 2 VLM", async () => {
  const res = await analyzePayload({
    type: "image",
    image: "data:image/png;base64,iVBORw0KGgo...",
  });
  assert.equal(res.tier, 2);
});
