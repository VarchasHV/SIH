import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import vm from "node:vm";
import { fileURLToPath } from "node:url";

import { RESTRICTED_PII_CATEGORIES, isRestrictedCategory } from "../client/lib/sensitive-fields.mjs";
import { Vault } from "../client/lib/tokenizer.mjs";
import { classifyPayload } from "../client/lib/security-policy.mjs";

const __dirname = path.dirname(fileURLToPath(import.meta.url));

test("RESTRICTED_PII_CATEGORIES contains Aadhaar, PAN, Passport, and Voter ID aliases", () => {
  const expected = [
    "Aadhaar number",
    "aadhaar number",
    "Aadhaar",
    "aadhaar",
    "PAN",
    "pan",
    "PAN number",
    "pan number",
    "Passport number",
    "passport number",
    "passport",
    "Voter ID",
    "voter id",
    "epic",
    "EPIC",
    "government ID",
  ];
  for (const cat of expected) {
    assert.equal(RESTRICTED_PII_CATEGORIES.has(cat), true, `Category "${cat}" must be in RESTRICTED_PII_CATEGORIES`);
    assert.equal(isRestrictedCategory(cat), true, `isRestrictedCategory("${cat}") must be true`);
  }
});

test("agent-bridge resolveProfileValue accurately resolves Aadhaar, PAN, Passport, and Voter ID", () => {
  // Load agent-bridge.js in a mock DOM environment
  const bridgeCode = fs.readFileSync(path.join(__dirname, "../client/agent-bridge.js"), "utf8");
  const ctx = {
    window: {
      __PL: {
        RESTRICTED_PII_CATEGORIES,
      },
    },
    chrome: {
      runtime: {
        onMessage: { addListener: () => {} },
      },
      storage: {
        local: {
          get: async () => ({}),
        },
      },
    },
    document: {},
    location: { href: "http://localhost:4173/kyc.html" },
  };

  vm.createContext(ctx);
  // Extract resolveProfileValue
  const fnMatch = bridgeCode.match(/function resolveProfileValue\([\s\S]*?\n  \}/);
  assert.ok(fnMatch, "resolveProfileValue function should be in agent-bridge.js");

  const canonicalMatch = bridgeCode.match(/const CANONICAL_CATEGORIES = \{[\s\S]*?\n  \};/);
  assert.ok(canonicalMatch, "CANONICAL_CATEGORIES should be in agent-bridge.js");

  const script = new vm.Script(`
    ${canonicalMatch[0]}
    ${fnMatch[0]}
    this.resolveProfileValue = resolveProfileValue;
  `);
  script.runInContext(ctx);

  const resolveProfileValue = ctx.resolveProfileValue;

  const testProfile = {
    "full name": "Aditi Sharma",
    "email": "aditi.sharma@example.com",
    "Aadhaar number": "2345 6789 0123",
    "PAN": "ABCDE1234F",
    "Passport number": "A1234567",
    "Voter ID": "TND1234567",
  };

  // Aadhaar tests
  assert.equal(resolveProfileValue(testProfile, "Aadhaar number"), "2345 6789 0123");
  assert.equal(resolveProfileValue(testProfile, "Aadhaar"), "2345 6789 0123");
  assert.equal(resolveProfileValue(testProfile, "aadhaar"), "2345 6789 0123");
  assert.equal(resolveProfileValue(testProfile, "uidai"), "2345 6789 0123");

  // PAN tests
  assert.equal(resolveProfileValue(testProfile, "PAN"), "ABCDE1234F");
  assert.equal(resolveProfileValue(testProfile, "pan"), "ABCDE1234F");
  assert.equal(resolveProfileValue(testProfile, "PAN number"), "ABCDE1234F");
  assert.equal(resolveProfileValue(testProfile, "pan number"), "ABCDE1234F");
  assert.equal(resolveProfileValue(testProfile, "pancard"), "ABCDE1234F");

  // Passport tests
  assert.equal(resolveProfileValue(testProfile, "Passport number"), "A1234567");
  assert.equal(resolveProfileValue(testProfile, "passport number"), "A1234567");
  assert.equal(resolveProfileValue(testProfile, "passport"), "A1234567");

  // Voter ID / Government ID tests
  assert.equal(resolveProfileValue(testProfile, "Voter ID"), "TND1234567");
  assert.equal(resolveProfileValue(testProfile, "voter id"), "TND1234567");
  assert.equal(resolveProfileValue(testProfile, "epic"), "TND1234567");
  assert.equal(resolveProfileValue(testProfile, "epic_no"), "TND1234567");
  assert.equal(resolveProfileValue(testProfile, "government ID"), "TND1234567");
  assert.equal(resolveProfileValue(testProfile, "govt_id"), "TND1234567");
});

test("tokenizer mints appropriate tokens for identity fields", () => {
  const v = new Vault();
  const map = v.addProfile({
    "Aadhaar number": "2345 6789 0123",
    "PAN": "ABCDE1234F",
    "Passport number": "A1234567",
    "Voter ID": "TND1234567",
  });
  assert.equal(map["Aadhaar number"], "[AADHAAR_1]");
  assert.equal(map["PAN"], "[PAN_1]");
  assert.equal(map["Passport number"], "[PASSPORT_1]");
  assert.equal(map["Voter ID"], "[VOTERID_1]");
});

test("security policy detects and blocks egress leak of identity profile fields", () => {
  const profile = {
    "Aadhaar number": "2345 6789 0123",
    "PAN": "ABCDE1234F",
    "Passport number": "A1234567",
    "Voter ID": "TND1234567",
  };

  // Test Aadhaar leak detection
  const rAadhaar = classifyPayload({ text: "Sending Aadhaar 2345 6789 0123" }, { profile });
  assert.equal(rAadhaar.decision, "BLOCK");
  assert.equal(rAadhaar.classification, "SECRET");

  // Test PAN leak detection
  const rPan = classifyPayload({ text: "Sending PAN ABCDE1234F" }, { profile });
  assert.equal(rPan.decision, "BLOCK");
  assert.equal(rPan.classification, "SECRET");

  // Test Passport leak detection
  const rPassport = classifyPayload({ text: "Sending Passport A1234567" }, { profile });
  assert.equal(rPassport.decision, "BLOCK");
  assert.equal(rPassport.classification, "SECRET");

  // Test Voter ID leak detection
  const rVoter = classifyPayload({ text: "Sending Voter ID TND1234567" }, { profile });
  assert.equal(rVoter.decision, "BLOCK");
  assert.equal(rVoter.classification, "SECRET");
});
