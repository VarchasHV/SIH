import test from "node:test";
import assert from "node:assert/strict";

import {
  SENSITIVE_PATTERNS,
  CENSORED_CATEGORIES,
  isSensitiveCategory,
  isSensitiveText,
} from "../client/lib/sensitive-fields.js";

// ═══════════════════════════════════════════════════════════════════════════
// Word-boundary regression: labels that MUST NOT match
// ═══════════════════════════════════════════════════════════════════════════

const MUST_NOT_MATCH = [
  "Company",     // previously matched `pan`
  "Position",
  "City",
  "State",
  "Country",
  "Full Name",
  "Web Site",
  "Japan",       // previously matched `pan`
  "Epicurean",   // previously matched `epic`
  "expand",      // previously matched `pan`
  "Bankruptcy",  // previously matched `bank`
  "Panther",     // previously matched `pan`
  "cupid",       // previously matched `upi`
  "Duplicator",  // previously matched `upi`
  "Episcopal",   // previously matched `epic`
  "Sublicense Agreement",  // previously matched `license` inside "sublicense" — but \blicense\b still matches "Sublicense" because "license" starts at a word boundary inside it
];

// NOTE: "Sublicense Agreement" is a tricky edge case. The word "Sublicense"
// does NOT contain `license` at a \b boundary (it's mid-word), so \blicense\b
// won't match it. We keep it in the must-not-match list.

test("SENSITIVE_PATTERNS must NOT match ordinary field labels", () => {
  for (const label of MUST_NOT_MATCH) {
    assert.equal(
      SENSITIVE_PATTERNS.test(label),
      false,
      `"${label}" should NOT match SENSITIVE_PATTERNS but did`
    );
  }
});

// ═══════════════════════════════════════════════════════════════════════════
// True positives: labels that MUST match
// ═══════════════════════════════════════════════════════════════════════════

const MUST_MATCH = [
  "Aadhaar Number",
  "PAN Number",
  "SSN",
  "Credit Card Number",
  "CVV",
  "IFSC Code",
  "UPI ID",
  "Passport Number",
  "Bank Account Number",
  "Password",
  "password",
  "Enter your PAN",
  "Enter your SSN",
  "Enter your CVV",
  "IFSC",
  "UPI",
  "voter_id",
  "govt_id",
  "national_id",
  "epic",
  "driver",
  "license",
  "Driver License Number",
];

test("SENSITIVE_PATTERNS MUST match sensitive field labels", () => {
  for (const label of MUST_MATCH) {
    assert.equal(
      SENSITIVE_PATTERNS.test(label),
      true,
      `"${label}" SHOULD match SENSITIVE_PATTERNS but did not`
    );
  }
});

// ═══════════════════════════════════════════════════════════════════════════
// isSensitiveCategory — covers every CENSORED_CATEGORIES entry
// ═══════════════════════════════════════════════════════════════════════════

test("isSensitiveCategory returns true for every CENSORED_CATEGORIES entry", () => {
  for (const cat of CENSORED_CATEGORIES) {
    assert.equal(
      isSensitiveCategory(cat),
      true,
      `isSensitiveCategory("${cat}") should be true`
    );
  }
});

test("isSensitiveCategory returns false for safe categories", () => {
  const safe = ["first name", "last name", "email", "phone number", "address", "postal/ZIP code", null, undefined, ""];
  for (const cat of safe) {
    assert.equal(
      isSensitiveCategory(cat),
      false,
      `isSensitiveCategory(${JSON.stringify(cat)}) should be false`
    );
  }
});

// ═══════════════════════════════════════════════════════════════════════════
// isSensitiveText — integration test with concatenated attribute strings
// ═══════════════════════════════════════════════════════════════════════════

test("isSensitiveText detects sensitive substrings in combined attribute text", () => {
  // Simulates: [name, id, placeholder, aria-label, type].join(" ")
  assert.equal(isSensitiveText("aadhaar_number uid-field Enter your Aadhaar text"), true);
  assert.equal(isSensitiveText("pan_input pancard-field Enter PAN text"), true);
  assert.equal(isSensitiveText("company_name company Enter company name text"), false);
  assert.equal(isSensitiveText("first_name fname First Name text"), false);
  assert.equal(isSensitiveText("city_field city City text"), false);
});

test("isSensitiveText does not false-positive on safe field combinations", () => {
  const safeFields = [
    "company comp Company Name text",
    "position pos Job Position text",
    "state_field state State / Province text",
    "country_code country Country text",
    "website url Web Site text",
    "full_name fullname Full Name text",
  ];
  for (const text of safeFields) {
    assert.equal(
      isSensitiveText(text),
      false,
      `isSensitiveText("${text}") should be false`
    );
  }
});
