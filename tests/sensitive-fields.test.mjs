import test from "node:test";
import assert from "node:assert/strict";

import {
  SENSITIVE_PATTERNS,
  CENSORED_CATEGORIES,
  isSensitiveCategory,
  isSensitiveText,
} from "../client/lib/sensitive-fields.mjs";

// ═══════════════════════════════════════════════════════════════════════════
// Word-boundary / Non-PII: labels that MUST NOT match
// ═══════════════════════════════════════════════════════════════════════════

const MUST_NOT_MATCH = [
  "Search",
  "Quantity",
  "Promo Code",
  "Coupon Code",
  "Filter Results",
  "Japan",       // contains `pan`
  "Epicurean",   // contains `epic`
  "expand",      // contains `pan`
  "Bankruptcy",  // contains `bank`
  "Panther",     // contains `pan`
  "cupid",       // contains `upi`
  "Duplicator",  // contains `upi`
  "Episcopal",   // contains `epic`
  "Sublicense Agreement",
];

test("SENSITIVE_PATTERNS must NOT match non-PII field labels", () => {
  for (const label of MUST_NOT_MATCH) {
    assert.equal(
      SENSITIVE_PATTERNS.test(label),
      false,
      `"${label}" should NOT match SENSITIVE_PATTERNS but did`
    );
  }
});

// ═══════════════════════════════════════════════════════════════════════════
// True positives: all PII categories that MUST match
// ═══════════════════════════════════════════════════════════════════════════

const MUST_MATCH = [
  // Government & National Identifiers
  "Aadhaar Number",
  "PAN Number",
  "Voter ID",
  "Passport Number",
  "SSN",
  "Driver License Number",
  "GSTIN",

  // Financial & Payment Data
  "Credit Card Number",
  "Credit Card Type",
  "Card Verification Code (CVV)",
  "Card Expiration Date",
  "Card User Name",
  "Card Issuing Bank",
  "Card Customer Service Phone",
  "IFSC Code",
  "UPI ID",
  "Bank Account Number",
  "Annual Income",

  // Personal & Demographic Information
  "First Name",
  "Middle Initial",
  "Last Name",
  "Full Name",
  "Date of Birth (DOB)",
  "Age",
  "Birth Place",
  "Sex / Gender",
  "Title",

  // Contact & Location Data
  "Address Line 1",
  "Address Line 2",
  "City",
  "State / Province",
  "Country",
  "Zip / Postal Code",
  "Home Phone",
  "Work Telephone",
  "Cell Phone",
  "Fax",
  "Email",

  // Digital, Technical & Employment Identifiers
  "IPv4 Address",
  "User ID",
  "Username",
  "Password",
  "Web Site",
  "Company",
  "Position",

  // Miscellaneous
  "Vehicle Registration",
  "Custom Messages and Comments",
];

test("SENSITIVE_PATTERNS MUST match all comprehensive PII field labels", () => {
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

test("isSensitiveCategory returns false for safe non-PII categories", () => {
  const safe = ["search", "promo", "quantity", "filter", null, undefined, ""];
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
  assert.equal(isSensitiveText("aadhaar_number uid-field Enter your Aadhaar text"), true);
  assert.equal(isSensitiveText("pan_input pancard-field Enter PAN text"), true);
  assert.equal(isSensitiveText("company_name company Enter company name text"), true);
  assert.equal(isSensitiveText("first_name fname First Name text"), true);
  assert.equal(isSensitiveText("city_field city City text"), true);
  assert.equal(isSensitiveText("05_company label Company text"), true);
  assert.equal(isSensitiveText("search_query q Enter search text"), false);
  assert.equal(isSensitiveText("promo_code coupon Enter discount text"), false);
});

// ═══════════════════════════════════════════════════════════════════════════
// Parity test: sensitive-fields.js (IIFE) must match sensitive-fields.mjs (ESM)
// ═══════════════════════════════════════════════════════════════════════════

import vm from "node:vm";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));

test("sensitive-fields.js (content script IIFE) and sensitive-fields.mjs (ESM) must be identical", () => {
  const jsPath = path.join(__dirname, "../client/lib/sensitive-fields.js");
  const jsContent = fs.readFileSync(jsPath, "utf8");

  const context = { window: {} };
  vm.createContext(context);
  vm.runInContext(jsContent, context);

  const windowPL = context.window.__PL;
  assert.ok(windowPL, "window.__PL should be defined by sensitive-fields.js");

  // Compare RESTRICTED_PII_CATEGORIES
  assert.deepEqual(
    Array.from(windowPL.RESTRICTED_PII_CATEGORIES).sort(),
    Array.from(CENSORED_CATEGORIES).sort(),
    "RESTRICTED_PII_CATEGORIES in sensitive-fields.js must match sensitive-fields.mjs"
  );

  // Compare SENSITIVE_PATTERNS regex source & flags
  assert.equal(
    windowPL.SENSITIVE_PATTERNS.source,
    SENSITIVE_PATTERNS.source,
    "SENSITIVE_PATTERNS regex source must match"
  );
  assert.equal(
    windowPL.SENSITIVE_PATTERNS.flags,
    SENSITIVE_PATTERNS.flags,
    "SENSITIVE_PATTERNS regex flags must match"
  );
});
