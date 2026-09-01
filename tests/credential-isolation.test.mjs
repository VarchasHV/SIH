import test from "node:test";
import assert from "node:assert/strict";

import {
  RESTRICTED_PII_CATEGORIES,
  ALWAYS_REDACT_CATEGORIES,
  CREDENTIAL_CATEGORIES,
  SENSITIVE_PATTERNS,
  isAlwaysRedact,
  isCredentialCategory,
  isAlwaysRedactCategory,
} from "../client/lib/sensitive-fields.mjs";
import { classifySignals } from "../client/lib/field-classifier.mjs";
import { DLP_RULES, classifyFieldHeuristics, sanitizeParagraphText } from "../client/lib/dlp-heuristics.mjs";
import { detectPII } from "../client/lib/pii-rules.mjs";

// ═══════════════════════════════════════════════════════════════════════════
// 1. Deterministic Always-Redact for Autofilled & Credential Fields
// ═══════════════════════════════════════════════════════════════════════════

test("classifySignals treats autofilled fields as always-redact with 1.0 confidence", () => {
  // Autofilled input with completely obfuscated or unknown name/id
  const signals = {
    tagName: "input",
    type: "text",
    name: "x_01_val",
    id: "rnd_field_982",
    labelText: "",
    isAutofilled: true,
  };

  const res = classifySignals(signals);
  assert.ok(res, "Autofilled field must be classified");
  assert.equal(res.confidence, 1.0, "Autofilled field confidence must be deterministically 1.0");
  assert.equal(res.alwaysRedact, true, "Autofilled field must have alwaysRedact: true");
  assert.equal(res.isAutofilled, true);
});

test("classifySignals treats password and 2FA/OTP fields as always-redact", () => {
  // Password input
  const pwdSignals = {
    tagName: "input",
    type: "password",
    name: "unlabeled_auth",
    id: "f_pwd",
  };
  const pwdRes = classifySignals(pwdSignals);
  assert.ok(pwdRes);
  assert.equal(pwdRes.confidence, 1.0);
  assert.equal(pwdRes.alwaysRedact, true);
  assert.equal(pwdRes.category, "password");

  // 2FA/OTP input
  const otpSignals = {
    tagName: "input",
    type: "text",
    autocomplete: "one-time-code",
    name: "sec_code",
  };
  const otpRes = classifySignals(otpSignals);
  assert.ok(otpRes);
  assert.equal(otpRes.confidence, 1.0);
  assert.equal(otpRes.alwaysRedact, true);
  assert.equal(otpRes.category, "otp");
});

test("isAlwaysRedact helper accurately identifies credential and autofill signals", () => {
  assert.equal(isAlwaysRedact({ isAutofilled: true }), true);
  assert.equal(isAlwaysRedact({ type: "password" }), true);
  assert.equal(isAlwaysRedact({ autocomplete: "current-password" }), true);
  assert.equal(isAlwaysRedact({ autocomplete: "one-time-code" }), true);
  assert.equal(isAlwaysRedact({ category: "credential" }), true);
  assert.equal(isAlwaysRedact({ category: "otp" }), true);
  assert.equal(isAlwaysRedact({ category: "credit-card" }), true);
  assert.equal(isAlwaysRedact({ category: "first name" }), false);
  assert.equal(isAlwaysRedact({ type: "text", name: "search" }), false);
});

// ═══════════════════════════════════════════════════════════════════════════
// 2. DLP Heuristics & Token Injections for Secrets
// ═══════════════════════════════════════════════════════════════════════════

test("DLP heuristics classifies credentials and OTPs with dedicated tokens", () => {
  const otpField = classifyFieldHeuristics({
    name: "auth_otp_code",
    labelText: "Enter 2FA Code",
    type: "text",
  });
  assert.equal(otpField.isSensitive, true);
  assert.equal(otpField.category, "otp");
  assert.equal(otpField.token, "[TOKEN_OTP_2FA]");
  assert.equal(otpField.alwaysRedact, true);

  const credField = classifyFieldHeuristics({
    name: "api_key_secret",
    type: "text",
  });
  assert.equal(credField.isSensitive, true);
  assert.equal(credField.token, "[TOKEN_API_KEY]");
  assert.equal(credField.alwaysRedact, true);
});

test("sanitizeParagraphText redacts SSH private keys, API keys, and 2FA tokens", () => {
  const rawText = "Your 2FA code is: 849201. Please do not share.";
  const sanitized = sanitizeParagraphText(rawText);
  assert.ok(!sanitized.includes("849201"), "OTP digits must be sanitized");
  assert.ok(sanitized.includes("[TOKEN_OTP_2FA]") || sanitized.includes("[TEXT_REDACTED]"));

  const sshText = "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAA\n-----END OPENSSH PRIVATE KEY-----";
  const sshSanitized = sanitizeParagraphText(sshText);
  assert.ok(!sshSanitized.includes("b3BlbnNzaC"), "SSH key data must be sanitized");
  assert.ok(sshSanitized.includes("[TOKEN_SSH_KEY]") || sshSanitized.includes("[TEXT_REDACTED]"));
});

// ═══════════════════════════════════════════════════════════════════════════
// 3. OCR PII Rules Detection for 2FA/OTP and Secrets
// ═══════════════════════════════════════════════════════════════════════════

test("detectPII catches 2FA/OTP codes in OCR text when context is present", () => {
  const ocrLine = "Slack verification code: 492019 valid for 5 mins";
  const hits = detectPII(ocrLine);
  const otpHit = hits.find((h) => h.category === "otp");
  assert.ok(otpHit, "OTP hit must be detected");
  assert.equal(otpHit.value, "492019");
  assert.ok(otpHit.confidence >= 0.8);
});

test("detectPII catches Bearer tokens and API keys in OCR screen text", () => {
  const ocrLine = "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.doNotLeakThisSecretKey123";
  const hits = detectPII(ocrLine);
  const credHit = hits.find((h) => h.category === "credential");
  assert.ok(credHit, "Bearer token must be detected");
  assert.ok(credHit.confidence >= 0.9);
});
