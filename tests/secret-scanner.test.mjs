// Phase 3 — secret scanner.

import test from "node:test";
import assert from "node:assert/strict";
import { scanSecrets, shannonEntropy, maskSecret } from "../client/lib/secret-scanner.mjs";

const cats = (t, opts) => scanSecrets(t, opts).map((f) => f.subtype);

test("structured vendor secrets are detected at high confidence", () => {
  const cases = [
    ["AKIAIOSFODNN7EXAMPLE", "aws_access_key_id"],
    ["ghp_1234567890abcdefghijklmnopqrstuvwxyz", "github_token"],
    ["sk_live_4eC39HqLyjWDarjtT1zdp7dcABCDEFGH", "stripe_secret_key"],
    ["AIza012345678901234567890123456789abcde", "gcp_api_key"],
    ["eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abcDEF123456ghiJKL", "jwt"],
    ["-----BEGIN RSA PRIVATE KEY-----", "private_key_pem"],
    ["postgres://admin:hunter2@db.internal:5432/prod", "db_connection_string"],
  ];
  for (const [text, want] of cases) {
    const f = scanSecrets(`config: ${text}`);
    assert.ok(f.some((x) => x.subtype === want), `${want} not found in "${text}" -> ${JSON.stringify(f.map((y) => y.subtype))}`);
    for (const x of f) assert.ok(!/EXAMPLE|hunter2|4eC39/.test(x.evidence), "evidence must be masked");
  }
});

test("evidence is masked, never the raw secret", () => {
  const [f] = scanSecrets("api_key = AKIAIOSFODNN7EXAMPLE");
  assert.ok(f);
  assert.doesNotMatch(f.evidence, /IOSFODNN7EXAM/);
  assert.match(f.evidence, /^AKIA…/);
  assert.equal("value" in f, false);
});

test("high entropy ALONE is not flagged; entropy + context is", () => {
  const token = "Zk9QvR3mX7pLwN2bT8cH4jF6sD1gA5eY0uI"; // random-ish, 35 chars
  assert.equal(cats(`the build hash is ${token} today`).length, 0, "no context -> not flagged at default threshold");
  const withCtx = scanSecrets(`client_secret: ${token}`);
  assert.ok(withCtx.some((f) => /high_entropy_with_context|generic_api_key_kv/.test(f.subtype)), JSON.stringify(withCtx));
});

test("obvious non-secrets are ignored", () => {
  for (const s of [
    "d41d8cd98f00b204e9800998ecf8427e",                 // md5 hex
    "550e8400-e29b-41d4-a716-446655440000",             // uuid
    "1234567890123456789012345",                        // digits
    "https://example.com/path/to/a/very/long/resource", // url path
    "Lorem ipsum dolor sit amet consectetur adipiscing", // prose
  ]) {
    assert.equal(scanSecrets(s).length, 0, `false positive on "${s}"`);
  }
});

test("negative context (example / placeholder) lowers confidence below threshold", () => {
  assert.equal(scanSecrets("example api_key: AKIAIOSFODNN7EXAMPLE (replace with yours)").filter((f) => f.confidence >= 0.6).length, 0);
});

test("fieldSecret raises confidence for a bare token from a credential-typed input", () => {
  const token = "Qk8vRm3nX7pLwN2bT8cH4jF6sD1gA5eYbc";
  assert.equal(scanSecrets(token).length, 0);
  const withField = scanSecrets(token, { fieldSecret: true });
  assert.ok(withField.some((f) => f.confidence >= 0.6));
});

test("action is derived from confidence", () => {
  for (const f of scanSecrets("token AKIAIOSFODNN7EXAMPLE and Bearer abcdefghijklmnopqrstuvwxyz012345")) {
    assert.ok(["block", "require_approval", "flag"].includes(f.action));
    if (f.confidence >= 0.85) assert.equal(f.action, "block");
  }
});

test("shannonEntropy + maskSecret sanity", () => {
  assert.ok(shannonEntropy("aaaaaaaa") < 0.5);
  assert.ok(shannonEntropy("aB3$xK9!") > 2.5);
  assert.equal(maskSecret("abcd"), "****");
  assert.match(maskSecret("abcdefghijklmnop"), /^abcd…\*+…mnop$/);
});
