// Phase 3 — secret scanner.
//
// NOTE: this file must not contain any contiguous credential-shaped literal, or
// it trips repository push-protection / secret scanners. Every test fixture is
// assembled at runtime from obviously-synthetic fragments via syn(). None of
// these are, or resemble, a real credential.

import test from "node:test";
import assert from "node:assert/strict";
import { scanSecrets, shannonEntropy, maskSecret } from "../client/lib/secret-scanner.mjs";

const cats = (t, opts) => scanSecrets(t, opts).map((f) => f.subtype);
const syn = (...parts) => parts.join("");
const R = (ch, n) => ch.repeat(n);

// synthetic, non-functional fixtures (each matches a pattern in secret-scanner.mjs)
const FX = {
  aws: syn("AKIA", "EXAMPLEKEY0000AB"),                         // AKIA + 16 [0-9A-Z]
  github: syn("ghp", "_", R("x", 36)),                           // ghp_ + 36 chars
  stripe: syn("sk", "_", "test", "_", R("0", 24)),               // TEST key, not live
  gcp: syn("AIza", R("0", 35)),
  jwt: syn("eyJ", R("0", 14), ".", "eyJ", R("0", 14), ".", R("0", 20)),
  pem: syn("-----BEGIN ", "RSA ", "PRIVATE KEY", "-----"),        // header only, no key body
  db: syn("postgres", "://", "u", ":", "p", "@", "db.example:5432/x"),
  // high-entropy but not a vendor pattern
  entropyTok: syn("aA1bB2", "cC3dD4", "eE5fF6", "gG7hH8", "iI9jJ0", "kKlLmM"),
};

test("structured vendor secrets are detected at high confidence", () => {
  const cases = [
    [FX.aws, "aws_access_key_id"],
    [FX.github, "github_token"],
    [FX.stripe, "stripe_secret_key"],
    [FX.gcp, "gcp_api_key"],
    [FX.jwt, "jwt"],
    [FX.pem, "private_key_pem"],
    [FX.db, "db_connection_string"],
  ];
  for (const [text, want] of cases) {
    const f = scanSecrets(`config: ${text}`);
    assert.ok(f.some((x) => x.subtype === want), `${want} not found -> ${JSON.stringify(f.map((y) => y.subtype))}`);
    for (const x of f) assert.equal(x.evidence.includes(text), false, "evidence must be masked");
  }
});

test("evidence is masked, never the raw secret", () => {
  const [f] = scanSecrets(`api_key = ${FX.aws}`);
  assert.ok(f);
  assert.equal(f.evidence.includes(FX.aws), false);
  assert.match(f.evidence, /^AKIA…/);
  assert.equal("value" in f, false);
});

test("high entropy ALONE is not flagged; entropy + context is", () => {
  const token = FX.entropyTok; // ~4.9 bits/char, 36 chars
  assert.ok(shannonEntropy(token) > 3.6);
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
  assert.equal(
    scanSecrets(`example api_key: ${FX.aws} (replace with yours)`).filter((f) => f.confidence >= 0.6).length,
    0,
  );
});

test("fieldSecret raises confidence for a bare token from a credential-typed input", () => {
  const token = syn("Qk8vRm", "3nX7pL", "wN2bT8", "cH4jF6", "sD1gA5", "eYbc");
  assert.equal(scanSecrets(token).length, 0);
  const withField = scanSecrets(token, { fieldSecret: true });
  assert.ok(withField.some((f) => f.confidence >= 0.6));
});

test("action is derived from confidence", () => {
  for (const f of scanSecrets(`token ${FX.aws} and Bearer ${R("a", 20)}${R("1", 10)}`)) {
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
