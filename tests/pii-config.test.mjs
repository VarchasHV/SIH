// Phase 3 — config structure + new-rule checksum logic (validated independently
// of the corpus generator).

import test from "node:test";
import assert from "node:assert/strict";

import { REGEX_RULES, CONTEXT, NEGATIVE_CONTEXT, CATEGORIES, IFSC_BANKS, RTO_STATES } from "../client/lib/pii-config.mjs";
import {
  verhoeffValid, luhnValid, cardIinOk, ssnValid,
  ibanValid, sha256, base58Decode, btcLegacyValid, bech32Valid, ninoValid,
} from "../client/lib/pii-checksums.mjs";
import { detectPII } from "../client/lib/pii-rules.mjs";

const hex = (u8) => Buffer.from(u8).toString("hex");
const has = (t, c, opts) => detectPII(t, opts).some((h) => h.category === c);

// ── config structure ────────────────────────────────────────────────────

test("REGEX_RULES load with the expected shape", () => {
  assert.ok(Array.isArray(REGEX_RULES) && REGEX_RULES.length >= 14);
  for (const r of REGEX_RULES) {
    assert.equal(typeof r.category, "string", "category is a string");
    assert.ok(r.re instanceof RegExp, `${r.category}: re is a RegExp`);
    assert.ok(r.re.flags.includes("g"), `${r.category}: re is global`);
    assert.equal(typeof r.base, "number", `${r.category}: base is a number`);
    assert.ok(r.base >= 0 && r.base <= 1, `${r.category}: base in [0,1]`);
    if (r.validate) assert.equal(typeof r.validate, "function");
    if (r.strongIf) assert.equal(typeof r.strongIf, "function");
  }
});

test("every gated category has a CONTEXT entry", () => {
  for (const r of REGEX_RULES) {
    if (r.gate || r.softGate) {
      assert.ok(CONTEXT[r.category] instanceof RegExp, `${r.category} needs a CONTEXT keyword regex`);
    }
  }
  // numeric-run categories too
  for (const c of ["aadhaar", "credit-card", "phone-in"]) {
    assert.ok(CONTEXT[c] instanceof RegExp, `${c} needs a CONTEXT keyword regex`);
  }
});

test("no duplicate CATEGORIES; a category may still have >1 rule (btc)", () => {
  assert.deepEqual([...CATEGORIES].sort(), [...new Set(CATEGORIES)].sort());
  const btcRules = REGEX_RULES.filter((r) => r.category === "btc-address");
  assert.equal(btcRules.length, 2, "btc has legacy + bech32 rules");
});

test("the 14 original categories are all still present", () => {
  for (const c of [
    "aadhaar", "credit-card", "phone-in", "email", "pan", "gstin", "ifsc",
    "upi-vpa", "voter-id", "vehicle-reg", "passport-in", "ssn", "ipv4", "dob",
  ]) {
    assert.ok(CATEGORIES.includes(c), `missing ${c}`);
  }
});

test("Phase 3 added exactly the curated set", () => {
  const added = CATEGORIES.filter((c) => !["aadhaar","credit-card","phone-in","email","pan","gstin","ifsc","upi-vpa","voter-id","vehicle-reg","passport-in","ssn","ipv4","dob"].includes(c));
  assert.deepEqual(added.sort(), ["btc-address", "eth-address", "iban", "uk-nino"]);
});

test("allow-lists still intact after externalisation", () => {
  assert.ok(IFSC_BANKS.has("SBIN") && IFSC_BANKS.has("HDFC"));
  assert.ok(RTO_STATES.has("KA") && RTO_STATES.has("MH"));
});

// ── checksum primitives: known-answer vectors ───────────────────────────

test("SHA-256 known-answer vectors", () => {
  assert.equal(hex(sha256(new Uint8Array(0))), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
  assert.equal(hex(sha256(new TextEncoder().encode("abc"))), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
});

test("Verhoeff / Luhn / IIN unchanged by the move", () => {
  assert.equal(verhoeffValid("234567890124"), true);
  assert.equal(verhoeffValid("234567890123"), false);
  assert.equal(luhnValid("4111111111111111"), true);
  assert.equal(luhnValid("4111111111111112"), false);
  assert.equal(cardIinOk("378282246310005"), true);
  assert.equal(cardIinOk("490154203237518"), false);
  assert.equal(ssnValid("123-45-6789"), true);
  assert.equal(ssnValid("000-45-6789"), false);
});

test("IBAN mod-97: real test vectors accepted, tampered rejected", () => {
  for (const ok of ["GB82WEST12345698765432", "DE89370400440532013000", "FR1420041010050500013M02606", "NO9386011117947"]) {
    assert.equal(ibanValid(ok), true, ok);
    assert.equal(ibanValid(ok.replace(/\s/g, "")), true);
  }
  assert.equal(ibanValid("GB82 WEST 1234 5698 7654 32"), true, "grouped form");
  assert.equal(ibanValid("GB82WEST12345698765433"), false, "check digit tampered");
  assert.equal(ibanValid("GB82WEST1234569876543"), false, "one digit short for GB");
  assert.equal(ibanValid("ZZ00NOTACOUNTRY0000000"), false, "unknown country code");
});

test("Bitcoin base58check: genesis address valid, one-char flip invalid", () => {
  assert.equal(btcLegacyValid("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"), true);       // block 0 coinbase
  assert.equal(btcLegacyValid("3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy"), true);       // P2SH BIP-16 vector
  assert.equal(btcLegacyValid("1A1zP1eP5QGefi2DMPTfTL5SLmv7Divfna"), false);      // last char flipped
  assert.equal(btcLegacyValid("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfN0"), false);      // '0' not in base58
  assert.equal(base58Decode("1A1zP1eP5QGefi2DMPTfTL5SLmv7Div0Na"), null);         // invalid alphabet
});

test("Bitcoin bech32 / bech32m: BIP-173 & BIP-350 vectors", () => {
  assert.equal(bech32Valid("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"), true);   // P2WPKH
  assert.equal(bech32Valid("bc1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qccfmv3"), true); // P2WSH
  assert.equal(bech32Valid("bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0"), true); // taproot, bech32m
  assert.equal(bech32Valid("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t5"), false);  // checksum flipped
  assert.equal(bech32Valid("bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj1"), false);
  assert.equal(bech32Valid("BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4"), false, "mixed/upper rejected (we only take lowercase)");
});

test("UK NINo structural rules", () => {
  assert.equal(ninoValid("AB123456C"), true);
  assert.equal(ninoValid("AB 12 34 56 C"), true);
  assert.equal(ninoValid("QQ123456A"), false, "Q not allowed as first letter");
  assert.equal(ninoValid("DA123456A"), false, "D not allowed as first letter");
  assert.equal(ninoValid("AO123456A"), false, "O not allowed as second letter");
  assert.equal(ninoValid("BG123456A"), false, "BG is a disallowed prefix");
  assert.equal(ninoValid("AB123456E"), false, "suffix must be A-D");
});

// ── new rules through the engine: true positives + FP resistance ────────

test("IBAN: strong on checksum, near a bank keyword or bare", () => {
  assert.ok(has("transfer to IBAN GB82WEST12345698765432 today", "iban"));
  assert.ok(has("GB82 WEST 1234 5698 7654 32", "iban"), "grouped, bare");
  assert.equal(has("order REF GB82WEST12345698765433 shipped", "iban"), false, "bad checksum, not flagged");
});

test("Bitcoin: checksummed address flagged with or without context; junk is not", () => {
  assert.ok(has("donate 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa please", "btc-address"));
  assert.ok(has("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4", "btc-address"), "bare bech32");
  assert.equal(has("commit 1A1zP1eP5QGefi2DMPTfTL5SLmv7Divfna landed", "btc-address"), false, "bad checksum");
  assert.equal(has("var x = 3Kx8sB9nT2wQ0abcдеf; // not base58", "btc-address"), false);
});

test("Ethereum: hard context gate — bare 0x-hex in code/logs is NOT flagged", () => {
  assert.ok(has("send 2 ETH to wallet 0x52908400098527886E0F7030069857D2E4169EE7", "eth-address"));
  assert.equal(has("git show 0x52908400098527886e0f7030069857d2e4169ee7abcd", "eth-address"), false, "64-ish hex, no addr shape");
  assert.equal(has("revert commit 0x52908400098527886e0f7030069857d2e4169ee7 now", "eth-address"), false, "commit keyword, no wallet keyword");
  assert.ok(has("git show 0x52908400098527886e0f7030069857d2e4169ee7", "eth-address", { minConfidence: 0 }), "still visible to a show-all caller");
});

test("UK NINo: needs the keyword; licence/reference lookalikes pass through", () => {
  assert.ok(has("National Insurance number AB123456C", "uk-nino"));
  assert.equal(has("membership card AB123456C expires 2027", "uk-nino"), false);
  assert.equal(has("NI number BG123456C", "uk-nino"), false, "keyword present but invalid prefix");
});

test("new rules do not fire on ordinary code / terminal / UI-chrome text", () => {
  const noise = [
    "const API_URL = 'https://api.example.com/v2/users';",
    "  at Object.<anonymous> (/app/src/index.js:42:15)",
    "HTTP/1.1 200 OK  content-length: 15234  x-request-id: 7f3a9c2e",
    "npm WARN deprecated core-js@2.6.12: core-js@<3.23.3 is no longer maintained",
    "Build #4821 passed in 3m12s on commit a1b2c3d4e5f6",
    "SELECT id, name FROM accounts WHERE created_at > '2026-01-01' LIMIT 100;",
    "Save   Cancel   Settings   Profile   Sign out",
    "0x1F  0xFF  0xDEAD_BEEF  0x00400000",
    "container 3f8a9c2e1b4d started; image sha256:9c1e...ab",
  ];
  for (const t of noise) {
    const cats = detectPII(t).map((h) => h.category);
    for (const c of ["iban", "btc-address", "eth-address", "uk-nino"]) {
      assert.equal(cats.includes(c), false, `${c} fired on: ${t}`);
    }
  }
});
