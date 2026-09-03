// Phase 2 — proves the benchmark's independent ground-truth generators are
// correct and are NOT circular with the detector under test.

import test from "node:test";
import assert from "node:assert/strict";

import {
  makeRng,
  isValidVerhoeff,
  verhoeffCheckDigit,
  isValidLuhn,
  luhnCheckDigit,
  isValidPAN,
  isValidSSN,
  genAadhaar,
  genCard,
  genLuhnNonCard,
  genPAN,
  genNonPAN,
  genSSN,
  genInvalidSSN,
  genIPv4,
  genIBAN,
  genIBANBadChecksum,
  ibanChecksumValid,
  genBtcLegacy,
  genBtcLegacyBad,
  genBtcBech32,
  genBtcBech32Bad,
  base58CheckValid,
  bech32CheckValid,
  genNINo,
  genNINoBad,
  ninoStructValid,
} from "../eval/bench/lib/independent-validators.mjs";

// The detector under test — imported HERE (in the test), never in the generator.
import { detectPII } from "../client/lib/pii-rules.mjs";

// ── Known-answer vectors (anchor: this is a *correct* Verhoeff / Luhn) ──────

test("Verhoeff: published known-answer vectors", () => {
  // Wikipedia: Verhoeff("236") -> check digit 3, so "2363" validates.
  assert.equal(verhoeffCheckDigit("236"), 3);
  assert.equal(isValidVerhoeff("2363"), true);
  assert.equal(isValidVerhoeff("2364"), false);
  assert.equal(isValidVerhoeff("2353"), false);
  // a couple more derived + round-tripped
  for (const body of ["23", "1234", "142857", "998877665544"]) {
    const full = body + verhoeffCheckDigit(body);
    assert.equal(isValidVerhoeff(full), true, `round-trip ${body}`);
  }
});

test("Luhn: published known-answer vectors", () => {
  assert.equal(isValidLuhn("4111111111111111"), true); // canonical Visa test number
  assert.equal(isValidLuhn("4111111111111112"), false);
  assert.equal(isValidLuhn("79927398713"), false); // 11 digits — below card length
  assert.equal(luhnCheckDigit("7992739871"), 3);
});

// ── Generated Aadhaar are valid; single-digit mutations are rejected ───────

test("genAadhaar: 5000 samples all pass the independent Verhoeff validator", () => {
  const rng = makeRng(20260902);
  for (let i = 0; i < 5000; i++) {
    const a = genAadhaar(rng);
    assert.equal(a.length, 12);
    assert.equal(isValidVerhoeff(a), true, `sample ${i}: ${a}`);
  }
});

test("Aadhaar: every single-digit mutation of a valid number fails Verhoeff", () => {
  // Verhoeff's defining property: detects 100% of single-digit errors.
  const rng = makeRng(1);
  for (let i = 0; i < 300; i++) {
    const a = genAadhaar(rng);
    for (let pos = 0; pos < 12; pos++) {
      for (let d = 0; d <= 9; d++) {
        if (String(d) === a[pos]) continue;
        const mutated = a.slice(0, pos) + d + a.slice(pos + 1);
        assert.equal(isValidVerhoeff(mutated), false,
          `mutation at ${pos} -> ${d} of ${a} should be invalid`);
      }
    }
  }
});

test("random 12-digit strings pass Verhoeff at ~1/10 (documents the base rate)", () => {
  const rng = makeRng(42);
  let valid = 0;
  const N = 20000;
  for (let i = 0; i < N; i++) {
    const s = Array.from({ length: 12 }, () => Math.floor(rng() * 10)).join("");
    if (isValidVerhoeff(s)) valid++;
  }
  const rate = valid / N;
  assert.ok(rate > 0.08 && rate < 0.12, `base rate ${rate} outside [0.08,0.12]`);
});

// ── Generated cards are Luhn-valid; non-cards are Luhn-valid but not cards ─

test("genCard: 3000 samples all pass the independent Luhn validator", () => {
  const rng = makeRng(20260902);
  for (let i = 0; i < 3000; i++) {
    const c = genCard(rng);
    assert.equal(isValidLuhn(c), true, `sample ${i}: ${c}`);
    assert.ok([13, 14, 15, 16].includes(c.length));
  }
});

test("genLuhnNonCard: Luhn-valid but outside every card IIN family", () => {
  const rng = makeRng(7);
  for (let i = 0; i < 1000; i++) {
    const n = genLuhnNonCard(rng, 15);
    assert.equal(isValidLuhn(n), true);
    assert.equal(/^(4|5[1-5]|3[47]|6011|60|65|81|508|2[2-7]|3[068])/.test(n), false, n);
  }
});

// ── Structural generators ────────────────────────────────────────────────

test("genPAN valid, genNonPAN invalid (holder-type char)", () => {
  const rng = makeRng(3);
  for (let i = 0; i < 1000; i++) {
    assert.equal(isValidPAN(genPAN(rng)), true);
    assert.equal(isValidPAN(genNonPAN(rng)), false);
  }
});

test("genSSN valid, genInvalidSSN violates an allocation rule", () => {
  const rng = makeRng(5);
  for (let i = 0; i < 1000; i++) {
    assert.equal(isValidSSN(genSSN(rng)), true);
    assert.equal(isValidSSN(genInvalidSSN(rng)), false);
  }
});

// ── Circularity check: generated positives are actually DETECTED ──────────
// (If the generator and detector disagreed systematically, the benchmark
//  would be meaningless. This ties the independent ground truth back to the
//  real detector without the generator ever importing it.)

test("generated valid Aadhaar are detected by the real detector (with a keyword)", () => {
  const rng = makeRng(20260902);
  let hit = 0;
  const N = 500;
  for (let i = 0; i < N; i++) {
    const a = genAadhaar(rng);
    const grouped = `${a.slice(0, 4)} ${a.slice(4, 8)} ${a.slice(8, 12)}`;
    const found = detectPII(`Aadhaar ${grouped} on file`).some((h) => h.category === "aadhaar");
    if (found) hit++;
  }
  // The detector should catch the overwhelming majority of checksum-valid,
  // keyworded Aadhaar. Allow a small margin for OCR-fix edge cases.
  assert.ok(hit / N > 0.97, `only ${hit}/${N} detected`);
});

test("generated valid cards are detected by the real detector (with a keyword)", () => {
  const rng = makeRng(20260902);
  let hit = 0;
  const N = 500;
  for (let i = 0; i < N; i++) {
    const c = genCard(rng);
    const found = detectPII(`card number ${c} charged`).some((h) => h.category === "credit-card");
    if (found) hit++;
  }
  assert.ok(hit / N > 0.95, `only ${hit}/${N} detected`);
});

// ── Phase 3: crypto / IBAN / NINo generators ────────────────────────────

test("Phase 3: independent crypto validators use a SEPARATE sha256 (node:crypto)", () => {
  // BIP-173 vector, checked by the eval-side implementation only.
  assert.equal(bech32CheckValid("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"), true);
  assert.equal(base58CheckValid("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"), true);
  assert.equal(ibanChecksumValid("GB82WEST12345698765432"), true);
});

test("genIBAN / genBtc* / genNINo: 2000 samples each valid, bad variants invalid", () => {
  const rng = makeRng(20260903);
  for (let i = 0; i < 2000; i++) {
    assert.equal(ibanChecksumValid(genIBAN(rng)), true);
    assert.equal(ibanChecksumValid(genIBANBadChecksum(rng)), false);
    assert.equal(base58CheckValid(genBtcLegacy(rng)), true);
    assert.equal(base58CheckValid(genBtcLegacyBad(rng)), false);
    assert.equal(bech32CheckValid(genBtcBech32(rng)), true);
    assert.equal(bech32CheckValid(genBtcBech32Bad(rng)), false);
    assert.equal(ninoStructValid(genNINo(rng)), true);
    assert.equal(ninoStructValid(genNINoBad(rng)), false);
  }
});

test("generated crypto/IBAN positives are detected by the real detector (keyworded)", () => {
  const rng = makeRng(20260903);
  let iban = 0, btc = 0;
  const N = 400;
  for (let i = 0; i < N; i++) {
    if (detectPII(`transfer to IBAN ${genIBAN(rng)}`).some((h) => h.category === "iban")) iban++;
    if (detectPII(`send bitcoin ${genBtcBech32(rng)}`).some((h) => h.category === "btc-address")) btc++;
  }
  assert.ok(iban / N > 0.98, `iban ${iban}/${N}`);
  assert.ok(btc / N > 0.98, `btc ${btc}/${N}`);
});

test("bad-checksum IBAN / BTC are NOT detected by the real detector", () => {
  const rng = makeRng(7);
  for (let i = 0; i < 300; i++) {
    assert.equal(detectPII(`IBAN ${genIBANBadChecksum(rng)}`).some((h) => h.category === "iban"), false);
    assert.equal(detectPII(`wallet ${genBtcLegacyBad(rng)}`).some((h) => h.category === "btc-address"), false);
  }
});

test("IPv4 addresses are NOT detected as Aadhaar by the real detector", () => {
  // Phase 3 regression, checked here too since genIPv4 lives in this module.
  const rng = makeRng(20260902);
  for (let i = 0; i < 500; i++) {
    const ip = genIPv4(rng);
    const cats = detectPII(`IP address ${ip} server host`).map((h) => h.category);
    assert.equal(cats.includes("aadhaar"), false, `${ip} flagged as aadhaar`);
  }
});
