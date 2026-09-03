// Independent validators + generators for structured Indian/global PII.
//
// PHASE 2 CONTRACT: this file MUST NOT import anything from `client/` or
// `server/`. Ground truth for the benchmark is produced here and verified
// here, with an implementation written separately from the detector under
// test. The Verhoeff implementation is anchored by a published known-answer
// vector (Verhoeff("236") -> check digit 3, so "2363" is valid) in
// tests/independent-validators.test.mjs, which proves it is a *correct*
// Verhoeff regardless of what the detector does.
//
// Generation strategy for checksum'd identifiers (Aadhaar, card):
//   1. draw the body digits at random
//   2. try every candidate check digit 0-9
//   3. keep the one for which the INDEPENDENT validator returns true
//   4. if none (shouldn't happen for Verhoeff/Luhn), redraw
// The detector is never consulted.

// ─────────────────────────────────────────────────────────────────────────
// seeded RNG (self-contained — no external dep)
// ─────────────────────────────────────────────────────────────────────────

export function makeRng(seed) {
  let s = seed >>> 0;
  return function rng() {
    s = (s + 0x6d2b79f5) | 0;
    let t = Math.imul(s ^ (s >>> 15), 1 | s);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}
const ri = (rng, n) => Math.floor(rng() * n);
const pick = (rng, arr) => arr[ri(rng, arr.length)];
const digitStr = (rng, n) => Array.from({ length: n }, () => ri(rng, 10)).join("");

// ─────────────────────────────────────────────────────────────────────────
// Verhoeff (D5 dihedral group) — independent implementation
// ─────────────────────────────────────────────────────────────────────────

const V_MUL = [
  [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
  [1, 2, 3, 4, 0, 6, 7, 8, 9, 5],
  [2, 3, 4, 0, 1, 7, 8, 9, 5, 6],
  [3, 4, 0, 1, 2, 8, 9, 5, 6, 7],
  [4, 0, 1, 2, 3, 9, 5, 6, 7, 8],
  [5, 9, 8, 7, 6, 0, 4, 3, 2, 1],
  [6, 5, 9, 8, 7, 1, 0, 4, 3, 2],
  [7, 6, 5, 9, 8, 2, 1, 0, 4, 3],
  [8, 7, 6, 5, 9, 3, 2, 1, 0, 4],
  [9, 8, 7, 6, 5, 4, 3, 2, 1, 0],
];
const V_PERM = [
  [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
  [1, 5, 7, 6, 2, 8, 3, 0, 9, 4],
  [5, 8, 0, 3, 7, 9, 6, 1, 4, 2],
  [8, 9, 1, 6, 0, 4, 3, 5, 2, 7],
  [9, 4, 5, 3, 1, 2, 6, 8, 7, 0],
  [4, 2, 8, 6, 5, 7, 3, 9, 0, 1],
  [2, 7, 9, 3, 8, 0, 6, 4, 1, 5],
  [7, 0, 4, 6, 9, 1, 3, 2, 5, 8],
];
/** True iff `num` (a digit string) carries a valid trailing Verhoeff check digit. */
export function isValidVerhoeff(num) {
  const s = String(num).replace(/\D/g, "");
  if (s.length < 2) return false;
  let c = 0;
  const rev = s.split("").reverse();
  for (let i = 0; i < rev.length; i++) c = V_MUL[c][V_PERM[i % 8][+rev[i]]];
  return c === 0;
}

/**
 * The Verhoeff check digit for a body of digits (no check digit yet).
 * Defined by brute force against isValidVerhoeff so the two can never drift.
 */
export function verhoeffCheckDigit(body) {
  const s = String(body).replace(/\D/g, "");
  for (let k = 0; k <= 9; k++) if (isValidVerhoeff(s + k)) return k;
  throw new Error(`verhoeffCheckDigit: no valid digit for "${s}" (impossible)`);
}

// ─────────────────────────────────────────────────────────────────────────
// Luhn — independent implementation
// ─────────────────────────────────────────────────────────────────────────

export function isValidLuhn(num) {
  const s = String(num).replace(/\D/g, "");
  if (s.length < 12 || s.length > 19) return false;
  let sum = 0;
  let dbl = false;
  for (let i = s.length - 1; i >= 0; i--) {
    let d = +s[i];
    if (dbl) { d += d; if (d > 9) d -= 9; }
    sum += d;
    dbl = !dbl;
  }
  return sum % 10 === 0;
}

export function luhnCheckDigit(body) {
  const s = String(body).replace(/\D/g, "");
  let sum = 0;
  let dbl = true; // the check digit will be at an even position from the right
  for (let i = s.length - 1; i >= 0; i--) {
    let d = +s[i];
    if (dbl) { d += d; if (d > 9) d -= 9; }
    sum += d;
    dbl = !dbl;
  }
  return (10 - (sum % 10)) % 10;
}

// ─────────────────────────────────────────────────────────────────────────
// structural validators (no checksum)
// ─────────────────────────────────────────────────────────────────────────

// PAN: AAAAA9999A. 4th char = holder type; 5th = first letter of surname/name.
const PAN_HOLDER_TYPES = "ABCFGHLJPT";
export function isValidPAN(s) {
  return /^[A-Z]{5}[0-9]{4}[A-Z]$/.test(s) && PAN_HOLDER_TYPES.includes(s[3]);
}

// IFSC: 4 letters + '0' + 6 alphanumerics.
export function isValidIFSCShape(s) {
  return /^[A-Z]{4}0[A-Z0-9]{6}$/.test(s);
}

// GSTIN: 2-digit state + 10-char PAN + entity digit + 'Z' + checksum char.
const GSTIN_STATE_CODES = new Set(
  Array.from({ length: 38 }, (_, i) => String(i + 1).padStart(2, "0")),
);
export function isValidGSTINShape(s) {
  if (!/^[0-9]{2}[A-Z]{5}[0-9]{4}[A-Z][0-9A-Z]Z[0-9A-Z]$/.test(s)) return false;
  return GSTIN_STATE_CODES.has(s.slice(0, 2)) && isValidPAN(s.slice(2, 12));
}

// US SSN: not area 000/666/900-999, not group 00, not serial 0000.
export function isValidSSN(s) {
  const m = /^(\d{3})-(\d{2})-(\d{4})$/.exec(s);
  if (!m) return false;
  const a = +m[1], g = +m[2], ser = +m[3];
  return a !== 0 && a !== 666 && a < 900 && g !== 0 && ser !== 0;
}

// ─────────────────────────────────────────────────────────────────────────
// generators — generate, then verify with the validators above
// ─────────────────────────────────────────────────────────────────────────

/** A 12-digit Aadhaar whose check digit the INDEPENDENT validator accepts. */
export function genAadhaar(rng) {
  for (let attempt = 0; attempt < 32; attempt++) {
    const body = String(1 + ri(rng, 9)) + digitStr(rng, 10); // no leading 0/1 per UIDAI
    const full = body + verhoeffCheckDigit(body);
    if (isValidVerhoeff(full)) return full;
  }
  throw new Error("genAadhaar: no valid Verhoeff after 32 attempts (impossible)");
}

const CARD_PREFIXES = {
  visa16: { iin: () => "4", len: 16 },
  visa13: { iin: () => "4", len: 13 },
  mc: { iin: (rng) => String(51 + ri(rng, 5)), len: 16 },
  mc2: { iin: (rng) => String(2221 + ri(rng, 499)), len: 16 },
  amex: { iin: (rng) => pick(rng, ["34", "37"]), len: 15 },
  discover: { iin: () => "6011", len: 16 },
  rupay: { iin: (rng) => pick(rng, ["60", "6521", "652", "81", "508"]), len: 16 },
  diners: { iin: (rng) => pick(rng, ["36", "38", "300", "305"]), len: 14 },
};

/** A Luhn-valid card number for a real IIN family. */
export function genCard(rng, brand) {
  const key = brand || pick(rng, Object.keys(CARD_PREFIXES));
  const spec = CARD_PREFIXES[key];
  const iin = spec.iin(rng);
  const body = iin + digitStr(rng, spec.len - iin.length - 1);
  const full = body + luhnCheckDigit(body);
  if (!isValidLuhn(full) || full.length !== spec.len) return genCard(rng, brand);
  return full;
}

/** A Luhn-valid number that is NOT a card (wrong IIN family) — for FP traps. */
export function genLuhnNonCard(rng, len = 15) {
  for (let attempt = 0; attempt < 64; attempt++) {
    const body = pick(rng, ["1", "7", "8", "9"]) + digitStr(rng, len - 2);
    const full = body + luhnCheckDigit(body);
    if (isValidLuhn(full) && !/^(4|5[1-5]|3[47]|6011|60|65|81|508|2[2-7]|3[068])/.test(full)) {
      return full;
    }
  }
  throw new Error("genLuhnNonCard: exhausted attempts");
}

const LETTERS = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const L = (rng) => LETTERS[ri(rng, 26)];
const Ls = (rng, n) => Array.from({ length: n }, () => L(rng)).join("");

export function genPAN(rng) {
  const s = Ls(rng, 3) + pick(rng, PAN_HOLDER_TYPES.split("")) + L(rng) + digitStr(rng, 4) + L(rng);
  return isValidPAN(s) ? s : genPAN(rng);
}
/** PAN-shaped but with an invalid holder-type 4th char. */
export function genNonPAN(rng) {
  const bad = "DEIKMNOQRSUVWXYZ";
  const s = Ls(rng, 3) + pick(rng, bad.split("")) + L(rng) + digitStr(rng, 4) + L(rng);
  return isValidPAN(s) ? genNonPAN(rng) : s;
}

const IFSC_REAL_BANKS = [
  "SBIN", "HDFC", "ICIC", "UTIB", "PUNB", "BARB", "CNRB", "IOBA", "CBIN", "UBIN",
  "MAHB", "KKBK", "YESB", "INDB", "IDIB", "IBKL", "FDRL", "RATN", "KOTA", "AUBL",
];
export function genIFSC(rng) {
  return pick(rng, IFSC_REAL_BANKS) + "0" + digitStr(rng, 6);
}
export function genFakeIFSC(rng) {
  let p;
  do { p = Ls(rng, 4); } while (IFSC_REAL_BANKS.includes(p));
  return p + "0" + digitStr(rng, 6);
}

export function genSSN(rng) {
  let a;
  do { a = 1 + ri(rng, 899); } while (a === 666);
  const g = 1 + ri(rng, 99);
  const ser = 1 + ri(rng, 9999);
  return `${String(a).padStart(3, "0")}-${String(g).padStart(2, "0")}-${String(ser).padStart(4, "0")}`;
}
/** SSN-shaped string that violates an allocation rule. */
export function genInvalidSSN(rng) {
  return pick(rng, [
    `000-${String(1 + ri(rng, 99)).padStart(2, "0")}-${String(1 + ri(rng, 9999)).padStart(4, "0")}`,
    `666-${String(1 + ri(rng, 99)).padStart(2, "0")}-${String(1 + ri(rng, 9999)).padStart(4, "0")}`,
    `${String(900 + ri(rng, 99)).padStart(3, "0")}-12-3456`,
    `${String(1 + ri(rng, 899)).padStart(3, "0")}-00-1234`,
    `${String(1 + ri(rng, 899)).padStart(3, "0")}-45-0000`,
  ]);
}

export function genGSTIN(rng) {
  const state = String(1 + ri(rng, 37)).padStart(2, "0");
  const pan = genPAN(rng);
  const s = state + pan + String(1 + ri(rng, 9)) + "Z" + pick(rng, (LETTERS + "0123456789").split(""));
  return isValidGSTINShape(s) ? s : genGSTIN(rng);
}

// A public/private IPv4 — adversarial negative for numeric-PII scanners.
export function genIPv4(rng) {
  const first = pick(rng, [10, 172, 192, 8, 1 + ri(rng, 223)]);
  return `${first}.${ri(rng, 256)}.${ri(rng, 256)}.${1 + ri(rng, 254)}`;
}

// ═════════════════════════════════════════════════════════════════════════
// Phase 3 — crypto addresses / IBAN / NINo
//
// Same contract: NOTHING here imports from client/. The SHA-256 used for
// Bitcoin base58check comes from node:crypto (a different implementation
// from client/lib/pii-checksums.mjs's hand-rolled one), so a bug shared
// between generator and detector is not possible. mod-97, the bech32
// polymod and the NINo rules are re-implemented here from their specs.
// ═════════════════════════════════════════════════════════════════════════

import { createHash } from "node:crypto";

const sha256d = (buf) => createHash("sha256").update(createHash("sha256").update(buf).digest()).digest();

// ---- base58 (encode + decode) -----------------------------------------
const B58_ALPHA = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
export function base58Encode(bytes) {
  let n = 0n;
  for (const b of bytes) n = n * 256n + BigInt(b);
  let out = "";
  while (n > 0n) { out = B58_ALPHA[Number(n % 58n)] + out; n /= 58n; }
  for (const b of bytes) { if (b === 0) out = "1" + out; else break; }
  return out;
}
export function base58CheckValid(str) {
  let n = 0n;
  for (const ch of str) {
    const v = B58_ALPHA.indexOf(ch);
    if (v < 0) return false;
    n = n * 58n + BigInt(v);
  }
  const bytes = [];
  while (n > 0n) { bytes.unshift(Number(n % 256n)); n /= 256n; }
  for (const ch of str) { if (ch === "1") bytes.unshift(0); else break; }
  if (bytes.length !== 25) return false;
  const body = Buffer.from(bytes.slice(0, 21));
  const chk = Buffer.from(bytes.slice(21));
  return sha256d(body).subarray(0, 4).equals(chk) && (bytes[0] === 0x00 || bytes[0] === 0x05);
}

/** A legacy P2PKH ('1') or P2SH ('3') mainnet address with a real checksum. */
export function genBtcLegacy(rng, kind) {
  const version = (kind || pick(rng, ["p2pkh", "p2sh"])) === "p2sh" ? 0x05 : 0x00;
  const hash160 = Buffer.from(Array.from({ length: 20 }, () => ri(rng, 256)));
  const payload = Buffer.concat([Buffer.from([version]), hash160]);
  const full = Buffer.concat([payload, sha256d(payload).subarray(0, 4)]);
  const addr = base58Encode(full);
  return base58CheckValid(addr) ? addr : genBtcLegacy(rng, kind);
}
/** base58 string of address shape whose checksum is wrong. */
export function genBtcLegacyBad(rng) {
  const good = genBtcLegacy(rng);
  const i = 1 + ri(rng, good.length - 1);
  let ch; do { ch = pick(rng, B58_ALPHA.split("")); } while (ch === good[i]);
  const bad = good.slice(0, i) + ch + good.slice(i + 1);
  return base58CheckValid(bad) ? genBtcLegacyBad(rng) : bad;
}

// ---- bech32 / bech32m -------------------------------------------------
const BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
const BECH32_GEN = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];
function bech32Polymod(values) {
  let chk = 1;
  for (const v of values) {
    const top = chk >>> 25;
    chk = ((chk & 0x1ffffff) << 5) ^ v;
    for (let i = 0; i < 5; i++) if ((top >> i) & 1) chk ^= BECH32_GEN[i];
  }
  return chk >>> 0;
}
function hrpExpand(hrp) {
  const a = [], b = [];
  for (const c of hrp) { a.push(c.charCodeAt(0) >> 5); b.push(c.charCodeAt(0) & 31); }
  return [...a, 0, ...b];
}
function convertBits(data, from, to, pad) {
  let acc = 0, bits = 0;
  const out = [];
  const maxv = (1 << to) - 1;
  for (const value of data) {
    acc = (acc << from) | value;
    bits += from;
    while (bits >= to) { bits -= to; out.push((acc >> bits) & maxv); }
  }
  if (pad && bits) out.push((acc << (to - bits)) & maxv);
  return out;
}
export function bech32Encode(hrp, witver, program, spec /* "bech32" | "bech32m" */) {
  const data = [witver, ...convertBits([...program], 8, 5, true)];
  const constant = spec === "bech32m" ? 0x2bc830a3 : 1;
  const values = [...hrpExpand(hrp), ...data];
  let polymod = bech32Polymod([...values, 0, 0, 0, 0, 0, 0]) ^ constant;
  const checksum = [];
  for (let i = 0; i < 6; i++) checksum.push((polymod >> (5 * (5 - i))) & 31);
  return hrp + "1" + [...data, ...checksum].map((d) => BECH32_CHARSET[d]).join("");
}
export function bech32CheckValid(addr) {
  const s = String(addr);
  if (s !== s.toLowerCase()) return false;
  const pos = s.lastIndexOf("1");
  if (pos < 1) return false;
  const hrp = s.slice(0, pos);
  const data = [];
  for (const ch of s.slice(pos + 1)) {
    const d = BECH32_CHARSET.indexOf(ch);
    if (d < 0) return false;
    data.push(d);
  }
  if (hrp !== "bc" && hrp !== "tb") return false;
  const poly = bech32Polymod([...hrpExpand(hrp), ...data]);
  return data[0] === 0 ? poly === 1 : poly === 0x2bc830a3;
}

/** A native-segwit ('bc1…') address: v0 P2WPKH (20B) / P2WSH (32B) or v1 taproot (32B). */
export function genBtcBech32(rng, kind) {
  const k = kind || pick(rng, ["v0-20", "v0-32", "v1"]);
  const witver = k === "v1" ? 1 : 0;
  const len = k === "v0-20" ? 20 : 32;
  const program = Array.from({ length: len }, () => ri(rng, 256));
  const spec = witver === 0 ? "bech32" : "bech32m";
  const addr = bech32Encode("bc", witver, program, spec);
  return bech32CheckValid(addr) ? addr : genBtcBech32(rng, kind);
}
export function genBtcBech32Bad(rng) {
  const good = genBtcBech32(rng, "v0-20");
  const i = 4 + ri(rng, good.length - 4);
  let ch; do { ch = pick(rng, BECH32_CHARSET.split("")); } while (ch === good[i]);
  const bad = good.slice(0, i) + ch + good.slice(i + 1);
  return bech32CheckValid(bad) ? genBtcBech32Bad(rng) : bad;
}

// ---- IBAN (mod-97, ISO 13616) --------------------------------------
const IBAN_LEN = {
  AD:24,AE:23,AT:20,BE:16,BG:22,CH:21,CY:28,CZ:24,DE:22,DK:18,EE:20,ES:24,FI:18,FR:27,GB:22,
  GR:27,HR:21,HU:28,IE:22,IS:26,IT:27,LI:21,LT:20,LU:20,LV:21,MC:27,MT:31,NL:18,NO:15,PL:28,
  PT:25,RO:24,RS:22,SE:24,SI:19,SK:24,SM:27,TR:26,
};
export const IBAN_COUNTRIES = Object.keys(IBAN_LEN);
function mod97(str) {
  let rem = 0;
  for (const ch of str) {
    const code = /[A-Z]/.test(ch) ? String(ch.charCodeAt(0) - 55) : ch;
    for (const d of code) rem = (rem * 10 + (+d)) % 97;
  }
  return rem;
}
export function ibanChecksumValid(iban) {
  const s = String(iban).replace(/[\s-]/g, "").toUpperCase();
  if (!/^[A-Z]{2}\d{2}[A-Z0-9]+$/.test(s)) return false;
  if (IBAN_LEN[s.slice(0, 2)] !== s.length) return false;
  return mod97(s.slice(4) + s.slice(0, 4)) === 1;
}
export function genIBAN(rng, country) {
  const cc = country || pick(rng, IBAN_COUNTRIES);
  const bbanLen = IBAN_LEN[cc] - 4;
  const alnum = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";
  const bban = Array.from({ length: bbanLen }, () => (rng() < 0.55 ? String(ri(rng, 10)) : pick(rng, alnum.split("")))).join("");
  const check = 98 - mod97(bban + cc + "00");
  const iban = cc + String(check).padStart(2, "0") + bban;
  return ibanChecksumValid(iban) ? iban : genIBAN(rng, country);
}
/** IBAN-shaped, correct per-country length, but the check digits are wrong. */
export function genIBANBadChecksum(rng) {
  const good = genIBAN(rng);
  let cd; do { cd = String(ri(rng, 100)).padStart(2, "0"); } while (cd === good.slice(2, 4));
  const bad = good.slice(0, 2) + cd + good.slice(4);
  return ibanChecksumValid(bad) ? genIBANBadChecksum(rng) : bad;
}

// ---- Ethereum (no keccak here — generate lowercase, which is EIP-55-valid) ---
export function genEthAddress(rng) {
  return "0x" + Array.from({ length: 40 }, () => "0123456789abcdef"[ri(rng, 16)]).join("");
}

// ---- UK National Insurance Number ---------------------------------
const NINO_BAD_PREFIX = new Set(["BG", "GB", "KN", "NK", "NT", "TN", "ZZ"]);
const NINO_L1 = "ABCEGHJKLMNOPRSTWXYZ".split("").filter((c) => !"DFIQUV".includes(c));
const NINO_L2 = "ABCEGHJLMNPRSTWXYZ".split("").filter((c) => !"DFIOQUV".includes(c));
export function ninoStructValid(raw) {
  const s = String(raw).replace(/\s/g, "").toUpperCase();
  if (!/^[A-Z]{2}\d{6}[A-D]$/.test(s)) return false;
  if ("DFIQUV".includes(s[0]) || "DFIOQUV".includes(s[1])) return false;
  return !NINO_BAD_PREFIX.has(s.slice(0, 2));
}
export function genNINo(rng) {
  let p;
  do { p = pick(rng, NINO_L1) + pick(rng, NINO_L2); } while (NINO_BAD_PREFIX.has(p));
  const body = digitStr(rng, 6);
  const suffix = pick(rng, ["A", "B", "C", "D"]);
  const spaced = rng() < 0.5;
  const v = spaced ? `${p} ${body.slice(0,2)} ${body.slice(2,4)} ${body.slice(4,6)} ${suffix}` : `${p}${body}${suffix}`;
  return ninoStructValid(v) ? v : genNINo(rng);
}
/** NINo shape with a disallowed prefix — should NOT be flagged. */
export function genNINoBad(rng) {
  const p = pick(rng, [...NINO_BAD_PREFIX, "DA", "FE", "QQ", "AO"]);
  return `${p}${digitStr(rng, 6)}${pick(rng, ["A", "B", "C", "D"])}`;
}

export const _internal = { ri, pick, digitStr, CARD_PREFIXES, IFSC_REAL_BANKS };
