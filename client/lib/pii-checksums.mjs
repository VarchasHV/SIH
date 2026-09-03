// Checksum / structural validators for the PII engine.
//
// Pure, synchronous, dependency-free. `pii-rules.mjs` (the engine) and
// `pii-config.mjs` (the rule definitions) both import from here so a rule's
// `validate()` can run a real checksum instead of trusting the regex shape.
//
// Anchored by known-answer vectors in tests/pii-config.test.mjs:
//   verhoeff("234567890124") -> valid;  luhn("4111111111111111") -> valid
//   sha256("") -> e3b0c442…b855
//   IBAN "GB82WEST12345698765432" -> valid (ISO 13616 test vector)
//   BTC "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa" (genesis) -> valid
//   BTC "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4" (BIP-173) -> valid

// ─────────────────────────── numeric checksums ───────────────────────────

const VERHOEFF_D = [
  [0,1,2,3,4,5,6,7,8,9],[1,2,3,4,0,6,7,8,9,5],[2,3,4,0,1,7,8,9,5,6],[3,4,0,1,2,8,9,5,6,7],
  [4,0,1,2,3,9,5,6,7,8],[5,9,8,7,6,0,4,3,2,1],[6,5,9,8,7,1,0,4,3,2],[7,6,5,9,8,2,1,0,4,3],
  [8,7,6,5,9,3,2,1,0,4],[9,8,7,6,5,4,3,2,1,0],
];
const VERHOEFF_P = [
  [0,1,2,3,4,5,6,7,8,9],[1,5,7,6,2,8,3,0,9,4],[5,8,0,3,7,9,6,1,4,2],[8,9,1,6,0,4,3,5,2,7],
  [9,4,5,3,1,2,6,8,7,0],[4,2,8,6,5,7,3,9,0,1],[2,7,9,3,8,0,6,4,1,5],[7,0,4,6,9,1,3,2,5,8],
];

export function verhoeffValid(digits) {
  const s = String(digits).replace(/\D/g, "");
  if (s.length !== 12) return false;
  let c = 0;
  const rev = s.split("").reverse();
  for (let i = 0; i < rev.length; i++) c = VERHOEFF_D[c][VERHOEFF_P[i % 8][Number(rev[i])]];
  return c === 0;
}

export function luhnValid(digits) {
  const s = String(digits).replace(/\D/g, "");
  if (s.length < 12 || s.length > 19) return false;
  let sum = 0, dbl = false;
  for (let i = s.length - 1; i >= 0; i--) {
    let d = Number(s[i]);
    if (dbl) { d *= 2; if (d > 9) d -= 9; }
    sum += d; dbl = !dbl;
  }
  return sum % 10 === 0;
}

// Card IIN / BIN prefixes (Visa, Mastercard incl. 2-series, Amex, Discover,
// Diners, JCB, RuPay, Maestro). Cuts Luhn-valid non-cards (IMEIs, some account
// numbers). 12-digit runs are excluded (too collision-prone).
export function cardIinOk(digits) {
  const n = digits.length;
  if (n < 13 || n > 19) return false;
  if (n === 15) return /^3[47]/.test(digits);
  if (n === 14) return /^3(0[0-5]|[68]\d)/.test(digits);
  if (n === 13) return /^4/.test(digits);
  return (
    /^4/.test(digits) ||                                  // Visa
    /^5[1-5]/.test(digits) ||                             // Mastercard
    /^2(2[2-9]\d|[3-6]\d\d|7[01]\d|720)/.test(digits) ||  // Mastercard 2-series
    /^35(2[89]|[3-8]\d)/.test(digits) ||                  // JCB
    /^6(011|4[4-9]\d|5)/.test(digits) ||                  // Discover
    /^(60|65|81|508[5-9]|353|356)/.test(digits) ||        // RuPay
    /^(5018|5020|5038|56|58|6304|6759|676[1-3])/.test(digits) // Maestro
  );
}

// US SSN: not area 000/666/900-999, not group 00, not serial 0000.
export function ssnValid(m) {
  const s = typeof m === "string" ? m : (m && m[0]) || "";
  const parts = s.match(/^(\d{3})-(\d{2})-(\d{4})$/);
  if (!parts) return false;
  const A = +parts[1], G = +parts[2], S = +parts[3];
  return A !== 0 && A !== 666 && A < 900 && G !== 0 && S !== 0;
}

// ───────────────────────────── IBAN (ISO 13616) ──────────────────────────
// 2-letter country + 2 check digits + BBAN; the whole string, rearranged and
// A→10…Z→35, must be ≡ 1 (mod 97). Per-country length is fixed.

const IBAN_LEN = {
  AD:24,AE:23,AL:28,AT:20,AZ:28,BA:20,BE:16,BG:22,BH:22,BR:29,BY:28,CH:21,CR:22,CY:28,CZ:24,
  DE:22,DK:18,DO:28,EE:20,EG:29,ES:24,FI:18,FO:18,FR:27,GB:22,GE:22,GI:23,GL:18,GR:27,GT:28,
  HR:21,HU:28,IE:22,IL:23,IQ:23,IS:26,IT:27,JO:30,KW:30,KZ:20,LB:28,LC:32,LI:21,LT:20,LU:20,
  LV:21,LY:25,MC:27,MD:24,ME:22,MK:19,MR:27,MT:31,MU:30,NL:18,NO:15,PK:24,PL:28,PS:29,PT:25,
  QA:29,RO:24,RS:22,SA:24,SC:31,SD:18,SE:24,SI:19,SK:24,SM:27,ST:25,SV:28,TL:23,TN:24,TR:26,
  UA:29,VA:22,VG:24,XK:20,
};

export function ibanValid(raw) {
  const s = String(raw || "").replace(/[\s-]/g, "").toUpperCase();
  if (!/^[A-Z]{2}\d{2}[A-Z0-9]+$/.test(s)) return false;
  const cc = s.slice(0, 2);
  if (!(cc in IBAN_LEN) || s.length !== IBAN_LEN[cc]) return false;
  const rearranged = s.slice(4) + s.slice(0, 4);
  let rem = 0;
  for (const ch of rearranged) {
    const code = ch >= "A" && ch <= "Z" ? String(ch.charCodeAt(0) - 55) : ch;
    for (const d of code) rem = (rem * 10 + (d.charCodeAt(0) - 48)) % 97;
  }
  return rem === 1;
}

export const _ibanCountries = IBAN_LEN;

// ─────────────────────────── SHA-256 (sync, pure JS) ─────────────────────
// Needed for Bitcoin base58check (double-SHA256). Small inputs only (≤55B).

const SHA_K = new Uint32Array([
  0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
  0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
  0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
  0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
  0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
  0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
  0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
  0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2,
]);
const rotr = (x, n) => (x >>> n) | (x << (32 - n));

export function sha256(bytes) {
  let h0=0x6a09e667,h1=0xbb67ae85,h2=0x3c6ef372,h3=0xa54ff53a,h4=0x510e527f,h5=0x9b05688c,h6=0x1f83d9ab,h7=0x5be0cd19;
  const l = bytes.length;
  const padded = new Uint8Array((((l + 8) >> 6) + 1) << 6);
  padded.set(bytes);
  padded[l] = 0x80;
  const dv = new DataView(padded.buffer);
  const bits = l * 8;
  dv.setUint32(padded.length - 8, Math.floor(bits / 0x100000000), false);
  dv.setUint32(padded.length - 4, bits >>> 0, false);
  const w = new Uint32Array(64);
  for (let off = 0; off < padded.length; off += 64) {
    for (let i = 0; i < 16; i++) w[i] = dv.getUint32(off + i * 4, false);
    for (let i = 16; i < 64; i++) {
      const s0 = rotr(w[i-15], 7) ^ rotr(w[i-15], 18) ^ (w[i-15] >>> 3);
      const s1 = rotr(w[i-2], 17) ^ rotr(w[i-2], 19) ^ (w[i-2] >>> 10);
      w[i] = (w[i-16] + s0 + w[i-7] + s1) | 0;
    }
    let a=h0,b=h1,c=h2,d=h3,e=h4,f=h5,g=h6,h=h7;
    for (let i = 0; i < 64; i++) {
      const S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
      const ch = (e & f) ^ (~e & g);
      const t1 = (h + S1 + ch + SHA_K[i] + w[i]) | 0;
      const S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
      const maj = (a & b) ^ (a & c) ^ (b & c);
      const t2 = (S0 + maj) | 0;
      h=g; g=f; f=e; e=(d + t1) | 0; d=c; c=b; b=a; a=(t1 + t2) | 0;
    }
    h0=(h0+a)|0; h1=(h1+b)|0; h2=(h2+c)|0; h3=(h3+d)|0; h4=(h4+e)|0; h5=(h5+f)|0; h6=(h6+g)|0; h7=(h7+h)|0;
  }
  const out = new Uint8Array(32);
  new DataView(out.buffer).setUint32(0, h0 >>> 0, false);
  const odv = new DataView(out.buffer);
  [h0,h1,h2,h3,h4,h5,h6,h7].forEach((x, i) => odv.setUint32(i * 4, x >>> 0, false));
  return out;
}

// ───────────────────────── Bitcoin address checks ───────────────────────

const B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

export function base58Decode(str) {
  const bytes = [0];
  for (const ch of String(str)) {
    const val = B58.indexOf(ch);
    if (val < 0) return null;
    let carry = val;
    for (let j = 0; j < bytes.length; j++) {
      carry += bytes[j] * 58;
      bytes[j] = carry & 0xff;
      carry >>= 8;
    }
    while (carry > 0) { bytes.push(carry & 0xff); carry >>= 8; }
  }
  for (let k = 0; k < str.length && str[k] === "1"; k++) bytes.push(0);
  return new Uint8Array(bytes.reverse());
}

/** Legacy P2PKH ('1') / P2SH ('3') mainnet address with a valid base58check checksum. */
export function btcLegacyValid(addr) {
  const dec = base58Decode(addr);
  if (!dec || dec.length !== 25) return false;
  const payload = dec.slice(0, 21);
  const want = dec.slice(21);
  const got = sha256(sha256(payload));
  for (let i = 0; i < 4; i++) if (got[i] !== want[i]) return false;
  return payload[0] === 0x00 || payload[0] === 0x05;
}

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
  const out = [];
  for (let i = 0; i < hrp.length; i++) out.push(hrp.charCodeAt(i) >> 5);
  out.push(0);
  for (let i = 0; i < hrp.length; i++) out.push(hrp.charCodeAt(i) & 31);
  return out;
}

/** Native segwit ('bc1' / 'tb1') address with a valid bech32 / bech32m checksum. */
export function bech32Valid(addr) {
  const s = String(addr || "");
  if (s.length < 8 || s.length > 90 || s !== s.toLowerCase()) return false;
  const pos = s.lastIndexOf("1");
  if (pos < 1 || pos + 7 > s.length) return false;
  const hrp = s.slice(0, pos);
  if (hrp !== "bc" && hrp !== "tb") return false;
  const data = [];
  for (const ch of s.slice(pos + 1)) {
    const d = BECH32_CHARSET.indexOf(ch);
    if (d < 0) return false;
    data.push(d);
  }
  if (data.length < 6) return false;
  const poly = bech32Polymod(hrpExpand(hrp).concat(data));
  const witver = data[0];
  if (witver === 0) return poly === 1;                 // bech32
  if (witver >= 1 && witver <= 16) return poly === 0x2bc830a3; // bech32m
  return false;
}

export function btcAddressValid(addr) {
  return /^(bc1|tb1)/.test(addr) ? bech32Valid(addr) : btcLegacyValid(addr);
}

// ───────────────────────── UK National Insurance No. ────────────────────
// AA 12 34 56 A — 2 prefix letters (with exclusions), 6 digits, suffix A-D.
// No checksum; the constraints below are the whole validation.

const NINO_BAD_PREFIX = new Set(["BG", "GB", "KN", "NK", "NT", "TN", "ZZ"]);

export function ninoValid(raw) {
  const s = String(raw || "").replace(/\s/g, "").toUpperCase();
  if (!/^[A-Z]{2}\d{6}[A-D]$/.test(s)) return false;
  if ("DFIQUV".includes(s[0])) return false;
  if ("DFIOQUV".includes(s[1])) return false;
  if (NINO_BAD_PREFIX.has(s.slice(0, 2))) return false;
  return true;
}

export default {
  verhoeffValid, luhnValid, cardIinOk, ssnValid,
  ibanValid, sha256, base58Decode, btcLegacyValid, bech32Valid, btcAddressValid, ninoValid,
};
