// Value-format PII detection: normalization + digit-run classification + regex,
// each hit confidence-scored and (for shape-only identifiers) context-gated.
//
// Runs on (a) OCR'd screen text in the offscreen document and (b) any raw text
// the client is about to send. Detects the *value*, not just the field name.
//
// Design (see eval/bench/README.md for the benchmark that drove it):
//  - normalize(text): fold unicode digits -> ASCII, dash/space variants -> ASCII,
//    strip zero-width chars, fold fullwidth letters. Keeps a char-offset map so
//    every hit maps back to the ORIGINAL string.
//  - numeric IDs (Aadhaar / card / phone) are found by extracting maximal digit
//    runs and classifying by (length, checksum, IIN prefix) - immune to which
//    separator was used, and a 16-digit run can never partially match as a
//    12-digit Aadhaar.
//  - shape-only identifiers with no checksum (PAN structural check is weak; IFSC,
//    voter-id, passport, DOB, SSN have none) are CONTEXT-GATED: a match only
//    reaches blocking confidence when a category keyword sits within ~40 chars.
//    Absent context they are emitted at low confidence (below the default
//    threshold) so a "show everything" caller still sees them.

// ============================ checksums =================================

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
  // length-specific: 15-digit cards are Amex only; 14 is Diners; 13 is old Visa
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

const SSN_VALID = (m) => {
  const [, a, g, s] = m.match(/^(\d{3})-(\d{2})-(\d{4})$/) || [];
  if (!a) return false;
  const A = +a, G = +g, S = +s;
  return A !== 0 && A !== 666 && A < 900 && G !== 0 && S !== 0;
};

// ============================ normalization ============================

const DIGIT_ZEROS = [0x0660, 0x06f0, 0x0966, 0x09e6, 0x0a66, 0x0ae6, 0x0b66, 0x0be6, 0x0c66, 0x0ce6, 0x0d66, 0x0e50, 0x0ff10];
function asciiDigit(cp) {
  for (const z of DIGIT_ZEROS) if (cp >= z && cp <= z + 9) return String(cp - z);
  return null;
}
const DASHES = new Set([0x2010, 0x2011, 0x2012, 0x2013, 0x2014, 0x2015, 0x2212, 0xfe58, 0xfe63, 0xff0d]);
const SPACES = new Set([0x00a0, 0x1680, 0x2000, 0x2001, 0x2002, 0x2003, 0x2004, 0x2005, 0x2006, 0x2007, 0x2008, 0x2009, 0x200a, 0x202f, 0x205f, 0x3000]);
const ZEROWIDTH = new Set([0x200b, 0x200c, 0x200d, 0xfeff, 0x00ad]);

/**
 * @returns {{ norm: string, map: number[], mapEnd: number[] }}
 *   norm[i] came from original[ map[i] .. mapEnd[i] )
 */
export function normalize(text) {
  const norm = [];
  const map = [];
  const mapEnd = [];
  let idx = 0;
  for (const ch of text) {
    const cp = ch.codePointAt(0);
    const width = ch.length; // 1 or 2 UTF-16 units
    let repl = ch;
    if (ZEROWIDTH.has(cp)) { idx += width; continue; }
    else if (DASHES.has(cp)) repl = "-";
    else if (SPACES.has(cp)) repl = " ";
    else {
      const d = asciiDigit(cp);
      if (d != null) repl = d;
      else if (cp >= 0xff21 && cp <= 0xff3a) repl = String.fromCharCode(cp - 0xff21 + 65);
      else if (cp >= 0xff41 && cp <= 0xff5a) repl = String.fromCharCode(cp - 0xff41 + 97);
      else if (cp === 0xff20) repl = "@";
      else if (cp === 0xff0e) repl = ".";
    }
    for (const rc of repl) { norm.push(rc); map.push(idx); mapEnd.push(idx + width); }
    idx += width;
  }
  return { norm: norm.join(""), map, mapEnd };
}

// ============================ context gating ==========================

const CTX = {
  aadhaar: /\b(aadhaar|aadhaar|aadhar|uidai|uid)\b/i,
  "credit-card": /\b(card|credit|debit|cvv|cvc|visa|master ?card|rupay|amex|expiry)\b/i,
  "phone-in": /\b(phone|mobile|call|whats ?app|contact|tel|sms|dial|cell|number)\b/i,
  pan: /\b(pan|permanent account)\b/i,
  gstin: /\b(gst|gstin)\b/i,
  ifsc: /\b(ifsc|neft|rtgs|imps|branch|beneficiary|a\/c|account)\b/i,
  "upi-vpa": /\b(upi|vpa|pay to|gpay|phonepe|paytm|collect|@?scan)\b/i,
  "voter-id": /\b(voter|epic|electoral|election|booth|ward|constituency|elector)\b/i,
  "vehicle-reg": /\b(vehicle|rc |registration|challan|car|number plate|rto|bike|scooter)\b/i,
  "passport-in": /\b(passport|psk|travel document|immigration|visa|emigration)\b/i,
  ssn: /\b(ssn|social security)\b/i,
  ipv4: /\b(ip|address|server|host|dns|gateway|subnet|router|ping|localhost|port)\b/i,
  dob: /\b(dob|d\.?o\.?b|date of birth|born|birth ?date|birthday|age)\b/i,
  email: /./,
};
const NEGATIVE_CTX = {
  ipv4: /\b(version|build|v\d|release|firmware|semver|patch)\b/i,
  dob: /\b(expir|due|deadline|meeting|invoice|valid|fiscal|renew|version|build)\b/i,
  "credit-card": /\b(imei|order|invoice|awb|tracking|sku|batch|manifest|serial|ticket)\b/i,
  pan: /\b(licen[sc]e|serial|sku|product|model|coupon|voucher|batch|api ?key|order|invoice)\b/i,
  "vehicle-reg": /\b(order|invoice|sku|coupon|voucher|batch|part|manifest|docket)\b/i,
};

function hasCtx(norm, start, end, re, window = 40) {
  const before = norm.slice(Math.max(0, start - window), start);
  const after = norm.slice(end, end + window);
  return re.test(before) || re.test(after);
}

// ============================ regex rules =============================
// Structured (mostly alphanumeric) identifiers. Numeric IDs handled separately.

const RULES = [
  { category: "email", re: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g, base: 0.95, gate: false },
  // PAN: exact shape + holder-type 4th char (10/26 letters). Soft-gated: emits
  // on structure alone, keyword raises / "licence/serial/sku" lowers.
  { category: "pan", re: /\b[A-Z]{3}([ABCFGHLJPT])[A-Z][0-9]{4}[A-Z]\b/g, base: 0.6, gate: false, softGate: true },
  { category: "gstin", re: /\b(\d{2})([A-Z]{5}[0-9]{4}[A-Z])[A-Z0-9]Z[A-Z0-9]\b/g, base: 0.8, gate: false,
    validate: (m) => { const st = +m[1]; return st >= 1 && st <= 38 && "ABCFGHLJPT".includes(m[2][3]); } },
  // IFSC / vehicle-reg: authoritative prefix list = strong signal; recognized
  // prefix emits without a keyword, unrecognized is dropped entirely.
  { category: "ifsc", re: /\b([A-Z]{4})0[A-Z0-9]{6}\b/g, base: 0.55, gate: false,
    validate: (m) => IFSC_BANKS.has(m[1].toUpperCase()), strongIf: (m) => IFSC_BANKS.has(m[1].toUpperCase()) },
  { category: "upi-vpa", re: /\b([A-Za-z0-9][A-Za-z0-9.\-_]{1,})@([a-z]{2,15})\b/g, base: 0.3, gate: true,
    strongIf: (m) => UPI_HANDLES.has(m[2].toLowerCase()) },
  { category: "voter-id", re: /\b[A-Z]{3}[0-9]{7}\b/g, base: 0.3, gate: true },
  { category: "vehicle-reg", re: /\b([A-Z]{2})[ -]?\d{1,2}[ -]?[A-Z]{1,3}[ -]?\d{4}\b/g, base: 0.4, gate: false, softGate: true,
    validate: (m) => RTO_STATES.has(m[1].toUpperCase()), strongIf: (m) => RTO_STATES.has(m[1].toUpperCase()) },
  { category: "passport-in", re: /\b[A-PR-WYa-pr-wy][1-9]\d\s?\d{4}[1-9]\b/g, base: 0.3, gate: true },
  { category: "ssn", re: /\b\d{3}-\d{2}-\d{4}\b/g, base: 0.3, gate: true, validate: (m) => SSN_VALID(m[0]) },
  { category: "ipv4", re: /\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b/g, base: 0.45, gate: false, softGate: true },
  { category: "dob", re: /\b(?:0?[1-9]|[12]\d|3[01])[/\-.](?:0?[1-9]|1[0-2])[/\-.](?:19|20)\d{2}\b/g, base: 0.3, gate: true },
];

// RBI bank-code prefixes (first 4 chars of an IFSC). Common set - extend freely.
const IFSC_BANKS = new Set([
  "SBIN","HDFC","ICIC","UTIB","PUNB","BARB","CNRB","IOBA","CBIN","UBIN","MAHB","KKBK","YESB","INDB",
  "IDIB","IBKL","FDRL","RATN","DBSS","SCBL","CITI","HSBC","BKID","ANDB","CORP","SYNB","UCBA","PSIB",
  "KARB","TMBL","DCBL","BDBL","AUBL","JAKA","SIBL","KVBL","ESFB","AIRP","PYTM","KOTA","BOTM","MSCI",
  "ALLA","VIJB","ORBC","UTBI","BKDN","DLXB","KABL","SRCB","TNSC","APGB","PKGB","MABL","NKGS","ABHY",
  "SVCB","GSCB","BCEY","MCBL","PMCB","JSBP","HCBL","IDFB","INDB","KLGB","BGGB","PRTH","SURY","UGBX",
]);
// RTO state / UT codes (first two letters of an Indian vehicle registration).
const RTO_STATES = new Set([
  "AP","AR","AS","BR","CG","CH","DD","DL","DN","GA","GJ","HP","HR","JH","JK","KA","KL","LA","LD",
  "MH","ML","MN","MP","MZ","NL","OD","OR","PB","PY","RJ","SK","TN","TR","TS","UK","UP","UA","WB","BH",
]);
// NPCI-recognised UPI PSP handles (non-exhaustive; the heuristic covers the rest under context).
const UPI_HANDLES = new Set([
  "oksbi","okhdfcbank","okicici","okaxis","paytm","ybl","apl","ibl","axl","upi","sbi","icici","hdfcbank",
  "kotak","yesbank","idbi","unionbank","pnb","rbl","dbs","jio","airtel","axisbank","cnrb","indus","federal",
  "barodampay","aubank","idfcbank","jupiteraxis","fbl","kbl","tapicici","waaxis","yapl","pockets","freecharge",
  "timecosmos","abfspay","cboi","allbank","dlb","kvb","lvb","psb","utbi","hsbc","citi","sc","citigold","yescred",
]);

// ============================ numeric-run pass =======================

const OCR_FIX = { O: "0", o: "0", I: "1", l: "1", S: "5", B: "8", Z: "2", G: "6", g: "9", D: "0", Q: "0" };
const fixOcrDigits = (s) => s.replace(/[OoIlSBZGgDQ]/g, (c) => OCR_FIX[c] || c);

function scanNumericRuns(norm) {
  const hits = [];
  // maximal run of digits with internal separators (space/hyphen/dot, up to 2
  // between digits — covers "1234  5678" double-space, "1234 - 5678", etc.)
  const re = /(?<!\d)(\d(?:[ \-.]{0,3}\d){5,23})(?!\d)/g;
  let m;
  while ((m = re.exec(norm)) !== null) {
    const raw = m[1];
    const start = m.index;
    const end = start + raw.length;
    let digits = raw.replace(/\D/g, "");
    // OCR-confusion retry for the region around the run (letters glued to digits)
    if (digits.length < 10) {
      const wide = norm.slice(Math.max(0, start - 2), Math.min(norm.length, end + 2));
      const fixed = fixOcrDigits(wide).replace(/\D/g, "");
      if (fixed.length >= 10) digits = fixed;
    }

    const prefix = norm.slice(Math.max(0, start - 5), start);
    const hadCC = /(?:\+?91[ -]?|\b0)$/.test(prefix);

    if (digits.length === 12 && (verhoeffValid(digits) || verhoeffValid(fixOcrDigits(raw).replace(/\D/g, "")))) {
      const conf = hasCtx(norm, start, end, NEGATIVE_CTX.dob, 20) && !hasCtx(norm, start, end, CTX.aadhaar) ? 0.55 : 0.9;
      hits.push({ category: "aadhaar", start, end, value: raw, confidence: conf });
    } else if (digits.length >= 13 && digits.length <= 19 && luhnValid(digits) && cardIinOk(digits)) {
      const conf = hasCtx(norm, start, end, NEGATIVE_CTX["credit-card"], 25) ? 0.35 : 0.9;
      hits.push({ category: "credit-card", start, end, value: raw, confidence: conf });
    } else if (digits.length === 10 && /[6-9]/.test(digits[0])) {
      const conf = hadCC || hasCtx(norm, start, end, CTX["phone-in"]) ? 0.8 : 0.3;
      hits.push({ category: "phone-in", start, end, value: raw, confidence: conf });
    } else if (digits.length === 11 && digits[0] === "0" && /[6-9]/.test(digits[1])) {
      hits.push({ category: "phone-in", start, end, value: raw, confidence: 0.75 });
    } else if (digits.length === 12 && /^91[6-9]/.test(digits)) {
      hits.push({ category: "phone-in", start, end, value: raw, confidence: 0.8 });
    }
  }
  return hits;
}

// ============================ main =====================================

/**
 * @param {string} text
 * @param {{minConfidence?: number}} [opts]  minConfidence default 0.5 (blocking).
 *        Pass 0 to also get low-confidence / context-less shape matches.
 * @returns {Array<{category, value, start, end, confidence}>}  offsets into `text`
 */
export function detectPII(text, opts = {}) {
  if (!text || typeof text !== "string") return [];
  const minConfidence = opts.minConfidence ?? 0.5;
  const { norm, map, mapEnd } = normalize(text);

  const raw = [];

  // numeric IDs
  for (const h of scanNumericRuns(norm)) raw.push(h);

  // structured regex rules
  for (const rule of RULES) {
    rule.re.lastIndex = 0;
    let m;
    while ((m = rule.re.exec(norm)) !== null) {
      const value = m[0];
      const start = m.index;
      const end = start + value.length;
      if (m.index === rule.re.lastIndex) rule.re.lastIndex++;
      if (rule.validate && !rule.validate(m)) continue;

      let conf = rule.base;
      const strong = rule.strongIf ? rule.strongIf(m) : false;
      const hasPos = hasCtx(norm, start, end, CTX[rule.category]);
      if (strong) conf = 0.9;
      if (rule.gate && !strong) {
        conf = hasPos ? 0.9 : Math.min(conf, 0.3);          // hard gate: keyword required
      } else if (rule.softGate && hasPos) {
        conf = Math.max(conf, 0.75);                        // soft gate: keyword raises
      }
      const neg = NEGATIVE_CTX[rule.category];
      if (neg && !hasPos && hasCtx(norm, start, end, neg, 25)) {
        conf = Math.min(conf, 0.3);                         // negative keyword, no positive -> drop
      }
      raw.push({ category: rule.category, value, start, end, confidence: +conf.toFixed(2) });
    }
  }

  // map offsets back to the ORIGINAL string
  for (const h of raw) {
    h.start = map[h.start] ?? h.start;
    h.end = (mapEnd[h.end - 1] ?? h.end);
    h.value = text.slice(h.start, h.end);
  }

  // threshold
  let hits = raw.filter((h) => h.confidence >= minConfidence);

  // resolve overlaps: earliest start, then higher confidence, then longer
  hits.sort((a, b) => a.start - b.start || b.confidence - a.confidence || b.end - a.end);
  const kept = [];
  for (const h of hits) {
    if (!kept.some((k) => h.start < k.end && k.start < h.end)) kept.push(h);
  }
  return kept;
}

export const KEYWORDS = CTX;
export default { detectPII, normalize, verhoeffValid, luhnValid, cardIinOk, KEYWORDS };
