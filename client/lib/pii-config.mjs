// PII rule definitions — the data that `pii-rules.mjs` (the engine) runs.
//
// Externalised from pii-rules.mjs in Phase 3. The engine still owns the
// detection LOGIC (unicode normalization, digit-run classification, context
// gating, scoring, overlap resolution); this file only holds the patterns,
// the per-category context keywords, and the small allow-lists.
//
// Rule shape (unchanged from the inline version):
//   { category, re, base, gate, softGate?, validate?(m)->bool, strongIf?(m)->bool }
//     re        /…/g regex run against the NORMALISED text
//     base      confidence for a bare structural match
//     gate      true  = hard context gate: keyword required to reach blocking conf
//     softGate  true  = keyword raises confidence, absence does not kill it
//     validate  drop the match unless this returns true (checksum / structure)
//     strongIf  bump to 0.9 when this returns true (recognised prefix / checksum)
//
// The numeric IDs (aadhaar / credit-card / phone-in) are NOT rule-shaped —
// they come from the engine's shared digit-run scan (length + checksum + IIN),
// which cannot be expressed as one regex. Their context keywords live in
// CONTEXT below all the same.

import { ssnValid, ibanValid, btcLegacyValid, bech32Valid, ninoValid } from "./pii-checksums.mjs";

// ─────────────────────────── allow-lists ────────────────────────────────

// RBI bank-code prefixes (first 4 chars of an IFSC). Common set - extend freely.
export const IFSC_BANKS = new Set([
  "SBIN","HDFC","ICIC","UTIB","PUNB","BARB","CNRB","IOBA","CBIN","UBIN","MAHB","KKBK","YESB","INDB",
  "IDIB","IBKL","FDRL","RATN","DBSS","SCBL","CITI","HSBC","BKID","ANDB","CORP","SYNB","UCBA","PSIB",
  "KARB","TMBL","DCBL","BDBL","AUBL","JAKA","SIBL","KVBL","ESFB","AIRP","PYTM","KOTA","BOTM","MSCI",
  "ALLA","VIJB","ORBC","UTBI","BKDN","DLXB","KABL","SRCB","TNSC","APGB","PKGB","MABL","NKGS","ABHY",
  "SVCB","GSCB","BCEY","MCBL","PMCB","JSBP","HCBL","IDFB","INDB","KLGB","BGGB","PRTH","SURY","UGBX",
]);
// RTO state / UT codes (first two letters of an Indian vehicle registration).
export const RTO_STATES = new Set([
  "AP","AR","AS","BR","CG","CH","DD","DL","DN","GA","GJ","HP","HR","JH","JK","KA","KL","LA","LD",
  "MH","ML","MN","MP","MZ","NL","OD","OR","PB","PY","RJ","SK","TN","TR","TS","UK","UP","UA","WB","BH",
]);
// NPCI-recognised UPI PSP handles (non-exhaustive; the heuristic covers the rest under context).
export const UPI_HANDLES = new Set([
  "oksbi","okhdfcbank","okicici","okaxis","paytm","ybl","apl","ibl","axl","upi","sbi","icici","hdfcbank",
  "kotak","yesbank","idbi","unionbank","pnb","rbl","dbs","jio","airtel","axisbank","cnrb","indus","federal",
  "barodampay","aubank","idfcbank","jupiteraxis","fbl","kbl","tapicici","waaxis","yapl","pockets","freecharge",
  "timecosmos","abfspay","cboi","allbank","dlb","kvb","lvb","psb","utbi","hsbc","citi","sc","citigold","yescred",
]);

// ─────────────────────────── context keywords ──────────────────────────

export const CONTEXT = {
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
  // Phase 3 additions
  iban: /\b(iban|swift|bic|bank|beneficiary|transfer|remit|wire|account)\b/i,
  "eth-address": /\b(eth|ether|ethereum|wallet|address|metamask|erc-?20|erc-?721|contract|token|blockchain|web3|gas|gwei|0x)\b/i,
  "btc-address": /\b(btc|bitcoin|wallet|address|xpub|sats?|satoshi|on-?chain|utxo|segwit|lightning)\b/i,
  "uk-nino": /\b(national insurance|ni number|ni no|nino|hmrc)\b/i,
};

export const NEGATIVE_CONTEXT = {
  ipv4: /\b(version|build|v\d|release|firmware|semver|patch)\b/i,
  dob: /\b(expir|due|deadline|meeting|invoice|valid|fiscal|renew|version|build)\b/i,
  "credit-card": /\b(imei|order|invoice|awb|tracking|sku|batch|manifest|serial|ticket)\b/i,
  pan: /\b(licen[sc]e|serial|sku|product|model|coupon|voucher|batch|api ?key|order|invoice)\b/i,
  "vehicle-reg": /\b(order|invoice|sku|coupon|voucher|batch|part|manifest|docket)\b/i,
  // Phase 3 additions
  "eth-address": /\b(commit|sha|hash|digest|revision|checksum|trace|0x[0-9a-f]{2,8}\b)\b/i,
};

// ─────────────────────────── regex rules ───────────────────────────────

export const REGEX_RULES = [
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
  { category: "ssn", re: /\b\d{3}-\d{2}-\d{4}\b/g, base: 0.3, gate: true, validate: (m) => ssnValid(m[0]) },
  { category: "ipv4", re: /\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b/g, base: 0.45, gate: false, softGate: true },
  { category: "dob", re: /\b(?:0?[1-9]|[12]\d|3[01])[/\-.](?:0?[1-9]|1[0-2])[/\-.](?:19|20)\d{2}\b/g, base: 0.3, gate: true },

  // ─────────── Phase 3: curated additions (checksum-gated where one exists) ───────────

  // IBAN — ISO 13616. mod-97 == 1 + fixed per-country length. Checksum makes a
  // bare match strong; no keyword needed. Grouped ("DE89 3704 …") is accepted;
  // greedy match can rarely over-run into following ALL-CAPS/space text, which
  // then fails the checksum and is dropped (the valid IBAN before it is lost in
  // that rare case — see tests).
  { category: "iban", re: /\b[A-Z]{2}\d{2}(?:[ ]?[A-Z0-9]){11,30}\b/g, base: 0.55, gate: false, softGate: true,
    validate: (m) => ibanValid(m[0]), strongIf: (m) => ibanValid(m[0]) },

  // Bitcoin — legacy base58check ('1'/'3') and native segwit ('bc1', bech32/
  // bech32m). Both carry a real checksum; a surviving match is unambiguous, so
  // it emits at high confidence with or without context.
  { category: "btc-address", re: /\bbc1[a-z0-9]{11,71}\b/g, base: 0.5, gate: false,
    validate: (m) => bech32Valid(m[0]), strongIf: () => true },
  { category: "btc-address", re: /\b[13][1-9A-HJ-NP-Za-km-z]{25,34}\b/g, base: 0.5, gate: false,
    validate: (m) => btcLegacyValid(m[0]), strongIf: () => true },

  // Ethereum — 0x + 40 hex. EIP-55 casing is optional and needs keccak256 (a
  // hash primitive we deliberately don't vendor), so there is no checksum path
  // here: the rule is HARD context-gated. A bare 0x40-hex in a stack trace or
  // git output stays below threshold; "wallet 0x…" / "send to 0x…" fires.
  { category: "eth-address", re: /\b0x[0-9a-fA-F]{40}\b/g, base: 0.3, gate: true },

  // UK National Insurance Number — no checksum; the prefix-letter constraints
  // are the validation. HARD context-gated: "AB123456C" shape collides with
  // some licence/reference formats.
  { category: "uk-nino", re: /\b[A-Z]{2}\s?\d{2}\s?\d{2}\s?\d{2}\s?[A-D]\b/g, base: 0.3, gate: true,
    validate: (m) => ninoValid(m[0]) },
];

// Every category the engine can emit (numeric-run + regex). Used by tests to
// assert no accidental drops/dupes.
export const CATEGORIES = [
  "aadhaar", "credit-card", "phone-in",
  ...REGEX_RULES.map((r) => r.category),
].filter((c, i, a) => a.indexOf(c) === i);

export default { REGEX_RULES, CONTEXT, NEGATIVE_CONTEXT, IFSC_BANKS, RTO_STATES, UPI_HANDLES, CATEGORIES };
