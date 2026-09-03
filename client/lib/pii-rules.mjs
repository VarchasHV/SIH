// Value-format PII detection: normalization + digit-run classification + regex,
// each hit confidence-scored and (for shape-only identifiers) context-gated.
//
// Runs on (a) OCR'd screen text in the offscreen document and (b) any raw text
// the client is about to send. Detects the *value*, not just the field name.
//
// This file is the ENGINE. Rule definitions (patterns, context keywords,
// allow-lists) live in ./pii-config.mjs; checksums in ./pii-checksums.mjs.
// Phase 3 externalised the data; the logic below is unchanged.
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

import { verhoeffValid, luhnValid, cardIinOk } from "./pii-checksums.mjs";
import { REGEX_RULES, CONTEXT, NEGATIVE_CONTEXT } from "./pii-config.mjs";

export { verhoeffValid, luhnValid, cardIinOk };

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

function hasCtx(norm, start, end, re, window = 40) {
  const before = norm.slice(Math.max(0, start - window), start);
  const after = norm.slice(end, end + window);
  return re.test(before) || re.test(after);
}

// ============================ numeric-run pass =======================

const OCR_FIX = { O: "0", o: "0", I: "1", l: "1", S: "5", B: "8", Z: "2", G: "6", g: "9", D: "0", Q: "0" };
const fixOcrDigits = (s) => s.replace(/[OoIlSBZGgDQ]/g, (c) => OCR_FIX[c] || c);

// Dot-separated numeric strings that are NOT grouped PII: IPv4 ("164.154.182.151"),
// version/build strings ("10.0.19045.3803"), etc. These strip to a 12- or
// 16-digit run that can pass Verhoeff/Luhn by chance and be mislabelled
// Aadhaar/card. Aadhaar and card *dot* surface forms use uniform 4-digit
// groups ("2345.6789.0124"), so a run with a "." where any dot-group is not
// exactly 4 digits is treated as non-PII and left to the `ipv4` rule.
function isDottedNonPii(raw) {
  if (!raw.includes(".")) return false;
  return !raw.split(".").every((g) => /^\d{4}$/.test(g));
}

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
    // IPv4 / version strings are not numeric PII — leave them to the `ipv4` rule.
    if (isDottedNonPii(raw)) continue;
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
      const conf = hasCtx(norm, start, end, NEGATIVE_CONTEXT.dob, 20) && !hasCtx(norm, start, end, CONTEXT.aadhaar) ? 0.55 : 0.9;
      hits.push({ category: "aadhaar", start, end, value: raw, confidence: conf });
    } else if (digits.length >= 13 && digits.length <= 19 && luhnValid(digits) && cardIinOk(digits)) {
      const conf = hasCtx(norm, start, end, NEGATIVE_CONTEXT["credit-card"], 25) ? 0.35 : 0.9;
      hits.push({ category: "credit-card", start, end, value: raw, confidence: conf });
    } else if (digits.length === 10 && /[6-9]/.test(digits[0])) {
      const conf = hadCC || hasCtx(norm, start, end, CONTEXT["phone-in"]) ? 0.8 : 0.3;
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
  for (const rule of REGEX_RULES) {
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
      const hasPos = hasCtx(norm, start, end, CONTEXT[rule.category]);
      if (strong) conf = 0.9;
      if (rule.gate && !strong) {
        conf = hasPos ? 0.9 : Math.min(conf, 0.3);          // hard gate: keyword required
      } else if (rule.softGate && hasPos) {
        conf = Math.max(conf, 0.75);                        // soft gate: keyword raises
      }
      const neg = NEGATIVE_CONTEXT[rule.category];
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

export const KEYWORDS = CONTEXT;
export default { detectPII, normalize, verhoeffValid, luhnValid, cardIinOk, KEYWORDS };
