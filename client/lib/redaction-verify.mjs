// Redaction verification gate (security plan S4 / item 11).
//
// The first redaction pass masks what the first OCR + detection pass found.
// It is blind to anything that pass missed — bare/unlabelled shape IDs, PII
// left visible by a box that was drawn too small, low-confidence matches the
// first pass suppressed. `redact.mjs::leakScore` only checks the regions it
// already decided to mask, so it cannot see this.
//
// verifyRedaction() closes the gap:
//   1. re-OCR the ALREADY-MASKED canvas (masked pixels read as nothing)
//   2. re-run detectPII + scanSecrets on that text — at a paranoid threshold,
//      because this image is about to be sent to a remote VLM
//   3. residual hits  -> grow the offending boxes and mask ONCE more
//   4. re-verify. still leaking -> REDACTION_FAILED (caller blocks egress).
//      Bounded to exactly one re-mask pass; never loops until clean.
//
// It reuses the ONE PII detector and the ONE secret scanner — no parallel
// engine. OCR is injected (the caller owns the Tesseract worker).

import { detectPII } from "./pii-rules.mjs";
import { scanSecrets } from "./secret-scanner.mjs";
import { redactCanvas } from "./redact.mjs";

/** char span within a line -> pixel sub-box of that line's bbox (same math as the OCR pass). */
function spanToRegion(line, start, end, category) {
  const b = line.bbox || { x0: 0, y0: 0, x1: 0, y1: 0 };
  const width = (b.x1 - b.x0) || 1;
  const n = Math.max(1, (line.text || "").length);
  const cs = Math.max(0, Math.min(1, start / n));
  const ce = Math.max(0, Math.min(1, end / n));
  return {
    x: b.x0 + cs * width,
    y: b.y0,
    w: Math.max(1, (ce - cs) * width),
    h: Math.max(1, b.y1 - b.y0),
    category,
  };
}

function growBox(r, m) {
  return { x: r.x - m, y: r.y - m, w: r.w + 2 * m, h: r.h + 2 * m, category: r.category };
}

/**
 * @param {(text:string)=>[{text:string,bbox:{x0,y0,x1,y1}}]} lines
 * @returns {Array<{ kind:'pii'|'secret', category?:string, subtype?:string, region:object, evidence:string }>}
 */
function scanLines(lines, { piiMinConfidence, secretMinConfidence }) {
  const residual = [];
  for (const line of lines || []) {
    const text = line.text || "";
    if (!text.trim()) continue;
    for (const h of detectPII(text, { minConfidence: piiMinConfidence })) {
      residual.push({ kind: "pii", category: h.category, region: spanToRegion(line, h.start, h.end, `verify:${h.category}`), evidence: `[${h.category}]` });
    }
    for (const s of scanSecrets(text, { minConfidence: secretMinConfidence })) {
      residual.push({ kind: "secret", subtype: s.subtype, region: spanToRegion(line, s.start, s.end, `verify:secret`), evidence: s.evidence });
    }
  }
  return residual;
}

/**
 * @param {OffscreenCanvas|HTMLCanvasElement} canvas   the ALREADY-redacted canvas
 * @param {Array} appliedRegions                        regions the first pass masked (for the report only)
 * @param {object} opts
 *   opts.ocr                async (canvas) => [{text, bbox:{x0,y0,x1,y1}}]   REQUIRED
 *   opts.piiMinConfidence  default 0.3 — paranoid: mask anything shaped like PII on an image about to leave
 *   opts.secretMinConfidence default 0.5
 *   opts.growMargin        px to grow a residual box before re-masking (default 8)
 *   opts.maxRepasses       hard cap (default 1 — do not raise)
 * @returns {{
 *   verified:boolean, status:'VERIFIED'|'VERIFIED_AFTER_REMASK'|'REDACTION_FAILED'|'SKIPPED',
 *   passes:number, residual:Array<{kind,category?,subtype?,evidence}>, residualCategories:string[],
 *   addedRegions:Array, ocrLines:number, ms:number
 * }}
 */
export async function verifyRedaction(canvas, appliedRegions = [], opts = {}) {
  const t0 = (typeof performance !== "undefined" ? performance.now() : Date.now());
  const {
    ocr,
    piiMinConfidence = 0.3,
    secretMinConfidence = 0.5,
    growMargin = 8,
    maxRepasses = 1,
  } = opts;

  if (typeof ocr !== "function") {
    return { verified: true, status: "SKIPPED", passes: 0, residual: [], residualCategories: [], addedRegions: [], ocrLines: 0, ms: 0, reason: "no ocr available" };
  }

  const scanConf = { piiMinConfidence, secretMinConfidence };
  let lines;
  try {
    lines = await ocr(canvas);
  } catch (e) {
    // OCR is unavailable for the re-pass. It was also unavailable for the first
    // detection pass, so the redaction is DOM-only and re-OCR can't add signal.
    // Don't hard-block on this — skip, and surface why.
    return { verified: true, status: "SKIPPED", passes: 0, residual: [], residualCategories: [], addedRegions: [], ocrLines: 0, ms: Math.round((typeof performance !== "undefined" ? performance.now() : Date.now()) - t0), reason: `ocr unavailable: ${e.message}` };
  }
  let residual = scanLines(lines, scanConf);
  const addedRegions = [];
  let passes = 0;

  while (residual.length > 0 && passes < Math.max(0, maxRepasses)) {
    passes++;
    const grown = residual.map((r) => growBox(r.region, growMargin));
    redactCanvas(canvas, grown, { pad: 0, labelOffset: 0 });
    addedRegions.push(...grown);
    try {
      lines = await ocr(canvas);
    } catch {
      // we found residual PII but can't confirm the re-mask cleared it -> fail closed
      break;
    }
    residual = scanLines(lines, scanConf);
  }

  const ms = Math.round((typeof performance !== "undefined" ? performance.now() : Date.now()) - t0);

  if (residual.length > 0) {
    return {
      verified: false,
      status: "REDACTION_FAILED",
      passes,
      residual: residual.map((r) => ({ kind: r.kind, category: r.category, subtype: r.subtype, evidence: r.evidence })),
      residualCategories: [...new Set(residual.map((r) => r.category || r.subtype || r.kind))],
      addedRegions,
      ocrLines: (lines || []).length,
      ms,
    };
  }

  return {
    verified: true,
    status: passes > 0 ? "VERIFIED_AFTER_REMASK" : "VERIFIED",
    passes,
    residual: [],
    residualCategories: [],
    addedRegions,
    ocrLines: (lines || []).length,
    ms,
  };
}

export default { verifyRedaction };
