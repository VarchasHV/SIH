// Fuse the perception channels (DOM classifier + OCR + face/ViT) into one list
// of detections, each carrying a documented privacy-risk score and a redaction
// decision (Phase 9).
//
// ─────────────────────────────────────────────────────────────────────────
// FUSION STRATEGY (why this is not a blind OR)
//
// A blind OR of every channel maximises recall but destroys precision — a
// stray OCR "invoice number" would blackout a real product field. Instead each
// detection gets a privacyRisk in [0,1] built from:
//
//   1. base risk by category
//        restricted (password / aadhaar / PAN / card / SSN / CVV / bank)  0.92
//        face / person                                                    0.85
//        profile PII (name / email / phone / address / DOB)               0.62
//        weak/ambiguous shape IDs (ipv4, bare dob)                        0.35
//        everything else                                                  0.15
//
//   2. corroboration — more independent channels agreeing raises risk
//        +0.12 for a 2nd source, +0.06 for a 3rd  (capped at 1.0)
//        DOM field of a matching sensitive type + any OCR/vision hit -> 1.0
//
//   3. conflict de-rating — lowers risk when signals disagree
//        a single OCR-only hit whose category the DOM channel classified as
//        NON-sensitive for the same field  -> x0.5
//        an OCR-only weak-ID hit with no corroboration                    -> x0.7
//
//   4. detector confidence — multiply by the detection's own confidence
//
// redact = privacyRisk >= redactThreshold (default 0.5); a restricted category
// always redacts. `reason` records the decision in words.
// ─────────────────────────────────────────────────────────────────────────

import { isRestrictedCategory, isSensitiveCategory } from "./sensitive-fields.mjs";

export function iou(a, b) {
  const x1 = Math.max(a.x, b.x);
  const y1 = Math.max(a.y, b.y);
  const x2 = Math.min(a.x + a.w, b.x + b.w);
  const y2 = Math.min(a.y + a.h, b.y + b.h);
  const inter = Math.max(0, x2 - x1) * Math.max(0, y2 - y1);
  if (!inter) return 0;
  const union = a.w * a.h + b.w * b.h - inter;
  return inter / union;
}

function unionBox(a, b) {
  const x = Math.min(a.x, b.x);
  const y = Math.min(a.y, b.y);
  return { x, y, w: Math.max(a.x + a.w, b.x + b.w) - x, h: Math.max(a.y + a.h, b.y + b.h) - y };
}

// Rough category compatibility so an OCR "email" near a DOM "email" field merges,
// but a DOM "password" box and an OCR "aadhaar" hit stay separate.
const FAMILY = {
  email: "email", "email address": "email",
  aadhaar: "aadhaar", Aadhaar: "aadhaar",
  pan: "pan", PAN: "pan",
  "phone number": "phone", "phone-in": "phone",
  "credit/debit card number": "card", "credit-card": "card",
  ssn: "ssn", SSN: "ssn",
};
const fam = (c) => FAMILY[c] || c;

const WEAK_CATEGORIES = new Set(["ipv4", "dob", "voter-id", "passport-in"]);

// `fromDom` = the detection is (also) a DOM form field the classifier labelled
// with this category. That is a much stronger signal than a bare shape match,
// so the weak-category demotion does not apply.
function baseRisk(category, fromDom) {
  if (isRestrictedCategory(category)) return 0.92;
  if (category === "face" || category === "person") return 0.85;
  if (WEAK_CATEGORIES.has(category) && !fromDom) return 0.35;
  if (isSensitiveCategory(category)) return 0.62;
  return fromDom ? 0.5 : 0.15;
}

/**
 * @param {object} item      merged detection {category, confidence, sources, bbox, fieldId, domFieldCategory?}
 * @param {number} threshold redact threshold
 * @returns {{privacyRisk:number, redact:boolean, reason:string}}
 */
function scoreRisk(item, threshold) {
  const restricted = isRestrictedCategory(item.category);
  const nSources = item.sources.length;
  const hasDom = item.sources.includes("dom");
  let risk = baseRisk(item.category, hasDom);
  const why = [`base ${risk.toFixed(2)} (${item.category}${hasDom ? ", dom field" : ""})`];

  const hasVision = item.sources.some((s) => s !== "dom");

  // 1. corroboration
  if (hasDom && hasVision && restricted) {
    risk = 1.0;
    why.push("DOM sensitive field + vision hit -> 1.00");
  } else if (nSources >= 2) {
    const bump = 0.12 + (nSources >= 3 ? 0.06 : 0);
    risk = Math.min(1, risk + bump);
    why.push(`+${bump.toFixed(2)} corroboration (${item.sources.join("+")})`);
  }

  // 2. conflict de-rating (only for non-restricted — never soften a password box)
  if (!restricted) {
    if (item.domFieldCategory && !isSensitiveCategory(item.domFieldCategory) && !hasDom) {
      risk *= 0.5;
      why.push(`x0.5 DOM says field is "${item.domFieldCategory}" (not sensitive)`);
    } else if (!hasDom && nSources === 1 && WEAK_CATEGORIES.has(item.category)) {
      risk *= 0.7;
      why.push("x0.7 lone weak-ID OCR hit, no corroboration");
    }
  }

  // 3. detector confidence — not applied to restricted categories (a detected
  //    password / Aadhaar field is binary; detectPII already gates bad checksums)
  if (!restricted) {
    const conf = item.confidence ?? 0.7;
    risk *= (0.55 + 0.45 * conf);
    why.push(`xconf ${conf.toFixed(2)}`);
  }

  risk = Math.max(0, Math.min(1, risk));
  const redact = restricted || risk >= threshold;
  why.push(redact ? `=> REDACT (${risk.toFixed(2)} >= ${threshold})` : `=> keep (${risk.toFixed(2)} < ${threshold})`);
  return { privacyRisk: +risk.toFixed(3), redact, reason: why.join("; ") };
}

/**
 * @param {Array} domBoxes   - [{category, confidence, bbox:{x,y,w,h}, fieldId}]
 * @param {Array} visionBoxes- [{category, confidence, bbox:{x,y,w,h}, source:"ocr"|"face"|"vit", value?}]
 * @param {number} iouThresh
 * @param {{redactThreshold?:number, domFieldCategories?:Record<string,string>}} [opts]
 */
export function mergeDetections(domBoxes = [], visionBoxes = [], iouThresh = 0.4, opts = {}) {
  const redactThreshold = opts.redactThreshold ?? 0.5;
  const domFieldCategories = opts.domFieldCategories || {};

  const items = domBoxes.map((d, i) => ({
    id: d.fieldId || `dom-${i}`,
    category: d.category,
    confidence: d.confidence ?? 0.8,
    bbox: { ...d.bbox },
    sources: ["dom"],
    fieldId: d.fieldId || null,
    value: d.value || null,
    domFieldCategory: d.category,
  }));

  for (let j = 0; j < visionBoxes.length; j++) {
    const v = visionBoxes[j];
    const src = v.source || "ocr";
    let hit = null;
    for (const it of items) {
      if (fam(it.category) === fam(v.category) && iou(it.bbox, v.bbox) >= iouThresh) { hit = it; break; }
    }
    if (hit) {
      if (!hit.sources.includes(src)) hit.sources.push(src);
      hit.bbox = unionBox(hit.bbox, v.bbox);
      hit.confidence = Math.max(hit.confidence, v.confidence ?? 0.7);
      if (!hit.value && v.value) hit.value = v.value;
    } else {
      // vision-only detection — attach the DOM's opinion of any field it overlaps
      let domCat = null;
      for (const d of domBoxes) {
        if (d.fieldId && domFieldCategories[d.fieldId] && iou(d.bbox, v.bbox) >= iouThresh) {
          domCat = domFieldCategories[d.fieldId];
          break;
        }
      }
      items.push({
        id: `${src}-${j}`,
        category: v.category,
        confidence: v.confidence ?? 0.7,
        bbox: { ...v.bbox },
        sources: [src],
        fieldId: null,
        value: v.value || null,
        domFieldCategory: domCat,
      });
    }
  }

  for (const it of items) Object.assign(it, scoreRisk(it, redactThreshold));
  return items;
}

export function redundancyStats(merged) {
  const total = merged.length || 1;
  const both = merged.filter((m) => m.sources.length > 1).length;
  const domOnly = merged.filter((m) => m.sources.length === 1 && m.sources[0] === "dom").length;
  const visionOnly = merged.filter((m) => m.sources.length === 1 && m.sources[0] !== "dom").length;
  return {
    total: merged.length,
    both,
    domOnly,
    visionOnly,
    redactedCount: merged.filter((m) => m.redact).length,
    visionUniqueRate: visionOnly / total, // PII the DOM channel alone would have missed
  };
}

export default { mergeDetections, redundancyStats, iou };
