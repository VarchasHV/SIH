// Fuse the two detection channels (DOM classifier + on-device vision) into one
// list. Also reports, per item, which channels saw it - that feeds the
// "two-channel redundancy" number in the eval harness.

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
  email: "email",
  "email address": "email",
  aadhaar: "aadhaar",
  Aadhaar: "aadhaar",
  pan: "pan",
  PAN: "pan",
  "phone number": "phone",
  "phone-in": "phone",
  "credit/debit card number": "card",
  "credit-card": "card",
  ssn: "ssn",
  SSN: "ssn",
};
const fam = (c) => FAMILY[c] || c;

/**
 * @param {Array} domBoxes   - [{category, confidence, bbox:{x,y,w,h}, fieldId}]
 * @param {Array} visionBoxes- [{category, confidence, bbox:{x,y,w,h}, source:"ocr"|"face", value?}]
 * @param {number} iouThresh
 */
export function mergeDetections(domBoxes = [], visionBoxes = [], iouThresh = 0.4) {
  const items = domBoxes.map((d, i) => ({
    id: d.fieldId || `dom-${i}`,
    category: d.category,
    confidence: d.confidence ?? 0.8,
    bbox: { ...d.bbox },
    sources: ["dom"],
    fieldId: d.fieldId || null,
    value: d.value || null,
  }));

  for (let j = 0; j < visionBoxes.length; j++) {
    const v = visionBoxes[j];
    const src = v.source || "ocr";
    let hit = null;
    for (const it of items) {
      if (fam(it.category) === fam(v.category) && iou(it.bbox, v.bbox) >= iouThresh) {
        hit = it;
        break;
      }
    }
    if (hit) {
      if (!hit.sources.includes(src)) hit.sources.push(src);
      hit.bbox = unionBox(hit.bbox, v.bbox);
      hit.confidence = Math.max(hit.confidence, v.confidence ?? 0.7);
      if (!hit.value && v.value) hit.value = v.value;
    } else {
      items.push({
        id: `${src}-${j}`,
        category: v.category,
        confidence: v.confidence ?? 0.7,
        bbox: { ...v.bbox },
        sources: [src],
        fieldId: null,
        value: v.value || null,
      });
    }
  }

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
    visionUniqueRate: visionOnly / total, // PII the DOM channel alone would have missed
  };
}

export default { mergeDetections, redundancyStats, iou };
