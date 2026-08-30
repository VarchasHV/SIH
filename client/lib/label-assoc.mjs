// Vision label association: pair an OCR caption with an unclassified field the
// DOM couldn't name (obfuscated markup, canvas-drawn fields, cross-origin
// frames), then classify the field from the caption text. This is the vision
// channel's contribution to *field detection*, on top of PII-value redaction.

import { classifySignals } from "./field-classifier.mjs";

/**
 * @param {Array<{text:string,bbox:{x0,y0,x1,y1}}>} lines   OCR lines (device px)
 * @param {Array<{id:string,piiCategory:?string,bbox:{x,y,w,h}}>} fields  CSS px
 * @param {number} dpr
 * @returns {Array<{category,confidence,source,fieldId,bbox}>}  bbox in device px
 */
export function associateLabels(lines, fields, dpr = 1) {
  const out = [];
  const captions = (lines || [])
    .map((l) => ({ text: (l.text || "").replace(/\s+/g, " ").trim(), b: l.bbox }))
    .filter((l) => l.b && l.text && l.text.length <= 60 && /[a-zA-Z]/.test(l.text));

  for (const f of fields || []) {
    if (f.piiCategory) continue;
    const fb = { x: f.bbox.x * dpr, y: f.bbox.y * dpr, w: f.bbox.w * dpr, h: f.bbox.h * dpr };
    const cy = fb.y + fb.h / 2;
    let best = null;
    let bestCost = Infinity;
    for (const l of captions) {
      const { x0, y0, x1, y1 } = l.b;
      const lcy = (y0 + y1) / 2;
      let cost = Infinity;
      // caption to the LEFT, roughly same row
      if (x1 <= fb.x + 8 && Math.abs(lcy - cy) < fb.h * 1.2 && fb.x - x1 < 320 * dpr) {
        cost = fb.x - x1 + Math.abs(lcy - cy);
      }
      // caption ABOVE, x-overlapping
      const overlap = Math.min(x1, fb.x + fb.w) - Math.max(x0, fb.x);
      if (y1 <= fb.y + 6 && overlap > 0 && fb.y - y1 < 60 * dpr) {
        cost = Math.min(cost, (fb.y - y1) * 1.5 + Math.max(0, fb.x - x0));
      }
      if (cost < bestCost) { bestCost = cost; best = l; }
    }
    if (!best) continue;
    const cls = classifySignals({ tagName: "INPUT", type: "text", labelText: best.text });
    if (cls && cls.category !== "safe") {
      out.push({
        category: cls.category,
        confidence: Math.min(0.78, cls.confidence),
        source: "ocr-label",
        fieldId: f.id,
        bbox: fb,
        caption: best.text,
      });
    }
  }
  return out;
}

export default { associateLabels };
