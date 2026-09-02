// Phase 8 — score the fusion + redaction geometry on the synthetic screen corpus.
//
//   node eval/screens/score.mjs
//
// Pipeline per screen:
//   DOM channel   <- elements of kind "field" (declared field type = DOM class)
//   OCR channel   <- detectPII() run on each element's declared text (treated as
//                    a PERFECT OCR read — the optimistic ceiling)
//   face channel  <- elements whose pii.category is "face"
//   -> mergeDetections()  ->  regions where m.redact is true
//
// Scored against the ground-truth PII boxes (elements with a `pii` label):
//   visualRecall       GT PII elements with a covering redaction region
//   visualPrecision    redaction regions that land on a GT PII element
//   overRedaction      1 - visualPrecision  (redacted a non-PII element)
//   bboxIoU            mean IoU over matched (region, GT) pairs
//   geometricLeakage   GT PII box AREA left uncovered / total GT PII box area
//   adversarialFP      non-PII look-alikes (order id, SKU, IPv4, build #) redacted
//
// NOT MEASURED here: real OCR recall, real ViT/face recall, real rendering.
// Compose with eval/bench OCR recall (ASCII 91%, OCR-garbled 16%) for an
// end-to-end estimate.

import { readFileSync, writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { detectPII } from "../../client/lib/pii-rules.mjs";
import { mergeDetections } from "../../client/lib/merge.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
const screens = readFileSync(join(HERE, "screens.jsonl"), "utf8").trim().split("\n").map((l) => JSON.parse(l));

function iou(a, b) {
  const x1 = Math.max(a.x, b.x), y1 = Math.max(a.y, b.y);
  const x2 = Math.min(a.x + a.w, b.x + b.w), y2 = Math.min(a.y + a.h, b.y + b.h);
  const inter = Math.max(0, x2 - x1) * Math.max(0, y2 - y1);
  if (!inter) return 0;
  return inter / (a.w * a.h + b.w * b.h - inter);
}
function coveredArea(box, regions) {
  // sample-grid estimate of box area covered by the union of regions
  const N = 24;
  let hit = 0;
  for (let i = 0; i < N; i++) for (let j = 0; j < N; j++) {
    const px = box.x + (i + 0.5) / N * box.w;
    const py = box.y + (j + 0.5) / N * box.h;
    if (regions.some((r) => px >= r.x && px <= r.x + r.w && py >= r.y && py <= r.y + r.h)) hit++;
  }
  return hit / (N * N);
}

const NON_PII_ADVERSARIAL = /order\s*#|invoice\s*no|inv-|sku|build \d|region |last login from|member since|theme preference|next review|deploys/i;

function scoreScreen(s) {
  const dom = s.elements
    .filter((e) => e.kind === "field" && e.pii)
    .map((e) => ({ category: e.pii.category, confidence: 0.9, bbox: e.bbox, fieldId: e.id }));
  const domFieldCategories = Object.fromEntries(dom.map((d) => [d.fieldId, d.category]));

  const vision = [];
  for (const e of s.elements) {
    if (e.pii?.category === "face") { vision.push({ category: "face", confidence: 0.95, source: "face", bbox: e.bbox }); continue; }
    if (e.pii?.category === "id-document") { vision.push({ category: "sensitive", confidence: 0.8, source: "vit", bbox: e.bbox }); continue; }
    for (const h of detectPII(e.text)) {
      vision.push({ category: h.category, confidence: h.confidence, source: "ocr", bbox: e.bbox });
    }
  }

  const merged = mergeDetections(dom, vision, 0.3, { redactThreshold: 0.5, domFieldCategories });
  const regions = merged.filter((m) => m.redact).map((m) => m.bbox);

  const gtPii = s.elements.filter((e) => e.pii);
  const gtAdversarial = s.elements.filter((e) => !e.pii && NON_PII_ADVERSARIAL.test(e.text));

  let recalled = 0, leakAreaNum = 0, leakAreaDen = 0;
  const ious = [];
  for (const g of gtPii) {
    const cov = coveredArea(g.bbox, regions);
    if (cov >= 0.6) recalled++;
    leakAreaNum += (1 - cov) * (g.bbox.w * g.bbox.h);
    leakAreaDen += g.bbox.w * g.bbox.h;
    const best = Math.max(0, ...regions.map((r) => iou(r, g.bbox)));
    if (best > 0) ious.push(best);
  }

  let regionsOnPii = 0;
  for (const r of regions) {
    if (gtPii.some((g) => iou(r, g.bbox) >= 0.1 || coveredArea(g.bbox, [r]) > 0.3)) regionsOnPii++;
  }
  const advFP = gtAdversarial.filter((g) => regions.some((r) => iou(r, g.bbox) >= 0.1)).length;

  return {
    name: s.name, type: s.type, theme: s.theme,
    gtPii: gtPii.length, gtAdversarial: gtAdversarial.length,
    regions: regions.length,
    visualRecall: gtPii.length ? recalled / gtPii.length : 1,
    visualPrecision: regions.length ? regionsOnPii / regions.length : 1,
    bboxIoU: ious.length ? ious.reduce((a, b) => a + b, 0) / ious.length : 0,
    geometricLeakage: leakAreaDen ? leakAreaNum / leakAreaDen : 0,
    adversarialFP: gtAdversarial.length ? advFP / gtAdversarial.length : 0,
    adversarialFPCount: advFP,
  };
}

const rows = screens.map(scoreScreen);

const agg = (key, weightKey) => {
  let num = 0, den = 0;
  for (const r of rows) { const w = weightKey ? r[weightKey] : 1; num += r[key] * w; den += w; }
  return den ? num / den : 0;
};
const overall = {
  visualRecall: agg("visualRecall", "gtPii"),
  visualPrecision: agg("visualPrecision", "regions"),
  bboxIoU: rows.reduce((a, r) => a + r.bboxIoU, 0) / rows.length,
  geometricLeakage: agg("geometricLeakage", "gtPii"),
  adversarialFP: agg("adversarialFP", "gtAdversarial"),
  totalAdversarialFP: rows.reduce((a, r) => a + r.adversarialFPCount, 0),
};

const meta = {
  generatedAt: new Date().toISOString(), nodeVersion: process.version,
  screens: screens.length, gtPiiTotal: rows.reduce((a, r) => a + r.gtPii, 0),
  disclaimer: "Fusion + redaction geometry on DECLARED boxes/text. OCR recall, ViT/face recall and rendering are NOT MEASURED — real end-to-end numbers are lower.",
};
writeFileSync(join(HERE, "screens.results.json"), JSON.stringify({ meta, overall, rows }, null, 2) + "\n");

const pct = (n) => (n * 100).toFixed(1) + "%";
let md = `# Screenshot / Vision Benchmark (Phase 8)\n\n`;
md += `> **Layout specs, not pixels.** No headless browser / real OCR in this environment. This measures the FUSION + REDACTION GEOMETRY: given a screen with PII at known boxes and a perfect OCR read, does \`mergeDetections\` + the risk model cover the PII boxes and leave the decoys alone? Real end-to-end numbers are lower — multiply by OCR recall (eval/bench: ASCII 91%, OCR-garbled 16%) and real ViT/face recall (NOT MEASURED).\n\n`;
md += `**Corpus**: ${screens.length} screens · ${meta.gtPiiTotal} ground-truth PII boxes · ${[...new Set(screens.map((s) => s.type))].join(", ")}\n\n`;
md += `## Overall\n\n`;
md += `| Metric | Value |\n|---|--:|\n`;
md += `| Visual PII recall (box covered) | ${pct(overall.visualRecall)} |\n`;
md += `| Visual PII precision (region on PII) | ${pct(overall.visualPrecision)} |\n`;
md += `| Mean bbox IoU (matched) | ${pct(overall.bboxIoU)} |\n`;
md += `| Geometric leakage (PII area uncovered) | ${pct(overall.geometricLeakage)} |\n`;
md += `| Adversarial false-redaction (order-id/SKU/IPv4/build) | ${pct(overall.adversarialFP)} (${overall.totalAdversarialFP} boxes) |\n`;
md += `\n## Per screen\n\n`;
md += `| Screen | Type | GT PII | Recall | Precision | bbox IoU | Leakage | Adv-FP |\n|---|---|--:|--:|--:|--:|--:|--:|\n`;
for (const r of rows) {
  md += `| ${r.name} | ${r.type} | ${r.gtPii} | ${pct(r.visualRecall)} | ${pct(r.visualPrecision)} | ${pct(r.bboxIoU)} | ${pct(r.geometricLeakage)} | ${r.adversarialFPCount}/${r.gtAdversarial} |\n`;
}
md += `\n_NOT MEASURED: real OCR, real ViT/face detection, real rendering, dark/light pixel contrast, font scaling effects._\n`;
writeFileSync(join(HERE, "screens.results.md"), md);

console.error(`screens: recall ${pct(overall.visualRecall)} · precision ${pct(overall.visualPrecision)} · leakage ${pct(overall.geometricLeakage)} · adv-FP ${overall.totalAdversarialFP}`);
console.error(`wrote eval/screens/screens.results.{json,md}`);
