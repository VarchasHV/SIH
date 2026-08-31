// Offscreen document: all on-device vision inference + pixel redaction.
// Kept off the page and the service worker so neither stalls.
//
//   in  : { screenshot(dataURL), domPiiBoxes(cssPx), fields[], dpr, mode }
//   out : { redactedDataURL, detections[], fieldCategories, stats, timings }
//         -- NO raw OCR text ever leaves this document.

import { detectPII } from "./lib/pii-rules.mjs";
import { redactCanvas } from "./lib/redact.mjs";
import { mergeDetections, redundancyStats } from "./lib/merge.mjs";
import { associateLabels } from "./lib/label-assoc.mjs";
import { isSensitiveCategory } from "./lib/sensitive-fields.mjs";
import { detectObjects, visionModelInfo } from "./lib/vision-transformer.mjs";

const url = (p) => chrome.runtime.getURL(p);

let ocrWorker = null;
let faceDetector = null;
let faceLoadFailed = false;

async function getOcrWorker() {
  if (ocrWorker) return ocrWorker;
  ocrWorker = await Tesseract.createWorker("eng", 1, {
    workerPath: url("vendor/tesseract-worker.min.js"),
    corePath: url("vendor/"),
    langPath: url("vendor/"),
    gzip: true,
    workerBlobURL: false,
  });
  return ocrWorker;
}

async function getFaceDetector() {
  if (faceDetector || faceLoadFailed) return faceDetector;
  try {
    const { FilesetResolver, FaceDetector } = await import("./vendor/tasks-vision.mjs");
    const fileset = await FilesetResolver.forVisionTasks(url("vendor/mp-wasm"));
    faceDetector = await FaceDetector.createFromOptions(fileset, {
      baseOptions: { modelAssetPath: url("vendor/blaze_face_short_range.tflite") },
      runningMode: "IMAGE",
      minDetectionConfidence: 0.5,
    });
  } catch (e) {
    console.warn("[offscreen] face detector unavailable:", e.message);
    faceLoadFailed = true;
  }
  return faceDetector;
}

async function loadBitmap(dataURL) {
  const blob = await (await fetch(dataURL)).blob();
  return createImageBitmap(blob);
}

async function runOCR(bitmap) {
  const t0 = performance.now();
  const worker = await getOcrWorker();
  const { data } = await worker.recognize(bitmap, {}, { text: true, blocks: true });
  const lines = [];
  const pushLine = (l) => l && l.bbox && lines.push({ text: l.text || "", bbox: l.bbox });
  if (Array.isArray(data.lines)) {
    data.lines.forEach(pushLine); // flat shape (older / some builds)
  } else {
    for (const block of data.blocks || []) {
      for (const para of block.paragraphs || []) (para.lines || []).forEach(pushLine);
    }
  }
  // last-resort: split the full text, no per-line bbox (whole-image fallback)
  if (!lines.length && data.text) {
    lines.push({ text: data.text, bbox: { x0: 0, y0: 0, x1: bitmap.width, y1: bitmap.height } });
  }
  const dets = [];
  for (const line of lines) {
    for (const hit of detectPII(line.text)) {
      const b = line.bbox; // {x0,y0,x1,y1}
      const width = b.x1 - b.x0;
      // approx horizontal span of the match within the line
      const cs = hit.start / Math.max(1, line.text.length);
      const ce = hit.end / Math.max(1, line.text.length);
      dets.push({
        category: hit.category,
        confidence: hit.confidence,
        source: "ocr",
        bbox: { x: b.x0 + cs * width, y: b.y0, w: (ce - cs) * width, h: b.y1 - b.y0 },
      });
    }
  }
  return { dets, lines, lineCount: lines.length, ms: performance.now() - t0 };
}

async function runFaces(bitmap) {
  const t0 = performance.now();
  const det = await getFaceDetector();
  if (!det) return { dets: [], ms: performance.now() - t0, available: false };
  const res = det.detect(bitmap);
  const dets = (res.detections || []).map((d) => ({
    category: "face",
    confidence: d.categories?.[0]?.score ?? 0.9,
    source: "face",
    bbox: { x: d.boundingBox.originX, y: d.boundingBox.originY, w: d.boundingBox.width, h: d.boundingBox.height },
  }));
  return { dets, ms: performance.now() - t0, available: true };
}

async function process({ screenshot, domPiiBoxes = [], fields = [], dpr = 1, mode = "blackout" }) {
  const timings = {};
  const tAll = performance.now();

  const bitmap = await loadBitmap(screenshot);
  const canvas = new OffscreenCanvas(bitmap.width, bitmap.height);
  canvas.getContext("2d").drawImage(bitmap, 0, 0);

  const [ocr, faces, vit] = await Promise.all([
    runOCR(bitmap).catch((e) => ({ dets: [], lines: [], lineCount: 0, ms: 0, error: e.message })),
    runFaces(bitmap).catch((e) => ({ dets: [], ms: 0, available: false, error: e.message })),
    // Vision Transformer (YOLOS-tiny) — WebGPU with WASM fallback
    detectObjects(url, canvas).catch((e) => ({ dets: [], backend: null, ms: 0, loadMs: null, labels: [], available: false, error: e.message, gpu: { available: false } })),
  ]);
  timings.ocrMs = Math.round(ocr.ms);
  timings.faceMs = Math.round(faces.ms);
  timings.vitMs = Math.round(vit.ms);
  if (vit.loadMs != null) timings.vitLoadMs = vit.loadMs;

  // vision-derived field classifications for fields the DOM couldn't name
  const labelDets = fields.length ? associateLabels(ocr.lines || [], fields, dpr) : [];

  // DOM boxes: css px -> screenshot (device) px
  const domScaled = domPiiBoxes.map((d) => ({
    category: d.category,
    confidence: d.confidence,
    fieldId: d.fieldId,
    bbox: { x: d.bbox.x * dpr, y: d.bbox.y * dpr, w: d.bbox.w * dpr, h: d.bbox.h * dpr },
  }));

  // Only the ViT's privacy-relevant classes (person) join the redaction merge;
  // the rest of its labels are kept as visual context, not as redaction targets.
  const vitPrivacyDets = (vit.dets || []).filter((d) => d.privacy);
  const visionDets = [...ocr.dets, ...faces.dets, ...labelDets, ...vitPrivacyDets];
  const merged = mergeDetections(domScaled, visionDets, 0.35);

  // fieldId -> category, for the service worker to enrich the skeleton
  const fieldCategories = {};
  for (const d of labelDets) fieldCategories[d.fieldId] = d.category;

  // redact: union of every merged region whose category the shared module
  // flags as sensitive. This ensures the screenshot blackout list is
  // decided identically to skeleton filtering and the executor guard.
  const regions = merged
    .filter((m) => isSensitiveCategory(m.category) || m.category === "face" || m.category === "person")
    .map((m) => ({ ...m.bbox, category: m.category }));
  const tRedact = performance.now();
  const applied = redactCanvas(canvas, regions, { mode });
  timings.redactMs = Math.round(performance.now() - tRedact);

  const blob = await canvas.convertToBlob({ type: "image/jpeg", quality: 0.82 });
  const redactedDataURL = await new Promise((res) => {
    const fr = new FileReader();
    fr.onload = () => res(fr.result);
    fr.readAsDataURL(blob);
  });

  timings.totalMs = Math.round(performance.now() - tAll);

  return {
    redactedDataURL,
    // strip values: only bbox + category + which channel saw it
    detections: merged.map((m) => ({ category: m.category, confidence: Number(m.confidence.toFixed(2)), sources: m.sources, bbox: roundBox(m.bbox), fieldId: m.fieldId })),
    fieldCategories,
    redactedRegions: applied.regions.map((r) => ({ ...roundBox(r), mode: r.mode, category: r.category })),
    stats: {
      ...redundancyStats(merged),
      ocrLines: ocr.lineCount,
      visionLabelledFields: labelDets.length,
      faceDetectorAvailable: faces.available,
      ocrError: ocr.error || null,
      faceError: faces.error || null,
      // --- client-side Vision Transformer ---
      vit: {
        ...visionModelInfo(),
        available: vit.available,
        backend: vit.backend,            // "webgpu" | "wasm" | null
        gpu: vit.gpu,                    // adapter info when WebGPU is present
        objects: (vit.dets || []).length,
        privacyObjects: vitPrivacyDets.length,
        labels: vit.labels || [],        // what the ViT saw on screen
        error: vit.error || null,
      },
    },
    timings,
  };
}

const roundBox = (b) => ({ x: Math.round(b.x), y: Math.round(b.y), w: Math.round(b.w), h: Math.round(b.h) });

chrome.runtime.onMessage.addListener((msg, _s, sendResponse) => {
  if (msg.action !== "PL_VISION") return;
  process(msg.payload)
    .then((r) => sendResponse({ ok: true, ...r }))
    .catch((e) => sendResponse({ ok: false, error: e.message, stack: e.stack }));
  return true;
});

// tell the worker we're alive
chrome.runtime.sendMessage({ action: "PL_OFFSCREEN_READY" }).catch(() => {});
