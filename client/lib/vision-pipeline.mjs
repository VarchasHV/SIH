// Universal on-device vision pipeline for Privacy Lens.
// Works seamlessly in Chrome offscreen documents, Firefox background contexts, and workers.
//
//   in  : { screenshot(dataURL), domPiiBoxes(cssPx), fields[], dpr, mode }
//   out : { redactedDataURL, detections[], fieldCategories, stats, timings }
//         -- NO raw OCR text or raw PII ever leaves this pipeline.

import { detectPII } from "./pii-rules.mjs";
import { redactCanvas } from "./redact.mjs";
import { mergeDetections, redundancyStats } from "./merge.mjs";
import { associateLabels } from "./label-assoc.mjs";
import { detectObjects, visionModelInfo } from "./vision-transformer.mjs";
import { detectPromptInjection } from "./adversarial-guard.mjs";
import { verifyRedaction } from "./redaction-verify.mjs";

const getRuntimeUrl = (p) => {
  if (typeof chrome !== "undefined" && chrome.runtime?.getURL) {
    return chrome.runtime.getURL(p);
  }
  if (typeof browser !== "undefined" && browser.runtime?.getURL) {
    return browser.runtime.getURL(p);
  }
  return `./${p}`;
};

let ocrWorker = null;
let faceDetector = null;
let faceLoadFailed = false;

async function getTesseract() {
  if (typeof globalThis.Tesseract !== "undefined") {
    return globalThis.Tesseract;
  }
  try {
    const tessUrl = getRuntimeUrl("vendor/tesseract.min.js");
    await import(tessUrl);
    return globalThis.Tesseract;
  } catch (e) {
    console.warn("[vision-pipeline] dynamic tesseract load fallback:", e.message);
    return globalThis.Tesseract;
  }
}

async function getOcrWorker() {
  if (ocrWorker) return ocrWorker;
  const Tesseract = await getTesseract();
  if (!Tesseract || typeof Tesseract.createWorker !== "function") {
    throw new Error("Tesseract runtime is unavailable");
  }
  ocrWorker = await Tesseract.createWorker("eng", 1, {
    workerPath: getRuntimeUrl("vendor/tesseract-worker.min.js"),
    corePath: getRuntimeUrl("vendor/"),
    langPath: getRuntimeUrl("vendor/"),
    gzip: true,
    workerBlobURL: false,
  });
  return ocrWorker;
}

async function getFaceDetector() {
  if (faceDetector || faceLoadFailed) return faceDetector;
  try {
    const { FilesetResolver, FaceDetector } = await import(getRuntimeUrl("vendor/tasks-vision.mjs"));
    const fileset = await FilesetResolver.forVisionTasks(getRuntimeUrl("vendor/mp-wasm"));
    faceDetector = await FaceDetector.createFromOptions(fileset, {
      baseOptions: { modelAssetPath: getRuntimeUrl("vendor/blaze_face_short_range.tflite") },
      runningMode: "IMAGE",
      minDetectionConfidence: 0.5,
    });
  } catch (e) {
    console.warn("[vision-pipeline] face detector unavailable:", e.message);
    faceLoadFailed = true;
  }
  return faceDetector;
}

async function loadBitmap(dataURL) {
  try {
    const blob = await (await fetch(dataURL)).blob();
    if (typeof createImageBitmap === "function") {
      return createImageBitmap(blob);
    }
    if (typeof globalThis.Image !== "undefined") {
      return new Promise((resolve, reject) => {
        const img = new Image();
        img.onload = () => resolve(img);
        img.onerror = reject;
        img.src = dataURL;
      });
    }
  } catch {}
  return { width: 1, height: 1 };
}

// HiDPI / 4K captures carry no extra text detail over their CSS-pixel size but
// cost 4-16x the single-threaded WASM OCR time. Downscale to ~1x (capped) before
// OCR, then scale the line boxes back so every caller keeps working in
// full-resolution screenshot coordinates.
const OCR_TARGET_MAX_WIDTH = 2000;

function makeCanvas(w, h) {
  if (typeof OffscreenCanvas !== "undefined") return new OffscreenCanvas(w, h);
  if (typeof document !== "undefined" && document.createElement) {
    const c = document.createElement("canvas");
    c.width = w;
    c.height = h;
    return c;
  }
  return null;
}

async function ocrLinesScaled(source, dpr = 1, fullW = 1, fullH = 1) {
  const w = source?.width || fullW;
  const h = source?.height || fullH;
  let scale = dpr > 1 ? 1 / dpr : 1;
  if (w * scale > OCR_TARGET_MAX_WIDTH) scale = OCR_TARGET_MAX_WIDTH / w;
  if (!w || !h || scale >= 0.999) return ocrLines(source, w, h);

  const sw = Math.max(1, Math.round(w * scale));
  const sh = Math.max(1, Math.round(h * scale));
  const small = makeCanvas(sw, sh);
  if (!small) return ocrLines(source, w, h);
  try {
    small.getContext("2d").drawImage(source, 0, 0, sw, sh);
  } catch {
    return ocrLines(source, w, h);
  }
  const inv = 1 / scale;
  const lines = await ocrLines(small, sw, sh);
  return lines.map((l) => ({
    text: l.text,
    bbox: { x0: l.bbox.x0 * inv, y0: l.bbox.y0 * inv, x1: l.bbox.x1 * inv, y1: l.bbox.y1 * inv },
  }));
}

// OCR any source Tesseract.js accepts (ImageBitmap, canvas, ImageData, dataURL)
// -> [{ text, bbox:{x0,y0,x1,y1} }]. Reuses the single shared worker.
async function ocrLines(source, fallbackW = 1, fallbackH = 1) {
  const worker = await getOcrWorker();
  const { data } = await worker.recognize(source, {}, { text: true, blocks: true });
  const lines = [];
  const pushLine = (l) => l && l.bbox && lines.push({ text: l.text || "", bbox: l.bbox });
  if (Array.isArray(data.lines)) {
    data.lines.forEach(pushLine);
  } else {
    for (const block of data.blocks || []) {
      for (const para of block.paragraphs || []) (para.lines || []).forEach(pushLine);
    }
  }
  if (!lines.length && data.text) {
    lines.push({ text: data.text, bbox: { x0: 0, y0: 0, x1: fallbackW, y1: fallbackH } });
  }
  return lines;
}

async function runOCR(bitmap, dpr = 1) {
  const t0 = performance.now();
  const lines = await ocrLinesScaled(bitmap, dpr, bitmap.width, bitmap.height);
  const dets = [];
  for (const line of lines) {
    // 1. Scan for PII text
    for (const hit of detectPII(line.text)) {
      const b = line.bbox;
      const width = b.x1 - b.x0;
      const cs = hit.start / Math.max(1, line.text.length);
      const ce = hit.end / Math.max(1, line.text.length);
      dets.push({
        category: hit.category,
        confidence: hit.confidence,
        source: "ocr",
        bbox: { x: b.x0 + cs * width, y: b.y0, w: (ce - cs) * width, h: b.y1 - b.y0 },
      });
    }

    // 2. Scan for Indirect Prompt Injection text
    const inj = detectPromptInjection(line.text);
    if (inj.isInjection) {
      const b = line.bbox;
      dets.push({
        category: "adversarial_injection",
        confidence: inj.confidence || 0.95,
        source: "ocr_injection_guard",
        bbox: { x: b.x0, y: b.y0, w: b.x1 - b.x0, h: b.y1 - b.y0 },
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

export async function processVision({ screenshot, domPiiBoxes = [], fields = [], dpr = 1, mode = "blackout", a11yStats = null, forceVision = false, visionStageBaselineMs = null, skipVerify = false }) {
  const timings = {};
  const tAll = performance.now();

  const bitmap = await loadBitmap(screenshot);
  let canvas;
  if (typeof OffscreenCanvas !== "undefined") {
    canvas = new OffscreenCanvas(bitmap.width, bitmap.height);
  } else if (typeof document !== "undefined" && document.createElement) {
    canvas = document.createElement("canvas");
    canvas.width = bitmap.width;
    canvas.height = bitmap.height;
  } else {
    // Node.js test environment fallback canvas mock
    canvas = {
      width: bitmap.width || 1,
      height: bitmap.height || 1,
      getContext: () => ({ drawImage: () => {}, fillRect: () => {}, toDataURL: () => screenshot }),
      toDataURL: () => screenshot,
    };
  }

  const ctx = canvas.getContext("2d");
  ctx.drawImage(bitmap, 0, 0);

  // Check Hybrid A11y Fast-Path eligibility
  const useFastPath = a11yStats?.fastPathEligible === true && !forceVision;
  let ocr = { dets: [], lines: [], lineCount: 0, ms: 0 };
  let faces = { dets: [], ms: 0, available: false };
  let vit = { dets: [], backend: "a11y_fastpath", ms: 0, loadMs: null, labels: [], available: true, gpu: { available: false } };

  if (useFastPath) {
    // HYBRID A11Y FASTPATH: skip OCR / face / ViT inference on structured DOM.
    // The wall-clock saving is simply the vision-stage time that did NOT run;
    // the Activity panel shows it directly (fast-path steps have a much lower
    // `totalMs`). No fabricated constant — if the caller has measured the
    // vision stage on this device it passes `visionStageBaselineMs` through.
    timings.ocrMs = 0;
    timings.faceMs = 0;
    timings.vitMs = 0;
    timings.a11yBypassed = true;
    timings.visionStageSkipped = true;
    if (typeof visionStageBaselineMs === "number") {
      timings.visionStageBaselineMs = Math.round(visionStageBaselineMs);
    }
  } else {
    // Face detection + the YOLOS ViT only ever find things in RASTER imagery
    // (a person / face in a photo, avatar or screenshot). On a page the DOM
    // reports as having no <canvas> and no large image, they cost ~1.5s to
    // return nothing. Run them only when there is raster content to inspect;
    // OCR (the primary PII channel) always runs. `forceVision` and a missing
    // a11yStats both fall back to running everything.
    const wantRaster = forceVision || !a11yStats || a11yStats.hasLargeRaster === true || a11yStats.hasCanvas === true;
    const [ocrRes, facesRes, vitRes] = await Promise.all([
      runOCR(bitmap, dpr).catch((e) => ({ dets: [], lines: [], lineCount: 0, ms: 0, error: e.message })),
      wantRaster
        ? runFaces(bitmap).catch((e) => ({ dets: [], ms: 0, available: false, error: e.message }))
        : Promise.resolve({ dets: [], ms: 0, available: false, skipped: true }),
      wantRaster
        ? detectObjects(getRuntimeUrl, canvas).catch((e) => ({
            dets: [], backend: null, ms: 0, loadMs: null, labels: [],
            available: false, error: e.message, gpu: { available: false },
          }))
        : Promise.resolve({ dets: [], backend: "skipped:no-raster", ms: 0, loadMs: null, labels: [], available: false, skipped: true, gpu: { available: false } }),
    ]);
    ocr = ocrRes;
    faces = facesRes;
    vit = vitRes;
    timings.ocrMs = Math.round(ocr.ms);
    timings.faceMs = Math.round(faces.ms);
    timings.vitMs = Math.round(vit.ms);
    timings.rasterInspected = wantRaster;
    if (vit.loadMs != null) timings.vitLoadMs = vit.loadMs;
    timings.a11yBypassed = false;
  }

  // vision-derived field classifications for fields the DOM couldn't name
  const labelDets = fields.length ? associateLabels(ocr.lines || [], fields, dpr) : [];

  // DOM boxes: css px -> screenshot (device) px
  const domScaled = domPiiBoxes.map((d) => ({
    category: d.category,
    confidence: d.confidence,
    fieldId: d.fieldId,
    bbox: { x: d.bbox.x * dpr, y: d.bbox.y * dpr, w: d.bbox.w * dpr, h: d.bbox.h * dpr },
  }));

  // Only the ViT's privacy-relevant classes (person) join the redaction merge
  const vitPrivacyDets = (vit.dets || []).filter((d) => d.privacy);
  const visionDets = [...ocr.dets, ...faces.dets, ...labelDets, ...vitPrivacyDets];
  // fieldId -> category, for the service worker to enrich the skeleton
  const fieldCategories = {};
  for (const d of labelDets) fieldCategories[d.fieldId] = d.category;

  const merged = mergeDetections(domScaled, visionDets, 0.35, {
    redactThreshold: 0.5,
    domFieldCategories: fieldCategories,
  });

  // redact: every merged detection whose documented privacy-risk decision says so
  const regions = merged
    .filter((m) => m.redact)
    .map((m) => ({ ...m.bbox, category: m.category }));
  const tRedact = performance.now();
  const applied = redactCanvas(canvas, regions, { mode });
  timings.redactMs = Math.round(performance.now() - tRedact);

  // ── REDACTION VERIFICATION GATE (S4/11) ─────────────────────────────────
  // Re-OCR the masked canvas and re-scan. Residual PII/secrets -> grow boxes
  // and mask once more; still leaking -> REDACTION_FAILED and the caller must
  // NOT send the image. Skipped only when nothing was masked on a fast-path
  // step (a11y tree already asserted no unlabelled content) or OCR is absent.
  let verify = { verified: true, status: "SKIPPED", passes: 0, residual: [], residualCategories: [], addedRegions: [], ocrLines: 0, ms: 0 };
  const doVerify = !skipVerify && (regions.length > 0 || !useFastPath);
  if (doVerify) {
    try {
      verify = await verifyRedaction(canvas, applied.regions, {
        ocr: (c) => ocrLinesScaled(c, dpr, canvas.width, canvas.height),
      });
    } catch (e) {
      // a verification error is a fail-closed condition — we could not confirm
      // the image is clean, so treat it as unverified.
      verify = { verified: false, status: "REDACTION_FAILED", passes: 0, residual: [], residualCategories: ["verify-error"], addedRegions: [], ocrLines: 0, ms: 0, error: e.message };
    }
  }
  timings.verifyMs = verify.ms;

  let redactedDataURL;
  if (typeof canvas.convertToBlob === "function") {
    const blob = await canvas.convertToBlob({ type: "image/jpeg", quality: 0.82 });
    redactedDataURL = await new Promise((res) => {
      const fr = new FileReader();
      fr.onload = () => res(fr.result);
      fr.readAsDataURL(blob);
    });
  } else if (typeof canvas.toDataURL === "function") {
    redactedDataURL = canvas.toDataURL("image/jpeg", 0.82);
  }

  timings.totalMs = Math.round(performance.now() - tAll);

  return {
    redactedDataURL,
    redactionVerified: verify.verified,
    redactionStatus: verify.status,
    // metadata only — category / masked evidence, never a raw value
    redactionResidual: verify.residual,
    detections: merged.map((m) => ({
      category: m.category,
      confidence: Number(m.confidence.toFixed(2)),
      sources: m.sources,
      privacyRisk: m.privacyRisk,
      redact: m.redact,
      reason: m.reason,
      bbox: roundBox(m.bbox),
      fieldId: m.fieldId,
    })),
    fieldCategories,
    redactedRegions: [
      ...applied.regions.map((r) => ({ ...roundBox(r), mode: r.mode, category: r.category })),
      ...verify.addedRegions.map((r) => ({ ...roundBox(r), mode: "blackout", category: r.category || "verify_residual" })),
    ],
    stats: {
      ...redundancyStats(merged),
      ocrLines: ocr.lineCount,
      visionLabelledFields: labelDets.length,
      faceDetectorAvailable: faces.available,
      ocrError: ocr.error || null,
      faceError: faces.error || null,
      redaction: {
        verified: verify.verified,
        status: verify.status,
        repasses: verify.passes,
        addedRegions: verify.addedRegions.length,
        residualCategories: verify.residualCategories,
      },
      vit: {
        ...visionModelInfo(),
        available: vit.available,
        backend: vit.backend,
        gpu: vit.gpu,
        objects: (vit.dets || []).length,
        privacyObjects: vitPrivacyDets.length,
        labels: vit.labels || [],
        error: vit.error || null,
      },
    },
    timings,
  };
}

const roundBox = (b) => ({ x: Math.round(b.x), y: Math.round(b.y), w: Math.round(b.w), h: Math.round(b.h) });
