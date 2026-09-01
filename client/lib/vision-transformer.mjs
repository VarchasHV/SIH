// Client-side Vision Transformer.
//
// Runs YOLOS-tiny (a ViT / DETR-family object detector, int8-quantised ~9.4 MB)
// on the captured screenshot, entirely on device, via Transformers.js +
// ONNX Runtime Web. Tries the **WebGPU** execution provider first and falls back
// to **WASM (SIMD)**; the backend that actually ran is reported so the popup and
// the eval harness can show it.
//
// Everything (library, ORT binary, model weights) is vendored in the extension —
// no network fetch at inference time, which MV3 requires and which keeps the
// demo reproducible offline.
//
// Its detections are a third perception channel alongside the DOM classifier and
// Tesseract OCR: `person` boxes feed the redaction pipeline (a face detector
// misses a body/torso; the ViT does not), and the full label set is a genuine
// "what is on this screen" signal.

const MODEL_ID = "Xenova/yolos-tiny";

// COCO labels that are privacy-relevant on a screen capture. Everything the
// model finds is reported for visual context; only these are redacted.
export const PRIVACY_LABELS = new Set(["person"]);

let _pipe = null;          // cached pipeline
let _backend = null;       // "webgpu" | "wasm" | null
let _loadMs = null;        // one-time model load cost
let _failed = false;
let _lastError = null;

/** Probe WebGPU without throwing on browsers that lack it. */
export async function probeWebGPU() {
  try {
    if (typeof navigator === "undefined" || !navigator.gpu) return { available: false, reason: "navigator.gpu missing" };
    const adapter = await navigator.gpu.requestAdapter();
    if (!adapter) return { available: false, reason: "no adapter" };
    const info = (typeof adapter.requestAdapterInfo === "function" ? await adapter.requestAdapterInfo() : adapter.info) || {};
    return {
      available: true,
      vendor: info.vendor || null,
      architecture: info.architecture || null,
      device: info.device || null,
      description: info.description || null,
      maxBufferSize: adapter.limits?.maxBufferSize ?? null,
    };
  } catch (e) {
    return { available: false, reason: e.message };
  }
}

async function loadPipeline(runtimeUrl) {
  const getUrl = typeof runtimeUrl === "function"
    ? runtimeUrl
    : (p) => (typeof chrome !== "undefined" && chrome.runtime?.getURL ? chrome.runtime.getURL(p) : `./${p}`);

  const { pipeline, env } = await import(getUrl("vendor/transformers.min.js"));

  // Fully local: never touch the Hugging Face CDN at inference time.
  env.allowRemoteModels = false;
  env.allowLocalModels = true;
  env.localModelPath = getUrl("vendor/models/");
  env.useBrowserCache = false;
  // One JSEP binary serves both the WebGPU and the WASM execution providers.
  // `backends.onnx.wasm` is created lazily by some builds — make it safely.
  env.backends = env.backends || {};
  env.backends.onnx = env.backends.onnx || {};
  env.backends.onnx.wasm = env.backends.onnx.wasm || {};
  env.backends.onnx.wasm.wasmPaths = getUrl("vendor/");
  env.backends.onnx.wasm.numThreads = 1; // no COOP/COEP in an extension page

  const gpu = await probeWebGPU();
  const order = gpu.available ? ["webgpu", "wasm"] : ["wasm"];
  let lastErr = null;

  for (const device of order) {
    const t0 = performance.now();
    try {
      const pipe = await pipeline("object-detection", MODEL_ID, {
        device,
        dtype: "q8",
        local_files_only: true,
      });
      _backend = device;
      _loadMs = Math.round(performance.now() - t0);
      return { pipe, gpu };
    } catch (e) {
      lastErr = e;
      console.warn(`[vit] ${device} backend unavailable: ${e.message}`);
    }
  }
  throw lastErr || new Error("no ONNX execution provider available");
}

/**
 * @param {(p:string)=>string} runtimeUrl  extension URL resolver (chrome.runtime.getURL)
 * @param {ImageBitmap|HTMLCanvasElement|OffscreenCanvas} image
 * @param {{threshold?:number}} opts
 * @returns {Promise<{dets:Array, backend:string|null, ms:number, loadMs:number|null,
 *                    labels:string[], available:boolean, error:string|null, gpu:object}>}
 */
export async function detectObjects(runtimeUrl, image, opts = {}) {
  const threshold = opts.threshold ?? 0.5;
  const t0 = performance.now();

  if (_failed) {
    return { dets: [], backend: null, ms: 0, loadMs: null, labels: [], available: false, error: _lastError, gpu: { available: false } };
  }

  let gpu = { available: false };
  try {
    if (!_pipe) {
      const loaded = await loadPipeline(runtimeUrl);
      _pipe = loaded.pipe;
      gpu = loaded.gpu;
    } else {
      gpu = await probeWebGPU();
    }
  } catch (e) {
    _failed = true;
    _lastError = e.message;
    console.warn("[vit] disabled:", e.message);
    return { dets: [], backend: null, ms: Math.round(performance.now() - t0), loadMs: null, labels: [], available: false, error: e.message, gpu };
  }

  try {
    // Transformers.js accepts a RawImage; an ImageBitmap/canvas is converted by
    // the processor. Pass through a canvas so OffscreenCanvas works everywhere.
    const out = await _pipe(image, { threshold, percentage: false });
    const dets = (out || []).map((d) => ({
      category: PRIVACY_LABELS.has(d.label) ? "person" : `object:${d.label}`,
      label: d.label,
      confidence: Number((d.score ?? 0).toFixed(3)),
      source: "vit",
      privacy: PRIVACY_LABELS.has(d.label),
      bbox: {
        x: Math.max(0, d.box.xmin),
        y: Math.max(0, d.box.ymin),
        w: Math.max(1, d.box.xmax - d.box.xmin),
        h: Math.max(1, d.box.ymax - d.box.ymin),
      },
    }));
    return {
      dets,
      backend: _backend,
      ms: Math.round(performance.now() - t0),
      loadMs: _loadMs,
      labels: [...new Set(dets.map((d) => d.label))],
      available: true,
      error: null,
      gpu,
    };
  } catch (e) {
    console.warn("[vit] inference failed:", e.message);
    return { dets: [], backend: _backend, ms: Math.round(performance.now() - t0), loadMs: _loadMs, labels: [], available: false, error: e.message, gpu };
  }
}

export function visionModelInfo() {
  return { modelId: MODEL_ID, backend: _backend, loadMs: _loadMs, failed: _failed, error: _lastError };
}
