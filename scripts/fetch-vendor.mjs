// Fetches the ML libraries the extension needs into client/vendor/.
// MV3 forbids remote code, so these must be shipped inside the extension.
// Model *weights* are still fetched from the HF/MediaPipe CDN on first use
// (that is data, not code) and cached by the browser.
//
// Run: npm run fetch:vendor

import { mkdir, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const VENDOR = join(ROOT, "client", "vendor");

const FILES = [
  {
    // Transformers.js (ESM) - object detection + optional OCR/NER, WebGPU/WASM.
    url: "https://cdn.jsdelivr.net/npm/@huggingface/transformers@3.0.2/dist/transformers.min.js",
    out: "transformers.min.js",
  },
  {
    // Tesseract.js main thread API (UMD).
    url: "https://cdn.jsdelivr.net/npm/tesseract.js@5.1.1/dist/tesseract.min.js",
    out: "tesseract.min.js",
  },
  {
    // Tesseract.js worker script.
    url: "https://cdn.jsdelivr.net/npm/tesseract.js@5.1.1/dist/worker.min.js",
    out: "tesseract-worker.min.js",
  },
  {
    // Tesseract core (WASM glue, SIMD build).
    url: "https://cdn.jsdelivr.net/npm/tesseract.js-core@5.1.1/tesseract-core-simd.wasm.js",
    out: "tesseract-core-simd.wasm.js",
  },
  {
    url: "https://cdn.jsdelivr.net/npm/tesseract.js-core@5.1.1/tesseract-core-simd.wasm",
    out: "tesseract-core-simd.wasm",
  },
  {
    // English trained data (gzip). ~10 MB.
    url: "https://cdn.jsdelivr.net/npm/@tesseract.js-data/eng@1.0.0/4.0.0_best_int/eng.traineddata.gz",
    out: "eng.traineddata.gz",
  },
  {
    // MediaPipe tasks-vision (ESM) - face detection.
    url: "https://cdn.jsdelivr.net/npm/@mediapipe/tasks-vision@0.10.18/vision_bundle.mjs",
    out: "tasks-vision.mjs",
  },
  {
    url: "https://cdn.jsdelivr.net/npm/@mediapipe/tasks-vision@0.10.18/wasm/vision_wasm_internal.js",
    out: "mp-wasm/vision_wasm_internal.js",
  },
  {
    url: "https://cdn.jsdelivr.net/npm/@mediapipe/tasks-vision@0.10.18/wasm/vision_wasm_internal.wasm",
    out: "mp-wasm/vision_wasm_internal.wasm",
  },
  {
    url: "https://cdn.jsdelivr.net/npm/@mediapipe/tasks-vision@0.10.18/wasm/vision_wasm_nosimd_internal.js",
    out: "mp-wasm/vision_wasm_nosimd_internal.js",
  },
  {
    url: "https://cdn.jsdelivr.net/npm/@mediapipe/tasks-vision@0.10.18/wasm/vision_wasm_nosimd_internal.wasm",
    out: "mp-wasm/vision_wasm_nosimd_internal.wasm",
  },
  {
    // BlazeFace short-range face detector (~230 KB).
    url: "https://storage.googleapis.com/mediapipe-models/face_detector/blaze_face_short_range/float16/1/blaze_face_short_range.tflite",
    out: "blaze_face_short_range.tflite",
  },
];

async function fetchOne({ url, out }) {
  const dest = join(VENDOR, out);
  await mkdir(dirname(dest), { recursive: true });
  process.stdout.write(`  ${out} ... `);
  const res = await fetch(url);
  if (!res.ok) throw new Error(`${res.status} ${res.statusText} for ${url}`);
  const buf = Buffer.from(await res.arrayBuffer());
  await writeFile(dest, buf);
  console.log(`${(buf.length / 1024).toFixed(0)} KB`);
}

console.log("Fetching vendor libraries into client/vendor/ ...");
let failed = 0;
for (const f of FILES) {
  try {
    await fetchOne(f);
  } catch (err) {
    failed++;
    console.log(`FAILED (${err.message})`);
  }
}
console.log(failed ? `\nDone with ${failed} failure(s).` : "\nAll vendor files fetched.");
process.exit(failed ? 1 : 0);
