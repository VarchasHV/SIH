// Phase 12 — real latency measurement. Percentiles + a full environment block.
//
//   node eval/bench/latency.mjs [detector] [--corpus path] [--warmup 500] [--repeat 3]
//
// What IS measured here: per-sample PII DETECTION latency (client/lib/pii-rules.mjs
// via the `current` detector wrapper), cold vs warm, p50/p90/p95/p99/mean/max.
//
// What is NOT measured (needs a real browser — none in this environment; marked
// NOT_MEASURED in the output):
//   - OCR latency (Tesseract WASM)
//   - face-detection latency (MediaPipe)
//   - vision-transformer latency (YOLOS via ONNX Runtime, WebGPU/WASM)
//   - screenshot capture, canvas redaction, JPEG encode
//   - network round-trip, end-to-end
// Do NOT add those as constants. They must come from an in-browser measurement.

import { readFileSync, writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { benchEnv } from "./lib/env.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
const args = process.argv.slice(2);
const opt = (k, d) => { const i = args.indexOf(`--${k}`); return i > -1 ? args[i + 1] : d; };
const FLAG_ARGS = new Set(["--corpus", "--warmup", "--repeat"]);
const detName = args.find((a, i) => !a.startsWith("--") && !FLAG_ARGS.has(args[i - 1])) || "current";
const corpusPath = opt("corpus", join(HERE, "corpus.jsonl"));
const warmup = Number(opt("warmup", 500));
const repeat = Number(opt("repeat", 3));

const { detect } = await import(join(HERE, "detectors", `${detName}.mjs`));

const samples = readFileSync(corpusPath, "utf8").trim().split("\n").map((l) => JSON.parse(l).text);

function pctl(sorted, p) {
  if (!sorted.length) return 0;
  const idx = (p / 100) * (sorted.length - 1);
  const lo = Math.floor(idx), hi = Math.min(lo + 1, sorted.length - 1);
  return sorted[lo] + (sorted[hi] - sorted[lo]) * (idx - lo);
}
const summary = (arr) => {
  const s = [...arr].sort((a, b) => a - b);
  return {
    n: s.length,
    mean: +(s.reduce((a, b) => a + b, 0) / s.length).toFixed(4),
    p50: +pctl(s, 50).toFixed(4), p90: +pctl(s, 90).toFixed(4),
    p95: +pctl(s, 95).toFixed(4), p99: +pctl(s, 99).toFixed(4),
    max: +s[s.length - 1].toFixed(4),
    unit: "ms",
  };
};

// cold: first call after import, no warmup
const cold = [];
{
  const t0 = performance.now();
  await detect(samples[0]);
  cold.push(performance.now() - t0);
}

// warm
for (let i = 0; i < warmup; i++) await detect(samples[i % samples.length]);

const warm = [];
const memBefore = process.memoryUsage().heapUsed;
for (let r = 0; r < repeat; r++) {
  for (const text of samples) {
    const t0 = performance.now();
    await detect(text);
    warm.push(performance.now() - t0);
  }
}
const memAfter = process.memoryUsage().heapUsed;

const result = {
  benchmark: "pii-detection-latency",
  benchmarkVersion: 1,
  measured: {
    detector: detName,
    detectorSource: "client/lib/pii-rules.mjs",
    coldStartMs: +cold[0].toFixed(4),
    warm: summary(warm),
    samplesPerRun: samples.length,
    runs: repeat,
    heapDeltaBytes: memAfter - memBefore,
  },
  notMeasured: {
    ocrMs: "NOT_MEASURED — Tesseract WASM, needs a browser",
    faceDetectionMs: "NOT_MEASURED — MediaPipe, needs a browser",
    visionTransformerMs: "NOT_MEASURED — YOLOS/ONNX Runtime, needs a browser (WebGPU/WASM)",
    screenshotCaptureMs: "NOT_MEASURED",
    redactionMs: "NOT_MEASURED — canvas + JPEG encode, needs a browser",
    networkRoundTripMs: "NOT_MEASURED — depends on the VLM endpoint",
    endToEndMs: "NOT_MEASURED",
  },
  environment: benchEnv({ corpusFile: corpusPath, warmupIterations: warmup }),
};

const isDefault = corpusPath === join(HERE, "corpus.jsonl");
const out = isDefault ? join(HERE, "latency.json") : corpusPath.replace(/\.jsonl$/, "") + ".latency.json";
writeFileSync(out, JSON.stringify(result, null, 2) + "\n");

const w = result.measured.warm;
console.error(`[${detName}] detector-only latency (warm): p50 ${w.p50}ms · p95 ${w.p95}ms · p99 ${w.p99}ms · max ${w.max}ms · cold ${result.measured.coldStartMs}ms`);
console.error(`OCR / ViT / face / network / end-to-end: NOT MEASURED (need a browser)`);
console.error(`wrote ${out}`);
