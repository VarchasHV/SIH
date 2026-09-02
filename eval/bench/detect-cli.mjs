// Batch PII-detection bridge for non-JS callers (the Python benchmarks).
//
//   echo '["Aadhaar 2345 6789 0124","order #12345"]' \
//     | node eval/bench/detect-cli.mjs --detector current
//
// stdin  : a JSON array of strings.
// stdout : a JSON array, one object per input:
//            { categories: string[], spans: [{category,value,start,end}], ms }
//
// --detector <name>  loads eval/bench/detectors/<name>.mjs (default: current).
// This is the ONLY sanctioned way to benchmark "Privacy Lens" from Python —
// it runs the exact detector the browser ships (client/lib/pii-rules.mjs via
// the `current` detector wrapper), never a re-implementation.

import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const HERE = dirname(fileURLToPath(import.meta.url));

const argv = process.argv.slice(2);
const detName = (() => {
  const i = argv.indexOf("--detector");
  return i > -1 ? argv[i + 1] : "current";
})();

const mod = await import(join(HERE, "detectors", `${detName}.mjs`));
if (typeof mod.detect !== "function") {
  process.stderr.write(`detector "${detName}" has no detect()\n`);
  process.exit(2);
}

const chunks = [];
for await (const c of process.stdin) chunks.push(c);
let inputs;
try {
  inputs = JSON.parse(Buffer.concat(chunks).toString() || "[]");
} catch (e) {
  process.stderr.write(`stdin is not JSON: ${e.message}\n`);
  process.exit(2);
}
if (!Array.isArray(inputs)) {
  process.stderr.write("stdin must be a JSON array of strings\n");
  process.exit(2);
}

// warm up (model load, regex compile) so the first timed sample isn't an outlier
await mod.detect("warmup 4111 1111 1111 1111 aadhaar 2345 6789 0124");

const out = [];
for (const text of inputs) {
  const t0 = performance.now();
  let spans = [];
  try {
    spans = (await mod.detect(String(text ?? ""))) || [];
  } catch {
    spans = [];
  }
  const ms = performance.now() - t0;
  out.push({
    categories: [...new Set(spans.map((s) => s.category))],
    spans: spans.map((s) => ({ category: s.category, value: s.value, start: s.start, end: s.end })),
    ms,
  });
}

process.stdout.write(JSON.stringify(out));
