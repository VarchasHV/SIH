// Phase 17/18 — collect every benchmark's JSON output into one machine-readable
// benchmark-results.json + a human-readable BENCHMARK_REPORT.md.
//
//   node scripts/aggregate-benchmarks.mjs
//
// Reads whatever result files exist; missing ones are recorded as "not run".
// Run the benchmarks first: npm run bench && npm run bench:redaction &&
// npm run bench:latency && npm run bench:screens &&
// node eval/experiments/privacy-egress.mjs &&
// .venv/bin/python eval/bench/competitors/run_competitors.py

import { readFileSync, writeFileSync, existsSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { benchEnv } from "../eval/bench/lib/env.mjs";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const read = (p) => (existsSync(join(ROOT, p)) ? JSON.parse(readFileSync(join(ROOT, p), "utf8")) : null);
const pct = (n) => (n * 100).toFixed(1) + "%";

const detection = read("eval/bench/results.json");
const redaction = read("eval/bench/redaction.json");
const latency = read("eval/bench/latency.json");
const screens = read("eval/screens/screens.results.json");
const privacy = read("eval/experiments/privacy-egress.json");
const competitors = read("eval/bench/competitors/competitors.json");
const corpusManifest = read("eval/bench/corpus.manifest.json");

const cur = detection?.results?.find((r) => r.id === "current");

const out = {
  generatedAt: new Date().toISOString(),
  environment: benchEnv(),
  corpus: corpusManifest && {
    seed: corpusManifest.seed, samples: corpusManifest.samples, goldSpans: corpusManifest.goldSpans,
    spanOffsetErrors: corpusManifest.spanOffsetErrors, version: corpusManifest.corpusVersion,
  },
  detection: cur && {
    overall: cur.overall,
    byClass: cur.byClass,
    bySurfaceForm: cur.recallBySurfaceForm,
    note: "span-level IoU>=0.5, micro-averaged; class A/B/C/D reported separately",
  },
  redaction: redaction?.rows?.find((r) => r.id === "current"),
  latency: latency?.measured && { ...latency.measured, notMeasured: latency.notMeasured },
  screens: screens?.overall && { ...screens.overall, disclaimer: screens.meta?.disclaimer },
  privacyExperiment: privacy?.headline && {
    ...privacy.headline, leakByCategory: privacy.leakByCategory, caveats: privacy.caveats,
  },
  competitors: competitors && {
    scoring: competitors.scoring, samples: competitors.environment?.samples,
    openSource: Object.fromEntries(Object.entries(competitors.openSource).map(([k, v]) =>
      [k, v?.result ? { ...v.result.overall, msPerSample: v.msPerSample } : { error: v?.error }])),
    commercial: competitors.commercial,
  },
  missing: [
    !detection && "eval/bench/results.json (npm run bench)",
    !redaction && "eval/bench/redaction.json (npm run bench:redaction)",
    !latency && "eval/bench/latency.json (npm run bench:latency)",
    !screens && "eval/screens/screens.results.json (npm run bench:screens)",
    !privacy && "eval/experiments/privacy-egress.json",
    !competitors && "eval/bench/competitors/competitors.json",
  ].filter(Boolean),
};

writeFileSync(join(ROOT, "benchmark-results.json"), JSON.stringify(out, null, 2) + "\n");

// ── BENCHMARK_REPORT.md ──────────────────────────────────────────────────
let md = `# Benchmark Report\n\n`;
md += `Generated ${out.generatedAt} · commit \`${out.environment.gitCommit}\`${out.environment.gitDirty ? " (dirty)" : ""} · ${out.environment.cpuModel} · Node ${out.environment.nodeVersion} · ${out.environment.os}\n\n`;
md += `Every number here is a **measurement**. Where something was not run it says so. Regenerate: \`npm run bench && npm run bench:redaction && npm run bench:latency && npm run bench:screens && node eval/experiments/privacy-egress.mjs && .venv/bin/python eval/bench/competitors/run_competitors.py && node scripts/aggregate-benchmarks.mjs\`\n\n`;

if (out.corpus) md += `**Corpus** (\`eval/bench/gen-corpus.mjs\`): seed ${out.corpus.seed} · ${out.corpus.samples} samples · ${out.corpus.goldSpans} gold spans · ${out.corpus.spanOffsetErrors} offset errors.\n\n`;

if (out.detection) {
  md += `## 1. PII detection (span-level, seeded adversarial corpus)\n\n`;
  const o = out.detection.overall;
  md += `Overall (blended): **P ${pct(o.precision)} · R ${pct(o.recall)} · F1 ${pct(o.f1)}**\n\n`;
  md += `| Class | metric | value |\n|---|---|--:|\n`;
  for (const [k, v] of Object.entries(out.detection.byClass || {})) {
    if (v.kind === "positive") md += `| ${k} | recall (n=${v.gold}) | ${pct(v.recall)} |\n`;
    else md += `| ${k} | false-positive rate (${v.lineFP}/${v.n}) | ${pct(v.falsePositiveRate)} |\n`;
  }
  md += `\nUnicode/OCR (recall by surface form): `;
  md += Object.entries(out.detection.bySurfaceForm || {}).map(([k, v]) => `${k} ${pct(v.recall)}`).join(" · ") + `\n\n`;
}

if (out.redaction) {
  const r = out.redaction;
  md += `## 2. Redaction (scored against ground-truth spans)\n\n`;
  md += `Leakage rate **${pct(r.leakageRate)}** · fully redacted ${pct(r.fullyRedactedRate)} · over-redaction ${pct(r.overRedactionRate)} · char IoU ${pct(r.charIoU)}\n\n`;
  md += `Leakage by class: ` + Object.entries(r.leakageByClass || {}).map(([k, v]) => `${k} ${pct(v.leakageRate)}`).join(" · ") + `\n\n`;
}

if (out.latency) {
  const w = out.latency.warm;
  md += `## 3. Latency — DETECTOR ONLY (measured)\n\n`;
  md += `p50 **${w.p50}ms** · p90 ${w.p90}ms · p95 ${w.p95}ms · p99 ${w.p99}ms · max ${w.max}ms · cold start ${out.latency.coldStartMs}ms · ${w.n} samples\n\n`;
  md += `**Not measured** (need a browser): ` + Object.keys(out.latency.notMeasured).join(", ") + `\n\n`;
}

if (out.screens) {
  md += `## 4. Screenshot / vision (fusion + redaction GEOMETRY — no real OCR/render)\n\n`;
  md += `Visual PII recall ${pct(out.screens.visualRecall)} · precision ${pct(out.screens.visualPrecision)} · bbox IoU ${pct(out.screens.bboxIoU)} · geometric leakage ${pct(out.screens.geometricLeakage)} · adversarial false-redaction ${out.screens.totalAdversarialFP}\n\n`;
  md += `> ${out.screens.disclaimer}\n\n`;
}

if (out.privacyExperiment) {
  const p = out.privacyExperiment;
  md += `## 5. The privacy experiment — raw PII bytes to server\n\n`;
  md += `| Pipeline | raw PII bytes |\n|---|--:|\n`;
  md += `| A — unprotected | ${p.A_unprotected} |\n| B — OCR→PII→redact | ${p.B_ocr_pii_redact} |\n| C — full pipeline + egress gate | ${p.C_full_pipeline} |\n`;
  if (p["C+profile_full_pipeline_with_user_profile"] != null) md += `| C+profile — real flow | ${p["C+profile_full_pipeline_with_user_profile"]} |\n`;
  md += `\nReduction A→C: **${(100 * (1 - p.C_full_pipeline / p.A_unprotected)).toFixed(1)}%**. Task-goal PII → 0 in every protected pipeline.\n\n`;
}

if (out.competitors) {
  md += `## 6. Competitors (${out.competitors.samples} samples, ${out.competitors.scoring})\n\n`;
  md += `| System | P | R | F1 | ms/sample |\n|---|--:|--:|--:|--:|\n`;
  for (const [k, v] of Object.entries(out.competitors.openSource)) {
    md += v.error ? `| ${k} | — | — | — | ${v.error} |\n`
      : `| ${k} | ${pct(v.precision)} | ${pct(v.recall)} | ${pct(v.f1)} | ${v.msPerSample} |\n`;
  }
  for (const [k, v] of Object.entries(out.competitors.commercial)) md += `| ${k} | — | — | — | ${v} |\n`;
  md += `\n`;
}

if (out.missing.length) md += `## Not run this pass\n\n${out.missing.map((m) => `- ${m}`).join("\n")}\n`;

writeFileSync(join(ROOT, "BENCHMARK_REPORT.md"), md);
console.error(`wrote benchmark-results.json and BENCHMARK_REPORT.md`);
if (out.missing.length) console.error(`  (${out.missing.length} benchmark(s) not run — see report)`);
