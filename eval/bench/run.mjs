// Runs each detector over eval/bench/corpus.jsonl and scores it.
//
// Scoring:
//  - SPAN level (the number that matters for redaction): a prediction is a TP if
//    its category matches a gold span's category AND character IoU >= 0.5.
//    Greedy 1:1 matching per sample. Unmatched preds = FP, unmatched gold = FN.
//    Reported per-category and micro-averaged overall.
//  - LINE level (redaction usefulness): on a positive sample, did the detector
//    flag >=1 PII span? on a negative sample, did it stay silent? -> a simple
//    "would we have redacted correctly" precision/recall.
//  - LATENCY: wall-clock ms per sample.
//
// Usage:
//   node eval/bench/run.mjs                 # all detectors that load
//   node eval/bench/run.mjs current naive   # subset by name prefix
//   LIMIT=150 node eval/bench/run.mjs       # first N samples (for the slow LLM)

import { readFileSync, writeFileSync, readdirSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const HERE = dirname(fileURLToPath(import.meta.url));
const CORPUS = join(HERE, "corpus.jsonl");
const DET_DIR = join(HERE, "detectors");

// category aliases so external models can report their own label strings
const ALIAS = {
  "aadhaar number": "aadhaar", "aadhaar": "aadhaar", "aadhar": "aadhaar", "uidai number": "aadhaar",
  "pan": "pan", "pan card number": "pan", "pan number": "pan", "permanent account number": "pan",
  "gst number": "gstin", "gstin": "gstin", "gst identification number": "gstin",
  "ifsc": "ifsc", "ifsc code": "ifsc",
  "upi id": "upi-vpa", "upi-vpa": "upi-vpa", "vpa": "upi-vpa", "upi": "upi-vpa",
  "voter id": "voter-id", "voter-id": "voter-id", "epic number": "voter-id", "voter id number": "voter-id",
  "vehicle registration number": "vehicle-reg", "vehicle-reg": "vehicle-reg", "license plate": "vehicle-reg", "vehicle number": "vehicle-reg", "number plate": "vehicle-reg",
  "passport number": "passport-in", "passport-in": "passport-in", "passport": "passport-in",
  "credit card number": "credit-card", "credit-card": "credit-card", "card number": "credit-card", "debit card number": "credit-card", "credit card": "credit-card", "payment card number": "credit-card",
  "phone number": "phone-in", "phone-in": "phone-in", "mobile number": "phone-in", "telephone number": "phone-in", "phone": "phone-in", "mobile": "phone-in",
  "social security number": "ssn", "ssn": "ssn",
  "ip address": "ipv4", "ipv4": "ipv4", "ipv4 address": "ipv4", "ip": "ipv4",
  "date of birth": "dob", "dob": "dob", "birth date": "dob", "birthdate": "dob",
  "email address": "email", "email": "email", "e-mail": "email", "email id": "email",
};
const norm = (c) => ALIAS[String(c || "").trim().toLowerCase()] || String(c || "").trim().toLowerCase();

const CATS = ["aadhaar", "pan", "gstin", "ifsc", "upi-vpa", "voter-id", "vehicle-reg", "passport-in", "credit-card", "phone-in", "ssn", "ipv4", "dob", "email"];

function iou(a, b) {
  const lo = Math.max(a.start, b.start), hi = Math.min(a.end, b.end);
  const inter = Math.max(0, hi - lo);
  const uni = (a.end - a.start) + (b.end - b.start) - inter;
  return uni > 0 ? inter / uni : 0;
}

function scoreSample(gold, pred) {
  // greedy IoU matching, category must agree
  const G = gold.map((g) => ({ ...g, category: norm(g.category), used: false }));
  const Pr = pred.map((p) => ({ ...p, category: norm(p.category), used: false }));
  const pairs = [];
  for (let i = 0; i < G.length; i++)
    for (let j = 0; j < Pr.length; j++)
      if (G[i].category === Pr[j].category) {
        const s = iou(G[i], Pr[j]);
        if (s >= 0.5) pairs.push([s, i, j]);
      }
  pairs.sort((x, y) => y[0] - x[0]);
  const per = {};
  const bump = (cat, k) => { (per[cat] ??= { tp: 0, fp: 0, fn: 0 })[k]++; };
  for (const [, i, j] of pairs) {
    if (G[i].used || Pr[j].used) continue;
    G[i].used = Pr[j].used = true;
    bump(G[i].category, "tp");
  }
  for (const g of G) if (!g.used) bump(g.category, "fn");
  for (const p of Pr) if (!p.used) bump(p.category, "fp");
  return per;
}

const PRF = ({ tp, fp, fn }) => {
  const p = tp / (tp + fp || 1), r = tp / (tp + fn || 1);
  return { tp, fp, fn, precision: p, recall: r, f1: (2 * p * r) / (p + r || 1) };
};

async function loadDetectors(filter) {
  const files = readdirSync(DET_DIR).filter((f) => f.endsWith(".mjs"));
  const dets = [];
  for (const f of files) {
    try {
      const mod = await import(join(DET_DIR, f));
      if (!mod.detect) continue;
      const name = mod.meta?.name || f.replace(".mjs", "");
      if (filter.length && !filter.some((x) => f.startsWith(x) || name.toLowerCase().includes(x))) continue;
      // warmup (model load)
      await mod.detect("warmup 4111 1111 1111 1111");
      dets.push({ id: f.replace(".mjs", ""), name, meta: mod.meta || {}, detect: mod.detect });
      console.error(`  loaded: ${name}`);
    } catch (e) {
      console.error(`  SKIP ${f}: ${e.message.split("\n")[0]}`);
    }
  }
  return dets;
}

async function main() {
  const filter = process.argv.slice(2);
  const limit = Number(process.env.LIMIT || 0);
  let samples = readFileSync(CORPUS, "utf8").trim().split("\n").map((l) => JSON.parse(l));
  if (limit) samples = samples.slice(0, limit);

  console.error(`corpus: ${samples.length} samples, ${samples.reduce((n, s) => n + s.spans.length, 0)} gold spans`);
  console.error("loading detectors...");
  const dets = await loadDetectors(filter);

  const ctxTag = (kind) => {
    if (kind.includes("regression")) return "aadhaar-substring-regression";
    if (kind.includes("composite")) return "composite";
    if (kind.endsWith(":ocr")) return "ocr-garbled";
    if (kind.endsWith(":bare")) return "bare (no keyword)";
    if (kind.startsWith("pos:")) return "keyworded";
    return "negative";
  };

  const results = [];
  for (const d of dets) {
    const agg = {};
    const ctxRecall = {}; // tag -> {tp, fn}
    let lineTP = 0, lineFP = 0, lineFN = 0, lineTN = 0;
    const t0 = performance.now();
    for (const s of samples) {
      let preds = [];
      try { preds = (await d.detect(s.text)) || []; } catch { preds = []; }
      const per = scoreSample(s.spans, preds);
      const tag = ctxTag(s.kind);
      for (const [cat, v] of Object.entries(per)) {
        agg[cat] ??= { tp: 0, fp: 0, fn: 0 };
        agg[cat].tp += v.tp; agg[cat].fp += v.fp; agg[cat].fn += v.fn;
        if (s.spans.length) {
          ctxRecall[tag] ??= { tp: 0, fn: 0 };
          ctxRecall[tag].tp += v.tp; ctxRecall[tag].fn += v.fn;
        }
      }
      const goldHas = s.spans.length > 0;
      const predHas = preds.length > 0;
      if (goldHas && predHas) lineTP++;
      else if (goldHas && !predHas) lineFN++;
      else if (!goldHas && predHas) lineFP++;
      else lineTN++;
    }
    const ms = performance.now() - t0;
    const overall = PRF(Object.values(agg).reduce((a, v) => ({ tp: a.tp + v.tp, fp: a.fp + v.fp, fn: a.fn + v.fn }), { tp: 0, fp: 0, fn: 0 }));
    const linePRF = PRF({ tp: lineTP, fp: lineFP, fn: lineFN });
    results.push({
      id: d.id, name: d.name, meta: d.meta,
      perCategory: Object.fromEntries(CATS.map((c) => [c, agg[c] ? PRF(agg[c]) : null])),
      overall,
      recallByContext: Object.fromEntries(Object.entries(ctxRecall).map(([k, v]) => [k, { recall: v.tp / (v.tp + v.fn || 1), n: v.tp + v.fn }])),
      line: { ...linePRF, tn: lineTN, accuracy: (lineTP + lineTN) / samples.length },
      latency: { totalMs: Math.round(ms), msPerSample: +(ms / samples.length).toFixed(2) },
    });
    console.error(`  ${d.name}: F1 ${(overall.f1 * 100).toFixed(1)}%  (${Math.round(ms)}ms)`);
  }

  writeFileSync(join(HERE, "results.json"), JSON.stringify({ generatedAt: new Date().toISOString(), corpusSize: samples.length, results }, null, 2));
  writeFileSync(join(HERE, "results.md"), renderMarkdown(samples, results));
  console.error(`\nwrote eval/bench/results.json and results.md`);
}

function renderMarkdown(samples, results) {
  const pct = (n) => (n * 100).toFixed(1) + "%";
  const goldSpans = samples.reduce((n, s) => n + s.spans.length, 0);
  let md = `# PII Detection Benchmark\n\n`;
  md += `**Corpus**: ${samples.length} samples · ${goldSpans} gold spans · ${samples.filter((s) => s.spans.length).length} positive / ${samples.filter((s) => !s.spans.length).length} negative lines\n`;
  md += `**Generated**: ${new Date().toISOString().slice(0, 10)} · seeded, reproducible via \`node eval/bench/gen-corpus.mjs\`\n\n`;
  md += `Span match = same category + character IoU ≥ 0.5, greedy 1:1 per sample. Micro-averaged.\n\n`;

  md += `## Overall (span-level)\n\n`;
  md += `| Detector | Kind | Precision | Recall | F1 | Line acc. | ms/sample |\n|---|---|--:|--:|--:|--:|--:|\n`;
  for (const r of [...results].sort((a, b) => b.overall.f1 - a.overall.f1)) {
    md += `| ${r.name} | ${r.meta.kind || "—"} | ${pct(r.overall.precision)} | ${pct(r.overall.recall)} | **${pct(r.overall.f1)}** | ${pct(r.line.accuracy)} | ${r.latency.msPerSample} |\n`;
  }

  md += `\n## Per-category F1\n\n`;
  md += `| Category | ${results.map((r) => r.name).join(" | ")} |\n|---|${results.map(() => "--:").join("|")}|\n`;
  for (const c of CATS) {
    md += `| \`${c}\` | ` + results.map((r) => {
      const v = r.perCategory[c];
      return v ? pct(v.f1) : "—";
    }).join(" | ") + ` |\n`;
  }

  md += `\n## Per-category recall (did it catch the PII?)\n\n`;
  md += `| Category | ${results.map((r) => r.name).join(" | ")} |\n|---|${results.map(() => "--:").join("|")}|\n`;
  for (const c of CATS) {
    md += `| \`${c}\` | ` + results.map((r) => {
      const v = r.perCategory[c];
      return v ? pct(v.recall) : "—";
    }).join(" | ") + ` |\n`;
  }

  md += `\n## Per-category precision (of what it flagged, how much was right?)\n\n`;
  md += `| Category | ${results.map((r) => r.name).join(" | ")} |\n|---|${results.map(() => "--:").join("|")}|\n`;
  for (const c of CATS) {
    md += `| \`${c}\` | ` + results.map((r) => {
      const v = r.perCategory[c];
      return v ? pct(v.precision) : "—";
    }).join(" | ") + ` |\n`;
  }

  const CTX_ORDER = ["keyworded", "bare (no keyword)", "ocr-garbled", "composite", "aadhaar-substring-regression"];
  md += `\n## Recall by context (span-level)\n\n`;
  md += `Context-gated categories deliberately miss *bare* shape-only IDs (voter-id, passport, DOB, SSN with no keyword nearby) — that is the precision trade. "ocr-garbled" = a letter/digit was corrupted, breaking structural validation.\n\n`;
  md += `| Context | ${results.map((r) => r.name).join(" | ")} |\n|---|${results.map(() => "--:").join("|")}|\n`;
  for (const tag of CTX_ORDER) {
    const any = results.some((r) => r.recallByContext[tag]);
    if (!any) continue;
    md += `| ${tag} | ` + results.map((r) => {
      const v = r.recallByContext[tag];
      return v ? `${pct(v.recall)} (n=${v.n})` : "—";
    }).join(" | ") + ` |\n`;
  }

  md += `\n## Detectors\n\n`;
  for (const r of results) md += `- **${r.name}** — ${r.meta.notes || ""}\n`;
  md += `\n_See \`eval/bench/README.md\` for methodology and bias controls._\n`;
  return md;
}

main();
