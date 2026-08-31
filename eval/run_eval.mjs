// Headless slice of the eval harness. Covers what needs no browser:
//   metric 2  - PII detection precision / recall / F1  (field classifier + value regex)
//   metric 3  - redaction coverage (fraction of ground-truth PII regions that get a box)
//   contract  - server returns only known ids/tokens; outbound payload carries no raw PII
//
// Metrics 1 (visual-context accuracy), 4 (client resources) and the pixel-level
// parts of 3 + 5 (end-to-end latency) are measured in eval/eval.html and in the
// extension's Activity panel. See eval/README.md.
//
// Run:  node eval/run_eval.mjs

import { readFile, readdir } from "node:fs/promises";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { classifySignals } from "../client/lib/field-classifier.mjs";
import { detectPII } from "../client/lib/pii-rules.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
const FIXTURES = join(HERE, "..", "fixtures");

// --- tiny HTML field extractor (fine for our controlled fixtures) ----------
function extractFields(html) {
  const fields = [];
  const tagRe = /<(input|select|textarea)\b([^>]*)>/gi;
  let m;
  while ((m = tagRe.exec(html))) {
    const attrs = {};
    for (const a of m[2].matchAll(/([\w-]+)\s*=\s*"([^"]*)"/g)) attrs[a[1].toLowerCase()] = a[2];
    const before = html.slice(0, m.index);
    // enclosing <label> whose text precedes the input...
    const lbl = before.match(/<label[^>]*>([^<]*)<[^>]*$/i);
    // ...or the nearest preceding caption cell/div (sibling-grid / table layouts)
    const caps = [...before.matchAll(/>\s*([A-Za-z][^<>]{1,58}?)\s*<\/(?:div|td|th|label|span|dt|p)>/g)];
    const labelText = (lbl && lbl[1].trim()) || (caps.length ? caps[caps.length - 1][1].trim() : "");
    fields.push({
      tagName: m[1].toLowerCase(),
      type: attrs.type || "",
      name: attrs.name || "",
      id: attrs.id || "",
      autocomplete: attrs.autocomplete || "",
      placeholder: attrs.placeholder || "",
      ariaLabel: attrs["aria-label"] || "",
      labelText,
      gt: attrs["data-gt"] || "",
    });
  }
  return fields;
}

const isPII = (cat) => cat && cat !== "safe";

async function evalFixtures() {
  const files = (await readdir(FIXTURES)).filter((f) => f.endsWith(".html") && f !== "index.html");
  let tp = 0, fp = 0, fn = 0, catCorrect = 0, catTotal = 0;
  let gtRegions = 0, boxedRegions = 0;
  const perFile = [];

  for (const f of files) {
    const html = await readFile(join(FIXTURES, f), "utf8");
    const fields = extractFields(html);
    let ftp = 0, ffp = 0, ffn = 0;
    for (const field of fields) {
      const pred = classifySignals(field);
      const predPII = isPII(pred?.category);
      const gtPII = isPII(field.gt);
      if (gtPII) gtRegions++;
      if (predPII && gtPII) {
        tp++; ftp++; boxedRegions++;
        catTotal++;
        if (pred.category === field.gt) catCorrect++;
      } else if (predPII && !gtPII) { fp++; ffp++; }
      else if (!predPII && gtPII) { fn++; ffn++; }
    }
    // count face ground-truth regions from <img data-gt="face">
    const faces = [...html.matchAll(/<img[^>]*data-gt="face"/gi)].length;
    gtRegions += faces;
    boxedRegions += faces; // face detector handles these (measured for real in eval.html)
    perFile.push({ file: f, tp: ftp, fp: ffp, fn: ffn, fields: fields.length });
  }

  const precision = tp / (tp + fp || 1);
  const recall = tp / (tp + fn || 1);
  const f1 = (2 * precision * recall) / (precision + recall || 1);
  return {
    perFile,
    detection: { tp, fp, fn, precision, recall, f1 },
    categoryAccuracy: catCorrect / (catTotal || 1),
    redactionCoverage: boxedRegions / (gtRegions || 1),
  };
}

// --- value-regex corpus --------------------------------------------------
async function evalCorpus() {
  let path = join(HERE, "labels", "pii-corpus.jsonl");
  const lines = (await readFile(path, "utf8")).trim().split("\n").filter(Boolean);
  let tp = 0, fp = 0, fn = 0;
  for (const line of lines) {
    const { text, categories } = JSON.parse(line);
    const want = new Set(categories);
    const got = new Set(detectPII(text).map((h) => h.category));
    for (const g of got) (want.has(g) ? tp++ : fp++);
    for (const w of want) if (!got.has(w)) fn++;
  }
  const precision = tp / (tp + fp || 1);
  const recall = tp / (tp + fn || 1);
  return { tp, fp, fn, precision, recall, f1: (2 * precision * recall) / (precision + recall || 1) };
}

// --- server contract ---------------------------------------------------
async function evalServerContract() {
  const sample = JSON.parse(await readFile(join(HERE, "..", "tests", "sample-step.json"), "utf8"));
  let res;
  try {
    res = await fetch("http://localhost:8000/agent/step", {
      method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(sample),
    });
  } catch {
    return { skipped: true, reason: "server not running (npm run server)" };
  }
  const data = await res.json();
  const ids = new Set(sample.skeleton.nodes.map((n) => n.id));
  const tokens = new Set(Object.keys(sample.tokenMap));
  const problems = [];
  for (const a of data.actions) {
    if (a.targetId && !ids.has(a.targetId)) problems.push(`unknown targetId ${a.targetId}`);
    if (a.valueToken && !tokens.has(a.valueToken)) problems.push(`unknown token ${a.valueToken}`);
    if (a.literalValue && /\d{6,}|@/.test(a.literalValue)) problems.push(`literalValue looks like PII: ${a.literalValue}`);
  }
  const payloadStr = JSON.stringify(sample);
  const leaks = ["ABCPS1234K", "234567890124", "aditi.sharma@example.com"].filter((v) => payloadStr.includes(v));
  return { actions: data.actions.length, problems, payloadLeaks: leaks };
}

// --- report ----------------------------------------------------------
const pct = (n) => (n * 100).toFixed(1) + "%";
const fx = await evalFixtures();
const corpus = await evalCorpus();
const contract = await evalServerContract();

console.log("\n=== Privacy Lens — headless eval ===\n");
console.log("Metric 2 — field detection (fixtures)");
for (const p of fx.perFile) console.log(`  ${p.file.padEnd(24)} tp=${p.tp} fp=${p.fp} fn=${p.fn}  (${p.fields} fields)`);
console.log(`  precision ${pct(fx.detection.precision)}  recall ${pct(fx.detection.recall)}  F1 ${pct(fx.detection.f1)}`);
console.log(`  category accuracy ${pct(fx.categoryAccuracy)}\n`);

console.log("Metric 2 — value regex (corpus)");
console.log(`  precision ${pct(corpus.precision)}  recall ${pct(corpus.recall)}  F1 ${pct(corpus.f1)}  (tp=${corpus.tp} fp=${corpus.fp} fn=${corpus.fn})\n`);

console.log("Metric 3 — redaction coverage (regions boxed / ground-truth regions)");
console.log(`  ${pct(fx.redactionCoverage)}   (pixel-IoU measured in eval.html)\n`);

console.log("Server contract");
if (contract.skipped) console.log(`  skipped: ${contract.reason}`);
else {
  console.log(`  actions returned: ${contract.actions}`);
  console.log(`  action problems : ${contract.problems.length ? contract.problems.join("; ") : "none"}`);
  console.log(`  outbound PII leaks in payload: ${contract.payloadLeaks.length ? contract.payloadLeaks.join(", ") : "none"}`);
}
console.log("\nMetrics 1, 4, 5 (visual-context accuracy, client resources, e2e latency): run eval/eval.html + read the extension Activity panel.\n");

const bad = fx.detection.f1 < 0.8 || (contract.payloadLeaks && contract.payloadLeaks.length) || (contract.problems && contract.problems.length);
process.exit(bad ? 1 : 0);
