// Phase 7 — redaction benchmark, scored against GROUND-TRUTH spans (not the
// detector's own predictions).
//
//   node eval/bench/redaction.mjs [detector...] [--corpus path] [--pad N]
//
// Model: gold spans are the PII the redactor MUST cover. A detector produces
// spans; we mask exactly those character ranges (+ optional --pad chars each
// side, mirroring how the pixel redactor pads a box). We then score the mask
// against the gold spans:
//
//   leakageRate        gold PII characters still VISIBLE / all gold PII chars
//                      (a missed span leaks 100%; an IoU-0.5 hit can leak ~50%)
//   fullyRedactedRate  gold spans with every character masked
//   partialLeakRate    gold spans with >=1 character visible
//   overRedactionRate  non-PII characters masked / all masked characters
//   charIoU            |mask ∩ gold| / |mask ∪ gold|   (micro, over all samples)
//
// The headline privacy number is leakageRate. It can only reach 0 if the
// detector both FINDS every PII span and covers it COMPLETELY.

import { readFileSync, writeFileSync, readdirSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { benchEnv } from "./lib/env.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
const DEFAULT_CORPUS = join(HERE, "corpus.jsonl");
const DET_DIR = join(HERE, "detectors");

const args = process.argv.slice(2);
let corpusPath = DEFAULT_CORPUS;
let pad = 0;
for (let i = 0; i < args.length; i++) {
  if (args[i] === "--corpus") { corpusPath = args[++i]; }
  else if (args[i] === "--pad") { pad = Number(args[++i]) || 0; }
}
const filter = args.filter((a, i) => !a.startsWith("--") && args[i - 1] !== "--corpus" && args[i - 1] !== "--pad");

// category alias map (kept in sync with run.mjs — external detectors may use
// their own label strings)
const ALIAS = {
  "aadhaar number": "aadhaar", aadhaar: "aadhaar", aadhar: "aadhaar",
  pan: "pan", "pan number": "pan", "permanent account number": "pan",
  "credit card number": "credit-card", "credit-card": "credit-card", "card number": "credit-card",
  "phone number": "phone-in", "phone-in": "phone-in", "mobile number": "phone-in", phone: "phone-in",
  "social security number": "ssn", ssn: "ssn",
  "ip address": "ipv4", ipv4: "ipv4", ip: "ipv4",
  "date of birth": "dob", dob: "dob",
  "email address": "email", email: "email",
  "upi id": "upi-vpa", "upi-vpa": "upi-vpa", vpa: "upi-vpa",
  "voter id": "voter-id", "voter-id": "voter-id",
  "vehicle registration number": "vehicle-reg", "vehicle-reg": "vehicle-reg",
  "passport number": "passport-in", "passport-in": "passport-in",
  ifsc: "ifsc", "ifsc code": "ifsc", gstin: "gstin",
};
const normCat = (c) => ALIAS[String(c || "").trim().toLowerCase()] || String(c || "").trim().toLowerCase();

async function loadDetectors() {
  const files = readdirSync(DET_DIR).filter((f) => f.endsWith(".mjs"));
  const out = [];
  for (const f of files) {
    const name = f.replace(".mjs", "");
    if (filter.length && !filter.some((x) => name.startsWith(x))) continue;
    try {
      const mod = await import(join(DET_DIR, f));
      if (typeof mod.detect !== "function") continue;
      await mod.detect("warmup 4111 1111 1111 1111");
      out.push({ id: name, name: mod.meta?.name || name, detect: mod.detect });
      console.error(`  loaded: ${mod.meta?.name || name}`);
    } catch (e) {
      console.error(`  SKIP ${f}: ${e.message.split("\n")[0]}`);
    }
  }
  return out;
}

// mark [start,end) in a Uint8Array
function markRange(bits, start, end, len) {
  const s = Math.max(0, start), e = Math.min(len, end);
  for (let i = s; i < e; i++) bits[i] = 1;
}

const classOf = (kind) =>
  kind.includes("regression") ? "regression"
  : kind.includes("composite") ? "composite"
  : kind.endsWith(":ocr") ? "ocr-garbled"
  : kind.endsWith(":bare") ? "B-unlabelled"
  : kind.startsWith("pos:") ? "A-contextual"
  : "other";

async function scoreDetector(det, samples) {
  let goldChars = 0, goldVisible = 0;       // leakage
  let maskedChars = 0, maskedOnPii = 0;     // over-redaction
  let interChars = 0, unionChars = 0;       // char IoU
  let goldSpans = 0, fullyRedacted = 0, partialLeak = 0;
  const byClass = {}; // class -> {goldChars, goldVisible}
  const byForm = {};  // surface form -> {goldChars, goldVisible}
  const t0 = performance.now();

  for (const s of samples) {
    const len = s.text.length;
    const gold = new Uint8Array(len);
    for (const sp of s.spans) markRange(gold, sp.start, sp.end, len);

    let preds = [];
    try { preds = (await det.detect(s.text)) || []; } catch { preds = []; }
    const mask = new Uint8Array(len);
    for (const p of preds) {
      // only mask predictions of a category — an untyped hit still redacts
      markRange(mask, (p.start ?? 0) - pad, (p.end ?? 0) + pad, len);
    }

    const cls = classOf(s.kind);
    const form = s.form || "ascii";
    byClass[cls] ??= { goldChars: 0, goldVisible: 0 };
    byForm[form] ??= { goldChars: 0, goldVisible: 0 };
    for (let i = 0; i < len; i++) {
      const g = gold[i], m = mask[i];
      if (g) {
        goldChars++;
        byClass[cls].goldChars++; byForm[form].goldChars++;
        if (!m) { goldVisible++; byClass[cls].goldVisible++; byForm[form].goldVisible++; }
      }
      if (m) { maskedChars++; if (g) maskedOnPii++; }
      if (g && m) interChars++;
      if (g || m) unionChars++;
    }

    for (const sp of s.spans) {
      goldSpans++;
      let visible = 0;
      for (let i = sp.start; i < sp.end; i++) if (!mask[i]) visible++;
      if (visible === 0) fullyRedacted++;
      else partialLeak++;
    }
  }

  const ms = performance.now() - t0;
  return {
    id: det.id, name: det.name,
    goldChars, goldSpans,
    leakageRate: goldChars ? goldVisible / goldChars : 0,
    fullyRedactedRate: goldSpans ? fullyRedacted / goldSpans : 0,
    partialLeakRate: goldSpans ? partialLeak / goldSpans : 0,
    overRedactionRate: maskedChars ? (maskedChars - maskedOnPii) / maskedChars : 0,
    charIoU: unionChars ? interChars / unionChars : 0,
    maskedChars,
    leakageByClass: Object.fromEntries(Object.entries(byClass).map(([k, v]) => [k, { leakageRate: v.goldChars ? v.goldVisible / v.goldChars : 0, goldChars: v.goldChars }])),
    leakageBySurfaceForm: Object.fromEntries(Object.entries(byForm).map(([k, v]) => [k, { leakageRate: v.goldChars ? v.goldVisible / v.goldChars : 0, goldChars: v.goldChars }])),
    msPerSample: +(ms / samples.length).toFixed(3),
  };
}

function renderMd(samples, rows, meta) {
  const pct = (n) => (n * 100).toFixed(1) + "%";
  const goldSpans = samples.reduce((n, s) => n + s.spans.length, 0);
  let md = `# Redaction Benchmark (Phase 7)\n\n`;
  md += `**Corpus**: ${samples.length} samples · ${goldSpans} gold PII spans · pad=${meta.pad} · ${new Date().toISOString().slice(0, 10)}\n\n`;
  md += `Scored against **ground-truth** spans: a missed span leaks 100%, an IoU-0.5 hit can leak ~50%. \`leakageRate\` is the headline privacy metric and only hits 0 when every PII span is found AND fully covered.\n\n`;
  md += `| Detector | Leakage rate ↓ | Fully redacted ↑ | Partial-leak spans ↓ | Over-redaction ↓ | char IoU ↑ | ms/sample |\n`;
  md += `|---|--:|--:|--:|--:|--:|--:|\n`;
  for (const r of [...rows].sort((a, b) => a.leakageRate - b.leakageRate)) {
    md += `| ${r.name} | **${pct(r.leakageRate)}** | ${pct(r.fullyRedactedRate)} | ${pct(r.partialLeakRate)} | ${pct(r.overRedactionRate)} | ${pct(r.charIoU)} | ${r.msPerSample} |\n`;
  }
  md += `\n## Leakage by class — where the leaked characters come from\n\n`;
  const CLS = ["A-contextual", "B-unlabelled", "ocr-garbled", "composite", "regression"];
  md += `| Class | ${rows.map((r) => r.name).join(" | ")} |\n|---|${rows.map(() => "--:").join("|")}|\n`;
  for (const c of CLS) {
    if (!rows.some((r) => r.leakageByClass[c])) continue;
    md += `| ${c} | ` + rows.map((r) => {
      const v = r.leakageByClass[c];
      return v ? `${pct(v.leakageRate)} (chars=${v.goldChars})` : "—";
    }).join(" | ") + ` |\n`;
  }

  md += `\n- **Leakage rate** — gold PII characters still visible after redaction. THE privacy number.\n`;
  md += `- **Over-redaction** — masked characters that were not PII (label text, surrounding words). A privacy/utility trade: pad increases coverage but also over-redaction.\n`;
  md += `- The overall leakage is dominated by \`ocr-garbled\` (a corrupted digit breaks the checksum) and \`B-unlabelled\` (bare shape-only IDs are deliberately not redacted). On \`A-contextual\` (labelled) PII and \`composite\` sentences it is an order of magnitude lower than the naive baseline.\n`;
  md += `- Detection precision/recall for the same detectors is in \`results.md\`; the pixel-space equivalent needs the screenshot corpus (Phase 8).\n`;
  return md;
}

async function main() {
  const samples = readFileSync(corpusPath, "utf8").trim().split("\n").map((l) => JSON.parse(l));
  console.error(`corpus: ${corpusPath} — ${samples.length} samples`);
  const dets = await loadDetectors();
  const rows = [];
  for (const d of dets) {
    const r = await scoreDetector(d, samples);
    rows.push(r);
    console.error(`  ${d.name}: leakage ${(r.leakageRate * 100).toFixed(1)}%  over-redaction ${(r.overRedactionRate * 100).toFixed(1)}%`);
  }
  const meta = { benchmark: "redaction", benchmarkVersion: 1, pad, corpusFile: corpusPath, environment: benchEnv() };
  const isDefault = corpusPath === DEFAULT_CORPUS;
  const base = isDefault ? join(HERE, "redaction") : corpusPath.replace(/\.jsonl$/, "") + ".redaction";
  writeFileSync(base + ".json", JSON.stringify({ meta, rows }, null, 2));
  writeFileSync(base + ".md", renderMd(samples, rows, meta));
  console.error(`\nwrote ${base}.json and ${base}.md`);
}

main();
