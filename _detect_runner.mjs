import { detectPII } from "./client/lib/pii-rules.mjs";
const chunks = [];
process.stdin.on("data", d => chunks.push(d));
process.stdin.on("end", () => {
  const samples = JSON.parse(Buffer.concat(chunks).toString());
  const out = samples.map(s => {
    const t0 = performance.now();
    const hits = detectPII(s.text);
    const t1 = performance.now();
    return { cats: hits.map(h => h.category), latency_us: Math.round((t1-t0)*1000) };
  });
  process.stdout.write(JSON.stringify(out));
});
