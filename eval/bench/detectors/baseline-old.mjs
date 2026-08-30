// FROZEN SNAPSHOT of client/lib/pii-rules.mjs as it was BEFORE the benchmark
// fixes (commit 7dafeaa). Kept here so every benchmark run shows the before/after
// side by side. Do not edit — this is the "before".

export const meta = {
  name: "baseline (pre-fix)",
  kind: "on-device / rules",
  notes: "pii-rules.mjs @ 7dafeaa — 14 flat regexes, Verhoeff+Luhn only, no normalization, no context gating.",
};

function verhoeffValid(digits) {
  const D = [[0,1,2,3,4,5,6,7,8,9],[1,2,3,4,0,6,7,8,9,5],[2,3,4,0,1,7,8,9,5,6],[3,4,0,1,2,8,9,5,6,7],[4,0,1,2,3,9,5,6,7,8],[5,9,8,7,6,0,4,3,2,1],[6,5,9,8,7,1,0,4,3,2],[7,6,5,9,8,2,1,0,4,3],[8,7,6,5,9,3,2,1,0,4],[9,8,7,6,5,4,3,2,1,0]];
  const P = [[0,1,2,3,4,5,6,7,8,9],[1,5,7,6,2,8,3,0,9,4],[5,8,0,3,7,9,6,1,4,2],[8,9,1,6,0,4,3,5,2,7],[9,4,5,3,1,2,6,8,7,0],[4,2,8,6,5,7,3,9,0,1],[2,7,9,3,8,0,6,4,1,5],[7,0,4,6,9,1,3,2,5,8]];
  const s = String(digits).replace(/\D/g, "");
  if (s.length !== 12) return false;
  let c = 0;
  const rev = s.split("").reverse();
  for (let i = 0; i < rev.length; i++) c = D[c][P[i % 8][Number(rev[i])]];
  return c === 0;
}
function luhnValid(digits) {
  const s = String(digits).replace(/\D/g, "");
  if (s.length < 12 || s.length > 19) return false;
  let sum = 0, dbl = false;
  for (let i = s.length - 1; i >= 0; i--) {
    let d = Number(s[i]); if (dbl) { d *= 2; if (d > 9) d -= 9; } sum += d; dbl = !dbl;
  }
  return sum % 10 === 0;
}

const RULES = [
  { category: "email", re: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g },
  { category: "aadhaar", re: /\b\d{4}\s?\d{4}\s?\d{4}\b/g, validate: (m) => verhoeffValid(m) },
  { category: "pan", re: /\b[A-Z]{5}[0-9]{4}[A-Z]\b/g },
  { category: "gstin", re: /\b\d{2}[A-Z]{5}\d{4}[A-Z][A-Z0-9]Z[A-Z0-9]\b/g },
  { category: "ifsc", re: /\b[A-Z]{4}0[A-Z0-9]{6}\b/g },
  { category: "upi-vpa", re: /\b[A-Za-z0-9.\-_]{2,}@(?:oksbi|okhdfcbank|okicici|okaxis|paytm|ybl|apl|ibl|axl|upi)\b/gi },
  { category: "voter-id", re: /\b[A-Z]{3}[0-9]{7}\b/g },
  { category: "vehicle-reg", re: /\b[A-Z]{2}[ -]?\d{1,2}[ -]?[A-Z]{1,3}[ -]?\d{4}\b/g },
  { category: "passport-in", re: /\b[A-PR-WY][1-9]\d\s?\d{4}[1-9]\b/g },
  { category: "credit-card", re: /\b(?:\d[ -]?){12,19}\b/g, validate: (m) => luhnValid(m) },
  { category: "phone-in", re: /(?:\+?91[ -]?)?[6-9]\d{9}\b/g },
  { category: "ssn", re: /\b\d{3}-\d{2}-\d{4}\b/g },
  { category: "ipv4", re: /\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b/g },
  { category: "dob", re: /\b(?:0?[1-9]|[12]\d|3[01])[/\-.](?:0?[1-9]|1[0-2])[/\-.](?:19|20)\d{2}\b/g },
];

export async function detect(text) {
  const hits = [];
  for (const rule of RULES) {
    rule.re.lastIndex = 0;
    let m;
    while ((m = rule.re.exec(text)) !== null) {
      const value = m[0];
      if (rule.validate && !rule.validate(value)) continue;
      hits.push({ category: rule.category, value, start: m.index, end: m.index + value.length });
      if (m.index === rule.re.lastIndex) rule.re.lastIndex++;
    }
  }
  hits.sort((a, b) => a.start - b.start || b.end - a.end);
  const kept = [];
  for (const h of hits) if (!kept.some((k) => h.start < k.end && k.start < h.end)) kept.push(h);
  return kept;
}
