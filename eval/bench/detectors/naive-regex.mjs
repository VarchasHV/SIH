// Floor baseline: "just regex", no checksums, no anchoring, no normalization.
// Shows what the engineering (Verhoeff/Luhn gates, digit boundaries) actually buys.

export const meta = {
  name: "naive regex (no checksum)",
  kind: "on-device / rules",
  notes: "Loose patterns, no Verhoeff/Luhn, no digit-boundary anchoring.",
};

const RULES = [
  ["email", /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g],
  ["aadhaar", /\b\d{4}[ .-]?\d{4}[ .-]?\d{4}\b/g],
  ["pan", /\b[A-Z]{5}\d{4}[A-Z]\b/g],
  ["gstin", /\b\d{2}[A-Z]{5}\d{4}[A-Z]\dZ[A-Z\d]\b/g],
  ["ifsc", /\b[A-Z]{4}0[A-Z0-9]{6}\b/g],
  ["upi-vpa", /\b[A-Za-z0-9._-]{2,}@[a-z]{3,}\b/g],
  ["credit-card", /\b\d{4}[ -]?\d{4}[ -]?\d{4}[ -]?\d{1,7}\b/g],
  ["credit-card", /\b\d{13,19}\b/g],
  ["phone-in", /\b\d{10}\b/g],
  ["ssn", /\b\d{3}-\d{2}-\d{4}\b/g],
  ["ipv4", /\b(?:\d{1,3}\.){3}\d{1,3}\b/g],
  ["dob", /\b\d{1,2}[/.-]\d{1,2}[/.-]\d{2,4}\b/g],
  ["voter-id", /\b[A-Z]{3}\d{7}\b/g],
  ["passport-in", /\b[A-Z]\d{7}\b/g],
];

export async function detect(text) {
  const out = [];
  for (const [category, re] of RULES) {
    re.lastIndex = 0;
    let m;
    while ((m = re.exec(text))) {
      out.push({ category, value: m[0], start: m.index, end: m.index + m[0].length });
      if (m.index === re.lastIndex) re.lastIndex++;
    }
  }
  return out;
}
