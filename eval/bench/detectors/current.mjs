// Detector under test: the extension's regex + checksum detector.
import { detectPII } from "../../../client/lib/pii-rules.mjs";

export const meta = {
  name: "current (regex+checksum)",
  kind: "on-device / rules",
  notes: "client/lib/pii-rules.mjs — unicode normalization + digit-run classification (Aadhaar/card/phone by length+checksum+IIN) + context-gated regex for shape-only IDs.",
};

export async function detect(text) {
  return detectPII(text).map((h) => ({
    category: h.category,
    value: h.value,
    start: h.start,
    end: h.end,
  }));
}
