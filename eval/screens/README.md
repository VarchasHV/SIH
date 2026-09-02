# eval/screens — screenshot / vision benchmark (Phase 8)

## What this is

`screens.jsonl` — 11 synthetic **screen layout specs**: login, banking, checkout,
KYC (government form), invoice, profile (mobile), and a clean dashboard, across
light/dark themes and 1x–1.4x font scales. Each element has a declared bounding
box (px at the screen's viewport) and a ground-truth PII label. Deterministic
from `--seed` (default `20260902`); structured values (Aadhaar, card, PAN, SSN,
IFSC) come from `eval/bench/lib/independent-validators.mjs`.

## What this is NOT

**There is no real browser render and no real OCR in this environment** (no
headless Chromium / Playwright / node-canvas installed). `score.mjs`:

- treats each element's declared text as a **perfect OCR read** (the optimistic ceiling);
- treats `kind:"field"` elements as the **DOM channel** (field type = classifier output);
- runs the **real** `detectPII` + `mergeDetections` + risk-model redaction decision;
- scores the resulting redaction regions' **geometry** against the ground-truth boxes.

So it measures **fusion + redaction geometry** honestly. It does **not** measure
OCR recall, ViT/face-detector recall, rendering, or pixel contrast — those are
`NOT MEASURED`. For an end-to-end estimate, multiply the recall here by the OCR
recall from `eval/bench` (ASCII 91%, OCR-garbled 16%) and real ViT/face recall.

## Run

```bash
node eval/screens/gen-screens.mjs --seed 20260902   # -> screens.jsonl + manifest
node eval/screens/score.mjs                          # -> screens.results.{json,md}
# npm run bench:screens
```

## Metrics

| Metric | Meaning |
|---|---|
| visual PII recall | GT PII box ≥60% covered by a redaction region |
| visual PII precision | redaction regions landing on a GT PII box |
| bbox IoU | mean IoU of matched region↔GT pairs |
| geometric leakage | GT PII box **area** left uncovered / total GT PII area |
| adversarial false-redaction | order-id / SKU / IPv4 / build-number boxes redacted |

The consistent finding: PII **in form fields** is covered (DOM channel); PII in
**static display text without a nearby keyword** is missed — same trade as the
`B-unlabelled` class in `eval/bench`.
