# eval/

Two harnesses, split by what needs a browser.

## `run_eval.mjs` — headless (`npm run eval`)

- **Metric 2** — PII detection precision / recall / F1:
  - field classifier (`field-classifier.mjs`) over the 3 fixtures, scored against
    each field's `data-gt` attribute;
  - value regex (`pii-rules.mjs`) over `labels/pii-corpus.jsonl` (includes
    negatives + a checksum-failing "not an Aadhaar" line).
- **Metric 3** — redaction *coverage*: ground-truth PII regions that receive a box.
- **Server contract** (if `npm run server` is up): every returned action references
  a known `targetId` + token; no `literalValue` looks like PII; the outbound
  payload contains no profile value.

Exits non-zero if F1 < 0.8, an action is malformed, or a PII leak is detected.

## `eval.html` — in-browser

Serve the repo root and open it:

```bash
node scripts/serve.mjs . 4173
# http://localhost:4173/eval/eval.html  → "Run eval"
```

- **Metric 2** with a real DOM (labels via associated `<label>`, computed
  visibility) + classifier timing per page.
- **Metric 1** — structure recall (interactables captured / present). Lower bound;
  the extension adds OCR + screenshot fusion on top.
- **Metric 4** — JS heap delta + classifier ms/page for this harness.

## Metrics 4 (full) & 5 — from the extension

Run a live task and read the **Activity** panel: each step logs
`OCR Xms · faces Yms · redact Zms · total Tms`, the round-trip time, and the
`faceDetectorAvailable` / `ocrLines` / redacted-region counts. `redact.mjs`
exposes `leakScore(original, redacted, regions)` for pixel-IoU if you wire a
before/after canvas capture.

## Ground truth

Fixture fields carry `data-gt="<category>"` (or `"safe"`). `<img data-gt="face">`
marks expected face regions. Keep these in sync with
`client/lib/field-classifier.mjs` category names.
