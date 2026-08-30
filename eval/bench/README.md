# eval/bench — adversarial PII-detection benchmark

Independent, seeded benchmark for the on-device value detector
(`client/lib/pii-rules.mjs`). Built to answer: *how often does it miss real PII,
and how often does it flag something that isn't?* — across separator styles,
unicode, OCR corruption, and same-shaped decoys.

## Run it

```bash
node eval/bench/gen-corpus.mjs --n-per-category 200 --n-clean 700 --n-composite 300 --seed 20260830
node eval/bench/run.mjs                 # all detectors -> results.md + results.json
node eval/bench/run.mjs current baseline  # subset
LIMIT=300 node eval/bench/run.mjs         # first N samples (for slow detectors)
```

Change `--seed` to get a fresh corpus — scores should move < ~1 F1 point. If they
move more, the detector is memorising wording rather than structure.

## What's in the corpus (~6,100 samples, 3,655 gold spans)

| Bucket | How it's built |
|---|---|
| positives, 14 categories, ~200 each | valid values (real checksums / IIN prefixes / RTO codes / NPCI handles) rendered in **9 surface forms**: plain, single-space, **double-space**, hyphen, dot, NBSP, en-dash, **Devanagari digits**, **OCR-confusion** (O↔0, l↔1, S↔5 …) |
| keyworded vs bare | ~78% sit next to a category keyword ("Aadhaar", "IFSC", "born on"); ~22% are dropped into neutral prose with no keyword |
| composite | 300 multi-PII sentences (KYC lines, payment lines) with 2–4 spans each |
| hard negatives, ~160 per category | **same-shape, not-that-PII**: Verhoeff-failing 12-digit numbers, Luhn-valid 15-digit IMEIs, 16-digit order numbers, `NNN-NN-NNNN` case/claim/docket numbers, dotted version strings, non-DOB dates, PAN-shaped SKUs, unrecognised IFSC prefixes, `user@github`-style handles — each wrapped in a misleading keyword ("order", "invoice", "IMEI", "manifest") |
| clean | 700 plain business sentences, some with bare numbers (counts, prices, years, room numbers) |
| aadhaar-substring regression | 60 real 16-digit cards whose **first 12 digits coincidentally pass Verhoeff** — labelled `credit-card` only |

## Bias controls

- **Labels come only from generation parameters.** No detector is ever run to
  decide a label. The generator emits e.g. a hyphen-separated Aadhaar whether or
  not any detector can parse hyphens.
- **Every category is stressed evenly** (~200 positives + ~160 negatives each) —
  the corpus is not weighted toward categories the current detector is good at.
- **Negatives target each detector's known failure mode**, not just easy noise.
- **Deterministic**: everything derives from `--seed`; the corpus is committable.
- Known limits: English prose only; synthetic sentence templates (not scraped
  text); OCR corruption is simulated char-swaps, not a real OCR pass.

## Scoring

- **Span level** (the number that matters for redaction): a prediction is a TP if
  its category matches a gold span AND character IoU ≥ 0.5. Greedy 1:1 per
  sample. Micro-averaged. Reported per category + overall.
- **Recall by context**: recall split into keyworded / bare / ocr-garbled /
  composite so the context-gating trade-off is explicit — shape-only IDs
  (voter-id, passport, DOB, SSN) are *designed* to miss bare instances.
- **Line level**: on a positive line did it flag ≥1 span; on a negative line did
  it stay silent → "would we have redacted this line correctly".
- **Latency**: wall-clock ms/sample.

## Detectors

| id | what |
|---|---|
| `current` | `client/lib/pii-rules.mjs` — normalization + digit-run classification + context-gated regex |
| `baseline-old` | frozen snapshot of the detector before the benchmark fixes (14 flat regexes, Verhoeff+Luhn only) — the "before" |
| `naive-regex` | loose patterns, no checksums, no anchoring — the floor |

Add a detector by dropping a `detectors/*.mjs` that exports
`meta` and `async detect(text) -> [{category, value, start, end}]`. External
models can return their own label strings; `run.mjs` has an alias map.
