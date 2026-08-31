# PII Detection Benchmark

**Corpus**: 6100 samples · 3655 gold spans · 3160 positive / 2940 negative lines
**Generated**: 2026-08-30 · seeded, reproducible via `node eval/bench/gen-corpus.mjs`

Span match = same category + character IoU ≥ 0.5, greedy 1:1 per sample. Micro-averaged.

## Overall (span-level)

| Detector | Kind | Precision | Recall | F1 | Line acc. | ms/sample |
|---|---|--:|--:|--:|--:|--:|
| current (regex+checksum) | on-device / rules | 99.1% | 87.0% | **92.7%** | 92.2% | 0 |
| baseline (pre-fix) | on-device / rules | 63.8% | 76.1% | **69.4%** | 63.0% | 0 |
| naive regex (no checksum) | on-device / rules | 51.4% | 79.0% | **62.3%** | 57.8% | 0 |

## Per-category F1

| Category | baseline (pre-fix) | current (regex+checksum) | naive regex (no checksum) |
|---|--:|--:|--:|
| `aadhaar` | 56.7% | 94.8% | 47.3% |
| `pan` | 73.5% | 96.1% | 73.5% |
| `gstin` | 66.2% | 94.2% | 65.9% |
| `ifsc` | 72.0% | 95.9% | 72.0% |
| `upi-vpa` | 47.0% | 100.0% | 53.1% |
| `voter-id` | 63.1% | 78.0% | 63.1% |
| `vehicle-reg` | 65.9% | 92.4% | 0.0% |
| `passport-in` | 75.5% | 84.7% | 70.5% |
| `credit-card` | 57.7% | 93.1% | 35.3% |
| `phone-in` | 43.8% | 90.5% | 51.4% |
| `ssn` | 71.4% | 84.1% | 71.4% |
| `ipv4` | 79.4% | 87.3% | 79.4% |
| `dob` | 91.3% | 92.0% | 73.5% |
| `email` | 100.0% | 100.0% | 100.0% |

## Per-category recall (did it catch the PII?)

| Category | baseline (pre-fix) | current (regex+checksum) | naive regex (no checksum) |
|---|--:|--:|--:|
| `aadhaar` | 41.6% | 96.0% | 68.3% |
| `pan` | 92.6% | 92.6% | 92.6% |
| `gstin` | 89.0% | 89.0% | 88.5% |
| `ifsc` | 92.1% | 92.1% | 92.1% |
| `upi-vpa` | 30.7% | 100.0% | 100.0% |
| `voter-id` | 83.0% | 64.0% | 83.0% |
| `vehicle-reg` | 88.5% | 88.5% | 0.0% |
| `passport-in` | 88.9% | 73.5% | 88.9% |
| `credit-card` | 55.5% | 87.7% | 51.1% |
| `phone-in` | 45.6% | 82.8% | 44.7% |
| `ssn` | 100.0% | 72.5% | 100.0% |
| `ipv4` | 100.0% | 77.5% | 100.0% |
| `dob` | 100.0% | 85.1% | 100.0% |
| `email` | 100.0% | 100.0% | 100.0% |

## Per-category precision (of what it flagged, how much was right?)

| Category | baseline (pre-fix) | current (regex+checksum) | naive regex (no checksum) |
|---|--:|--:|--:|
| `aadhaar` | 88.7% | 93.6% | 36.1% |
| `pan` | 60.9% | 100.0% | 60.9% |
| `gstin` | 52.7% | 100.0% | 52.5% |
| `ifsc` | 59.2% | 100.0% | 59.2% |
| `upi-vpa` | 100.0% | 100.0% | 36.2% |
| `voter-id` | 50.9% | 100.0% | 50.9% |
| `vehicle-reg` | 52.5% | 96.7% | 0.0% |
| `passport-in` | 65.6% | 100.0% | 58.4% |
| `credit-card` | 60.1% | 99.3% | 27.0% |
| `phone-in` | 42.2% | 99.6% | 60.4% |
| `ssn` | 55.6% | 100.0% | 55.6% |
| `ipv4` | 65.8% | 100.0% | 65.8% |
| `dob` | 84.1% | 100.0% | 58.1% |
| `email` | 100.0% | 100.0% | 100.0% |

## Recall by context (span-level)

Context-gated categories deliberately miss *bare* shape-only IDs (voter-id, passport, DOB, SSN with no keyword nearby) — that is the precision trade. "ocr-garbled" = a letter/digit was corrupted, breaking structural validation.

| Context | baseline (pre-fix) | current (regex+checksum) | naive regex (no checksum) |
|---|--:|--:|--:|
| keyworded | 77.5% (n=2017) | 97.1% (n=2017) | 76.5% (n=2017) |
| bare (no keyword) | 76.1% (n=595) | 58.3% (n=595) | 76.1% (n=595) |
| ocr-garbled | 21.8% (n=188) | 18.1% (n=188) | 18.1% (n=188) |
| composite | 83.5% (n=795) | 98.5% (n=795) | 100.0% (n=795) |
| aadhaar-substring-regression | 100.0% (n=60) | 96.7% (n=60) | 100.0% (n=60) |

## Detectors

- **baseline (pre-fix)** — pii-rules.mjs @ 7dafeaa — 14 flat regexes, Verhoeff+Luhn only, no normalization, no context gating.
- **current (regex+checksum)** — client/lib/pii-rules.mjs — unicode normalization + digit-run classification (Aadhaar/card/phone by length+checksum+IIN) + context-gated regex for shape-only IDs.
- **naive regex (no checksum)** — Loose patterns, no Verhoeff/Luhn, no digit-boundary anchoring.

_See `eval/bench/README.md` for methodology and bias controls._
