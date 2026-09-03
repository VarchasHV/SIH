# PII Detection Benchmark

**Corpus**: 9940 samples · 6835 gold spans · 6360 positive / 3580 negative lines
**Generated**: 2026-09-03 · seeded, reproducible via `node eval/bench/gen-corpus.mjs`

Span match = same category + character IoU ≥ 0.5, greedy 1:1 per sample. Micro-averaged.

## Overall (span-level, all positives blended)

> This single number mixes contextual and unlabelled positives. See the class breakdown below — a context-gated detector deliberately trades unlabelled-recall (B) for precision, and that trade must not be hidden here.

| Detector | Kind | Precision | Recall | F1 | Line acc. | ms/sample |
|---|---|--:|--:|--:|--:|--:|
| current (regex+checksum) | on-device / rules | 99.4% | 84.1% | **91.1%** | 89.1% | 0.01 |
| baseline (pre-fix) | on-device / rules | 64.4% | 42.1% | **50.9%** | 46.7% | 0 |
| naive regex (no checksum) | on-device / rules | 51.1% | 42.4% | **46.3%** | 42.4% | 0 |

## Phase 4 — results by class (A/B/C/D reported separately)

| Class | Metric | baseline (pre-fix) | current (regex+checksum) | naive regex (no checksum) |
|---|---|--:|--:|--:|
| A · contextual positive (keyworded) | recall | 35.5% (n=4731) | 93.5% (n=4731) | 33.1% (n=4731) |
| B · unlabelled positive (no keyword) | recall | 62.0% (n=727) | 56.3% (n=727) | 60.0% (n=727) |
| C · structured-identifier positive | recall | 39.0% (n=4110) | 87.4% (n=4110) | 37.8% (n=4110) |
| D · adversarial negative (same shape, not PII) | false-positive rate | 53.3% (1534/2880) | 0.7% (20/2880) | 63.1% (1818/2880) |
| clean negative (safe prose) | false-positive rate | 0.0% (0/700) | 0.0% (0/700) | 0.0% (0/700) |
| OCR-garbled positive | recall | 12.2% (n=542) | 16.2% (n=542) | 10.7% (n=542) |
| multi-PII sentence | recall | 79.9% (n=775) | 98.7% (n=775) | 100.0% (n=775) |
| aadhaar-substring regression | recall | 100.0% (n=60) | 98.3% (n=60) | 100.0% (n=60) |

**A vs B is the whole story of a context-gated detector.** B (unlabelled) recall being lower than A (contextual) is by design — bare shape-only IDs are dropped to keep precision high on class D.

## Per-category F1

| Category | baseline (pre-fix) | current (regex+checksum) | naive regex (no checksum) |
|---|--:|--:|--:|
| `aadhaar` | 33.1% | 93.4% | 22.4% |
| `pan` | 72.6% | 97.0% | 72.6% |
| `gstin` | 64.9% | 92.8% | 64.7% |
| `ifsc` | 74.4% | 97.7% | 74.4% |
| `upi-vpa` | 41.5% | 100.0% | 54.9% |
| `voter-id` | 64.9% | 85.1% | 64.9% |
| `vehicle-reg` | 64.7% | 92.3% | 0.0% |
| `passport-in` | 79.4% | 85.7% | 73.5% |
| `credit-card` | 27.9% | 89.5% | 21.3% |
| `phone-in` | 17.3% | 83.3% | 18.4% |
| `ssn` | 71.4% | 83.7% | 71.4% |
| `ipv4` | 78.7% | 87.0% | 78.7% |
| `dob` | 90.5% | 90.1% | 72.4% |
| `email` | 100.0% | 100.0% | 100.0% |
| `iban` | 0.0% | 100.0% | 0.0% |
| `btc-address` | 0.0% | 100.0% | 0.0% |
| `eth-address` | 0.0% | 81.7% | 0.0% |
| `uk-nino` | 0.0% | 88.3% | 0.0% |

## Per-category recall (did it catch the PII?)

| Category | baseline (pre-fix) | current (regex+checksum) | naive regex (no checksum) |
|---|--:|--:|--:|
| `aadhaar` | 20.2% | 89.7% | 17.5% |
| `pan` | 94.3% | 94.3% | 94.3% |
| `gstin` | 86.5% | 86.5% | 86.0% |
| `ifsc` | 95.4% | 95.4% | 95.4% |
| `upi-vpa` | 26.2% | 100.0% | 100.0% |
| `voter-id` | 86.5% | 74.0% | 86.5% |
| `vehicle-reg` | 86.5% | 86.5% | 0.0% |
| `passport-in` | 93.5% | 74.9% | 93.5% |
| `credit-card` | 18.0% | 81.2% | 16.5% |
| `phone-in` | 11.2% | 71.8% | 11.0% |
| `ssn` | 100.0% | 72.0% | 100.0% |
| `ipv4` | 100.0% | 77.0% | 100.0% |
| `dob` | 100.0% | 82.0% | 100.0% |
| `email` | 100.0% | 100.0% | 100.0% |
| `iban` | 0.0% | 100.0% | 0.0% |
| `btc-address` | 0.0% | 100.0% | 0.0% |
| `eth-address` | 0.0% | 69.0% | 0.0% |
| `uk-nino` | 0.0% | 79.0% | 0.0% |

## Per-category precision (of what it flagged, how much was right?)

| Category | baseline (pre-fix) | current (regex+checksum) | naive regex (no checksum) |
|---|--:|--:|--:|
| `aadhaar` | 90.3% | 97.4% | 31.0% |
| `pan` | 59.0% | 100.0% | 59.0% |
| `gstin` | 52.0% | 100.0% | 51.8% |
| `ifsc` | 61.0% | 100.0% | 61.0% |
| `upi-vpa` | 100.0% | 100.0% | 37.8% |
| `voter-id` | 52.0% | 100.0% | 52.0% |
| `vehicle-reg` | 51.6% | 98.9% | 0.0% |
| `passport-in` | 68.9% | 100.0% | 60.6% |
| `credit-card` | 62.1% | 99.8% | 30.2% |
| `phone-in` | 37.5% | 99.2% | 54.7% |
| `ssn` | 55.6% | 100.0% | 55.6% |
| `ipv4` | 64.9% | 100.0% | 64.9% |
| `dob` | 82.6% | 100.0% | 56.7% |
| `email` | 100.0% | 100.0% | 100.0% |
| `iban` | 0.0% | 100.0% | 0.0% |
| `btc-address` | 0.0% | 100.0% | 0.0% |
| `eth-address` | 0.0% | 100.0% | 0.0% |
| `uk-nino` | 0.0% | 100.0% | 0.0% |

## Recall by context (span-level)

Context-gated categories deliberately miss *bare* shape-only IDs (voter-id, passport, DOB, SSN with no keyword nearby) — that is the precision trade. "ocr-garbled" = a letter/digit was corrupted, breaking structural validation.

| Context | baseline (pre-fix) | current (regex+checksum) | naive regex (no checksum) |
|---|--:|--:|--:|
| keyworded | 35.5% (n=4731) | 93.5% (n=4731) | 33.1% (n=4731) |
| bare (no keyword) | 62.0% (n=727) | 56.3% (n=727) | 60.0% (n=727) |
| ocr-garbled | 12.2% (n=542) | 16.2% (n=542) | 10.7% (n=542) |
| composite | 79.9% (n=775) | 98.7% (n=775) | 100.0% (n=775) |
| aadhaar-substring-regression | 100.0% (n=60) | 98.3% (n=60) | 100.0% (n=60) |

## Phase 6 — recall by surface form (Unicode / OCR robustness)

Preprocessing is a real, separate pipeline stage — it must not be silently credited to "the detector". `current` runs `pii-rules.mjs normalize()` (folds Arabic / Persian / Devanagari / fullwidth digits, NBSP, Unicode dashes, strips zero-width) **before** matching; `naive regex` does not. The gap between the two columns on the non-ASCII rows below IS the normalization contribution, shown explicitly.

| Surface form | baseline (pre-fix) | current (regex+checksum) | naive regex (no checksum) |
|---|--:|--:|--:|
| ASCII (plain / space / hyphen / dot) | 67.5% (n=3981) | 90.2% (n=3981) | 71.3% (n=3981) |
| Arabic-Indic digits | 0.0% (n=300) | 90.0% (n=300) | 0.0% (n=300) |
| Persian digits | 0.0% (n=300) | 89.3% (n=300) | 0.0% (n=300) |
| Devanagari digits | 0.0% (n=375) | 87.2% (n=375) | 0.0% (n=375) |
| fullwidth digits | 0.0% (n=300) | 89.7% (n=300) | 0.0% (n=300) |
| non-breaking space sep | 33.2% (n=370) | 90.5% (n=370) | 0.0% (n=370) |
| en-dash sep | 0.0% (n=367) | 89.1% (n=367) | 0.0% (n=367) |
| zero-width space between digits | 0.0% (n=300) | 90.3% (n=300) | 0.0% (n=300) |
| OCR char-confusion (O↔0, l↔1, S↔5…) | 12.2% (n=542) | 16.2% (n=542) | 10.7% (n=542) |

OCR-confusion recall is low for every detector — a corrupted digit breaks the checksum, and `normalize()` cannot recover it. That is a genuine limitation of a screenshot-reading pipeline and is reported, not hidden.

## Detectors

- **baseline (pre-fix)** — pii-rules.mjs @ 7dafeaa — 14 flat regexes, Verhoeff+Luhn only, no normalization, no context gating.
- **current (regex+checksum)** — client/lib/pii-rules.mjs — unicode normalization + digit-run classification (Aadhaar/card/phone by length+checksum+IIN) + context-gated regex for shape-only IDs.
- **naive regex (no checksum)** — Loose patterns, no Verhoeff/Luhn, no digit-boundary anchoring.

_See `eval/bench/README.md` for methodology and bias controls._
