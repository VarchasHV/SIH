# PII Detection Benchmark

**Corpus**: 8500 samples · 6037 gold spans · 5560 positive / 2940 negative lines
**Generated**: 2026-09-02 · seeded, reproducible via `node eval/bench/gen-corpus.mjs`

Span match = same category + character IoU ≥ 0.5, greedy 1:1 per sample. Micro-averaged.

## Overall (span-level, all positives blended)

> This single number mixes contextual and unlabelled positives. See the class breakdown below — a context-gated detector deliberately trades unlabelled-recall (B) for precision, and that trade must not be hidden here.

| Detector | Kind | Precision | Recall | F1 | Line acc. | ms/sample |
|---|---|--:|--:|--:|--:|--:|
| current (regex+checksum) | on-device / rules | 99.2% | 84.1% | **91.0%** | 88.8% | 0 |

## Phase 4 — results by class (A/B/C/D reported separately)

| Class | Metric | current (regex+checksum) |
|---|---|--:|
| A · contextual positive (keyworded) | recall | 93.8% (n=4099) |
| B · unlabelled positive (no keyword) | recall | 57.1% (n=559) |
| C · structured-identifier positive | recall | 86.2% (n=3706) |
| D · adversarial negative (same shape, not PII) | false-positive rate | 0.8% (19/2240) |
| clean negative (safe prose) | false-positive rate | 0.0% (0/700) |
| OCR-garbled positive | recall | 16.1% (n=542) |
| multi-PII sentence | recall | 98.6% (n=777) |
| aadhaar-substring regression | recall | 98.3% (n=60) |

**A vs B is the whole story of a context-gated detector.** B (unlabelled) recall being lower than A (contextual) is by design — bare shape-only IDs are dropped to keep precision high on class D.

## Per-category F1

| Category | current (regex+checksum) |
|---|--:|
| `aadhaar` | 93.2% |
| `pan` | 97.3% |
| `gstin` | 92.8% |
| `ifsc` | 97.7% |
| `upi-vpa` | 100.0% |
| `voter-id` | 85.1% |
| `vehicle-reg` | 92.3% |
| `passport-in` | 85.0% |
| `credit-card` | 90.0% |
| `phone-in` | 84.4% |
| `ssn` | 83.7% |
| `ipv4` | 87.0% |
| `dob` | 89.8% |
| `email` | 100.0% |

## Per-category recall (did it catch the PII?)

| Category | current (regex+checksum) |
|---|--:|
| `aadhaar` | 89.7% |
| `pan` | 94.7% |
| `gstin` | 86.5% |
| `ifsc` | 95.6% |
| `upi-vpa` | 100.0% |
| `voter-id` | 74.0% |
| `vehicle-reg` | 86.5% |
| `passport-in` | 73.9% |
| `credit-card` | 81.9% |
| `phone-in` | 73.5% |
| `ssn` | 72.0% |
| `ipv4` | 77.0% |
| `dob` | 81.4% |
| `email` | 100.0% |

## Per-category precision (of what it flagged, how much was right?)

| Category | current (regex+checksum) |
|---|--:|
| `aadhaar` | 97.1% |
| `pan` | 100.0% |
| `gstin` | 100.0% |
| `ifsc` | 100.0% |
| `upi-vpa` | 100.0% |
| `voter-id` | 100.0% |
| `vehicle-reg` | 98.9% |
| `passport-in` | 100.0% |
| `credit-card` | 99.8% |
| `phone-in` | 99.2% |
| `ssn` | 100.0% |
| `ipv4` | 100.0% |
| `dob` | 100.0% |
| `email` | 100.0% |

## Recall by context (span-level)

Context-gated categories deliberately miss *bare* shape-only IDs (voter-id, passport, DOB, SSN with no keyword nearby) — that is the precision trade. "ocr-garbled" = a letter/digit was corrupted, breaking structural validation.

| Context | current (regex+checksum) |
|---|--:|
| keyworded | 93.8% (n=4099) |
| bare (no keyword) | 57.1% (n=559) |
| ocr-garbled | 16.1% (n=542) |
| composite | 98.6% (n=777) |
| aadhaar-substring-regression | 98.3% (n=60) |

## Phase 6 — recall by surface form (Unicode / OCR robustness)

Preprocessing is a real, separate pipeline stage — it must not be silently credited to "the detector". `current` runs `pii-rules.mjs normalize()` (folds Arabic / Persian / Devanagari / fullwidth digits, NBSP, Unicode dashes, strips zero-width) **before** matching; `naive regex` does not. The gap between the two columns on the non-ASCII rows below IS the normalization contribution, shown explicitly.

| Surface form | current (regex+checksum) |
|---|--:|
| ASCII (plain / space / hyphen / dot) | 91.0% (n=3183) |
| Arabic-Indic digits | 90.3% (n=300) |
| Persian digits | 91.3% (n=300) |
| Devanagari digits | 89.6% (n=375) |
| fullwidth digits | 90.7% (n=300) |
| non-breaking space sep | 88.9% (n=370) |
| en-dash sep | 92.1% (n=367) |
| zero-width space between digits | 91.3% (n=300) |
| OCR char-confusion (O↔0, l↔1, S↔5…) | 16.1% (n=542) |

OCR-confusion recall is low for every detector — a corrupted digit breaks the checksum, and `normalize()` cannot recover it. That is a genuine limitation of a screenshot-reading pipeline and is reported, not hidden.

## Detectors

- **current (regex+checksum)** — client/lib/pii-rules.mjs — unicode normalization + digit-run classification (Aadhaar/card/phone by length+checksum+IIN) + context-gated regex for shape-only IDs.

_See `eval/bench/README.md` for methodology and bias controls._
