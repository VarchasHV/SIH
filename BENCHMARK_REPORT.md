# Benchmark Report

Generated 2026-09-03T15:12:02.630Z · commit `b7f0cb8` (dirty) · Apple M3 · Node v24.16.0 · Darwin 25.6.0

Every number here is a **measurement**. Where something was not run it says so. Regenerate: `npm run bench && npm run bench:redaction && npm run bench:latency && npm run bench:screens && node eval/experiments/privacy-egress.mjs && .venv/bin/python eval/bench/competitors/run_competitors.py && node scripts/aggregate-benchmarks.mjs`

**Corpus** (`eval/bench/gen-corpus.mjs`): seed 20260902 · 9940 samples · 6835 gold spans · 0 offset errors.

## 1. PII detection (span-level, seeded adversarial corpus)

Overall (blended): **P 99.4% · R 84.1% · F1 91.1%**

| Class | metric | value |
|---|---|--:|
| A-contextual | recall (n=4731) | 93.5% |
| B-unlabelled | recall (n=727) | 56.3% |
| C-structured | recall (n=4110) | 87.4% |
| D-adversarial-neg | false-positive rate (20/2880) | 0.7% |
| clean | false-positive rate (0/700) | 0.0% |
| ocr | recall (n=542) | 16.2% |
| composite | recall (n=775) | 98.7% |
| regression | recall (n=60) | 98.3% |

Unicode/OCR (recall by surface form): zwsp 90.3% · ascii 90.2% · endash 89.1% · pers 89.3% · arab 90.0% · ocr 16.2% · fullwidth 89.7% · nbsp 90.5% · deva 87.2%

## 2. Redaction (scored against ground-truth spans)

Leakage rate **14.4%** · fully redacted 82.6% · over-redaction 0.3% · char IoU 85.4%

Leakage by class: other 0.0% · A-contextual 6.3% · ocr-garbled 85.3% · composite 1.5% · B-unlabelled 35.7% · regression 1.7%

## 3. Latency — DETECTOR ONLY (measured)

p50 **0.0026ms** · p90 0.0045ms · p95 0.0074ms · p99 0.011ms · max 0.1273ms · cold start 0.9252ms · 25500 samples

**Not measured** (need a browser): ocrMs, faceDetectionMs, visionTransformerMs, screenshotCaptureMs, redactionMs, networkRoundTripMs, endToEndMs

## 4. Screenshot / vision (fusion + redaction GEOMETRY — no real OCR/render)

Visual PII recall 78.9% · precision 100.0% · bbox IoU 90.9% · geometric leakage 21.1% · adversarial false-redaction 0

> Fusion + redaction geometry on DECLARED boxes/text. OCR recall, ViT/face recall and rendering are NOT MEASURED — real end-to-end numbers are lower.

## 5. The privacy experiment — raw PII bytes to server

| Pipeline | raw PII bytes |
|---|--:|
| A — unprotected | 3794 |
| B — OCR→PII→redact | 960 |
| C — full pipeline + egress gate | 535 |
| C+profile — real flow | 535 |

Reduction A→C: **85.9%**. Task-goal PII → 0 in every protected pipeline.

## 6. Competitors (2500 samples, category-set per line (did the tool flag gold category C on a line containing a gold C span))

| System | P | R | F1 | ms/sample |
|---|--:|--:|--:|--:|
| Privacy Lens (pii-rules.mjs) | 98.9% | 84.7% | 91.3% | 0.0231 |
| Microsoft Presidio | 46.7% | 34.1% | 39.4% | 2.5059 |
| spaCy NER (en_core_web_sm) | 15.4% | 7.2% | 9.8% | 1.9008 |
| AWS Comprehend (PII) | — | — | — | NOT_EXECUTED — no AWS credentials in this environment |
| Google Cloud DLP | — | — | — | NOT_EXECUTED — no GCP credentials in this environment |
| Azure AI Language (PII) | — | — | — | NOT_EXECUTED — no Azure credentials in this environment |

