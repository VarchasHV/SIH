# SIH Scorecard

**Commit `78d05d8` · 2026-09-02 · Apple M3 / Node v24.16.0 / Python 3.12 / Darwin 25.6**

Every figure is a measurement from `BENCHMARK_REPORT.md` / `benchmark-results.json`.
Where a rubric item cannot be measured in this environment it says **NOT MEASURED**
and why. Nothing here is estimated or assumed.

Regenerate: `npm run bench && npm run bench:redaction && npm run bench:latency && npm run bench:screens && node eval/experiments/privacy-egress.mjs && .venv/bin/python eval/bench/competitors/run_competitors.py && node scripts/aggregate-benchmarks.mjs`

---

### 1. Visual Context Accuracy — 25%

| Metric | Value | Source |
|---|--:|---|
| Agent action-correctness (F1 of field-coverage × targeting) | **NOT MEASURED** — needs a running VLM server (`eval/agent-eval.mjs`, not in `npm test`) | — |
| Mock-VLM field-targeting accuracy (deterministic, offline) | **100%** (3/3 fillable KYC fields; skips the no-value password field) | `tests/test_mock_agent.py` |
| Screen fusion — visual PII recall (box covered) | 78.9% | `eval/screens/screens.results.md` |
| Screen fusion — visual PII precision | 100.0% | ″ |
| Screen fusion — bbox IoU (matched) | 90.9% | ″ |

**NOT MEASURED**: real OCR read of a rendered page, ViT/face-detector recall,
pixel rendering — no headless browser in this environment. The screen numbers
are fusion + redaction **geometry** on declared boxes/text (perfect-OCR ceiling).

---

### 2. PII Detection Precision / Recall — 20%

Span-level (IoU ≥ 0.5), 8,500-sample seeded adversarial corpus, `current` detector.

| | Value |
|---|--:|
| Precision (blended) | **99.2%** |
| Recall (blended) | **84.1%** |
| F1 (blended) | **91.0%** |

Reported by class (the blended number hides the trade — see it):

| Class | Recall / FP-rate |
|---|--:|
| A · contextual (labelled) positive | 93.8% recall |
| B · unlabelled positive | 57.1% recall |
| C · structured-identifier positive | 86.2% recall |
| D · adversarial negative (order-id / SKU / IMEI / version) | **0.8%** false-positive rate |
| clean prose | 0.0% false-positive rate |
| OCR-garbled positive | 16.1% recall |

Unicode robustness (recall by digit system): Arabic 90.3% · Persian 91.3% ·
Devanagari 89.6% · fullwidth 90.7% · zero-width-sep 91.3% (vs 0% for a detector
without the normalization pre-pass).

Competitors on the same corpus (2,500 samples, category-set scoring):
Presidio F1 **39.4%**, spaCy F1 **9.8%**. Commercial APIs **NOT EXECUTED** (no
credentials) — see `COMPETITOR_BENCHMARK.md`.

---

### 3. Redaction Precision — 20%

Scored against **ground-truth** spans (a missed span leaks 100%).

| | Value |
|---|--:|
| Redaction leakage rate (headline privacy metric) | **14.7%** |
| — on class A (labelled PII) | 6.0% |
| — on composite (KYC / payment sentences) | 1.0% |
| — on OCR-garbled | 85.4% |
| Fully-redacted spans | 82.4% |
| Over-redaction rate | 0.3% |
| Character IoU | 85.0% |

Baseline comparison (`naive-regex`): leakage **55.5%**, over-redaction 36.1%.

**NOT MEASURED**: pixel-space leakage on a real rendered+redacted screenshot
(needs a browser). `client/lib/redact.mjs::leakScore` is a proxy over detected
regions only and is not used for this number.

---

### 4. Client Resource Utilization — 20%

| Metric | Value | Notes |
|---|--:|---|
| Detector latency p50 / p95 / p99 | **2.5µs / 7.1µs / 10.5µs** | warm, 25,500 samples, Apple M3 |
| Detector cold start | ~0.9 ms | first call after import |
| Detector heap delta over a run | ~3.9 MB | `process.memoryUsage` |
| Model footprint — regex detector | 0 (pure JS, no model) | `client/lib/pii-rules.mjs` |
| Model footprint — Tesseract core | ~24 MB WASM (vendored) | `client/vendor/` |
| Model footprint — YOLOS-tiny int8 | ~9.4 MB ONNX | fetched on first use |
| Model footprint — BlazeFace | ~230 KB tflite | ″ |

**NOT MEASURED**: OCR / face / ViT stage latency, CPU%, GPU memory, full
extension RAM — all need an in-browser measurement (no headless browser here).
The fabricated "280 ms saving" constant has been removed from the code.

---

### 5. End-to-End Latency — 15%

**NOT MEASURED.** End-to-end = screenshot capture → OCR + face + ViT → fusion →
redaction → JPEG encode → network → VLM → action, and every stage except the
detector needs a real browser + a live VLM endpoint. `eval/bench/latency.mjs`
records the one stage it can measure (detection: p50 2.5µs) and marks the rest
`NOT_MEASURED` rather than inventing p50/p95/p99.

To measure: load the extension (`chrome://extensions` → Load unpacked → `client/`),
run the agent on `fixtures/kyc.html`, read the Activity panel's per-step
`ocr/face/ViT/redact/total ms`.

---

## Honest summary

| Rubric item | Measured? | Headline |
|---|:--:|---|
| 1 · Visual context (25%) | Partial | fusion geometry F1 measured; real OCR/agent NOT MEASURED |
| 2 · PII P/R (20%) | ✅ | P 99.2% · R 84.1% · F1 91.0% (span-level, adversarial) |
| 3 · Redaction (20%) | ✅ (text) | leakage 14.7% overall, 6.0% on labelled PII; pixel-space NOT MEASURED |
| 4 · Client resources (20%) | Partial | detector p50 2.5µs, footprints listed; stage latency/CPU/RAM NOT MEASURED |
| 5 · End-to-end latency (15%) | ❌ | NOT MEASURED — needs a browser + live VLM |

**Do not award points for items marked NOT MEASURED.**
