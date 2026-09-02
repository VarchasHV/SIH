# Competitor Benchmark

**Commit `78d05d8` · 2026-09-02 · Apple M3 / Node v24 / Python 3.12**

Two things are compared: **text-PII detection quality** (measured, same dataset)
and **privacy architecture** (capability matrix). Cells are only filled from what
was actually run.

---

## 1. Text-PII detection — MEASURED

`eval/bench/competitors/run_competitors.py`, 2,500 samples of the seeded
adversarial corpus (`eval/bench/corpus.jsonl`, seed 20260902). Scoring:
category-set per line — did the tool flag gold category *C* somewhere on a line
that contains a gold *C* span. Micro-averaged over 14 categories.

| System | Precision | Recall | F1 | ms/sample | On-device |
|---|--:|--:|--:|--:|:--:|
| **Privacy Lens** (`client/lib/pii-rules.mjs`) | **98.9%** | **84.7%** | **91.3%** | 0.023 | ✅ |
| Microsoft Presidio 2.2 (`en_core_web_lg` + recognizers) | 46.7% | 34.1% | 39.4% | 2.51 | ✅ |
| spaCy NER `en_core_web_sm` (+ email regex) | 15.4% | 7.2% | 9.8% | 1.90 | ✅ |
| Flair `ner-english-ontonotes-large` | — | — | — | NOT TESTED — package not installed |
| AWS Comprehend PII | — | — | — | **NOT EXECUTED** — no AWS credentials |
| Google Cloud DLP | — | — | — | **NOT EXECUTED** — no GCP credentials |
| Azure AI Language PII | — | — | — | **NOT EXECUTED** — no Azure credentials |

**Why Presidio/spaCy score low here** (not a rigged corpus — these are real runs):
- the corpus is India-weighted (Aadhaar, PAN, IFSC, UPI, voter-ID, vehicle-reg);
  Presidio ships recognizers for Aadhaar/PAN/passport/voter/vehicle but not UPI,
  IFSC or GSTIN, and spaCy has none of them;
- ~40% of the corpus is **adversarial negatives** (order-IDs, SKUs, IMEIs,
  version strings shaped like the real thing); Presidio's broad patterns flag
  many of them (its precision here is 47%);
- spaCy is generic OntoNotes NER — it contributes `email` (via the regex we
  bolt on) and some `DATE→dob`, nothing else.

This is **not** a claim that our regex engine beats commercial NLP at English
prose PII. It is a claim that for **structured Indian browser PII + adversarial
look-alikes**, on-device, a purpose-built detector wins on this dataset. The
commercial APIs were not run and their published capability is in §2.

Re-run: `.venv/bin/pip install presidio-analyzer spacy && .venv/bin/python -m spacy download en_core_web_sm && .venv/bin/python eval/bench/competitors/run_competitors.py --limit 2500`

---

## 2. Privacy-architecture capability matrix

Legend: **PASS** = tested and works · **PARTIAL** = tested, limited · **NOT SUPPORTED** = the system cannot do this · **NOT TESTED** = not evaluated here.

| System | Text PII | Screenshot PII | Browser DOM | On-device | Pre-egress redaction | Agent integration |
|---|:--:|:--:|:--:|:--:|:--:|:--:|
| **Privacy Lens** | PASS (F1 91.3%, §1) | PARTIAL (geometry F1 measured; real OCR NOT TESTED) | PASS (`skeleton.js` + field classifier) | PASS (all detection in the browser) | PASS (`redact.mjs` + `egress-guard.mjs`, §5 of BENCHMARK_REPORT) | PASS (`/agent/step`, `executor.js`; mock-VLM suite `test_mock_agent.py`) |
| Microsoft Presidio | PARTIAL (F1 39.4%, §1) | NOT SUPPORTED (text only; `presidio-image-redactor` is a separate OCR project, NOT TESTED) | NOT SUPPORTED | PASS | NOT SUPPORTED (it detects; redaction/anonymization is a separate step you build) | NOT SUPPORTED |
| AWS Comprehend | NOT TESTED (docs: US/EU entities; no native Aadhaar/PAN/UPI/IFSC) | NOT SUPPORTED | NOT SUPPORTED | NOT SUPPORTED (cloud API — text leaves the device) | NOT SUPPORTED | NOT SUPPORTED |
| Google Cloud DLP | NOT TESTED (docs: has `AADHAAR…`, `INDIA_PAN…`, `INDIA_GST…`; no UPI/voter/vehicle infoType) | PARTIAL per docs (image inspection + redaction infoTypes) — NOT TESTED | NOT SUPPORTED | NOT SUPPORTED (cloud API) | PARTIAL per docs (de-identification templates) — NOT TESTED | NOT SUPPORTED |
| Azure AI Language PII | NOT TESTED (docs: limited India entities) | NOT SUPPORTED | NOT SUPPORTED | NOT SUPPORTED (cloud API) | NOT SUPPORTED | NOT SUPPORTED |
| GitHub regex baseline (`eval/bench/detectors/naive-regex.mjs`) | PARTIAL (F1 49.7%, `eval/bench/results.md`) | NOT SUPPORTED | NOT SUPPORTED | PASS | NOT SUPPORTED | NOT SUPPORTED |

**The defensible claim**: no other system in this table does the whole chain —
detect (DOM + OCR + vision + DLP), fuse with a risk model, **redact locally**,
and gate the payload — *before anything reaches a remote VLM*. The commercial
DLP services are themselves the remote service that receives your data.

---

## 3. What would make this stronger

- Run AWS Comprehend / Google Cloud DLP / Azure on the exact `corpus.jsonl`
  with credentials, span-aligned, and fill §1.
- Install Flair + `presidio-image-redactor` and test the screenshot path.
- A real headless-browser OCR pass for §2's "Screenshot PII" row (currently the
  geometry is measured but OCR recall is imported from `eval/bench`, not run
  end-to-end).
