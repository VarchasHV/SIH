# Screenshot / Vision Benchmark (Phase 8)

> **Layout specs, not pixels.** No headless browser / real OCR in this environment. This measures the FUSION + REDACTION GEOMETRY: given a screen with PII at known boxes and a perfect OCR read, does `mergeDetections` + the risk model cover the PII boxes and leave the decoys alone? Real end-to-end numbers are lower — multiply by OCR recall (eval/bench: ASCII 91%, OCR-garbled 16%) and real ViT/face recall (NOT MEASURED).

**Corpus**: 11 screens · 38 ground-truth PII boxes · login, banking, checkout, government-form, invoice, profile, dashboard

## Overall

| Metric | Value |
|---|--:|
| Visual PII recall (box covered) | 78.9% |
| Visual PII precision (region on PII) | 100.0% |
| Mean bbox IoU (matched) | 90.9% |
| Geometric leakage (PII area uncovered) | 21.1% |
| Adversarial false-redaction (order-id/SKU/IPv4/build) | 0.0% (0 boxes) |

## Per screen

| Screen | Type | GT PII | Recall | Precision | bbox IoU | Leakage | Adv-FP |
|---|---|--:|--:|--:|--:|--:|--:|
| login-light | login | 2 | 100.0% | 100.0% | 100.0% | 0.0% | 0/0 |
| login-dark | login | 2 | 100.0% | 100.0% | 100.0% | 0.0% | 0/0 |
| banking-light | banking | 4 | 75.0% | 100.0% | 100.0% | 26.1% | 0/1 |
| banking-dark | banking | 4 | 50.0% | 100.0% | 100.0% | 52.2% | 0/1 |
| checkout-payment | checkout | 4 | 100.0% | 100.0% | 100.0% | 0.0% | 0/1 |
| kyc-onboarding | government-form | 6 | 100.0% | 100.0% | 100.0% | 0.0% | 0/0 |
| kyc-onboarding | government-form | 6 | 100.0% | 100.0% | 100.0% | 0.0% | 0/0 |
| invoice | invoice | 4 | 25.0% | 100.0% | 100.0% | 71.9% | 0/2 |
| profile-light | profile | 3 | 66.7% | 100.0% | 100.0% | 33.3% | 0/2 |
| profile-dark | profile | 3 | 66.7% | 100.0% | 100.0% | 33.3% | 0/2 |
| dashboard-clean | dashboard | 0 | 100.0% | 100.0% | 0.0% | 0.0% | 0/3 |

_NOT MEASURED: real OCR, real ViT/face detection, real rendering, dark/light pixel contrast, font scaling effects._
