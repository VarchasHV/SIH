# The Privacy Experiment — raw PII bytes to server (Phase 15)

**11 screens × 5 task goals = 55 cases per pipeline** · 2026-09-02 · commit `78d05d8`

| Pipeline | Raw PII bytes → server | Distinct PII values leaked | Task-goal PII bytes |
|---|--:|--:|--:|
| **A — unprotected** (raw page text + raw goal) | **3794** | 226 | 1496 |
| **B — OCR → PII → redact** (+ goal scrubbed) | **960** | 75 | 0 |
| **C — full local pipeline + egress gate** (empty profile) | **535** | 40 | 0 |
| **C+profile — real flow** (user's own profile on device) | **535** | 40 | 0 |

Reduction A→C: **85.9%** · A→C+profile: **85.9%**.

## Residual leak by category

| Category | A | B | C | C+profile |
|---|--:|--:|--:|--:|
| aadhaar | 448 | 0 | 0 | 0 |
| address | 646 | 305 | 150 | 150 |
| bank-account | 110 | 55 | 55 | 55 |
| credit-card | 304 | 0 | 0 | 0 |
| cvv | 15 | 15 | 0 | 0 |
| dob | 90 | 90 | 0 | 0 |
| email | 1021 | 0 | 0 | 0 |
| gstin | 75 | 75 | 75 | 75 |
| ifsc | 110 | 0 | 0 | 0 |
| name | 552 | 420 | 255 | 255 |
| pan | 100 | 0 | 0 | 0 |
| phone-in | 280 | 0 | 0 | 0 |

Task-goal PII → **0 bytes** in every protected pipeline (the goal sanitizer).

## Caveats (read these)

- Declared screen text is treated as a PERFECT OCR read — real OCR recall (eval/bench: ASCII 91%, OCR-garbled 16%) would leave more visible in B and C.
- No pixels / no real render. This counts PII BYTES in the text payload; the redacted screenshot bytes are a separate channel (eval/bench redaction leakage 14.7% overall, 6.0% on labelled PII).
- C's element-drop is geometric (a redact-decision box overlapping an element drops it).
- C residual is dominated by bare third-party names/addresses in static display text — the same B-unlabelled limitation. C+profile shows the real flow, where the user's OWN name/address/email are exact-matched by the egress gate.

## What each pipeline sends

- **A**: every element's text verbatim + the goal verbatim. This is what a naive "screenshot + DOM to the VLM" agent does.
- **B**: `detectPII` masks the spans it finds in each line; `sanitizeTaskGoal` scrubs the goal. Residual = PII the detector missed (bare / OCR-garbled / not-a-supported-category).
- **C**: adds the DOM field-type channel and the fusion risk model (whole sensitive elements are dropped, not just span-masked), then `assertNoSensitivePayload` walks the assembled payload and blocks/redacts anything that slipped through — a RESTRICTED category is a hard block.
