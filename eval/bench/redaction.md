# Redaction Benchmark (Phase 7)

**Corpus**: 9940 samples · 6835 gold PII spans · pad=0 · 2026-09-03

Scored against **ground-truth** spans: a missed span leaks 100%, an IoU-0.5 hit can leak ~50%. `leakageRate` is the headline privacy metric and only hits 0 when every PII span is found AND fully covered.

| Detector | Leakage rate ↓ | Fully redacted ↑ | Partial-leak spans ↓ | Over-redaction ↓ | char IoU ↑ | ms/sample |
|---|--:|--:|--:|--:|--:|--:|
| current (regex+checksum) | **14.4%** | 82.6% | 17.4% | 0.3% | 85.4% | 0.005 |
| naive regex (no checksum) | **66.0%** | 41.6% | 58.4% | 36.1% | 28.5% | 0.001 |
| baseline (pre-fix) | **66.7%** | 42.2% | 57.8% | 31.6% | 28.8% | 0.002 |

## Leakage by class — where the leaked characters come from

| Class | baseline (pre-fix) | current (regex+checksum) | naive regex (no checksum) |
|---|--:|--:|--:|
| A-contextual | 73.6% (chars=78178) | 6.3% (chars=78178) | 75.0% (chars=78178) |
| B-unlabelled | 56.8% (chars=12768) | 35.7% (chars=12768) | 56.9% (chars=12768) |
| ocr-garbled | 88.9% (chars=7118) | 85.3% (chars=7118) | 89.1% (chars=7118) |
| composite | 19.9% (chars=10450) | 1.5% (chars=10450) | 1.9% (chars=10450) |
| regression | 0.0% (chars=1140) | 1.7% (chars=1140) | 0.0% (chars=1140) |

## Post-verification (redaction-verify.mjs re-OCR gate — S4/11)

The verify pass re-scans the masked image at a paranoid threshold (PII ≥ 0.3, secrets ≥ 0.5), masks residual once more, and — if anything is *still* readable — **blocks egress** rather than send a partly-redacted image. Char-span model.

| Detector | Raw leakage | Verify best-effort¹ | Verify gated: in sent² | Verify gated: blocked³ |
|---|--:|--:|--:|--:|
| current (regex+checksum) | 14.4% | 7.3% | **0.0%** | 5.7% samples · 7.6% of gold chars |
| naive regex (no checksum) | 66.0% | 7.0% | **0.0%** | 5.6% samples · 7.2% of gold chars |
| baseline (pre-fix) | 66.7% | 7.0% | **0.0%** | 5.5% samples · 7.2% of gold chars |

¹ apply the verify masks but send the image anyway (no blocking).
² leakage among images that **were** sent — the gate blocked the rest.
³ share of samples / gold-PII-chars in images the gate refused to send (mostly `ocr-garbled` + un-shaped PII like names). This is the utility cost of the gate.

- **Leakage rate** — gold PII characters still visible after redaction. THE privacy number.
- **Over-redaction** — masked characters that were not PII (label text, surrounding words). A privacy/utility trade: pad increases coverage but also over-redaction.
- The overall leakage is dominated by `ocr-garbled` (a corrupted digit breaks the checksum) and `B-unlabelled` (bare shape-only IDs are deliberately not redacted). On `A-contextual` (labelled) PII and `composite` sentences it is an order of magnitude lower than the naive baseline.
- Detection precision/recall for the same detectors is in `results.md`; the pixel-space equivalent needs the screenshot corpus (Phase 8).
