# Redaction Benchmark (Phase 7)

**Corpus**: 8500 samples · 6037 gold PII spans · pad=0 · 2026-09-03

Scored against **ground-truth** spans: a missed span leaks 100%, an IoU-0.5 hit can leak ~50%. `leakageRate` is the headline privacy metric and only hits 0 when every PII span is found AND fully covered.

| Detector | Leakage rate ↓ | Fully redacted ↑ | Partial-leak spans ↓ | Over-redaction ↓ | char IoU ↑ | ms/sample |
|---|--:|--:|--:|--:|--:|--:|
| current (regex+checksum) | **14.7%** | 82.4% | 17.6% | 0.3% | 85.0% | 0.005 |

## Leakage by class — where the leaked characters come from

| Class | current (regex+checksum) |
|---|--:|
| A-contextual | 6.0% (chars=57833) |
| B-unlabelled | 36.8% (chars=7073) |
| ocr-garbled | 85.4% (chars=7131) |
| composite | 1.0% (chars=10448) |
| regression | 1.7% (chars=1140) |

## Post-verification (redaction-verify.mjs re-OCR gate — S4/11)

The verify pass re-scans the masked image at a paranoid threshold (PII ≥ 0.3, secrets ≥ 0.5), masks residual once more, and — if anything is *still* readable — **blocks egress** rather than send a partly-redacted image. Char-span model.

| Detector | Raw leakage | Verify best-effort¹ | Verify gated: in sent² | Verify gated: blocked³ |
|---|--:|--:|--:|--:|
| current (regex+checksum) | 14.7% | 9.3% | **0.0%** | 6.5% samples · 9.6% of gold chars |

¹ apply the verify masks but send the image anyway (no blocking).
² leakage among images that **were** sent — the gate blocked the rest.
³ share of samples / gold-PII-chars in images the gate refused to send (mostly `ocr-garbled` + un-shaped PII like names). This is the utility cost of the gate.

- **Leakage rate** — gold PII characters still visible after redaction. THE privacy number.
- **Over-redaction** — masked characters that were not PII (label text, surrounding words). A privacy/utility trade: pad increases coverage but also over-redaction.
- The overall leakage is dominated by `ocr-garbled` (a corrupted digit breaks the checksum) and `B-unlabelled` (bare shape-only IDs are deliberately not redacted). On `A-contextual` (labelled) PII and `composite` sentences it is an order of magnitude lower than the naive baseline.
- Detection precision/recall for the same detectors is in `results.md`; the pixel-space equivalent needs the screenshot corpus (Phase 8).
