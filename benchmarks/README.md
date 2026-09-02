# benchmarks/

The fabricated competitor benchmark that used to live here (`run_bench.py`,
`results/bench_*.json`) has been **removed**. It hard-coded competitor
precision/recall/latency and generated per-sample outcomes with an RNG
(`simulate_competitor`). Nothing in it was a real measurement of a competitor.

## Real benchmarks

| What | Where | Status |
|---|---|---|
| PII detection — span-level, seeded, context-tagged | `eval/bench/` (`gen-corpus.mjs` → `run.mjs`) | active |
| Independent ground-truth generators + validators | `eval/bench/lib/independent-validators.mjs` | active (Phase 2) |
| Adversarial corpus + open-source competitors (Presidio / spaCy / Flair) | `scripts/pii_benchmark_unbiased.py` | active; competitors run only if the package is installed, else `UNAVAILABLE` |
| Node bridge so Python can call the real detector | `eval/bench/detect-cli.mjs` | active |

## The one detector

`client/lib/pii-rules.mjs` is the only Privacy Lens PII detector. The browser
ships it; every benchmark reaches it through `eval/bench/detectors/current.mjs`
(directly, or via `detect-cli.mjs` from Python). The old `server/tier1_fastpath.py`
and `client/lib/tier1-fastpath.mjs` re-implementations have been deleted.

## Commercial APIs

AWS Comprehend, Google Cloud DLP, Azure PII: **NOT EXECUTED** — no credentials
in this environment. See `results/references.md` for what the vendors document.
Any future run must call the real API on the same labelled dataset and record
actual numbers; documented capabilities are never written as benchmark results.

## Run

```bash
node eval/bench/gen-corpus.mjs --seed 20260902   # (re)generate the corpus
node eval/bench/run.mjs                          # score every detector
python3 scripts/pii_benchmark_unbiased.py        # + open-source competitors
```
