# AUDIT.md — CONNOR / SIH26171

**Commit:** `78d05d8` · **Branch:** `working` · **Date:** 2026-09-02
**Env:** Node v24.16.0 · Python 3.12.7 (`.venv`) · Darwin 25.6.0
**Method:** static read of every non-vendored source file + ran both test suites
(`npm test` = 93 pass, `pytest tests/` = 31 pass *after the two import fixes below*)
and the two Python benchmarks.

This is Phase 1 (audit only). Two build-blocking errors were fixed to make the
suites runnable at all — noted as `[FIXED]`. Nothing else was changed.

---

## 0. Errors fixed to unblock the audit

| # | Error | File | Root cause | Fix applied |
|---|---|---|---|---|
| E1 | `SyntaxError` — file began `git u"""VLM adapters.` | `server/vlm.py:1` | stray paste of a shell command into the source | removed the `git u` prefix |
| E2 | `re.error: look-behind requires fixed-width pattern` — module could not be imported at all, so `pii_benchmark_unbiased.py`, `pii_benchmark.py`, and `tests/test_tier1_fastpath.py` were **all dead** | `server/tier1_fastpath.py:103,113` | two variable-width negative lookbehinds (`(?<!(?:order|ref|id|...)[:\s-]*)`, `(?<![vV](?:ersion)?\.?\s*)`); the module's `try: import regex` fallback to stdlib `re` then crashes on class-body compile | replaced both with a `neg_prefix` regex checked against the 24 chars before each match in `detect()`; behaviour verified (`SSN:` detected, `Order: 123-45-6789` and `v1.2.3.4` rejected) |

---

## 1. Component map

| Component | Implementation | Claimed behaviour | Reality / gap |
|---|---|---|---|
| **Manifest / MV3** | `client/manifest.json` (committed = Chrome build) + `manifest.chrome.json` / `manifest.firefox.json` + `scripts/build-manifest.mjs` | cross-browser MV3 | OK now. Was repeatedly breaking Chrome "Load unpacked" because `manifest.json` had been gitignored. |
| **Background / SW** | `client/background.js` (429 ln) | orchestrates capture → vision → egress → plan → execute; DLP-scrubs goal | Works. Egress sanitisation is **partial** — see §4. |
| **Content scripts** | `content.js`, `dlp-content-script.js`, `skeleton.js`, `executor.js`, `agent-bridge.js`, `dom-redactor.js` | build skeleton, execute actions, redact DOM text | `executor.js` now has typed-input normalisation + pre-DOM validation (recent). |
| **Vision pipeline** | `client/lib/vision-pipeline.mjs` (294 ln), `offscreen.js` (19 ln) | OCR + face + ViT fused, redact screenshot before egress | Runs 3 channels. **`timings.latencySavingsMs = 280` is hard-coded** (`vision-pipeline.mjs:193`), surfaced in the popup as a real saving. |
| **OCR** | Tesseract.js 5 via `vision-pipeline.mjs`; vendored by `scripts/fetch-vendor.mjs` | on-device OCR | Full core set now vendored. No OCR-quality benchmark exists. |
| **Face detection** | MediaPipe BlazeFace via `vision-pipeline.mjs` | redact faces | Best-effort; failures are swallowed to `faceError`. No recall measurement. |
| **Object/vision model** | `client/lib/vision-transformer.mjs` — YOLOS-tiny int8, Transformers.js + ORT, WebGPU→WASM | ViT detections join redaction | Only `person` is redacted. No benchmark of its contribution. |
| **DOM / A11y extraction** | `skeleton.js` | values reduced to empty/filled/readonly | Non-censored nodes keep `label`, `name`, `text` — see §4. |
| **DLP rules** | `client/lib/dlp-heuristics.mjs` (405 ln), `dlp-sanitizer.mjs` (345 ln) | scrub free-form goal | Covered by `tests/dlp-sanitizer.test.mjs`, `task-goal-sanitizer.test.mjs`. Semantic-preservation not asserted. |
| **PII detector (browser)** | `client/lib/pii-rules.mjs` (311 ln) | normalize → digit-run classify → context-gated regex | **The real detector.** Reasonably sophisticated. Numeric-run scanner treats dotted quads as Aadhaar candidates → IPv4 false-positive path (§3). |
| **PII detector (server)** | `server/tier1_fastpath.py` (296 ln) | "sub-10ms" regex + checksum | **Second, weaker implementation.** Diverges from `pii-rules.mjs`. Used by the Python benchmarks only. |
| **PII detector (JS tier-1)** | `client/lib/tier1-fastpath.mjs` (173 ln) | mirror of the Python one | **Third implementation.** Three detectors, no single source of truth. |
| **Redaction** | `client/lib/redact.mjs` (79 ln) | solid black boxes over regions + left-label zone | `leakScore()` only measures pixels **inside already-detected regions** — a missed PII region scores as zero leak. Misleading (§4, §7). |
| **Fusion / merge** | `client/lib/merge.mjs` (101 ln) | fuse DOM + vision channels | Plain **OR + max-confidence**. No privacy-risk score, no per-detection reason, no precision-aware combination. Phase 9 gap. |
| **VLM / server comms** | `client/lib/agent-client.mjs`, `server/main.py`, `server/vlm.py` | sanitized context in, validated actions out | Solid. No-mock-fallback + 503 + Retry added recently (`test_vlm_no_fallback.py`). |
| **Task planning** | `server/vlm.py` `_gemini`/`_openai`/`_mock` | model returns UI actions referencing categories/tokens | OK. `_mock` is deterministic from the skeleton. |
| **Agent execution** | `client/executor.js` + `agent-bridge.js` | resolve category→value locally, type it | OK. Loop guards in place. |
| **Telemetry / activity panel** | `client/popup.js` | per-step OCR/face/ViT ms, egress bytes, plan | Shows real per-step ms **except** the fabricated 280 ms saving. |
| **Benchmark infra (A)** | `benchmarks/run_bench.py` (947 ln) | "competitor analysis … apples-to-apples" | **Fabricated.** Competitor precision/recall/latency are hard-coded constants; `simulate_competitor()` draws TP/FN from `random.random() < recall_p`. Directly violates the brief. |
| **Benchmark infra (B)** | `eval/bench/` (`gen-corpus.mjs`, `run.mjs`, 3 detectors, `corpus.jsonl` 6100 lines) | seeded, span-level IoU, context-tagged recall | **This is the good one.** Labels come only from generation params. Reuse this. One flaw: generator imports `verhoeffValid`/`luhnValid` from the detector module (§2). |
| **Benchmark infra (C)** | `scripts/pii_benchmark_unbiased.py` (508 ln) | independent adversarial corpus + real Presidio/spaCy/Flair | **Honest structure.** Real competitor calls that degrade to `UNAVAILABLE: <reason>` when the package is absent. Was 100% dead until E2 fixed. Small corpus (~78 gold spans); category-set scoring, not span-level. Checksum helpers are a re-derivation of the same algorithm, not a truly independent oracle. |
| **Benchmark infra (D)** | `scripts/pii_benchmark.py` (339 ln) | — | Older variant; overlaps (B)/(C). Candidate for deletion. |
| **Tests** | `tests/*.test.mjs` (17 files, 93 cases), `tests/test_*.py` (2 files, 31 cases) | unit coverage of shared logic | Good breadth. No regression tests for the IPv4/Aadhaar interaction, no egress-gate test, no redaction-leak test. |
| **Mock VLM** | `server/vlm.py::_mock` | offline deterministic agent | Deterministic. `benchmarks/run_bench.py::bench_mock_adapter` reports `tokenized_fill_correct` as a single bool derived from one 10-step sim — brittle, not a task-success-rate. |
| **Competitor comparison code** | `benchmarks/run_bench.py`, `benchmarks/results/references.md` | — | `references.md` states outright: "implemented as reproducible statistical simulations". This is the single biggest liability under an adversarial judge. |
| **Repo hygiene** | `_detect_runner.mjs` + `benchmarks/_detect_runner.mjs` committed | — | Generated runner files checked in; `benchmarks/results/*.json` snapshots checked in. |

---

## 2. Severity table

| Severity | Issue | File | Root cause | Fix |
|---|---|---|---|---|
| **Critical** | Competitor benchmark is fabricated: hard-coded `recall_by_cat`, `fp_rate`, `p50_ms`, `p99_ms`; `simulate_competitor()` generates outcomes with an RNG. Output is written to `benchmarks/results/*.json` and printed as a comparison table. | `benchmarks/run_bench.py:436-549`, `benchmarks/results/references.md` | someone wanted a comparison table without running the competitors | Delete `simulate_competitor` + `COMPETITORS`. Build the real framework on `scripts/pii_benchmark_unbiased.py` (Presidio/spaCy/Flair already wired) + `eval/bench/run.mjs`. Commercial APIs → `NOT EXECUTED` unless credentials present. (Phase 13) |
| **Critical** | Benchmark ground truth shares its checksum implementation with the detector under test. `gen-corpus.mjs` imports `verhoeffValid`, `luhnValid` from `client/lib/pii-rules.mjs`. If the detector's Verhoeff is subtly wrong, the corpus inherits the identical bug and the benchmark can't see it. | `eval/bench/gen-corpus.mjs:26,71,105` | convenience import | Write an independent Aadhaar/Luhn validator (different algorithm structure or a vetted third-party), generate by brute-forcing the check digit 0–9, accept only numbers the independent validator passes. Add tests: valid→pass, 1-digit mutation→fail, generated positives→detected. (Phase 2) |
| **Critical** | Three divergent PII detectors with no shared source of truth: `client/lib/pii-rules.mjs` (browser, sophisticated), `server/tier1_fastpath.py` (weaker), `client/lib/tier1-fastpath.mjs` (mirror). The Python benchmarks measure the *Python* detector; the browser ships the *JS* one. Reported numbers may not describe what runs. | `pii-rules.mjs`, `server/tier1_fastpath.py`, `client/lib/tier1-fastpath.mjs` | parallel evolution across client/server | Pick `pii-rules.mjs` as canonical. Either compile/port it once and have the server call the same logic, or delete the server detector and route all benchmarking through `eval/bench/run.mjs`. Every headline number must name which detector produced it. |
| **High** | IPv4 → Aadhaar false-positive path. `scanNumericRuns` regex `/(?<!\d)(\d(?:[ \-.]{0,3}\d){5,23})(?!\d)/g` accepts `.` as an internal separator, so `164.154.182.151` becomes the 12-digit candidate `164154182151` and is checksum-tested for Aadhaar; if Verhoeff passes it wins the overlap over the (lower-confidence) `ipv4` rule. | `client/lib/pii-rules.mjs:210,227` | dotted quads not excluded before numeric-PII classification | Run the `ipv4` rule first and subtract its spans from the numeric-run input; or reject a digit run whose original text matches the dotted-quad shape; or make overlap resolution privacy-aware (a valid IPv4 span suppresses an Aadhaar span it contains). Add the regression `IP address 164.154.182.151 server host` → no aadhaar. (Phase 3) |
| **High** | No egress privacy gate. Non-censored skeleton nodes are sent with `label`, `name`, `text` intact (`{...node}`); only `isCensored` nodes get `label:""`. A visible non-sensitive-classified field or static text containing a name/number goes to the server unredacted. There is no `assertNoSensitivePayload()` before `fetch`. | `client/background.js:233-237, 276-283` | sanitisation keyed on `isCensored` only | Add a gate: run `detectPII` (+ name heuristics) over the serialized outbound payload (skeleton text + goal); on any hit above threshold, block or redact and log metadata only. (Phase 10) |
| **High** | Redaction leak metric is blind to misses. `redact.mjs::leakScore` only inspects pixels **within `regions`** (the regions that were detected). PII the detector missed contributes 0 to the leak score, so a pipeline that misses 30 % of PII can still report ~0 leakage. | `client/lib/redact.mjs:62-77` | metric measures "did we paint what we found", not "is PII still visible" | Redaction benchmark must score against **ground-truth** PII boxes, not predicted ones: leakage = GT PII pixels still visible after redaction. (Phase 7) |
| **High** | Fabricated 280 ms latency saving. `vision-pipeline.mjs:193` sets `timings.latencySavingsMs = 280` unconditionally on the A11y fast-path; `popup.js:255` shows it as "saved ~280 ms". Not measured. | `client/lib/vision-pipeline.mjs:193`, `client/popup.js:255` | placeholder never replaced | Measure fast-path vs full-vision on the same page (warm), or label the figure `estimated` and stop showing a per-step number. (Phase 12) |
| **High** | Benchmark recall mixes contextual and bare positives. `gen-corpus.mjs` emits ~78 % keyworded / ~22 % bare and the detector *intentionally* drops bare shape-only IDs (voter-id, passport, DOB, SSN). Aggregate recall therefore blends "can detect labelled PII" with "chose not to detect unlabelled PII". `run.mjs` does tag recall-by-context, but the headline F1 is still blended. | `eval/bench/gen-corpus.mjs:281`, `eval/bench/run.mjs:149` | one corpus, one headline number | Split reporting into explicit categories A (contextual), B (unlabelled), C (structured/valid), D (adversarial non-PII) and report each separately. Never average B into A. (Phase 4) |
| **Medium** | `benchmarks/run_bench.py::rand_aadhaar` derives the check digit with a hand-written expression (`check = [x for x in range(10) if D[D[c][P[len(digits)%8][x]]][P[(len(digits)+1)%8][0]] == 0]`) and does **not** verify the result. Suspect and unverified. | `benchmarks/run_bench.py:75-93` | hand-derived Verhoeff | Same fix as Phase 2; or delete this generator in favour of the `eval/bench` one. |
| **Medium** | Mock-VLM "tokenized fill correctness" is a single boolean from one simulated 10-step loop; `benchmarks/run_bench.py` prints it as PASS/FAIL. Not a task-success rate, and the brief explicitly says don't hard-code success/failure. | `benchmarks/run_bench.py:669-702` | shortcut | Build deterministic mock tasks with ground truth (find button, locate field, complete without seeing PII) and report an actual rate. (Phase 16) |
| **Medium** | Fusion is a blind OR. `merge.mjs` unions DOM + vision and takes `max(confidence)`; no privacy-risk score, no per-detection `{sources, reason, privacyRisk, redact}`. | `client/lib/merge.mjs:45-85` | initial version never revisited | Documented fusion: combine signals into a risk score, record provenance + reason per final detection. (Phase 9) |
| **Medium** | `pii_benchmark_unbiased.py` corpus is tiny (~78 gold spans) and scores at **category-set-per-sample** granularity, not span-level. Over-redaction of ambiguous IDs is invisible at this granularity. | `scripts/pii_benchmark_unbiased.py:270-297` | quick script | Scale to ≥100k via deterministic generation, score span-level, seed `20260902`. (Phases 4–6) |
| **Medium** | `server/tier1_fastpath.py` per-category precision is poor on the honest run just executed: `pan` 55 %, `voter-id` 36 %, `dob` 55 %, `ssn` 50 %, `ifsc` 62 %, `phone-in` 60 %. `upi-vpa` recall 40 %. These are real and currently unreported anywhere user-facing. | `server/tier1_fastpath.py:85-180` | shape-only regexes with no context gating (unlike `pii-rules.mjs`) | If this detector stays, port the context-gating from `pii-rules.mjs`. Otherwise retire it. |
| **Medium** | No Unicode/OCR "raw vs normalized" split. `pii-rules.mjs::normalize` folds Unicode digits, dashes, zero-width, full-width **before** detection. The benchmark then reports one number and implicitly credits the detector for handling inputs the preprocessor actually fixed. | `client/lib/pii-rules.mjs:97-121` | normalization is inside `detectPII` | Report detector-on-raw vs detector-on-normalized separately; document preprocessing as its own stage. (Phase 6) |
| **Medium** | No reproducibility metadata in any benchmark output. `eval/bench/results.json` has `generatedAt` + `corpusSize` only; `benchmarks/results/*.json` has partial `meta`. No git commit, OS, CPU, model versions, seed echoed. | `eval/bench/run.mjs:162`, `benchmarks/run_bench.py:918` | — | Emit a full `meta` block + `benchmark-results.json` + `BENCHMARK_REPORT.md`. (Phase 18) |
| **Medium** | Screenshot / vision-PII benchmark does not exist. `eval/eval.html` is a manual in-browser harness; there is no labelled screenshot corpus with PII bounding boxes, no visual-PII precision/recall/IoU. SIH metric 1 (25 %) and metric 3 (20 %) are therefore unmeasured. | (absent) | scope | Build a screenshot corpus with GT boxes; measure visual recall/precision, bbox IoU, redaction IoU, leakage. (Phase 8) |
| **Medium** | `invoke_tier2_vlm` returns fabricated bounding boxes when no API key: `"boundingBoxes": [{"x":10,"y":20,"width":100,"height":30,"label":"face"}]` with `"status":"simulated"`. If any benchmark consumes this path it ingests fake detections. | `server/tier1_fastpath.py:230-237` | offline placeholder | Return an explicit unavailable/error, never a plausible-looking fake box. |
| **Low** | Generated runner files committed: `_detect_runner.mjs`, `benchmarks/_detect_runner.mjs`. `benchmarks/run_bench.py::_write_detect_script` rewrites the root one on every run. | repo root, `benchmarks/` | — | gitignore + generate to a temp dir. |
| **Low** | `find_node()` hard-codes a Nix store path `/nix/store/k3nz3s314bipvqbcbw3faq823hxpwbn1-nodejs-slim-24.19.0/bin/node`. | `benchmarks/run_bench.py:377` | copied from a Nix shell | use `shutil.which("node")`. |
| **Low** | `README.md` architecture diagram still describes **tokenization** (`[AADHAAR_1]`, "token→category", "token-ised skeleton") but `server/vlm.py` docstring and `/privacy` say **"No tokenization"**. Contradictory. | `README.md:6-33` vs `server/vlm.py:12`, `server/main.py:51` | design changed, README not updated | reconcile — pick one description of what leaves the browser. |
| **Low** | `benchmarks/run_bench.py` docstring promises `--json` "machine-readable output" and competitor comparison; both are built on simulated data, so the JSON is not a trustworthy artifact. | `benchmarks/run_bench.py:1-33` | — | rewrite alongside Phase 13. |
| **Low** | `eval/agent-eval.mjs` and `benchmarks/run_bench.py` use different demo profiles / seeds (`random.seed(42)` vs `20260830` vs none). | multiple | — | standardise on seed `20260902`. |
| **Low** | `dob` regex in all three detectors accepts `mm/dd/yyyy` and `dd/mm/yyyy` and any `19xx|20xx`; combined with low base confidence and broad negative context this is the largest FP source (`dob` precision 55 % on the honest run). | `pii-rules.mjs:177`, `tier1_fastpath.py:176` | ambiguous format | tighten or require context; measure separately as category A vs D. |

---

## 3. What is actually solid (keep, build on)

- **`client/lib/pii-rules.mjs`** — Unicode normalization with an offset map back to the original string, digit-run classification (length + checksum + IIN) instead of separator-specific regexes, context gating with positive **and** negative keyword windows, confidence thresholding, overlap resolution. This is a legitimately good detector core.
- **`eval/bench/`** — seeded generator, span-level IoU scoring, recall-by-context tags, hard negatives with misleading keywords, an explicit "aadhaar-substring regression" class. Labels never come from a detector. This is the benchmark to extend for Phases 2–6.
- **`scripts/pii_benchmark_unbiased.py`** — real Presidio/spaCy/Flair integration that fails safe to `UNAVAILABLE: <reason>`. This is the skeleton for Phase 13.
- **Privacy architecture** — screenshot redaction happens in the offscreen document before the background worker sees it; skeleton values are reduced to empty/filled; the goal is DLP-scrubbed; server actions are validated against known element ids; no-mock-fallback + 503. The *architecture* is defensible; the *measurement* of it is not yet.
- **Test breadth** — 124 passing unit tests across DLP, tokenizer, field classifier, merge, adversarial guard, cross-browser, executor.

---

## 4. Privacy / egress findings (detail)

Places data leaves the browser (`client/background.js`):

1. `requestStep(cfg.serverUrl, payload)` → `POST /agent/step`. Payload = `{ taskGoal (scrubbed), skeleton (partially sanitized), screenshot (redacted), history }`.
2. `chrome.runtime.sendMessage({action:"PL_PROGRESS", evt})` to the popup — includes `payloadPreview`, `rawImage`, `redactedImage`. Local only (extension messaging) but the raw screenshot crosses the SW↔popup boundary.
3. `console.warn`/`console.info` in `vision-transformer.mjs`, `background.js` — none log PII values today, but there is no lint rule preventing it.

Gaps:

- **Skeleton, non-censored nodes:** `{...node}` passes `label`, `name`, `text`, `options`, `piiCategory`. `skeleton.js` needs review for whether any of these can carry a rendered PII value (e.g. a read-only "Account holder: <name>" field, an order-summary line item).
- **No `assertNoSensitivePayload()`** before the `fetch`. The brief (Phase 10) wants this as an automated gate with a test: raw-PII payload → blocked, sanitized → allowed.
- **Screenshot redaction is detection-bounded.** If OCR + DOM + ViT + face all miss a PII region (stylised text, PII inside a raster image, a signature), it ships. `leakScore` won't catch it because it only looks inside detected regions.
- **`history` (last 8 steps)** is sent back each step. `sanitizeAction()` is applied on push — verify it strips `literalValue`.

---

## 5. Recommended execution order (Phases 2–20)

The brief's order is right. Concretely, against this repo:

1. **Phase 2 — Aadhaar/structured ground truth.** New `eval/bench/lib/independent-validators.mjs` (no import from `client/`). Rewrite `validAadhaar`, `validCard`, `validSSN`, etc. to generate-then-verify with the independent validator. Tests in `tests/gen-corpus-groundtruth.test.mjs`.
2. **Phase 3 — IPv4/numeric-run fix** in `pii-rules.mjs` (+ port to the other two detectors or retire them). Regression tests.
3. **Phase 4 — split the corpus** into A/B/C/D, one JSONL per class, `run.mjs` reports each separately; kill the single blended headline F1.
4. **Phase 5–6 — scale to 100k**, seed `20260902`, add Unicode/OCR variation axes, report raw-vs-normalized. Persist `dataset-manifest.json`.
5. **Phase 7 — redaction benchmark** scoring against GT boxes (leakage, IoU, over/under-redaction). Needs Phase 8's corpus.
6. **Phase 8 — screenshot corpus** with GT bounding boxes (can start from the `fixtures/` pages rendered headless).
7. **Phase 9 — fusion rewrite** in `merge.mjs` with a documented risk model + provenance records.
8. **Phase 10 — egress gate** + tests.
9. **Phase 11 — task-goal semantic-preservation tests** on the existing sanitizer.
10. **Phase 12 — real latency harness**; delete the 280 ms constant.
11. **Phase 13 — competitor framework** on `pii_benchmark_unbiased.py`; commercial APIs gated on credentials, else `NOT EXECUTED`. **Delete `benchmarks/run_bench.py`'s `simulate_competitor`.**
12. **Phases 14–18 — the deliverable docs** (`COMPETITOR_BENCHMARK.md`, `SIH_SCORECARD.md`, `BENCHMARK_REPORT.md`, `benchmark-results.json`) generated from real runs, with `NOT MEASURED` where honest.
13. **Phase 19 — regression suite** consolidation.

**Biggest single risk to defensibility:** `benchmarks/run_bench.py` + `benchmarks/results/references.md`. Under an adversarial judge, "reproducible statistical simulations" of competitors reads as fabricated results. This should be removed or rebuilt before anything else user-facing is presented.

---

## 6. Test / benchmark status at audit time

| Suite | Result |
|---|---|
| `npm test` | 93 pass / 0 fail |
| `pytest tests/` | 31 pass / 0 fail (was: collection error, dead — fixed by E2) |
| `scripts/pii_benchmark_unbiased.py` | runs; PL(py) P=71% R=91% F1=79.8% on ~78 gold spans; Presidio/spaCy/Flair = UNAVAILABLE (not installed) |
| `benchmarks/run_bench.py` | runs but output is partly simulated — **do not cite** |
| `eval/bench/run.mjs` | not re-run this pass; `results.json` on disk is from a prior corpus |
