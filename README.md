# Privacy Lens — On-Device Vision Agent

**SIH26171 · On-device Visual Perception for Light-weight Browser Agents**

A browser extension + server that lets a cloud/served VLM drive form-filling on any
page **without ever seeing the user's personal data**. The client reads the screen
with on-device vision (OCR + face detection) and a DOM classifier, redacts every
PII region locally, tokenises the rest, and sends only a blurred screenshot + a
token-ised page structure to the server. The server returns UI actions that
reference *tokens*; the client resolves them to real values locally, at the last
moment, and types them in.

```
┌───────────────────────── BROWSER — real PII never leaves here ─────────────────────────┐
│ content + agent-bridge     skeleton (values → empty/filled) · DOM PII boxes · vault    │
│        │                   (profile values → [AADHAAR_1] …, stored in chrome.storage)  │
│        │  captureVisibleTab → raw screenshot                                            │
│        ▼                                                                               │
│ offscreen document         Tesseract OCR + BlazeFace  →  PII regions                   │
│  (WebGPU/WASM)             merge(DOM ∪ vision)  →  redact screenshot (blur/pixelate)    │
│        │                                                                               │
│        ▼                                                                               │
│ background (service worker)  build sanitized payload · show egress preview in popup    │
│        │                                                                               │
└────────┼──────────────────────────────────────────────────────────────────────────────┘
         │  POST /agent/step   { redacted screenshot, token-ised skeleton, token→category }
         ▼
┌──────────────── SERVER ────────────────┐
│ FastAPI + VLM (Qwen2.5-VL / Llama-3.2- │   returns  [{action:"type", targetId:"el-4",
│ Vision, or the offline `mock` agent)   │            valueToken:"[AADHAAR_1]"}, …]
└────────────────────────────────────────┘
         │
         ▼  client validates → resolves [AADHAAR_1] → real value locally → executor types it
```

## Layout

| Path | What |
|---|---|
| `client/` | Cross-browser MV3 extension (**Google Chrome** and **Mozilla Firefox**). Plain JS, no bundler. |
| `client/lib/*.mjs` | Shared logic: `pii-rules` (regex + Verhoeff/Luhn), `tokenizer` (vault), `redact` (canvas), `merge`, `field-classifier`, `agent-client`. |
| `client/offscreen.*` | On-device OCR + face detection + redaction. |
| `server/` | FastAPI agent. `VLM_MODE=gemini` (default), `openai` (any OpenAI-compatible VLM), or `mock` (offline). |
| `fixtures/` | 4 demo forms: job application, checkout, KYC, and a hostile form (obfuscated names / no labels). |
| `eval/` | Metric harness (`run_eval.mjs` headless + `eval.html` in-browser). |
| `tests/` | `node --test` unit tests for the shared logic. |

## Setup

```bash
npm run fetch:vendor     # download Tesseract.js + MediaPipe into client/vendor/  (~40 MB, once)
npm run server:install   # pip install FastAPI etc. (use a venv)
npm test                 # unit tests for the shared logic
npm run eval             # headless metric report
```

### Run the demo

```bash
cp server/.env.example server/.env   # set GEMINI_API_KEY (default VLM_MODE=gemini, model gemini-3.6-flash)
npm run server                       # http://localhost:8000
npm run fixtures                     # http://localhost:4173  (the demo forms)
```

1. Load the extension:
   - **Chrome:** `chrome://extensions` → Developer mode → **Load unpacked** →
     select `client/`. `client/manifest.json` is committed as the Chrome build,
     so this works with no build step. (If you previously switched to Firefox,
     run `npm run manifest:chrome` to switch back.)
   - **Firefox:** `npm run manifest:firefox`, then `about:debugging#/runtime/this-firefox`
     → **Load Temporary Add-on** → select `client/manifest.json`.

   Chrome and Firefox need different `background` architectures (`service_worker` vs
   `scripts`), so `client/manifest.json` is copied from `client/manifest.chrome.json`
   or `client/manifest.firefox.json` by `scripts/build-manifest.mjs`. Edit the two
   source manifests, not `client/manifest.json`.
2. Open the extension popup → **Profile** tab → fill in some values → **Save profile**
   (they go to `chrome.storage.local` only).
3. Open a fixture (e.g. `http://localhost:4173/kyc.html`).
4. Popup → **Assist** tab → pick a preset or type a goal → **Start agent**.
5. Watch the **Activity** tab: per-step you see the *exact* redacted screenshot +
   JSON leaving the machine, the server's plan, and each action being executed on
   the page (redacted regions flash red, targeted fields flash green).

### VLM options

- **`gemini`** (default) — Google Gemini via `GEMINI_API_KEY`. The redacted
  screenshot is sent as inline image data, so the model uses real visual context.
  Default model `gemini-3.6-flash` (`gemini-2.5-flash` is blocked for new API
  keys as of 2026; `2.5-pro` / `3.5-flash` also work). ~3–30 s/step.
- **`openai`** — any OpenAI-compatible endpoint (`VLM_BASE_URL` + `VLM_API_KEY` +
  `VLM_MODEL`): OpenRouter `qwen/qwen-2.5-vl-7b-instruct`, or local vLLM / Ollama
  `llama3.2-vision`. The "offline-deployable open-weights" path the brief asks for.
- **`mock`** — deterministic, offline, instant. An **explicit** offline demo mode
  (`VLM_MODE=mock`) for latency work — never an automatic fallback. If the
  configured model fails, `/agent/step` returns **HTTP 503**, the agent stops,
  and the popup shows "AI unavailable" with a **Retry** button. It does not
  silently degrade to a heuristic agent that keeps acting on a live page.

## Privacy model

- **The vault** (real profile values) lives only in the page's content-script world
  and `chrome.storage.local`. The background worker, the offscreen document, and
  the network only ever handle `[CATEGORY_N]` tokens + redacted pixels.
- **The screenshot** is redacted in the offscreen document *before* it reaches the
  background worker — OCR'd PII spans, detected faces, and every DOM PII field
  bbox (blur / pixelate; blackout for passwords & card numbers).
- **The skeleton** reports field values only as `empty` / `filled` / `readonly`.
- The server is told the scheme (`GET /privacy`) and instructed never to request a
  real value; every returned action is validated against the known element ids and
  tokens before the executor runs it.
- **Egress preview**: the popup shows the byte-for-byte payload each step; the
  headless eval asserts no profile value ever appears in it.

## Benchmark Results

Full detail + reproduction commands in **[`BENCHMARK_REPORT.md`](BENCHMARK_REPORT.md)**,
**[`SIH_SCORECARD.md`](SIH_SCORECARD.md)**, **[`COMPETITOR_BENCHMARK.md`](COMPETITOR_BENCHMARK.md)**,
machine-readable **[`benchmark-results.json`](benchmark-results.json)**. Audit of the
prior state in [`AUDIT.md`](AUDIT.md).

```bash
npm run bench                                       # detection (span-level, A/B/C/D classes)
npm run bench:redaction                             # redaction leakage vs ground truth
npm run bench:latency                               # detector latency percentiles + env
npm run bench:screens                               # screen fusion/redaction geometry
node eval/experiments/privacy-egress.mjs            # raw PII bytes to server (A vs B vs C)
npm run bench:competitors                           # Presidio / spaCy (if installed)
node scripts/aggregate-benchmarks.mjs               # -> benchmark-results.json + BENCHMARK_REPORT.md
```

**MEASURED** (commit `78d05d8`, Apple M3 / Node v24, seed `20260902`):

| What | Result |
|---|---|
| PII detection (span-level, 8.5k adversarial corpus) | **P 99.2% · R 84.1% · F1 91.0%** |
| — by class | A-contextual 93.8% · B-unlabelled 57.1% · **D adversarial-neg 0.8% FP** |
| — Unicode (Arabic/Persian/Devanagari/fullwidth) | ~90% recall (0% without normalization) |
| Redaction leakage vs ground-truth spans | **14.7%** overall · 6.0% on labelled PII · 1.0% composite |
| Detector latency (warm, 25.5k samples) | p50 **2.5µs** · p95 7.1µs · p99 10.5µs · cold ~0.9ms |
| Screen fusion (geometry, perfect-OCR ceiling) | visual recall 78.9% · precision 100% · bbox IoU 90.9% |
| Privacy experiment — raw PII bytes to server | A **3794** → B 960 → C **535** (85.9% reduction); task-goal PII → **0** |
| Competitors, same corpus (2.5k, category-set) | Presidio F1 **39.4%** · spaCy F1 **9.8%** |

**NOT MEASURED** (need a real browser / live VLM / cloud credentials): end-to-end
latency, OCR/ViT/face stage latency, pixel-space redaction leakage, the agent
action-correctness harness (`eval/agent-eval.mjs`, needs a server), and AWS
Comprehend / Google Cloud DLP / Azure PII. These are marked `NOT MEASURED` in
the scorecard — not estimated.

The old `eval.html` in-browser harness and `npm run eval` still exist for
manual checks; `node scripts/serve.mjs . 4173` then open `/eval/eval.html`.

## Status / limitations

- On-device vision runs **three** channels in the offscreen document:
  1. **Vision Transformer** — YOLOS-tiny (`YolosForObjectDetection`, ViT/DETR
     family, int8, 9.4 MB) via Transformers.js + ONNX Runtime Web,
     **WebGPU with WASM(SIMD) fallback** (`client/lib/vision-transformer.mjs`).
     Its `person` detections join the redaction merge (a face detector misses a
     torso; the ViT doesn't); its full COCO label set is the "what is on screen"
     signal. The backend that actually ran is reported in the popup.
  2. **Tesseract OCR** (WASM) — reads on-screen text; PII values found in it are
     redacted, and captions **name fields the DOM can't**
     (`client/lib/label-assoc.mjs`, folded back into the skeleton).
  3. **BlazeFace** (MediaPipe, WASM) — faces.
  All model weights are vendored; inference makes no network call.
- The field classifier does three passes: exact (`type`/`autocomplete`/`name`/
  `<label>`), fuzzy (letters-only substring match for obfuscated names like
  `02frstname`, `24emailadr`), and spatial (caption in a sibling grid/table cell).
  `hostile-form.html` mirrors the RoboForm test page and scores 16/16.
- Still weak: `<select>` triples sharing one caption (mm/dd/yy), Shadow DOM.
- The `mock` agent is deterministic and makes the pipeline run offline. It is
  opt-in only (`VLM_MODE=mock`) — a real-model failure stops the agent (HTTP 503
  + Retry), it is never swapped in automatically mid-run.
- **Cross-Browser Support (Chrome & Firefox)**: Fully compatible with both Google Chrome (using `chrome.offscreen` + WebGPU/WASM) and Mozilla Firefox (using native background vision dispatcher + Gecko MV3 manifest). Each browser gets its own source manifest (`manifest.chrome.json` / `manifest.firefox.json`); run `npm run manifest:firefox` then load temporarily via `about:debugging#/runtime/this-firefox` -> **Load Temporary Add-on** -> select `client/manifest.json`.
- **Adversarial Guard & Threat Model**: `client/lib/adversarial-guard.mjs` provides an on-device first-line heuristic defense against prompt injections, leetspeak variants (`1gn0re`), zero-width Unicode steganography (`\u200B`), hidden styles, and attribute injections (`alt`/`aria-label`/`title`). *Known Limitation*: As a heuristic regex layer, it catches known attack signatures and obfuscations, but is not a full semantic NLP classifier for arbitrary open-ended paraphrases. It operates in defense-in-depth alongside structural DLP tokenization, zero-PII skeleton filtering, and human-in-the-loop gates.

