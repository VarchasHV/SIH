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
| `client/` | MV3 extension (**Chrome/Chromium only** — see limitations). Plain JS, no bundler. |
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

1. `chrome://extensions` → Developer mode → **Load unpacked** → select `client/`.
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
- **`mock`** — deterministic, offline, instant. Best for latency demos and the
  automatic fallback when a real model errors.

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

## Evaluation (maps to the 5 SIH metrics)

| # | Metric | Where |
|---|---|---|
| 1 | Visual-context accuracy (25%) | `eval.html` — structure recall; extension fuses OCR + screenshot on top |
| 2 | PII detection precision/recall (20%) | `npm run eval` — field classifier + value regex, with a labelled corpus |
| 3 | Redaction precision (20%) | `eval.html` — pixel IoU / leak score (`redact.mjs` `leakScore`) |
| 4 | Client resource use (20%) | extension Activity panel — per-step OCR/face/redact ms, heap, WebGPU adapter |
| 5 | End-to-end latency (15%) | extension Activity panel — capture → vision → network → execute |

Run `node scripts/serve.mjs . 4173` then open `http://localhost:4173/eval/eval.html`.

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
- The `mock` agent is deterministic and makes the pipeline run offline; it's also
  the automatic fallback when a real VLM errors.
- **Firefox: not supported yet.** The extension is Chrome/Chromium-only — it uses
  `chrome.offscreen` and `chrome.runtime.getContexts`, neither of which Firefox
  implements, and there is no `webextension-polyfill` or
  `browser_specific_settings.gecko` key. A Firefox path needs the offscreen
  document replaced with a background/worker equivalent.
