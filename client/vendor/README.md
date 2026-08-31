# client/vendor/

On-device ML assets, shipped inside the extension because Manifest V3 forbids
loading remote code — and because the demo must run with no network except the
`/agent/step` call. Populate with:

```
npm run fetch:vendor
```

## Vision Transformer (the client-side vision model)

| File | Purpose |
|---|---|
| `transformers.min.js` | Transformers.js 3.0.2 (ESM) — runs the ViT |
| `ort-wasm-simd-threaded.jsep.wasm` | ONNX Runtime Web **JSEP** binary — one file serving **both** the WebGPU and the WASM(SIMD) execution providers. Transformers.js otherwise fetches this from a jsdelivr CDN at runtime, which MV3 disallows; `client/lib/vision-transformer.mjs` overrides `env.backends.onnx.wasm.wasmPaths` to point here. |
| `models/Xenova/yolos-tiny/config.json` | `YolosForObjectDetection` — a ViT/DETR-family detector, 91 COCO classes |
| `models/Xenova/yolos-tiny/preprocessor_config.json` | image preprocessing |
| `models/Xenova/yolos-tiny/onnx/model_q8.onnx` | int8-quantised weights, **9.4 MB**. Saved as `model_q8.onnx` because Transformers.js v3 resolves `dtype: "q8"` to that name, while the HF repo still publishes the v2 name `model_quantized.onnx`. |

`vision-transformer.mjs` tries **WebGPU first and falls back to WASM(SIMD)**, and
reports which backend actually ran (surfaced in the popup and in the eval output).
Model weights are local — `env.allowRemoteModels = false` — so inference never
touches the network.

## OCR + face detection

| File | Purpose |
|---|---|
| `tesseract.min.js`, `tesseract-worker.min.js`, `tesseract-core-simd.wasm(.js)` | Tesseract.js 5 LSTM OCR engine (WASM/CPU) |
| `eng.traineddata.gz` | Tesseract English model |
| `tasks-vision.mjs`, `mp-wasm/*` | MediaPipe Tasks-Vision runtime |
| `blaze_face_short_range.tflite` | BlazeFace face detector (~230 KB) |

Everything here is `.gitignore`d except this README.
