# client/vendor/

On-device ML libraries, shipped inside the extension because Manifest V3 forbids
loading remote code. Populate this folder with:

```
npm run fetch:vendor
```

| File | Purpose |
|---|---|
| `transformers.min.js` | Transformers.js (ESM) — object detection / OCR / NER, WebGPU + WASM |
| `tesseract.min.js`, `tesseract-worker.min.js`, `tesseract-core-simd.wasm(.js)` | Tesseract.js OCR engine |
| `eng.traineddata.gz` | Tesseract English model |
| `tasks-vision.mjs`, `mp-wasm/*` | MediaPipe Tasks Vision runtime |
| `blaze_face_short_range.tflite` | BlazeFace face detector (~230 KB) |

Everything here is `.gitignore`d except this README. Model **weights** for
Transformers.js are still pulled from the Hugging Face CDN on first use (that is
data, not executable code, which MV3 permits) and cached by the browser.
