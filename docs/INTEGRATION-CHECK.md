# Browser integration check

The shared logic has unit coverage (`npm test` — 28 tests) and the server is
verified end-to-end headlessly (`npm run eval` with the server up). What can only
be checked in a real browser is the extension message flow. This is a code trace
of that flow plus a manual checklist.

## Message flow (traced, contracts verified)

```
popup  ──PL_RUN_TASK──▶ background.runAgentTask()          (responds immediately; drives via events)
                          │
  each step:              ▼
  background ──PL_PREPARE──▶ agent-bridge.prepare()
      ◀── { ok, skeleton, domPiiBoxes, tokenContext, profileTokens }   [vault stays in the page]
                          │
  background.captureVisibleTab()  ──▶ raw PNG
                          │
  background ──PL_VISION {screenshot, domPiiBoxes, fields, dpr, mode}──▶ offscreen.process()
      ◀── { ok, redactedDataURL, detections, fieldCategories, redactedRegions, stats, timings }
                          │
  background: patch skeleton nodes with fieldCategories (vision-named fields → fillToken)
  background ──PL_HIGHLIGHT {regions, kind:"redact"}──▶ agent-bridge (page overlay)
  background: emit "egress" event  ──▶ popup shows redacted image + payload JSON
                          │
  background ──POST /agent/step { taskGoal, skeleton, tokenMap, availableTokens,
                                  visionDetections, screenshot(redacted), history }──▶ server
      ◀── { actions:[{action,targetId,valueToken?}], rationale, done }
                          │
  background: validatePlan(actions, knownIds, knownTokens)
  for each action:
    background ──PL_EXECUTE {step: action}──▶ agent-bridge.execute()
        agent-bridge: resolve valueToken → real value from the in-page vault
        agent-bridge ──▶ executor.executeAction(action, value)   [types into the field]
      ◀── { ok, result:{ note, verified } }
```

Contract checks done statically:
- `PL_PREPARE` / `PL_VISION` / `PL_EXECUTE` / `PL_HIGHLIGHT` payload keys match on
  both sides.
- Server `StepRequest` / `StepResponse` (Pydantic) match what `background.js`
  sends / `agent-client.mjs` expects. Extra node key `labelSource` is ignored by
  Pydantic (`extra="ignore"` default).
- Coordinate spaces: screenshot + `bboxDevice` + offscreen output = **device px**;
  `skeleton.bbox` + `domPiiBoxes` + `fields[].bbox` = **CSS px** (offscreen and
  `label-assoc` multiply by `dpr`); the page overlay divides device coords back
  by `dpr`.
- `window.__PL.{buildSkeleton,domPiiBoxes,executeAction,verifyField}` are defined
  in `skeleton.js` / `executor.js`, both loaded before `agent-bridge.js` in the
  manifest `content_scripts.js` array.
- Double-injection guarded (`window.__plAgentBridgeLoaded`, `hasInjectedPrivacyAgent`).

## Manual checklist (load in Chrome)

1. `npm run fetch:vendor` populated `client/vendor/` (transformers, tesseract*,
   tasks-vision, blaze_face*.tflite). **If this folder is empty, vision is a
   no-op** (pipeline still runs on the DOM channel).
2. `server/.venv/bin/pip install -r server/requirements.txt` (needs `httpx`).
3. `cp server/.env.example server/.env`, set `GEMINI_API_KEY`. `npm run server` →
   `GET localhost:8000/health` shows `"vlm_mode":"gemini"`.
4. `npm run fixtures`. `chrome://extensions` → Developer mode → Load unpacked →
   `client/`. Reload any already-open fixture tab.
5. Popup → **Profile** → fill values → **Save profile**.
6. Open `http://localhost:4173/hostile-form.html`. Popup → **Assist** → preset →
   **Start agent**.

### What to verify
| Check | Where | Pass = |
|---|---|---|
| offscreen doc spins up | `chrome://extensions` → service worker → "Inspect" → no error on `createDocument` | no throw |
| OCR runs | Activity panel `OCR …ms`, `ocr lines: N>0` | non-zero |
| face model | Activity `face model: on` (needs the .tflite) | on (or graceful "off") |
| redaction | egress image in Activity has blurred/mosaiced fields | visibly redacted |
| **no PII in payload** | Activity → "Payload JSON" details | only `[TOKEN]`s, no real values, screenshot shown as `<redacted image…>` |
| vision-named fields | Activity `fields named by vision: N` on the hostile form | N > 0 |
| server plan | Activity shows `type [TOKEN] → el-N` actions | tokens, valid ids |
| execution | fields on the page fill; targeted field flashes green | values appear |
| token resolution | filled values match your saved profile | correct |
| submit gate | if goal says "submit", popup asks first | prompt appears |

## Known risk points (graceful-degradation built in)

| Risk | Behaviour if it fails |
|---|---|
| Tesseract `corePath` dir resolution under MV3 | `runOCR` catches → `ocrError` in stats, pipeline continues DOM-only |
| MediaPipe WASM/model load | `faceLoadFailed` → no faces, `faceError` in stats |
| `captureVisibleTab` throttle (>2/s) | steps are seconds apart (server round-trip), not hit in practice |
| offscreen not ready for first `PL_VISION` | `ensureOffscreen` polls `PL_OFFSCREEN_READY`; `callOffscreen` retries 3× |
| popup closed mid-run | events dropped (`emit` catches); gates auto-deny after 90 s |
| large PNG over `sendMessage` | re-encoded to JPEG q0.82 on the way back; inbound PNG within MV3 limits |
| Gemini slow / errors | `run_step` falls back to `mock`; rationale notes it |

## Not yet covered
- Shadow DOM fields (skeleton uses `querySelectorAll`, no shadow traversal).
- Cross-origin iframes (content script runs per-frame but skeleton/exec are top-frame).
- `<select>` month/day/year triples that share one caption.
- Firefox (MV3 offscreen differs; needs a background-page shim).
