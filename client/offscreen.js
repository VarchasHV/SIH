// Offscreen document: on-device vision inference + pixel redaction for Chrome MV3.
// Kept off the page and the service worker so neither stalls.
//
//   in  : { screenshot(dataURL), domPiiBoxes(cssPx), fields[], dpr, mode }
//   out : { redactedDataURL, detections[], fieldCategories, stats, timings }
//         -- NO raw OCR text ever leaves this document.

import { processVision } from "./lib/vision-pipeline.mjs";

chrome.runtime.onMessage.addListener((msg, _s, sendResponse) => {
  if (msg.action !== "PL_VISION") return;
  processVision(msg.payload)
    .then((r) => sendResponse({ ok: true, ...r }))
    .catch((e) => sendResponse({ ok: false, error: e.message, stack: e.stack }));
  return true;
});

// tell the worker we're alive
chrome.runtime.sendMessage({ action: "PL_OFFSCREEN_READY" }).catch(() => {});
