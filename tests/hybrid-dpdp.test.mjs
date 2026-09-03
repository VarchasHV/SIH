import { test } from "node:test";
import assert from "node:assert/strict";
import { classifyDPDP, generateDPDPAuditReport } from "../client/lib/dpdp-audit.mjs";
import { processVision } from "../client/lib/vision-pipeline.mjs";

test("DPDP Classification - Maps PII categories to MeitY DPDP 2023 Schedules", () => {
  const financial = classifyDPDP("card");
  assert.equal(financial.schedule, "Section 3(1)(a)");
  assert.equal(financial.riskLevel, "CRITICAL");

  const aadhaar = classifyDPDP("aadhaar");
  assert.equal(aadhaar.schedule, "Section 3(1)(b)");
  assert.equal(aadhaar.categoryName, "National Identity (Aadhaar)");

  const phone = classifyDPDP("phone");
  assert.equal(phone.schedule, "Section 3(1)(c)");
  assert.equal(phone.riskLevel, "MEDIUM");

  const face = classifyDPDP("face");
  assert.equal(face.schedule, "Section 3(1)(d)");
  assert.equal(face.categoryName, "Biometric (Face Identifier)");
});

test("DPDP Audit Report Generation - Produces compliant JSON audit record", () => {
  const report = generateDPDPAuditReport({
    url: "https://bank.example.in/kyc",
    step: 1,
    detections: [
      { category: "aadhaar", source: "dom_dlp" },
      { category: "pan", source: "dom_dlp" },
      { category: "card", source: "dom_dlp" },
      { category: "phone", source: "dom_dlp" },
    ],
    securityAlerts: [{ type: "HIDDEN_PROMPT_INJECTION", reason: "Opacity zero payload" }],
    hybridStats: { a11yBypassed: true },
  });

  assert.equal(report.act, "Digital Personal Data Protection Act (DPDP) 2023 / Rules 2025");
  assert.equal(report.complianceStatus, "COMPLIANT_ON_DEVICE_MINIMIZATION");
  assert.equal(report.minimizationScore, "100%");
  assert.equal(report.hybridEngineMode, "HYBRID_A11Y_FASTPATH");
  assert.equal(report.statistics.totalRedactedElements, 4);
  assert.equal(report.statistics.financialDataCount, 1);
  assert.equal(report.statistics.identityDataCount, 2);
  assert.equal(report.statistics.contactDataCount, 1);
  assert.equal(report.statistics.adversarialThreatsBlocked, 1);
  assert.equal(report.auditEntries.length, 4);
});

test("Hybrid A11y Fast-Path - Bypasses heavy vision inference when accessibility confidence is sufficient", async () => {
  // Create dummy screenshot (1x1 PNG data URI)
  const dummyShot = "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==";

  const a11yStatsFastPath = {
    totalNodes: 5,
    labeledNodes: 5,
    unlabeledNodes: 0,
    hasCanvas: false,
    confidence: 1.0,
    fastPathEligible: true,
  };

  const res = await processVision({
    screenshot: dummyShot,
    domPiiBoxes: [],
    fields: [],
    dpr: 1,
    mode: "blackout",
    a11yStats: a11yStatsFastPath,
  });

  assert.equal(res.timings.a11yBypassed, true, "Heavy vision models should be bypassed on high-confidence A11y tree");
  assert.equal(res.timings.ocrMs, 0, "OCR should take 0ms when fast-path is active");
  assert.equal(res.timings.vitMs, 0, "ViT should take 0ms when fast-path is active");
  assert.equal(res.timings.visionStageSkipped, true, "the skipped vision stage is flagged (no fabricated ms constant)");
  assert.equal("latencySavingsMs" in res.timings, false, "the fabricated 280ms constant is gone");
});

test("Selective ViT - raster detectors are skipped when the DOM reports no image/canvas content", async () => {
  const dummyShot = "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==";

  // slow path (fastPathEligible:false) but a clean text form — no canvas, no raster
  const res = await processVision({
    screenshot: dummyShot, domPiiBoxes: [], fields: [], dpr: 1, mode: "blackout",
    a11yStats: { totalNodes: 12, labeledNodes: 9, unlabeledNodes: 3, unlabeledInputNodes: 0, hasCanvas: false, hasLargeRaster: false, confidence: 0.75, fastPathEligible: false },
  });
  assert.equal(res.timings.a11yBypassed, false, "still the full pipeline (OCR runs)");
  assert.equal(res.timings.rasterInspected, false, "face + ViT skipped: nothing raster to inspect");
  assert.equal(res.stats.vit.backend, "skipped:no-raster");
  assert.equal(res.timings.vitMs, 0);

  // same page but with a large image present -> raster detectors run
  const res2 = await processVision({
    screenshot: dummyShot, domPiiBoxes: [], fields: [], dpr: 1, mode: "blackout",
    a11yStats: { totalNodes: 12, labeledNodes: 9, unlabeledNodes: 3, unlabeledInputNodes: 0, hasCanvas: false, hasLargeRaster: true, confidence: 0.75, fastPathEligible: false },
  });
  assert.equal(res2.timings.rasterInspected, true);
  assert.notEqual(res2.stats.vit.backend, "skipped:no-raster");

  // forceVision overrides the skip
  const res3 = await processVision({
    screenshot: dummyShot, domPiiBoxes: [], fields: [], dpr: 1, mode: "blackout",
    a11yStats: { totalNodes: 3, labeledNodes: 3, unlabeledNodes: 0, hasCanvas: false, hasLargeRaster: false, confidence: 1, fastPathEligible: false },
    forceVision: true,
  });
  assert.equal(res3.timings.rasterInspected, true, "forceVision runs raster detectors regardless");
});

test("Hybrid A11y Fast-Path - a caller-measured vision baseline is echoed, not invented", async () => {
  const dummyShot = "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==";
  const res = await processVision({
    screenshot: dummyShot, domPiiBoxes: [], fields: [], dpr: 1, mode: "blackout",
    a11yStats: { totalNodes: 5, labeledNodes: 5, unlabeledNodes: 0, hasCanvas: false, confidence: 1, fastPathEligible: true },
    visionStageBaselineMs: 312,
  });
  assert.equal(res.timings.visionStageBaselineMs, 312);
});
