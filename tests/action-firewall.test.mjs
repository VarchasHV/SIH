// Phases 6 + 13 — agent action firewall.

import test from "node:test";
import assert from "node:assert/strict";
import { classifyAction } from "../client/lib/action-firewall.mjs";

const at = (action, ctx) => classifyAction(action, ctx);

test("non-mutating actions are LOW / ALLOW", () => {
  for (const a of ["wait", "scroll", "done"]) {
    const r = at({ action: a });
    assert.equal(r.risk, "LOW");
    assert.equal(r.decision, "ALLOW");
  }
});

test("clicking a plain 'Next' button is LOW", () => {
  assert.equal(at({ action: "click", targetId: "n" }, { targetNode: { text: "Next" } }).risk, "LOW");
});

test("submitting a form is MEDIUM; a credential form is HIGH", () => {
  assert.equal(at({ action: "submit" }, { targetNode: { text: "Continue" } }).risk, "MEDIUM");
  assert.equal(at({ action: "submit" }, { targetNode: { name: "password", text: "Sign in" } }).risk, "HIGH");
});

test("uploading / downloading needs approval even at MEDIUM", () => {
  assert.equal(at({ action: "upload" }, {}).decision, "REQUIRE_APPROVAL");
  assert.equal(at({ action: "download", literalValue: "https://x/report.pdf" }, {}).decision, "REQUIRE_APPROVAL");
});

test("CRITICAL: restricted PII into a cross-origin form is BLOCKed + flagged as exfil", () => {
  const r = at({ action: "type", literalValue: "2345 6789 0124" },
    { targetNode: { piiCategory: "aadhaar", formCrossOrigin: true, formOrigin: "https://skimmer.example" } });
  assert.equal(r.risk, "CRITICAL");
  assert.equal(r.decision, "BLOCK");
  assert.equal(r.exfil.channel, "cross_origin_form");
  assert.ok(r.exfil.categories.includes("aadhaar"));
});

test("CRITICAL: clicking a link whose URL carries PII is an exfil BLOCK", () => {
  const r = at({ action: "click", targetId: "a" }, {
    targetNode: { href: "https://exfil.evil.example/save?aadhaar=357454365042&email=a@b.com", text: "Share" },
    pageOrigin: "https://bank.example",
  });
  assert.equal(r.decision, "BLOCK");
  assert.equal(r.exfil.channel, "url");
});

test("CRITICAL: executable download from a low-trust host is BLOCKed", () => {
  const r = at({ action: "click", targetId: "d" }, {
    targetNode: { href: "https://cdn.free-downloads.top/cert.scr", downloadAttr: true, text: "Download" },
    pageOrigin: "https://kyc.example.com", destinationTrust: 0.3,
  });
  assert.equal(r.risk, "CRITICAL");
  assert.equal(r.decision, "BLOCK");
});

test("CRITICAL: cross-origin form submit (skimmer) is blocked", () => {
  const r = at({ action: "submit" }, { targetNode: { text: "Pay", formCrossOrigin: true, formOrigin: "https://collect.skimmer.xyz" } });
  assert.equal(r.decision, "BLOCK");
  assert.equal(r.exfil.channel, "cross_origin_form_submit");
});

test("a MALICIOUS page escalates any mutating action to at least approval", () => {
  const r = at({ action: "click", targetId: "n" }, { targetNode: { text: "OK" }, pageMalicious: true });
  assert.ok(["HIGH", "CRITICAL"].includes(r.risk));
  assert.notEqual(r.decision, "ALLOW");
});

test("typing a plain value into a normal field stays LOW", () => {
  assert.equal(at({ action: "type", literalValue: "laptop stand" }, { targetNode: { piiCategory: "search" } }).risk, "LOW");
});

test("reasons never contain the raw value", () => {
  const r = at({ action: "type", literalValue: "AKIAIOSFODNN7EXAMPLE" }, { targetNode: { formCrossOrigin: true, formOrigin: "https://x.example" } });
  for (const why of r.reasons) assert.equal(why.includes("AKIAIOSFODNN7EXAMPLE"), false);
});
