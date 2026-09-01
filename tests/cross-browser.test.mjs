import { test } from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");

test("Cross-Browser Manifest - Valid for Chrome and Firefox MV3", async () => {
  const raw = await readFile(join(ROOT, "client", "manifest.json"), "utf8");
  const manifest = JSON.parse(raw);

  assert.equal(manifest.manifest_version, 3, "Manifest version must be 3");
  assert.ok(manifest.name, "Manifest must have a name");
  assert.ok(manifest.version, "Manifest must have a version");

  // Firefox Gecko requirements
  assert.ok(manifest.browser_specific_settings?.gecko?.id, "Firefox Gecko ID must be defined");
  assert.equal(manifest.browser_specific_settings.gecko.id, "privacy-lens@sih2026.org");
  assert.ok(manifest.browser_specific_settings.gecko.strict_min_version, "Firefox strict_min_version must be defined");

  // Background scripts / service worker
  assert.ok(
    manifest.background?.service_worker || manifest.background?.scripts,
    "Background handler must be defined for MV3"
  );

  // Content security policy for local WASM
  assert.ok(
    manifest.content_security_policy?.extension_pages?.includes("wasm-unsafe-eval"),
    "CSP must permit local wasm execution"
  );
});

test("Cross-Browser Vision Pipeline Module - Exports processVision", async () => {
  const mod = await import("../client/lib/vision-pipeline.mjs");
  assert.equal(typeof mod.processVision, "function", "vision-pipeline.mjs must export processVision");
});
