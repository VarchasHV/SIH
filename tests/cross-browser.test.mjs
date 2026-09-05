import { test } from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");

async function loadManifest(name) {
  return JSON.parse(await readFile(join(ROOT, "client", name), "utf8"));
}

test("Chrome manifest - MV3 with service worker background", async () => {
  const manifest = await loadManifest("manifest.chrome.json");

  assert.equal(manifest.manifest_version, 3, "Manifest version must be 3");
  assert.ok(manifest.name, "Manifest must have a name");
  assert.ok(manifest.version, "Manifest must have a version");

  assert.equal(
    manifest.background?.service_worker,
    "background.js",
    "Chrome must use a service_worker background"
  );
  assert.ok(
    !manifest.background?.scripts,
    "Chrome manifest must not declare background.scripts (MV2-only for Chromium)"
  );

  assert.ok(
    manifest.content_security_policy?.extension_pages?.includes("wasm-unsafe-eval"),
    "CSP must permit local wasm execution"
  );
});

test("Firefox manifest - Gecko MV3 with background scripts", async () => {
  const manifest = await loadManifest("manifest.firefox.json");

  assert.equal(manifest.manifest_version, 3, "Manifest version must be 3");
  assert.ok(manifest.name, "Manifest must have a name");
  assert.ok(manifest.version, "Manifest must have a version");

  // Firefox Gecko requirements
  assert.ok(manifest.browser_specific_settings?.gecko?.id, "Firefox Gecko ID must be defined");
  assert.equal(manifest.browser_specific_settings.gecko.id, "connor@sih2026.org");
  assert.ok(
    manifest.browser_specific_settings.gecko.strict_min_version,
    "Firefox strict_min_version must be defined"
  );

  assert.deepEqual(
    manifest.background?.scripts,
    ["background.js"],
    "Firefox must use background.scripts"
  );
  assert.ok(
    !manifest.background?.service_worker,
    "Firefox MV3 background must not declare service_worker"
  );

  assert.ok(
    manifest.content_security_policy?.extension_pages?.includes("wasm-unsafe-eval"),
    "CSP must permit local wasm execution"
  );
});

test("Chrome and Firefox manifests only differ in background + gecko settings", async () => {
  const chrome = await loadManifest("manifest.chrome.json");
  const firefox = await loadManifest("manifest.firefox.json");

  for (const m of [chrome, firefox]) {
    delete m.background;
    delete m.browser_specific_settings;
    delete m.permissions; // offscreen is Chrome-only
  }
  assert.deepEqual(chrome, firefox, "Non-background manifest keys must stay in sync");
});

test("Cross-Browser Vision Pipeline Module - Exports processVision", async () => {
  const mod = await import("../client/lib/vision-pipeline.mjs");
  assert.equal(typeof mod.processVision, "function", "vision-pipeline.mjs must export processVision");
});
