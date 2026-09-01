#!/usr/bin/env node
/**
 * Selects the browser-specific manifest and writes it to client/manifest.json.
 *
 * Chrome/Firefox need different `background` architectures (service_worker vs
 * scripts), so we keep one source manifest per target and copy the right one
 * to client/manifest.json.
 *
 * client/manifest.json is committed as the Chrome build so "Load unpacked"
 * works on a fresh clone with no build step. Run this only to switch builds:
 *
 *   node scripts/build-manifest.mjs chrome    (default)
 *   node scripts/build-manifest.mjs firefox
 */
import { readFile, writeFile } from "node:fs/promises";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const CLIENT = join(ROOT, "client");

const target = (process.argv[2] || "chrome").toLowerCase();
if (!["chrome", "firefox"].includes(target)) {
  console.error(`Unknown target "${target}". Use "chrome" or "firefox".`);
  process.exit(1);
}

const src = join(CLIENT, `manifest.${target}.json`);
const dest = join(CLIENT, "manifest.json");

const raw = await readFile(src, "utf8");
JSON.parse(raw); // fail loudly on malformed source
await writeFile(dest, raw.endsWith("\n") ? raw : raw + "\n");

console.log(`client/manifest.json <- manifest.${target}.json`);
