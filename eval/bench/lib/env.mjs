// Phase 18 — the reproducibility block every benchmark output must carry.
import os from "node:os";
import { execSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { dirname } from "node:path";

const HERE = dirname(fileURLToPath(import.meta.url));

export function benchEnv(extra = {}) {
  let gitCommit = null, gitBranch = null, gitDirty = null;
  try {
    gitCommit = execSync("git rev-parse --short HEAD", { cwd: HERE }).toString().trim();
    gitBranch = execSync("git rev-parse --abbrev-ref HEAD", { cwd: HERE }).toString().trim();
    gitDirty = execSync("git status --porcelain", { cwd: HERE }).toString().trim().length > 0;
  } catch {}
  const cpu = os.cpus()[0];
  return {
    timestamp: new Date().toISOString(),
    gitCommit, gitBranch, gitDirty,
    nodeVersion: process.version,
    v8: process.versions.v8,
    os: `${os.type()} ${os.release()}`,
    platform: os.platform(),
    arch: os.arch(),
    cpuModel: cpu?.model || "unknown",
    cpuCount: os.cpus().length,
    totalMemGB: +(os.totalmem() / 1e9).toFixed(1),
    ...extra,
  };
}
