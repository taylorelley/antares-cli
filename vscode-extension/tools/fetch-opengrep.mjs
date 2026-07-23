#!/usr/bin/env node

/**
 * fetch-opengrep.mjs — Download opengrep binary for a given platform target.
 *
 * Usage:
 *   node tools/fetch-opengrep.mjs <target>
 *   node tools/fetch-opengrep.mjs --all
 *
 * Targets: linux-x64, linux-arm64, darwin-x64, darwin-arm64, win32-x64, alpine-x64
 *
 * No external dependencies; uses Node.js 18+ built-in fetch and fs/promises.
 */

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------
const VERSION = "1.25.0";

const TARGET_MAP = {
  "linux-x64":    "opengrep_manylinux_x86",
  "linux-arm64":  "opengrep_manylinux_aarch64",
  "darwin-x64":   "opengrep_osx_x86",
  "darwin-arm64": "opengrep_osx_arm64",
  "win32-x64":    "opengrep_windows_x86.exe",
  "alpine-x64":   "opengrep_musllinux_x86",
};

const ALL_TARGETS = Object.keys(TARGET_MAP);

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------
import { mkdir, writeFile, chmod } from "fs/promises";
import path from "path";
import { fileURLToPath } from "url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = path.resolve(__dirname, "..");

function binaryName(target) {
  return target === "win32-x64" ? "opengrep.exe" : "opengrep";
}

function downloadUrl(target) {
  const dist = TARGET_MAP[target];
  if (!dist) {
    throw new Error(`Unknown target "${target}". Valid targets: ${ALL_TARGETS.join(", ")}`);
  }
  return `https://github.com/opengrep/opengrep/releases/download/v${VERSION}/${dist}`;
}

function log(message) {
  console.error(`[fetch-opengrep] ${message}`);
}

// ---------------------------------------------------------------------------
// Download
// ---------------------------------------------------------------------------
async function fetchBinary(url, destPath) {
  log(`Downloading ${url} ...`);
  const response = await fetch(url);
  if (!response.ok) {
    throw new Error(`Download failed: HTTP ${response.status} ${response.statusText}`);
  }
  const buffer = Buffer.from(await response.arrayBuffer());
  await writeFile(destPath, buffer);
  log(`Saved ${destPath} (${(buffer.length / 1024 / 1024).toFixed(1)} MB)`);
}

// ---------------------------------------------------------------------------
// Per-target download
// ---------------------------------------------------------------------------
async function fetchTarget(target) {
  const binDir = path.join(REPO_ROOT, "bin", target);
  const binFile = binaryName(target);
  const binPath = path.join(binDir, binFile);
  const versionPath = path.join(binDir, "VERSION");

  // Create directory
  await mkdir(binDir, { recursive: true });

  // Download binary
  const url = downloadUrl(target);
  await fetchBinary(url, binPath);

  // Make executable (not on Windows)
  if (target !== "win32-x64") {
    await chmod(binPath, 0o755);
    log(`chmod +x ${binPath}`);
  }

  // Write VERSION file
  await writeFile(versionPath, `${VERSION}\n`);
  log(`Wrote ${versionPath}`);

  // TODO: Add checksum verification with cosign once opengrep publishes
  // signatures and checksums alongside releases.
  //
  // Steps to add:
  //   1. Download opengrep_<dist>.sig and opengrep_<dist>.pem from the release
  //   2. Verify using `cosign verify-blob ...` (requires cosign CLI installed)
  //   3. Fall back to SHA-256 checksum verification if cosign is unavailable

  log(`Done — ${target} ready at ${binPath}`);
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------
async function main() {
  const args = process.argv.slice(2);

  if (args.length === 0) {
    console.error("Usage: node tools/fetch-opengrep.mjs <target>");
    console.error("       node tools/fetch-opengrep.mjs --all");
    console.error(`Targets: ${ALL_TARGETS.join(", ")}`);
    process.exit(1);
  }

  const targets = args.includes("--all") ? ALL_TARGETS : args;

  for (const target of targets) {
    if (!TARGET_MAP[target]) {
      console.error(`Unknown target "${target}". Valid targets: ${ALL_TARGETS.join(", ")}`);
      process.exit(1);
    }
  }

  for (const target of targets) {
    await fetchTarget(target);
  }
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
