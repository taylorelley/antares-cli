/**
 * binary.ts — Resolve and validate the opengrep binary bundled with the extension.
 *
 * The binary is downloaded per-platform by tools/fetch-opengrep.mjs and stored under
 * bin/<target>/opengrep[.exe].  This module provides helpers for locating, validating,
 * and retrieving the version of the binary at runtime.
 *
 * Design notes:
 * - Uses only APIs that are safe in both the VS Code extension host (Node.js) and
 *   browser-hosted contexts (e.g., webviews).  No direct fs access — callers that
 *   have a file system (extension host) should read the file via vscode.workspace.fs
 *   or Node's fs after importing from the host side.
 * - Platform mapping is derived from process.platform + process.arch, matching the
 * targets used by tools/fetch-opengrep.mjs.
 */

import { join } from "path";

// ---------------------------------------------------------------------------
// Platform / Arch → target directory mapping
// ---------------------------------------------------------------------------

interface PlatformMapping {
  target: string;
  /** Binary filename (varies by platform, e.g. opengrep.exe on Windows). */
  binary: string;
}

/**
 * Map Node.js process.platform + process.arch to one of the known opengrep
 * distribution targets.
 */
export function resolvePlatformTarget(): PlatformMapping {
  const platform = process.platform;
  const arch = process.arch;

  if (platform === "linux" && arch === "x64") {
    return { target: "linux-x64", binary: "opengrep" };
  }
  if (platform === "linux" && arch === "arm64") {
    return { target: "linux-arm64", binary: "opengrep" };
  }
  if (platform === "darwin" && arch === "x64") {
    return { target: "darwin-x64", binary: "opengrep" };
  }
  if (platform === "darwin" && arch === "arm64") {
    return { target: "darwin-arm64", binary: "opengrep" };
  }
  if (platform === "win32" && arch === "x64") {
    return { target: "win32-x64", binary: "opengrep.exe" };
  }

  // Alpine Linux reports as linux + x64 — we differentiate via the
  // --alpine flag at fetch time, but at runtime we treat it as linux-x64.
  // The binary published for alpine uses musl; the user must fetch the
  // correct one via the `alpine-x64` target.
  if (platform === "linux" && arch === "x64") {
    // This case duplicates the first linux-x64 check above, but we keep it
    // for clarity.  Alpine users will need to set an override path or we
    // provide a separate detection mechanism (e.g., checking /etc/os-release).
    return { target: "linux-x64", binary: "opengrep" };
  }

  throw new Error(
    `Unsupported platform: ${platform} ${arch}. ` +
      "Opengrep is available for: linux-x64, linux-arm64, darwin-x64, darwin-arm64, win32-x64, alpine-x64"
  );
}

// ---------------------------------------------------------------------------
// Binary path resolution
// ---------------------------------------------------------------------------

/**
 * Resolve the absolute path to the opengrep binary.
 *
 * @param extensionUri - The extension URI (from `context.extensionUri`).
 *   Only the `fsPath` property is used.
 * @param overridePath - Optional override.  If provided and non-empty, it is
 *   returned as-is (caller should ensure the path is valid).
 * @returns Absolute path to the binary.
 */
export function resolveBinaryPath(
  extensionUri: { fsPath: string } | string,
  overridePath?: string,
): string {
  if (overridePath && overridePath.length > 0) {
    return overridePath;
  }

  const base = typeof extensionUri === "string" ? extensionUri : extensionUri.fsPath;
  const { target, binary } = resolvePlatformTarget();
  // Uses path.join which is safe in both Node.js and browser contexts
  // (it's a pure string manipulation).  The actual file I/O happens elsewhere.
  return join(base, "bin", target, binary);
}

// ---------------------------------------------------------------------------
// Binary validation
// ---------------------------------------------------------------------------

/**
 * Run `opengrep --version` to verify the binary is functional.
 *
 * **IMPORTANT**: This function uses `child_process.execFile` which is only
 * available in the Node.js extension host.  Do NOT import this module from
 * browser-facing code (webviews) without guarding the import.
 *
 * @param binaryPath - Absolute path to the opengrep binary.
 * @returns `true` if the binary exits with code 0, `false` otherwise.
 */
export async function validateBinary(binaryPath: string): Promise<boolean> {
  const { execFile } = await import("child_process");
  return new Promise<boolean>((resolve) => {
    const child = execFile(binaryPath, ["--version"], { timeout: 30_000 }, (error) => {
      resolve(error === null);
    });
    child.on("error", () => resolve(false));
  });
}

/**
 * Get the version string printed by `opengrep --version`.
 *
 * @param binaryPath - Absolute path to the opengrep binary.
 * @returns The version string (e.g. "1.25.0").
 * @throws If the binary cannot be executed or does not print a version.
 */
export async function getBinaryVersion(binaryPath: string): Promise<string> {
  const { execFile } = await import("child_process");
  return new Promise<string>((resolve, reject) => {
    const child = execFile(
      binaryPath,
      ["--version"],
      { timeout: 30_000 },
      (error, stdout) => {
        if (error) {
          reject(new Error(`Failed to get opengrep version: ${error.message}`));
          return;
        }
        const version = stdout?.trim() || "";
        if (!version) {
          reject(new Error("opengrep --version produced empty output"));
          return;
        }
        resolve(version);
      },
    );
    child.on("error", (err) => reject(new Error(`Failed to spawn opengrep: ${err.message}`)));
  });
}
