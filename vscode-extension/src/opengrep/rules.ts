/**
 * rules.ts — Resolve and validate the path to the antares-sast rules directory.
 *
 * Rules are bundled as .yml files under `rules/antares-sast/` within the
 * extension directory.  This module resolves the path (with optional override)
 * and validates that the directory exists and contains at least one .yml file.
 */

import { readdir, stat } from "fs/promises";
import { join } from "path";

// ---------------------------------------------------------------------------
// Path resolution
// ---------------------------------------------------------------------------

/**
 * Resolve the absolute path to the antares-sast rules directory.
 *
 * @param overridePath - Optional override.  If provided and non-empty, it is
 *   returned as-is (caller should validate separately).
 * @param extensionUri - The extension path (from `context.extensionUri.fsPath`
 *   or a plain absolute path string).
 * @returns The resolved rules directory path.
 */
export function resolveRulesPath(
  overridePath?: string,
  extensionUri?: string,
): string {
  if (overridePath && overridePath.length > 0) {
    return overridePath;
  }

  if (!extensionUri) {
    throw new Error(
      "resolveRulesPath requires either an overridePath or extensionUri",
    );
  }

  return join(extensionUri, "rules", "antares-sast");
}

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

/**
 * Validate that a rules directory exists and contains at least one .yml file.
 *
 * @param rulesPath - Absolute path to the rules directory.
 * @returns `true` if the directory exists with .yml files.
 * @throws If the filesystem cannot be queried.
 */
export async function validateRules(rulesPath: string): Promise<boolean> {
  let stats;
  try {
    stats = await stat(rulesPath);
  } catch {
    return false;
  }

  if (!stats.isDirectory()) {
    return false;
  }

  const entries = await readdir(rulesPath);
  return entries.some(
    (entry) =>
      entry.endsWith(".yml") || entry.endsWith(".yaml"),
  );
}
