/**
 * types.ts — TypeScript types matching opengrep JSON output schema.
 *
 * Opengrep (and semgrep) emits a JSON result object on stdout when invoked
 * with `--json`.  This module defines the relevant subsets of that schema,
 * plus a helper to extract CWE identifiers from rule metadata.
 */

// ---------------------------------------------------------------------------
// Opengrep JSON output types
// ---------------------------------------------------------------------------

export interface OpengrepFinding {
  check_id: string;
  path: string;
  start: { line: number; col: number };
  end: { line: number; col: number };
  extra: {
    message: string;
    severity: "ERROR" | "WARNING" | "INFO";
    metadata: {
      cwe?: string | string[];
      category?: string;
    };
    lines: string;
  };
}

export interface OpengrepError {
  type: string;
  level: string;
  path?: string;
  message: string;
}

export interface OpengrepResult {
  results: OpengrepFinding[];
  errors: OpengrepError[];
  paths: { scanned: string[] };
}

// ---------------------------------------------------------------------------
// CWE extraction helper
// ---------------------------------------------------------------------------

/**
 * Parse CWE identifiers from opengrep metadata.
 *
 * Opengrep rulesets typically embed CWE information in one of two formats:
 *   - A single string: "CWE-89: SQL Injection"
 *   - An array of strings: ["CWE-89: SQL Injection", "CWE-78: OS Command Injection"]
 *
 * This function extracts the compact identifier (e.g. "CWE-89") from each entry.
 *
 * @param metadata - The `metadata` field from an OpengrepFinding.
 * @returns An array of CWE identifiers (e.g. ["CWE-89"]).
 */
export function parseCweFromMetadata(
  metadata: { cwe?: string | string[] },
): string[] {
  const raw = metadata.cwe;
  if (!raw) {
    return [];
  }

  const entries = Array.isArray(raw) ? raw : [raw];
  const ids: string[] = [];

  for (const entry of entries) {
    // Match "CWE-NNN" at the start of the string (possibly followed by a colon or space).
    const match = /^(CWE-\d+)/i.exec(entry.trim());
    if (match) {
      // Normalise to uppercase "CWE-XXXX".
      ids.push(match[1].toUpperCase());
    }
  }

  return ids;
}
