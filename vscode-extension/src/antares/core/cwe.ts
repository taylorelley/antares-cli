// Port of antares_cli/core/cwe.py — deterministic CWE id normalization/validation.

import { CweDatabase } from "../knowledge/cweDatabase";

const CWE_STRICT_PATTERN = /^(?:CWE[-_\s]*)?0*(\d+)$/i;
const CWE_SEARCH_PATTERN = /CWE-(\d+)/i;

export class CweIdError extends Error {}

// Normalize a CWE identifier to canonical "CWE-NNN" form.
// strict=true: input must be a standalone reference ("22", "cwe-22", "CWE_22").
// strict=false: extract the first CWE-NNN anywhere, fall back to bare digits,
//   else return the original string unchanged.
export function normalizeCweId(rawCweId: string, strict = true): string {
  const text = rawCweId.trim();

  if (strict) {
    const match = text.match(CWE_STRICT_PATTERN);
    if (match === null) {
      throw new CweIdError(`Invalid CWE ID: ${JSON.stringify(rawCweId)}`);
    }
    const numericId = Number.parseInt(match[1], 10);
    if (numericId <= 0) {
      throw new CweIdError(`Invalid CWE ID: ${JSON.stringify(rawCweId)}`);
    }
    return `CWE-${numericId}`;
  }

  const searchMatch = text.match(CWE_SEARCH_PATTERN);
  if (searchMatch) {
    return `CWE-${Number.parseInt(searchMatch[1], 10)}`;
  }
  if (/^\d+$/.test(text)) {
    return `CWE-${Number.parseInt(text, 10)}`;
  }
  return text;
}

// Normalize, validate against the catalog, and de-duplicate while preserving order.
export function normalizeCweIds(rawCweIds: string[], cweDatabase: CweDatabase): string[] {
  const normalizedIds: string[] = [];
  const seen = new Set<string>();
  for (const rawCweId of rawCweIds) {
    const normalizedId = normalizeCweId(rawCweId);
    if (cweDatabase.getById(normalizedId) === undefined) {
      throw new CweIdError(`Unknown CWE ID: ${normalizedId}`);
    }
    if (!seen.has(normalizedId)) {
      normalizedIds.push(normalizedId);
      seen.add(normalizedId);
    }
  }
  return normalizedIds;
}

// Parse a comma-separated CLI CWE list into raw id tokens.
export function parseCweIdList(rawValue: string | null | undefined): string[] {
  if (rawValue === null || rawValue === undefined) {
    return [];
  }
  return rawValue
    .split(",")
    .map((part) => part.trim())
    .filter((part) => part.length > 0);
}
