// Loads the generated CWE-selection rule tables (data/selection_tables.json), produced
// from the Python reference by tools/gen-selection-tables.py so the data is byte-identical.

import * as fs from "fs";
import * as path from "path";

export interface EvidenceRuleData {
  label: string;
  cwe_scores: [string, number][];
  tokens: string[];
  languages: string[];
  required_token_groups: string[][];
}

export interface SelectionTables {
  PROFILE_SIGNAL_RULES: [string, string, string[]][];
  PRIMARY_PROFILE_SIGNAL_CWE_IDS: Record<string, string[]>;
  FRAMEWORK_PROFILE_SIGNAL_RULES: [string, string[], string[], number][];
  AUTOMATIC_SELECTION_POLICY: string;
  EXPLICIT_SELECTION_POLICY: string;
  SIMPLIFIED_MAPPING_VIEW: string;
  SOFTWARE_DEVELOPMENT_VIEW: string;
  CURRENT_TOP_25_BASELINE_NAME: string;
  AUTO_RELATIONSHIP_FAMILY_CAP: number;
  COMMON_AUTOMATIC_SELECTION_NOTES: string[];
  EXPLICIT_SELECTION_NOTES: string[];
  LANGUAGE_BY_SUFFIX: Record<string, string>;
  FRAMEWORK_DEPENDENCY_EXACT: Record<string, string>;
  FRAMEWORK_DEPENDENCY_PREFIXES: Record<string, string>;
  DEPENDENCY_CAPABILITY_PREFIXES: Record<string, string[]>;
  DEPENDENCY_MANIFEST_NAMES: string[];
  SECURITY_SENSITIVE_PATH_MARKERS: string[];
  MAX_PROFILE_FILES: number;
  MAX_PROFILE_FILE_BYTES: number;
  MAX_PRIORITY_PROFILE_FILES: number;
  SECRET_SIGNAL_PATTERN: string;
  SENSITIVE_VALUE_TOKENS: string[];
  EVIDENCE_RULES: EvidenceRuleData[];
}

const cache = new Map<string, SelectionTables>();

export function loadSelectionTables(dataDir: string): SelectionTables {
  const cached = cache.get(dataDir);
  if (cached) {
    return cached;
  }
  const file = path.join(dataDir, "selection_tables.json");
  const tables = JSON.parse(fs.readFileSync(file, "utf-8")) as SelectionTables;
  cache.set(dataDir, tables);
  return tables;
}
