// Port of antares_cli/core/cwe_selection_models.py (fields relevant to selection output).

export type CweAbstractionLevel = "all" | "pillar" | "class" | "base" | "variant" | "compound";
export type ScanScope = "auto" | "top25" | "owasp";

// Mutable signal accumulator used during profiling (Python ProfileSignals).
export interface ProfileSignals {
  frameworks: Set<string>;
  packageManagers: Set<string>;
  dependencyFiles: Set<string>;
  routeFiles: Set<string>;
  authSignals: Set<string>;
  dataStoreSignals: Set<string>;
  templateSignals: Set<string>;
  fileIoSignals: Set<string>;
  networkClientSignals: Set<string>;
  deserializationSignals: Set<string>;
  cryptoSignals: Set<string>;
  nativeCodeSignals: Set<string>;
  iacSignals: Set<string>;
  secretSignals: Set<string>;
  requestInputSignals: Set<string>;
  uploadSignals: Set<string>;
  loggingSignals: Set<string>;
  parserSignals: Set<string>;
  configurationSignals: Set<string>;
  cweEvidence: Map<string, Set<string>>;
  cweEvidenceFiles: Map<string, Set<string>>;
  cweEvidenceScores: Map<string, number>;
}

export function newProfileSignals(): ProfileSignals {
  return {
    frameworks: new Set(),
    packageManagers: new Set(),
    dependencyFiles: new Set(),
    routeFiles: new Set(),
    authSignals: new Set(),
    dataStoreSignals: new Set(),
    templateSignals: new Set(),
    fileIoSignals: new Set(),
    networkClientSignals: new Set(),
    deserializationSignals: new Set(),
    cryptoSignals: new Set(),
    nativeCodeSignals: new Set(),
    iacSignals: new Set(),
    secretSignals: new Set(),
    requestInputSignals: new Set(),
    uploadSignals: new Set(),
    loggingSignals: new Set(),
    parserSignals: new Set(),
    configurationSignals: new Set(),
    cweEvidence: new Map(),
    cweEvidenceFiles: new Map(),
    cweEvidenceScores: new Map(),
  };
}

// Frozen repository profile. `signalField` maps the Python profile_field names used by
// the rule tables to the corresponding sorted string arrays.
export interface RepositoryProfile {
  languages: Record<string, number>;
  frameworks: string[];
  dependencyFiles: string[];
  routeFiles: string[];
  iacSignals: string[];
  secretSignals: string[];
  requestInputSignals: string[];
  templateSignals: string[];
  uploadSignals: string[];
  dataStoreSignals: string[];
  fileIoSignals: string[];
  // Access any signal bucket by its Python profile_field name (e.g. "auth_signals").
  signalField(field: string): string[];
  cweEvidence: Map<string, string[]>;
  cweEvidenceFiles: Map<string, string[]>;
  cweEvidenceScores: Map<string, number>;
  confidence: number;
}

export interface SelectedCheck {
  cweId: string;
  title: string;
  score: number;
  confidence: number;
  repositoryEvidenceScore: number;
  repositorySpecificEvidenceScore: number;
  repositoryCategoryEvidenceScore: number;
  repositoryRelationshipEvidenceScore: number;
  repositoryEvidenceCoverage: number;
  taxonomyPriorityScore: number;
  rankingScore: number;
  exactPlatformMatch: boolean;
  concreteLanguageMismatch: boolean;
  selectionTier: string;
}

export interface CweSelectionRequest {
  target: string;
  cweIds: string[];
  ignorePaths: string[];
  allowSensitiveFiles: string[];
  scope: ScanScope;
  cweLevel: CweAbstractionLevel;
  maxCwes: number;
}

export interface CweSelectionPlan {
  selectedChecks: SelectedCheck[];
  explicitCweIds: string[];
  selectionPolicy: string;
  cweIds(): string[];
}

export function planCweIds(selectedChecks: SelectedCheck[]): string[] {
  const ids: string[] = [];
  const seen = new Set<string>();
  for (const check of selectedChecks) {
    if (!seen.has(check.cweId)) {
      ids.push(check.cweId);
      seen.add(check.cweId);
    }
  }
  return ids;
}
