// Port of antares_cli/core/cwe_selection.py — repository-aware CWE selection.

import { normalizeCweIds } from "../cwe";
import { CweDatabase, CweEntry } from "../../knowledge/cweDatabase";
import {
  CweSelectionPlan,
  CweSelectionRequest,
  planCweIds,
  RepositoryProfile,
  ScanScope,
  SelectedCheck,
} from "./models";
import { RepositoryProfiler } from "./profiler";
import { exclusionReason, hasConcreteLanguageMismatch, hasExactPlatformMatch } from "./relevance";
import { SelectionTables } from "./tables";

const CURRENT_TOP_25_VIEW_ID = "CWE-1435";
const CURRENT_OWASP_VIEW_ID = "CWE-1450";

function tupleCompare(a: number[], b: number[]): number {
  for (let i = 0; i < Math.max(a.length, b.length); i++) {
    const av = a[i] ?? 0;
    const bv = b[i] ?? 0;
    if (av !== bv) {
      return av - bv;
    }
  }
  return 0;
}

function cweNumber(check: SelectedCheck): number {
  return Number.parseInt(check.cweId.split("-")[1], 10);
}

export class CweSelectionService {
  private readonly childrenByParent = new Map<string, Set<string>>();
  private readonly parentsByChild = new Map<string, Set<string>>();
  private readonly tables: SelectionTables;
  private readonly SIMPLIFIED_MAPPING_VIEW: string;
  private readonly SOFTWARE_DEVELOPMENT_VIEW: string;
  private readonly FAMILY_CAP: number;

  constructor(
    private readonly cweDatabase: CweDatabase,
    tables: SelectionTables
  ) {
    this.tables = tables;
    this.SIMPLIFIED_MAPPING_VIEW = tables.SIMPLIFIED_MAPPING_VIEW;
    this.SOFTWARE_DEVELOPMENT_VIEW = tables.SOFTWARE_DEVELOPMENT_VIEW;
    this.FAMILY_CAP = tables.AUTO_RELATIONSHIP_FAMILY_CAP;
    this.buildRelationshipGraph();
  }

  private buildRelationshipGraph(): void {
    const entries = this.cweDatabase.listAll();
    const knownIds = new Set(entries.map((e) => e.id));
    for (const entry of entries) {
      for (const relationship of entry.related_weaknesses) {
        if (relationship.nature !== "ChildOf") {
          continue;
        }
        const parentId = relationship.cwe_id ?? "";
        if (!knownIds.has(parentId)) {
          continue;
        }
        if (!this.childrenByParent.has(parentId)) {
          this.childrenByParent.set(parentId, new Set());
        }
        this.childrenByParent.get(parentId)!.add(entry.id);
        if (!this.parentsByChild.has(entry.id)) {
          this.parentsByChild.set(entry.id, new Set());
        }
        this.parentsByChild.get(entry.id)!.add(parentId);
      }
    }
  }

  select(request: CweSelectionRequest): CweSelectionPlan {
    if (request.cweIds.length > 0) {
      return this.explicitPlan(request);
    }
    const profiler = new RepositoryProfiler(this.tables);
    const profile = profiler.profile(request.target, request.ignorePaths, request.allowSensitiveFiles);
    return this.autoPlan(request, profile);
  }

  private explicitPlan(request: CweSelectionRequest): CweSelectionPlan {
    const cweIds = normalizeCweIds(request.cweIds, this.cweDatabase);
    const selected = cweIds.map((cweId) => this.baseCheck(this.entryForCweId(cweId), 1.0, 1.0));
    return {
      selectedChecks: selected,
      explicitCweIds: cweIds,
      selectionPolicy: this.tables.EXPLICIT_SELECTION_POLICY,
      cweIds: () => planCweIds(selected),
    };
  }

  private autoPlan(request: CweSelectionRequest, profile: RepositoryProfile): CweSelectionPlan {
    const relationshipEvidence = this.relationshipEvidence(profile);
    const selected: SelectedCheck[] = [];
    for (const entry of this.cweDatabase.listAll()) {
      if (levelExclusionReason(entry, request.cweLevel) !== null) {
        continue;
      }
      if (exclusionReason(entry, request.scope) !== null) {
        continue;
      }
      selected.push(this.autoSelectedCheck(entry, profile, request.scope, relationshipEvidence.get(entry.id)));
    }
    selected.sort(request.scope === "auto" ? autoRelevanceCompare : rankedCheckCompare);
    const limit = request.maxCwes;
    const selectedChecks = this.selectPortfolio(selected, limit, request.scope, profile);
    return {
      selectedChecks,
      explicitCweIds: [],
      selectionPolicy: this.tables.AUTOMATIC_SELECTION_POLICY,
      cweIds: () => planCweIds(selectedChecks),
    };
  }

  private relationshipEvidence(profile: RepositoryProfile): Map<string, [string, number]> {
    const evidence = new Map<string, [string, number]>();
    const record = (candidate: string, seed: string, score: number) => {
      const existing = evidence.get(candidate);
      if (existing && existing[1] >= score) {
        return;
      }
      evidence.set(candidate, [`MITRE CWE relationship connects this entry to evidence-backed ${seed}`, score]);
    };
    for (const seedId of [...this.profileEvidenceSeedIds(profile)].sort()) {
      for (const childId of [...(this.childrenByParent.get(seedId) ?? [])].sort()) {
        record(childId, seedId, 45);
        for (const grandchildId of [...(this.childrenByParent.get(childId) ?? [])].sort()) {
          record(grandchildId, seedId, 25);
        }
      }
      for (const parentId of [...(this.parentsByChild.get(seedId) ?? [])].sort()) {
        record(parentId, seedId, 20);
      }
    }
    return evidence;
  }

  private profileEvidenceSeedIds(profile: RepositoryProfile): Set<string> {
    const seeds = new Set<string>();
    for (const [, field, cweIds] of this.tables.PROFILE_SIGNAL_RULES) {
      if (profile.signalField(field).length > 0) {
        for (const cweId of cweIds) {
          seeds.add(cweId);
        }
      }
    }
    const frameworks = new Set(profile.frameworks);
    for (const [, ruleFrameworks, cweIds] of this.tables.FRAMEWORK_PROFILE_SIGNAL_RULES) {
      if (ruleFrameworks.some((f) => frameworks.has(f))) {
        for (const cweId of cweIds) {
          seeds.add(cweId);
        }
      }
    }
    for (const cweId of profile.cweEvidence.keys()) {
      seeds.add(cweId);
    }
    return seeds;
  }

  private matchingProfileSignals(entry: CweEntry, profile: RepositoryProfile): { files: Set<string>; score: number } {
    const files = new Set<string>();
    const scores: number[] = [];
    for (const [, field, cweIds] of this.tables.PROFILE_SIGNAL_RULES) {
      const signalFiles = profile.signalField(field);
      if (signalFiles.length > 0 && cweIds.includes(entry.id)) {
        for (const f of signalFiles) {
          files.add(f);
        }
        const primary = this.tables.PRIMARY_PROFILE_SIGNAL_CWE_IDS[field] ?? [];
        scores.push(primary.includes(entry.id) ? 50 : 40);
      }
    }
    const frameworks = new Set(profile.frameworks);
    for (const [, ruleFrameworks, cweIds, frameworkScore] of this.tables.FRAMEWORK_PROFILE_SIGNAL_RULES) {
      if (ruleFrameworks.some((f) => frameworks.has(f)) && cweIds.includes(entry.id)) {
        for (const f of profile.dependencyFiles) {
          files.add(f);
        }
        scores.push(frameworkScore);
      }
    }
    const score = scores.length > 0 ? Math.min(60, Math.max(...scores) + (scores.length - 1) * 5) : 0;
    return { files, score };
  }

  private autoSelectedCheck(
    entry: CweEntry,
    profile: RepositoryProfile,
    scope: ScanScope,
    relationshipEvidence: [string, number] | undefined
  ): SelectedCheck {
    const exactPlatformMatch = hasExactPlatformMatch(entry, profile);
    const languageMismatch = hasConcreteLanguageMismatch(entry, profile);
    const { files: categoryFiles, score: categoryEvidenceScore } = this.matchingProfileSignals(entry, profile);
    const exactSignalFiles = profile.cweEvidenceFiles.get(entry.id) ?? [];
    const evidenceCoverage = new Set([...categoryFiles, ...exactSignalFiles]).size;
    const relationshipScore = relationshipEvidence ? relationshipEvidence[1] : 0;
    const exactEvidenceScore = profile.cweEvidenceScores.get(entry.id) ?? 0;
    const directEvidenceScore = Math.min(
      140,
      Math.max(categoryEvidenceScore, exactEvidenceScore) + (categoryEvidenceScore && exactEvidenceScore ? 10 : 0)
    );
    const repositoryEvidenceScore = directEvidenceScore + relationshipScore;
    const taxonomyPriorityScore = this.taxonomyPriorityScore(entry, scope);
    const rankingScore = automaticRankingScore(exactPlatformMatch, repositoryEvidenceScore, taxonomyPriorityScore, languageMismatch);
    return {
      cweId: entry.id,
      title: entry.name,
      score: Math.max(0, Math.min(rankingScore / 250, 1)),
      confidence: relevanceConfidence(exactEvidenceScore, categoryEvidenceScore, relationshipScore, exactPlatformMatch, languageMismatch),
      repositoryEvidenceScore,
      repositorySpecificEvidenceScore: exactEvidenceScore,
      repositoryCategoryEvidenceScore: categoryEvidenceScore,
      repositoryRelationshipEvidenceScore: relationshipScore,
      repositoryEvidenceCoverage: evidenceCoverage,
      taxonomyPriorityScore,
      rankingScore,
      exactPlatformMatch,
      concreteLanguageMismatch: languageMismatch,
      selectionTier: "",
    };
  }

  private taxonomyPriorityScore(entry: CweEntry, scope: ScanScope): number {
    let priority = 0;
    if (scope !== "auto" && entry.view_ids.includes(CURRENT_TOP_25_VIEW_ID)) priority += 100;
    if (entry.view_ids.includes(this.SIMPLIFIED_MAPPING_VIEW)) priority += 20;
    if (scope !== "auto" && entry.view_ids.includes(CURRENT_OWASP_VIEW_ID)) priority += 10;
    if (entry.view_ids.includes(this.SOFTWARE_DEVELOPMENT_VIEW)) priority += 5;
    priority += ({ Allowed: 5, "Allowed-with-Review": 3 } as Record<string, number>)[entry.mapping_usage] ?? 0;
    priority += ({ Base: 4, Variant: 3, Compound: 2, Class: 1 } as Record<string, number>)[entry.abstraction] ?? 0;
    priority += ({ High: 4, Medium: 2, Low: 1 } as Record<string, number>)[entry.likelihood_of_exploit] ?? 0;
    if (entry.status === "Stable") priority += 3;
    return priority;
  }

  private baseCheck(entry: CweEntry, score: number, confidence: number): SelectedCheck {
    return {
      cweId: entry.id,
      title: entry.name,
      score,
      confidence,
      repositoryEvidenceScore: 0,
      repositorySpecificEvidenceScore: 0,
      repositoryCategoryEvidenceScore: 0,
      repositoryRelationshipEvidenceScore: 0,
      repositoryEvidenceCoverage: 0,
      taxonomyPriorityScore: 0,
      rankingScore: 0,
      exactPlatformMatch: false,
      concreteLanguageMismatch: false,
      selectionTier: "",
    };
  }

  private entryForCweId(cweId: string): CweEntry {
    const entry = this.cweDatabase.getById(cweId);
    if (!entry) {
      throw new Error(`Unknown CWE ID after normalization: ${cweId}`);
    }
    return entry;
  }

  // --- portfolio selection ---

  private selectPortfolio(ranked: SelectedCheck[], limit: number, scope: ScanScope, profile: RepositoryProfile): SelectedCheck[] {
    if (scope === "auto") {
      return this.selectAutoRelevancePortfolio(ranked, limit);
    }
    const repositoryQuota = Math.max(1, Math.trunc((limit * 3) / 8));
    const baselineQuota = limit - repositoryQuota;
    const repositorySpecific = ranked
      .filter((c) => c.repositoryEvidenceScore > 0 && !this.isCurrentTop25Check(c))
      .sort(repositorySpecificCompare);
    const baseline = ranked.filter((c) => this.isPriorityBaselineCheck(c, profile));
    const chosen: SelectedCheck[] = [];
    const chosenIds = new Set<string>();
    extendUnique(chosen, chosenIds, repositorySpecific.slice(0, repositoryQuota), "repository-specific");
    extendUnique(chosen, chosenIds, baseline.slice(0, baselineQuota), "priority-baseline");
    extendUnique(chosen, chosenIds, baseline, "priority-baseline", limit);
    extendUnique(chosen, chosenIds, ranked, "ranked-fill", limit);
    return chosen.slice(0, limit);
  }

  private selectAutoRelevancePortfolio(ranked: SelectedCheck[], limit: number): SelectedCheck[] {
    const chosen: SelectedCheck[] = [];
    const deferred: SelectedCheck[] = [];
    const familyCounts = new Map<string, number>();
    for (const check of ranked) {
      const familyIds = this.relationshipFamilyIds(check.cweId);
      const hasDirectOrCategory = check.repositorySpecificEvidenceScore > 0 || check.repositoryCategoryEvidenceScore > 0;
      if (!hasDirectOrCategory && [...familyIds].some((id) => (familyCounts.get(id) ?? 0) >= this.FAMILY_CAP)) {
        deferred.push(check);
        continue;
      }
      chosen.push(withAutoRelevanceTier(check));
      for (const id of familyIds) {
        familyCounts.set(id, (familyCounts.get(id) ?? 0) + 1);
      }
      if (chosen.length >= limit) {
        return chosen;
      }
    }
    for (const check of deferred) {
      chosen.push(withAutoRelevanceTier(check));
      if (chosen.length >= limit) {
        break;
      }
    }
    return chosen;
  }

  private relationshipFamilyIds(cweId: string): Set<string> {
    const familyIds = new Set<string>([cweId]);
    const directParents = this.parentsByChild.get(cweId) ?? new Set();
    for (const p of directParents) {
      familyIds.add(p);
      for (const gp of this.parentsByChild.get(p) ?? new Set()) {
        familyIds.add(gp);
      }
    }
    return familyIds;
  }

  private entryViewIds(check: SelectedCheck): string[] {
    return this.cweDatabase.getById(check.cweId)?.view_ids ?? [];
  }

  private isCurrentTop25Check(check: SelectedCheck): boolean {
    return this.entryViewIds(check).includes(CURRENT_TOP_25_VIEW_ID);
  }

  private isPriorityBaselineCheck(check: SelectedCheck, profile: RepositoryProfile): boolean {
    if (!this.isCurrentTop25Check(check)) {
      return false;
    }
    if (check.repositoryEvidenceScore > 0) {
      return true;
    }
    const entry = this.cweDatabase.getById(check.cweId);
    return entry !== undefined && !hasConcreteLanguageMismatch(entry, profile);
  }
}

function levelExclusionReason(entry: CweEntry, cweLevel: string): string | null {
  if (cweLevel === "all") {
    return null;
  }
  if (entry.abstraction.toLowerCase() === cweLevel) {
    return null;
  }
  return `Excluded because MITRE abstraction is ${entry.abstraction || "unspecified"}, not ${cweLevel}`;
}

function automaticRankingScore(exactPlatformMatch: boolean, repositoryEvidenceScore: number, taxonomyPriorityScore: number, languageMismatch: boolean): number {
  let priority = repositoryEvidenceScore + taxonomyPriorityScore;
  if (exactPlatformMatch) priority += 30;
  if (languageMismatch) priority -= 80;
  return Math.max(0, priority);
}

function relevanceConfidence(exactEvidenceScore: number, categoryEvidenceScore: number, relationshipScore: number, exactPlatformMatch: boolean, languageMismatch: boolean): number {
  if (exactEvidenceScore > 0) return 0.9;
  if (categoryEvidenceScore > 0) return 0.75;
  if (relationshipScore > 0) return 0.6;
  if (exactPlatformMatch) return 0.5;
  if (languageMismatch) return 0.15;
  return 0.3;
}

function withAutoRelevanceTier(check: SelectedCheck): SelectedCheck {
  return { ...check, selectionTier: check.repositoryEvidenceScore > 0 ? "repository-specific" : "ranked-fill" };
}

function extendUnique(chosen: SelectedCheck[], chosenIds: Set<string>, candidates: SelectedCheck[], tier: string, limit?: number): void {
  for (const check of candidates) {
    if (limit !== undefined && chosen.length >= limit) {
      return;
    }
    if (chosenIds.has(check.cweId)) {
      continue;
    }
    chosen.push({ ...check, selectionTier: tier });
    chosenIds.add(check.cweId);
  }
}

function autoRelevanceCompare(a: SelectedCheck, b: SelectedCheck): number {
  return tupleCompare(autoRelevanceKey(a), autoRelevanceKey(b));
}

function autoRelevanceKey(check: SelectedCheck): number[] {
  const evidenceClass = check.repositorySpecificEvidenceScore > 0 ? 0
    : check.repositoryCategoryEvidenceScore > 0 ? 1
    : check.repositoryRelationshipEvidenceScore > 0 ? 2
    : check.exactPlatformMatch ? 3
    : check.concreteLanguageMismatch ? 5
    : 4;
  return [
    evidenceClass,
    -check.repositorySpecificEvidenceScore,
    -(check.repositorySpecificEvidenceScore ? 0 : check.repositoryCategoryEvidenceScore),
    -check.repositoryEvidenceCoverage,
    -check.repositoryCategoryEvidenceScore,
    -check.repositoryRelationshipEvidenceScore,
    -(check.exactPlatformMatch ? 1 : 0),
    check.concreteLanguageMismatch ? 1 : 0,
    -check.taxonomyPriorityScore,
    -check.rankingScore,
    cweNumber(check),
  ];
}

function rankedCheckKey(check: SelectedCheck): number[] {
  const rankingScore = check.rankingScore || Math.round(check.score * 250);
  return [-rankingScore, cweNumber(check)];
}

function rankedCheckCompare(a: SelectedCheck, b: SelectedCheck): number {
  return tupleCompare(rankedCheckKey(a), rankedCheckKey(b));
}

function repositorySpecificCompare(a: SelectedCheck, b: SelectedCheck): number {
  return tupleCompare(repositorySpecificKey(a), repositorySpecificKey(b));
}

function repositorySpecificKey(check: SelectedCheck): number[] {
  const evidenceClass = check.repositorySpecificEvidenceScore > 0 ? 0 : check.repositoryCategoryEvidenceScore > 0 ? 1 : 2;
  const [rankedScore, cweNum] = rankedCheckKey(check);
  return [
    evidenceClass,
    -check.repositorySpecificEvidenceScore,
    -check.repositoryCategoryEvidenceScore,
    -check.repositoryRelationshipEvidenceScore,
    rankedScore,
    cweNum,
  ];
}
