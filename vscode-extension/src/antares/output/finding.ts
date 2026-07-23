// Port of antares_cli/output/finding.py — Finding, ReportSummary, dedup + ordering.

import { normalizeCweId } from "../core/cwe";

export interface Finding {
  title: string;
  file_path: string;
  cwe_ids: string[];
  confidence: number;
  submission_rank: number | null;
  likelihood_of_exploit: string;
}

export type TrajectoryEntryType = "think" | "tool_call" | "tool_response" | "finding";

export interface TrajectoryEntry {
  entry_type: TrajectoryEntryType;
  content: string;
}

export interface ReportSummary {
  total_findings: number;
  tool_call_count: number;
  duration_seconds: number;
  cwe_ids_triggered: string[];
  investigation_trace: string | null;
  failed_tool_calls: number;
  retried_turns: number;
  generation_errors: number;
  failed_workers: number;
  total_workers: number;
  incomplete_reason: string | null;
}

export function makeFinding(partial: Partial<Finding> & { title: string; file_path: string }): Finding {
  return {
    title: partial.title,
    file_path: partial.file_path,
    cwe_ids: partial.cwe_ids ?? [],
    confidence: partial.confidence ?? 0.5,
    submission_rank: partial.submission_rank ?? null,
    likelihood_of_exploit: partial.likelihood_of_exploit ?? "",
  };
}

// Public finding contract: drops confidence; drops submission_rank when null.
export function findingToDict(finding: Finding): Record<string, unknown> {
  const payload: Record<string, unknown> = {
    title: finding.title,
    file_path: finding.file_path,
    cwe_ids: finding.cwe_ids,
    likelihood_of_exploit: finding.likelihood_of_exploit,
  };
  if (finding.submission_rank !== null) {
    payload.submission_rank = finding.submission_rank;
  }
  return payload;
}

export function makeSummary(partial: Partial<ReportSummary>): ReportSummary {
  return {
    total_findings: partial.total_findings ?? 0,
    tool_call_count: partial.tool_call_count ?? 0,
    duration_seconds: partial.duration_seconds ?? 0,
    cwe_ids_triggered: partial.cwe_ids_triggered ?? [],
    investigation_trace: partial.investigation_trace ?? null,
    failed_tool_calls: partial.failed_tool_calls ?? 0,
    retried_turns: partial.retried_turns ?? 0,
    generation_errors: partial.generation_errors ?? 0,
    failed_workers: partial.failed_workers ?? 0,
    total_workers: partial.total_workers ?? 0,
    incomplete_reason: partial.incomplete_reason ?? null,
  };
}

export function summaryToPublicDict(summary: ReportSummary): Record<string, unknown> {
  const { investigation_trace, ...rest } = summary;
  void investigation_trace;
  return { ...rest };
}

function normalizeFindingPath(rawPath: string): string {
  const p = rawPath.trim().replace(/\\/g, "/");
  if (!p) {
    return p;
  }
  return posixNormpath(p);
}

function posixNormpath(p: string): string {
  const isAbsolute = p.startsWith("/");
  const out: string[] = [];
  for (const segment of p.split("/")) {
    if (segment === "" || segment === ".") {
      continue;
    }
    if (segment === "..") {
      if (out.length > 0 && out[out.length - 1] !== "..") {
        out.pop();
      } else if (!isAbsolute) {
        out.push("..");
      }
    } else {
      out.push(segment);
    }
  }
  const joined = out.join("/");
  return isAbsolute ? "/" + joined : joined || ".";
}

// Deduplicate by canonical path + exact CWE scope, keeping the higher-confidence entry.
export function deduplicateFindings(findings: Finding[]): Finding[] {
  const keptByKey = new Map<string, Finding>();
  for (const finding of findings) {
    const normalized: Finding = {
      ...finding,
      file_path: normalizeFindingPath(finding.file_path),
      cwe_ids: [...new Set(finding.cwe_ids.map((c) => normalizeCweId(c, false)))],
    };
    const key = JSON.stringify([normalized.file_path, [...normalized.cwe_ids].sort()]);
    const existing = keptByKey.get(key);
    if (existing === undefined || normalized.confidence > existing.confidence) {
      keptByKey.set(key, normalized);
    }
  }
  const kept = [...keptByKey.values()];
  kept.sort(compareFindings);
  return kept;
}

export function compareFindings(a: Finding, b: Finding): number {
  const aCwe = a.cwe_ids[0] ?? "";
  const bCwe = b.cwe_ids[0] ?? "";
  if (aCwe !== bCwe) {
    return aCwe < bCwe ? -1 : 1;
  }
  const aNull = a.submission_rank === null ? 1 : 0;
  const bNull = b.submission_rank === null ? 1 : 0;
  if (aNull !== bNull) {
    return aNull - bNull;
  }
  const aRank = a.submission_rank ?? 0;
  const bRank = b.submission_rank ?? 0;
  if (aRank !== bRank) {
    return aRank - bRank;
  }
  if (a.file_path !== b.file_path) {
    return a.file_path < b.file_path ? -1 : 1;
  }
  if (a.title !== b.title) {
    return a.title < b.title ? -1 : 1;
  }
  return 0;
}
