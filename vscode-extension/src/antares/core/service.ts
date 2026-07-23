// Port of the query path of antares_cli/core/service.py + core/runtime.py.

import * as path from "path";

import { AntaresAgentLoop } from "../agent/loop";
import { resolveModelAdapter } from "../agent/modelAdapter";
import { ToolRouter } from "../agent/toolRouter";
import { AgentRunResult } from "../agent/state";
import { ProgressCallback } from "../agent/types";
import { InferenceBackend } from "../inference/backend";
import { RemoteInferenceBackend } from "../inference/remote";
import { CweDatabase, CweEntry } from "../knowledge/cweDatabase";
import {
  deduplicateFindings,
  Finding,
  findingToDict,
  makeSummary,
  ReportSummary,
  summaryToPublicDict,
} from "../output/finding";
import { CweSelectionService } from "./cweSelection/engine";
import { CweSelectionRequest, ScanScope } from "./cweSelection/models";
import { loadSelectionTables } from "./cweSelection/tables";
import {
  runOrchestratedSweep,
  SweepWorkerEvent,
  WorkerTask,
} from "../sweep/orchestrator";
import { normalizeCweIds } from "./cwe";

export interface SweepRequest {
  target: string;
  cweIds?: string[];
  query?: string | null;
  model?: string | null;
  endpoint?: string | null;
  apiStyle?: string | null;
  apiKey?: string | null;
  terminalCallBudget?: number | null;
  workers?: number;
  maxCwes?: number;
  scope?: ScanScope;
}

export interface QueryRequest {
  target: string;
  cweIds: string[];
  query?: string | null;
  model?: string | null;
  endpoint?: string | null;
  backend?: string | null;
  apiStyle?: string | null;
  apiKey?: string | null;
  terminalCallBudget?: number | null;
}

export interface WorkflowResult {
  summary: ReportSummary;
  findings: Finding[];
  metadata: Record<string, unknown>;
  toDict(): Record<string, unknown>;
}

export class SecurityWorkflowService {
  constructor(private readonly dataDir: string) {}

  async runQuery(
    request: QueryRequest,
    progressCallback?: ProgressCallback
  ): Promise<WorkflowResult> {
    const cweDatabase = CweDatabase.loadDefault(this.dataDir);
    const cweIds = normalizeCweIds(request.cweIds, cweDatabase);

    const backend = buildRemoteBackend(request);
    const adapter = resolveModelAdapter(request.model ?? "antares");
    const toolRouter = new ToolRouter(request.target);
    const loop = new AntaresAgentLoop({
      toolRouter,
      cweDatabase,
      inferenceBackend: backend,
      adapter,
    });

    const agentResult: AgentRunResult = await loop.runAudit(request.target, {
      userQuery: cweAnalysisPrompt(cweIds, cweDatabase, request.query ?? null),
      focusCweIds: cweIds.length > 0 ? cweIds : null,
      progressCallback,
      terminalCallBudget: request.terminalCallBudget ?? null,
    });

    const findings = deduplicateFindings(agentResult.findings);
    const summary = summaryForFindings(findings, agentResult.summary);
    const metadata: Record<string, unknown> = {
      mode: "query",
      model: request.model ?? null,
      backend: "remote",
      cwe_ids: cweIds,
      query: request.query ?? null,
      target: path.basename(request.target),
      engine: "typescript",
    };
    return makeWorkflowResult(findings, summary, metadata);
  }

  async runCweSweep(
    request: SweepRequest,
    onEvent?: (event: SweepWorkerEvent) => void
  ): Promise<WorkflowResult> {
    const startedAt = Date.now();
    const cweDatabase = CweDatabase.loadDefault(this.dataDir);
    const tables = loadSelectionTables(this.dataDir);

    const selectionRequest: CweSelectionRequest = {
      target: request.target,
      cweIds: request.cweIds ?? [],
      ignorePaths: [],
      allowSensitiveFiles: [],
      scope: request.scope ?? "auto",
      cweLevel: "all",
      maxCwes: request.maxCwes && request.maxCwes > 0 ? request.maxCwes : 50,
    };
    const plan = new CweSelectionService(cweDatabase, tables).select(selectionRequest);
    const cweIds = plan.cweIds();

    const backend = buildRemoteBackend(request);
    const adapter = resolveModelAdapter(request.model ?? "antares");
    const tasks: WorkerTask[] = cweIds.map((cweId) => ({
      cweId,
      prompt: cweAnalysisPrompt([cweId], cweDatabase, request.query ?? null) ?? cweId,
      terminalCallBudget: request.terminalCallBudget ?? null,
    }));

    const merged = await runOrchestratedSweep(tasks, {
      target: request.target,
      backend,
      cweDatabase,
      adapter,
      workerCount: request.workers && request.workers > 0 ? request.workers : 8,
      onEvent,
    });

    const findings = deduplicateFindings(merged.allFindings);
    const summary = makeSummary({
      total_findings: findings.length,
      tool_call_count: merged.totalToolCalls,
      duration_seconds: (Date.now() - startedAt) / 1000,
      cwe_ids_triggered: [...new Set(findings.flatMap((f) => f.cwe_ids))].sort(),
      failed_tool_calls: merged.workerResults.reduce((s, r) => s + r.failedToolCalls, 0),
      retried_turns: merged.workerResults.reduce((s, r) => s + r.retriedTurns, 0),
      generation_errors: merged.workerResults.reduce((s, r) => s + r.generationErrors, 0),
      failed_workers: merged.failedTaskCount,
      total_workers: merged.completedTaskCount + merged.failedTaskCount,
    });
    const metadata: Record<string, unknown> = {
      mode: "cwe_sweep",
      model: request.model ?? null,
      backend: "remote",
      cwe_ids: cweIds,
      query: request.query ?? null,
      target: path.basename(request.target),
      engine: "typescript",
      selection: { scope: selectionRequest.scope, selected_cwe_ids: cweIds, policy: plan.selectionPolicy },
    };
    return makeWorkflowResult(findings, summary, metadata);
  }

  async runVerification(
    request: VerificationRequest,
    onEvent?: (event: VerificationWorkerEvent) => void
  ): Promise<VerificationResult[]> {
    const backend = buildRemoteBackend(request);
    const adapter = resolveModelAdapter(request.model ?? "antares");
    const cweDatabase = CweDatabase.loadDefault(this.dataDir);

    // WorkerTask per verification group (reuse runOrchestratedSweep for parallelism)
    const tasks: WorkerTask[] = request.groups.map((group) => ({
      cweId: group.cweId,
      prompt: verificationPrompt(group),
      terminalCallBudget: request.terminalCallBudget ?? null,
    }));

    // Wrap group index into events
    const wrappedOnEvent = onEvent
      ? (event: SweepWorkerEvent) => {
          // Find the group matching this cweId — for verification each task is a distinct group
          const groupIdx = request.groups.findIndex((g) => g.cweId === event.cweId);
          if (groupIdx === -1) return;
          const group = request.groups[groupIdx];
          onEvent({
            event: event.event === "progress" ? "started" : (event.event as "started" | "completed" | "failed"),
            groupIndex: groupIdx,
            group,
            verdict: undefined,
            errorMessage: event.errorMessage,
          });
        }
      : undefined;

    const merged = await runOrchestratedSweep(tasks, {
      target: request.target,
      backend,
      cweDatabase,
      adapter,
      workerCount: request.workers && request.workers > 0 ? request.workers : 8,
      onEvent: wrappedOnEvent,
    });

    // Map each worker result to a verdict
    const results: VerificationResult[] = request.groups.map((group, idx) => {
      const workerResult = merged.workerResults[idx];
      if (!workerResult || workerResult.errorMessage) {
        return { group, verdict: "uncertain" };
      }
      // If the agent submitted findings that match the flagged file → verified
      // If no findings → rejected
      // Error case → uncertain
      const fileFindings = workerResult.findings.filter(
        (f) => f.file_path === group.file
      );
      if (fileFindings.length > 0) {
        return { group, verdict: "verified", confidence: "medium" };
      }
      return { group, verdict: "rejected" };
    });

    // Emit completion events for each group
    if (onEvent) {
      for (let i = 0; i < results.length; i++) {
        onEvent({
          event: "completed",
          groupIndex: i,
          group: results[i].group,
          verdict: results[i].verdict,
        });
      }
    }

    return results;
  }
}

export function buildRemoteBackend(request: {
  model?: string | null;
  endpoint?: string | null;
  apiStyle?: string | null;
  apiKey?: string | null;
}): InferenceBackend {
  const model = (request.model ?? "").trim();
  if (!model) {
    throw new Error("Inference requires an explicit model ID (set the Antares: Model setting).");
  }
  const endpoint = (request.endpoint ?? "").trim();
  if (!endpoint) {
    throw new Error("Inference requires a configured endpoint.");
  }
  let useCompletionsApi: boolean | undefined;
  if (request.apiStyle === "chat") {
    useCompletionsApi = false;
  } else if (request.apiStyle === "completions") {
    useCompletionsApi = true;
  }
  return new RemoteInferenceBackend({
    modelId: model,
    endpoint,
    apiKey: request.apiKey ?? null,
    useCompletionsApi,
  });
}

export function makeWorkflowResult(
  findings: Finding[],
  summary: ReportSummary,
  metadata: Record<string, unknown>
): WorkflowResult {
  return {
    summary,
    findings,
    metadata,
    toDict(): Record<string, unknown> {
      const payload: Record<string, unknown> = {
        summary: summaryToPublicDict(summary),
        findings: findings.map(findingToDict),
        metadata,
      };
      const warnings = collectWarnings(summary);
      if (warnings.length > 0) {
        payload.warnings = warnings;
      }
      return payload;
    },
  };
}

export function summaryForFindings(findings: Finding[], source: ReportSummary): ReportSummary {
  const cweIds = new Set<string>();
  for (const finding of findings) {
    for (const cweId of finding.cwe_ids) {
      cweIds.add(cweId);
    }
  }
  return makeSummary({
    total_findings: findings.length,
    tool_call_count: source.tool_call_count,
    duration_seconds: source.duration_seconds,
    investigation_trace: source.investigation_trace,
    cwe_ids_triggered: [...cweIds].sort(),
    failed_tool_calls: source.failed_tool_calls,
    retried_turns: source.retried_turns,
    generation_errors: source.generation_errors,
    incomplete_reason: source.incomplete_reason,
  });
}

export function collectWarnings(summary: ReportSummary): string[] {
  const warnings: string[] = [];
  if (summary.generation_errors > 0) {
    warnings.push(
      `Model backend error interrupted the scan (${summary.generation_errors} error(s)); ` +
        "results may be incomplete"
    );
  }
  if (summary.failed_workers > 0) {
    warnings.push(
      `${summary.failed_workers}/${summary.total_workers} CWE workers failed; ` +
        "some vulnerability classes were not scanned"
    );
  }
  if (summary.incomplete_reason !== null) {
    warnings.push(summary.incomplete_reason);
  }
  return warnings;
}

function isPlaceholderCweEntry(entry: CweEntry): boolean {
  return (
    entry.name.startsWith("Placeholder CWE") ||
    entry.description.startsWith("Offline placeholder entry")
  );
}

// ---------------------------------------------------------------------------
// Verification types
// ---------------------------------------------------------------------------

export interface VerificationGroup {
  file: string;
  line: number;
  cweId: string;
  message: string;
  snippet: string;
}

export interface VerificationRequest {
  target: string;
  groups: VerificationGroup[];
  model?: string | null;
  endpoint?: string | null;
  apiStyle?: string | null;
  apiKey?: string | null;
  terminalCallBudget?: number | null;
  workers?: number;
}

export interface VerificationResult {
  group: VerificationGroup;
  verdict: "verified" | "rejected" | "uncertain";
  confidence?: string;
}

export interface VerificationWorkerEvent {
  event: "started" | "completed" | "failed";
  groupIndex: number;
  group: VerificationGroup;
  verdict?: "verified" | "rejected" | "uncertain";
  errorMessage?: string;
}

/**
 * Build the verification prompt for a single finding group.
 */
export function verificationPrompt(group: VerificationGroup): string {
  return [
    "Verify this suspected vulnerability:",
    `- File: ${group.file}`,
    `- Line: ${group.line}`,
    `- CWE: ${group.cweId}`,
    `- SAST tool reports: ${group.message}`,
    `- Code snippet: ${group.snippet}`,
    "",
    "Investigate the code at the specified location. If the vulnerability is genuine, submit the file. If it's a false positive, declare no vulnerability found.",
  ].join("\n");
}

export function cweAnalysisPrompt(
  cweIds: string[],
  cweDatabase: CweDatabase,
  query: string | null
): string | null {
  if (cweIds.length === 0) {
    return query;
  }
  const label = cweIds.length === 1 ? "vulnerability class" : "vulnerability classes";
  const contextText = cweIds.map((id) => cweContextBlock(id, cweDatabase)).join("\n\n");
  const closing =
    "Use the terminal tool to explore and determine if this vulnerability exists. " +
    "Then either submit the vulnerable file(s) or declare no vulnerability found.";
  const base = `Analyze this codebase for the following ${label}:\n\n${contextText}\n\n${closing}`;
  if (query) {
    return `${base}\n\nAdditional instructions:\n${query}`;
  }
  return base;
}

function cweContextBlock(cweId: string, cweDatabase: CweDatabase): string {
  const entry = cweDatabase.getById(cweId);
  if (!entry || isPlaceholderCweEntry(entry)) {
    return cweId;
  }
  const description = entry.description.trim();
  const parts = [`${entry.id}: ${entry.name}`];
  if (entry.likelihood_of_exploit) {
    parts.push(`Likelihood of Exploit: ${entry.likelihood_of_exploit}`);
  }
  parts.push(description);
  const extended = entry.extended_description.trim();
  if (extended && extended !== description) {
    parts.push(extended);
  }
  return parts.join("\n");
}
