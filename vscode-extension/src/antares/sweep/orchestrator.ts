// Port of antares_cli/agent/subagent.py — parallel per-CWE sweep workers.
// Model calls are HTTP-bound, so workers run as an async Promise pool (not OS threads).

import { AntaresAgentLoop } from "../agent/loop";
import { ModelAdapter } from "../agent/modelAdapter";
import { ToolRouter } from "../agent/toolRouter";
import { InferenceBackend } from "../inference/backend";
import { InferenceError } from "../inference/backend";
import { CweDatabase } from "../knowledge/cweDatabase";
import { compareFindings, Finding } from "../output/finding";

export interface WorkerTask {
  cweId: string;
  prompt: string;
  terminalCallBudget: number | null;
}

export interface WorkerResult {
  cweId: string;
  findings: Finding[];
  toolCallCount: number;
  durationSeconds: number;
  errorMessage: string | null;
  generationErrors: number;
  failedToolCalls: number;
  retriedTurns: number;
}

export interface SweepWorkerEvent {
  event: "started" | "progress" | "completed" | "failed";
  cweId: string;
  contextUsagePercent?: number;
  finding?: Finding;
  errorMessage?: string;
}

export interface MergedSweepResult {
  allFindings: Finding[];
  workerResults: WorkerResult[];
  totalToolCalls: number;
  completedTaskCount: number;
  failedTaskCount: number;
}

export interface OrchestratorDeps {
  target: string;
  backend: InferenceBackend;
  cweDatabase: CweDatabase;
  adapter: ModelAdapter;
  workerCount: number;
  onEvent?: (event: SweepWorkerEvent) => void;
}

export async function runOrchestratedSweep(
  tasks: WorkerTask[],
  deps: OrchestratorDeps
): Promise<MergedSweepResult> {
  const results = await runPool(tasks, Math.min(deps.workerCount, Math.max(1, tasks.length)), (task) =>
    executeWorkerTask(task, deps)
  );

  const merged = mergeFindings(results);
  const totalToolCalls = results.reduce((sum, r) => sum + r.toolCallCount, 0);
  const failed = results.filter((r) => r.errorMessage !== null).length;
  return {
    allFindings: merged,
    workerResults: results,
    totalToolCalls,
    completedTaskCount: results.length - failed,
    failedTaskCount: failed,
  };
}

async function executeWorkerTask(task: WorkerTask, deps: OrchestratorDeps): Promise<WorkerResult> {
  const started = Date.now();
  deps.onEvent?.({ event: "started", cweId: task.cweId });
  const loop = new AntaresAgentLoop({
    toolRouter: new ToolRouter(deps.target),
    cweDatabase: deps.cweDatabase,
    inferenceBackend: deps.backend,
    adapter: deps.adapter,
  });
  try {
    const result = await loop.runAudit(deps.target, {
      userQuery: task.prompt,
      focusCweIds: [task.cweId],
      terminalCallBudget: task.terminalCallBudget,
      progressCallback: (state, finding) => {
        deps.onEvent?.({
          event: "progress",
          cweId: task.cweId,
          contextUsagePercent: state.contextUsagePercent,
          finding: finding ?? undefined,
        });
      },
    });
    const workerResult: WorkerResult = {
      cweId: task.cweId,
      findings: result.findings,
      toolCallCount: result.summary.tool_call_count,
      durationSeconds: (Date.now() - started) / 1000,
      errorMessage: result.summary.incomplete_reason,
      generationErrors: result.summary.generation_errors,
      failedToolCalls: result.summary.failed_tool_calls,
      retriedTurns: result.summary.retried_turns,
    };
    deps.onEvent?.({
      event: workerResult.errorMessage ? "failed" : "completed",
      cweId: task.cweId,
      errorMessage: workerResult.errorMessage ?? undefined,
    });
    return workerResult;
  } catch (error) {
    const message =
      error instanceof InferenceError
        ? error.message
        : error instanceof Error
          ? error.message
          : String(error);
    deps.onEvent?.({ event: "failed", cweId: task.cweId, errorMessage: message });
    return {
      cweId: task.cweId,
      findings: [],
      toolCallCount: 0,
      durationSeconds: (Date.now() - started) / 1000,
      errorMessage: message,
      generationErrors: 0,
      failedToolCalls: 0,
      retriedTurns: 0,
    };
  }
}

// Worker-merge dedup: key (file_path, title), keep the higher-confidence finding.
function mergeFindings(results: WorkerResult[]): Finding[] {
  const keptByKey = new Map<string, Finding>();
  for (const result of results) {
    for (const finding of result.findings) {
      const key = JSON.stringify([finding.file_path, finding.title]);
      const existing = keptByKey.get(key);
      if (existing === undefined || finding.confidence > existing.confidence) {
        keptByKey.set(key, finding);
      }
    }
  }
  return [...keptByKey.values()].sort(compareFindings);
}

async function runPool<T, R>(items: T[], size: number, worker: (item: T) => Promise<R>): Promise<R[]> {
  const results = new Array<R>(items.length);
  let index = 0;
  const runner = async () => {
    while (index < items.length) {
      const current = index++;
      results[current] = await worker(items[current]);
    }
  };
  await Promise.all(Array.from({ length: Math.min(size, items.length) || 0 }, runner));
  return results;
}
