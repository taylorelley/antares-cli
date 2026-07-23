// Port of antares_cli/agent/loop.py — the top-level model-driven audit loop.

import { InferenceBackend } from "../inference/backend";
import { granitePromptTokenUpperBound, promptTokenBudget } from "../inference/granite";
import { CweDatabase } from "../knowledge/cweDatabase";
import { TrajectoryEntry } from "../output/finding";
import { isSubmitToolCall } from "./contracts";
import { resolveTerminalCallBudget } from "./executionPolicy";
import { AgentRunFinalizer } from "./finalizer";
import { ModelAdapter } from "./modelAdapter";
import { ModelTurnRunner } from "./modelTurn";
import { initializeSession } from "./session";
import { AgentRunResult, ModelSessionState } from "./state";
import { SubmissionHandler } from "./submission";
import { AgentToolExecutor } from "./toolExecution";
import { ToolRouter } from "./toolRouter";
import { AgentStateSnapshot, ProgressCallback } from "./types";

export const MAXIMUM_MODEL_LOOP_ITERATIONS = 50;

export class ModelBackendRequiredError extends Error {}

export interface AgentLoopDeps {
  toolRouter: ToolRouter;
  cweDatabase: CweDatabase;
  inferenceBackend: InferenceBackend | null;
  adapter: ModelAdapter;
}

export interface RunAuditOptions {
  userQuery?: string | null;
  focusCweIds?: string[] | null;
  progressCallback?: ProgressCallback;
  terminalCallBudget?: number | null;
}

export class AntaresAgentLoop {
  constructor(private readonly deps: AgentLoopDeps) {}

  async runAudit(repoPath: string, options: RunAuditOptions = {}): Promise<AgentRunResult> {
    const backend = this.deps.inferenceBackend;
    if (backend === null) {
      throw new ModelBackendRequiredError(
        "No inference backend is available for model-driven audit. " +
          "Provide model weights or configure a remote endpoint/API key."
      );
    }

    const resolvedBudget = resolveTerminalCallBudget(options.terminalCallBudget ?? null);

    const buildAgentState = (
      messages: ModelSessionState["messages"],
      trajectory: TrajectoryEntry[]
    ): AgentStateSnapshot => ({
      contextUsagePercent: computeContextUsagePercent(backend, messages),
      trajectory,
    });

    const submissionHandler = new SubmissionHandler(this.deps.cweDatabase, repoPath, buildAgentState);
    const toolExecutor = new AgentToolExecutor(this.deps.toolRouter);
    const turnRunner = new ModelTurnRunner(
      backend,
      this.deps.adapter,
      toolExecutor,
      submissionHandler,
      buildAgentState,
      isSubmitToolCall
    );
    const finalizer = new AgentRunFinalizer(this.deps.adapter, submissionHandler);

    const state = initializeSession({
      repositoryPath: repoPath,
      userQuery: options.userQuery ?? null,
      focusCweIds: options.focusCweIds ?? [],
      adapter: this.deps.adapter,
      terminalCallBudget: resolvedBudget,
    });

    try {
      for (let iteration = 0; iteration < MAXIMUM_MODEL_LOOP_ITERATIONS; iteration++) {
        const turn = await turnRunner.runTurn(
          state,
          iteration,
          MAXIMUM_MODEL_LOOP_ITERATIONS,
          options.progressCallback
        );
        if (turn.done) {
          break;
        }
      }
      return finalizer.finalize(state);
    } catch (error) {
      state.sessionTrace.finalizeError(error);
      throw error;
    }
  }
}

function computeContextUsagePercent(
  backend: InferenceBackend,
  messages: { role: string; content: string }[]
): number {
  const reservedOutputTokens = Number.isInteger(backend.maxTokens) ? backend.maxTokens : 4096;
  let budget: number;
  try {
    budget = promptTokenBudget(backend.contextWindow, reservedOutputTokens);
  } catch {
    return 0;
  }
  const used = granitePromptTokenUpperBound(messages);
  return Math.min(100, Math.floor((used / budget) * 100));
}
