// Port of antares_cli/agent/model_turn.py + model_turn_stream.py — one model turn.

import {
  InferenceBackend,
  InferenceContextLengthError,
  InferenceError,
  InferenceHttpError,
  InferenceStreamError,
} from "../inference/backend";
import { TrajectoryEntry } from "../output/finding";
import { ModelAdapter, ToolCallResult } from "./modelAdapter";
import { ModelSessionState, TurnResult } from "./state";
import { ParsedToolCall } from "./streamingParser";
import { SubmissionHandler } from "./submission";
import { AgentToolExecutor } from "./toolExecution";
import { AgentStateSnapshot, ProgressCallback } from "./types";

const MAX_PARSE_RETRIES = 2;
const MAX_MODEL_TURN_CHARS = 1_000_000;
const MAX_POST_BUDGET_SUBMISSION_ATTEMPTS = 3;

interface ParsedTurn {
  generationError: boolean;
  assistantText: string;
  toolCalls: ParsedToolCall[];
  doneSignaled: boolean;
  answerText: string | null;
  parseError: boolean;
}

interface ToolExecution {
  submitted: boolean;
  allDuplicates: boolean;
  executedToolCalls: ToolCallResult[];
}

export type BuildAgentStateFn = (
  messages: ModelSessionState["messages"],
  trajectory: TrajectoryEntry[]
) => AgentStateSnapshot;

export class ModelTurnRunner {
  constructor(
    private readonly backend: InferenceBackend,
    private readonly adapter: ModelAdapter,
    private readonly toolExecutor: AgentToolExecutor,
    private readonly submissionHandler: SubmissionHandler,
    private readonly buildAgentState: BuildAgentStateFn,
    private readonly isSubmitToolCall: (call: ParsedToolCall) => boolean
  ) {}

  async runTurn(
    state: ModelSessionState,
    iterationIndex: number,
    maximumIterations: number,
    progressCallback?: ProgressCallback
  ): Promise<TurnResult> {
    const parsed = await this.parseTurnWithRetries(state, progressCallback);
    if (parsed.generationError) {
      state.generationErrors += 1;
      state.reasoningLog.push(
        "Model generation error interrupted this run; results may be incomplete."
      );
      return { done: true };
    }

    if (isTerminalBudgetExhausted(state)) {
      const execution = this.executeToolCalls(parsed.toolCalls, state, progressCallback);
      if (execution.submitted || state.doneSignaled) {
        return { done: true };
      }
      return this.handlePostBudgetSubmissionAttempt(
        state,
        parsed.assistantText,
        execution.executedToolCalls,
        progressCallback
      );
    }

    if (parsed.toolCalls.length === 0) {
      return this.handleNoToolCalls(state, parsed.assistantText);
    }

    state.consecutiveNoToolTurns = 0;
    const execution = this.executeToolCalls(parsed.toolCalls, state, progressCallback);
    if (execution.submitted) {
      return { done: true };
    }
    if (execution.allDuplicates) {
      return this.handleDuplicateToolTurn(state, parsed.assistantText);
    }
    state.consecutiveDuplicateTurns = 0;
    return this.handleToolResults(
      state,
      parsed.assistantText,
      execution.executedToolCalls,
      iterationIndex,
      maximumIterations,
      progressCallback
    );
  }

  private async parseTurnWithRetries(
    state: ModelSessionState,
    progressCallback?: ProgressCallback
  ): Promise<ParsedTurn> {
    const retryParseErrors = !isTerminalBudgetExhausted(state);
    let attempt = await this.streamSingleAttempt(state, progressCallback);
    for (let retryIndex = 0; retryIndex < MAX_PARSE_RETRIES; retryIndex++) {
      if (attempt.generationError) {
        return attempt;
      }
      const shouldRetry =
        retryParseErrors &&
        attempt.parseError &&
        attempt.toolCalls.length === 0 &&
        !attempt.doneSignaled;
      if (!shouldRetry) {
        return attempt;
      }
      state.retriedTurnsCount += 1;
      state.reasoningLog.push(`Parse retry ${retryIndex + 1}/${MAX_PARSE_RETRIES}: retrying model turn`);
      attempt = await this.streamSingleAttempt(state, progressCallback);
    }
    return attempt;
  }

  private async streamSingleAttempt(
    state: ModelSessionState,
    progressCallback?: ProgressCallback
  ): Promise<ParsedTurn> {
    state.outputParser = this.adapter.createOutputParser();
    let assistantText = "";
    const toolCalls: ParsedToolCall[] = [];
    let doneSignaled = false;
    let answerText: string | null = null;
    let parseError = false;

    const consume = (events: ReturnType<typeof state.outputParser.feed>) => {
      for (const event of events) {
        if (event.kind === "tool_call") {
          toolCalls.push(event);
          this.publishProgress(state, progressCallback);
        } else if (event.kind === "done") {
          doneSignaled = true;
          state.trajectory.push({ entry_type: "think", content: "Investigation complete." });
        } else if (event.kind === "answer") {
          answerText = this.adapter.cleanModelText(event.text);
          doneSignaled = true;
        } else {
          parseError = parseError || event.text.startsWith("parse error:");
          const stripped = event.text.trim();
          if (stripped) {
            state.reasoningLog.push(stripped);
            state.trajectory.push({ entry_type: "think", content: stripped });
            this.publishProgress(state, progressCallback);
          }
        }
      }
    };

    try {
      for await (const chunk of this.backend.streamGenerate(state.messages)) {
        assistantText += chunk;
        if (assistantText.length > MAX_MODEL_TURN_CHARS) {
          return this.streamFailure(assistantText, toolCalls, doneSignaled, answerText);
        }
        consume(state.outputParser.feed(chunk));
      }
      consume(state.outputParser.flush());
    } catch (error) {
      if (error instanceof InferenceHttpError) {
        throw new InferenceError(httpErrorMessage(error));
      }
      if (error instanceof InferenceContextLengthError || error instanceof InferenceStreamError) {
        return this.streamFailure(assistantText, toolCalls, doneSignaled, answerText);
      }
      throw error;
    }

    return { generationError: false, assistantText, toolCalls, doneSignaled, answerText, parseError };
  }

  private streamFailure(
    assistantText: string,
    toolCalls: ParsedToolCall[],
    doneSignaled: boolean,
    answerText: string | null
  ): ParsedTurn {
    return { generationError: true, assistantText, toolCalls, doneSignaled, answerText, parseError: false };
  }

  private executeToolCalls(
    toolCalls: ParsedToolCall[],
    state: ModelSessionState,
    progressCallback?: ProgressCallback
  ): ToolExecution {
    const result: ToolExecution = { submitted: false, allDuplicates: true, executedToolCalls: [] };
    for (const parsedCall of toolCalls) {
      if (this.isSubmitToolCall(parsedCall)) {
        this.submissionHandler.handle(parsedCall, state, progressCallback);
        result.submitted = true;
        return result;
      }
      if (this.skipDuplicateToolCall(parsedCall, state)) {
        continue;
      }
      result.allDuplicates = false;
      result.executedToolCalls.push(this.toolExecutor.execute(parsedCall.toolName, parsedCall.arguments, state));
    }
    return result;
  }

  private skipDuplicateToolCall(parsedCall: ParsedToolCall, state: ModelSessionState): boolean {
    const dedupKey = stableStringify({ tool: parsedCall.toolName, args: parsedCall.arguments });
    if (!state.seenToolCalls.has(dedupKey)) {
      state.seenToolCalls.add(dedupKey);
      return false;
    }
    state.toolCallCount += 1;
    state.failedToolCallsCount += 1;
    state.reasoningLog.push(`Skipped duplicate tool call: ${parsedCall.toolName}`);
    return true;
  }

  private handleNoToolCalls(state: ModelSessionState, assistantText: string): TurnResult {
    const remainingText = this.adapter.cleanModelText(assistantText);
    if (remainingText && !state.answerText) {
      state.answerText = remainingText;
    }
    const retryIndex = state.consecutiveNoToolTurns;
    if (retryIndex < this.adapter.noToolRetryLimit && !state.doneSignaled) {
      state.consecutiveNoToolTurns += 1;
      state.messages.push({ role: "assistant", content: assistantText });
      appendTracedMessage(state, this.adapter.formatNoToolRetry(retryIndex));
      return { done: false };
    }
    return { done: true };
  }

  private handleDuplicateToolTurn(state: ModelSessionState, assistantText: string): TurnResult {
    state.consecutiveDuplicateTurns += 1;
    state.messages.push({ role: "assistant", content: assistantText });
    const forceSubmit = state.consecutiveDuplicateTurns >= 3;
    appendTracedMessage(state, this.adapter.formatDuplicateToolRetry(forceSubmit));
    if (forceSubmit) {
      state.reasoningLog.push("Loop stuck: 3 consecutive duplicate turns - forcing submit.");
      state.trajectory.push({
        entry_type: "think",
        content: "Stuck loop detected - forcing transition to submission.",
      });
    }
    return { done: false };
  }

  private handlePostBudgetSubmissionAttempt(
    state: ModelSessionState,
    assistantText: string,
    executedToolCalls: ToolCallResult[],
    progressCallback?: ProgressCallback
  ): TurnResult {
    state.postBudgetSubmissionAttempts += 1;
    state.messages.push({ role: "assistant", content: assistantText });
    if (state.postBudgetSubmissionAttempts >= MAX_POST_BUDGET_SUBMISSION_ATTEMPTS) {
      return { done: true };
    }
    appendTracedMessage(
      state,
      this.adapter.formatToolResults(executedToolCalls, submissionRequiredNudge(state))
    );
    this.publishProgress(state, progressCallback);
    return { done: false };
  }

  private handleToolResults(
    state: ModelSessionState,
    assistantText: string,
    executedToolCalls: ToolCallResult[],
    iterationIndex: number,
    maximumIterations: number,
    progressCallback?: ProgressCallback
  ): TurnResult {
    if (state.doneSignaled) {
      return { done: true };
    }
    state.messages.push({ role: "assistant", content: assistantText });
    let nudge = nudgeSuffix(this.adapter, state, iterationIndex, maximumIterations);
    if (isTerminalBudgetExhausted(state)) {
      nudge = submissionRequiredNudge(state);
    }
    appendTracedMessage(state, this.adapter.formatToolResults(executedToolCalls, nudge));
    this.publishProgress(state, progressCallback);
    return { done: false };
  }

  private publishProgress(state: ModelSessionState, progressCallback?: ProgressCallback): void {
    if (!progressCallback) {
      return;
    }
    progressCallback(this.buildAgentState(state.messages, state.trajectory), null);
  }
}

function isTerminalBudgetExhausted(state: ModelSessionState): boolean {
  if (state.terminalCallBudget === null) {
    return false;
  }
  return state.terminalCallsUsed >= state.terminalCallBudget;
}

function nudgeSuffix(
  adapter: ModelAdapter,
  state: ModelSessionState,
  iterationIndex: number,
  maximumIterations: number
): string {
  const budgetSuffix = terminalBudgetSuffix(state);
  const nudgeThreshold = Math.trunc(maximumIterations * adapter.investigationNudgeFraction);
  if (iterationIndex !== nudgeThreshold - 1) {
    return budgetSuffix;
  }
  state.trajectory.push({
    entry_type: "think",
    content: "Running low on turns - wrapping up investigation.",
  });
  return (
    "\n\nYou are running low on remaining turns. " +
    "Finish your investigation and submit file-level results now." +
    budgetSuffix
  );
}

function terminalBudgetSuffix(state: ModelSessionState): string {
  if (state.terminalCallBudget === null) {
    return "";
  }
  const remaining = state.terminalCallBudget - state.terminalCallsUsed;
  return `\n[${remaining} tool-calls remaining]`;
}

function submissionRequiredNudge(state: ModelSessionState): string {
  const budget = state.terminalCallBudget;
  return (
    `\nERROR: Repository tool budget exhausted (${budget}/${budget}). ` +
    "Submit now using either " +
    '<tool_call>{"name":"submit_vulnerable_files","arguments":{"ranked_files":' +
    '["path/to/file"]}}</tool_call> or ' +
    '<tool_call>{"name":"submit_no_vulnerability_found","arguments":{}}</tool_call>.'
  );
}

function appendTracedMessage(state: ModelSessionState, message: { role: string; content: string }): void {
  state.messages.push(message);
  state.sessionTrace.recordMessage(message);
}

function httpErrorMessage(error: InferenceHttpError): string {
  if (error.statusCode === 401) {
    return "Inference endpoint authentication failed (HTTP 401). Check the configured credentials.";
  }
  if (error.statusCode === 403) {
    return "Inference endpoint denied access (HTTP 403). Check the configured permissions.";
  }
  return `Inference endpoint request failed (HTTP ${error.statusCode}).`;
}

// Deterministic JSON with sorted keys (mirrors json.dumps(..., sort_keys=True)).
function stableStringify(value: unknown): string {
  return JSON.stringify(sortKeys(value));
}

function sortKeys(value: unknown): unknown {
  if (Array.isArray(value)) {
    return value.map(sortKeys);
  }
  if (value && typeof value === "object") {
    const sorted: Record<string, unknown> = {};
    for (const key of Object.keys(value as Record<string, unknown>).sort()) {
      sorted[key] = sortKeys((value as Record<string, unknown>)[key]);
    }
    return sorted;
  }
  return value;
}
