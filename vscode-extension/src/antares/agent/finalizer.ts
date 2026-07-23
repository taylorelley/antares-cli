// Port of antares_cli/agent/finalizer.py — final answer fallback + summary.

import { AgentRunResult, ModelSessionState } from "./state";
import { isSubmitToolCall } from "./contracts";
import { makeSummary, ReportSummary } from "../output/finding";
import { ModelAdapter } from "./modelAdapter";
import { SubmissionHandler } from "./submission";

export class AgentRunFinalizer {
  constructor(
    private readonly adapter: ModelAdapter,
    private readonly submissionHandler: SubmissionHandler
  ) {}

  finalize(state: ModelSessionState): AgentRunResult {
    if (!state.resultSubmitted && state.submissionError === null) {
      this.runAnswerParserFallback(state);
    }
    const investigationTrace = state.sessionTrace.finalize({});
    return {
      findings: state.findings,
      summary: summaryForState(state),
      investigationTrace,
    };
  }

  private runAnswerParserFallback(state: ModelSessionState): void {
    const text = fallbackText(state);
    const submitCalls = this.adapter.extractSubmitToolCalls(text, isSubmitToolCall);
    for (const call of submitCalls) {
      this.submissionHandler.handle(call, state);
      if (state.resultSubmitted) {
        break;
      }
    }
    if (submitCalls.length > 0) {
      state.reasoningLog.push(
        `Submit parser: extracted ${state.findings.length} file-level finding(s) from free text.`
      );
    } else {
      state.reasoningLog.push(
        "Submit parser: no submit tool calls found in free text; no findings extracted."
      );
    }
  }
}

function fallbackText(state: ModelSessionState): string {
  if (state.answerText) {
    return state.answerText;
  }
  if (state.findings.length > 0) {
    return "";
  }
  return state.reasoningLog.join("\n");
}

function summaryForState(state: ModelSessionState): ReportSummary {
  const cweIds = new Set<string>();
  for (const finding of state.findings) {
    for (const cweId of finding.cwe_ids) {
      cweIds.add(cweId);
    }
  }
  const incompleteReason = state.resultSubmitted
    ? null
    : state.submissionError ?? "Model ended without an explicit final submission.";
  return makeSummary({
    total_findings: state.findings.length,
    tool_call_count: state.toolCallCount,
    duration_seconds: (Date.now() - state.startedAt) / 1000,
    investigation_trace: "",
    cwe_ids_triggered: [...cweIds].sort(),
    failed_tool_calls: state.failedToolCallsCount,
    retried_turns: state.retriedTurnsCount,
    generation_errors: state.generationErrors,
    incomplete_reason: incompleteReason,
  });
}
