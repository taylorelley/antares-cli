// Port of the agent session state (antares_cli/agent/state.py).

import { ChatMessage } from "../inference/backend";
import { Finding, ReportSummary, TrajectoryEntry } from "../output/finding";
import { ContentQuarantine } from "./quarantine";
import { StreamingToolCallParser } from "./streamingParser";
import { SessionTrace } from "./trace";

export interface ModelSessionState {
  findings: Finding[];
  dedupeKeys: Set<string>;
  reasoningLog: string[];
  toolCallCount: number;
  messages: ChatMessage[];
  sessionTrace: SessionTrace;
  contentQuarantine: ContentQuarantine;
  outputParser: StreamingToolCallParser;
  doneSignaled: boolean;
  answerText: string | null;
  consecutiveErrors: number;
  retriedTurnsCount: number;
  failedToolCallsCount: number;
  seenToolCalls: Set<string>;
  startedAt: number;
  repositoryPath: string;
  focusCweIds: string[];
  resultSubmitted: boolean;
  submissionError: string | null;
  consecutiveNoToolTurns: number;
  consecutiveDuplicateTurns: number;
  trajectory: TrajectoryEntry[];
  terminalCallBudget: number | null;
  terminalCallsUsed: number;
  postBudgetSubmissionAttempts: number;
  generationErrors: number;
}

export interface AgentRunResult {
  findings: Finding[];
  summary: ReportSummary;
  investigationTrace: string;
}

export interface TurnResult {
  done: boolean;
}
