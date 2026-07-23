// Port of antares_cli/agent/session.py — builds the initial ModelSessionState.

import * as path from "path";

import { ModelAdapter } from "./modelAdapter";
import { ContentQuarantine } from "./quarantine";
import { ModelSessionState } from "./state";
import { SessionTrace } from "./trace";

const DEFAULT_TASK_DESCRIPTION =
  "Search this repository for security vulnerabilities. Focus on: CWE-89 (SQL Injection), " +
  "CWE-78 (Command Injection), CWE-79 (XSS), CWE-798 (Hardcoded Credentials), " +
  "CWE-22 (Path Traversal), CWE-502 (Deserialization), CWE-306 (Missing Authentication). " +
  "Read source files and submit ranked vulnerable file paths only.";

export function defaultTaskDescription(
  userQuery: string | null | undefined,
  focusCweIds: string[]
): string {
  if (userQuery) {
    return userQuery;
  }
  if (focusCweIds.length > 0) {
    return (
      `Search this repository for vulnerabilities matching: ${focusCweIds.join(", ")}. ` +
      "Read source files, identify vulnerable code patterns, and submit ranked vulnerable file paths only."
    );
  }
  return DEFAULT_TASK_DESCRIPTION;
}

export function initializeSession(options: {
  repositoryPath: string;
  userQuery: string | null | undefined;
  focusCweIds: string[];
  adapter: ModelAdapter;
  terminalCallBudget: number;
}): ModelSessionState {
  const { repositoryPath, userQuery, focusCweIds, adapter, terminalCallBudget } = options;
  const sessionTrace = new SessionTrace(path.basename(repositoryPath));
  const contentQuarantine = new ContentQuarantine();

  sessionTrace.recordEvent("ingest", { path: repositoryPath, query: userQuery ?? null });

  const systemPrompt = adapter.buildSystemPrompt(terminalCallBudget);
  const userContent = defaultTaskDescription(userQuery, focusCweIds);
  const messages = adapter.formatInitialMessages(systemPrompt, userContent);
  for (const message of messages) {
    sessionTrace.recordMessage(message);
  }

  return {
    findings: [],
    dedupeKeys: new Set(),
    reasoningLog: [],
    toolCallCount: 0,
    messages,
    sessionTrace,
    contentQuarantine,
    outputParser: adapter.createOutputParser(),
    doneSignaled: false,
    answerText: null,
    consecutiveErrors: 0,
    retriedTurnsCount: 0,
    failedToolCallsCount: 0,
    seenToolCalls: new Set(),
    startedAt: Date.now(),
    repositoryPath,
    focusCweIds,
    resultSubmitted: false,
    submissionError: null,
    consecutiveNoToolTurns: 0,
    consecutiveDuplicateTurns: 0,
    trajectory: [],
    terminalCallBudget,
    terminalCallsUsed: 0,
    postBudgetSubmissionAttempts: 0,
    generationErrors: 0,
  };
}
