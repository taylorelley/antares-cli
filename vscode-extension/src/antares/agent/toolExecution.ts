// Port of antares_cli/agent/tool_execution.py — budget, dispatch, output formatting.

import { MAX_TOOL_OUTPUT_CHARS } from "../sandbox/shellPolicy";
import { ToolCallResult } from "./modelAdapter";
import { validateToolCallSafety } from "./quarantine";
import { ModelSessionState } from "./state";
import { ToolRouter } from "./toolRouter";

const REPOSITORY_COMMAND_TOOLS = new Set(["bash", "terminal", "read_file"]);
const MAX_TOOL_ERROR_CHARS = 2_000;
const TOOL_ERROR_TRUNCATION_SUFFIX = "...[tool error truncated]";
const AVAILABLE_TOOLS = "terminal, read_file, submit_vulnerable_files, submit_no_vulnerability_found";

export class AgentToolExecutor {
  constructor(private readonly toolRouter: ToolRouter) {}

  execute(
    toolName: string,
    args: Record<string, unknown>,
    state: ModelSessionState
  ): ToolCallResult {
    state.toolCallCount += 1;
    state.sessionTrace.recordToolCall({ toolName, arguments: args });

    const normalized = toolName.trim().toLowerCase();
    if (REPOSITORY_COMMAND_TOOLS.has(normalized)) {
      const budget = state.terminalCallBudget;
      if (budget !== null && state.terminalCallsUsed >= budget) {
        state.failedToolCallsCount += 1;
        return {
          toolName,
          toolResponse: `Terminal call budget exhausted (${budget}/${budget}). Submit your answer.`,
        };
      }
      state.terminalCallsUsed += 1;
    }

    const safety = validateToolCallSafety(toolName, args);
    if (safety.blocked) {
      state.failedToolCallsCount += 1;
      return { toolName, toolResponse: `Tool call blocked: ${safety.reason}` };
    }

    const result = this.toolRouter.execute(toolName, args);
    let response: string;
    if (!result.success) {
      response = this.recordToolError(toolName, result.errorMessage ?? "unknown error", state);
    } else {
      state.consecutiveErrors = 0;
      response = formatToolOutput(result.output);
    }

    const sanitized = state.contentQuarantine.sanitize(response);
    state.trajectory.push({ entry_type: "tool_call", content: `→ ${toolName}(${argsPreview(args)})` });
    state.trajectory.push({ entry_type: "tool_response", content: sanitized.slice(0, 500) });
    return { toolName, toolResponse: sanitized };
  }

  private recordToolError(toolName: string, error: string, state: ModelSessionState): string {
    state.consecutiveErrors += 1;
    state.failedToolCallsCount += 1;
    let message = boundToolError(`Tool ${toolName} failed: ${error}`);
    if (state.consecutiveErrors >= 2) {
      message += `\n\nAvailable tools: ${AVAILABLE_TOOLS}. Use one of these exact names.`;
    }
    return message;
  }
}

function argsPreview(args: Record<string, unknown>): string {
  return Object.entries(args)
    .map(([key, value]) => `${key}=${typeof value === "string" ? value : JSON.stringify(value)}`)
    .join(", ");
}

function formatToolOutput(output: Record<string, unknown>): string {
  if ("stdout" in output) {
    let text = String(output.stdout ?? "");
    const stderr = output.stderr ? String(output.stderr) : "";
    if (stderr) {
      text += `\n[stderr]: ${stderr}`;
    }
    if (output.truncated) {
      text +=
        `\n\n[OUTPUT TRUNCATED: showing first ${MAX_TOOL_OUTPUT_CHARS.toLocaleString("en-US")} ` +
        "characters. Use head/tail/sed with line ranges to read specific sections.]";
    }
    return text;
  }
  return JSON.stringify(output);
}

function boundToolError(message: string): string {
  const sanitized = message.replace(/[^\P{C}\n\t]/gu, "");
  if (sanitized.length <= MAX_TOOL_ERROR_CHARS) {
    return sanitized;
  }
  return sanitized.slice(0, MAX_TOOL_ERROR_CHARS - TOOL_ERROR_TRUNCATION_SUFFIX.length) + TOOL_ERROR_TRUNCATION_SUFFIX;
}
