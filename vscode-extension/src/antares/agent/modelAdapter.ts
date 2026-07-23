// Port of antares_cli/agent/model_adapter.py — the single authoritative model config.

import { ChatMessage } from "../inference/backend";
import {
  SUBMIT_NO_VULNERABILITY_FOUND_TOOL,
  SUBMIT_VULNERABLE_FILES_TOOL,
  TERMINAL_TOOL_NAME,
} from "./contracts";
import { resolveTerminalCallBudget } from "./executionPolicy";
import { ANTARES_INVESTIGATION_PROMPT } from "./prompts";
import {
  ParsedEvent,
  ParsedToolCall,
  StreamingToolCallParser,
} from "./streamingParser";

const EOS_TOKENS = /<\|end_of_text\|>|<\|endoftext\|>|<\|eot_id\|>/g;
const THINK_TAGS = /<\/?think>/g;
const TOOL_CALL_BLOCK = /<tool_call>[\s\S]*?<\/tool_call>/g;

export interface ToolCallResult {
  toolName: string;
  toolResponse: string;
}

export interface ModelAdapterConfig {
  name: string;
  investigationSystemPrompt: string;
  preserveThinkInAnswer?: boolean;
  stripToolCallsFromText?: boolean;
  investigationNudgeFraction?: number;
  toolResponseRole?: string;
  noToolRetryLimit?: number;
}

export class ModelAdapter {
  readonly name: string;
  readonly investigationSystemPrompt: string;
  readonly preserveThinkInAnswer: boolean;
  readonly stripToolCallsFromText: boolean;
  readonly investigationNudgeFraction: number;
  readonly toolResponseRole: string;
  readonly noToolRetryLimit: number;

  constructor(config: ModelAdapterConfig) {
    this.name = config.name;
    this.investigationSystemPrompt = config.investigationSystemPrompt;
    this.preserveThinkInAnswer = config.preserveThinkInAnswer ?? false;
    this.stripToolCallsFromText = config.stripToolCallsFromText ?? true;
    this.investigationNudgeFraction = config.investigationNudgeFraction ?? 0.75;
    this.toolResponseRole = config.toolResponseRole ?? "user";
    this.noToolRetryLimit = config.noToolRetryLimit ?? 1;
  }

  buildSystemPrompt(terminalCallBudget: number | null | undefined): string {
    const resolvedBudget = resolveTerminalCallBudget(terminalCallBudget);
    return this.investigationSystemPrompt.split("{terminal_call_budget}").join(String(resolvedBudget));
  }

  createOutputParser(): StreamingToolCallParser {
    return new StreamingToolCallParser();
  }

  cleanModelText(text: string): string {
    let cleaned = text.replace(EOS_TOKENS, "");
    if (!this.preserveThinkInAnswer) {
      cleaned = cleaned.replace(THINK_TAGS, "");
    }
    if (this.stripToolCallsFromText) {
      cleaned = cleaned.replace(TOOL_CALL_BLOCK, "");
    }
    return cleaned.trim();
  }

  formatInitialMessages(systemPrompt: string, userContent: string): ChatMessage[] {
    return [
      { role: "system", content: systemPrompt },
      { role: "user", content: userContent },
    ];
  }

  formatNoToolRetry(iterationIndex = 0): ChatMessage {
    const isFinal = iterationIndex >= this.noToolRetryLimit - 1;
    let content: string;
    if (iterationIndex === 0) {
      content =
        "You must use tools to investigate before reporting. " +
        `Start by calling ${TERMINAL_TOOL_NAME} to examine the code. ` +
        `When finished, submit file paths with ${SUBMIT_VULNERABLE_FILES_TOOL} ` +
        `or call ${SUBMIT_NO_VULNERABILITY_FOUND_TOOL}.`;
    } else if (isFinal) {
      content =
        `Call ${SUBMIT_VULNERABLE_FILES_TOOL} with the file paths you identified, ` +
        `or call ${SUBMIT_NO_VULNERABILITY_FOUND_TOOL} if you found nothing.`;
    } else {
      content = `Continue investigating. Use ${TERMINAL_TOOL_NAME} to read more source files.`;
    }
    return { role: this.toolResponseRole, content };
  }

  formatDuplicateToolRetry(forceSubmit: boolean): ChatMessage {
    let content: string;
    if (forceSubmit) {
      content =
        "You have repeated the same tool calls 3 times. " +
        "Stop investigating. Summarize what you found and " +
        `submit file-level results now using ${SUBMIT_VULNERABLE_FILES_TOOL}. ` +
        `If you found nothing, call ${SUBMIT_NO_VULNERABILITY_FOUND_TOOL}.`;
    } else {
      content =
        "You already called these tools with these exact arguments. " +
        "Please try a different approach.";
    }
    return { role: this.toolResponseRole, content };
  }

  formatToolResults(results: ToolCallResult[], nudgeSuffix = ""): ChatMessage {
    let content: string;
    if (this.toolResponseRole === "tool_response") {
      content =
        results.length === 1
          ? results[0].toolResponse
          : results.map((r) => r.toolResponse).join("\n\n");
      if (nudgeSuffix) {
        content += nudgeSuffix;
      }
    } else if (results.length === 1) {
      content = `<tool_response>\n${results[0].toolResponse}${nudgeSuffix}\n</tool_response>`;
    } else {
      const sections = results.map(
        (result, index) =>
          `<tool_response id="${index + 1}">\n${result.toolResponse}\n</tool_response>`
      );
      content = sections.join("\n\n");
      if (nudgeSuffix) {
        content += nudgeSuffix;
      }
    }
    return { role: this.toolResponseRole, content };
  }

  extractSubmitToolCalls(
    text: string,
    isSubmitToolCall: (call: ParsedToolCall) => boolean
  ): ParsedToolCall[] {
    const parser = this.createOutputParser();
    const events: ParsedEvent[] = parser.feed(text);
    events.push(...parser.flush());
    return events.filter(
      (event): event is ParsedToolCall => event.kind === "tool_call" && isSubmitToolCall(event)
    );
  }
}

export const ANTARES_ADAPTER = new ModelAdapter({
  name: "antares",
  investigationSystemPrompt: ANTARES_INVESTIGATION_PROMPT,
  toolResponseRole: "tool_response",
  noToolRetryLimit: 5,
});

const MODEL_ADAPTER_REGISTRY: Record<string, ModelAdapter> = {
  antares: ANTARES_ADAPTER,
};

export const DEFAULT_ADAPTER = ANTARES_ADAPTER;

export function resolveModelAdapter(identifier: string): ModelAdapter {
  const normalized = identifier.toLowerCase().trim();
  return MODEL_ADAPTER_REGISTRY[normalized] ?? DEFAULT_ADAPTER;
}
