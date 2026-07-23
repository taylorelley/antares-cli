// Port of antares_cli/inference/granite.py — Granite prompt serialization and
// tokenizer-independent capacity bounds. The template must be byte-identical to
// what the /v1/completions endpoint receives.

import { ChatMessage } from "./backend";

const CONTEXT_SAFETY_TOKENS = 512;
const GRANITE_CONTROL_TOKENS = [
  "<|start_of_role|>",
  "<|end_of_role|>",
  "<|end_of_text|>",
  "<|endoftext|>",
  "<|eot_id|>",
] as const;
const TOOL_RESPONSE_DELIMITER = /<\/?tool_response(?:\s+[^>]*)?>/gi;
const ASSISTANT_PREFILL = "<|start_of_role|>assistant<|end_of_role|><think>\n";

export function applyGraniteChatTemplate(messages: ChatMessage[]): string {
  const parts = messages.map(serializeGraniteMessage);
  parts.push(ASSISTANT_PREFILL);
  return parts.join("\n");
}

export function graniteMessageTokenUpperBound(message: ChatMessage): number {
  return encodedSize(serializeGraniteMessage(message)) + 1;
}

export function granitePromptTokenUpperBound(messages: ChatMessage[]): number {
  return encodedSize(applyGraniteChatTemplate(messages));
}

function serializeGraniteMessage(message: ChatMessage): string {
  const role = message.role;
  let content = escapeGraniteControlTokens(message.content);
  if (role === "assistant") {
    const prefixed = content.startsWith("<think>") ? content : `<think>\n${content}`;
    return `<|start_of_role|>assistant<|end_of_role|>${prefixed}<|end_of_text|>`;
  }
  if (role === "tool_response") {
    content = content.replace(TOOL_RESPONSE_DELIMITER, "[escaped tool-response delimiter]");
    return (
      "<|start_of_role|>user<|end_of_role|>\n<tool_response>\n" +
      `${content}\n</tool_response><|end_of_text|>`
    );
  }
  return `<|start_of_role|>${role}<|end_of_role|>${content}<|end_of_text|>`;
}

function escapeGraniteControlTokens(content: string): string {
  let result = content;
  for (const token of GRANITE_CONTROL_TOKENS) {
    const tokenName = token.replace(/^<\|/, "").replace(/\|>$/, "");
    result = result.split(token).join(`[escaped Granite control token: ${tokenName}]`);
  }
  return result;
}

function encodedSize(text: string): number {
  return Buffer.byteLength(text, "utf-8");
}

export const FINAL_ASSISTANT_PREFILL_TOKEN_UPPER_BOUND = encodedSize(ASSISTANT_PREFILL);
const MINIMUM_SERIALIZED_MESSAGE_TOKENS = Math.max(
  ...(["system", "user", "assistant", "tool_response"] as const).map((role) =>
    graniteMessageTokenUpperBound({ role, content: "" })
  )
);
export const MINIMUM_SERIALIZED_PROMPT_TOKENS =
  2 * MINIMUM_SERIALIZED_MESSAGE_TOKENS + FINAL_ASSISTANT_PREFILL_TOKEN_UPPER_BOUND;

// Reserve output, template variance, and a usable serialized prompt.
export function promptTokenBudget(contextWindow: number, reservedOutputTokens: number): number {
  if (!Number.isInteger(contextWindow)) {
    throw new Error("Model context_window must be an integer");
  }
  if (!Number.isInteger(reservedOutputTokens)) {
    throw new Error("Reserved output tokens must be an integer");
  }
  if (contextWindow < 1 || reservedOutputTokens < 1) {
    throw new Error("Context window and reserved output tokens must be positive");
  }
  if (reservedOutputTokens >= contextWindow) {
    throw new Error("Reserved output tokens must be smaller than the context window");
  }

  const safetyTokens = Math.max(CONTEXT_SAFETY_TOKENS, Math.floor(contextWindow / 20));
  const available = contextWindow - reservedOutputTokens - safetyTokens;
  if (available < MINIMUM_SERIALIZED_PROMPT_TOKENS) {
    const requiredHeadroom = safetyTokens + MINIMUM_SERIALIZED_PROMPT_TOKENS;
    throw new Error(
      "Context window and max_tokens must leave at least " +
        `${requiredHeadroom} tokens for the serialized prompt and safety reserve`
    );
  }
  return available;
}
