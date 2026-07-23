// Port of antares_cli/inference/remote.py — OpenAI-compatible streaming backend.
// Uses the Node global fetch (Node 18+) for SSE streaming; no HTTP package needed.

import {
  ChatMessage,
  InferenceBackend,
  InferenceContextLengthError,
  InferenceHttpError,
  InferenceStreamError,
} from "./backend";
import {
  DEFAULT_ANTARES_CONTEXT_WINDOW,
  DEFAULT_ANTARES_FREQUENCY_PENALTY,
  DEFAULT_ANTARES_MAX_TOKENS,
  DEFAULT_ANTARES_REMOTE_TIMEOUT_SECONDS,
  DEFAULT_ANTARES_STOP_TOKENS,
  DEFAULT_ANTARES_TEMPERATURE,
  DEFAULT_ANTARES_TOP_P,
  DEFAULT_ANTARES_USE_COMPLETIONS_API,
} from "./defaults";
import { applyGraniteChatTemplate, promptTokenBudget } from "./granite";

const COLD_START_RETRY_DELAY = 5.0;
const COLD_START_MAX_RETRIES = 6;
const MAX_RETRY_DELAY_SECONDS = 30.0;
const MAX_SSE_LINE_CHARS = 1_000_000;
const MAX_STREAM_CHARS = 4_000_000;
const MAX_ERROR_BODY_CHARS = 16_384;
const TRANSIENT_HTTP_STATUS_CODES = new Set([404, 408, 429, 500, 502, 503, 504]);

const CONTEXT_REJECTION_INDICATORS = [
  "maximum context length",
  "context length exceeded",
  "context_length_exceeded",
  "max_model_len",
  "prompt is too long",
  "input is too long",
  "too many input tokens",
];

export interface RemoteBackendOptions {
  modelId: string;
  endpoint: string;
  contextWindow?: number;
  timeoutSeconds?: number;
  apiKey?: string | null;
  retryCount?: number;
  retryDelay?: number;
  maxTokens?: number;
  temperature?: number | null;
  topP?: number | null;
  repetitionPenalty?: number | null;
  frequencyPenalty?: number | null;
  stopTokens?: string[] | null;
  useCompletionsApi?: boolean;
}

function validateGenerationValue(
  name: string,
  value: number | null | undefined,
  minimum: number,
  maximum: number | null,
  minimumOpen = false
): void {
  if (value === null || value === undefined) {
    return;
  }
  if (typeof value !== "number" || Number.isNaN(value)) {
    throw new Error(`Remote inference ${name} must be numeric`);
  }
  const belowMinimum = minimumOpen ? value <= minimum : value < minimum;
  if (!Number.isFinite(value) || belowMinimum || (maximum !== null && value > maximum)) {
    throw new Error(`Remote inference ${name} is out of range`);
  }
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, Math.max(0, ms)));
}

export class RemoteInferenceBackend implements InferenceBackend {
  readonly modelId: string;
  readonly contextWindow: number;
  readonly maxTokens: number;
  readonly endpoint: string;
  readonly useCompletionsApi: boolean;

  private readonly timeoutSeconds: number;
  private readonly retryCount: number;
  private readonly retryDelay: number;
  private readonly temperature: number | null;
  private readonly topP: number | null;
  private readonly repetitionPenalty: number | null;
  private readonly frequencyPenalty: number | null;
  private readonly stopTokens: string[];
  private readonly headers: Record<string, string>;

  constructor(options: RemoteBackendOptions) {
    this.modelId = options.modelId;
    this.contextWindow = options.contextWindow ?? DEFAULT_ANTARES_CONTEXT_WINDOW;
    this.maxTokens = options.maxTokens ?? DEFAULT_ANTARES_MAX_TOKENS;
    this.timeoutSeconds = options.timeoutSeconds ?? DEFAULT_ANTARES_REMOTE_TIMEOUT_SECONDS;
    this.retryDelay = options.retryDelay ?? COLD_START_RETRY_DELAY;
    this.retryCount = options.retryCount ?? COLD_START_MAX_RETRIES;
    this.temperature = options.temperature ?? DEFAULT_ANTARES_TEMPERATURE;
    this.topP = options.topP ?? DEFAULT_ANTARES_TOP_P;
    this.repetitionPenalty = options.repetitionPenalty ?? null;
    this.frequencyPenalty = options.frequencyPenalty ?? DEFAULT_ANTARES_FREQUENCY_PENALTY;
    this.stopTokens = options.stopTokens ?? [...DEFAULT_ANTARES_STOP_TOKENS];

    const normalizedEndpoint = options.endpoint.trim().replace(/\/+$/, "");
    let parsed: URL;
    try {
      parsed = new URL(normalizedEndpoint);
    } catch {
      throw new Error("Remote inference endpoint must be an HTTP(S) URL");
    }
    if (
      (parsed.protocol !== "http:" && parsed.protocol !== "https:") ||
      parsed.username ||
      parsed.password ||
      parsed.search ||
      parsed.hash
    ) {
      throw new Error(
        "Remote inference endpoint must be an HTTP(S) URL without embedded " +
          "credentials, query parameters, or fragments"
      );
    }
    if (!Number.isFinite(this.timeoutSeconds) || this.timeoutSeconds <= 0) {
      throw new Error("Remote inference timeout must be a finite number greater than zero");
    }
    if (!Number.isInteger(this.retryCount) || this.retryCount < 1) {
      throw new Error("Remote inference retry count must be at least one");
    }
    if (!Number.isFinite(this.retryDelay) || this.retryDelay < 0) {
      throw new Error("Remote inference retry delay must be a finite non-negative number");
    }
    if (!Number.isInteger(this.maxTokens) || this.maxTokens < 1) {
      throw new Error("Remote inference max_tokens must be at least one");
    }
    if (this.maxTokens >= this.contextWindow) {
      throw new Error("Remote inference max_tokens must be smaller than context_window");
    }
    promptTokenBudget(this.contextWindow, this.maxTokens);
    validateGenerationValue("temperature", this.temperature, 0.0, 2.0);
    validateGenerationValue("top_p", this.topP, 0.0, 1.0, true);
    validateGenerationValue("repetition_penalty", this.repetitionPenalty, 0.0, null, true);
    validateGenerationValue("frequency_penalty", this.frequencyPenalty, -2.0, 2.0);

    this.endpoint = normalizedEndpoint;
    this.useCompletionsApi =
      (options.useCompletionsApi ?? DEFAULT_ANTARES_USE_COMPLETIONS_API) ||
      (normalizedEndpoint.endsWith("/v1/completions") &&
        !normalizedEndpoint.includes("/chat/completions"));

    this.headers = { "Content-Type": "application/json" };
    if (options.apiKey) {
      this.headers.Authorization = `Bearer ${options.apiKey}`;
    }
  }

  streamGenerate(messages: ChatMessage[]): AsyncIterable<string> {
    return this.useCompletionsApi
      ? this.streamResponse(this.completionsPayload(messages), "/completions", "text")
      : this.streamResponse(this.chatPayload(messages), "/chat/completions", "delta");
  }

  private commonGenerationFields(payload: Record<string, unknown>): void {
    if (this.temperature !== null) {
      payload.temperature = this.temperature;
    }
    if (this.topP !== null) {
      payload.top_p = this.topP;
    }
    if (this.repetitionPenalty !== null) {
      payload.repetition_penalty = this.repetitionPenalty;
    }
    if (this.frequencyPenalty !== null) {
      payload.frequency_penalty = this.frequencyPenalty;
    }
    if (this.stopTokens.length > 0) {
      payload.stop = this.stopTokens;
    }
  }

  private chatPayload(messages: ChatMessage[]): Record<string, unknown> {
    const payload: Record<string, unknown> = {
      model: this.modelId,
      messages,
      stream: true,
      max_tokens: this.maxTokens,
    };
    this.commonGenerationFields(payload);
    return payload;
  }

  private completionsPayload(messages: ChatMessage[]): Record<string, unknown> {
    const payload: Record<string, unknown> = {
      model: this.modelId,
      prompt: applyGraniteChatTemplate(messages),
      stream: true,
      max_tokens: this.maxTokens,
    };
    this.commonGenerationFields(payload);
    return payload;
  }

  private resolveUrl(pathSuffix: string): string {
    let base = this.endpoint;
    if (base.endsWith("/chat/completions")) {
      base = base.slice(0, -"/chat/completions".length);
    } else if (base.endsWith("/v1/completions")) {
      base = base.slice(0, -"/v1/completions".length);
    } else if (base.endsWith("/completions")) {
      base = base.slice(0, -"/completions".length);
    }
    if (!base.endsWith("/v1")) {
      base = `${base}/v1`;
    }
    return `${base}${pathSuffix}`;
  }

  private async *streamResponse(
    payload: Record<string, unknown>,
    pathSuffix: string,
    contentKey: "delta" | "text"
  ): AsyncGenerator<string> {
    const url = this.resolveUrl(pathSuffix);
    const body = JSON.stringify(payload);
    const deadline = Date.now() + this.timeoutSeconds * 1000;

    for (let attempt = 0; attempt < this.retryCount; attempt++) {
      let yielded = false;
      let retryAfter: number | null = null;
      const remaining = remainingMs(deadline);
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), remaining);
      try {
        const response = await fetch(url, {
          method: "POST",
          headers: this.headers,
          body,
          signal: controller.signal,
        });

        if (
          TRANSIENT_HTTP_STATUS_CODES.has(response.status) &&
          attempt < this.retryCount - 1
        ) {
          retryAfter = parseRetryAfter(response);
          await response.body?.cancel();
        } else {
          if (response.status === 400) {
            const text = (await response.text()).slice(0, MAX_ERROR_BODY_CHARS).toLowerCase();
            if (CONTEXT_REJECTION_INDICATORS.some((indicator) => text.includes(indicator))) {
              throw new InferenceContextLengthError(
                "Inference request exceeded the model context capacity."
              );
            }
            throw new InferenceHttpError(400, "Inference endpoint request failed (HTTP 400).");
          }
          if (!response.ok) {
            throw new InferenceHttpError(
              response.status,
              `Inference endpoint request failed (HTTP ${response.status}).`
            );
          }
          for await (const line of iterSseLines(response, deadline)) {
            const { done, content } = contentFromSseLine(line, contentKey);
            if (done) {
              return;
            }
            if (content !== null) {
              yielded = true;
              yield content;
            }
          }
          throw new InferenceStreamError(
            "Inference response stream ended before completion."
          );
        }
      } catch (error) {
        // Deterministic errors propagate; only network/abort errors are retried.
        if (
          error instanceof InferenceContextLengthError ||
          error instanceof InferenceHttpError ||
          error instanceof InferenceStreamError
        ) {
          throw error;
        }
        if (Date.now() >= deadline) {
          throw new InferenceStreamError("Inference request exceeded the configured timeout.");
        }
        if (yielded) {
          throw new InferenceStreamError(
            "Inference response stream ended before completion."
          );
        }
        if (attempt >= this.retryCount - 1) {
          throw error;
        }
      } finally {
        clearTimeout(timer);
      }

      if (attempt < this.retryCount - 1) {
        const delayMs =
          (retryAfter ?? exponentialRetryDelay(this.retryDelay, attempt)) * 1000;
        await sleep(Math.min(delayMs, remainingMs(deadline)));
      }
    }
  }
}

function remainingMs(deadline: number): number {
  const remaining = deadline - Date.now();
  if (remaining <= 0) {
    throw new InferenceStreamError("Inference request exceeded the configured timeout.");
  }
  return remaining;
}

function parseRetryAfter(response: Response): number | null {
  const raw = response.headers.get("retry-after");
  if (raw === null) {
    return null;
  }
  const value = Number.parseFloat(raw);
  if (!Number.isFinite(value) || value < 0) {
    return null;
  }
  return Math.min(value, MAX_RETRY_DELAY_SECONDS);
}

function exponentialRetryDelay(baseDelay: number, attempt: number): number {
  const maximum = Math.min(MAX_RETRY_DELAY_SECONDS, baseDelay * 2 ** attempt);
  return Math.random() * maximum;
}

async function* iterSseLines(response: Response, deadline: number): AsyncGenerator<string> {
  if (!response.body) {
    return;
  }
  const reader = response.body.getReader();
  const decoder = new TextDecoder("utf-8");
  let pending = "";
  let total = 0;
  try {
    for (;;) {
      remainingMs(deadline);
      const { done, value } = await reader.read();
      if (done) {
        break;
      }
      const text = decoder.decode(value, { stream: true });
      total += text.length;
      if (total > MAX_STREAM_CHARS) {
        throw new InferenceStreamError("Inference response exceeded the streaming size limit.");
      }
      pending += text;
      let newlineIndex: number;
      while ((newlineIndex = pending.indexOf("\n")) >= 0) {
        let line = pending.slice(0, newlineIndex);
        pending = pending.slice(newlineIndex + 1);
        if (line.endsWith("\r")) {
          line = line.slice(0, -1);
        }
        if (line.length > MAX_SSE_LINE_CHARS) {
          throw new InferenceStreamError("Inference response contained an oversized SSE line.");
        }
        yield line;
      }
      if (pending.length > MAX_SSE_LINE_CHARS) {
        throw new InferenceStreamError("Inference response contained an oversized SSE line.");
      }
    }
  } finally {
    reader.releaseLock();
  }
  if (pending) {
    if (pending.length > MAX_SSE_LINE_CHARS) {
      throw new InferenceStreamError("Inference response contained an oversized SSE line.");
    }
    yield pending.replace(/\r$/, "");
  }
}

function contentFromSseLine(
  rawLine: string,
  contentKey: "delta" | "text"
): { done: boolean; content: string | null } {
  if (!rawLine || !rawLine.startsWith("data:")) {
    return { done: false, content: null };
  }
  const data = rawLine.slice("data:".length).trim();
  if (data === "[DONE]") {
    return { done: true, content: null };
  }
  let payload: unknown;
  try {
    payload = JSON.parse(data);
  } catch {
    throw new InferenceStreamError("Inference endpoint returned malformed streaming data.");
  }
  if (typeof payload !== "object" || payload === null) {
    throw new InferenceStreamError("Inference endpoint returned malformed streaming data.");
  }
  const record = payload as Record<string, unknown>;
  if ("error" in record) {
    throw new InferenceStreamError("Inference endpoint reported an error while streaming.");
  }
  const choices = record.choices;
  if (!Array.isArray(choices) || choices.length === 0) {
    return { done: false, content: null };
  }
  const choice = choices[0];
  if (typeof choice !== "object" || choice === null) {
    throw new InferenceStreamError("Inference endpoint returned malformed streaming data.");
  }
  let content: unknown;
  if (contentKey === "delta") {
    const delta = (choice as Record<string, unknown>).delta;
    if (typeof delta !== "object" || delta === null) {
      throw new InferenceStreamError("Inference endpoint returned malformed streaming data.");
    }
    content = (delta as Record<string, unknown>).content;
  } else {
    content = (choice as Record<string, unknown>)[contentKey];
  }
  return {
    done: false,
    content: typeof content === "string" && content ? content : null,
  };
}
