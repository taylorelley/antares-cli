// Port of antares_cli/inference/backend.py — inference backend contract + errors.

export class InferenceError extends Error {}
export class InferenceStreamError extends InferenceError {}
export class InferenceContextLengthError extends InferenceError {}

// Carries the HTTP status so the turn layer can render 401/403/other messages.
export class InferenceHttpError extends InferenceError {
  constructor(
    readonly statusCode: number,
    message: string
  ) {
    super(message);
  }
}

export interface ChatMessage {
  role: string;
  content: string;
}

export interface InferenceBackend {
  readonly modelId: string;
  readonly contextWindow: number;
  readonly maxTokens: number;
  streamGenerate(messages: ChatMessage[]): AsyncIterable<string>;
}

export function normalizeModelId(raw: string): string {
  const trimmed = raw.trim();
  if (!trimmed) {
    throw new Error("Model id must be a non-empty string");
  }
  return trimmed;
}
