// Port of antares_cli/inference/defaults.py — endpoint-neutral generation defaults.

export const DEFAULT_ANTARES_CONTEXT_WINDOW = 16_384;
export const DEFAULT_ANTARES_MAX_TOKENS = 4_096;
export const DEFAULT_ANTARES_TEMPERATURE = 0.3;
export const DEFAULT_ANTARES_TOP_P = 1.0;
export const DEFAULT_ANTARES_FREQUENCY_PENALTY = 0.3;
export const DEFAULT_ANTARES_STOP_TOKENS: readonly string[] = [
  "<|end_of_text|>",
  "<|start_of_role|>",
];
export const DEFAULT_ANTARES_USE_COMPLETIONS_API = true;
export const DEFAULT_ANTARES_REMOTE_TIMEOUT_SECONDS = 300.0;
