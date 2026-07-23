// Pure configuration -> host-request mapping. No `vscode` import so it is unit-testable.

import { HostRequest, ScanMode } from "./findings";

export type Provider = "ollama" | "openai-compatible" | "vllm" | "custom";
export type ApiStyleSetting = "auto" | "chat" | "completions";
export type ApiStyle = "chat" | "completions";

// Plain snapshot of the user's configuration, decoupled from vscode APIs.
export interface AntaresConfig {
  provider: Provider;
  endpoint: string;
  model: string;
  apiStyle: ApiStyleSetting;
  toolBudget: number;
  sweepWorkers: number;
  sweepMaxCwes: number;
}

const PROVIDER_DEFAULT_ENDPOINT: Record<Provider, string | null> = {
  ollama: "http://localhost:11434/v1",
  "openai-compatible": null,
  vllm: null,
  custom: null,
};

// Providers that default to the raw completions API when apiStyle is "auto".
const COMPLETIONS_PROVIDERS: ReadonlySet<Provider> = new Set<Provider>(["vllm"]);

export function resolveApiStyle(config: AntaresConfig): ApiStyle {
  if (config.apiStyle === "chat" || config.apiStyle === "completions") {
    return config.apiStyle;
  }
  return COMPLETIONS_PROVIDERS.has(config.provider) ? "completions" : "chat";
}

export function resolveEndpoint(config: AntaresConfig): string | null {
  const explicit = config.endpoint.trim();
  if (explicit) {
    return explicit;
  }
  return PROVIDER_DEFAULT_ENDPOINT[config.provider];
}

export class ConfigError extends Error {}

export interface ScanParams {
  mode: ScanMode;
  target: string;
  cweIds?: string[];
  query?: string | null;
  apiKey?: string | null;
}

// Build the host request, validating that the minimum required fields are present.
export function buildHostRequest(config: AntaresConfig, params: ScanParams): HostRequest {
  const model = config.model.trim();
  if (!model) {
    throw new ConfigError(
      "No model configured. Set 'antares.model' to the identifier your endpoint serves."
    );
  }

  const endpoint = resolveEndpoint(config);
  if (!endpoint) {
    throw new ConfigError(
      "No endpoint configured. Set 'antares.endpoint' (e.g. http://localhost:11434/v1)."
    );
  }

  if (params.mode === "query" && (!params.cweIds || params.cweIds.length === 0)) {
    throw new ConfigError("At least one CWE ID is required for a targeted scan.");
  }

  const request: HostRequest = {
    mode: params.mode,
    target: params.target,
    cwe_ids: params.cweIds ?? [],
    query: normalizeOptional(params.query),
    model,
    endpoint,
    backend: "remote",
    api_style: resolveApiStyle(config),
    api_key: normalizeOptional(params.apiKey),
    profile: null,
    terminal_call_budget: config.toolBudget > 0 ? Math.trunc(config.toolBudget) : null,
  };

  if (params.mode === "sweep") {
    if (config.sweepWorkers > 0) {
      request.workers = Math.trunc(config.sweepWorkers);
    }
    if (config.sweepMaxCwes > 0) {
      request.max_cwes = Math.trunc(config.sweepMaxCwes);
    }
  }

  return request;
}

function normalizeOptional(value: string | null | undefined): string | null {
  if (value === null || value === undefined) {
    return null;
  }
  const trimmed = value.trim();
  return trimmed ? trimmed : null;
}

// Parse a free-form CWE input ("89, CWE-79 cwe-22") into canonical CWE-<n> tokens.
export function parseCweIds(raw: string): string[] {
  const ids: string[] = [];
  const seen = new Set<string>();
  for (const token of raw.split(/[\s,;]+/)) {
    const match = token.match(/(\d+)/);
    if (!match) {
      continue;
    }
    const id = `CWE-${match[1]}`;
    if (!seen.has(id)) {
      seen.add(id);
      ids.push(id);
    }
  }
  return ids;
}
