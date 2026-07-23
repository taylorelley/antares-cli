// Types mirroring the public JSON contract emitted by the Antares Python service
// (`WorkflowResult.to_dict()` and `Finding.to_dict()`), plus the NDJSON host events.
//
// These types are intentionally free of any `vscode` import so the request-building
// logic can be unit-tested with a plain Node test runner.

export interface AntaresFinding {
  title: string;
  file_path: string;
  cwe_ids: string[];
  likelihood_of_exploit?: string;
  submission_rank?: number;
}

export interface AntaresSummary {
  total_findings: number;
  tool_call_count: number;
  duration_seconds: number;
  cwe_ids_triggered: string[];
  failed_tool_calls?: number;
  retried_turns?: number;
  generation_errors?: number;
  failed_workers?: number;
  total_workers?: number;
  incomplete_reason?: string | null;
}

export interface AntaresResult {
  summary: AntaresSummary;
  findings: AntaresFinding[];
  metadata: Record<string, unknown>;
  per_cwe_results?: unknown[];
  warnings?: string[];
}

export type ScanMode = "query" | "sweep";

// The request object written to the host script's stdin.
export interface HostRequest {
  mode: ScanMode;
  target: string;
  cwe_ids: string[];
  query: string | null;
  model: string | null;
  endpoint: string | null;
  backend: string | null;
  api_style: string | null;
  api_key: string | null;
  profile: string | null;
  terminal_call_budget: number | null;
  workers?: number;
  max_cwes?: number;
}

// NDJSON events emitted by the host script on stdout.
export interface ReadyEvent {
  type: "ready";
}

export interface ProgressEvent {
  type: "progress";
  mode: "query";
  context_usage_percent: number | null;
  trajectory_len: number;
}

export interface WorkerEvent {
  type: "worker";
  event: "started" | "progress" | "completed" | "failed";
  worker_index: number | null;
  label: string | null;
  focus_cwe_ids: string[];
  context_usage_percent?: number | null;
  finding?: AntaresFinding;
  error_message?: string;
}

export interface FindingEvent {
  type: "finding";
  finding: AntaresFinding;
}

export interface ResultEvent {
  type: "result";
  result: AntaresResult;
}

export interface ErrorEvent {
  type: "error";
  error_type: string;
  message: string;
  traceback?: string;
}

export type HostEvent =
  | ReadyEvent
  | ProgressEvent
  | WorkerEvent
  | FindingEvent
  | ResultEvent
  | ErrorEvent;

export function isHostEvent(value: unknown): value is HostEvent {
  return (
    typeof value === "object" &&
    value !== null &&
    typeof (value as { type?: unknown }).type === "string"
  );
}
