// Engine entry invoked inside the worker thread. This module grows over the port:
// later phases replace the stub body with the real SecurityWorkflowService.

import { AntaresResult, HostEvent, HostRequest } from "../findings";

export interface EngineContext {
  apiKey: string | null;
  dataDir: string;
  emit: (event: HostEvent) => void;
}

export async function runEngine(
  request: HostRequest,
  ctx: EngineContext
): Promise<AntaresResult> {
  ctx.emit({ type: "ready" });

  // TODO(port): dispatch to the native SecurityWorkflowService (query | sweep).
  // Phase 1 returns an empty, well-formed result to prove the worker round-trip.
  const result: AntaresResult = {
    summary: {
      total_findings: 0,
      tool_call_count: 0,
      duration_seconds: 0,
      cwe_ids_triggered: [],
    },
    findings: [],
    metadata: {
      mode: request.mode,
      model: request.model,
      engine: "typescript",
    },
  };
  return result;
}
