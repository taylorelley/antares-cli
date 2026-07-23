// Engine entry invoked inside the worker thread: dispatch the request to the native
// SecurityWorkflowService and stream progress/result events back to the extension.

import { ProgressCallback } from "../antares/agent/types";
import { QueryRequest, SecurityWorkflowService } from "../antares/core/service";
import { findingToDict } from "../antares/output/finding";
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

  const service = new SecurityWorkflowService(ctx.dataDir);
  const apiKey = request.api_key ?? ctx.apiKey;

  if (request.mode === "sweep") {
    // Auto-sweep (CWE selection engine) lands in a later phase.
    throw new Error("Auto-sweep is not yet available in the native engine.");
  }

  const progressCallback: ProgressCallback = (state, finding) => {
    ctx.emit({
      type: "progress",
      mode: "query",
      context_usage_percent: state.contextUsagePercent,
      trajectory_len: state.trajectory.length,
    });
    if (finding) {
      ctx.emit({ type: "finding", finding: findingToDict(finding) as never });
    }
  };

  const queryRequest: QueryRequest = {
    target: request.target,
    cweIds: request.cwe_ids,
    query: request.query,
    model: request.model,
    endpoint: request.endpoint,
    backend: request.backend,
    apiStyle: request.api_style,
    apiKey,
    terminalCallBudget: request.terminal_call_budget,
  };

  const result = await service.runQuery(queryRequest, progressCallback);
  return result.toDict() as unknown as AntaresResult;
}
