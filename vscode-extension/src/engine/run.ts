// Engine entry invoked inside the worker thread: dispatch the request to the native
// SecurityWorkflowService and stream progress/result events back to the extension.

import { ProgressCallback } from "../antares/agent/types";
import { QueryRequest, SecurityWorkflowService, SweepRequest } from "../antares/core/service";
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
    const sweepRequest: SweepRequest = {
      target: request.target,
      cweIds: request.cwe_ids,
      query: request.query,
      model: request.model,
      endpoint: request.endpoint,
      apiStyle: request.api_style,
      apiKey,
      terminalCallBudget: request.terminal_call_budget,
      workers: request.workers,
      maxCwes: request.max_cwes,
    };
    const result = await service.runCweSweep(sweepRequest, (event) => {
      ctx.emit({
        type: "worker",
        event: event.event,
        worker_index: null,
        label: event.cweId,
        focus_cwe_ids: [event.cweId],
        context_usage_percent: event.contextUsagePercent ?? null,
        finding: event.finding ? (findingToDict(event.finding) as never) : undefined,
        error_message: event.errorMessage,
      });
    });
    return result.toDict() as unknown as AntaresResult;
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
