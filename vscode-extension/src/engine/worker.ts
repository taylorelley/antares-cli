// Worker-thread entry. Receives the scan request via workerData, streams NDJSON-style
// events back to the extension host through postMessage, and never imports `vscode`.

import { parentPort, workerData } from "worker_threads";

import { HostEvent } from "../findings";
import { EngineContext, runEngine } from "./run";

interface WorkerInput {
  request: Parameters<typeof runEngine>[0];
  apiKey: string | null;
  dataDir: string;
}

async function main(): Promise<void> {
  const port = parentPort;
  if (!port) {
    return;
  }
  const input = workerData as WorkerInput;
  const emit = (event: HostEvent) => port.postMessage(event);
  const ctx: EngineContext = {
    apiKey: input.apiKey,
    dataDir: input.dataDir,
    emit,
  };

  try {
    const result = await runEngine(input.request, ctx);
    port.postMessage({ type: "result", result });
  } catch (error) {
    const err = error as { name?: string; message?: string; stack?: string };
    port.postMessage({
      type: "error",
      error_type: err?.name ?? "Error",
      message: err?.message ? String(err.message) : String(error),
      traceback: err?.stack,
    });
  }
}

void main();
