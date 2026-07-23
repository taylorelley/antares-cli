import * as path from "path";
import { Worker } from "worker_threads";
import * as vscode from "vscode";

import {
  AntaresResult,
  ErrorEvent,
  HostEvent,
  HostRequest,
  isHostEvent,
} from "../findings";

export class EngineError extends Error {
  constructor(message: string, readonly detail?: string) {
    super(message);
  }
}

export class ScanCancelledError extends Error {}

export interface RunScanOptions {
  request: HostRequest;
  dataDir: string;
  apiKey?: string;
  token?: vscode.CancellationToken;
  onEvent?: (event: HostEvent) => void;
  log?: (line: string) => void;
}

// Resolve the bundled worker entry (dist/worker.js sits next to dist/extension.js).
function workerScriptPath(): string {
  return path.join(__dirname, "worker.js");
}

// Run a scan inside a worker thread so CPU-bound work never blocks the extension host.
export function runScan(options: RunScanOptions): Promise<AntaresResult> {
  return new Promise<AntaresResult>((resolve, reject) => {
    let result: AntaresResult | undefined;
    let lastError: ErrorEvent | undefined;
    let cancelled = false;
    let settled = false;

    const worker = new Worker(workerScriptPath(), {
      workerData: {
        request: options.request,
        apiKey: options.apiKey ?? null,
        dataDir: options.dataDir,
      },
    });

    const cancelListener = options.token?.onCancellationRequested(() => {
      cancelled = true;
      void worker.terminate();
    });

    const finish = (fn: () => void) => {
      if (settled) {
        return;
      }
      settled = true;
      cancelListener?.dispose();
      void worker.terminate();
      fn();
    };

    worker.on("message", (message: unknown) => {
      if (!isHostEvent(message)) {
        return;
      }
      const event = message;
      if (event.type === "result") {
        result = event.result;
      } else if (event.type === "error") {
        lastError = event;
      } else {
        options.onEvent?.(event);
      }
    });

    worker.on("error", (error) => {
      finish(() => reject(new EngineError(`Engine worker crashed: ${error.message}`)));
    });

    worker.on("exit", (code) => {
      finish(() => {
        if (cancelled) {
          reject(new ScanCancelledError("Scan cancelled."));
          return;
        }
        if (result) {
          resolve(result);
          return;
        }
        if (lastError) {
          reject(new EngineError(lastError.message, lastError.traceback));
          return;
        }
        reject(new EngineError(`Engine worker exited with code ${code ?? "unknown"}.`));
      });
    });
  });
}
