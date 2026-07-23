import { ChildProcessWithoutNullStreams, spawn } from "child_process";
import * as vscode from "vscode";

import {
  AntaresResult,
  ErrorEvent,
  HostEvent,
  HostRequest,
  isHostEvent,
} from "./findings";

export class HostRunError extends Error {
  constructor(message: string, readonly detail?: string) {
    super(message);
  }
}

export class ScanCancelledError extends Error {}

export interface RunScanOptions {
  interpreter: string;
  hostScript: string;
  request: HostRequest;
  apiKey?: string;
  cwd: string;
  token?: vscode.CancellationToken;
  onEvent?: (event: HostEvent) => void;
  log?: (line: string) => void;
}

// Spawn the Python host, stream its NDJSON events, and resolve with the final result.
export function runScan(options: RunScanOptions): Promise<AntaresResult> {
  const env: NodeJS.ProcessEnv = { ...process.env };
  // Pass the secret through the environment so it never lands in argv or the payload.
  if (options.apiKey && options.apiKey.trim()) {
    env.ANTARES_API_KEY = options.apiKey.trim();
  }

  const child: ChildProcessWithoutNullStreams = spawn(
    options.interpreter,
    [options.hostScript],
    { cwd: options.cwd, env }
  );

  return new Promise<AntaresResult>((resolve, reject) => {
    let result: AntaresResult | undefined;
    let lastError: ErrorEvent | undefined;
    let stdoutBuffer = "";
    let stderrBuffer = "";
    let cancelled = false;
    let settled = false;

    const cancelListener = options.token?.onCancellationRequested(() => {
      cancelled = true;
      child.kill("SIGTERM");
      // Give the process a moment before forcing termination.
      setTimeout(() => {
        if (!settled) {
          child.kill("SIGKILL");
        }
      }, 2000);
    });

    const finish = (fn: () => void) => {
      if (settled) {
        return;
      }
      settled = true;
      cancelListener?.dispose();
      fn();
    };

    const handleLine = (line: string) => {
      const trimmed = line.trim();
      if (!trimmed) {
        return;
      }
      let parsed: unknown;
      try {
        parsed = JSON.parse(trimmed);
      } catch {
        options.log?.(`[host] non-JSON output: ${trimmed}`);
        return;
      }
      if (!isHostEvent(parsed)) {
        return;
      }
      const event = parsed;
      options.onEvent?.(event);
      if (event.type === "result") {
        result = event.result;
      } else if (event.type === "error") {
        lastError = event;
      }
    };

    child.stdout.setEncoding("utf8");
    child.stdout.on("data", (chunk: string) => {
      stdoutBuffer += chunk;
      let newlineIndex: number;
      while ((newlineIndex = stdoutBuffer.indexOf("\n")) >= 0) {
        const line = stdoutBuffer.slice(0, newlineIndex);
        stdoutBuffer = stdoutBuffer.slice(newlineIndex + 1);
        handleLine(line);
      }
    });

    child.stderr.setEncoding("utf8");
    child.stderr.on("data", (chunk: string) => {
      stderrBuffer += chunk;
      options.log?.(`[host stderr] ${chunk.trimEnd()}`);
    });

    child.on("error", (error) => {
      finish(() =>
        reject(new HostRunError(`Failed to start Python host: ${error.message}`))
      );
    });

    child.on("close", (code) => {
      if (stdoutBuffer.trim()) {
        handleLine(stdoutBuffer);
        stdoutBuffer = "";
      }
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
          reject(new HostRunError(lastError.message, lastError.traceback));
          return;
        }
        reject(
          new HostRunError(
            `Antares host exited with code ${code ?? "unknown"} without a result.`,
            stderrBuffer.trim() || undefined
          )
        );
      });
    });

    // Send the request and close stdin.
    try {
      child.stdin.write(JSON.stringify(options.request));
      child.stdin.end();
    } catch (error) {
      finish(() =>
        reject(
          new HostRunError(`Failed to send request to Python host: ${String(error)}`)
        )
      );
    }
  });
}
