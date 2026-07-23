/**
 * runner.ts — Spawn the opengrep binary and collect JSON results.
 *
 * Uses Node.js `child_process.spawn` (not worker threads) for async execution.
 * Environment variables that affect metrics / telemetry are set to off.
 */

import { spawn } from "child_process";
import { OpengrepResult } from "./types";

// ---------------------------------------------------------------------------
// Options
// ---------------------------------------------------------------------------

export interface ScanOptions {
  /** Absolute path to the opengrep binary. */
  binaryPath: string;
  /** Path to directory containing .yml rule files. */
  rulesPath: string;
  /** Absolute path to the directory or file to scan. */
  targetPath: string;
  /** Optional per-rule timeout in seconds (passed as --timeout). */
  timeoutSeconds?: number;
  /** Optional glob patterns to ignore (e.g. ["*.test.js", "node_modules/**"]). */
  ignoreGlobs?: string[];
}

// ---------------------------------------------------------------------------
// Scan runner
// ---------------------------------------------------------------------------

/**
 * Run an opengrep scan and return the parsed JSON result.
 *
 * The opengrep binary is spawned with:
 *   - `--config <rulesPath>`  – rule directory
 *   - `--json`               – JSON output mode
 *   - `--metrics=off`        – disable telemetry
 *   - `--timeout <sec>`      – optional per-rule timeout
 *   - `--exclude` entries    – optional ignore globs
 *   - `<targetPath>`         – the path to scan
 *
 * Environment variable `SEMGREP_SEND_METRICS=off` is set as a secondary
 * guard against telemetry.
 *
 * @throws If the binary cannot be spawned, exits with non-zero code, or
 *   stdout cannot be parsed as valid JSON.
 */
export async function runOpengrepScan(
  options: ScanOptions,
): Promise<OpengrepResult> {
  const { binaryPath, rulesPath, targetPath, timeoutSeconds, ignoreGlobs } =
    options;

  const args: string[] = [
    "scan",
    "--config",
    rulesPath,
    "--json",
    "--metrics=off",
  ];

  if (timeoutSeconds !== undefined && timeoutSeconds > 0) {
    args.push("--timeout", String(timeoutSeconds));
  }

  if (ignoreGlobs && ignoreGlobs.length > 0) {
    for (const glob of ignoreGlobs) {
      args.push("--exclude", glob);
    }
  }

  args.push(targetPath);

  return new Promise<OpengrepResult>((resolve, reject) => {
    const child = spawn(binaryPath, args, {
      stdio: ["ignore", "pipe", "pipe"],
      env: {
        ...process.env,
        SEMGREP_SEND_METRICS: "off",
      },
      // Allow up to 10 minutes; the --timeout flag controls per-rule timeout.
      timeout: 600_000,
    });

    const stdoutChunks: Buffer[] = [];
    const stderrChunks: Buffer[] = [];

    child.stdout.on("data", (chunk: Buffer) => {
      stdoutChunks.push(chunk);
    });

    child.stderr.on("data", (chunk: Buffer) => {
      stderrChunks.push(chunk);
    });

    child.on("error", (err: NodeJS.ErrnoException) => {
      // Spawn failure (e.g. binary not found, permission denied).
      reject(
        new Error(
          `Opengrep scan failed: unable to spawn binary — ${err.message}`,
        ),
      );
    });

    child.on("close", (code: number | null) => {
      const stderr = Buffer.concat(stderrChunks).toString("utf8").trim();

      if (code !== 0 && stdoutChunks.length === 0) {
        // Non-zero exit with no stdout — treat as a failure.
        const detail = stderr || `exit code ${code}`;
        reject(
          new Error(
            `Opengrep scan failed: ${detail}`,
          ),
        );
        return;
      }

      const raw = Buffer.concat(stdoutChunks).toString("utf8");
      if (!raw) {
        const detail = stderr || `exit code ${code}`;
        reject(
          new Error(
            `Opengrep scan failed: empty output — ${detail}`,
          ),
        );
        return;
      }

      try {
        const parsed: OpengrepResult = JSON.parse(raw);
        resolve(parsed);
      } catch (parseErr) {
        reject(
          new Error(
            `Opengrep scan failed: unable to parse JSON output — ${
              parseErr instanceof Error ? parseErr.message : String(parseErr)
            }`,
          ),
        );
      }
    });
  });
}
