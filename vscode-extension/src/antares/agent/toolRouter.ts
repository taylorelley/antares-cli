// Port of antares_cli/agent/tool_router.py — dispatches terminal + read_file.

import * as fs from "fs";
import * as path from "path";

import { isSensitiveRepositoryPath } from "../core/sensitivePaths";
import { runBash } from "../sandbox/runBash";
import { MAX_TOOL_OUTPUT_CHARS, ShellPolicyError } from "../sandbox/shellPolicy";

const MAX_READ_FILE_CHARS = 50_000;
const MAX_READ_FILE_BYTES = 10_000_000;

export interface ToolExecutionResult {
  success: boolean;
  output: Record<string, unknown>;
  errorMessage: string | null;
  maxChars?: number;
}

export class ToolRouter {
  private readonly workspaceRoot: string;
  private readonly allowedSensitiveFiles: readonly string[];

  constructor(workspaceRoot: string, allowedSensitiveFiles: readonly string[] = []) {
    this.workspaceRoot = path.resolve(workspaceRoot);
    this.allowedSensitiveFiles = allowedSensitiveFiles;
  }

  execute(toolName: string, args: Record<string, unknown>): ToolExecutionResult {
    const normalized = toolName.trim().toLowerCase().replace(/ /g, "");
    try {
      if (normalized === "terminal" || normalized === "bash") {
        return { success: true, output: this.terminal(args), errorMessage: null, maxChars: MAX_TOOL_OUTPUT_CHARS };
      }
      if (normalized === "read_file" || normalized === "readfile") {
        return { success: true, output: this.readFile(args), errorMessage: null, maxChars: MAX_READ_FILE_CHARS };
      }
      return {
        success: false,
        output: {},
        errorMessage: `Unsupported tool: ${toolName}. Use terminal.`,
      };
    } catch (error) {
      return {
        success: false,
        output: {},
        errorMessage: error instanceof Error ? error.message : String(error),
      };
    }
  }

  private terminal(args: Record<string, unknown>): Record<string, unknown> {
    const command = args.command;
    if (typeof command !== "string") {
      throw new ShellPolicyError("terminal requires a 'command' string");
    }
    let maxChars = Number.parseInt(String(args.max_chars ?? 2000), 10);
    if (!Number.isFinite(maxChars) || maxChars <= 0) {
      maxChars = 2000;
    }
    const result = runBash(command, {
      cwd: this.workspaceRoot,
      allowedSensitiveFiles: this.allowedSensitiveFiles,
    });
    let stdout = result.stdout;
    let stderr = result.stderr;
    let truncated = result.truncated;
    if (stdout.length > maxChars) {
      stdout = stdout.slice(0, maxChars);
      truncated = true;
    }
    if (stderr && stderr.length > maxChars) {
      stderr = stderr.slice(0, maxChars);
      truncated = true;
    }
    return { command: result.command, returncode: result.returncode, stdout, stderr, truncated };
  }

  private readFile(args: Record<string, unknown>): Record<string, unknown> {
    const rawPath = args.path;
    if (typeof rawPath !== "string") {
      throw new Error("read_file requires a 'path' string");
    }
    if (rawPath.includes("*") || rawPath.includes("?")) {
      throw new Error(
        `read_file does not support glob patterns: ${rawPath}. ` +
          "Use terminal with `find` or `ls` to list matching files, " +
          "then call read_file on each individual file."
      );
    }
    this.validateReadPath(rawPath);

    const resolved = path.isAbsolute(rawPath)
      ? rawPath
      : path.join(this.workspaceRoot, rawPath);
    let stat: fs.Stats;
    try {
      stat = fs.statSync(resolved);
    } catch {
      throw new Error(`File not found: ${resolved}`);
    }
    if (stat.isDirectory()) {
      throw new Error(
        `read_file does not work on directories: ${resolved}. ` +
          "Use `terminal` with `ls` or `find` to list directory contents, " +
          "then call read_file on individual files."
      );
    }
    if (!stat.isFile()) {
      throw new Error(`File not found: ${resolved}`);
    }
    if (stat.size > MAX_READ_FILE_BYTES) {
      throw new Error(
        `File is too large for read_file (${stat.size.toLocaleString("en-US")} bytes; ` +
          `limit ${MAX_READ_FILE_BYTES.toLocaleString("en-US")}). ` +
          "Use terminal with head or sed to inspect a slice."
      );
    }

    const start = positiveLineNumber(args.start_line, "start_line") ?? 1;
    const end = positiveLineNumber(args.end_line, "end_line");
    if (end !== null && end < start) {
      throw new Error("end_line must be greater than or equal to start_line");
    }

    const content = fs.readFileSync(resolved, "utf-8");
    const rawLines = content.split("\n");
    if (rawLines[rawLines.length - 1] === "") {
      rawLines.pop();
    }

    let numberedOutput = "";
    let outputLength = 0;
    let totalLines = 0;
    let lastSelectedLine: number | null = null;
    let truncated = false;
    let hasMore = false;
    for (let lineNumber = 1; lineNumber <= rawLines.length; lineNumber++) {
      totalLines = lineNumber;
      if (end !== null && lineNumber > end) {
        hasMore = true;
        break;
      }
      if (lineNumber < start) {
        continue;
      }
      const line = rawLines[lineNumber - 1].replace(/[\r\n]+$/, "");
      const rendered = `${String(lineNumber).padStart(5)}: ${line}`;
      const separator = numberedOutput ? "\n" : "";
      const addition = `${separator}${rendered}`;
      const remaining = MAX_READ_FILE_CHARS - outputLength;
      if (addition.length > remaining) {
        if (remaining > 0) {
          numberedOutput += addition.slice(0, remaining);
          outputLength += remaining;
        }
        truncated = true;
        hasMore = true;
      } else {
        numberedOutput += addition;
        outputLength += addition.length;
      }
      lastSelectedLine = lineNumber;
      if (truncated) {
        break;
      }
    }

    return {
      path: resolved,
      total_lines: hasMore ? null : totalLines,
      has_more: hasMore,
      showing_lines: lastSelectedLine !== null ? `${start}-${lastSelectedLine}` : "none",
      stdout: numberedOutput,
      truncated,
    };
  }

  private validateReadPath(rawPath: string): void {
    const normalized = rawPath.replace(/\\/g, "/");
    if (
      isSensitiveRepositoryPath(normalized) &&
      !this.allowedSensitiveFiles.includes(normalized.replace(/^\.\//, ""))
    ) {
      throw new Error(`Sensitive path is blocked: ${rawPath}`);
    }
    if (path.isAbsolute(rawPath)) {
      throw new Error("Absolute repository paths are blocked. Use relative paths instead.");
    }
    const resolved = path.resolve(this.workspaceRoot, rawPath);
    if (resolved !== this.workspaceRoot && !resolved.startsWith(this.workspaceRoot + path.sep)) {
      throw new Error(`Path is outside the repository workspace: ${rawPath}`);
    }
  }
}

function positiveLineNumber(value: unknown, fieldName: string): number | null {
  if (value === null || value === undefined) {
    return null;
  }
  if (typeof value === "boolean" || !Number.isInteger(value) || (value as number) < 1) {
    throw new Error(`${fieldName} must be a positive integer`);
  }
  return value as number;
}

// Value clamp bound exposed for arg validation elsewhere.
export const MAX_TERMINAL_OUTPUT = MAX_TOOL_OUTPUT_CHARS;
