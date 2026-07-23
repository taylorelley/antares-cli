// Port of run_bash() from tools/shell_exec.py — validate a read-only command and
// execute it against the workspace using the pure-TS command emulation.

import { runPipeline } from "./pipeline";
import {
  MAX_TOOL_OUTPUT_CHARS,
  parseReadOnlyCommandList,
  preparePipeline,
  ShellPolicyError,
  validateCommandSize,
  validateReadOnlyStage,
} from "./shellPolicy";

const MAX_COMMAND_CHARS = 16_384;

export interface RunBashResult {
  command: string;
  returncode: number;
  stdout: string;
  stderr: string;
  truncated: boolean;
}

export interface RunBashOptions {
  cwd: string;
  allowedSensitiveFiles?: readonly string[];
}

function appendBounded(current: string, addition: string): { text: string; truncated: boolean } {
  const remaining = MAX_TOOL_OUTPUT_CHARS - current.length;
  if (remaining <= 0) {
    return { text: current, truncated: addition.length > 0 };
  }
  return {
    text: current + addition.slice(0, remaining),
    truncated: addition.length > remaining,
  };
}

export function runBash(command: string, options: RunBashOptions): RunBashResult {
  if (!command || !command.trim()) {
    throw new ShellPolicyError("Command cannot be empty");
  }
  const stripped = command.trim();
  if (stripped.length > MAX_COMMAND_CHARS) {
    throw new ShellPolicyError(
      `Read-only command exceeds the ${MAX_COMMAND_CHARS.toLocaleString("en-US")}-character limit`
    );
  }
  const allowedSensitiveFiles = options.allowedSensitiveFiles ?? [];

  const commandList = parseReadOnlyCommandList(stripped).map((parsed) => ({
    connector: parsed.connector,
    stages: parsed.stages.map(validateReadOnlyStage),
  }));
  validateCommandSize(command, commandList);

  let stdout = "";
  let stderr = "";
  let truncated = false;
  let returnCode = 0;
  for (const { connector, stages } of commandList) {
    if (connector === "&&" && returnCode !== 0) {
      continue;
    }
    if (connector === "||" && returnCode === 0) {
      continue;
    }
    const expandedStages = preparePipeline(stages, options.cwd, allowedSensitiveFiles);
    const pipelineResult = runPipeline(expandedStages, options.cwd);
    returnCode = pipelineResult.code;
    const outAppend = appendBounded(stdout, pipelineResult.stdout);
    const errAppend = appendBounded(stderr, pipelineResult.stderr);
    stdout = outAppend.text;
    stderr = errAppend.text;
    truncated = truncated || pipelineResult.truncated || outAppend.truncated || errAppend.truncated;
  }

  return { command, returncode: returnCode, stdout, stderr, truncated };
}
