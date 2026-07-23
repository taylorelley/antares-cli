// Wire a validated pipeline of expanded stages together (stdout -> stdin), replacing
// the OS-pipe subprocess execution in tools/shell_exec.py with in-process commands.

import { COMMANDS } from "./commands";
import { MAX_TOOL_OUTPUT_CHARS } from "./shellPolicy";

function baseName(p: string): string {
  const parts = p.split(/[\\/]/);
  return parts[parts.length - 1];
}

export interface PipelineResult {
  stdout: string;
  stderr: string;
  code: number;
  truncated: boolean;
}

export function runPipeline(expandedStages: string[][], cwd: string): PipelineResult {
  let stdin = "";
  let stderrAll = "";
  let lastCode = 0;
  for (const stage of expandedStages) {
    const name = baseName(stage[0]);
    const fn = COMMANDS[name];
    if (!fn) {
      return { stdout: "", stderr: `${name}: command not found\n`, code: 127, truncated: false };
    }
    const result = fn({ argv: stage, stdin, cwd });
    stdin = result.stdout;
    stderrAll += result.stderr;
    lastCode = result.code;
  }
  let stdout = stdin;
  let truncated = false;
  if (stdout.length > MAX_TOOL_OUTPUT_CHARS) {
    stdout = stdout.slice(0, MAX_TOOL_OUTPUT_CHARS);
    truncated = true;
  }
  if (stderrAll.length > MAX_TOOL_OUTPUT_CHARS) {
    stderrAll = stderrAll.slice(0, MAX_TOOL_OUTPUT_CHARS);
    truncated = true;
  }
  return { stdout, stderr: stderrAll, code: lastCode, truncated };
}
