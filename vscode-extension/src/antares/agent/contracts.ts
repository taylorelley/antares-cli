// Port of antares_cli/agent/contracts.py — canonical agent contracts.

import { ParsedToolCall } from "./streamingParser";

export const TERMINAL_TOOL_NAME = "terminal";
export const BASH_TOOL_NAME = "bash";
export const SUBMIT_VULNERABLE_FILES_TOOL = "submit_vulnerable_files";
export const SUBMIT_NO_VULNERABILITY_FOUND_TOOL = "submit_no_vulnerability_found";
export const RANKED_FILES_ARGUMENT = "ranked_files";
export const RANKED_FILE_ARGUMENT_ALIASES = ["ranked_files", "files", "file_paths"];
export const SUBMIT_FILE_PATH_FIELD_ALIASES = ["file_path", "path", "file"];

export function normalizeToolName(toolName: string): string {
  return toolName.trim().toLowerCase();
}

const SUBMIT_TOOL_NAMES = new Set([
  SUBMIT_VULNERABLE_FILES_TOOL,
  SUBMIT_NO_VULNERABILITY_FOUND_TOOL,
]);

export function isSubmitToolName(toolName: string): boolean {
  return SUBMIT_TOOL_NAMES.has(normalizeToolName(toolName));
}

export function isSubmitToolCall(parsedCall: ParsedToolCall): boolean {
  return isSubmitToolName(parsedCall.toolName);
}
