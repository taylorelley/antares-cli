// Port of the policy half of antares_cli/tools/shell_exec.py — parsing, tokenizing,
// allow-list validation, per-command argument restrictions, glob expansion, and path
// confinement. Error messages are reproduced verbatim (the model reads them).

import * as fs from "fs";
import * as path from "path";

import { fnmatchcase } from "../core/repositoryPaths";
import { isSensitiveRepositoryPath } from "../core/sensitivePaths";

export class ShellPolicyError extends Error {}

export const SAFE_COMMAND_ALLOWLIST = new Set([
  "basename", "cat", "cut", "diff", "dirname", "du", "echo", "false", "file", "find",
  "grep", "head", "ls", "nl", "pwd", "realpath", "rg", "sed", "sort", "stat", "tail",
  "tree", "true", "uniq", "wc",
]);

export const MAX_TOOL_OUTPUT_CHARS = 12_000;
const MAX_COMMAND_CHARS = 16_384;
const MAX_COMPOUND_COMMANDS = 32;
const MAX_PIPELINE_STAGES = 16;
const MAX_COMMAND_TOKENS = 512;
const MAX_GLOB_MATCHES = 4_096;
const MAX_STAGE_ARGV_BYTES = 128 * 1024;

const COMPOUND_OPERATORS = new Set(["&&", "||", ";"]);
const DENIED_SHELL_TOKENS = new Set(["&", "<", ">", ">>", "<<"]);
const FIND_MUTATING_PREFIXES = ["-delete", "-exec", "-ok", "-fprint", "-fprintf", "-fls"];
const SENSITIVE_SYSTEM_PATHS = ["/etc/passwd", "/etc/shadow"];
const SED_ALLOWED_OPTIONS = new Set(["-n", "--quiet", "--silent", "-E", "-r", "--regexp-extended"]);
const SED_READ_EXPRESSION = /^(?:\d+|\$)(?:,(?:\d+|\$))?p$/;
const GLOB_METACHARACTERS = new Set(["*", "?", "["]);

export interface ShellToken {
  value: string;
  expandGlob: boolean;
}

export interface ParsedCommand {
  connector: string | null;
  stages: ShellToken[][];
}

function baseName(p: string): string {
  const parts = p.split(/[\\/]/);
  return parts[parts.length - 1];
}

export function parseReadOnlyCommandList(command: string): ParsedCommand[] {
  if (command.includes("\n") || command.includes("\r")) {
    throw new ShellPolicyError("Read-only command policy does not allow multiline commands");
  }
  if (containsUnquotedShellExpansion(command)) {
    throw new ShellPolicyError("Read-only command policy does not allow shell expansion");
  }

  const tokens = tokenizeReadOnlyCommand(command);
  const commands: ParsedCommand[] = [];
  let connector: string | null = null;
  let stages: ShellToken[][] = [[]];
  for (const token of tokens) {
    if (token.value === "|") {
      if (stages[stages.length - 1].length === 0) {
        throw new ShellPolicyError("Read-only command policy does not allow empty pipelines");
      }
      stages.push([]);
      continue;
    }
    if (COMPOUND_OPERATORS.has(token.value)) {
      if (stages[stages.length - 1].length === 0) {
        throw new ShellPolicyError("Read-only command policy does not allow empty commands");
      }
      commands.push({ connector, stages });
      connector = token.value;
      stages = [[]];
      continue;
    }
    if (DENIED_SHELL_TOKENS.has(token.value)) {
      throw new ShellPolicyError(
        `Read-only command policy does not allow shell operator: ${token.value}`
      );
    }
    stages[stages.length - 1].push(token);
  }
  if (stages[stages.length - 1].length === 0) {
    throw new ShellPolicyError("Read-only command policy does not allow empty commands");
  }
  commands.push({ connector, stages });
  return commands;
}

export function parseReadOnlyCommandStages(command: string): string[][] {
  const result: string[][] = [];
  for (const { stages } of parseReadOnlyCommandList(command)) {
    for (const stage of stages) {
      result.push(stage.map((token) => token.value));
    }
  }
  return result;
}

function tokenizeReadOnlyCommand(command: string): ShellToken[] {
  const tokens: ShellToken[] = [];
  let characters: string[] = [];
  let quote: string | null = null;
  let tokenStarted = false;
  let expandGlob = false;
  let index = 0;

  const flushToken = () => {
    if (!tokenStarted) {
      return;
    }
    tokens.push({ value: characters.join(""), expandGlob });
    characters = [];
    tokenStarted = false;
    expandGlob = false;
  };

  while (index < command.length) {
    const character = command[index];
    if (quote === "'") {
      if (character === "'") {
        quote = null;
      } else {
        characters.push(character);
      }
      tokenStarted = true;
      index += 1;
      continue;
    }
    if (quote === '"') {
      if (character === '"') {
        quote = null;
        tokenStarted = true;
        index += 1;
        continue;
      }
      if (character === "\\" && index + 1 < command.length) {
        const escaped = command[index + 1];
        if (escaped === '"' || escaped === "\\" || escaped === "$" || escaped === "`") {
          characters.push(escaped);
          tokenStarted = true;
          index += 2;
          continue;
        }
      }
      characters.push(character);
      tokenStarted = true;
      index += 1;
      continue;
    }
    if (/\s/.test(character)) {
      flushToken();
      index += 1;
      continue;
    }
    if (character === "'" || character === '"') {
      quote = character;
      tokenStarted = true;
      index += 1;
      continue;
    }
    if (character === "\\") {
      if (index + 1 >= command.length) {
        throw new ShellPolicyError("Invalid command syntax: No escaped character");
      }
      characters.push(command[index + 1]);
      tokenStarted = true;
      index += 2;
      continue;
    }
    if ("|&;<>".includes(character)) {
      flushToken();
      let end = index + 1;
      while (end < command.length && "|&;<>".includes(command[end])) {
        end += 1;
      }
      tokens.push({ value: command.slice(index, end), expandGlob: false });
      index = end;
      continue;
    }
    characters.push(character);
    tokenStarted = true;
    if (GLOB_METACHARACTERS.has(character)) {
      expandGlob = true;
    }
    index += 1;
  }

  if (quote !== null) {
    throw new ShellPolicyError("Invalid command syntax: No closing quotation");
  }
  flushToken();
  return tokens;
}

function containsUnquotedShellExpansion(command: string): boolean {
  let quote: string | null = null;
  let escaped = false;
  for (let index = 0; index < command.length; index++) {
    const character = command[index];
    if (escaped) {
      escaped = false;
      continue;
    }
    if (character === "\\" && quote !== "'") {
      escaped = true;
      continue;
    }
    if (quote !== null) {
      if (character === quote) {
        quote = null;
      } else if (quote === '"' && (character === "`" || startsShellExpansion(command, index))) {
        return true;
      }
      continue;
    }
    if (character === "'" || character === '"') {
      quote = character;
      continue;
    }
    if (character === "`" || startsShellExpansion(command, index)) {
      return true;
    }
    if (character === "~" && (index === 0 || /\s/.test(command[index - 1]))) {
      return true;
    }
  }
  return false;
}

function startsShellExpansion(command: string, index: number): boolean {
  if (command[index] !== "$" || index + 1 >= command.length) {
    return false;
  }
  const next = command[index + 1];
  return "({?#-$!@*_".includes(next) || /[a-zA-Z0-9]/.test(next);
}

export function validateReadOnlyStage(argTokens: ShellToken[]): ShellToken[] {
  const executable = argTokens[0].value;
  if (executable !== baseName(executable) || !SAFE_COMMAND_ALLOWLIST.has(executable)) {
    if (executable === "cd") {
      throw new ShellPolicyError(
        "cd is not supported. Commands run from the repository root. " +
          "Use relative paths directly (e.g., `ls src/utils/` instead of `cd src/utils && ls`)."
      );
    }
    throw new ShellPolicyError(`Command is not allowlisted: ${executable}`);
  }
  validateCommandArguments(
    executable,
    argTokens.slice(1).map((token) => token.value)
  );
  return argTokens;
}

function shortOptionClusterContains(
  argument: string,
  option: string,
  optionsWithValue: Set<string>
): boolean {
  if (!argument.startsWith("-") || argument.startsWith("--")) {
    return false;
  }
  for (const candidate of argument.slice(1)) {
    if (candidate === option) {
      return true;
    }
    if (optionsWithValue.has(candidate)) {
      return false;
    }
  }
  return false;
}

function positionalArguments(argumentList: string[], optionsWithValue: Set<string>): string[] {
  const positional: string[] = [];
  let index = 0;
  let optionsEnded = false;
  while (index < argumentList.length) {
    const argument = argumentList[index];
    if (!optionsEnded && argument === "--") {
      optionsEnded = true;
    } else if (!optionsEnded && optionsWithValue.has(argument)) {
      index += 1;
    } else if (!optionsEnded && (argument.startsWith("-") || argument.startsWith("+"))) {
      // skip flag
    } else {
      positional.push(argument);
    }
    index += 1;
  }
  return positional;
}

function validateCommandArguments(executable: string, argumentList: string[]): void {
  if (
    executable === "find" &&
    argumentList.some((argument) => FIND_MUTATING_PREFIXES.some((p) => argument.startsWith(p)))
  ) {
    throw new ShellPolicyError("Read-only command policy blocks mutating or nested find actions");
  }

  if (executable === "sed") {
    validateSedArguments(argumentList);
  }

  if (
    executable === "sort" &&
    argumentList.some(
      (argument) =>
        argument === "-o" ||
        argument === "--output" ||
        argument.startsWith("-o") ||
        argument.startsWith("--output=") ||
        shortOptionClusterContains(argument, "o", new Set(["k", "S", "T", "t", "o"]))
    )
  ) {
    throw new ShellPolicyError("Read-only command policy blocks sort output files");
  }

  if (
    executable === "tree" &&
    argumentList.some(
      (argument) =>
        argument === "-o" ||
        argument.startsWith("--output=") ||
        shortOptionClusterContains(argument, "o", new Set(["H", "L", "P", "I", "T", "o", "X"]))
    )
  ) {
    throw new ShellPolicyError("Read-only command policy blocks tree output files");
  }

  if (executable === "tree" && argumentList.some((a) => a === "--fromfile" || a === "--fromtabfile")) {
    throw new ShellPolicyError("Read-only command policy blocks repository-controlled path lists");
  }

  if (
    executable === "file" &&
    argumentList.some(
      (argument) =>
        argument === "--compile" ||
        shortOptionClusterContains(argument, "C", new Set(["e", "F", "f", "m", "M", "P"]))
    )
  ) {
    throw new ShellPolicyError("Read-only command policy blocks compiled file databases");
  }

  if (
    executable === "file" &&
    argumentList.some(
      (argument) =>
        argument === "--uncompress" ||
        argument === "--uncompress-noreport" ||
        argument === "--no-sandbox" ||
        ["z", "Z", "S"].some((option) =>
          shortOptionClusterContains(argument, option, new Set(["e", "F", "f", "m", "M", "P"]))
        )
    )
  ) {
    throw new ShellPolicyError(
      "Read-only command policy blocks nested or unsandboxed file inspection"
    );
  }

  if (
    executable === "file" &&
    argumentList.some(
      (argument) =>
        argument === "-f" ||
        argument === "--files-from" ||
        argument.startsWith("--files-from=") ||
        shortOptionClusterContains(argument, "f", new Set(["e", "F", "f", "m", "M", "P"]))
    )
  ) {
    throw new ShellPolicyError("Read-only command policy blocks repository-controlled path lists");
  }

  if (
    ["find", "du", "sort", "wc"].includes(executable) &&
    argumentList.some(
      (argument) =>
        argument === "-files0-from" ||
        argument === "--files0-from" ||
        argument.startsWith("-files0-from=") ||
        argument.startsWith("--files0-from=")
    )
  ) {
    throw new ShellPolicyError("Read-only command policy blocks repository-controlled path lists");
  }

  if (
    executable === "sort" &&
    argumentList.some(
      (argument) =>
        argument === "--compress-program" || argument.startsWith("--compress-program=")
    )
  ) {
    throw new ShellPolicyError("Read-only command policy blocks nested sort helpers");
  }

  if (
    executable === "rg" &&
    argumentList.some(
      (argument) =>
        argument === "--pre" ||
        argument.startsWith("--pre=") ||
        argument === "--hostname-bin" ||
        argument.startsWith("--hostname-bin=") ||
        argument === "--search-zip" ||
        shortOptionClusterContains(
          argument,
          "z",
          new Set(["A", "B", "C", "E", "F", "e", "f", "g", "j", "m", "M", "r", "t", "T"])
        )
    )
  ) {
    throw new ShellPolicyError("Read-only command policy blocks nested search executables");
  }

  if (
    executable === "uniq" &&
    positionalArguments(argumentList, new Set(["-f", "-s", "-w"])).length > 1
  ) {
    throw new ShellPolicyError("Read-only command policy blocks uniq output files");
  }
}

function validateSedArguments(argumentList: string[]): void {
  const expressions: string[] = [];
  let index = 0;
  while (index < argumentList.length) {
    const argument = argumentList[index];
    if (
      argument === "-i" ||
      argument === "--in-place" ||
      argument.startsWith("-i") ||
      argument.startsWith("--in-place=")
    ) {
      throw new ShellPolicyError("Read-only command policy blocks sed in-place editing");
    }
    if (argument === "-e") {
      index += 1;
      if (index >= argumentList.length) {
        throw new ShellPolicyError("sed -e requires an expression");
      }
      expressions.push(argumentList[index]);
    } else if (argument.startsWith("-")) {
      if (!SED_ALLOWED_OPTIONS.has(argument)) {
        throw new ShellPolicyError(`Read-only command policy blocks sed option: ${argument}`);
      }
    } else if (expressions.length === 0) {
      expressions.push(argument);
    }
    index += 1;
  }

  if (expressions.length === 0 || expressions.some((item) => !isSafeSedExpression(item))) {
    throw new ShellPolicyError(
      "Read-only command policy permits sed only for line-range printing or " +
        "non-writing substitutions"
    );
  }
}

function isSafeSedExpression(expression: string): boolean {
  if (SED_READ_EXPRESSION.test(expression)) {
    return true;
  }
  if (expression.length < 4 || expression[0] !== "s") {
    return false;
  }
  const delimiter = expression[1];
  if (/[a-zA-Z0-9]/.test(delimiter) || /\s/.test(delimiter) || delimiter === "\\") {
    return false;
  }

  let index = 2;
  for (let section = 0; section < 2; section++) {
    let closed = false;
    while (index < expression.length) {
      const character = expression[index];
      if (character === "\\" && index + 1 < expression.length) {
        index += 2;
        continue;
      }
      index += 1;
      if (character === delimiter) {
        closed = true;
        break;
      }
    }
    if (!closed) {
      return false;
    }
  }

  const flags = expression.slice(index);
  return [...flags].every((character) => "0123456789gIpMm".includes(character));
}

// --- path confinement -----------------------------------------------------

function pathCandidates(token: string): string[] {
  if (token.startsWith("-") && token.includes("=")) {
    return [token, token.slice(token.indexOf("=") + 1)];
  }
  if (token.startsWith("-")) {
    const markers = ["../", "./", "/", "~"];
    const offsets: number[] = [];
    for (const marker of markers) {
      const offset = token.indexOf(marker, 2);
      if (offset >= 2) {
        offsets.push(offset);
      }
    }
    if (offsets.length > 0) {
      return [token, token.slice(Math.min(...offsets))];
    }
  }
  return [token];
}

function looksLikePathToken(token: string): boolean {
  if (token === ".." || token === ".") {
    return token === "..";
  }
  if (token.startsWith("/")) {
    return true;
  }
  const normalized = token.replace(/\\/g, "/");
  return normalized.includes("/") || normalized.split("/").includes("..");
}

function referencesSensitivePath(value: string, allowedSensitiveFiles: readonly string[]): boolean {
  const normalized = value.replace(/\\/g, "/").toLowerCase();
  if (SENSITIVE_SYSTEM_PATHS.some((systemPath) => normalized.includes(systemPath))) {
    return true;
  }
  let canonical = posixNormpath(normalized);
  while (canonical.startsWith("./")) {
    canonical = canonical.slice(2);
  }
  const normalizedAllowed = new Set(allowedSensitiveFiles.map((p) => p.toLowerCase()));
  return isSensitiveRepositoryPath(canonical) && !normalizedAllowed.has(canonical);
}

function posixNormpath(p: string): string {
  const isAbsolute = p.startsWith("/");
  const segments = p.split("/");
  const out: string[] = [];
  for (const segment of segments) {
    if (segment === "" || segment === ".") {
      continue;
    }
    if (segment === "..") {
      if (out.length > 0 && out[out.length - 1] !== "..") {
        out.pop();
      } else if (!isAbsolute) {
        out.push("..");
      }
    } else {
      out.push(segment);
    }
  }
  const joined = out.join("/");
  if (isAbsolute) {
    return "/" + joined;
  }
  return joined || ".";
}

function pathStaysInsideWorkspace(workspaceRoot: string, rawPath: string): boolean {
  let candidate = rawPath;
  if (!path.isAbsolute(candidate)) {
    candidate = path.join(workspaceRoot, candidate);
  }
  let resolved: string;
  try {
    resolved = fs.realpathSync(candidate);
  } catch {
    resolved = path.resolve(candidate);
  }
  const rel = path.relative(workspaceRoot, resolved);
  return resolved === workspaceRoot || (rel !== "" && !rel.startsWith("..") && !path.isAbsolute(rel));
}

function workspacePathExists(workspaceRoot: string, rawValue: string): boolean {
  if (rawValue.startsWith("-")) {
    return false;
  }
  const candidate = path.join(workspaceRoot, rawValue);
  try {
    fs.lstatSync(candidate);
    return true;
  } catch (error) {
    const code = (error as NodeJS.ErrnoException).code;
    if (code === "ENOENT") {
      return false;
    }
    if (code === "ENAMETOOLONG") {
      return false;
    }
    return true;
  }
}

function globMatchesSensitivePath(workspaceRoot: string, rawPath: string): boolean {
  if (![...rawPath].some((character) => GLOB_METACHARACTERS.has(character))) {
    return false;
  }
  let count = 0;
  for (const match of globRelative(rawPath, workspaceRoot)) {
    count += 1;
    if (count > MAX_GLOB_MATCHES) {
      throw new ShellPolicyError(
        `Read-only command glob matched more than ${MAX_GLOB_MATCHES.toLocaleString("en-US")} paths`
      );
    }
    if (isSensitiveRepositoryPath(match)) {
      return true;
    }
  }
  return false;
}

function validateReadOnlyStagePaths(
  stage: string[],
  workspaceRoot: string,
  allowedSensitiveFiles: readonly string[]
): string | null {
  if (stage.length === 0) {
    return null;
  }
  const root = path.resolve(workspaceRoot);

  for (const token of stage.slice(1)) {
    for (const candidate of pathCandidates(token)) {
      if (globMatchesSensitivePath(root, candidate)) {
        return `Sensitive path is blocked: ${candidate}`;
      }
      if (path.isAbsolute(candidate)) {
        if (referencesSensitivePath(candidate, allowedSensitiveFiles)) {
          return `Sensitive path is blocked: ${candidate}`;
        }
        if (!pathStaysInsideWorkspace(root, candidate)) {
          return `Path is outside the repository workspace: ${candidate}`;
        }
        return "Absolute repository paths are blocked. Use relative paths instead.";
      }
      if (!looksLikePathToken(candidate) && !workspacePathExists(root, candidate)) {
        continue;
      }
      if (referencesSensitivePath(candidate, allowedSensitiveFiles)) {
        return `Sensitive path is blocked: ${candidate}`;
      }
      if (!pathStaysInsideWorkspace(root, candidate)) {
        return (
          `Path is outside the repository workspace: ${candidate}. ` +
          "Use relative paths from the repository root " +
          "(e.g., src/utils.py instead of /workspace/repo/src/utils.py)."
        );
      }
    }
  }
  return null;
}

// --- glob expansion -------------------------------------------------------

const OPTIONS_CONSUMING_GLOB_PATTERN: Record<string, Set<string>> = {
  find: new Set([
    "-name", "-iname", "-path", "-ipath", "-wholename", "-iwholename", "-lname",
    "-ilname", "-regex", "-iregex",
  ]),
  grep: new Set(["--include", "--exclude", "--exclude-dir"]),
  rg: new Set(["--glob", "--iglob", "-g", "--type-add"]),
  tree: new Set(["-P", "-I"]),
};

// Python glob.iglob(pattern, root_dir) — non-recursive, no dotfile match unless the
// segment starts with '.'. Returns matches relative to rootDir.
export function globRelative(pattern: string, rootDir: string): string[] {
  if (path.isAbsolute(pattern)) {
    return [];
  }
  const segments = pattern.split("/");
  let results: string[] = [""];
  for (let si = 0; si < segments.length; si++) {
    const segment = segments[si];
    const isLast = si === segments.length - 1;
    const hasMeta = [...segment].some((c) => GLOB_METACHARACTERS.has(c));
    const next: string[] = [];
    for (const base of results) {
      const baseAbs = base ? path.join(rootDir, base) : rootDir;
      if (!hasMeta) {
        if (segment === "" || segment === ".") {
          continue;
        }
        const rel = base ? `${base}/${segment}` : segment;
        if (fs.existsSync(path.join(rootDir, rel))) {
          next.push(rel);
        }
      } else {
        let entries: string[];
        try {
          entries = fs.readdirSync(baseAbs);
        } catch {
          continue;
        }
        for (const name of entries) {
          if (name.startsWith(".") && !segment.startsWith(".")) {
            continue;
          }
          if (!fnmatchcase(name, segment)) {
            continue;
          }
          const rel = base ? `${base}/${name}` : name;
          if (isLast) {
            next.push(rel);
          } else {
            try {
              if (fs.statSync(path.join(rootDir, rel)).isDirectory()) {
                next.push(rel);
              }
            } catch {
              // not a directory: cannot descend
            }
          }
        }
      }
    }
    results = next;
  }
  return results;
}

function expandGlobs(stage: ShellToken[], workingDirectory: string | null): string[] {
  if (workingDirectory === null) {
    return stage.map((token) => token.value);
  }
  const expanded: string[] = [stage[0].value];
  const patternOptions =
    OPTIONS_CONSUMING_GLOB_PATTERN[baseName(stage[0].value)] ?? new Set<string>();
  let skipNext = false;
  for (const token of stage.slice(1)) {
    const argument = token.value;
    if (skipNext) {
      expanded.push(argument);
      skipNext = false;
      continue;
    }
    if (patternOptions.has(argument)) {
      expanded.push(argument);
      skipNext = true;
      continue;
    }
    if (argument.startsWith("-")) {
      expanded.push(argument);
      continue;
    }
    if (!token.expandGlob) {
      expanded.push(argument);
      continue;
    }
    const matches: string[] = [];
    for (const match of globRelative(argument, workingDirectory)) {
      matches.push(match);
      if (matches.length > MAX_GLOB_MATCHES) {
        throw new ShellPolicyError(
          `Read-only command glob matched more than ${MAX_GLOB_MATCHES.toLocaleString("en-US")} paths`
        );
      }
    }
    matches.sort();
    if (matches.length > 0) {
      expanded.push(...matches);
    } else {
      expanded.push(argument);
    }
  }
  return expanded;
}

export function validateCommandSize(command: string, commandList: ParsedCommand[]): void {
  if (command.length > MAX_COMMAND_CHARS) {
    throw new ShellPolicyError(
      `Read-only command exceeds the ${MAX_COMMAND_CHARS.toLocaleString("en-US")}-character limit`
    );
  }
  if (commandList.length > MAX_COMPOUND_COMMANDS) {
    throw new ShellPolicyError(
      `Read-only command contains more than ${MAX_COMPOUND_COMMANDS} compound entries`
    );
  }
  let tokenCount = 0;
  for (const { stages } of commandList) {
    if (stages.length > MAX_PIPELINE_STAGES) {
      throw new ShellPolicyError(
        `Read-only command contains more than ${MAX_PIPELINE_STAGES} pipeline stages`
      );
    }
    tokenCount += stages.reduce((sum, stage) => sum + stage.length, 0);
  }
  if (tokenCount > MAX_COMMAND_TOKENS) {
    throw new ShellPolicyError(
      `Read-only command contains more than ${MAX_COMMAND_TOKENS} arguments`
    );
  }
}

// Run the full validation pipeline (parse -> allow-list -> size -> prepare every
// pipeline) without executing. Throws ShellPolicyError on the first violation.
export function validateCommandOnly(
  command: string,
  workingDirectory: string | null,
  allowedSensitiveFiles: readonly string[] = []
): ParsedCommand[] {
  const stripped = command.trim();
  if (!command || !stripped) {
    throw new ShellPolicyError("Command cannot be empty");
  }
  if (stripped.length > MAX_COMMAND_CHARS) {
    throw new ShellPolicyError(
      `Read-only command exceeds the ${MAX_COMMAND_CHARS.toLocaleString("en-US")}-character limit`
    );
  }
  const commandList = parseReadOnlyCommandList(stripped).map((parsed) => ({
    connector: parsed.connector,
    stages: parsed.stages.map(validateReadOnlyStage),
  }));
  validateCommandSize(command, commandList);
  for (const { stages } of commandList) {
    preparePipeline(stages, workingDirectory, allowedSensitiveFiles);
  }
  return commandList;
}

// Expand and validate every stage before executing anything.
export function preparePipeline(
  stages: ShellToken[][],
  workingDirectory: string | null,
  allowedSensitiveFiles: readonly string[]
): string[][] {
  const expandedStages: string[][] = [];
  for (const stage of stages) {
    const expandedStage = expandGlobs(stage, workingDirectory);
    const argvBytes = expandedStage.reduce(
      (sum, argument) => sum + Buffer.byteLength(argument, "utf-8") + 1,
      0
    );
    if (argvBytes > MAX_STAGE_ARGV_BYTES) {
      throw new ShellPolicyError(
        `Read-only command arguments exceed the ${MAX_STAGE_ARGV_BYTES.toLocaleString("en-US")}-byte limit`
      );
    }
    validateCommandArguments(baseName(expandedStage[0]), expandedStage.slice(1));
    if (workingDirectory !== null) {
      const pathError = validateReadOnlyStagePaths(
        expandedStage,
        workingDirectory,
        allowedSensitiveFiles
      );
      if (pathError !== null) {
        throw new ShellPolicyError(pathError);
      }
    }
    expandedStages.push(expandedStage);
  }
  return expandedStages;
}
