// Port of antares_cli/core/repository_paths.py — shared repository traversal policy.

import * as fs from "fs";
import * as path from "path";

import { isSensitiveRepositoryPath } from "./sensitivePaths";

export const MAX_REPOSITORY_FILES = 100_000;
export const MAX_REPOSITORY_BYTES = 2 * 1024 * 1024 * 1024;
export const MAX_REPOSITORY_FILE_BYTES = 256 * 1024 * 1024;

export const COMMON_IGNORED_DIRECTORY_NAMES = new Set([
  ".antares-data",
  ".git",
  ".gradle",
  ".hg",
  ".mypy_cache",
  ".nox",
  ".pytest_cache",
  ".ruff_cache",
  ".svn",
  ".tox",
  ".venv",
  ".worktrees",
  "__pycache__",
  "node_modules",
  "venv",
]);

// Case-sensitive fnmatch (Python fnmatch.fnmatchcase): translate a glob to an
// anchored regular expression. Supports * ? [seq] [!seq].
export function fnmatchcase(name: string, pattern: string): boolean {
  return translateGlob(pattern).test(name);
}

const globCache = new Map<string, RegExp>();

function translateGlob(pattern: string): RegExp {
  const cached = globCache.get(pattern);
  if (cached) {
    return cached;
  }
  let regex = "";
  let i = 0;
  while (i < pattern.length) {
    const c = pattern[i++];
    if (c === "*") {
      regex += ".*";
    } else if (c === "?") {
      regex += ".";
    } else if (c === "[") {
      let j = i;
      if (j < pattern.length && (pattern[j] === "!" || pattern[j] === "^")) {
        j++;
      }
      if (j < pattern.length && pattern[j] === "]") {
        j++;
      }
      while (j < pattern.length && pattern[j] !== "]") {
        j++;
      }
      if (j >= pattern.length) {
        regex += "\\[";
      } else {
        let stuff = pattern.slice(i, j).replace(/\\/g, "\\\\");
        i = j + 1;
        if (stuff.startsWith("!")) {
          stuff = "^" + stuff.slice(1);
        } else if (stuff.startsWith("^")) {
          stuff = "\\" + stuff;
        }
        regex += `[${stuff}]`;
      }
    } else {
      regex += c.replace(/[.^$+{}()|\\/\[\]*?-]/g, "\\$&");
    }
  }
  const compiled = new RegExp(`^(?:${regex})$`, "s");
  globCache.set(pattern, compiled);
  return compiled;
}

// Normalize repository-relative exclusion patterns.
export function normalizeIgnorePatterns(ignorePaths: readonly string[]): string[] {
  return ignorePaths
    .map((pattern) => pattern.trim())
    .filter((pattern) => pattern.length > 0)
    .map((pattern) => pattern.replace(/^\.\//, "").replace(/\/+$/, ""));
}

// Return whether one repository path matches a normalized exclusion pattern.
export function matchesIgnorePattern(
  relativePath: string,
  name: string,
  pattern: string
): boolean {
  if (fnmatchcase(relativePath, pattern) || fnmatchcase(name, pattern)) {
    return true;
  }
  if (pattern.endsWith("/**")) {
    const directoryPrefix = pattern.slice(0, -"/**".length).replace(/\/+$/, "");
    return relativePath === directoryPrefix || relativePath.startsWith(`${directoryPrefix}/`);
  }
  return false;
}

function toPosix(p: string): string {
  return p.split(path.sep).join("/");
}

// Yield repository files deterministically without descending into ignored trees.
export function* iterRepositoryFiles(
  root: string,
  ignorePaths: readonly string[] = [],
  allowSensitiveFiles: readonly string[] = []
): Generator<string> {
  const normalizedPatterns = normalizeIgnorePatterns(ignorePaths);
  const rootStat = safeLstat(root);
  if (rootStat?.isFile()) {
    const name = path.basename(root);
    if (!normalizedPatterns.some((pattern) => matchesIgnorePattern(name, name, pattern))) {
      yield root;
    }
    return;
  }

  const walk = function* (dir: string, relDir: string): Generator<string> {
    let entries: fs.Dirent[];
    try {
      entries = fs.readdirSync(dir, { withFileTypes: true });
    } catch {
      return;
    }
    const dirNames = entries
      .filter((e) => e.isDirectory() && !e.isSymbolicLink())
      .map((e) => e.name)
      .filter(
        (name) =>
          !COMMON_IGNORED_DIRECTORY_NAMES.has(name) &&
          !normalizedPatterns.some((pattern) =>
            matchesIgnorePattern(joinPosix(relDir, name), name, pattern)
          )
      )
      .sort();

    const fileNames = entries
      .filter((e) => !e.isDirectory())
      .map((e) => e.name)
      .sort();

    for (const fileName of fileNames) {
      const full = path.join(dir, fileName);
      const relativePath = joinPosix(relDir, fileName);
      const lst = safeLstat(full);
      if (!lst || lst.isSymbolicLink()) {
        continue;
      }
      if (normalizedPatterns.some((pattern) => matchesIgnorePattern(relativePath, fileName, pattern))) {
        continue;
      }
      if (isSensitiveRepositoryPath(relativePath) && !allowSensitiveFiles.includes(relativePath)) {
        continue;
      }
      yield full;
    }

    for (const name of dirNames) {
      yield* walk(path.join(dir, name), joinPosix(relDir, name));
    }
  };

  yield* walk(root, "");
}

function joinPosix(relDir: string, name: string): string {
  return relDir ? `${relDir}/${name}` : name;
}

function safeLstat(target: string): fs.Stats | undefined {
  try {
    return fs.lstatSync(target);
  } catch {
    return undefined;
  }
}

export { toPosix };
