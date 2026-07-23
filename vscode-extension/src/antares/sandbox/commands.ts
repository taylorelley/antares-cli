// Pure-TypeScript emulation of the allow-listed read-only commands, operating over
// the workspace filesystem. These replace the subprocess execution half of
// tools/shell_exec.py. They target functional correctness (the output the agent reads
// to locate vulnerabilities), not byte-identical GNU coreutils formatting.

import * as fs from "fs";
import * as path from "path";

export interface CommandContext {
  argv: string[]; // argv[0] is the command name
  stdin: string;
  cwd: string;
}

export interface CommandResult {
  stdout: string;
  stderr: string;
  code: number;
}

export type CommandFn = (ctx: CommandContext) => CommandResult;

function ok(stdout: string, code = 0, stderr = ""): CommandResult {
  return { stdout, stderr, code };
}

// Resolve a repository-relative path inside the workspace, or null if it escapes.
function resolveInside(cwd: string, rel: string): string | null {
  const resolved = path.resolve(cwd, rel);
  if (resolved === cwd || resolved.startsWith(cwd + path.sep)) {
    return resolved;
  }
  return null;
}

function readFileConfined(cwd: string, rel: string): { content?: string; error?: string } {
  const resolved = resolveInside(cwd, rel);
  if (!resolved) {
    return { error: `${rel}: Permission denied` };
  }
  let real: string;
  try {
    real = fs.realpathSync(resolved);
  } catch {
    return { error: `${rel}: No such file or directory` };
  }
  if (real !== resolved && !real.startsWith(cwd + path.sep) && real !== cwd) {
    return { error: `${rel}: Permission denied` };
  }
  let stat: fs.Stats;
  try {
    stat = fs.statSync(real);
  } catch {
    return { error: `${rel}: No such file or directory` };
  }
  if (stat.isDirectory()) {
    return { error: `${rel}: Is a directory` };
  }
  return { content: fs.readFileSync(real, "utf-8") };
}

// Split argv into options and positional operands (first "--" ends options).
// valueOptions naming exactly-matching flags that consume the following argument.
function positional(argv: string[], valueOptions: Set<string> = new Set()): string[] {
  const out: string[] = [];
  let optionsEnded = false;
  const args = argv.slice(1);
  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    if (!optionsEnded && arg === "--") {
      optionsEnded = true;
    } else if (!optionsEnded && valueOptions.has(arg)) {
      i += 1; // skip the option's value
    } else if (!optionsEnded && arg.startsWith("-") && arg !== "-") {
      // flag, skip
    } else {
      out.push(arg);
    }
  }
  return out;
}

function toLines(text: string): string[] {
  if (text === "") {
    return [];
  }
  const lines = text.split("\n");
  if (lines[lines.length - 1] === "") {
    lines.pop();
  }
  return lines;
}

function* walkDir(root: string): Generator<string> {
  let entries: fs.Dirent[];
  try {
    entries = fs.readdirSync(root, { withFileTypes: true }).sort((a, b) => (a.name < b.name ? -1 : 1));
  } catch {
    return;
  }
  for (const entry of entries) {
    const full = path.join(root, entry.name);
    if (entry.isSymbolicLink()) {
      continue;
    }
    if (entry.isDirectory()) {
      yield* walkDir(full);
    } else if (entry.isFile()) {
      yield full;
    }
  }
}

// --- individual commands --------------------------------------------------

const echo: CommandFn = ({ argv }) => {
  let args = argv.slice(1);
  let newline = true;
  while (args.length > 0 && args[0] === "-n") {
    newline = false;
    args = args.slice(1);
  }
  return ok(args.join(" ") + (newline ? "\n" : ""));
};

const pwd: CommandFn = ({ cwd }) => ok(`${cwd}\n`);
const truthy: CommandFn = () => ok("", 0);
const falsy: CommandFn = () => ok("", 1);

const cat: CommandFn = ({ argv, stdin, cwd }) => {
  const files = positional(argv);
  if (files.length === 0) {
    return ok(stdin);
  }
  let out = "";
  let stderr = "";
  let code = 0;
  for (const file of files) {
    if (file === "-") {
      out += stdin;
      continue;
    }
    const { content, error } = readFileConfined(cwd, file);
    if (error) {
      stderr += `cat: ${error}\n`;
      code = 1;
      continue;
    }
    out += content;
  }
  return ok(out, code, stderr);
};

const HEADTAIL_VALUE_OPTIONS = new Set(["-n", "-c", "--lines", "--bytes"]);

function collectInputs(
  argv: string[],
  stdin: string,
  cwd: string,
  valueOptions: Set<string> = new Set()
): { name: string | null; lines: string[]; content: string; error?: string }[] {
  const files = positional(argv, valueOptions);
  if (files.length === 0) {
    return [{ name: null, lines: toLines(stdin), content: stdin }];
  }
  return files.map((file) => {
    if (file === "-") {
      return { name: null, lines: toLines(stdin), content: stdin };
    }
    const { content, error } = readFileConfined(cwd, file);
    if (error) {
      return { name: file, lines: [], content: "", error };
    }
    return { name: file, lines: toLines(content ?? ""), content: content ?? "" };
  });
}

function parseCount(argv: string[], flag: string, fallback: number): number {
  for (let i = 1; i < argv.length; i++) {
    const arg = argv[i];
    if (arg === flag) {
      return Number.parseInt(argv[i + 1] ?? "", 10) || fallback;
    }
    if (arg.startsWith(flag)) {
      const n = Number.parseInt(arg.slice(flag.length), 10);
      if (Number.isFinite(n)) {
        return n;
      }
    }
    const shorthand = arg.match(/^-(\d+)$/);
    if (shorthand) {
      return Number.parseInt(shorthand[1], 10);
    }
  }
  return fallback;
}

const head: CommandFn = ({ argv, stdin, cwd }) => {
  const n = parseCount(argv, "-n", 10);
  const inputs = collectInputs(argv, stdin, cwd, HEADTAIL_VALUE_OPTIONS);
  const multi = inputs.filter((i) => i.name).length > 1;
  let out = "";
  let stderr = "";
  let code = 0;
  let first = true;
  for (const input of inputs) {
    if (input.error) {
      stderr += `head: cannot open '${input.name}' for reading: No such file or directory\n`;
      code = 1;
      continue;
    }
    if (multi) {
      out += `${first ? "" : "\n"}==> ${input.name} <==\n`;
    }
    first = false;
    const selected = input.lines.slice(0, Math.max(0, n));
    out += selected.map((l) => `${l}\n`).join("");
  }
  return ok(out, code, stderr);
};

const tail: CommandFn = ({ argv, stdin, cwd }) => {
  const n = parseCount(argv, "-n", 10);
  const inputs = collectInputs(argv, stdin, cwd, HEADTAIL_VALUE_OPTIONS);
  const multi = inputs.filter((i) => i.name).length > 1;
  let out = "";
  let stderr = "";
  let code = 0;
  let first = true;
  for (const input of inputs) {
    if (input.error) {
      stderr += `tail: cannot open '${input.name}' for reading: No such file or directory\n`;
      code = 1;
      continue;
    }
    if (multi) {
      out += `${first ? "" : "\n"}==> ${input.name} <==\n`;
    }
    first = false;
    const selected = n >= input.lines.length ? input.lines : input.lines.slice(input.lines.length - n);
    out += selected.map((l) => `${l}\n`).join("");
  }
  return ok(out, code, stderr);
};

const wc: CommandFn = ({ argv, stdin, cwd }) => {
  const flags = argv.slice(1).filter((a) => a.startsWith("-") && a !== "-");
  const wantLines = flags.some((f) => f.includes("l"));
  const wantWords = flags.some((f) => f.includes("w"));
  const wantBytes = flags.some((f) => f.includes("c") || f.includes("m"));
  const showAll = !wantLines && !wantWords && !wantBytes;
  const inputs = collectInputs(argv, stdin, cwd);
  let out = "";
  let stderr = "";
  let code = 0;
  const totals = { lines: 0, words: 0, bytes: 0 };
  for (const input of inputs) {
    if (input.error) {
      stderr += `wc: ${input.name}: No such file or directory\n`;
      code = 1;
      continue;
    }
    const lines = input.content.split("\n").length - 1 + (input.content.endsWith("\n") ? 0 : input.content ? 1 : 0);
    const lineCount = (input.content.match(/\n/g) || []).length;
    const words = input.content.split(/\s+/).filter((w) => w.length > 0).length;
    const bytes = Buffer.byteLength(input.content, "utf-8");
    totals.lines += lineCount;
    totals.words += words;
    totals.bytes += bytes;
    void lines;
    const parts: string[] = [];
    if (showAll || wantLines) parts.push(String(lineCount).padStart(7));
    if (showAll || wantWords) parts.push(String(words).padStart(7));
    if (showAll || wantBytes) parts.push(String(bytes).padStart(7));
    out += parts.join("") + (input.name ? ` ${input.name}` : "") + "\n";
  }
  const named = inputs.filter((i) => i.name && !i.error);
  if (named.length > 1) {
    const parts: string[] = [];
    if (showAll || wantLines) parts.push(String(totals.lines).padStart(7));
    if (showAll || wantWords) parts.push(String(totals.words).padStart(7));
    if (showAll || wantBytes) parts.push(String(totals.bytes).padStart(7));
    out += parts.join("") + " total\n";
  }
  return ok(out, code, stderr);
};

const nl: CommandFn = ({ argv, stdin, cwd }) => {
  const inputs = collectInputs(argv, stdin, cwd);
  let out = "";
  let stderr = "";
  let code = 0;
  let counter = 1;
  for (const input of inputs) {
    if (input.error) {
      stderr += `nl: ${input.name}: No such file or directory\n`;
      code = 1;
      continue;
    }
    for (const line of input.lines) {
      if (line.trim() === "") {
        out += "       \n";
      } else {
        out += `${String(counter).padStart(6)}\t${line}\n`;
        counter += 1;
      }
    }
  }
  return ok(out, code, stderr);
};

function buildRegex(pattern: string, opts: { ignoreCase: boolean; fixed: boolean; word: boolean }): RegExp {
  let source = opts.fixed ? pattern.replace(/[.*+?^${}()|[\]\\]/g, "\\$&") : pattern;
  if (opts.word) {
    source = `\\b(?:${source})\\b`;
  }
  return new RegExp(source, opts.ignoreCase ? "i" : "");
}

const grep: CommandFn = ({ argv, stdin, cwd }) => {
  const args = argv.slice(1);
  const flagChars = new Set<string>();
  const longFlags = new Set<string>();
  const operands: string[] = [];
  let pattern: string | null = null;
  let optionsEnded = false;
  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    if (!optionsEnded && arg === "--") {
      optionsEnded = true;
    } else if (!optionsEnded && arg === "-e") {
      pattern = args[++i] ?? "";
    } else if (!optionsEnded && arg.startsWith("--")) {
      longFlags.add(arg.split("=")[0]);
    } else if (!optionsEnded && arg.startsWith("-") && arg !== "-") {
      for (const c of arg.slice(1)) {
        flagChars.add(c);
      }
    } else if (pattern === null) {
      pattern = arg;
    } else {
      operands.push(arg);
    }
  }
  if (pattern === null) {
    return ok("", 2, "grep: no pattern\n");
  }
  const opts = {
    ignoreCase: flagChars.has("i"),
    fixed: flagChars.has("F"),
    word: flagChars.has("w"),
  };
  const recursive = flagChars.has("r") || flagChars.has("R");
  const withNumbers = flagChars.has("n");
  const invert = flagChars.has("v");
  const listFiles = flagChars.has("l");
  const countOnly = flagChars.has("c");
  const onlyMatching = flagChars.has("o");
  const noFilename = flagChars.has("h");
  let regex: RegExp;
  try {
    regex = buildRegex(pattern, opts);
  } catch {
    return ok("", 2, `grep: invalid pattern: ${pattern}\n`);
  }

  const targets = operands.length > 0 ? operands : recursive ? ["."] : [null];
  const fileList: (string | null)[] = [];
  for (const target of targets) {
    if (target === null) {
      fileList.push(null);
      continue;
    }
    const resolved = resolveInside(cwd, target);
    if (!resolved) {
      continue;
    }
    let stat: fs.Stats;
    try {
      stat = fs.statSync(resolved);
    } catch {
      continue;
    }
    if (stat.isDirectory()) {
      if (recursive) {
        for (const f of walkDir(resolved)) {
          fileList.push(path.relative(cwd, f).split(path.sep).join("/"));
        }
      }
    } else {
      fileList.push(target);
    }
  }

  const showName = recursive || fileList.filter((f) => f !== null).length > 1;
  let out = "";
  let matchedAny = false;
  for (const file of fileList) {
    const content =
      file === null ? stdin : readFileConfined(cwd, file).content ?? "";
    const lines = toLines(content);
    let fileMatches = 0;
    const fileOut: string[] = [];
    lines.forEach((line, index) => {
      const isMatch = regex.test(line);
      if (isMatch === invert) {
        return;
      }
      fileMatches += 1;
      matchedAny = true;
      const prefix = showName && !noFilename && file ? `${file}:` : "";
      const num = withNumbers ? `${index + 1}:` : "";
      if (onlyMatching && !invert) {
        const globalRe = new RegExp(regex.source, regex.flags.includes("g") ? regex.flags : regex.flags + "g");
        for (const m of line.matchAll(globalRe)) {
          fileOut.push(`${prefix}${num}${m[0]}`);
        }
      } else {
        fileOut.push(`${prefix}${num}${line}`);
      }
    });
    if (listFiles) {
      if (fileMatches > 0 && file) {
        out += `${file}\n`;
      }
    } else if (countOnly) {
      const prefix = showName && file ? `${file}:` : "";
      out += `${prefix}${fileMatches}\n`;
    } else {
      out += fileOut.map((l) => `${l}\n`).join("");
    }
  }
  return ok(out, matchedAny ? 0 : 1);
};

// ripgrep: behave like `grep -rn` by default (recursive, line-numbered), grouped flat.
const rg: CommandFn = (ctx) => {
  const args = ctx.argv.slice(1);
  const hasPathOrRecursive = args.some((a) => !a.startsWith("-"));
  const augmented = ["grep", "-r", "-n", ...args.filter((a) => a !== "-r" && a !== "-n")];
  void hasPathOrRecursive;
  return grep({ ...ctx, argv: augmented });
};

const find: CommandFn = ({ argv, cwd }) => {
  const args = argv.slice(1);
  const roots: string[] = [];
  let namePattern: string | null = null;
  let iname = false;
  let typeFilter: string | null = null;
  let maxDepth = Infinity;
  let i = 0;
  while (i < args.length && !args[i].startsWith("-")) {
    roots.push(args[i]);
    i += 1;
  }
  if (roots.length === 0) {
    roots.push(".");
  }
  for (; i < args.length; i++) {
    const arg = args[i];
    if (arg === "-name") {
      namePattern = args[++i];
    } else if (arg === "-iname") {
      namePattern = args[++i];
      iname = true;
    } else if (arg === "-type") {
      typeFilter = args[++i];
    } else if (arg === "-maxdepth") {
      maxDepth = Number.parseInt(args[++i], 10);
    }
  }
  const nameRe = namePattern
    ? new RegExp(
        "^" +
          namePattern
            .replace(/[.+^${}()|[\]\\]/g, "\\$&")
            .replace(/\*/g, ".*")
            .replace(/\?/g, ".") +
          "$",
        iname ? "i" : ""
      )
    : null;

  let out = "";
  let stderr = "";
  let code = 0;
  const emit = (rel: string, isDir: boolean) => {
    const base = path.basename(rel);
    if (nameRe && !nameRe.test(base)) {
      return;
    }
    if (typeFilter === "f" && isDir) return;
    if (typeFilter === "d" && !isDir) return;
    out += `${rel}\n`;
  };

  const walk = (absDir: string, relDir: string, depth: number) => {
    if (depth > maxDepth) {
      return;
    }
    let entries: fs.Dirent[];
    try {
      entries = fs.readdirSync(absDir, { withFileTypes: true }).sort((a, b) => (a.name < b.name ? -1 : 1));
    } catch {
      return;
    }
    for (const entry of entries) {
      if (entry.isSymbolicLink()) {
        continue;
      }
      const rel = relDir === "" ? entry.name : `${relDir}/${entry.name}`;
      const display = relDir === "." || relDir === "" ? `./${entry.name}` : `${relDir}/${entry.name}`;
      if (entry.isDirectory()) {
        emit(display, true);
        walk(path.join(absDir, entry.name), rel === entry.name && relDir === "" ? entry.name : rel, depth + 1);
      } else if (entry.isFile()) {
        emit(display, false);
      }
    }
  };

  for (const root of roots) {
    const resolved = resolveInside(cwd, root);
    if (!resolved || !fs.existsSync(resolved)) {
      stderr += `find: '${root}': No such file or directory\n`;
      code = 1;
      continue;
    }
    if (maxDepth >= 0) {
      emit(root, fs.statSync(resolved).isDirectory());
    }
    if (fs.statSync(resolved).isDirectory()) {
      walk(resolved, root === "." ? "." : root, 1);
    }
  }
  return ok(out, code, stderr);
};

const ls: CommandFn = ({ argv, cwd }) => {
  const flagChars = new Set<string>();
  for (const arg of argv.slice(1)) {
    if (arg.startsWith("-") && arg !== "-" && !arg.startsWith("--")) {
      for (const c of arg.slice(1)) {
        flagChars.add(c);
      }
    }
  }
  const all = flagChars.has("a");
  const targets = positional(argv);
  const dirs = targets.length > 0 ? targets : ["."];
  let out = "";
  let stderr = "";
  let code = 0;
  for (const dir of dirs) {
    const resolved = resolveInside(cwd, dir);
    if (!resolved || !fs.existsSync(resolved)) {
      stderr += `ls: cannot access '${dir}': No such file or directory\n`;
      code = 2;
      continue;
    }
    const stat = fs.statSync(resolved);
    if (stat.isFile()) {
      out += `${dir}\n`;
      continue;
    }
    let names = fs.readdirSync(resolved).sort();
    if (!all) {
      names = names.filter((n) => !n.startsWith("."));
    } else {
      names = [".", "..", ...names];
    }
    if (dirs.length > 1) {
      out += `${dir}:\n`;
    }
    out += names.map((n) => `${n}\n`).join("");
    if (dirs.length > 1) {
      out += "\n";
    }
  }
  return ok(out, code, stderr);
};

const sortCmd: CommandFn = ({ argv, stdin, cwd }) => {
  const flags = argv.slice(1).filter((a) => a.startsWith("-") && a !== "-");
  const numeric = flags.some((f) => f.includes("n"));
  const reverse = flags.some((f) => f.includes("r"));
  const unique = flags.some((f) => f.includes("u"));
  const fold = flags.some((f) => f.includes("f"));
  const inputs = collectInputs(argv, stdin, cwd);
  let lines: string[] = [];
  let stderr = "";
  let code = 0;
  for (const input of inputs) {
    if (input.error) {
      stderr += `sort: cannot read: ${input.name}: No such file or directory\n`;
      code = 2;
      continue;
    }
    lines = lines.concat(input.lines);
  }
  lines.sort((a, b) => {
    let x = fold ? a.toLowerCase() : a;
    let y = fold ? b.toLowerCase() : b;
    if (numeric) {
      return (Number.parseFloat(x) || 0) - (Number.parseFloat(y) || 0);
    }
    return x < y ? -1 : x > y ? 1 : 0;
  });
  if (reverse) {
    lines.reverse();
  }
  if (unique) {
    lines = lines.filter((line, index) => index === 0 || line !== lines[index - 1]);
  }
  return ok(lines.map((l) => `${l}\n`).join(""), code, stderr);
};

const uniq: CommandFn = ({ argv, stdin, cwd }) => {
  const flags = argv.slice(1).filter((a) => a.startsWith("-") && a !== "-");
  const count = flags.some((f) => f.includes("c"));
  const onlyDup = flags.some((f) => f.includes("d"));
  const onlyUniq = flags.some((f) => f.includes("u"));
  const ignoreCase = flags.some((f) => f.includes("i"));
  const files = positional(argv);
  const content =
    files.length > 0 ? readFileConfined(cwd, files[0]).content ?? "" : stdin;
  const lines = toLines(content);
  const groups: { line: string; n: number }[] = [];
  for (const line of lines) {
    const last = groups[groups.length - 1];
    const same = last && (ignoreCase ? last.line.toLowerCase() === line.toLowerCase() : last.line === line);
    if (same) {
      last.n += 1;
    } else {
      groups.push({ line, n: 1 });
    }
  }
  let out = "";
  for (const g of groups) {
    if (onlyDup && g.n < 2) continue;
    if (onlyUniq && g.n > 1) continue;
    out += (count ? `${String(g.n).padStart(7)} ` : "") + `${g.line}\n`;
  }
  return ok(out);
};

const cut: CommandFn = ({ argv, stdin, cwd }) => {
  const args = argv.slice(1);
  let delim = "\t";
  let fields: string | null = null;
  let chars: string | null = null;
  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    if (arg === "-d") delim = args[++i] ?? "\t";
    else if (arg.startsWith("-d")) delim = arg.slice(2);
    else if (arg === "-f") fields = args[++i] ?? null;
    else if (arg.startsWith("-f")) fields = arg.slice(2);
    else if (arg === "-c") chars = args[++i] ?? null;
    else if (arg.startsWith("-c")) chars = arg.slice(2);
  }
  const files = positional(args.length ? ["cut", ...positional(argv)] : argv);
  const content = files.length > 0 ? readFileConfined(cwd, files[0]).content ?? "" : stdin;
  const lines = toLines(content);
  const selectors = (spec: string): number[] =>
    spec
      .split(",")
      .flatMap((part) => {
        const m = part.match(/^(\d+)?-(\d+)?$/);
        if (m) {
          const start = m[1] ? Number.parseInt(m[1], 10) : 1;
          const end = m[2] ? Number.parseInt(m[2], 10) : 9999;
          return Array.from({ length: end - start + 1 }, (_, k) => start + k);
        }
        return [Number.parseInt(part, 10)];
      })
      .filter((n) => Number.isFinite(n));
  let out = "";
  for (const line of lines) {
    if (chars) {
      const idx = selectors(chars);
      out += idx.map((i) => line[i - 1] ?? "").join("") + "\n";
    } else if (fields) {
      const idx = selectors(fields);
      const parts = line.split(delim);
      out += idx.map((i) => parts[i - 1]).filter((v) => v !== undefined).join(delim) + "\n";
    } else {
      out += line + "\n";
    }
  }
  return ok(out);
};

const sed: CommandFn = ({ argv, stdin, cwd }) => {
  const args = argv.slice(1);
  let quiet = false;
  const scripts: string[] = [];
  const files: string[] = [];
  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    if (arg === "-n" || arg === "--quiet" || arg === "--silent") quiet = true;
    else if (arg === "-e") scripts.push(args[++i]);
    else if (arg === "-E" || arg === "-r" || arg === "--regexp-extended") {
      // extended regex — JS regex already extended
    } else if (arg.startsWith("-")) {
      // ignore other allowed options
    } else if (scripts.length === 0) {
      scripts.push(arg);
    } else {
      files.push(arg);
    }
  }
  const content = files.length > 0 ? readFileConfined(cwd, files[0]).content ?? "" : stdin;
  const lines = toLines(content);
  let out = "";
  for (const script of scripts) {
    const rangeMatch = script.match(/^(\d+|\$)(?:,(\d+|\$))?p$/);
    if (rangeMatch) {
      const total = lines.length;
      const start = rangeMatch[1] === "$" ? total : Number.parseInt(rangeMatch[1], 10);
      const end = rangeMatch[2] === undefined ? start : rangeMatch[2] === "$" ? total : Number.parseInt(rangeMatch[2], 10);
      lines.forEach((line, index) => {
        const n = index + 1;
        if (n >= start && n <= end) {
          out += `${line}\n`;
        }
      });
      continue;
    }
    if (script[0] === "s") {
      const delimiter = script[1];
      const parts: string[] = [];
      let current = "";
      let i = 2;
      while (i < script.length && parts.length < 3) {
        const ch = script[i];
        if (ch === "\\" && i + 1 < script.length) {
          current += script[i] + script[i + 1];
          i += 2;
          continue;
        }
        if (ch === delimiter) {
          parts.push(current);
          current = "";
          i += 1;
          continue;
        }
        current += ch;
        i += 1;
      }
      parts.push(current);
      const [patternSrc, replacement, flags = ""] = parts;
      const jsFlags = "g" + (flags.includes("i") || flags.includes("I") ? "i" : "");
      const global = flags.includes("g");
      let re: RegExp;
      try {
        re = new RegExp(patternSrc, global ? jsFlags : jsFlags.replace("g", ""));
      } catch {
        return ok(out, 1, `sed: invalid expression\n`);
      }
      const jsReplacement = replacement.replace(/\\(\d)/g, "$$$1").replace(/&/g, "$$&");
      for (const line of lines) {
        const replaced = line.replace(re, jsReplacement);
        if (!quiet) {
          out += `${replaced}\n`;
        }
      }
      continue;
    }
  }
  return ok(out);
};

const basename: CommandFn = ({ argv }) => {
  const args = positional(argv);
  if (args.length === 0) {
    return ok("", 1, "basename: missing operand\n");
  }
  let base = path.posix.basename(args[0].replace(/\\/g, "/"));
  if (args[1] && base.endsWith(args[1]) && base !== args[1]) {
    base = base.slice(0, -args[1].length);
  }
  return ok(`${base}\n`);
};

const dirname: CommandFn = ({ argv }) => {
  const args = positional(argv);
  if (args.length === 0) {
    return ok("", 1, "dirname: missing operand\n");
  }
  return ok(`${path.posix.dirname(args[0].replace(/\\/g, "/"))}\n`);
};

const realpath: CommandFn = ({ argv, cwd }) => {
  const args = positional(argv);
  let out = "";
  let stderr = "";
  let code = 0;
  for (const arg of args) {
    const resolved = resolveInside(cwd, arg);
    if (resolved && fs.existsSync(resolved)) {
      out += `${resolved}\n`;
    } else {
      stderr += `realpath: ${arg}: No such file or directory\n`;
      code = 1;
    }
  }
  return ok(out, code, stderr);
};

const stat: CommandFn = ({ argv, cwd }) => {
  const files = positional(argv);
  let out = "";
  let stderr = "";
  let code = 0;
  for (const file of files) {
    const resolved = resolveInside(cwd, file);
    if (!resolved || !fs.existsSync(resolved)) {
      stderr += `stat: cannot statx '${file}': No such file or directory\n`;
      code = 1;
      continue;
    }
    const st = fs.statSync(resolved);
    out += `  File: ${file}\n  Size: ${st.size}\t${st.isDirectory() ? "directory" : "regular file"}\n`;
  }
  return ok(out, code, stderr);
};

const du: CommandFn = ({ argv, cwd }) => {
  const files = positional(argv);
  const targets = files.length > 0 ? files : ["."];
  let out = "";
  for (const target of targets) {
    const resolved = resolveInside(cwd, target);
    if (!resolved || !fs.existsSync(resolved)) {
      continue;
    }
    let total = 0;
    if (fs.statSync(resolved).isDirectory()) {
      for (const f of walkDir(resolved)) {
        total += fs.statSync(f).size;
      }
    } else {
      total = fs.statSync(resolved).size;
    }
    out += `${Math.ceil(total / 1024)}\t${target}\n`;
  }
  return ok(out);
};

const file: CommandFn = ({ argv, cwd }) => {
  const files = positional(argv);
  let out = "";
  for (const f of files) {
    const resolved = resolveInside(cwd, f);
    if (!resolved || !fs.existsSync(resolved)) {
      out += `${f}: cannot open (No such file or directory)\n`;
      continue;
    }
    if (fs.statSync(resolved).isDirectory()) {
      out += `${f}: directory\n`;
      continue;
    }
    const buf = fs.readFileSync(resolved);
    const isBinary = buf.includes(0);
    out += `${f}: ${isBinary ? "data" : "ASCII text"}\n`;
  }
  return ok(out);
};

const diff: CommandFn = ({ argv, cwd }) => {
  const files = positional(argv);
  if (files.length < 2) {
    return ok("", 2, "diff: missing operand\n");
  }
  const a = readFileConfined(cwd, files[0]);
  const b = readFileConfined(cwd, files[1]);
  if (a.error || b.error) {
    return ok("", 2, `diff: ${a.error ?? b.error}\n`);
  }
  if (a.content === b.content) {
    return ok("");
  }
  const al = toLines(a.content ?? "");
  const bl = toLines(b.content ?? "");
  let out = "";
  const max = Math.max(al.length, bl.length);
  for (let i = 0; i < max; i++) {
    if (al[i] !== bl[i]) {
      if (al[i] !== undefined) out += `< ${al[i]}\n`;
      if (bl[i] !== undefined) out += `> ${bl[i]}\n`;
    }
  }
  return ok(out, 1);
};

const tree: CommandFn = ({ argv, cwd }) => {
  const flagChars = new Set<string>();
  for (const arg of argv.slice(1)) {
    if (arg.startsWith("-") && !arg.startsWith("--")) {
      for (const c of arg.slice(1)) flagChars.add(c);
    }
  }
  const showAll = flagChars.has("a");
  const dirsOnly = flagChars.has("d");
  let maxLevel = Infinity;
  const args = argv.slice(1);
  for (let i = 0; i < args.length; i++) {
    if (args[i] === "-L") maxLevel = Number.parseInt(args[i + 1], 10);
  }
  const targets = positional(argv);
  const root = targets.length > 0 ? targets[0] : ".";
  const resolvedRoot = resolveInside(cwd, root);
  if (!resolvedRoot || !fs.existsSync(resolvedRoot)) {
    return ok("", 1, `${root} [error opening dir]\n`);
  }
  let out = `${root}\n`;
  let dirCount = 0;
  let fileCount = 0;
  const walk = (absDir: string, prefix: string, level: number) => {
    if (level > maxLevel) {
      return;
    }
    let entries: fs.Dirent[];
    try {
      entries = fs.readdirSync(absDir, { withFileTypes: true }).sort((a, b) => (a.name < b.name ? -1 : 1));
    } catch {
      return;
    }
    let filtered = entries.filter((e) => !e.isSymbolicLink());
    if (!showAll) filtered = filtered.filter((e) => !e.name.startsWith("."));
    if (dirsOnly) filtered = filtered.filter((e) => e.isDirectory());
    filtered.forEach((entry, index) => {
      const isLast = index === filtered.length - 1;
      const connector = isLast ? "└── " : "├── ";
      out += `${prefix}${connector}${entry.name}\n`;
      if (entry.isDirectory()) {
        dirCount += 1;
        walk(path.join(absDir, entry.name), prefix + (isLast ? "    " : "│   "), level + 1);
      } else {
        fileCount += 1;
      }
    });
  };
  walk(resolvedRoot, "", 1);
  out += `\n${dirCount} director${dirCount === 1 ? "y" : "ies"}, ${fileCount} file${fileCount === 1 ? "" : "s"}\n`;
  return ok(out);
};

export const COMMANDS: Record<string, CommandFn> = {
  echo,
  pwd,
  true: truthy,
  false: falsy,
  cat,
  head,
  tail,
  wc,
  nl,
  grep,
  rg,
  find,
  ls,
  sort: sortCmd,
  uniq,
  cut,
  sed,
  basename,
  dirname,
  realpath,
  stat,
  du,
  file,
  diff,
  tree,
};
