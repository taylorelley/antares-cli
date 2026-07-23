import { execFile } from "child_process";
import * as fs from "fs/promises";
import * as path from "path";
import { promisify } from "util";
import * as vscode from "vscode";

import { EnvironmentConfig } from "./config";

const execFileAsync = promisify(execFile);

export class PythonEnvError extends Error {}

export interface ResolvedInterpreter {
  // Absolute path (or command name) of a Python interpreter with antares-cli importable.
  interpreter: string;
  // Whether this interpreter lives in the extension-managed virtual environment.
  managed: boolean;
}

const MIN_PYTHON = [3, 11] as const;

interface CommandResult {
  code: number;
  stdout: string;
  stderr: string;
}

async function run(
  command: string,
  args: string[],
  options: { cwd?: string; timeoutMs?: number } = {}
): Promise<CommandResult> {
  try {
    const { stdout, stderr } = await execFileAsync(command, args, {
      cwd: options.cwd,
      timeout: options.timeoutMs ?? 300_000,
      maxBuffer: 16 * 1024 * 1024,
    });
    return { code: 0, stdout, stderr };
  } catch (error) {
    const err = error as NodeJS.ErrnoException & {
      code?: number | string;
      stdout?: string;
      stderr?: string;
    };
    if (err.code === "ENOENT") {
      throw new PythonEnvError(`Command not found: ${command}`);
    }
    return {
      code: typeof err.code === "number" ? err.code : 1,
      stdout: err.stdout ?? "",
      stderr: err.stderr ?? String(error),
    };
  }
}

function venvInterpreterPath(venvDir: string): string {
  return process.platform === "win32"
    ? path.join(venvDir, "Scripts", "python.exe")
    : path.join(venvDir, "bin", "python");
}

async function pathExists(target: string): Promise<boolean> {
  try {
    await fs.access(target);
    return true;
  } catch {
    return false;
  }
}

async function canImportAntares(interpreter: string): Promise<boolean> {
  const result = await run(interpreter, ["-c", "import antares_cli"], { timeoutMs: 30_000 });
  return result.code === 0;
}

async function pythonVersionAtLeast(interpreter: string): Promise<boolean> {
  const result = await run(
    interpreter,
    ["-c", "import sys; print('%d %d' % sys.version_info[:2])"],
    { timeoutMs: 30_000 }
  );
  if (result.code !== 0) {
    return false;
  }
  const parts = result.stdout.trim().split(/\s+/).map((v) => Number.parseInt(v, 10));
  if (parts.length < 2 || parts.some((v) => Number.isNaN(v))) {
    return false;
  }
  const [major, minor] = parts;
  return major > MIN_PYTHON[0] || (major === MIN_PYTHON[0] && minor >= MIN_PYTHON[1]);
}

// Candidate base interpreters to try, in priority order.
function baseInterpreterCandidates(envConfig: EnvironmentConfig): string[] {
  if (envConfig.pythonPath) {
    return [envConfig.pythonPath];
  }
  return process.platform === "win32" ? ["python", "py"] : ["python3", "python"];
}

async function firstUsableBaseInterpreter(
  envConfig: EnvironmentConfig
): Promise<string | undefined> {
  for (const candidate of baseInterpreterCandidates(envConfig)) {
    if (await pythonVersionAtLeast(candidate)) {
      return candidate;
    }
  }
  return undefined;
}

export interface ResolveOptions {
  report?: (message: string) => void;
}

// Resolve a Python interpreter that can import antares_cli, provisioning a managed
// virtual environment on demand when auto-install is enabled.
export async function resolveInterpreter(
  context: vscode.ExtensionContext,
  envConfig: EnvironmentConfig,
  options: ResolveOptions = {}
): Promise<ResolvedInterpreter> {
  const report = options.report ?? (() => undefined);

  // 1. Honor an explicitly configured interpreter that already has Antares.
  for (const candidate of baseInterpreterCandidates(envConfig)) {
    if (await canImportAntares(candidate)) {
      return { interpreter: candidate, managed: false };
    }
  }

  // 2. Reuse the managed virtual environment if it is already provisioned.
  const venvDir = path.join(context.globalStorageUri.fsPath, "venv");
  const venvInterpreter = venvInterpreterPath(venvDir);
  if (await pathExists(venvInterpreter)) {
    if (envConfig.autoInstall && !(await canImportAntares(venvInterpreter))) {
      report(`Updating Antares in the managed environment (${envConfig.packageSpec})…`);
      await installAntares(venvInterpreter, envConfig, report);
    }
    if (await canImportAntares(venvInterpreter)) {
      return { interpreter: venvInterpreter, managed: true };
    }
  }

  // 3. Provision a fresh managed environment.
  if (!envConfig.autoInstall) {
    throw new PythonEnvError(
      "antares-cli is not available and automatic installation is disabled " +
        "(antares.autoInstall = false). Install antares-cli into the interpreter at " +
        "antares.pythonPath, or enable auto-install."
    );
  }

  const baseInterpreter = await firstUsableBaseInterpreter(envConfig);
  if (!baseInterpreter) {
    throw new PythonEnvError(
      "Could not find a Python 3.11+ interpreter. Install Python 3.11 or newer, or set " +
        "antares.pythonPath to a suitable interpreter."
    );
  }

  await fs.mkdir(context.globalStorageUri.fsPath, { recursive: true });
  report("Creating managed Python environment…");
  const created = await run(baseInterpreter, ["-m", "venv", venvDir], { timeoutMs: 180_000 });
  if (created.code !== 0) {
    throw new PythonEnvError(
      `Failed to create virtual environment: ${created.stderr || created.stdout}`
    );
  }

  report(`Installing ${envConfig.packageSpec}…`);
  await installAntares(venvInterpreter, envConfig, report);

  if (!(await canImportAntares(venvInterpreter))) {
    throw new PythonEnvError(
      `Installed ${envConfig.packageSpec} but antares_cli is still not importable. ` +
        "Check antares.packageSpec."
    );
  }
  return { interpreter: venvInterpreter, managed: true };
}

async function installAntares(
  interpreter: string,
  envConfig: EnvironmentConfig,
  report: (message: string) => void
): Promise<void> {
  report("Upgrading pip…");
  await run(interpreter, ["-m", "pip", "install", "--upgrade", "pip"], { timeoutMs: 180_000 });

  report(`Installing ${envConfig.packageSpec}…`);
  const install = await run(
    interpreter,
    ["-m", "pip", "install", "--upgrade", envConfig.packageSpec],
    { timeoutMs: 600_000 }
  );
  if (install.code !== 0) {
    throw new PythonEnvError(
      `pip failed to install ${envConfig.packageSpec}: ${install.stderr || install.stdout}`
    );
  }
}
