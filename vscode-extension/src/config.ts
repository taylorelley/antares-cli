import * as vscode from "vscode";

import { AntaresConfig, ApiStyleSetting, Provider } from "./requestBuilder";

export interface EnvironmentConfig {
  pythonPath: string;
  autoInstall: boolean;
  packageSpec: string;
}

export type DiagnosticsSeverity = "error" | "warning" | "information" | "hint";

export function readConfig(scope?: vscode.ConfigurationScope): AntaresConfig {
  const config = vscode.workspace.getConfiguration("antares", scope);
  return {
    provider: config.get<Provider>("provider", "ollama"),
    endpoint: config.get<string>("endpoint", ""),
    model: config.get<string>("model", ""),
    apiStyle: config.get<ApiStyleSetting>("apiStyle", "auto"),
    toolBudget: config.get<number>("toolBudget", 0),
    sweepWorkers: config.get<number>("sweep.workers", 4),
    sweepMaxCwes: config.get<number>("sweep.maxCwes", 8),
  };
}

export function readEnvironmentConfig(): EnvironmentConfig {
  const config = vscode.workspace.getConfiguration("antares");
  return {
    pythonPath: config.get<string>("pythonPath", "").trim(),
    autoInstall: config.get<boolean>("autoInstall", true),
    packageSpec: config.get<string>("packageSpec", "antares-cli").trim() || "antares-cli",
  };
}

export function readDiagnosticsSeverity(): vscode.DiagnosticSeverity {
  const value = vscode.workspace
    .getConfiguration("antares")
    .get<DiagnosticsSeverity>("diagnosticsSeverity", "warning");
  switch (value) {
    case "error":
      return vscode.DiagnosticSeverity.Error;
    case "information":
      return vscode.DiagnosticSeverity.Information;
    case "hint":
      return vscode.DiagnosticSeverity.Hint;
    case "warning":
    default:
      return vscode.DiagnosticSeverity.Warning;
  }
}
