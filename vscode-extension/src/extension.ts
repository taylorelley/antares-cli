import * as vscode from "vscode";

import { readConfig, readDiagnosticsSeverity } from "./config";
import { DiagnosticsManager } from "./diagnostics";
import { EngineError, runScan, ScanCancelledError } from "./engine/runner";
import { AntaresResult, HostEvent, ScanMode } from "./findings";
import { buildHostRequest, ConfigError, parseCweIds } from "./requestBuilder";
import { CweDatabase } from "./antares/knowledge/cweDatabase";
import { ReportFormat, serializeReport } from "./reports";
import { AntaresResultsProvider } from "./resultsTree";
import { clearApiKey, getApiKey, promptAndStoreApiKey } from "./secrets";

interface LastReport {
  result: AntaresResult;
  target: string;
  mode: ScanMode;
}

export function activate(context: vscode.ExtensionContext): void {
  const output = vscode.window.createOutputChannel("Antares");
  const diagnostics = new DiagnosticsManager();
  const resultsProvider = new AntaresResultsProvider();
  const treeView = vscode.window.createTreeView("antaresResults", {
    treeDataProvider: resultsProvider,
  });

  let lastReport: LastReport | undefined;

  const dataDir = vscode.Uri.joinPath(context.extensionUri, "data").fsPath;

  async function runScanCommand(mode: ScanMode, resource?: vscode.Uri): Promise<void> {
    const target = await resolveTargetFolder(resource);
    if (!target) {
      return;
    }

    let cweIds: string[] | undefined;
    if (mode === "query") {
      const input = await vscode.window.showInputBox({
        title: "Antares: Scan for CWE",
        prompt: "Comma-separated CWE IDs to scan for (e.g. CWE-89, CWE-79, CWE-22).",
        placeHolder: "CWE-89, CWE-79",
        ignoreFocusOut: true,
      });
      if (input === undefined) {
        return;
      }
      cweIds = parseCweIds(input);
      if (cweIds.length === 0) {
        void vscode.window.showErrorMessage(
          "Antares: no valid CWE IDs were provided."
        );
        return;
      }
    }

    const config = readConfig(target);
    let request;
    try {
      request = buildHostRequest(config, { mode, target: target.fsPath, cweIds });
    } catch (error) {
      if (error instanceof ConfigError) {
        void offerSettings(error.message);
        return;
      }
      throw error;
    }

    const apiKey = await getApiKey(context);

    await vscode.window.withProgress(
      {
        location: vscode.ProgressLocation.Notification,
        cancellable: true,
        title: mode === "sweep" ? "Antares auto-sweep" : "Antares scan",
      },
      async (progress, token) => {
        try {
          let findingCount = 0;
          progress.report({
            message: mode === "sweep" ? "Selecting CWE classes…" : "Investigating…",
          });

          const result = await runScan({
            request,
            dataDir,
            apiKey,
            token,
            log: (line) => output.appendLine(line),
            onEvent: (event) => {
              findingCount = handleEvent(event, progress, findingCount);
            },
          });

          diagnostics.setFindings(
            target.fsPath,
            result.findings,
            readDiagnosticsSeverity()
          );
          resultsProvider.update(result, target.fsPath, mode);
          lastReport = { result, target: target.fsPath, mode };
          treeView.title = `Findings (${result.summary.total_findings})`;
          reportSummary(result);
        } catch (error) {
          handleScanError(error, output);
        }
      }
    );
  }

  context.subscriptions.push(
    output,
    diagnostics,
    treeView,
    vscode.commands.registerCommand("antares.scanForCwe", (resource?: vscode.Uri) =>
      runScanCommand("query", resource)
    ),
    vscode.commands.registerCommand("antares.autoSweep", (resource?: vscode.Uri) =>
      runScanCommand("sweep", resource)
    ),
    vscode.commands.registerCommand("antares.setApiKey", () =>
      promptAndStoreApiKey(context)
    ),
    vscode.commands.registerCommand("antares.clearApiKey", () => clearApiKey(context)),
    vscode.commands.registerCommand("antares.clearResults", () => {
      diagnostics.clear();
      resultsProvider.clear();
      treeView.title = "Findings";
    }),
    vscode.commands.registerCommand("antares.showLastReport", async () => {
      if (!lastReport) {
        void vscode.window.showInformationMessage("Antares: no scan has run yet.");
        return;
      }
      const document = await vscode.workspace.openTextDocument({
        language: "json",
        content: JSON.stringify(lastReport.result, null, 2),
      });
      await vscode.window.showTextDocument(document, { preview: false });
    }),
    vscode.commands.registerCommand("antares.saveReport", async () => {
      if (!lastReport) {
        void vscode.window.showInformationMessage("Antares: no scan has run yet.");
        return;
      }
      const format = await vscode.window.showQuickPick(
        [
          { label: "JSON", value: "json" as ReportFormat },
          { label: "SARIF", value: "sarif" as ReportFormat },
          { label: "Markdown", value: "markdown" as ReportFormat },
        ],
        { title: "Antares: report format", placeHolder: "Choose a report format" }
      );
      if (!format) {
        return;
      }
      const extensionByFormat: Record<ReportFormat, string> = {
        json: "json",
        sarif: "sarif",
        markdown: "md",
      };
      const target = await vscode.window.showSaveDialog({
        saveLabel: "Save Antares Report",
        defaultUri: vscode.Uri.file(`antares-report.${extensionByFormat[format.value]}`),
      });
      if (!target) {
        return;
      }
      let cweDatabase: CweDatabase | undefined;
      try {
        cweDatabase = CweDatabase.loadDefault(dataDir);
      } catch {
        cweDatabase = undefined;
      }
      const content = serializeReport(lastReport.result, format.value, cweDatabase);
      await vscode.workspace.fs.writeFile(target, Buffer.from(content, "utf-8"));
      void vscode.window.showInformationMessage(`Antares report saved to ${target.fsPath}`);
    })
  );
}

export function deactivate(): void {
  // Disposables are handled through context.subscriptions.
}

// Update the progress notification from a streamed host event; returns the finding count.
function handleEvent(
  event: HostEvent,
  progress: vscode.Progress<{ message?: string }>,
  findingCount: number
): number {
  switch (event.type) {
    case "progress": {
      const pct =
        typeof event.context_usage_percent === "number"
          ? ` · ${event.context_usage_percent}% context`
          : "";
      progress.report({ message: `Investigating…${pct}` });
      return findingCount;
    }
    case "worker": {
      const label = event.label ?? "CWE";
      if (event.event === "started") {
        progress.report({ message: `Scanning ${label}…` });
      } else if (event.event === "completed" || event.event === "failed") {
        progress.report({ message: `Finished ${label}` });
      }
      if (event.finding) {
        const next = findingCount + 1;
        progress.report({ message: `${next} finding(s) so far…` });
        return next;
      }
      return findingCount;
    }
    case "finding": {
      const next = findingCount + 1;
      progress.report({ message: `${next} finding(s) so far…` });
      return next;
    }
    default:
      return findingCount;
  }
}

function reportSummary(result: AntaresResult): void {
  const count = result.summary.total_findings;
  const warnings = result.warnings ?? [];
  if (warnings.length > 0) {
    void vscode.window.showWarningMessage(
      `Antares finished with ${count} finding(s). ${warnings.join(" ")}`
    );
    return;
  }
  if (count === 0) {
    void vscode.window.showInformationMessage(
      "Antares found no vulnerabilities for the requested scope."
    );
    return;
  }
  void vscode.window.showInformationMessage(
    `Antares found ${count} potentially vulnerable file(s). See the Antares view and Problems panel.`
  );
}

function handleScanError(error: unknown, output: vscode.OutputChannel): void {
  if (error instanceof ScanCancelledError) {
    output.appendLine("[scan] cancelled by user");
    return;
  }
  const message = error instanceof Error ? error.message : String(error);
  output.appendLine(`[error] ${message}`);
  if (error instanceof EngineError && error.detail) {
    output.appendLine(error.detail);
  }
  void vscode.window.showErrorMessage(`Antares: ${message}`, "Show Log").then((selection) => {
    if (selection === "Show Log") {
      output.show();
    }
  });
}

async function offerSettings(message: string): Promise<void> {
  const selection = await vscode.window.showErrorMessage(
    `Antares: ${message}`,
    "Open Settings"
  );
  if (selection === "Open Settings") {
    void vscode.commands.executeCommand("workbench.action.openSettings", "antares");
  }
}

async function resolveTargetFolder(
  resource?: vscode.Uri
): Promise<vscode.Uri | undefined> {
  if (resource) {
    return resource;
  }
  const folders = vscode.workspace.workspaceFolders;
  if (folders && folders.length === 1) {
    return folders[0].uri;
  }
  if (folders && folders.length > 1) {
    const picked = await vscode.window.showWorkspaceFolderPick({
      placeHolder: "Select a folder to scan with Antares",
    });
    return picked?.uri;
  }
  const chosen = await vscode.window.showOpenDialog({
    canSelectFolders: true,
    canSelectFiles: false,
    canSelectMany: false,
    openLabel: "Scan with Antares",
  });
  return chosen?.[0];
}
