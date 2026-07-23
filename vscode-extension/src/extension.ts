import * as vscode from "vscode";

import { readConfig, readDiagnosticsSeverity } from "./config";
import { DiagnosticsManager } from "./diagnostics";
import { EngineError, runScan, ScanCancelledError } from "./engine/runner";
import { AntaresFinding, AntaresResult, HostEvent, HostRequest, ScanMode, VerificationGroup } from "./findings";
import { buildHostRequest, ConfigError, parseCweIds, resolveEndpoint } from "./requestBuilder";
import { CweDatabase } from "./antares/knowledge/cweDatabase";
import { ReportFormat, serializeReport } from "./reports";
import { AntaresResultsProvider } from "./resultsTree";
import { clearApiKey, getApiKey, promptAndStoreApiKey } from "./secrets";
import { resolveBinaryPath, validateBinary } from "./opengrep/binary";
import { resolveRulesPath, validateRules } from "./opengrep/rules";
import { runOpengrepScan } from "./opengrep/runner";
import { opengrepResultToAntaresFindings } from "./opengrep/convert";
import { ReportPanel } from "./webview/reportPanel";
import { ScanHistory } from "./history";
import { StatusBarManager } from "./statusBar";
import { AntaresCodeActionProvider } from "./codeActions";

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
  const statusBar = new StatusBarManager(output);
  const scanHistory = new ScanHistory(context.globalStorageUri);

  // Register code action provider for all languages
  context.subscriptions.push(
    vscode.languages.registerCodeActionsProvider(
      { pattern: "**/*" },
      new AntaresCodeActionProvider(),
    ),
  );

  let lastReport: LastReport | undefined;
  let scanInProgress = false;

  const dataDir = vscode.Uri.joinPath(context.extensionUri, "data").fsPath;

  async function runScanCommand(mode: ScanMode, resource?: vscode.Uri): Promise<void> {
    if (scanInProgress) {
      void vscode.window.showInformationMessage("Antares: a scan is already in progress.");
      return;
    }
    scanInProgress = true;
    statusBar.setScanning();
    try {
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
        handleScanError(error, output);
        return;
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
            resultsProvider.update(result, target.fsPath, mode === "verify" ? "sast" : mode);
            lastReport = { result, target: target.fsPath, mode };
            treeView.title = `Findings (${result.summary.total_findings})`;
            statusBar.setDone();
            void scanHistory.save(result, target.fsPath, mode);
            reportSummary(result);
          } catch (error) {
            handleScanError(error, output);
          }
        }
      );
    } finally {
      scanInProgress = false;
      statusBar.setIdle();
    }
  }

  // -----------------------------------------------------------------------
  // Build verification groups from opengrep findings
  // -----------------------------------------------------------------------
  function buildVerificationGroups(
    findings: AntaresFinding[],
    maxGroups: number
  ): VerificationGroup[] {
    const seen = new Set<string>();
    const groups: VerificationGroup[] = [];
    for (const finding of findings) {
      const cweId = finding.cwe_ids.length > 0 ? finding.cwe_ids[0] : "CWE-000";
      const key = `${finding.file_path}:${cweId}`;
      if (seen.has(key)) continue;
      seen.add(key);
      if (groups.length >= maxGroups) break;
      groups.push({
        file: finding.file_path,
        line: finding.range?.start.line ?? 1,
        cweId,
        message: finding.title,
        snippet: finding.semgrep_message ?? finding.title,
      });
    }
    return groups;
  }

  // -----------------------------------------------------------------------
  // SAST scan command (opengrep)
  // -----------------------------------------------------------------------
  async function runSastScanCommand(resource?: vscode.Uri): Promise<void> {
    if (scanInProgress) {
      void vscode.window.showInformationMessage("Antares: a scan is already in progress.");
      return;
    }
    scanInProgress = true;
    statusBar.setScanning();
    try {
      const target = await resolveTargetFolder(resource);
      if (!target) {
        return;
      }
      const targetDir = target.fsPath;

      const config = readConfig(target);

      // Resolve binary path
      const binaryPath = resolveBinaryPath(context.extensionUri, config.opengrepBinaryPath);

      // Validate binary
      const binaryOk = await validateBinary(binaryPath);
      if (!binaryOk) {
        void vscode.window.showErrorMessage(
          `Antares (SAST): opengrep binary not found or not executable at "${binaryPath}". ` +
          "Run the 'fetch-opengrep' script or set 'antares.opengrep.binaryPath' in settings.",
          "Open Settings"
        ).then((selection) => {
          if (selection === "Open Settings") {
            void vscode.commands.executeCommand("workbench.action.openSettings", "antares.opengrep.binaryPath");
          }
        });
        return;
      }

      // Resolve rules path
      const rulesPath = resolveRulesPath(config.opengrepRulesPath, context.extensionUri.fsPath);

      // Validate rules
      const rulesOk = await validateRules(rulesPath);
      if (!rulesOk) {
        void vscode.window.showErrorMessage(
          `Antares (SAST): rules directory not found or has no .yml files at "${rulesPath}". ` +
          "Ensure bundled rules exist or set 'antares.opengrep.rulesPath' in settings.",
          "Open Settings"
        ).then((selection) => {
          if (selection === "Open Settings") {
            void vscode.commands.executeCommand("workbench.action.openSettings", "antares.opengrep.rulesPath");
          }
        });
        return;
      }

      await vscode.window.withProgress(
        {
          location: vscode.ProgressLocation.Notification,
          cancellable: true,
          title: "Antares SAST scan (Opengrep)",
        },
        async (progress, _token) => {
          try {
            progress.report({ message: "Running SAST scan…" });

            const result = await runOpengrepScan({
              binaryPath,
              rulesPath,
              targetPath: targetDir,
              timeoutSeconds: config.opengrepTimeoutSeconds,
              ignoreGlobs: config.opengrepIgnoreGlobs,
            });

            // Convert to Antares findings
            let findings: AntaresFinding[] = opengrepResultToAntaresFindings(result, targetDir);

            // Filter by minimum severity if not "ALL"
            const minSeverity = config.opengrepSeverity;
            if (minSeverity !== "ALL") {
              const severityRank: Record<string, number> = { ERROR: 3, WARNING: 2, INFO: 1 };
              const minRank = severityRank[minSeverity] ?? 0;
              findings = findings.filter((f) => {
                const rank = f.severity ? severityRank[f.severity] ?? 0 : 0;
                return rank >= minRank;
              });
            }

            // Build a result-like object for the tree view
            const sastResult: AntaresResult = {
              summary: {
                total_findings: findings.length,
                tool_call_count: 0,
                duration_seconds: 0,
                cwe_ids_triggered: [...new Set(findings.flatMap((f) => f.cwe_ids))],
              },
              findings,
              metadata: {},
              warnings: [],
            };

            diagnostics.setFindings(targetDir, findings, readDiagnosticsSeverity());
            resultsProvider.update(sastResult, targetDir, "sast");
            treeView.title = `Findings (${findings.length})`;
            statusBar.setDone();
            void scanHistory.save(sastResult, targetDir, "sast");

            if (findings.length === 0) {
              void vscode.window.showInformationMessage(
                "Antares (SAST): no vulnerabilities found."
              );
            } else {
              void vscode.window.showInformationMessage(
                `Antares (SAST): found ${findings.length} potential issue(s). See the Antares view and Problems panel.`
              );
            }
          } catch (error) {
            handleScanError(error, output);
          }
        }
      );
    } finally {
      scanInProgress = false;
      statusBar.setIdle();
    }
  }

  // -----------------------------------------------------------------------
  // SAST scan + verify command (opengrep + Antares verification)
  // -----------------------------------------------------------------------
  async function runSastScanAndVerifyCommand(resource?: vscode.Uri): Promise<void> {
    if (scanInProgress) {
      void vscode.window.showInformationMessage("Antares: a scan is already in progress.");
      return;
    }
    scanInProgress = true;
    try {
      const target = await resolveTargetFolder(resource);
      if (!target) {
        return;
      }
      const targetDir = target.fsPath;

      const config = readConfig(target);

      // Resolve binary path
      const binaryPath = resolveBinaryPath(context.extensionUri, config.opengrepBinaryPath);

      // Validate binary
      const binaryOk = await validateBinary(binaryPath);
      if (!binaryOk) {
        void vscode.window.showErrorMessage(
          `Antares (SAST+Verify): opengrep binary not found or not executable at "${binaryPath}".`
        );
        return;
      }

      // Resolve rules path
      const rulesPath = resolveRulesPath(config.opengrepRulesPath, context.extensionUri.fsPath);

      // Validate rules
      const rulesOk = await validateRules(rulesPath);
      if (!rulesOk) {
        void vscode.window.showErrorMessage(
          `Antares (SAST+Verify): rules directory not found or has no .yml files at "${rulesPath}".`
        );
        return;
      }

      const apiKey = await getApiKey(context);

      await vscode.window.withProgress(
        {
          location: vscode.ProgressLocation.Notification,
          cancellable: true,
          title: "Antares SAST Scan + Verify",
        },
        async (progress, token) => {
          try {
            statusBar.setScanning();

            // Step 1: Run opengrep scan
            progress.report({ message: "Running SAST scan…" });

            const scanResult = await runOpengrepScan({
              binaryPath,
              rulesPath,
              targetPath: targetDir,
              timeoutSeconds: config.opengrepTimeoutSeconds,
              ignoreGlobs: config.opengrepIgnoreGlobs,
            });

            let findings: AntaresFinding[] = opengrepResultToAntaresFindings(scanResult, targetDir);

            // Filter by minimum severity
            const minSeverity = config.opengrepSeverity;
            if (minSeverity !== "ALL") {
              const severityRank: Record<string, number> = { ERROR: 3, WARNING: 2, INFO: 1 };
              const minRank = severityRank[minSeverity] ?? 0;
              findings = findings.filter((f) => {
                const rank = f.severity ? severityRank[f.severity] ?? 0 : 0;
                return rank >= minRank;
              });
            }

            if (findings.length === 0) {
              void vscode.window.showInformationMessage(
                "Antares (SAST+Verify): no vulnerabilities found."
              );
              const emptyResult: AntaresResult = {
                summary: { total_findings: 0, tool_call_count: 0, duration_seconds: 0, cwe_ids_triggered: [] },
                findings: [],
                metadata: {},
              };
              diagnostics.setFindings(targetDir, emptyResult.findings, readDiagnosticsSeverity());
              resultsProvider.update(emptyResult, targetDir, "sast");
              treeView.title = "Findings (0)";
              statusBar.setDone();
              void scanHistory.save(emptyResult, targetDir, "sast");
              return;
            }

            // Step 2: Group findings by file+CWE (cap N)
            const maxGroups = config.opengrepMaxVerifiedFindings;
            const groups = buildVerificationGroups(findings, maxGroups);

            progress.report({ message: `Verifying ${groups.length} finding group(s)…` });
            statusBar.setVerifying(0, groups.length);

            // Step 3: Build verify request
            const verifyRequest: HostRequest = {
              mode: "verify",
              target: targetDir,
              cwe_ids: [],
              query: null,
              model: config.model,
              endpoint: config.endpoint,
              backend: "remote",
              api_style: config.apiStyle,
              api_key: apiKey ?? null,
              profile: null,
              terminal_call_budget: config.toolBudget > 0 ? Math.trunc(config.toolBudget) : null,
              groups,
            };

            if (config.sweepWorkers > 0) {
              verifyRequest.workers = Math.trunc(config.sweepWorkers);
            }

            // Step 4: Run verification
            let verifiedCount = 0;
            const verifyResult = await runScan({
              request: verifyRequest,
              dataDir,
              apiKey,
              token,
              log: (line) => output.appendLine(line),
              onEvent: (event) => {
                if (event.type === "verify_worker") {
                  if (event.event === "started") {
                    progress.report({ message: `Verifying ${event.file}…` });
                    statusBar.setVerifying(verifiedCount + 1, groups.length);
                  } else if (event.event === "completed") {
                    verifiedCount++;
                    progress.report({ message: `Verified ${event.file}: ${event.verdict ?? "done"}` });
                    statusBar.setVerifying(verifiedCount, groups.length);
                  } else if (event.event === "failed") {
                    verifiedCount++;
                    progress.report({ message: `Verification failed for ${event.file}` });
                    statusBar.setVerifying(verifiedCount, groups.length);
                  }
                } else {
                  handleEvent(event, progress, 0);
                }
              },
            });

            // Step 5: Map verdicts back to findings
            const verdictMap = new Map<string, "verified" | "rejected" | "uncertain" | "unverified">();
            for (const f of verifyResult.findings) {
              if (f.verification) {
                const key = `${f.file_path}:${f.cwe_ids[0] ?? "CWE-000"}`;
                verdictMap.set(key, f.verification);
              }
            }

            for (const finding of findings) {
              const cweId = finding.cwe_ids.length > 0 ? finding.cwe_ids[0] : "CWE-000";
              const key = `${finding.file_path}:${cweId}`;
              if (verdictMap.has(key)) {
                finding.verification = verdictMap.get(key);
              }
            }

            // Step 6: Update diagnostics and tree
            const finalResult: AntaresResult = {
              summary: {
                total_findings: findings.length,
                tool_call_count: verifyResult.summary.tool_call_count,
                duration_seconds: verifyResult.summary.duration_seconds,
                cwe_ids_triggered: [...new Set(findings.flatMap((f) => f.cwe_ids))],
              },
              findings,
              metadata: { mode: "sast_verify" },
            };

            diagnostics.setFindings(targetDir, findings, readDiagnosticsSeverity());
            resultsProvider.update(finalResult, targetDir, "sast");
            treeView.title = `Findings (${findings.length})`;

            // Step 7: Show summary
            statusBar.setDone();
            void scanHistory.save(finalResult, targetDir, "sast");

            const verified = findings.filter((f) => f.verification === "verified").length;
            const rejected = findings.filter((f) => f.verification === "rejected").length;
            const uncertain = findings.filter((f) => f.verification === "uncertain").length;
            const unverified = findings.filter((f) => f.verification === "unverified").length;

            void vscode.window.showInformationMessage(
              `Antares (SAST+Verify): ${findings.length} total — ` +
              `${verified} verified, ${rejected} rejected, ${uncertain} uncertain, ${unverified} unverified`
            );
          } catch (error) {
            handleScanError(error, output);
          }
        }
      );
    } finally {
      scanInProgress = false;
      statusBar.setIdle();
    }
  }

  context.subscriptions.push(
    output,
    diagnostics,
    treeView,
    statusBar,
    vscode.commands.registerCommand("antares.scanForCwe", (resource?: vscode.Uri) =>
      runScanCommand("query", resource)
    ),
    vscode.commands.registerCommand("antares.autoSweep", (resource?: vscode.Uri) =>
      runScanCommand("sweep", resource)
    ),
    vscode.commands.registerCommand("antares.sastScan", (resource?: vscode.Uri) =>
      runSastScanCommand(resource)
    ),
    vscode.commands.registerCommand("antares.sastScanAndVerify", (resource?: vscode.Uri) =>
      runSastScanAndVerifyCommand(resource)
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
    }),
    // -----------------------------------------------------------------------
    // Phase 3 commands
    // -----------------------------------------------------------------------
    vscode.commands.registerCommand("antares.showReport", () => {
      if (!lastReport) {
        void vscode.window.showInformationMessage("Antares: no scan has run yet.");
        return;
      }
      const panel = ReportPanel.createOrShow(context.extensionUri, lastReport.result, lastReport.target);
      // Set up triage persistence
      const triageFile = vscode.Uri.joinPath(context.globalStorageUri, "triage.json");
      panel.setStorageUri(triageFile);
    }),
    vscode.commands.registerCommand("antares.showHistory", async () => {
      const entries = await scanHistory.list();
      if (entries.length === 0) {
        void vscode.window.showInformationMessage("Antares: no scan history available.");
        return;
      }
      const items = entries.map((e) => ({
        label: `$(shield) ${e.summary.total_findings} findings — ${e.mode}`,
        description: new Date(e.timestamp).toLocaleString(),
        detail: `${e.targetDir}  |  CWEs: ${e.summary.cwe_ids_triggered.join(", ") || "none"}`,
        id: e.id,
      }));
      const picked = await vscode.window.showQuickPick(items, {
        title: "Antares Scan History",
        placeHolder: "Select a scan to view",
      });
      if (!picked) return;
      const entry = await scanHistory.get(picked.id);
      if (!entry) {
        void vscode.window.showErrorMessage("Antares: scan history entry not found.");
        return;
      }
      // Reconstruct from stored entry metadata — we store summary only, not full result
      // So we rebuild a minimal result to open in the webview
      const reconstructed: AntaresResult = {
        summary: {
          total_findings: entry.summary.total_findings,
          tool_call_count: entry.summary.tool_call_count ?? 0,
          duration_seconds: entry.summary.duration_seconds ?? 0,
          cwe_ids_triggered: entry.summary.cwe_ids_triggered,
        },
        findings: [],
        metadata: {},
      };
      const panel = ReportPanel.createOrShow(context.extensionUri, reconstructed, entry.targetDir);
      const triageFile = vscode.Uri.joinPath(context.globalStorageUri, "triage.json");
      panel.setStorageUri(triageFile);
    }),
    vscode.commands.registerCommand("antares.testConnection", async () => {
      await testConnection(context, output);
    }),
    vscode.commands.registerCommand("antares.showOutput", () => {
      output.show();
    }),
    vscode.commands.registerCommand("antares.verifyFinding", async (uri: vscode.Uri, range: vscode.Range, message: string, ruleId?: string) => {
      // Verify a single finding by running a targeted scan
      const targetDir = uri.fsPath;
      // Check if it's part of a workspace folder
      const folder = vscode.workspace.getWorkspaceFolder(uri);
      const scanTarget = folder?.uri.fsPath ?? (await vscode.window.showOpenDialog({
        canSelectFolders: true,
        canSelectFiles: false,
        canSelectMany: false,
        openLabel: "Select project root for verification",
      }))?.[0]?.fsPath;

      if (!scanTarget) return;

      const config = readConfig(folder?.uri);
      const apiKey = await getApiKey(context);

      try {
        const verifyRequest: HostRequest = {
          mode: "verify",
          target: scanTarget,
          cwe_ids: [],
          query: null,
          model: config.model,
          endpoint: config.endpoint,
          backend: "remote",
          api_style: config.apiStyle,
          api_key: apiKey ?? null,
          profile: null,
          terminal_call_budget: null,
          groups: [{
            file: targetDir,
            line: range.start.line + 1,
            cweId: ruleId ?? "CWE-000",
            message,
            snippet: message,
          }],
        };
        if (config.sweepWorkers > 0) {
          verifyRequest.workers = Math.trunc(config.sweepWorkers);
        }
        statusBar.setVerifying(1, 1);
        await vscode.window.withProgress(
          { location: vscode.ProgressLocation.Notification, title: "Antares: verifying finding…" },
          async () => {
            const verifyResult = await runScan({
              request: verifyRequest,
              dataDir,
              apiKey,
              log: (line) => output.appendLine(line),
            });
            const verdict = verifyResult.findings[0]?.verification ?? "uncertain";
            void vscode.window.showInformationMessage(
              `Antares: finding verification result: ${verdict}`
            );
            statusBar.setDone();
          }
        );
      } catch (error) {
        handleScanError(error, output);
      } finally {
        statusBar.setIdle();
      }
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

// -----------------------------------------------------------------------
// Connection test
// -----------------------------------------------------------------------

async function testConnection(context: vscode.ExtensionContext, output: vscode.OutputChannel): Promise<void> {
  const workspaceFolder = vscode.workspace.workspaceFolders?.[0];
  const config = readConfig(workspaceFolder?.uri);

  const endpoint = resolveEndpoint(config);
  if (!endpoint) {
    void vscode.window.showErrorMessage(
      "Antares: no endpoint configured. Set 'antares.endpoint' in settings.",
      "Open Settings"
    ).then((s) => { if (s === "Open Settings") void vscode.commands.executeCommand("workbench.action.openSettings", "antares.endpoint"); });
    return;
  }

  const model = config.model.trim();
  if (!model) {
    void vscode.window.showErrorMessage(
      "Antares: no model configured. Set 'antares.model' in settings.",
      "Open Settings"
    ).then((s) => { if (s === "Open Settings") void vscode.commands.executeCommand("workbench.action.openSettings", "antares.model"); });
    return;
  }

  const apiKey = await getApiKey(context);

  const statusMsg = vscode.window.setStatusBarMessage("$(sync~spin) Antares: testing connection…");
  output.appendLine(`[connection-test] endpoint: ${endpoint}, model: ${model}`);

  try {
    // Import the RemoteInferenceBackend
    const { RemoteInferenceBackend } = await import("./antares/inference/remote");
    const backend = new RemoteInferenceBackend({
      modelId: model,
      endpoint,
      apiKey: apiKey ?? null,
      retryCount: 1,
      retryDelay: 1,
      timeoutSeconds: 15,
      maxTokens: 10, // minimal generation to test
    });

    // Attempt a minimal chat to verify the endpoint and model
    const stream = backend.streamGenerate([{ role: "user", content: "Reply with just OK." }]);
    let response = "";
    for await (const chunk of stream) {
      response += chunk;
    }

    output.appendLine(`[connection-test] response: ${response.trim()}`);
    void vscode.window.showInformationMessage(
      `Antares: connection successful. Model "${model}" at ${endpoint} is reachable and responding.`
    );
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    output.appendLine(`[connection-test] FAILED: ${message}`);
    void vscode.window.showErrorMessage(
      `Antares: connection test failed — ${message}`,
      "Show Log"
    ).then((s) => { if (s === "Show Log") output.show(); });
  } finally {
    statusMsg.dispose();
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
