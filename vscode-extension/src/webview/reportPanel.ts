// Webview report panel for Antares scan results.
// CSP strict, no eval, nonce for inline scripts, no external assets.

import * as vscode from "vscode";
import { AntaresFinding, AntaresResult } from "../findings";

// ---------------------------------------------------------------------------
// Persisted triage state (keyed by finding identity)
// ---------------------------------------------------------------------------

interface TriageState {
  [key: string]: "confirmed" | "false_positive";
}

function findingKey(f: AntaresFinding): string {
  return `${f.file_path}:${f.cwe_ids.join(",")}:${f.rule_id ?? ""}:${f.range?.start.line ?? 0}`;
}

// ---------------------------------------------------------------------------
// Panel
// ---------------------------------------------------------------------------

export class ReportPanel {
  public static current: ReportPanel | undefined;

  private readonly _panel: vscode.WebviewPanel;
  private _disposables: vscode.Disposable[] = [];
  private _result: AntaresResult;
  private _triage: TriageState = {};
  private _sortBy: keyof AntaresFinding = "severity";
  private _sortDir: "asc" | "desc" = "desc";
  private _filterSeverity: string | null = null;
  private _filterStatus: string | null = null;
  private _filterCwe: string | null = null;
  private _selectedFinding: AntaresFinding | null = null;
  private _triageStorageUri: vscode.Uri | undefined;

  private constructor(
    panel: vscode.WebviewPanel,
    _extensionUri: vscode.Uri,
    result: AntaresResult,
    _targetDir: string,
  ) {
    this._panel = panel;
    this._result = result;

    panel.webview.onDidReceiveMessage(
      (msg) => void this._handleMessage(msg),
      null,
      this._disposables,
    );

    panel.onDidDispose(() => this.dispose(), null, this._disposables);

    this._render();
  }

  static createOrShow(
    extensionUri: vscode.Uri,
    result: AntaresResult,
    targetDir: string,
  ): ReportPanel {
    if (ReportPanel.current) {
      ReportPanel.current._panel.reveal(vscode.ViewColumn.One);
      ReportPanel.current._update(result, targetDir);
      return ReportPanel.current;
    }

    const panel = vscode.window.createWebviewPanel(
      "antaresReport",
      "Antares Report",
      vscode.ViewColumn.One,
      {
        enableScripts: true,
        localResourceRoots: [],
        retainContextWhenHidden: true,
      },
    );

    ReportPanel.current = new ReportPanel(panel, extensionUri, result, targetDir);
    return ReportPanel.current;
  }

  static disposeCurrent(): void {
    ReportPanel.current?.dispose();
  }

  dispose(): void {
    ReportPanel.current = undefined;
    this._panel.dispose();
    for (const d of this._disposables) {
      d.dispose();
    }
    this._disposables = [];
  }

  private _update(result: AntaresResult, _targetDir: string): void {
    this._result = result;
    this._selectedFinding = null;
    this._render();
  }

  // -----------------------------------------------------------------------
  // Triage persistence
  // -----------------------------------------------------------------------

  setStorageUri(storageUri: vscode.Uri): void {
    this._triageStorageUri = storageUri;
    // Load existing triage state
    void this._loadTriage();
  }

  private async _loadTriage(): Promise<void> {
    if (!this._triageStorageUri) return;
    try {
      const data = await vscode.workspace.fs.readFile(this._triageStorageUri);
      this._triage = JSON.parse(Buffer.from(data).toString("utf-8")) as TriageState;
      this._render();
    } catch {
      this._triage = {};
    }
  }

  private async _saveTriage(): Promise<void> {
    if (!this._triageStorageUri) return;
    try {
      await vscode.workspace.fs.writeFile(
        this._triageStorageUri,
        Buffer.from(JSON.stringify(this._triage, null, 2), "utf-8"),
      );
    } catch {
      // Best-effort
    }
  }

  // -----------------------------------------------------------------------
  // Message handling
  // -----------------------------------------------------------------------

  private async _handleMessage(msg: Record<string, unknown>): Promise<void> {
    const type = msg.type as string;
    switch (type) {
      case "confirmFinding": {
        const key = msg.value as string;
        this._triage[key] = "confirmed";
        await this._saveTriage();
        this._updateFindingInResult(key, "verified");
        this._render();
        break;
      }
      case "falsePositive": {
        const keyFP = msg.value as string;
        this._triage[keyFP] = "false_positive";
        await this._saveTriage();
        this._updateFindingInResult(keyFP, "rejected");
        this._render();
        break;
      }
      case "selectFinding": {
        const idx = msg.value as number;
        this._selectedFinding = this._result.findings[idx] ?? null;
        this._render();
        break;
      }
      case "sortBy": {
        const field = msg.value as string;
        if (this._sortBy === field) {
          this._sortDir = this._sortDir === "asc" ? "desc" : "asc";
        } else {
          this._sortBy = field as keyof AntaresFinding;
          this._sortDir = "desc";
        }
        this._render();
        break;
      }
      case "filterSeverity": {
        this._filterSeverity = (msg.value as string) || null;
        this._render();
        break;
      }
      case "filterStatus": {
        this._filterStatus = (msg.value as string) || null;
        this._render();
        break;
      }
      case "filterCwe": {
        this._filterCwe = (msg.value as string) || null;
        this._render();
        break;
      }
      case "exportJson": {
        await this._exportReport("json");
        break;
      }
      case "exportSarif": {
        await this._exportReport("sarif");
        break;
      }
      case "exportMarkdown": {
        await this._exportReport("markdown");
        break;
      }
      case "exportHtml": {
        await this._exportHtml();
        break;
      }
    }
  }

  private _updateFindingInResult(key: string, verdict: "verified" | "rejected"): void {
    for (const finding of this._result.findings) {
      if (findingKey(finding) === key) {
        finding.verification = verdict;
        break;
      }
    }
  }

  // -----------------------------------------------------------------------
  // Export
  // -----------------------------------------------------------------------

  private async _exportReport(format: "json" | "sarif" | "markdown"): Promise<void> {
    const extMap: Record<string, string> = { json: "json", sarif: "sarif", markdown: "md" };
    const uri = await vscode.window.showSaveDialog({
      saveLabel: "Export Antares Report",
      defaultUri: vscode.Uri.file(`antares-report.${extMap[format]}`),
    });
    if (!uri) return;
    const { serializeReport } = await import("../reports");
    const content = serializeReport(this._result, format);
    await vscode.workspace.fs.writeFile(uri, Buffer.from(content, "utf-8"));
    void vscode.window.showInformationMessage(`Report exported to ${uri.fsPath}`);
  }

  private async _exportHtml(): Promise<void> {
    const uri = await vscode.window.showSaveDialog({
      saveLabel: "Export Antares Report (HTML)",
      defaultUri: vscode.Uri.file("antares-report.html"),
    });
    if (!uri) return;
    const html = this._generateHtml({ standalone: true });
    await vscode.workspace.fs.writeFile(uri, Buffer.from(html, "utf-8"));
    void vscode.window.showInformationMessage(`Report exported to ${uri.fsPath}`);
  }

  // -----------------------------------------------------------------------
  // Render
  // -----------------------------------------------------------------------

  private _render(): void {
    this._panel.title = `Antares Report (${this._result.summary.total_findings} findings)`;
    this._panel.webview.html = this._generateHtml({ standalone: false });
  }

  // -----------------------------------------------------------------------
  // Data helpers
  // -----------------------------------------------------------------------

  private _getSortedFindings(): AntaresFinding[] {
    let findings = [...this._result.findings];

    // Apply filters
    if (this._filterSeverity) {
      findings = findings.filter((f) => f.severity === this._filterSeverity);
    }
    if (this._filterStatus) {
      const verdict = this._filterStatus as string;
      if (verdict === "unverified") {
        findings = findings.filter((f) => !f.verification || f.verification === "unverified");
      } else {
        findings = findings.filter((f) => f.verification === verdict);
      }
    }
    if (this._filterCwe) {
      findings = findings.filter((f) => f.cwe_ids.includes(this._filterCwe!));
    }

    // Sort
    findings.sort((a, b) => {
      const aVal = a[this._sortBy];
      const bVal = b[this._sortBy];
      const aStr = typeof aVal === "string" ? aVal : String(aVal ?? "");
      const bStr = typeof bVal === "string" ? bVal : String(bVal ?? "");
      const cmp = aStr.localeCompare(bStr);
      return this._sortDir === "asc" ? cmp : -cmp;
    });

    return findings;
  }

  // -----------------------------------------------------------------------
  // HTML generation
  // -----------------------------------------------------------------------

  private _generateHtml(opts: { standalone: boolean }): string {
    const nonce = opts.standalone ? "" : getNonce();
    const cspMeta = opts.standalone
      ? ""
      : `<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src ${this._panel.webview.cspSource} 'nonce-${nonce}'; script-src 'nonce-${nonce}';">`;

    const sorted = this._getSortedFindings();
    const summary = this._result.summary;

    const verified = this._result.findings.filter((f) => f.verification === "verified").length;
    const rejected = this._result.findings.filter((f) => f.verification === "rejected").length;
    const uncertain = this._result.findings.filter((f) => f.verification === "uncertain").length;
    const unverified = this._result.findings.filter((f) => !f.verification || f.verification === "unverified").length;
    const filesAffected = new Set(this._result.findings.map((f) => f.file_path)).size;
    const uniqueCwes = [...new Set(this._result.findings.flatMap((f) => f.cwe_ids))];

    const sortIcon = (field: string): string =>
      this._sortBy === field ? (this._sortDir === "asc" ? " ▲" : " ▼") : "";

    const filterOption = (val: string | null, current: string | null, label: string): string =>
      `<option value="${val ?? ""}"${val === current ? " selected" : ""}>${label}</option>`;

    const escHtml = (s: string): string =>
      s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");

    // Severity color
    const severityColor = (s?: string): string => {
      switch (s) {
        case "ERROR": return "#d32f2f";
        case "WARNING": return "#f57c00";
        case "INFO": return "#1976d2";
        default: return "#616161";
      }
    };

    // Status label
    const statusLabel = (v?: string): string => {
      switch (v) {
        case "verified": return "✓ Verified";
        case "rejected": return "✗ Rejected";
        case "uncertain": return "? Uncertain";
        default: return "○ Unverified";
      }
    };
    const statusColor = (v?: string): string => {
      switch (v) {
        case "verified": return "#2e7d32";
        case "rejected": return "#c62828";
        case "uncertain": return "#e65100";
        default: return "#757575";
      }
    };

    const selected = this._selectedFinding;

    return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
${cspMeta}
<style nonce="${nonce}">
*, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; font-size: 13px; line-height: 1.5; color: var(--vscode-editor-foreground, #ccc); background: var(--vscode-editor-background, #1e1e1e); padding: 16px; }
h1 { font-size: 20px; font-weight: 600; margin-bottom: 16px; }
h2 { font-size: 16px; font-weight: 600; margin-bottom: 12px; margin-top: 20px; }
.card-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(140px, 1fr)); gap: 12px; margin-bottom: 16px; }
.card { background: var(--vscode-editorWidget-background, #252526); border: 1px solid var(--vscode-widget-border, #3c3c3c); border-radius: 6px; padding: 12px; text-align: center; }
.card .num { font-size: 24px; font-weight: 700; }
.card .lbl { font-size: 11px; opacity: 0.8; margin-top: 4px; }
.filters { display: flex; gap: 8px; flex-wrap: wrap; margin-bottom: 12px; }
.filters select { background: var(--vscode-dropdown-background, #3c3c3c); color: var(--vscode-dropdown-foreground, #ccc); border: 1px solid var(--vscode-dropdown-border, #555); border-radius: 4px; padding: 4px 8px; font-size: 12px; }
table { width: 100%; border-collapse: collapse; margin-bottom: 16px; }
th, td { padding: 6px 8px; text-align: left; border-bottom: 1px solid var(--vscode-widget-border, #3c3c3c); font-size: 12px; }
th { cursor: pointer; user-select: none; font-weight: 600; background: var(--vscode-editorWidget-background, #252526); position: sticky; top: 0; z-index: 1; }
th:hover { background: var(--vscode-list-hoverBackground, #2a2d2e); }
tr:hover { background: var(--vscode-list-hoverBackground, #2a2d2e); }
tr.selected { background: var(--vscode-list-activeSelectionBackground, #04395e); }
.severity-badge { display: inline-block; padding: 1px 6px; border-radius: 3px; color: #fff; font-size: 11px; font-weight: 600; }
.detail-panel { background: var(--vscode-editorWidget-background, #252526); border: 1px solid var(--vscode-widget-border, #3c3c3c); border-radius: 6px; padding: 16px; margin-top: 12px; }
.detail-panel h3 { font-size: 14px; margin-bottom: 8px; }
.detail-panel .field { margin-bottom: 6px; }
.detail-panel .field-label { font-weight: 600; font-size: 11px; text-transform: uppercase; opacity: 0.7; }
.detail-panel pre { background: var(--vscode-textCodeBlock-background, #1e1e1e); border: 1px solid var(--vscode-widget-border, #3c3c3c); border-radius: 4px; padding: 8px; overflow-x: auto; font-size: 12px; margin: 8px 0; }
.btn-group { display: flex; gap: 8px; margin-top: 12px; flex-wrap: wrap; }
.btn { padding: 6px 14px; border: 1px solid var(--vscode-button-border, transparent); border-radius: 4px; cursor: pointer; font-size: 12px; font-weight: 500; }
.btn-primary { background: var(--vscode-button-background, #0e639c); color: var(--vscode-button-foreground, #fff); }
.btn-primary:hover { background: var(--vscode-button-hoverBackground, #1177bb); }
.btn-danger { background: var(--vscode-errorForeground, #f14c4c); color: #fff; }
.btn-danger:hover { opacity: 0.9; }
.btn-export { background: var(--vscode-button-secondaryBackground, #3a3d41); color: var(--vscode-button-secondaryForeground, #ccc); }
.btn-export:hover { background: var(--vscode-button-secondaryHoverBackground, #4a4d51); }
.no-findings { text-align: center; padding: 40px; opacity: 0.6; }
.export-bar { display: flex; gap: 6px; margin-bottom: 16px; flex-wrap: wrap; }
.mono { font-family: 'Cascadia Code', 'Fira Code', 'Consolas', monospace; }
.file-path { font-size: 11px; opacity: 0.7; }
</style>
<title>Antares Report</title>
</head>
<body>
<h1>Antares Security Report</h1>

<!-- Summary cards -->
<div class="card-grid">
  <div class="card"><div class="num">${summary.total_findings}</div><div class="lbl">Total Findings</div></div>
  <div class="card"><div class="num">${verified}</div><div class="lbl">Verified</div></div>
  <div class="card"><div class="num">${rejected}</div><div class="lbl">Rejected</div></div>
  <div class="card"><div class="num">${uncertain}</div><div class="lbl">Uncertain</div></div>
  <div class="card"><div class="num">${unverified}</div><div class="lbl">Unverified</div></div>
  <div class="card"><div class="num">${filesAffected}</div><div class="lbl">Files Affected</div></div>
</div>

<!-- Export bar -->
<div class="export-bar">
  <button class="btn btn-export" onclick="postMsg('exportJson')">Export JSON</button>
  <button class="btn btn-export" onclick="postMsg('exportSarif')">Export SARIF</button>
  <button class="btn btn-export" onclick="postMsg('exportMarkdown')">Export MD</button>
  <button class="btn btn-export" onclick="postMsg('exportHtml')">Export HTML</button>
</div>

<!-- Filters -->
<div class="filters">
  <select onchange="postMsg('filterSeverity', this.value)">
    <option value="">All Severities</option>
    ${filterOption("ERROR", this._filterSeverity, "Error")}
    ${filterOption("WARNING", this._filterSeverity, "Warning")}
    ${filterOption("INFO", this._filterSeverity, "Info")}
  </select>
  <select onchange="postMsg('filterStatus', this.value)">
    <option value="">All Statuses</option>
    ${filterOption("verified", this._filterStatus, "Verified")}
    ${filterOption("rejected", this._filterStatus, "Rejected")}
    ${filterOption("uncertain", this._filterStatus, "Uncertain")}
    ${filterOption("unverified", this._filterStatus, "Unverified")}
  </select>
  <select onchange="postMsg('filterCwe', this.value)">
    <option value="">All CWEs</option>
    ${uniqueCwes.map((c) => filterOption(c, this._filterCwe, c)).join("\n    ")}
  </select>
</div>

<!-- Findings table -->
${sorted.length === 0 ? '<div class="no-findings">No findings match the current filters.</div>' : `
<table>
<thead>
<tr>
  <th onclick="postMsg('sortBy','cwe_ids')">CWE${sortIcon("cwe_ids")}</th>
  <th onclick="postMsg('sortBy','severity')">Severity${sortIcon("severity")}</th>
  <th onclick="postMsg('sortBy','verification')">Status${sortIcon("verification")}</th>
  <th onclick="postMsg('sortBy','file_path')">File${sortIcon("file_path")}</th>
  <th onclick="postMsg('sortBy','title')">Finding${sortIcon("title")}</th>
</tr>
</thead>
<tbody>
${sorted.map((f, i) => {
  const key = findingKey(f);
  const triageAction = this._triage[key];
  const v = triageAction === "false_positive" ? "rejected" : (triageAction === "confirmed" ? "verified" : f.verification);
  return `<tr class="${this._selectedFinding === f ? "selected" : ""}" onclick="postMsg('selectFinding',${i})">
  <td>${escHtml(f.cwe_ids.join(", "))}</td>
  <td>${f.severity ? `<span class="severity-badge" style="background:${severityColor(f.severity)}">${f.severity}</span>` : "-"}</td>
  <td style="color:${statusColor(v)}">${statusLabel(v)}</td>
  <td><span class="file-path">${escHtml(f.file_path)}${f.range ? `:${f.range.start.line}` : ""}</span></td>
  <td>${escHtml(f.title)}</td>
</tr>`;
}).join("\n")}
</tbody>
</table>`}

<!-- Detail panel -->
${selected ? `
<div class="detail-panel">
  <h3>${escHtml(selected.title)}</h3>
  ${selected.rule_id ? `<div class="field"><span class="field-label">Rule</span><br>${escHtml(selected.rule_id)}</div>` : ""}
  ${selected.severity ? `<div class="field"><span class="field-label">Severity</span><br><span class="severity-badge" style="background:${severityColor(selected.severity)}">${selected.severity}</span></div>` : ""}
  <div class="field"><span class="field-label">CWE</span><br>${escHtml(selected.cwe_ids.join(", "))}</div>
  <div class="field"><span class="field-label">File</span><br>${escHtml(selected.file_path)}${selected.range ? `, line ${selected.range.start.line}` : ""}</div>
  <div class="field"><span class="field-label">Status</span><br><span style="color:${statusColor(selected.verification)}">${statusLabel(selected.verification)}</span></div>
  ${selected.semgrep_message ? `<div class="field"><span class="field-label">Message</span><pre>${escHtml(selected.semgrep_message)}</pre></div>` : ""}
  ${selected.likelihood_of_exploit ? `<div class="field"><span class="field-label">Likelihood of Exploit</span><br>${escHtml(selected.likelihood_of_exploit)}</div>` : ""}
  ${typeof selected.submission_rank === "number" ? `<div class="field"><span class="field-label">Submission Rank</span><br>${selected.submission_rank}</div>` : ""}

  <div class="btn-group">
    <button class="btn btn-primary" onclick="postMsg('confirmFinding','${escHtml(findingKey(selected))}')">✓ Confirm Finding</button>
    <button class="btn btn-danger" onclick="postMsg('falsePositive','${escHtml(findingKey(selected))}')">✗ False Positive</button>
  </div>
</div>
` : '<div class="detail-panel" style="opacity:0.5;text-align:center;padding:24px;">Select a finding to see details</div>'}
${!opts.standalone ? `<script nonce="${nonce}">
const vscode = acquireVsCodeApi();
function postMsg(type, value) {
  if (arguments.length === 1) {
    vscode.postMessage({ type: type });
  } else {
    vscode.postMessage({ type: type, value: value });
  }
}
</script>` : ""}
</body>
</html>`;
  }
}

function getNonce(): string {
  let text = "";
  const possible = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
  for (let i = 0; i < 64; i++) {
    text += possible.charAt(Math.floor(Math.random() * possible.length));
  }
  return text;
}
