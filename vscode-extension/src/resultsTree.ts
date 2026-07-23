import * as path from "path";
import * as vscode from "vscode";

import { resolveFindingPath } from "./diagnostics";
import { AntaresFinding, AntaresResult } from "./findings";

interface SummaryNode {
  kind: "summary";
  label: string;
  description: string;
  tooltip: vscode.MarkdownString;
}

interface WarningNode {
  kind: "warning";
  message: string;
}

interface CweNode {
  kind: "cwe";
  cwe: string;
  findings: AntaresFinding[];
}

interface SeverityNode {
  kind: "severity";
  severity: "ERROR" | "WARNING" | "INFO";
  findings: AntaresFinding[];
}

interface VerificationStatusNode {
  kind: "verification";
  verdict: "verified" | "rejected" | "uncertain" | "unverified";
  findings: AntaresFinding[];
}

interface FindingNode {
  kind: "finding";
  finding: AntaresFinding;
}

type TreeNode = SummaryNode | WarningNode | CweNode | SeverityNode | VerificationStatusNode | FindingNode;

const UNCLASSIFIED = "Unclassified";

export class AntaresResultsProvider implements vscode.TreeDataProvider<TreeNode> {
  private readonly changeEmitter = new vscode.EventEmitter<TreeNode | undefined | void>();
  readonly onDidChangeTreeData = this.changeEmitter.event;

  private result: AntaresResult | undefined;
  private targetDir = "";
  private mode: "query" | "sweep" | "sast" = "query";

  update(result: AntaresResult, targetDir: string, mode: "query" | "sweep" | "sast"): void {
    this.result = result;
    this.targetDir = targetDir;
    this.mode = mode;
    this.changeEmitter.fire();
  }

  clear(): void {
    this.result = undefined;
    this.targetDir = "";
    this.changeEmitter.fire();
  }

  getTreeItem(node: TreeNode): vscode.TreeItem {
    switch (node.kind) {
      case "summary": {
        const item = new vscode.TreeItem(node.label, vscode.TreeItemCollapsibleState.None);
        item.description = node.description;
        item.tooltip = node.tooltip;
        item.iconPath = new vscode.ThemeIcon("info");
        item.contextValue = "antaresSummary";
        return item;
      }
      case "warning": {
        const item = new vscode.TreeItem(node.message, vscode.TreeItemCollapsibleState.None);
        item.iconPath = new vscode.ThemeIcon("warning");
        item.tooltip = node.message;
        return item;
      }
      case "cwe": {
        const item = new vscode.TreeItem(node.cwe, vscode.TreeItemCollapsibleState.Expanded);
        item.description = `${node.findings.length} file${node.findings.length === 1 ? "" : "s"}`;
        item.iconPath = new vscode.ThemeIcon("shield");
        item.contextValue = "antaresCwe";
        return item;
      }
      case "severity": {
        const severityLabel = severityDisplayLabel(node.severity);
        const item = new vscode.TreeItem(severityLabel, vscode.TreeItemCollapsibleState.Expanded);
        item.description = `${node.findings.length} finding${node.findings.length === 1 ? "" : "s"}`;
        item.iconPath = severityIcon(node.severity);
        item.contextValue = "antaresSeverity";
        return item;
      }
      case "verification": {
        const label = verificationStatusLabel(node.verdict);
        const item = new vscode.TreeItem(label, vscode.TreeItemCollapsibleState.Expanded);
        item.description = `${node.findings.length} finding${node.findings.length === 1 ? "" : "s"}`;
        item.iconPath = verificationStatusIcon(node.verdict);
        item.contextValue = "antaresVerification";
        return item;
      }
      case "finding": {
        const absolute = resolveFindingPath(this.targetDir, node.finding.file_path);
        const verdictBadge = verificationBadge(node.finding.verification);
        const label = verdictBadge
          ? `${verdictBadge} ${path.basename(node.finding.file_path)}`
          : path.basename(node.finding.file_path);
        const item = new vscode.TreeItem(
          label,
          vscode.TreeItemCollapsibleState.None
        );
        item.description = node.finding.file_path;
        item.resourceUri = vscode.Uri.file(absolute);
        item.iconPath = vscode.ThemeIcon.File;
        item.tooltip = buildFindingTooltip(node.finding);
        item.command = {
          command: "vscode.open",
          title: "Open File",
          arguments: [vscode.Uri.file(absolute)],
        };
        item.contextValue = "antaresFinding";
        return item;
      }
    }
  }

  getChildren(element?: TreeNode): TreeNode[] {
    if (!this.result) {
      return [];
    }
    if (!element) {
      return this.rootNodes();
    }
    if (element.kind === "cwe") {
      return element.findings.map((finding) => ({ kind: "finding", finding }));
    }
    if (element.kind === "severity") {
      return element.findings.map((finding) => ({ kind: "finding", finding }));
    }
    if (element.kind === "verification") {
      return element.findings.map((finding) => ({ kind: "finding", finding }));
    }
    return [];
  }

  private rootNodes(): TreeNode[] {
    const result = this.result!;
    const summary = result.summary;
    const nodes: TreeNode[] = [];

    const label = `${summary.total_findings} finding${summary.total_findings === 1 ? "" : "s"}`;
    nodes.push({
      kind: "summary",
      label,
      description: this.mode === "sast"
        ? `SAST scan · ${summary.total_findings} finding${summary.total_findings === 1 ? "" : "s"}`
        : `${this.mode} · ${summary.duration_seconds.toFixed(1)}s · ${summary.tool_call_count} tool calls`,
      tooltip: buildSummaryTooltip(result),
    });

    for (const warning of result.warnings ?? []) {
      nodes.push({ kind: "warning", message: warning });
    }

    if (this.mode === "sast") {
      // Group by verification status for SAST results
      const byVerification = new Map<"verified" | "rejected" | "uncertain" | "unverified", AntaresFinding[]>();
      for (const finding of result.findings) {
        const v = finding.verification ?? "unverified";
        const list = byVerification.get(v) ?? [];
        list.push(finding);
        byVerification.set(v, list);
      }
      const verdictOrder: ("verified" | "rejected" | "uncertain" | "unverified")[] = [
        "verified", "rejected", "uncertain", "unverified",
      ];
      for (const verdict of verdictOrder) {
        const list = byVerification.get(verdict);
        if (list && list.length > 0) {
          nodes.push({ kind: "verification", verdict, findings: list });
        }
      }
    } else {
      // Group by CWE for query/sweep results
      const byCwe = new Map<string, AntaresFinding[]>();
      for (const finding of result.findings) {
        const keys = finding.cwe_ids.length > 0 ? finding.cwe_ids : [UNCLASSIFIED];
        for (const key of keys) {
          const list = byCwe.get(key) ?? [];
          list.push(finding);
          byCwe.set(key, list);
        }
      }

      const sortedCwes = [...byCwe.keys()].sort((a, b) => a.localeCompare(b));
      for (const cwe of sortedCwes) {
        nodes.push({ kind: "cwe", cwe, findings: byCwe.get(cwe)! });
      }
    }

    return nodes;
  }
}

function severityDisplayLabel(severity: "ERROR" | "WARNING" | "INFO"): string {
  switch (severity) {
    case "ERROR":
      return "Error";
    case "WARNING":
      return "Warning";
    case "INFO":
      return "Info";
  }
}

function severityIcon(severity: "ERROR" | "WARNING" | "INFO"): vscode.ThemeIcon {
  switch (severity) {
    case "ERROR":
      return new vscode.ThemeIcon("error", new vscode.ThemeColor("errorForeground"));
    case "WARNING":
      return new vscode.ThemeIcon("warning", new vscode.ThemeColor("testing.iconFailed"));
    case "INFO":
      return new vscode.ThemeIcon("info", new vscode.ThemeColor("debugIcon.startForeground"));
  }
}

function buildFindingTooltip(finding: AntaresFinding): vscode.MarkdownString {
  const md = new vscode.MarkdownString();
  md.appendMarkdown(`**${finding.title}**\n\n`);
  md.appendMarkdown(`- File: \`${finding.file_path}\`\n`);
  if (finding.rule_id) {
    md.appendMarkdown(`- Rule: \`${finding.rule_id}\`\n`);
  }
  if (finding.severity) {
    md.appendMarkdown(`- Severity: ${finding.severity}\n`);
  }
  if (finding.cwe_ids.length > 0) {
    md.appendMarkdown(`- CWE: ${finding.cwe_ids.join(", ")}\n`);
  }
  if (finding.range) {
    md.appendMarkdown(
      `- Lines: ${finding.range.start.line}–${finding.range.end.line}\n`
    );
  }
  if (finding.likelihood_of_exploit) {
    md.appendMarkdown(`- Likelihood of exploit: ${finding.likelihood_of_exploit}\n`);
  }
  if (typeof finding.submission_rank === "number") {
    md.appendMarkdown(`- Submission rank: ${finding.submission_rank}\n`);
  }
  if (finding.verification) {
    md.appendMarkdown(`- Verification: ${verificationStatusLabel(finding.verification)}\n`);
  }
  return md;
}

function buildSummaryTooltip(result: AntaresResult): vscode.MarkdownString {
  const summary = result.summary;
  const md = new vscode.MarkdownString();
  md.appendMarkdown(`**Antares scan summary**\n\n`);
  md.appendMarkdown(`- Findings: ${summary.total_findings}\n`);
  md.appendMarkdown(`- CWEs triggered: ${summary.cwe_ids_triggered.join(", ") || "none"}\n`);
  md.appendMarkdown(`- Tool calls: ${summary.tool_call_count}\n`);
  md.appendMarkdown(`- Duration: ${summary.duration_seconds.toFixed(1)}s\n`);
  const model = extractModelLabel(result.metadata);
  if (model) {
    md.appendMarkdown(`- Model: ${model}\n`);
  }
  return md;
}

function extractModelLabel(metadata: Record<string, unknown>): string | undefined {
  const model = metadata["model"];
  if (typeof model === "string") {
    return model;
  }
  return undefined;
}

// ---------------------------------------------------------------------------
// Verification status helpers
// ---------------------------------------------------------------------------

function verificationStatusLabel(verdict: "verified" | "rejected" | "uncertain" | "unverified"): string {
  switch (verdict) {
    case "verified":
      return "✓ Verified";
    case "rejected":
      return "✗ Rejected";
    case "uncertain":
      return "? Uncertain";
    case "unverified":
      return "○ Unverified";
  }
}

function verificationStatusIcon(verdict: "verified" | "rejected" | "uncertain" | "unverified"): vscode.ThemeIcon {
  switch (verdict) {
    case "verified":
      return new vscode.ThemeIcon("pass", new vscode.ThemeColor("testing.iconPassed"));
    case "rejected":
      return new vscode.ThemeIcon("error", new vscode.ThemeColor("testing.iconFailed"));
    case "uncertain":
      return new vscode.ThemeIcon("warning", new vscode.ThemeColor("testing.iconSkipped"));
    case "unverified":
      return new vscode.ThemeIcon("question", new vscode.ThemeColor("descriptionForeground"));
  }
}

function verificationBadge(verdict?: "verified" | "rejected" | "uncertain" | "unverified"): string {
  switch (verdict) {
    case "verified":
      return "✓";
    case "rejected":
      return "✗";
    case "uncertain":
      return "?";
    case "unverified":
      return "○";
    default:
      return "";
  }
}
