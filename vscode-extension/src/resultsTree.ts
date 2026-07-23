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

interface FindingNode {
  kind: "finding";
  finding: AntaresFinding;
}

type TreeNode = SummaryNode | WarningNode | CweNode | FindingNode;

const UNCLASSIFIED = "Unclassified";

export class AntaresResultsProvider implements vscode.TreeDataProvider<TreeNode> {
  private readonly changeEmitter = new vscode.EventEmitter<TreeNode | undefined | void>();
  readonly onDidChangeTreeData = this.changeEmitter.event;

  private result: AntaresResult | undefined;
  private targetDir = "";
  private mode: "query" | "sweep" = "query";

  update(result: AntaresResult, targetDir: string, mode: "query" | "sweep"): void {
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
      case "finding": {
        const absolute = resolveFindingPath(this.targetDir, node.finding.file_path);
        const item = new vscode.TreeItem(
          path.basename(node.finding.file_path),
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
      description: `${this.mode} · ${summary.duration_seconds.toFixed(1)}s · ${summary.tool_call_count} tool calls`,
      tooltip: buildSummaryTooltip(result),
    });

    for (const warning of result.warnings ?? []) {
      nodes.push({ kind: "warning", message: warning });
    }

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

    return nodes;
  }
}

function buildFindingTooltip(finding: AntaresFinding): vscode.MarkdownString {
  const md = new vscode.MarkdownString();
  md.appendMarkdown(`**${finding.title}**\n\n`);
  md.appendMarkdown(`- File: \`${finding.file_path}\`\n`);
  if (finding.cwe_ids.length > 0) {
    md.appendMarkdown(`- CWE: ${finding.cwe_ids.join(", ")}\n`);
  }
  if (finding.likelihood_of_exploit) {
    md.appendMarkdown(`- Likelihood of exploit: ${finding.likelihood_of_exploit}\n`);
  }
  if (typeof finding.submission_rank === "number") {
    md.appendMarkdown(`- Submission rank: ${finding.submission_rank}\n`);
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
