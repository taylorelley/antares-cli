import * as path from "path";
import * as vscode from "vscode";

import { AntaresFinding } from "./findings";

export function resolveFindingPath(targetDir: string, filePath: string): string {
  const joined = path.isAbsolute(filePath)
    ? filePath
    : path.join(targetDir, filePath);
  const normalized = path.normalize(joined);
  const relative = path.relative(targetDir, normalized);
  if (relative.startsWith("..") || path.isAbsolute(relative)) {
    return path.join(targetDir, path.basename(filePath));
  }
  return normalized;
}

// Publishes Antares findings as file-level diagnostics in the Problems panel.
export class DiagnosticsManager {
  private readonly collection: vscode.DiagnosticCollection;

  constructor() {
    this.collection = vscode.languages.createDiagnosticCollection("antares");
  }

  dispose(): void {
    this.collection.dispose();
  }

  clear(): void {
    this.collection.clear();
  }

  setFindings(
    targetDir: string,
    findings: AntaresFinding[],
    severity: vscode.DiagnosticSeverity
  ): void {
    this.collection.clear();
    const byFile = new Map<string, vscode.Diagnostic[]>();

    for (const finding of findings) {
      const absolute = resolveFindingPath(targetDir, finding.file_path);
      const cwes = finding.cwe_ids.join(", ");
      const message = cwes ? `${cwes}: ${finding.title}` : finding.title;

      // Map verification status to diagnostic severity
      let diagSeverity = severity;
      if (finding.verification === "rejected") {
        // Downgrade rejected findings to Hint
        diagSeverity = vscode.DiagnosticSeverity.Hint;
      } else if (finding.verification === "uncertain") {
        // Uncertain → Warning
        diagSeverity = vscode.DiagnosticSeverity.Warning;
      }
      // Verified → use original severity; unverified → use original severity

      // Use precise range if available (opengrep findings), else file-level.
      let range: vscode.Range;
      if (finding.range) {
        range = new vscode.Range(
          finding.range.start.line - 1,
          finding.range.start.col - 1,
          finding.range.end.line - 1,
          finding.range.end.col - 1
        );
      } else {
        range = new vscode.Range(0, 0, 0, 0);
      }
      const diagnostic = new vscode.Diagnostic(range, message, diagSeverity);
      diagnostic.source = finding.engine === "opengrep" ? "Antares (SAST)" : "Antares";
      if (finding.rule_id) {
        diagnostic.code = finding.rule_id;
      } else if (finding.cwe_ids.length > 0) {
        diagnostic.code = finding.cwe_ids[0];
      }
      const tags: string[] = [];
      if (finding.likelihood_of_exploit) {
        tags.push(`Likelihood: ${finding.likelihood_of_exploit}`);
      }
      if (typeof finding.submission_rank === "number") {
        tags.push(`Rank: ${finding.submission_rank}`);
      }
      if (finding.verification) {
        tags.push(`Verification: ${finding.verification}`);
      }
      if (tags.length > 0) {
        diagnostic.message = `${message} (${tags.join(", ")})`;
      }

      const list = byFile.get(absolute) ?? [];
      list.push(diagnostic);
      byFile.set(absolute, list);
    }

    for (const [absolute, diagnostics] of byFile) {
      this.collection.set(vscode.Uri.file(absolute), diagnostics);
    }
  }
}
