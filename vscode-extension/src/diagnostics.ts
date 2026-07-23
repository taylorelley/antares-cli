import * as path from "path";
import * as vscode from "vscode";

import { AntaresFinding } from "./findings";

export function resolveFindingPath(targetDir: string, filePath: string): string {
  return path.isAbsolute(filePath) ? filePath : path.join(targetDir, filePath);
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
      // Antares localizes at file granularity; anchor the diagnostic at the file start.
      const range = new vscode.Range(0, 0, 0, 0);
      const diagnostic = new vscode.Diagnostic(range, message, severity);
      diagnostic.source = "Antares";
      if (finding.cwe_ids.length > 0) {
        diagnostic.code = finding.cwe_ids[0];
      }
      const tags: string[] = [];
      if (finding.likelihood_of_exploit) {
        tags.push(`Likelihood: ${finding.likelihood_of_exploit}`);
      }
      if (typeof finding.submission_rank === "number") {
        tags.push(`Rank: ${finding.submission_rank}`);
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
