// Code action provider for Antares SAST diagnostics.
// Provides: "Verify with Antares" and "Suppress rule in file" actions.

import * as vscode from "vscode";

/**
 * Code action provider registered for all languages.
 * It handles diagnostics with source === "Antares (SAST)".
 */
export class AntaresCodeActionProvider implements vscode.CodeActionProvider {
  public static readonly providedCodeActionKinds = [
    vscode.CodeActionKind.QuickFix,
  ];

  provideCodeActions(
    document: vscode.TextDocument,
    _range: vscode.Range | vscode.Selection,
    context: vscode.CodeActionContext,
    _token: vscode.CancellationToken,
  ): vscode.CodeAction[] {
    const actions: vscode.CodeAction[] = [];

    for (const diagnostic of context.diagnostics) {
      if (diagnostic.source !== "Antares (SAST)") {
        continue;
      }

      const ruleId = typeof diagnostic.code === "string" ? diagnostic.code : undefined;

      // "Verify with Antares" action
      const verifyAction = new vscode.CodeAction(
        "Verify with Antares",
        vscode.CodeActionKind.QuickFix,
      );
      verifyAction.command = {
        command: "antares.verifyFinding",
        title: "Verify with Antares",
        arguments: [document.uri, diagnostic.range, diagnostic.message, ruleId],
      };
      verifyAction.diagnostics = [diagnostic];
      verifyAction.isPreferred = false;
      actions.push(verifyAction);

      // "Suppress rule in file" action
      if (ruleId) {
        const suppressAction = new vscode.CodeAction(
          `Suppress rule '${ruleId}' in file`,
          vscode.CodeActionKind.QuickFix,
        );
        suppressAction.edit = new vscode.WorkspaceEdit();
        suppressAction.edit.insert(
          document.uri,
          new vscode.Position(0, 0),
          this._suppressComment(document.languageId, ruleId) + "\n",
        );
        suppressAction.diagnostics = [diagnostic];
        actions.push(suppressAction);
      }
    }

    return actions;
  }

  /**
   * Build a suppress-comment line for the given language.
   * Falls back to `# nosemgrep: <rule_id>` for unknown languages.
   */
  private _suppressComment(languageId: string, ruleId: string): string {
    // Map language id to comment syntax
    const lineComment = this._lineCommentForLanguage(languageId);
    return `${lineComment} nosemgrep: ${ruleId}`;
  }

  private _lineCommentForLanguage(languageId: string): string {
    switch (languageId) {
      case "javascript":
      case "typescript":
      case "javascriptreact":
      case "typescriptreact":
      case "java":
      case "go":
      case "rust":
      case "c":
      case "cpp":
      case "csharp":
      case "swift":
      case "kotlin":
      case "scala":
      case "php":
      case "dart":
      case "solidity":
        return "//";
      case "python":
      case "python3":
      case "ruby":
      case "yaml":
      case "yml":
      case "shellscript":
      case "bash":
      case "zsh":
      case "sh":
      case "perl":
      case "r":
      case "coffeescript":
      case "makefile":
        return "#";
      case "html":
      case "xml":
      case "vue":
      case "svelte":
        return "<!--";
      case "css":
      case "scss":
      case "less":
        return "/*";
      case "lua":
        return "--";
      case "haskell":
      case "elm":
        return "--";
      case "sql":
        return "--";
      case "fsharp":
        return "//";
      case "fortran":
        return "!";
      case "erlang":
        return "%";
      case "elixir":
        return "#";
      default:
        return "#";
    }
  }
}
