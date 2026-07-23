// Status bar manager — shows Antares phase in the status bar.

import * as vscode from "vscode";

export type StatusPhase = "idle" | "scanning" | "verifying" | "done";

export class StatusBarManager implements vscode.Disposable {
  private readonly _item: vscode.StatusBarItem;
  private _phase: StatusPhase = "idle";
  private _verifyIndex = 0;
  private _verifyTotal = 0;

  constructor(_outputChannel: vscode.OutputChannel) {
    this._item = vscode.window.createStatusBarItem(
      vscode.StatusBarAlignment.Left,
      100,
    );
    this._item.command = "antares.showOutput";
    this._item.tooltip = "Click to show Antares output channel";
    this._update();
    this._item.show();
  }

  dispose(): void {
    this._item.dispose();
  }

  // -----------------------------------------------------------------------
  // Phase setters
  // -----------------------------------------------------------------------

  setIdle(): void {
    this._phase = "idle";
    this._verifyIndex = 0;
    this._verifyTotal = 0;
    this._update();
  }

  setScanning(): void {
    this._phase = "scanning";
    this._verifyIndex = 0;
    this._verifyTotal = 0;
    this._update();
  }

  setVerifying(current: number, total: number): void {
    this._phase = "verifying";
    this._verifyIndex = current;
    this._verifyTotal = total;
    this._update();
  }

  setDone(): void {
    this._phase = "done";

    this._update();
  }

  // -----------------------------------------------------------------------
  // Internal
  // -----------------------------------------------------------------------

  private _update(): void {
    let text: string;
    switch (this._phase) {
      case "idle":
        text = "$(shield) Antares: idle";
        break;
      case "scanning":
        text = "$(sync~spin) Antares: scanning";
        break;
      case "verifying":
        text = `$(sync~spin) Antares: verifying ${this._verifyIndex}/${this._verifyTotal}`;
        break;
      case "done":
        text = "$(check) Antares: done";
        break;
    }
    this._item.text = text;
  }
}
