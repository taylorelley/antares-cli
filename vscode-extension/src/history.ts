// Scan history — persists last N scan results to globalStorage.

import * as vscode from "vscode";
import { AntaresResult, ScanMode } from "./findings";

const MAX_HISTORY = 10;
const HISTORY_DIR = "history";

export interface HistoryEntry {
  id: string;
  timestamp: string;
  targetDir: string;
  mode: ScanMode;
  summary: {
    total_findings: number;
    cwe_ids_triggered: string[];
    duration_seconds: number;
    tool_call_count: number;
  };
}

export class ScanHistory {
  private readonly _storageUri: vscode.Uri;

  constructor(storageUri: vscode.Uri) {
    this._storageUri = storageUri;
  }

  // -----------------------------------------------------------------------
  // Save
  // -----------------------------------------------------------------------

  async save(result: AntaresResult, targetDir: string, mode: ScanMode): Promise<void> {
    const entries = await this._loadAll();

    const entry: HistoryEntry = {
      id: new Date().toISOString().replace(/[:.]/g, "-"),
      timestamp: new Date().toISOString(),
      targetDir,
      mode,
      summary: {
        total_findings: result.summary.total_findings,
        cwe_ids_triggered: result.summary.cwe_ids_triggered,
        duration_seconds: result.summary.duration_seconds,
        tool_call_count: result.summary.tool_call_count,
      },
    };

    entries.unshift(entry);

    // Trim to max
    while (entries.length > MAX_HISTORY) {
      const removed = entries.pop()!;
      await this._deleteEntry(removed.id);
    }

    // Save entry file + index
    await this._writeEntry(entry);
    await this._writeIndex(entries);
  }

  // -----------------------------------------------------------------------
  // List
  // -----------------------------------------------------------------------

  async list(): Promise<HistoryEntry[]> {
    return this._loadAll();
  }

  // -----------------------------------------------------------------------
  // Get
  // -----------------------------------------------------------------------

  async get(id: string): Promise<HistoryEntry | undefined> {
    const entries = await this._loadAll();
    return entries.find((e) => e.id === id);
  }

  // -----------------------------------------------------------------------
  // Clear
  // -----------------------------------------------------------------------

  async clear(): Promise<void> {
    const entries = await this._loadAll();
    for (const entry of entries) {
      await this._deleteEntry(entry.id);
    }
    await this._writeIndex([]);
  }

  // -----------------------------------------------------------------------
  // Internal helpers
  // -----------------------------------------------------------------------

  private _entryUri(id: string): vscode.Uri {
    return vscode.Uri.joinPath(this._storageUri, HISTORY_DIR, `${id}.json`);
  }

  private _indexUri(): vscode.Uri {
    return vscode.Uri.joinPath(this._storageUri, HISTORY_DIR, "index.json");
  }

  private async _ensureDir(): Promise<void> {
    const dir = vscode.Uri.joinPath(this._storageUri, HISTORY_DIR);
    try {
      await vscode.workspace.fs.stat(dir);
    } catch {
      await vscode.workspace.fs.createDirectory(dir);
    }
  }

  private async _loadAll(): Promise<HistoryEntry[]> {
    try {
      const data = await vscode.workspace.fs.readFile(this._indexUri());
      return JSON.parse(Buffer.from(data).toString("utf-8")) as HistoryEntry[];
    } catch {
      return [];
    }
  }

  private async _writeIndex(entries: HistoryEntry[]): Promise<void> {
    await this._ensureDir();
    await vscode.workspace.fs.writeFile(
      this._indexUri(),
      Buffer.from(JSON.stringify(entries, null, 2), "utf-8"),
    );
  }

  private async _writeEntry(entry: HistoryEntry): Promise<void> {
    await this._ensureDir();
    await vscode.workspace.fs.writeFile(
      this._entryUri(entry.id),
      Buffer.from(JSON.stringify(entry, null, 2), "utf-8"),
    );
  }

  private async _deleteEntry(id: string): Promise<void> {
    try {
      await vscode.workspace.fs.delete(this._entryUri(id));
    } catch {
      // Best-effort
    }
  }
}
