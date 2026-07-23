// Minimal session trace. The Python implementation writes a redacted trace bundle to
// disk; the extension does not surface it, so the recording methods are no-ops and
// finalize() returns an empty path. Kept as a seam for a future on-disk trace.

export class SessionTrace {
  private evidenceCounter = 0;

  constructor(readonly sessionName: string) {}

  recordEvent(_phase: string, _payload: Record<string, unknown>): void {}
  recordMessage(_message: { role: string; content: string }): void {}
  recordToolCall(_args: { toolName: string; arguments: Record<string, unknown> }): void {}
  recordToolResult(_args: Record<string, unknown>): void {}
  recordFinding(_args: { findingDict: Record<string, unknown>; evidenceId: string }): void {}

  newEvidenceId(): string {
    this.evidenceCounter += 1;
    return `evidence-${this.evidenceCounter}`;
  }

  finalize(_summary: Record<string, unknown>): string {
    return "";
  }

  finalizeError(_error: unknown): void {}
  close(): void {}
}
