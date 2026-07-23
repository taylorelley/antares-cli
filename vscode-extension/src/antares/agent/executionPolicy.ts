// Port of antares_cli/agent/execution_policy.py — terminal-call budget policy.

export const DEFAULT_TERMINAL_CALL_BUDGET = 15;
export const MIN_TERMINAL_CALL_BUDGET = 1;
export const MAX_TERMINAL_CALL_BUDGET = 50;

export function resolveTerminalCallBudget(value: number | null | undefined): number {
  if (value === null || value === undefined) {
    return DEFAULT_TERMINAL_CALL_BUDGET;
  }
  if (
    !Number.isInteger(value) ||
    value < MIN_TERMINAL_CALL_BUDGET ||
    value > MAX_TERMINAL_CALL_BUDGET
  ) {
    throw new Error("Terminal call budget must be between 1 and 50.");
  }
  return value;
}
