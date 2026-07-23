import { Finding, TrajectoryEntry } from "../output/finding";

export interface AgentStateSnapshot {
  contextUsagePercent: number;
  trajectory: TrajectoryEntry[];
}

export type ProgressCallback = (state: AgentStateSnapshot, finding: Finding | null) => void;
