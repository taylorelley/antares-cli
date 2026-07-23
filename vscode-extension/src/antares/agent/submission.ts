// Port of antares_cli/agent/submission.py — converts submit calls into findings.

import * as fs from "fs";
import * as path from "path";

import { normalizeCweId } from "../core/cwe";
import { CweDatabase } from "../knowledge/cweDatabase";
import { Finding, makeFinding, TrajectoryEntry } from "../output/finding";
import {
  RANKED_FILE_ARGUMENT_ALIASES,
  SUBMIT_FILE_PATH_FIELD_ALIASES,
  SUBMIT_NO_VULNERABILITY_FOUND_TOOL,
  SUBMIT_VULNERABLE_FILES_TOOL,
  normalizeToolName,
} from "./contracts";
import { ModelSessionState } from "./state";
import { ParsedToolCall } from "./streamingParser";
import { AgentStateSnapshot, ProgressCallback } from "./types";

export const INVALID_FINDING_PATHS = new Set(["unknown", "", "n/a", "none"]);
export const INVALID_SUBMISSION_MESSAGE = "Model submitted no valid repository file paths.";

const LIKELIHOOD_RANK: Record<string, number> = { High: 3, Medium: 2, Low: 1 };

export type BuildAgentStateFn = (
  messages: ModelSessionState["messages"],
  trajectory: TrajectoryEntry[]
) => AgentStateSnapshot;

export class SubmissionHandler {
  private readonly submissionRoot: string;

  constructor(
    private readonly cweDatabase: CweDatabase,
    submissionRoot: string,
    private readonly buildAgentState: BuildAgentStateFn
  ) {
    this.submissionRoot = path.resolve(submissionRoot);
  }

  handle(
    parsedCall: ParsedToolCall,
    state: ModelSessionState,
    progressCallback?: ProgressCallback
  ): Finding[] {
    const submitToolName = normalizeToolName(parsedCall.toolName);
    state.toolCallCount += 1;
    state.sessionTrace.recordToolCall({ toolName: parsedCall.toolName, arguments: parsedCall.arguments });

    if (submitToolName === SUBMIT_NO_VULNERABILITY_FOUND_TOOL) {
      state.doneSignaled = true;
      state.resultSubmitted = true;
      state.submissionError = null;
      state.reasoningLog.push("Submit tool: model reported no vulnerable files.");
      state.trajectory.push({
        entry_type: "tool_call",
        content: `-> ${SUBMIT_NO_VULNERABILITY_FOUND_TOOL}()`,
      });
      return [];
    }

    const newFindings = this.recordVulnerableFileSubmission(
      parsedCall.arguments,
      state,
      progressCallback
    );
    if (newFindings.length > 0) {
      state.doneSignaled = true;
      state.resultSubmitted = true;
      state.submissionError = null;
    } else {
      state.resultSubmitted = false;
      state.submissionError = INVALID_SUBMISSION_MESSAGE;
      state.reasoningLog.push(`Submit tool: ${INVALID_SUBMISSION_MESSAGE}`);
    }
    return newFindings;
  }

  extractRankedFilePaths(args: Record<string, unknown>): string[] {
    const rawFiles = firstPresentArgument(args, RANKED_FILE_ARGUMENT_ALIASES);
    if (!Array.isArray(rawFiles)) {
      return [];
    }
    const rankedFiles: string[] = [];
    const seen = new Set<string>();
    for (const rawEntry of rawFiles) {
      const normalized = this.normalizeRankedFileEntry(rawEntry);
      if (normalized && !seen.has(normalized)) {
        rankedFiles.push(normalized);
        seen.add(normalized);
      }
    }
    return rankedFiles;
  }

  private recordVulnerableFileSubmission(
    args: Record<string, unknown>,
    state: ModelSessionState,
    progressCallback?: ProgressCallback
  ): Finding[] {
    const rankedFiles = this.extractRankedFilePaths(args);
    state.trajectory.push({
      entry_type: "tool_call",
      content: `-> ${SUBMIT_VULNERABLE_FILES_TOOL}(ranked_files=${JSON.stringify(rankedFiles)})`,
    });
    const newFindings: Finding[] = [];
    rankedFiles.forEach((filePath, index) => {
      const rank = index + 1;
      const finding = this.buildFileLevelFinding(filePath, state, rank);
      if (!this.findingIsValid(finding)) {
        state.reasoningLog.push(`Submit tool: ignored invalid file path '${filePath}'`);
        return;
      }
      if (this.recordFinding(finding, state)) {
        newFindings.push(finding);
        if (progressCallback) {
          progressCallback(this.buildAgentState(state.messages, state.trajectory), finding);
        }
      }
    });
    state.reasoningLog.push(
      `Submit tool: collected ${newFindings.length} file-level vulnerable file(s).`
    );
    return newFindings;
  }

  private buildFileLevelFinding(filePath: string, state: ModelSessionState, rank: number): Finding {
    const cweIds = normalizeFocusCweIds(state.focusCweIds);
    const confidence = Math.max(0.5, 0.95 - (rank - 1) * 0.05);
    return makeFinding({
      title: this.fileLevelTitleForCwes(cweIds),
      file_path: filePath,
      cwe_ids: cweIds,
      confidence,
      submission_rank: rank,
      likelihood_of_exploit: this.highestLikelihoodForCwes(cweIds),
    });
  }

  private highestLikelihoodForCwes(cweIds: string[]): string {
    let highest = "";
    let highestRank = 0;
    for (const cweId of cweIds) {
      const entry = this.cweDatabase.getById(cweId);
      if (!entry) {
        continue;
      }
      const rank = LIKELIHOOD_RANK[entry.likelihood_of_exploit] ?? 0;
      if (rank > highestRank) {
        highestRank = rank;
        highest = entry.likelihood_of_exploit;
      }
    }
    return highest;
  }

  private fileLevelTitleForCwes(cweIds: string[]): string {
    const titles = cweIds.map((cweId) => this.cweDatabase.getById(cweId)?.name ?? cweId);
    return titles.length > 0 ? titles.join(" / ") : "Submitted vulnerable file";
  }

  private recordFinding(finding: Finding, state: ModelSessionState): boolean {
    const dedupeKey = JSON.stringify([finding.file_path, finding.title]);
    if (state.dedupeKeys.has(dedupeKey)) {
      return false;
    }
    state.dedupeKeys.add(dedupeKey);
    state.findings.push(finding);
    state.trajectory.push({ entry_type: "finding", content: `file-level: ${finding.file_path}` });
    return true;
  }

  private normalizeRankedFileEntry(rawEntry: unknown): string {
    if (typeof rawEntry === "string") {
      return this.normalizeSubmittedFilePath(rawEntry);
    }
    if (typeof rawEntry !== "object" || rawEntry === null) {
      return "";
    }
    const filePath = firstPresentArgument(rawEntry as Record<string, unknown>, SUBMIT_FILE_PATH_FIELD_ALIASES);
    if (typeof filePath !== "string") {
      return "";
    }
    return this.normalizeSubmittedFilePath(filePath);
  }

  private normalizeSubmittedFilePath(rawPath: string): string {
    let text = rawPath.trim().replace(/\\/g, "/");
    if (!text) {
      return "";
    }
    while (text.startsWith("./")) {
      text = text.slice(2);
    }
    if (!text) {
      return "";
    }
    const candidate = resolveExactRepositoryPath(text, this.submissionRoot);
    if (candidate === null) {
      return "";
    }
    return path.relative(this.submissionRoot, candidate).split(path.sep).join("/");
  }

  private findingIsValid(finding: Finding): boolean {
    if (INVALID_FINDING_PATHS.has(finding.file_path.toLowerCase().trim())) {
      return false;
    }
    if (!finding.title || finding.title.length < 5) {
      return false;
    }
    const candidate = resolveExactRepositoryPath(finding.file_path, this.submissionRoot);
    if (candidate === null) {
      return false;
    }
    try {
      return fs.statSync(candidate).isFile();
    } catch {
      return false;
    }
  }
}

function firstPresentArgument(args: Record<string, unknown>, aliases: string[]): unknown {
  for (const alias of aliases) {
    if (alias in args) {
      return args[alias];
    }
  }
  return null;
}

function normalizeFocusCweIds(focusCweIds: string[]): string[] {
  const normalized: string[] = [];
  const seen = new Set<string>();
  for (const raw of focusCweIds) {
    const cweId = normalizeCweId(raw, false);
    if (cweId && !seen.has(cweId)) {
      normalized.push(cweId);
      seen.add(cweId);
    }
  }
  return normalized;
}

function resolveExactRepositoryPath(filePath: string, repositoryRoot: string): string | null {
  const candidate = path.isAbsolute(filePath)
    ? filePath
    : path.join(repositoryRoot, filePath);
  let resolved: string;
  try {
    resolved = fs.realpathSync(candidate);
  } catch {
    return null;
  }
  const relative = path.relative(repositoryRoot, resolved);
  if (relative.startsWith("..") || path.isAbsolute(relative)) {
    return null;
  }
  if (!relativePathHasExactSpelling(repositoryRoot, relative)) {
    return null;
  }
  return resolved;
}

function relativePathHasExactSpelling(repositoryRoot: string, relative: string): boolean {
  let directory = repositoryRoot;
  for (const component of relative.split(path.sep)) {
    if (component === "") {
      continue;
    }
    let names: string[];
    try {
      names = fs.readdirSync(directory);
    } catch {
      return false;
    }
    if (!names.includes(component)) {
      return false;
    }
    directory = path.join(directory, component);
  }
  return true;
}
