/**
 * convert.ts — Convert opengrep JSON results to the AntaresFinding format.
 *
 * Each OpengrepFinding is mapped to an AntaresFinding with the engine set to
 * "opengrep", CWE identifiers extracted from metadata, and the matched code
 * snippet preserved in semgrep_message.
 */

import { relative } from "path";
import { AntaresFinding } from "../findings";
import { OpengrepResult, parseCweFromMetadata } from "./types";

// ---------------------------------------------------------------------------
// Conversion
// ---------------------------------------------------------------------------

/**
 * Convert an OpengrepResult to an array of AntaresFindings.
 *
 * @param result  - The parsed opengrep JSON result.
 * @param targetDir - The directory that was scanned; used to make `file_path`
 *   relative.  If empty or not provided, the original absolute path is kept.
 * @returns An array of findings suitable for the Antares pipeline.
 */
export function opengrepResultToAntaresFindings(
  result: OpengrepResult,
  targetDir?: string,
): AntaresFinding[] {
  return result.results.map((finding) => {
    const filePath = targetDir
      ? relative(targetDir, finding.path)
      : finding.path;

    const cweIds = parseCweFromMetadata(finding.extra.metadata);

    return {
      title: finding.extra.message,
      file_path: filePath,
      cwe_ids: cweIds,
      engine: "opengrep",
      rule_id: finding.check_id,
      severity: finding.extra.severity,
      range: {
        start: { line: finding.start.line, col: finding.start.col },
        end: { line: finding.end.line, col: finding.end.col },
      },
      verification: "unverified",
      semgrep_message: finding.extra.message,
    };
  });
}
