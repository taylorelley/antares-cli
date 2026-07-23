// Report serializers for the public scan result (json / markdown / sarif). Mirrors the
// shapes in antares_cli/output/report.py. Consumes the AntaresResult the extension holds.

import { CweDatabase } from "./antares/knowledge/cweDatabase";
import { AntaresFinding, AntaresResult } from "./findings";

export type ReportFormat = "json" | "markdown" | "sarif";

export function serializeReport(
  result: AntaresResult,
  format: ReportFormat,
  cweDatabase?: CweDatabase
): string {
  switch (format) {
    case "markdown":
      return serializeMarkdown(result, cweDatabase);
    case "sarif":
      return serializeSarif(result, cweDatabase);
    case "json":
    default:
      return JSON.stringify(result, null, 2);
  }
}

function cweName(cweId: string, cweDatabase?: CweDatabase): string {
  return cweDatabase?.getById(cweId)?.name ?? cweId;
}

function sarifUri(filePath: string): string {
  return filePath
    .split("/")
    .map((segment) => encodeURIComponent(segment))
    .join("/");
}

function sortFindings(findings: AntaresFinding[]): AntaresFinding[] {
  return [...findings].sort((a, b) => {
    if (a.file_path !== b.file_path) return a.file_path < b.file_path ? -1 : 1;
    const ac = a.cwe_ids[0] ?? "";
    const bc = b.cwe_ids[0] ?? "";
    if (ac !== bc) return ac < bc ? -1 : 1;
    const an = a.submission_rank == null ? 1 : 0;
    const bn = b.submission_rank == null ? 1 : 0;
    if (an !== bn) return an - bn;
    const ar = a.submission_rank ?? 0;
    const br = b.submission_rank ?? 0;
    if (ar !== br) return ar - br;
    return a.title < b.title ? -1 : a.title > b.title ? 1 : 0;
  });
}

function serializeSarif(result: AntaresResult, cweDatabase?: CweDatabase): string {
  const findings = result.findings;
  const uniqueCweIds = [...new Set(findings.flatMap((f) => f.cwe_ids))].sort();
  const rules = uniqueCweIds.map((cweId) => ({
    id: cweId,
    name: cweName(cweId, cweDatabase),
    shortDescription: { text: `${cweId}: ${cweName(cweId, cweDatabase)}` },
    helpUri: `https://cwe.mitre.org/data/definitions/${cweId.replace(/^CWE-/, "")}.html`,
    properties: { tags: ["security"] },
  }));

  const results = sortFindings(findings).map((finding) => {
    const properties: Record<string, unknown> = {
      title: finding.title,
      cweIds: finding.cwe_ids,
      likelihoodOfExploit: finding.likelihood_of_exploit ?? "",
    };
    if (finding.submission_rank != null) {
      properties.submissionRank = finding.submission_rank;
    }
    return {
      ruleId: finding.cwe_ids[0] ?? "ANTARES-GENERIC",
      level: "note",
      message: { text: finding.title },
      locations: [
        { physicalLocation: { artifactLocation: { uri: sarifUri(finding.file_path) } } },
      ],
      properties,
    };
  });

  const summary = result.summary;
  const executionSuccessful =
    (summary.generation_errors ?? 0) === 0 &&
    (summary.failed_workers ?? 0) === 0 &&
    (summary.incomplete_reason ?? null) === null;

  const payload = {
    version: "2.1.0",
    $schema: "https://json.schemastore.org/sarif-2.1.0.json",
    runs: [
      {
        tool: { driver: { name: "antares-cli", rules } },
        invocations: [{ executionSuccessful, properties: summary as unknown as Record<string, unknown> }],
        results,
      },
    ],
  };
  return JSON.stringify(sortKeys(payload), null, 2);
}

function serializeMarkdown(result: AntaresResult, cweDatabase?: CweDatabase): string {
  const s = result.summary;
  const lines: string[] = ["# Antares Security Report", "", "## Summary", ""];
  lines.push(`- Status: ${s.incomplete_reason ? "incomplete" : "complete"}`);
  lines.push(`- Findings: ${s.total_findings}`);
  lines.push(`- Affected files: ${new Set(result.findings.map((f) => f.file_path)).size}`);
  lines.push(`- CWEs with findings: ${(s.cwe_ids_triggered ?? []).join(", ") || "none"}`);
  lines.push(`- Tool calls: ${s.tool_call_count}`);
  lines.push(`- Duration: ${s.duration_seconds.toFixed(1)}s`);
  for (const warning of result.warnings ?? []) {
    lines.push(`- ⚠️ ${warning}`);
  }
  lines.push("", "## Findings by file", "");
  if (result.findings.length === 0) {
    lines.push("_No vulnerabilities were reported for the requested scope._");
  }
  const byFile = new Map<string, AntaresFinding[]>();
  for (const finding of sortFindings(result.findings)) {
    const list = byFile.get(finding.file_path) ?? [];
    list.push(finding);
    byFile.set(finding.file_path, list);
  }
  for (const [file, findings] of byFile) {
    lines.push(`### \`${file}\``, "");
    for (const finding of findings) {
      const cwes = finding.cwe_ids
        .map((id) => `${id} (${cweName(id, cweDatabase)})`)
        .join(", ");
      lines.push(`- **${finding.title}**`);
      if (cwes) lines.push(`  - CWE: ${cwes}`);
      if (finding.likelihood_of_exploit) lines.push(`  - Likelihood: ${finding.likelihood_of_exploit}`);
      if (finding.submission_rank != null) lines.push(`  - Rank: ${finding.submission_rank}`);
    }
    lines.push("");
  }
  return lines.join("\n");
}

// Deterministic key ordering for SARIF (mirrors json.dumps(sort_keys=True)).
function sortKeys(value: unknown): unknown {
  if (Array.isArray(value)) {
    return value.map(sortKeys);
  }
  if (value && typeof value === "object") {
    const out: Record<string, unknown> = {};
    for (const key of Object.keys(value as Record<string, unknown>).sort()) {
      out[key] = sortKeys((value as Record<string, unknown>)[key]);
    }
    return out;
  }
  return value;
}
