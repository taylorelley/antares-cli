import assert from "node:assert/strict";
import { test } from "node:test";

import { AntaresResult } from "../findings";
import { serializeReport } from "../reports";

const RESULT: AntaresResult = {
  summary: {
    total_findings: 1,
    tool_call_count: 3,
    duration_seconds: 1.2,
    cwe_ids_triggered: ["CWE-89"],
    generation_errors: 0,
    failed_workers: 0,
    incomplete_reason: null,
  },
  findings: [
    {
      title: "SQL Injection",
      file_path: "src/app.py",
      cwe_ids: ["CWE-89"],
      likelihood_of_exploit: "High",
      submission_rank: 1,
    },
  ],
  metadata: { mode: "query" },
};

test("SARIF report has the expected 2.1.0 structure", () => {
  const sarif = JSON.parse(serializeReport(RESULT, "sarif")) as {
    version: string;
    runs: {
      tool: { driver: { name: string; rules: { id: string; helpUri: string }[] } };
      results: { ruleId: string; level: string; locations: unknown[] }[];
      invocations: { executionSuccessful: boolean }[];
    }[];
  };
  assert.equal(sarif.version, "2.1.0");
  assert.equal(sarif.runs[0].tool.driver.name, "antares-cli");
  assert.equal(sarif.runs[0].tool.driver.rules[0].id, "CWE-89");
  assert.match(sarif.runs[0].tool.driver.rules[0].helpUri, /definitions\/89\.html$/);
  assert.equal(sarif.runs[0].results[0].ruleId, "CWE-89");
  assert.equal(sarif.runs[0].results[0].level, "note");
  assert.equal(sarif.runs[0].invocations[0].executionSuccessful, true);
});

test("Markdown and JSON reports include the finding", () => {
  const md = serializeReport(RESULT, "markdown");
  assert.match(md, /# Antares Security Report/);
  assert.match(md, /src\/app\.py/);
  assert.match(md, /CWE-89/);
  const json = JSON.parse(serializeReport(RESULT, "json")) as AntaresResult;
  assert.equal(json.findings[0].file_path, "src/app.py");
});
