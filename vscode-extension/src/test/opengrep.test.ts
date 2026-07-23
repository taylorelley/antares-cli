import assert from "node:assert/strict";
import { test } from "node:test";

import { opengrepResultToAntaresFindings } from "../opengrep/convert";
import {
  OpengrepResult,
  parseCweFromMetadata,
} from "../opengrep/types";

// ---------------------------------------------------------------------------
// Mock data
// ---------------------------------------------------------------------------

const MOCK_RESULT: OpengrepResult = {
  results: [
    {
      check_id: "python.lang.security.audit.dangerous-subprocess",
      path: "/home/user/project/src/app.py",
      start: { line: 42, col: 5 },
      end: { line: 42, col: 30 },
      extra: {
        message: "Detected dangerous subprocess call without sanitization",
        severity: "ERROR",
        metadata: {
          cwe: "CWE-78: OS Command Injection",
          category: "security",
        },
        lines: "subprocess.call(['rm', '-rf', user_input])",
      },
    },
    {
      check_id: "javascript.lang.security.audit.xss",
      path: "/home/user/project/src/views/index.js",
      start: { line: 10, col: 1 },
      end: { line: 10, col: 50 },
      extra: {
        message: "Detected potential XSS vulnerability",
        severity: "WARNING",
        metadata: {
          cwe: ["CWE-79: Cross-site Scripting (XSS)"],
          category: "security",
        },
        lines: 'element.innerHTML = userInput;',
      },
    },
    {
      check_id: "generic.secret",
      path: "/home/user/project/.env",
      start: { line: 3, col: 1 },
      end: { line: 3, col: 20 },
      extra: {
        message: "Hard-coded credential detected",
        severity: "INFO",
        metadata: {
          category: "security",
        },
        lines: "API_KEY=sk-1234",
      },
    },
  ],
  errors: [],
  paths: {
    scanned: ["/home/user/project/src/app.py", "/home/user/project/src/views/index.js"],
  },
};

// ---------------------------------------------------------------------------
// parseCweFromMetadata
// ---------------------------------------------------------------------------

test("parseCweFromMetadata extracts single CWE string", () => {
  const ids = parseCweFromMetadata({ cwe: "CWE-89: SQL Injection" });
  assert.deepEqual(ids, ["CWE-89"]);
});

test("parseCweFromMetadata extracts from array of CWE strings", () => {
  const ids = parseCweFromMetadata({
    cwe: ["CWE-79: XSS", "CWE-89: SQL Injection"],
  });
  assert.deepEqual(ids, ["CWE-79", "CWE-89"]);
});

test("parseCweFromMetadata returns empty array when no cwe field", () => {
  const ids = parseCweFromMetadata({} as { cwe?: string | string[] });
  assert.deepEqual(ids, []);
});

test("parseCweFromMetadata handles lowercase cwe prefix", () => {
  const ids = parseCweFromMetadata({ cwe: "cwe-78: OS Command Injection" });
  assert.deepEqual(ids, ["CWE-78"]);
});

test("parseCweFromMetadata returns empty array for undefined", () => {
  const ids = parseCweFromMetadata({});
  assert.deepEqual(ids, []);
});

// ---------------------------------------------------------------------------
// opengrepResultToAntaresFindings
// ---------------------------------------------------------------------------

test("converts opengrep result to antarest findings", () => {
  const findings = opengrepResultToAntaresFindings(MOCK_RESULT, "/home/user/project");

  assert.equal(findings.length, 3);

  const [f1, f2, f3] = findings;

  // Finding with single CWE
  assert.equal(f1.title, "Detected dangerous subprocess call without sanitization");
  assert.equal(f1.file_path, "src/app.py");
  assert.deepEqual(f1.cwe_ids, ["CWE-78"]);
  assert.equal(f1.engine, "opengrep");
  assert.equal(f1.rule_id, "python.lang.security.audit.dangerous-subprocess");
  assert.equal(f1.severity, "ERROR");
  assert.deepEqual(f1.range, {
    start: { line: 42, col: 5 },
    end: { line: 42, col: 30 },
  });
  assert.equal(f1.verification, "unverified");
  assert.equal(f1.semgrep_message, "Detected dangerous subprocess call without sanitization");

  // Finding with array of CWEs
  assert.equal(f2.title, "Detected potential XSS vulnerability");
  assert.equal(f2.file_path, "src/views/index.js");
  assert.deepEqual(f2.cwe_ids, ["CWE-79"]);

  // Finding with no CWE in metadata
  assert.equal(f3.title, "Hard-coded credential detected");
  assert.equal(f3.file_path, ".env");
  assert.deepEqual(f3.cwe_ids, []);
  assert.equal(f3.severity, "INFO");
});

test("keeps absolute path when targetDir is empty", () => {
  const findings = opengrepResultToAntaresFindings(MOCK_RESULT);
  assert.equal(findings[0].file_path, MOCK_RESULT.results[0].path);
});

test("converts empty results gracefully", () => {
  const empty: OpengrepResult = { results: [], errors: [], paths: { scanned: [] } };
  const findings = opengrepResultToAntaresFindings(empty, "/project");
  assert.deepEqual(findings, []);
});
