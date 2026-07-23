import assert from "node:assert/strict";
import { test } from "node:test";

import {
  AntaresConfig,
  buildHostRequest,
  ConfigError,
  parseCweIds,
  resolveApiStyle,
  resolveEndpoint,
} from "../requestBuilder";

function config(overrides: Partial<AntaresConfig> = {}): AntaresConfig {
  return {
    provider: "ollama",
    endpoint: "",
    model: "qwen2.5-coder",
    apiStyle: "auto",
    toolBudget: 0,
    sweepWorkers: 4,
    sweepMaxCwes: 8,
    ...overrides,
  };
}

test("resolveApiStyle derives chat for ollama and openai-compatible", () => {
  assert.equal(resolveApiStyle(config({ provider: "ollama" })), "chat");
  assert.equal(resolveApiStyle(config({ provider: "openai-compatible" })), "chat");
});

test("resolveApiStyle derives completions for vllm", () => {
  assert.equal(resolveApiStyle(config({ provider: "vllm" })), "completions");
});

test("resolveApiStyle honors explicit override", () => {
  assert.equal(resolveApiStyle(config({ provider: "vllm", apiStyle: "chat" })), "chat");
  assert.equal(
    resolveApiStyle(config({ provider: "ollama", apiStyle: "completions" })),
    "completions"
  );
});

test("resolveEndpoint falls back to the ollama default", () => {
  assert.equal(resolveEndpoint(config({ provider: "ollama" })), "http://localhost:11434/v1");
});

test("resolveEndpoint prefers an explicit endpoint", () => {
  assert.equal(
    resolveEndpoint(config({ provider: "ollama", endpoint: "http://host:1234/v1" })),
    "http://host:1234/v1"
  );
});

test("resolveEndpoint returns null for openai-compatible without an endpoint", () => {
  assert.equal(resolveEndpoint(config({ provider: "openai-compatible" })), null);
});

test("buildHostRequest builds a valid ollama query request", () => {
  const request = buildHostRequest(config(), {
    mode: "query",
    target: "/repo",
    cweIds: ["CWE-89"],
  });
  assert.equal(request.mode, "query");
  assert.equal(request.endpoint, "http://localhost:11434/v1");
  assert.equal(request.api_style, "chat");
  assert.equal(request.backend, "remote");
  assert.deepEqual(request.cwe_ids, ["CWE-89"]);
  assert.equal(request.terminal_call_budget, null);
});

test("buildHostRequest includes sweep parameters", () => {
  const request = buildHostRequest(config({ sweepWorkers: 6, sweepMaxCwes: 12 }), {
    mode: "sweep",
    target: "/repo",
  });
  assert.equal(request.mode, "sweep");
  assert.equal(request.workers, 6);
  assert.equal(request.max_cwes, 12);
});

test("buildHostRequest passes through a positive tool budget", () => {
  const request = buildHostRequest(config({ toolBudget: 25 }), {
    mode: "query",
    target: "/repo",
    cweIds: ["CWE-79"],
  });
  assert.equal(request.terminal_call_budget, 25);
});

test("buildHostRequest requires a model", () => {
  assert.throws(
    () => buildHostRequest(config({ model: "" }), { mode: "sweep", target: "/repo" }),
    ConfigError
  );
});

test("buildHostRequest requires an endpoint", () => {
  assert.throws(
    () =>
      buildHostRequest(config({ provider: "openai-compatible", endpoint: "" }), {
        mode: "sweep",
        target: "/repo",
      }),
    ConfigError
  );
});

test("buildHostRequest requires at least one CWE for query mode", () => {
  assert.throws(
    () => buildHostRequest(config(), { mode: "query", target: "/repo", cweIds: [] }),
    ConfigError
  );
});

test("parseCweIds normalizes and de-duplicates", () => {
  assert.deepEqual(parseCweIds("89, CWE-79 cwe-22"), ["CWE-89", "CWE-79", "CWE-22"]);
  assert.deepEqual(parseCweIds("CWE-89, 89"), ["CWE-89"]);
  assert.deepEqual(parseCweIds("garbage"), []);
});
