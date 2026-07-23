import assert from "node:assert/strict";
import * as fs from "node:fs";
import * as path from "node:path";
import { test } from "node:test";

import { ANTARES_ADAPTER, resolveModelAdapter } from "../antares/agent/modelAdapter";

const GOLDEN = JSON.parse(
  fs.readFileSync(
    path.join(__dirname, "..", "..", "src", "test", "fixtures", "prompt_golden.json"),
    "utf-8"
  )
) as { investigation_prompt: string; built_default: string };

test("investigation prompt byte-matches the Python reference", () => {
  assert.equal(ANTARES_ADAPTER.investigationSystemPrompt, GOLDEN.investigation_prompt);
});

test("build_system_prompt substitutes the budget", () => {
  assert.equal(ANTARES_ADAPTER.buildSystemPrompt(undefined), GOLDEN.built_default);
  assert.match(ANTARES_ADAPTER.buildSystemPrompt(30), /up to 30 repository tool calls/);
});

test("clean_model_text strips think, EOS, and tool-call blocks", () => {
  assert.equal(
    ANTARES_ADAPTER.cleanModelText("<think></think>hello<|end_of_text|>"),
    "hello"
  );
  assert.equal(
    ANTARES_ADAPTER.cleanModelText('a<tool_call>{"x":1}</tool_call>b'),
    "ab"
  );
});

test("resolveModelAdapter falls back to antares", () => {
  assert.equal(resolveModelAdapter("350M-dense").name, "antares");
  assert.equal(resolveModelAdapter("antares").name, "antares");
});
