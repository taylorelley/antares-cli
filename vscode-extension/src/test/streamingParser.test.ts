import assert from "node:assert/strict";
import * as fs from "node:fs";
import * as path from "node:path";
import { test } from "node:test";

import { ParsedEvent, StreamingToolCallParser } from "../antares/agent/streamingParser";

const GOLDEN = JSON.parse(
  fs.readFileSync(
    path.join(__dirname, "..", "..", "src", "test", "fixtures", "parser_golden.json"),
    "utf-8"
  )
) as { cases: Record<string, string>; events: Record<string, unknown[]> };

function serialize(event: ParsedEvent): unknown {
  switch (event.kind) {
    case "text":
      return { t: "text", text: event.text };
    case "tool_call":
      return { t: "tool_call", name: event.toolName, args: event.arguments };
    case "done":
      return { t: "done" };
    case "answer":
      return { t: "answer", text: event.text };
  }
}

for (const [name, input] of Object.entries(GOLDEN.cases)) {
  test(`streaming parser parity: ${name}`, () => {
    const parser = new StreamingToolCallParser();
    const events = parser.feed(input);
    events.push(...parser.flush());
    assert.deepEqual(events.map(serialize), GOLDEN.events[name]);
  });
}

test("streaming parser handles chunk-by-chunk feeding", () => {
  const input = '<tool_call>\n{"tool": "terminal", "args": {"command": "ls"}}\n</tool_call>';
  const parser = new StreamingToolCallParser();
  const events: ParsedEvent[] = [];
  for (const character of input) {
    events.push(...parser.feed(character));
  }
  events.push(...parser.flush());
  const toolCalls = events.filter((e) => e.kind === "tool_call");
  assert.equal(toolCalls.length, 1);
  assert.deepEqual((toolCalls[0] as { arguments: unknown }).arguments, { command: "ls" });
});
