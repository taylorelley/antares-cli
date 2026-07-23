import assert from "node:assert/strict";
import * as http from "node:http";
import * as path from "node:path";
import { test } from "node:test";

import { SecurityWorkflowService } from "../antares/core/service";

const DATA_DIR = path.join(__dirname, "..", "..", "data");
const FLASK = path.join(__dirname, "..", "..", "src", "test", "fixtures", "repos", "flask");

// The CWE-79 worker submits app.py; every other worker reports no vulnerability.
const server = http.createServer((req, res) => {
  let body = "";
  req.on("data", (c) => (body += c));
  req.on("end", () => {
    const content = /CWE-79:/.test(body)
      ? '<tool_call>{"tool":"submit_vulnerable_files","args":{"ranked_files":["app.py"]}}</tool_call>'
      : '<tool_call>{"tool":"submit_no_vulnerability_found","args":{}}</tool_call>';
    res.writeHead(200, { "Content-Type": "text/event-stream" });
    res.write(`data: ${JSON.stringify({ choices: [{ delta: { content } }] })}\n\n`);
    res.write("data: [DONE]\n\n");
    res.end();
  });
});

test("auto-sweep fans out to per-CWE workers and merges findings", async () => {
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address();
  const port = typeof address === "object" && address ? address.port : 0;

  const service = new SecurityWorkflowService(DATA_DIR);
  const events: string[] = [];
  const result = await service.runCweSweep(
    {
      target: FLASK,
      model: "mock",
      endpoint: `http://127.0.0.1:${port}/v1`,
      apiStyle: "chat",
      scope: "auto",
      maxCwes: 5,
      workers: 4,
      terminalCallBudget: 3,
    },
    (event) => events.push(event.event)
  );
  server.close();

  const dict = result.toDict() as {
    findings: { file_path: string; cwe_ids: string[] }[];
    summary: { total_workers: number };
  };
  // Exactly one finding (app.py, CWE-79) survives across the workers.
  assert.equal(dict.findings.length, 1);
  assert.equal(dict.findings[0].file_path, "app.py");
  assert.deepEqual(dict.findings[0].cwe_ids, ["CWE-79"]);
  assert.equal(dict.summary.total_workers, 5);
  assert.ok(events.includes("started") && events.includes("completed"));
});
