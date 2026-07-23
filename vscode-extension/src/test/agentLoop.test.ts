import assert from "node:assert/strict";
import * as fs from "node:fs";
import * as http from "node:http";
import * as os from "node:os";
import * as path from "node:path";
import { after, test } from "node:test";

import { AntaresAgentLoop } from "../antares/agent/loop";
import { ANTARES_ADAPTER } from "../antares/agent/modelAdapter";
import { ToolRouter } from "../antares/agent/toolRouter";
import { RemoteInferenceBackend } from "../antares/inference/remote";
import { CweDatabase } from "../antares/knowledge/cweDatabase";

const DATA_DIR = path.join(__dirname, "..", "..", "data");

const repo = fs.mkdtempSync(path.join(os.tmpdir(), "antares-e2e-"));
fs.mkdirSync(path.join(repo, "src"));
fs.writeFileSync(
  path.join(repo, "src", "app.py"),
  'import sqlite3\n\ndef get_user(db, uid):\n    return db.execute("SELECT * FROM users WHERE id = %s" % uid)\n'
);

// Scripted model transcript: inspect the file, then submit it.
const SCRIPT = [
  '<tool_call>\n{"tool": "terminal", "args": {"command": "cat src/app.py"}}\n</tool_call>\n',
  '<tool_call>\n{"tool": "submit_vulnerable_files", "args": {"ranked_files": ["src/app.py"]}}\n</tool_call>\n',
];

let turn = 0;
const server = http.createServer((req, res) => {
  let body = "";
  req.on("data", (c) => (body += c));
  req.on("end", () => {
    const content = SCRIPT[Math.min(turn, SCRIPT.length - 1)];
    turn += 1;
    res.writeHead(200, { "Content-Type": "text/event-stream" });
    res.write(`data: ${JSON.stringify({ choices: [{ delta: { content } }] })}\n\n`);
    res.write("data: [DONE]\n\n");
    res.end();
  });
});

after(() => {
  server.close();
  fs.rmSync(repo, { recursive: true, force: true });
});

test("agent loop investigates and submits a file-level finding", async () => {
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address();
  const port = typeof address === "object" && address ? address.port : 0;

  const backend = new RemoteInferenceBackend({
    modelId: "mock-model",
    endpoint: `http://127.0.0.1:${port}/v1`,
    useCompletionsApi: false,
  });
  const loop = new AntaresAgentLoop({
    toolRouter: new ToolRouter(repo),
    cweDatabase: CweDatabase.loadDefault(DATA_DIR),
    inferenceBackend: backend,
    adapter: ANTARES_ADAPTER,
  });

  const result = await loop.runAudit(repo, { focusCweIds: ["CWE-89"], terminalCallBudget: 5 });

  assert.equal(result.findings.length, 1);
  const finding = result.findings[0];
  assert.equal(finding.file_path, "src/app.py");
  assert.deepEqual(finding.cwe_ids, ["CWE-89"]);
  assert.equal(finding.submission_rank, 1);
  assert.ok(finding.title.length >= 5);
  assert.equal(result.summary.total_findings, 1);
  assert.equal(result.summary.incomplete_reason, null);
  assert.deepEqual(result.summary.cwe_ids_triggered, ["CWE-89"]);
});
