import assert from "node:assert/strict";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { after, test } from "node:test";

import { runBash } from "../antares/sandbox/runBash";

const dir = fs.mkdtempSync(path.join(os.tmpdir(), "antares-cmd-"));
fs.mkdirSync(path.join(dir, "src"));
const APP = 'import os\npassword = "hunter2"\ndef run(cmd):\n    os.system(cmd)\n';
fs.writeFileSync(path.join(dir, "src", "app.py"), APP);
fs.writeFileSync(path.join(dir, "README.md"), "hello world\n");

after(() => fs.rmSync(dir, { recursive: true, force: true }));

function run(command: string): { stdout: string; stderr: string; returncode: number } {
  const r = runBash(command, { cwd: dir });
  return { stdout: r.stdout, stderr: r.stderr, returncode: r.returncode };
}

test("echo prints its arguments", () => {
  assert.equal(run("echo hello world").stdout, "hello world\n");
  assert.equal(run("echo -n hi").stdout, "hi");
});

test("cat reads a file", () => {
  assert.equal(run("cat src/app.py").stdout, APP);
});

test("cat on a missing file reports an error and exit 1", () => {
  const r = run("cat nope.py");
  assert.equal(r.returncode, 1);
  assert.match(r.stderr, /No such file or directory/);
});

test("head and tail select line ranges", () => {
  assert.equal(run("head -n 2 src/app.py").stdout, 'import os\npassword = "hunter2"\n');
  assert.equal(run("tail -n 1 src/app.py").stdout, "    os.system(cmd)\n");
});

test("wc -l counts newlines", () => {
  assert.equal(run("wc -l src/app.py").stdout, `${String(4).padStart(7)} src/app.py\n`);
});

test("grep with line numbers on a single file omits the filename", () => {
  assert.equal(run("grep -n password src/app.py").stdout, '2:password = "hunter2"\n');
});

test("grep -rn prefixes the file path", () => {
  assert.equal(run("grep -rn os.system .").stdout, "src/app.py:4:    os.system(cmd)\n");
});

test("grep exit code is 1 when nothing matches", () => {
  assert.equal(run("grep nonexistent src/app.py").returncode, 1);
});

test("find -name matches by glob", () => {
  assert.equal(run("find . -name '*.py'").stdout, "./src/app.py\n");
});

test("sed -n prints a line range", () => {
  assert.equal(run("sed -n '1,2p' src/app.py").stdout, 'import os\npassword = "hunter2"\n');
});

test("sed substitution rewrites matches", () => {
  assert.equal(run("sed 's/hunter2/REDACTED/' src/app.py").stdout.includes("REDACTED"), true);
});

test("pipelines connect stdout to stdin", () => {
  assert.equal(run("cat src/app.py | grep password | wc -l").stdout, `${String(1).padStart(7)}\n`);
});

test("connector semantics: || runs on failure, && on success", () => {
  assert.equal(run("false || echo recovered").stdout, "recovered\n");
  assert.equal(run("true && echo proceeded").stdout, "proceeded\n");
  assert.equal(run("false && echo skipped").stdout, "");
});

test("ls lists directory entries", () => {
  const out = run("ls").stdout.trim().split("\n").sort();
  assert.deepEqual(out, ["README.md", "src"]);
});

test("policy violations throw from runBash", () => {
  assert.throws(() => runBash("cat /etc/passwd", { cwd: dir }), /Sensitive path is blocked/);
});
