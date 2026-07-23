import assert from "node:assert/strict";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { after, test } from "node:test";

import { validateCommandOnly } from "../antares/sandbox/shellPolicy";

// Outcomes captured from the Python read-only command policy (validation only).
const GOLDEN = JSON.parse(
  fs.readFileSync(
    path.join(__dirname, "..", "..", "src", "test", "fixtures", "policy_golden.json"),
    "utf-8"
  )
) as Record<string, string>;

// Build a fixture repo matching the one used to generate the golden outcomes.
const fixtureDir = fs.mkdtempSync(path.join(os.tmpdir(), "antares-policy-"));
fs.mkdirSync(path.join(fixtureDir, "src"));
fs.writeFileSync(path.join(fixtureDir, "src", "app.py"), "x=1\n");
fs.writeFileSync(path.join(fixtureDir, ".env"), "SECRET=1\n");
fs.writeFileSync(path.join(fixtureDir, "key.pem"), "k\n");

after(() => {
  fs.rmSync(fixtureDir, { recursive: true, force: true });
});

for (const [command, expected] of Object.entries(GOLDEN)) {
  test(`policy parity: ${command}`, () => {
    let outcome: string;
    try {
      validateCommandOnly(command, fixtureDir);
      outcome = "OK";
    } catch (error) {
      outcome = `ERR: ${(error as Error).message}`;
    }
    assert.equal(outcome, expected);
  });
}
