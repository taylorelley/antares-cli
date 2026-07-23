import assert from "node:assert/strict";
import * as fs from "node:fs";
import * as path from "node:path";
import { test } from "node:test";

import { CweSelectionService } from "../antares/core/cweSelection/engine";
import { ScanScope } from "../antares/core/cweSelection/models";
import { loadSelectionTables } from "../antares/core/cweSelection/tables";
import { CweDatabase } from "../antares/knowledge/cweDatabase";

const DATA_DIR = path.join(__dirname, "..", "..", "data");
const REPOS = path.join(__dirname, "..", "..", "src", "test", "fixtures", "repos");
const GOLDEN = JSON.parse(
  fs.readFileSync(
    path.join(__dirname, "..", "..", "src", "test", "fixtures", "selection_golden.json"),
    "utf-8"
  )
) as Record<string, string[]>;

const service = new CweSelectionService(
  CweDatabase.loadDefault(DATA_DIR),
  loadSelectionTables(DATA_DIR)
);

function select(repo: string, scope: ScanScope): string[] {
  return service
    .select({
      target: path.join(REPOS, repo),
      cweIds: [],
      ignorePaths: [],
      allowSensitiveFiles: [],
      scope,
      cweLevel: "all",
      maxCwes: 15,
    })
    .cweIds();
}

for (const key of Object.keys(GOLDEN)) {
  const [repo, scope] = key.split(":") as [string, ScanScope];
  test(`CWE selection parity: ${key}`, () => {
    assert.deepEqual(select(repo, scope), GOLDEN[key]);
  });
}
