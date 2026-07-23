import assert from "node:assert/strict";
import * as path from "node:path";
import { test } from "node:test";

import {
  CweIdError,
  normalizeCweId,
  normalizeCweIds,
  parseCweIdList,
} from "../antares/core/cwe";
import { CweDatabase } from "../antares/knowledge/cweDatabase";

const DATA_DIR = path.join(__dirname, "..", "..", "data");

test("CweDatabase loads the bundled catalog with the declared entry count", () => {
  const db = CweDatabase.loadDefault(DATA_DIR);
  assert.equal(db.listAll().length, 969);
  assert.equal(db.metadata?.entry_count, 969);
});

test("CweDatabase.getById is case/prefix tolerant", () => {
  const db = CweDatabase.loadDefault(DATA_DIR);
  const byCanonical = db.getById("CWE-89");
  assert.ok(byCanonical);
  assert.equal(db.getById("89")?.id, "CWE-89");
  assert.equal(db.getById("cwe-89")?.id, "CWE-89");
  assert.equal(db.getById("CWE-99999999"), undefined);
});

test("CweDatabase entries are sorted by numeric id", () => {
  const db = CweDatabase.loadDefault(DATA_DIR);
  const ids = db.listAll().map((e) => Number.parseInt(e.id.split("-")[1], 10));
  for (let i = 1; i < ids.length; i++) {
    assert.ok(ids[i] >= ids[i - 1], `not sorted at ${i}: ${ids[i - 1]} > ${ids[i]}`);
  }
});

test("normalizeCweId strict accepts standalone references", () => {
  assert.equal(normalizeCweId("22"), "CWE-22");
  assert.equal(normalizeCweId("cwe-22"), "CWE-22");
  assert.equal(normalizeCweId("CWE_22"), "CWE-22");
  assert.equal(normalizeCweId("CWE-0089"), "CWE-89");
});

test("normalizeCweId strict rejects junk and non-positive ids", () => {
  assert.throws(() => normalizeCweId("0"), CweIdError);
  assert.throws(() => normalizeCweId("abc"), CweIdError);
  assert.throws(() => normalizeCweId("CWE-89: SQL Injection"), CweIdError);
});

test("normalizeCweId non-strict extracts from free text", () => {
  assert.equal(normalizeCweId("CWE-798: Hard-coded Credentials", false), "CWE-798");
  assert.equal(normalizeCweId("22", false), "CWE-22");
  assert.equal(normalizeCweId("not a cwe", false), "not a cwe");
});

test("normalizeCweIds validates, de-dupes, and preserves order", () => {
  const db = CweDatabase.loadDefault(DATA_DIR);
  assert.deepEqual(normalizeCweIds(["CWE-89", "79", "cwe-89"], db), ["CWE-89", "CWE-79"]);
  assert.throws(() => normalizeCweIds(["CWE-99999999"], db), CweIdError);
});

test("parseCweIdList splits and trims", () => {
  assert.deepEqual(parseCweIdList("CWE-89, 79 , ,CWE-22"), ["CWE-89", "79", "CWE-22"]);
  assert.deepEqual(parseCweIdList(null), []);
});
