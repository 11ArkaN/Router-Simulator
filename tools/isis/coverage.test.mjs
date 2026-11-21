// Coverage fixtures reject omissions, unsupported completion claims and drift.
// Tests own detached data; production source files are read without mutation.
import test from "node:test";
import assert from "node:assert/strict";
import {readFileSync, existsSync} from "node:fs";
import {resolve} from "node:path";
import {parse} from "yaml";
import {validateIsisCoverage} from "./coverage.mjs";
const root = resolve(import.meta.dirname, "../..");
const inventory = JSON.parse(readFileSync(resolve(root, "schemas/cli/isis-26.7.R1-inventory.json"), "utf8"));
const matrix = parse(readFileSync(resolve(root, "schemas/cli/isis-26.7.R1-coverage.yaml"), "utf8"));
test("every pinned configuration, state and operation identity has a classification", () => {
  const result = validateIsisCoverage(inventory, matrix);
  assert.equal(result.configuration, 405); assert.equal(result.state, 592); assert.equal(result.management, 454);
  for (const row of matrix.nodes) for (const path of row.tests ?? []) assert.ok(existsSync(resolve(root, path)), path);
});
test("missing, duplicate, foreign and unpinned coverage identities reject", () => {
  for (const mutate of [
    (value) => value.nodes.pop(),
    (value) => value.nodes.push(value.nodes[0]),
    (value) => { value.nodes[0].schema_id += "/unknown"; },
    (value) => { value.source_commit = "other"; },
    (value) => { value.nodes[0].scope = "unsupported"; },
    (value) => { const row = value.nodes.find((entry) => entry.scope === "excluded"); delete row.dependency; }
  ]) { const value = structuredClone(matrix); mutate(value); assert.throws(() => validateIsisCoverage(inventory, value)); }
});
test("intent-only and pending exclusions cannot satisfy final acceptance", () => {
  assert.throws(() => validateIsisCoverage(inventory, matrix, {complete: true}), /unfinished acceptance/);
  for (const fields of [{status: "implemented"}, {status: "implemented", capability: "routing.isis"},
    {status: "verified-exclusion", tests: ["test.cpp"]}]) {
    const value = structuredClone(matrix); delete value.nodes[0].tests; Object.assign(value.nodes[0], fields);
    assert.throws(() => validateIsisCoverage(inventory, value));
  }
});

test("declared acceptance requires existing tests and an implemented capability", () => {
  const value = structuredClone(matrix);
  Object.assign(value.nodes[0], {status: "implemented", capability: "routing.isis", tests: ["test.cpp"]});
  assert.throws(() => validateIsisCoverage(inventory, value, {capabilityImplemented: () => false}), /not implemented/);
  assert.throws(() => validateIsisCoverage(inventory, matrix, {testExists: () => false}), /does not exist/);
});
