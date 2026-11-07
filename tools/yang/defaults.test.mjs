// Fixtures exercise configuration omission rules independently of CLI syntax.
// Each test owns its schema inputs and cannot change the pinned inventory.

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import { nodeDefaults } from "./defaults.mjs";

const leaf = (id, constraints = [], inherited) => ({ schema_id: id, kind: "leaf", constraints,
  resolved_type: inherited === undefined ? {} : { default: inherited } });
const constraint = (keyword, argument) => ({ keyword, argument });

test("explicit node defaults override typedef defaults without coercion", () => {
  const rows = [leaf("/x", [constraint("default", "false")], "true"),
    leaf("/y", [], "18446744073709551615"), leaf("/z", [constraint("default", "")])];
  assert.deepEqual([...nodeDefaults(rows).values()], [
    { required: false, values: ["false"], origin: "node" },
    { required: false, values: ["18446744073709551615"], origin: "type" },
    { required: false, values: [""], origin: "node" }]);
});

test("mandatory and key leaves cannot be filled from typedef defaults", () => {
  const rows = [{ schema_id: "/list", kind: "list", constraints: [constraint("key", "id other")] },
    leaf("/list/id", [constraint("default", "1")], "2"), leaf("/list/other", [], "3"),
    leaf("/list/value", [constraint("mandatory", "true")], "true")];
  for (const value of nodeDefaults(rows).values())
    assert.deepEqual(value, { required: true, values: [], origin: null });
  assert.throws(() => nodeDefaults([leaf("/bad", [constraint("mandatory", "true"), constraint("default", "1")])]), /invalid default/);
});

test("leaf-list defaults preserve order and respect minimum cardinality", () => {
  const list = { ...leaf("/values", [constraint("ordered-by", "user"),
    constraint("default", "second"), constraint("default", "first")], "other"), kind: "leaf-list" };
  assert.deepEqual(nodeDefaults([list]).get("/values"),
    { required: false, values: ["second", "first"], origin: "node" });
  const required = { ...list, constraints: [constraint("min-elements", "1")] };
  assert.deepEqual(nodeDefaults([required]).get("/values"), { required: true, values: [], origin: null });
  assert.throws(() => nodeDefaults([{ ...list, constraints: [...list.constraints,
    constraint("min-elements", "1")] }]), /invalid default/);
  assert.throws(() => nodeDefaults([leaf("/bad", [constraint("default", "1"), constraint("default", "2")])]), /invalid default/);
});

test("exact IS-IS inventory retains root/interface defaults and mandatory inputs", () => {
  const inventory = JSON.parse(readFileSync(new URL("../../schemas/cli/isis-26.7.R1-inventory.json", import.meta.url), "utf8"));
  const config = nodeDefaults(inventory.configuration);
  assert.deepEqual(config.get("/configure/router/isis/admin-state").values, ["disable"]);
  assert.deepEqual(config.get("/configure/router/isis/interface/admin-state").values, ["enable"]);
  assert.deepEqual(config.get("/configure/router/isis/level-capability").values, ["1/2"]);
  assert.deepEqual(config.get("/configure/router/isis/isis-instance"), { required: true, values: [], origin: null });
  const mandatory = inventory.management.filter((row) => row.kind === "leaf" &&
    row.constraints.some((item) => item.keyword === "mandatory" && item.argument === "true") &&
    row.resolved_type?.default !== undefined);
  assert.ok(mandatory.length > 0);
  const actions = nodeDefaults(inventory.management);
  for (const row of mandatory) assert.deepEqual(actions.get(row.schema_id).values, []);
});
