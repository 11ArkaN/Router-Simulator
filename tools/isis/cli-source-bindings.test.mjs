// Whole-surface source checks cover every admitted IS-IS node and removal form.
// Mutations are detached fixtures; no command or generated file is published.
import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { parse } from "yaml";
import { validateIsisCliBindings } from "./cli-source-bindings.mjs";

const read = (path) => readFileSync(new URL(path, import.meta.url), "utf8");
const schema = parse(read("../../schemas/cli/26.7.R1.yaml"));
const commands = schema.commands;
const inventory = JSON.parse(read("../../schemas/cli/isis-26.7.R1-inventory.json"));
const bindings = JSON.parse(read("../../schemas/cli/isis-26.7.R1-command-bindings.json"));
test("every admitted node has exact YANG and engine references plus required operators", () => {
  assert.equal(validateIsisCliBindings(commands, inventory, bindings, schema.parameters), bindings.bindings.length);
});
test("missing removals, changed names, wrong releases and leaf navigation fail", () => {
  const path = "/configure/router/isis/interface/level/metric";
  for (const engine of ["md", "classic"]) {
    const rows = commands.filter((row) => !(row.yang_path === path && row.engines.includes(engine) &&
      (row.tokens[0] === "delete" || row.tokens.includes("no"))));
    assert.throws(() => validateIsisCliBindings(rows, inventory, bindings));
  }
  for (const mutate of [
    (row) => { row.tokens[row.tokens.indexOf("metric")] = "cost"; },
    (row) => { row.source_ref = row.source_ref.replace("/26-7/", "/26-10/"); },
    (row) => { row.enters_context = true; },
    (row) => { delete row.yang_path; }
  ]) {
    const rows = structuredClone(commands);
    mutate(rows.find((row) => row.id === "md_isis_interface_level_metric"));
    assert.throws(() => validateIsisCliBindings(rows, inventory, bindings));
  }
});

test("classic default-metric keeps the multiword source parameter as one value", () => {
  for (const id of ["classic_isis_level_default_metric", "classic_isis_level_default_metric_default"]) {
    const row = commands.find((item) => item.id === id);
    const index = row.tokens.indexOf("default-metric");
    assert.deepEqual(row.tokens.slice(index + 1), [{parameter: "isis_metric"}]);
  }
  for (const id of ["classic_isis_no_level_default_metric", "classic_isis_no_level_default_metric_default"]) {
    const row = commands.find((item) => item.id === id);
    assert.deepEqual(row.tokens.slice(-2), ["no", "default-metric"]);
  }
});

test("value parameters cannot borrow a different YANG range", () => {
  const parameters = structuredClone(schema.parameters);
  parameters.isis_metric.yang_path = "/configure/router/isis/interface/level/priority";
  assert.throws(() => validateIsisCliBindings(commands, inventory, bindings, parameters));
});

test("compound classic timers retain exact child bindings and parent removal", () => {
  const path = "/configure/router/isis/timers/spf-wait";
  for (const mutate of [
    (value) => { value.bindings.find((entry) => entry.yang_path === path).classic_no = false; },
    (value) => { delete value.bindings.find((entry) => entry.yang_path === path).classic_parameters; },
    (value) => { value.bindings.find((entry) => entry.yang_path === path + "/spf-max-wait").classic_via_parent = path + "/missing"; },
    (value) => { value.bindings.find((entry) => entry.yang_path === path).classic_parameters.isis_spf_max_wait = path + "/spf-initial-wait"; }
  ]) {
    const value = structuredClone(bindings); mutate(value);
    assert.throws(() => validateIsisCliBindings(commands, inventory, value, schema.parameters));
  }
  const withoutReset = commands.filter((row) => !(row.yang_path === path && row.engines.includes("classic") && row.tokens.includes("no")));
  assert.throws(() => validateIsisCliBindings(withoutReset, inventory, bindings, schema.parameters));
  const withoutInitial = commands.filter((row) => !(row.yang_path === path && row.engines.includes("classic") &&
    row.tokens.some((token) => token.parameter === "isis_spf_initial_wait")));
  assert.throws(() => validateIsisCliBindings(withoutInitial, inventory, bindings, schema.parameters));
});
