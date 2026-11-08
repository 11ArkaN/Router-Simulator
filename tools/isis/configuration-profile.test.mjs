// Configuration source tests own detached inventory copies. They verify pin,
// inheritance and default/range validation without writing production files.

import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { renderConfigurationProfile, configurationParameterRanges, configurationRestartPaths } from "./configuration-profile.mjs";

const inventory = JSON.parse(readFileSync(new URL("../../schemas/cli/isis-26.7.R1-inventory.json", import.meta.url), "utf8"));
test("configuration projection resolves inherited levels and selected-release defaults", () => {
  const output = renderConfigurationProfile(inventory);
  for (const line of ["level_capability_default = 3;", "instance_admin_enabled_default = false;",
    "interface_admin_enabled_default = true;", "hello_interval_seconds_default = 9;",
    "csnp_interval_seconds_default = 10;", "level_lsp_mtu_octets_default = 1492;", "metric_maximum = 16777215;", "instance_maximum = 127;",
    "spf_max_wait_milliseconds_default = 10000;", "spf_initial_wait_milliseconds_default = 1000;",
    "spf_second_wait_milliseconds_default = 1000;", "lsp_max_wait_milliseconds_default = 5000;",
    "lsp_initial_wait_milliseconds_default = 10;", "lsp_second_wait_milliseconds_default = 1000;"])
    assert.ok(output.includes(line), line);
});
test("parameter bounds remain exact and classic keywords map to YANG enum values", () => {
  const parameters = {
    instance: {yang_path: "/configure/router/isis/isis-instance"},
    levels: {yang_path: "/configure/router/isis/level-capability",
      values: ["level-1", "level-2", "level-1/2"], canonical_values: ["1", "2", "1/2"]}
  };
  assert.deepEqual(configurationParameterRanges(parameters, inventory).get("instance"), {minimum: "0", maximum: "127"});
  assert.throws(() => configurationParameterRanges({...parameters,
    levels: {...parameters.levels, canonical_values: ["1", "2", "3"]}}, inventory));
  assert.throws(() => configurationParameterRanges({missing: {yang_path: "/configure/router/isis/not-a-leaf"}}, inventory));
  const copy = structuredClone(inventory);
  const node = copy.configuration.find((item) => item.data_path === parameters.instance.yang_path);
  node.resolved_type.builtin = "uint64";
  node.resolved_type.layers = [{restrictions: [{keyword: "range", argument: "0..18446744073709551615"}]}];
  assert.equal(configurationParameterRanges(parameters, copy).get("instance").maximum, "18446744073709551615");
});
test("unrecognized pins, duplicate nodes and invalid numeric defaults reject", () => {
  for (const mutate of [
    (value) => { value.source_commit = "0".repeat(40); },
    (value) => { value.configuration.push(value.configuration[0]); },
    (value) => { value.configuration = value.configuration.filter((node) => node.data_path !== "/configure/router/isis/interface/csnp-interval"); },
    (value) => { value.configuration.find((node) => node.data_path.endsWith("/csnp-interval")).constraints.find((item) => item.keyword === "default").argument = "0"; },
    (value) => { value.configuration.find((node) => node.data_path === "/configure/router/isis/level-capability").resolved_type.default = "missing"; }
  ]) {
    const value = structuredClone(inventory);
    mutate(value);
    assert.throws(() => renderConfigurationProfile(value));
  }
});

test("restart lifecycle preserves exact pinned schema paths", () => {
  const paths = configurationRestartPaths(inventory);
  for (const leaf of ["lsp-lifetime", "lsp-mtu-size", "router-id", "system-id"])
    assert.ok(paths.includes(`/configure/router/isis/${leaf}`));
  assert.ok(!paths.includes("/configure/router/isis/level/lsp-mtu-size"));
  assert.equal(paths.length, 10);
  assert.ok(renderConfigurationProfile(inventory).includes("restart_paths"));
  assert.ok(renderConfigurationProfile(inventory, "typescript").includes("ISIS_RESTART_PATHS"));
  const invalid = structuredClone(inventory);
  invalid.configuration.find((node) => node.data_path === "/configure/router/isis/lsp-lifetime")
    .extensions[0].argument = "false";
  assert.throws(() => configurationRestartPaths(invalid));
  assert.throws(() => configurationRestartPaths({...inventory, source_commit: "unknown"}));
});
