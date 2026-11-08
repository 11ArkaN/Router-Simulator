// Pinned YANG facts compile into immutable configuration defaults and bounds.
// The caller owns input values and publication; this module performs no I/O.

const commit = "6656cbb0905c7b952afaa1d7c2b63aa4da6cc5f7";
const prefix = "/configure/router/isis/";
const numeric = [
  ["instance", "isis-instance"],
  ["metric", "interface/level/metric"],
  ["default_metric", "level/default-metric"],
  ["preference", "level/preference"],
  ["external_preference", "level/external-preference"],
  ["hello_interval_seconds", "interface/level/hello-interval"],
  ["hello_multiplier", "interface/level/hello-multiplier"],
  ["priority", "interface/level/priority"],
  ["csnp_interval_seconds", "interface/csnp-interval"],
  ["lsp_pacing_interval_milliseconds", "interface/lsp-pacing-interval"],
  ["retransmit_interval_seconds", "interface/retransmit-interval"],
  ["lsp_lifetime_seconds", "lsp-lifetime"],
  ["lsp_mtu_octets", "lsp-mtu-size"],
  ["level_lsp_mtu_octets", "level/lsp-mtu-size"],
  ["spf_max_wait_milliseconds", "timers/spf-wait/spf-max-wait"],
  ["spf_initial_wait_milliseconds", "timers/spf-wait/spf-initial-wait"],
  ["spf_second_wait_milliseconds", "timers/spf-wait/spf-second-wait"],
  ["lsp_max_wait_milliseconds", "timers/lsp-wait/lsp-max-wait"],
  ["lsp_initial_wait_milliseconds", "timers/lsp-wait/lsp-initial-wait"],
  ["lsp_second_wait_milliseconds", "timers/lsp-wait/lsp-second-wait"]
];
const fail = (message) => { throw new Error(`IS-IS configuration profile: ${message}`); };
const statements = (node, keyword) =>
  (node.constraints ?? []).filter((item) => item.keyword === keyword).map((item) => item.argument);
const singleton = (values, name) => {
  if (values.length !== 1) fail(`${name} must have exactly one value`);
  return values[0];
};
const integer = (value, name) => {
  if (!/^\d+$/.test(String(value)) || !Number.isSafeInteger(Number(value))) fail(`${name} is not an exact unsigned integer`);
  return Number(value);
};

export function configurationParameterRanges(parameters, inventory) {
  if (inventory?.source_commit !== commit || inventory.release !== "26.7.R1") fail("unrecognized parameter source pin");
  const ranges = new Map();
  for (const [name, parameter] of Object.entries(parameters)) {
    if (!parameter.yang_path) continue;
    const matches = inventory.configuration.filter((node) => node.data_path === parameter.yang_path);
    const item = singleton(matches, parameter.yang_path);
    if (parameter.values) {
      const allowed = item.resolved_type?.builtin === "boolean" ? ["true", "false"] :
        item.resolved_type?.layers.flatMap((layer) => layer.restrictions ?? [])
          .filter((entry) => entry.keyword === "enum").map((entry) => entry.argument);
      if (!allowed?.length || (parameter.canonical_values ?? parameter.values).some((value) => !allowed.includes(value)))
        fail(`parameter keywords differ from YANG for ${name}`);
    }
    if (!/^(u?int)(8|16|32|64)$/.test(item.resolved_type?.builtin ?? "")) continue;
    const restrictions = item.resolved_type.layers.flatMap((layer) => layer.restrictions ?? []).filter((entry) => entry.keyword === "range");
    const bounds = singleton(restrictions, parameter.yang_path).argument.split("..");
    if (bounds.length !== 2 || bounds.some((value) => !/^\d+$/.test(value))) fail(`unsupported integer parameter ${name}`);
    const minimum = BigInt(bounds[0]), maximum = BigInt(bounds[1]);
    if (maximum < minimum || maximum > (1n << 64n) - 1n) fail(`invalid integer parameter ${name}`);
    ranges.set(name, {minimum: String(minimum), maximum: String(maximum)});
  }
  return ranges;
}

// Restart extensions apply to the schema node itself. Keep full paths so a
// similarly named leaf under another level cannot inherit lifecycle semantics.
export function configurationRestartPaths(inventory) {
  if (inventory?.schema_version !== 2 || inventory.source_commit !== commit ||
      inventory.release !== "26.7.R1" || !Array.isArray(inventory.configuration))
    fail("unrecognized lifecycle source pin");
  const paths = [];
  for (const node of inventory.configuration) {
    const extensions = (node.extensions ?? []).filter((item) =>
      item.keyword === "sros-ext:auto-restart-to-modify");
    if (!extensions.length) continue;
    if (extensions.length !== 1 || extensions[0].argument !== null ||
        !node.data_path.startsWith(prefix) || paths.includes(node.data_path))
      fail(`invalid restart extension ${node.data_path}`);
    paths.push(node.data_path);
  }
  return paths.sort();
}

export function renderConfigurationProfile(inventory, format = "cpp") {
  if (inventory?.schema_version !== 2 || inventory.release !== "26.7.R1" ||
      inventory.source_commit !== commit || !Array.isArray(inventory.configuration)) fail("unrecognized source pin");
  const nodes = new Map();
  const schemaIds = new Set();
  for (const node of inventory.configuration) {
    if (schemaIds.has(node.schema_id)) fail(`duplicate schema node ${node.schema_id}`);
    schemaIds.add(node.schema_id);
    const alternatives = nodes.get(node.data_path) ?? [];
    alternatives.push(node);
    nodes.set(node.data_path, alternatives);
  }
  // Choice/case alternatives may share a data path. This projection selects
  // unconditional leaves only, so an ambiguous selected path must reject.
  const node = (path) => singleton(nodes.get(prefix + path) ?? [], path);
  const inherited = (item, keyword) => (item.resolved_type?.layers ?? []).flatMap((layer) =>
    (layer.restrictions ?? []).filter((value) => value.keyword === keyword).map((value) => value.argument));
  const defaultValue = (item) => {
    const own = statements(item, "default");
    if (own.length > 1) fail(`duplicate default ${item.data_path}`);
    return own[0] ?? item.resolved_type?.default;
  };
  const constants = [];
  const add = (name, value, type = "std::uint32_t") => constants.push({name, value, type});
  for (const [name, path] of numeric) {
    const item = node(path);
    const bounds = singleton(inherited(item, "range"), `${path} range`).split("..");
    if (bounds.length !== 2) fail(`unsupported ${path} range`);
    const minimum = integer(bounds[0], path), maximum = integer(bounds[1], path);
    if (maximum < minimum || maximum > 0xffffffff) fail(`invalid ${path} range`);
    add(`${name}_minimum`, minimum);
    add(`${name}_maximum`, maximum);
    const value = defaultValue(item);
    if (value !== undefined) {
      const parsed = integer(value, path);
      if (parsed < minimum || parsed > maximum) fail(`out-of-range ${path} default`);
      add(`${name}_default`, parsed);
    }
  }
  for (const [name, path, enabled] of [
    ["instance_admin_enabled", "admin-state", "enable"],
    ["interface_admin_enabled", "interface/admin-state", "enable"],
    ["ipv4_routing", "ipv4-routing", "true"],
    ["advertise_passive_only", "advertise-passive-only", "true"],
    ["interface_passive", "interface/passive", "true"],
    ["interface_level_passive", "interface/level/passive", "true"],
    ["wide_metrics_only", "level/wide-metrics-only", "true"]
  ]) {
    const item = node(path), value = defaultValue(item);
    const allowed = enabled === "enable" ? ["enable", "disable"] : ["true", "false"];
    if (!allowed.includes(value)) fail(`unrecognized ${path} default`);
    add(`${name}_default`, value === enabled, "bool");
  }
  const levels = node("level-capability");
  const selected = defaultValue(levels);
  const enumeration = (levels.resolved_type?.layers ?? []).flatMap((layer) => layer.restrictions ?? [])
    .find((entry) => entry.keyword === "enum" && entry.argument === selected);
  const enumValue = singleton((enumeration?.children ?? []).filter((entry) => entry.keyword === "value").map((entry) => entry.argument), "level default");
  const levelDefault = integer(enumValue, "level default");
  if (levelDefault < 1 || levelDefault > 3) fail("unsupported level default");
  add("level_capability_default", levelDefault, "std::uint8_t");
  add("area_addresses_maximum", integer(singleton(statements(node("area-address"), "max-elements"), "area limit"), "area limit"));
  const interfaceLength = singleton(inherited(node("interface/interface-name"), "length"), "interface name length").split("..");
  if (interfaceLength.length !== 2) fail("unsupported interface name length");
  const nameMinimum = integer(interfaceLength[0], "interface length");
  const nameMaximum = integer(interfaceLength[1], "interface length");
  if (nameMaximum < nameMinimum || nameMaximum > 0xffffffff) fail("invalid interface name length");
  add("interface_name_minimum", nameMinimum);
  add("interface_name_maximum", nameMaximum);
  if (defaultValue(node("ipv6-routing")) !== "false" || defaultValue(node("system-id")) !== "0000.0000.0000")
    fail("identity or IPv6 default requires an explicit configuration contract update");
  const restartPaths = configurationRestartPaths(inventory);
  if (format === "typescript")
    return `// Immutable IS-IS intent bounds from the pinned SR OS 26.7.R1 YANG.\n// Offline generation owns these facts; browser validators cannot alter them.\nexport const ISIS_CONFIGURATION_PROFILE = ${JSON.stringify(Object.fromEntries(constants.map(({name, value}) => [name, value])), null, 2)} as const;\nexport const ISIS_RESTART_PATHS = ${JSON.stringify(restartPaths, null, 2)} as const;\n`;
  if (format !== "cpp") fail("unrecognized output language");
  return `// Immutable configuration facts from pinned SR OS 26.7.R1 YANG.\n// Generated offline; configuration owners consume values without source I/O.\n#pragma once\n#include <array>\n#include <cstdint>\n#include <string_view>\nnamespace router::isis::configuration_profile {\n${constants.map(({name, value, type}) => `inline constexpr ${type} ${name} = ${value};`).join("\n")}\ninline constexpr std::array<std::string_view, ${restartPaths.length}> restart_paths{{${restartPaths.map((path) => JSON.stringify(path)).join(", ")}}};\n}\n`;
}
