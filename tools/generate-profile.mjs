// Canonical YAML to compile-time C++ and TypeScript profile projection.
// Output comparison in CI rejects manual drift in either consumer language.

import { readFileSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";
import { parse } from "yaml";

const root = resolve(import.meta.dirname, "..");
const sourcePath = resolve(root, "profiles/7750-sr-7-iom4-e.yaml");
const cliSourcePath = resolve(root, "schemas/cli/26.7.R1.yaml");
const headerPath = resolve(root, "core/include/router/generated_profile.hpp");
const cliHeaderPath = resolve(root, "core/include/router/generated_cli_schema.hpp");
const typescriptPath = resolve(root, "packages/contracts/src/generated-profile.ts");
const profile = parse(readFileSync(sourcePath, "utf8"));
const cliSchema = parse(readFileSync(cliSourcePath, "utf8"));

const ip = (value) => value.split("/")[0].split(".").map(Number);
const prefix = (value) => Number(value.split("/")[1]);
const mac = (value) => value.split(":").map((byte) => `0x${byte.toLowerCase()}`);
const networkHex = (value) =>
  `0x${ip(value).reduce((sum, byte) => (sum * 256 + byte) >>> 0, 0).toString(16).padStart(8, "0")}U`;
const cppBytes = (values) => `{${values.join(", ")}}`;
const quoted = (values) => values.map((value) => `"${value}"`).join(", ");

const endpointCount = profile.hosts?.length ?? 0;
const interfaceCount = profile.router_interfaces?.length ?? 0;
if (!endpointCount || endpointCount !== interfaceCount) {
  throw new Error("A profile requires one router interface for every endpoint");
}
if (profile.capture_interfaces?.length !== endpointCount * 4 + 1) {
  throw new Error("Capture points require two link directions, ingress, egress and one CPM point");
}
if (!Number.isInteger(profile.ports?.count) || profile.ports.count < endpointCount) {
  throw new Error("Equipped port count must cover every endpoint binding");
}

const portIds = Array.from({ length: profile.ports.count }, (_, index) =>
  `${profile.line_card.slot}/${profile.mda.slot}/${index + 1}`);
const cppRows = (items, convert) => items.map((item) => `    ${convert(item)}`).join(",\n");

const header = `#pragma once

// Compile-time projection of the canonical 7750 SR-7 profile. Full-output
// comparison in CI prevents C++ constants from drifting away from the YAML.

#include "router/packet.hpp"

#include <array>
#include <chrono>
#include <cstdint>

namespace router::profile {

inline constexpr char id[] = "${profile.id}";
inline constexpr char release[] = "${profile.release}";
inline constexpr char chassis[] = "${profile.chassis}";
inline constexpr std::size_t chassis_slots = 5;
inline constexpr std::size_t line_card_slot = ${profile.line_card.slot};
inline constexpr std::size_t mda_slot = ${profile.mda.slot};
inline constexpr char line_card_type[] = "${profile.line_card.type}";
inline constexpr char modeled_mda_type[] = "${profile.mda.modeled_type}";
inline constexpr std::size_t port_count = ${profile.ports.count};
inline constexpr std::size_t endpoint_count = ${endpointCount};
inline constexpr std::uint32_t port_speed_mbps = ${profile.ports.speed_mbps}U;
// These delays are an emulator profile, not a claim about physical SR-7 boot
// time. The YAML marks both values experimental so projections retain source
// status without presenting them as Nokia guarantees.
inline constexpr std::chrono::milliseconds card_initialization{
    ${profile.line_card.initialization_milliseconds}};
inline constexpr std::chrono::milliseconds mda_initialization{
    ${profile.mda.initialization_milliseconds}};
// Ethernet serialization derives from equipped port speed. Propagation belongs
// to each project link and does not alter transmitter throughput.
inline constexpr std::uint64_t port_bits_per_second =
    static_cast<std::uint64_t>(port_speed_mbps) * 1000000ULL;
inline constexpr std::chrono::nanoseconds default_link_propagation{
    ${profile.link_defaults.propagation_delay_nanoseconds}};

inline constexpr std::array<packet::Mac, endpoint_count> host_macs{{
${cppRows(profile.hosts, (host) => cppBytes(mac(host.mac)))},
}};
inline constexpr std::array<packet::Ipv4, endpoint_count> host_addresses{{
${cppRows(profile.hosts, (host) => cppBytes(ip(host.address)))},
}};
inline constexpr std::array<packet::Ipv4, endpoint_count> host_gateways{{
${cppRows(profile.hosts, (host) => cppBytes(ip(host.gateway)))},
}};
inline constexpr std::array<std::uint8_t, endpoint_count> host_prefix_lengths{
    ${profile.hosts.map((host) => prefix(host.address)).join(", ")}};
inline constexpr std::array<packet::Mac, endpoint_count> router_macs{{
${cppRows(profile.router_interfaces, (item) => cppBytes(mac(item.mac)))},
}};
inline constexpr std::array<packet::Ipv4, endpoint_count> router_addresses{{
${cppRows(profile.router_interfaces, (item) => cppBytes(ip(item.address)))},
}};
inline constexpr std::array<std::uint32_t, endpoint_count> router_networks{
    ${profile.router_interfaces.map((item) => networkHex(item.network)).join(", ")}};
inline constexpr std::array<const char*, port_count> port_ids{
    ${quoted(portIds)}};
inline constexpr std::array<const char*, ${profile.mda.supported.length}> supported_mda_types{
    ${quoted(profile.mda.supported)}};
inline constexpr std::array<const char*, endpoint_count> interface_names{
    ${quoted(profile.router_interfaces.map((item) => item.name))}};
inline constexpr std::array<const char*, endpoint_count> interface_addresses{
    ${quoted(profile.router_interfaces.map((item) => item.address))}};
inline constexpr std::array<const char*, endpoint_count> interface_prefixes{
    ${quoted(profile.router_interfaces.map((item) => item.network))}};
inline constexpr std::array<const char*, ${profile.capture_interfaces.length}> capture_interface_names{
    ${quoted(profile.capture_interfaces)}};

}  // namespace router::profile
`;

const parameterKinds = [
  "card_slot", "mda_slot", "card_type", "mda_type", "port_id",
  "interface_name", "ipv4", "ipv4_prefix", "count", "mtu",
  "system_name", "description"
];
const commandIds = new Set();
const sourceIds = new Set();
let maximumTokens = 0;
for (const command of cliSchema.commands ?? []) {
  if (!/^[a-z][a-z0-9_]*$/.test(command.id ?? "")) {
    throw new Error(`Invalid CLI command id: ${command.id}`);
  }
  if (commandIds.has(command.id)) throw new Error(`Duplicate CLI command id: ${command.id}`);
  commandIds.add(command.id);
  sourceIds.add(command.source_id);
  if (!command.engines?.length || command.engines.some((engine) => !["md", "classic"].includes(engine))) {
    throw new Error(`${command.id}: invalid CLI engine list`);
  }
  if (!command.tokens?.length) throw new Error(`${command.id}: empty CLI token list`);
  maximumTokens = Math.max(maximumTokens, command.tokens.length);
  for (const token of command.tokens) {
    if (typeof token === "string") continue;
    if (!parameterKinds.includes(token?.parameter)) {
      throw new Error(`${command.id}: invalid CLI parameter ${token?.parameter}`);
    }
  }
}
if (cliSchema.release !== profile.release) {
  throw new Error(`CLI schema ${cliSchema.release} does not match profile ${profile.release}`);
}

const cppToken = (token) => typeof token === "string"
  ? `{TokenKind::literal, "${token.replaceAll("\\", "\\\\").replaceAll('"', '\\"')}"}`
  : `{TokenKind::${token.parameter}, "<${token.parameter.replaceAll("_", "-")}>"}`;
const cliRows = cliSchema.commands.map((command) => {
  const mask = (command.engines.includes("md") ? 1 : 0) |
    (command.engines.includes("classic") ? 2 : 0);
  const tokens = command.tokens.map(cppToken);
  while (tokens.length < maximumTokens) tokens.push("{}");
  return `    {CommandId::${command.id}, ${mask}, ${command.tokens.length}, {{${tokens.join(", ")}}}, "${command.source_id}"}`;
}).join(",\n");

const cliHeader = `#pragma once

// Generated from the release-pinned CLI grammar. The runtime matches token
// descriptors and never carries a second handwritten list of command lines.

#include <array>
#include <cstddef>
#include <cstdint>
#include <string_view>

namespace router::cli_schema {

enum class CommandId : std::uint16_t {
${[...commandIds].map((id) => `  ${id}`).join(",\n")}
};

enum class TokenKind : std::uint8_t {
  literal,
${parameterKinds.map((kind) => `  ${kind}`).join(",\n")}
};

struct TokenSpec {
  TokenKind kind{TokenKind::literal};
  std::string_view display{};
};

inline constexpr std::size_t maximum_tokens = ${maximumTokens};

struct CommandSpec {
  CommandId id{};
  std::uint8_t engine_mask{};
  std::uint8_t token_count{};
  std::array<TokenSpec, maximum_tokens> tokens{};
  std::string_view source_id{};
};

inline constexpr std::array<CommandSpec, ${cliSchema.commands.length}> commands{{
${cliRows}
}};

}  // namespace router::cli_schema
`;

const typescript = `// Typed projection of the canonical 7750 SR-7 profile. Full-output
// comparison in CI prevents browser defaults from drifting away from the YAML.

export const GENERATED_PROFILE = {
  id: "${profile.id}",
  release: "${profile.release}",
  chassis: "${profile.chassis}",
  chassisSlots: 5,
  portCount: ${profile.ports.count},
  portSpeedMbps: ${profile.ports.speed_mbps},
  cardInitializationMs: ${profile.line_card.initialization_milliseconds},
  mdaInitializationMs: ${profile.mda.initialization_milliseconds},
  defaultPropagationDelayNs: ${profile.link_defaults.propagation_delay_nanoseconds},
  routerInterfaces: [
${profile.router_interfaces.map((item) => `    { mac: "${item.mac}", address: "${item.address}" }`).join(",\n")}
  ],
  hosts: [
${profile.hosts.map((host) => `    { id: "${host.id}", name: "${host.name}", mac: "${host.mac}", address: "${host.address}", gateway: "${host.gateway}" }`).join(",\n")}
  ]
} as const;
`;

const outputs = [[headerPath, header], [cliHeaderPath, cliHeader], [typescriptPath, typescript]];
if (process.argv.includes("--check")) {
  const drift = outputs.filter(([path, expected]) => readFileSync(path, "utf8") !== expected);
  if (drift.length) {
    console.error(`Generated profile drift: ${drift.map(([path]) => path).join(", ")}`);
    process.exit(1);
  }
  console.log(`generated profile valid: ${outputs.length} targets`);
} else {
  for (const [path, value] of outputs) writeFileSync(path, value);
}
