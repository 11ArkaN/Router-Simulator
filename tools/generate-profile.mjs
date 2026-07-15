// Canonical profile compiler. It owns the only conversion from release YAML to
// C++, TypeScript and CMake. Consumers must not reconstruct slot, topology,
// resource, timing or ABI values independently.

import { createHash } from "node:crypto";
import { readFileSync, readdirSync, writeFileSync } from "node:fs";
import { basename, resolve } from "node:path";
import { parse } from "yaml";

const root = resolve(import.meta.dirname, "..");
const profileDirectory = resolve(root, "profiles");
const profileFiles = readdirSync(profileDirectory)
  .filter((name) => name.endsWith(".yaml"))
  .sort();
const requestedProfile = process.env.ROUTER_PROFILE;
// A single-profile repository selects itself. Once more profiles are added,
// explicit selection prevents a filesystem-order dependent production build.
const selectedProfile = requestedProfile
  ? profileFiles.find((name) => name === requestedProfile || name.replace(/\.yaml$/, "") === requestedProfile)
  : profileFiles.length === 1 ? profileFiles[0] : undefined;
if (!selectedProfile) {
  throw new Error("Select one profile through ROUTER_PROFILE when multiple profiles exist");
}

const sourcePath = resolve(profileDirectory, selectedProfile);
// Profile release selects its CLI schema and ABI versions select the remaining
// schemas. Filenames are never duplicated in CMake, UI or runtime code.
const profileText = readFileSync(sourcePath, "utf8");
const profile = parse(profileText);
const cliSourcePath = resolve(root, "schemas/cli", `${profile.release}.yaml`);
const cliSchema = parse(readFileSync(cliSourcePath, "utf8"));
const headerPath = resolve(root, "core/include/router/generated_profile.hpp");
const cliHeaderPath = resolve(root, "core/include/router/generated_cli_schema.hpp");
const typescriptPath = resolve(root, "packages/contracts/src/generated-profile.ts");
const cmakePath = resolve(root, "core/generated-profile.cmake");
const runtimeHeaderPath = resolve(root, "core/include/router/generated_runtime_protocol.hpp");
const runtimeTypescriptPath = resolve(root, "packages/contracts/src/generated-runtime-protocol.ts");

// These small converters normalize YAML text into language-specific literals.
// They perform no profile selection and are deterministic for identical input.
const ip = (value) => value.split("/")[0].split(".").map(Number);
const prefix = (value) => Number(value.split("/")[1]);
const mac = (value) => value.split(":").map((byte) => `0x${byte.toLowerCase()}`);
// IPv4 network values are emitted in network bit order, matching the C++ RIB.
const networkHex = (value) =>
  `0x${ip(value).reduce((sum, byte) => (sum * 256 + byte) >>> 0, 0).toString(16).padStart(8, "0")}U`;
const cppBytes = (values) => `{${values.join(", ")}}`;
const cppString = (value) => `"${String(value).replaceAll("\\", "\\\\").replaceAll('"', '\\"')}"`;
// Array helpers keep generated formatting stable so --check reports only real
// semantic drift and not nondeterministic whitespace.
const quoted = (values) => values.map(cppString).join(", ");
const cppRows = (items, convert) => items.map((item) => `    ${convert(item)}`).join(",\n");
const stableJson = (value) => {
  // Recursive key sorting produces a content hash independent of YAML key
  // order while preserving array order where profile order is semantic.
  if (Array.isArray(value)) return `[${value.map(stableJson).join(",")}]`;
  if (value && typeof value === "object") {
    return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${stableJson(value[key])}`).join(",")}}`;
  }
  return JSON.stringify(value);
};
const profileHash = createHash("sha256").update(stableJson(profile)).digest("hex").slice(0, 16);
// Checkpoint hash covers field order and meaning, while the profile hash covers
// values. A matching version number alone is insufficient for safe restore.
const checkpointSchemaPath = resolve(root, "schemas/checkpoint", `${profile.abi.checkpoint}.yaml`);
const checkpointSchema = parse(readFileSync(checkpointSchemaPath, "utf8"));
if (checkpointSchema.version !== profile.abi.checkpoint) {
  throw new Error("Checkpoint schema version does not match the active profile");
}
const checkpointSchemaHash = createHash("sha256")
  .update(stableJson(checkpointSchema)).digest("hex").slice(0, 16);
const runtimeSchemaPath = resolve(root, "schemas/runtime", `${profile.abi.runtime_messages}.yaml`);
const runtimeSchema = parse(readFileSync(runtimeSchemaPath, "utf8"));
if (runtimeSchema.version !== profile.abi.runtime_messages) {
  throw new Error("Runtime protocol schema version does not match the active profile");
}

// Checkpoint compatibility depends on executable semantics, not only field
// order. Hash every hand-maintained core source and header while excluding
// generated outputs whose content already derives from these same inputs.
const coreRoot = resolve(root, "core");
const coreFiles = readdirSync(coreRoot, { recursive: true })
  .map((name) => String(name).replaceAll("\\", "/"))
  .filter((name) => (name.startsWith("src/") || name.startsWith("include/")) &&
    /\.(cpp|hpp)$/.test(name) && !name.includes("generated_"))
  .sort();
const buildHasher = createHash("sha256")
  .update(stableJson(profile))
  .update(stableJson(cliSchema))
  .update(stableJson(checkpointSchema))
  .update(stableJson(runtimeSchema));
for (const name of coreFiles)
  buildHasher.update(name).update(readFileSync(resolve(coreRoot, name)));
const buildCompatibilityHash = buildHasher.digest("hex").slice(0, 16);

const endpointCount = profile.hosts?.length ?? 0;
const interfaceCount = profile.router_interfaces?.length ?? 0;
const links = profile.links ?? [];
// Cross-field validation occurs before emitting any target. A partially valid
// profile can therefore never update one language while another stays stale.
if (!endpointCount || endpointCount !== interfaceCount || links.length !== endpointCount) {
  throw new Error("A profile requires one router interface and one link for every endpoint");
}
if (profile.capture_interfaces?.length !== endpointCount * 4 + 1) {
  throw new Error("Capture points require two link directions, ingress, egress and one CPM point");
}
if (!Number.isInteger(profile.ports?.count) || profile.ports.count < endpointCount) {
  throw new Error("Equipped port count must cover every endpoint binding");
}
if (profile.ports.count > 32) {
  throw new Error("Telemetry ABI v3 represents operational ports in a 32-bit bitmap");
}
if (profile.capture_interfaces.length > 255 || endpointCount > 127) {
  throw new Error("Current capture and link identifiers require capacities below 256");
}
// The largest legal first-stage running configuration contains every port
// description and every static route. Netstring framing adds a decimal length,
// colon and comma to each value. A conservative 12-byte framing allowance per
// field keeps this proof independent from the exact number of decimal digits.
const runningFieldCount = 2 + profile.ports.count * 4 + 1 +
  interfaceCount * 4 + 1 + profile.resources.static_route_capacity * 2;
const maximumRunningCommandBytes = 32 + profile.limits.system_name_bytes +
  profile.ports.count * (32 + profile.limits.port_description_bytes) +
  interfaceCount * 128 + profile.resources.static_route_capacity * 96 +
  runningFieldCount * 12;
if (profile.resources.command_message_bytes < maximumRunningCommandBytes) {
  throw new Error(`Command mailbox cannot hold a maximum valid running datastore (${maximumRunningCommandBytes} bytes)`);
}
if (profile.resources.fib_route_capacity < profile.ports.count + profile.resources.static_route_capacity) {
  throw new Error("FIB capacity must cover every connected and static route slot");
}
if (profile.resources.fib_route_capacity > 255 || profile.ports.count > 255) {
  throw new Error("Current bounded route and port counters require capacities at or below 255");
}
if (!Number.isInteger(profile.resources.pthread_pool_min) ||
    !Number.isInteger(profile.resources.pthread_pool_max) ||
    profile.resources.pthread_pool_min < 2 ||
    profile.resources.pthread_pool_max > 4 ||
    profile.resources.pthread_pool_min > profile.resources.pthread_pool_max ||
    profile.resources.runtime_worker_count > profile.resources.pthread_pool_min) {
  throw new Error("pthread pool must contain 2 to 4 workers and cover active shard owners");
}
// Template capacities become array extents in C++. Reject zero, fractional or
// unsafe values here so invalid queue types never reach a compiler diagnostic.
for (const key of ["link_queue_frames", "link_inflight_frames", "adjacency_pending_frames",
  "command_ring_capacity", "response_ring_capacity", "forwarding_ring_capacity"]) {
  const value = profile.resources[key];
  if (!Number.isSafeInteger(value) || value <= 0) {
    throw new Error(`${key} must be a positive safe integer`);
  }
}
// Text and UI limits are cross-language contracts. Validate them once before
// using them as C++ array extents or browser parser bounds.
for (const [group, keys] of [[profile.resources, ["command_message_bytes", "response_message_bytes",
  "cli_input_queue_bytes", "cli_output_queue_bytes"]],
  [profile.limits, ["system_name_bytes", "port_description_bytes", "host_name_bytes", "project_name_bytes"]],
  [profile.cli_defaults, ["ping_count", "ping_max_count", "ping_size", "ping_min_size", "ping_max_size", "history_entries"]],
  [profile.timing, ["arp_timeout_seconds", "telemetry_read_attempts", "autosave_debounce_milliseconds"]]]) {
  for (const key of keys) {
    if (!Number.isSafeInteger(group?.[key]) || group[key] <= 0) {
      throw new Error(`${key} must be a positive safe integer`);
    }
  }
}
for (const key of ["snmp_port", "config_backup_count"]) {
  if (!Number.isSafeInteger(profile.system?.[key]) || profile.system[key] <= 0) {
    throw new Error(`system.${key} must be a positive safe integer`);
  }
}
if (profile.cli_defaults.ping_count > profile.cli_defaults.ping_max_count) {
  throw new Error("Default ping count cannot exceed its CLI limit");
}
if (profile.cli_defaults.ping_min_size > profile.cli_defaults.ping_size ||
    profile.cli_defaults.ping_size > profile.cli_defaults.ping_max_size ||
    profile.cli_defaults.ping_max_size > 1472) {
  throw new Error("Ping data-size defaults exceed the untagged endpoint frame profile");
}

const portIds = Array.from({ length: profile.ports.count }, (_, index) =>
  `${profile.line_card.slot}/${profile.mda.slot}/${index + 1}`);
// Maps are generator-only validation aids. Generated consumers receive compact
// arrays and do not perform string-keyed lookup on the packet path.
const portIndex = new Map(portIds.map((id, index) => [id, index]));
const initiallyEnabledPorts = new Set(profile.ports.initially_enabled ?? []);
for (const id of initiallyEnabledPorts) {
  if (!portIndex.has(id)) throw new Error(`${id}: initially enabled port is not generated by the MDA`);
}
const hostIndex = new Map(profile.hosts.map((host, index) => [host.id, index]));
for (const [index, link] of links.entries()) {
  // Profile array order is the compact cross-language endpoint index. Requiring
  // aligned host, link and interface order prevents hidden topology maps.
  if (hostIndex.get(link.host) !== index || !portIndex.has(link.router_port)) {
    throw new Error(`${link.id}: links must follow host order and reference a generated port`);
  }
  if (profile.router_interfaces[index].port !== link.router_port) {
    throw new Error(`${link.id}: router interface and physical link must reference the same port`);
  }
  if (!["enable", "disable"].includes(profile.router_interfaces[index].admin_state)) {
    throw new Error(`${profile.router_interfaces[index].name}: interface admin_state must be enable or disable`);
  }
}

const header = `#pragma once

// Generated profile projection. This file is the only compile-time source for
// hardware identity, topology, resources, timing and cross-language versions.

#include "router/packet.hpp"

#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>

namespace router::profile {

inline constexpr char id[] = ${cppString(profile.id)};
inline constexpr char release[] = ${cppString(profile.release)};
inline constexpr char chassis[] = ${cppString(profile.chassis)};
inline constexpr char default_system_name[] = ${cppString(profile.system.default_name)};
inline constexpr char software_version[] = ${cppString(profile.system.software_version)};
inline constexpr char crypto_module_version[] = ${cppString(profile.system.crypto_module_version)};
inline constexpr char configuration_mode[] = ${cppString(profile.system.configuration_mode)};
inline constexpr std::uint16_t snmp_port = ${profile.system.snmp_port};
inline constexpr std::uint16_t config_backup_count = ${profile.system.config_backup_count};
inline constexpr char dns_resolve_preference[] = ${cppString(profile.system.dns_resolve_preference)};
inline constexpr char dnssec_response_control[] = ${cppString(profile.system.dnssec_response_control)};
inline constexpr char control_slot[] = ${cppString(profile.control.slot)};
inline constexpr char control_card_type[] = ${cppString(profile.control.card)};
inline constexpr char control_initial_state[] = ${cppString(profile.control.initial_state)};
inline constexpr std::size_t chassis_slots = ${profile.chassis_slots};
inline constexpr std::size_t line_card_slot = ${profile.line_card.slot};
inline constexpr std::size_t line_card_index = line_card_slot - 1U;
inline constexpr std::size_t mda_slot = ${profile.mda.slot};
inline constexpr std::size_t mda_index = mda_slot - 1U;
inline constexpr std::size_t mda_slots_per_card = ${profile.mda.slots_per_card};
inline constexpr char line_card_type[] = ${cppString(profile.line_card.type)};
inline constexpr char modeled_mda_type[] = ${cppString(profile.mda.modeled_type)};
inline constexpr char line_card_alarm_id[] = "card-${profile.line_card.slot}";
inline constexpr char mda_alarm_id[] = "mda-${profile.line_card.slot}/${profile.mda.slot}";
inline constexpr std::size_t port_count = ${profile.ports.count};
inline constexpr std::size_t endpoint_count = ${endpointCount};
inline constexpr std::size_t link_direction_count = endpoint_count * 2U;
inline constexpr std::size_t capture_ingress_base = link_direction_count;
inline constexpr std::size_t capture_egress_base = capture_ingress_base + endpoint_count;
inline constexpr std::size_t capture_cpm_index = capture_egress_base + endpoint_count;
inline constexpr std::uint32_t port_speed_mbps = ${profile.ports.speed_mbps}U;
inline constexpr std::uint16_t default_port_mtu = ${profile.ports.default_mtu};
inline constexpr std::uint16_t minimum_port_mtu = ${profile.ports.minimum_mtu};
inline constexpr std::uint16_t maximum_port_mtu = ${profile.ports.maximum_mtu};
inline constexpr std::size_t static_route_capacity = ${profile.resources.static_route_capacity};
inline constexpr std::size_t fib_route_capacity = ${profile.resources.fib_route_capacity};
inline constexpr std::uint32_t runtime_worker_count = ${profile.resources.runtime_worker_count}U;
inline constexpr std::uint32_t pthread_pool_min = ${profile.resources.pthread_pool_min}U;
inline constexpr std::uint32_t pthread_pool_max = ${profile.resources.pthread_pool_max}U;
inline constexpr std::size_t command_message_bytes = ${profile.resources.command_message_bytes};
inline constexpr std::size_t response_message_bytes = ${profile.resources.response_message_bytes};
inline constexpr std::size_t packet_pool_bytes = ${profile.resources.packet_pool_bytes}U;
inline constexpr std::size_t capture_memory_bytes = ${profile.resources.capture_memory_bytes}U;
inline constexpr std::size_t link_queue_capacity = ${profile.resources.link_queue_frames};
inline constexpr std::size_t link_inflight_capacity = ${profile.resources.link_inflight_frames};
inline constexpr std::size_t adjacency_pending_capacity = ${profile.resources.adjacency_pending_frames};
inline constexpr std::size_t command_ring_capacity = ${profile.resources.command_ring_capacity};
inline constexpr std::size_t response_ring_capacity = ${profile.resources.response_ring_capacity};
inline constexpr std::size_t forwarding_ring_capacity = ${profile.resources.forwarding_ring_capacity};
inline constexpr std::size_t cli_input_queue_bytes = ${profile.resources.cli_input_queue_bytes}U;
inline constexpr std::size_t cli_output_queue_bytes = ${profile.resources.cli_output_queue_bytes}U;
inline constexpr std::size_t system_name_bytes = ${profile.limits.system_name_bytes};
inline constexpr std::size_t port_description_bytes = ${profile.limits.port_description_bytes};
inline constexpr std::size_t host_name_bytes = ${profile.limits.host_name_bytes};
inline constexpr std::size_t project_name_bytes = ${profile.limits.project_name_bytes};
inline constexpr std::uint32_t default_ping_count = ${profile.cli_defaults.ping_count}U;
inline constexpr std::uint32_t maximum_ping_count = ${profile.cli_defaults.ping_max_count}U;
inline constexpr std::uint16_t default_ping_payload_octets = ${profile.cli_defaults.ping_size}U;
inline constexpr std::uint16_t minimum_ping_payload_octets = ${profile.cli_defaults.ping_min_size}U;
inline constexpr std::uint16_t maximum_ping_payload_octets = ${profile.cli_defaults.ping_max_size}U;
inline constexpr std::size_t cli_history_entries = ${profile.cli_defaults.history_entries};
inline constexpr std::uint32_t runtime_snapshot_abi = ${profile.abi.runtime_snapshot};
inline constexpr std::uint32_t telemetry_abi = ${profile.abi.telemetry};
inline constexpr std::uint32_t runtime_message_abi = ${profile.abi.runtime_messages};
inline constexpr std::uint32_t checkpoint_abi = ${profile.abi.checkpoint};
inline constexpr std::uint64_t profile_hash = 0x${profileHash}ULL;
inline constexpr std::uint64_t checkpoint_schema_hash = 0x${checkpointSchemaHash}ULL;
inline constexpr std::uint64_t build_hash = 0x${buildCompatibilityHash}ULL;

// Hardware initialization values are experimental emulator timing profiles,
// not claims about physical platform boot guarantees.
inline constexpr std::chrono::milliseconds card_initialization{
    ${profile.line_card.initialization_milliseconds}};
inline constexpr std::chrono::milliseconds mda_initialization{
    ${profile.mda.initialization_milliseconds}};
inline constexpr std::chrono::milliseconds ping_timeout{
    ${profile.timing.ping_timeout_milliseconds}};
inline constexpr std::chrono::seconds arp_timeout{
    ${profile.timing.arp_timeout_seconds}};
inline constexpr std::chrono::milliseconds telemetry_interval{
    ${profile.timing.telemetry_interval_milliseconds}};
inline constexpr std::chrono::milliseconds equipment_poll_interval{
    ${profile.timing.equipment_poll_milliseconds}};
inline constexpr std::chrono::milliseconds worker_shutdown_timeout{
    ${profile.timing.worker_shutdown_milliseconds}};
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
inline constexpr std::array<bool, port_count> initial_port_admin_enabled{
    ${portIds.map((id) => initiallyEnabledPorts.has(id)).join(", ")}};
inline constexpr std::array<const char*, ${profile.mda.supported.length}> supported_mda_types{
    ${quoted(profile.mda.supported)}};
inline constexpr std::array<const char*, endpoint_count> host_ids{
    ${quoted(profile.hosts.map((host) => host.id))}};
inline constexpr std::array<const char*, endpoint_count> host_names{
    ${quoted(profile.hosts.map((host) => host.name))}};
inline constexpr std::array<const char*, endpoint_count> link_ids{
    ${quoted(links.map((link) => link.id))}};
inline constexpr std::array<std::uint8_t, endpoint_count> link_port_indices{
    ${links.map((link) => portIndex.get(link.router_port)).join(", ")}};
inline constexpr std::array<const char*, endpoint_count> interface_names{
    ${quoted(profile.router_interfaces.map((item) => item.name))}};
inline constexpr std::array<const char*, endpoint_count> interface_addresses{
    ${quoted(profile.router_interfaces.map((item) => item.address))}};
inline constexpr std::array<const char*, endpoint_count> interface_prefixes{
    ${quoted(profile.router_interfaces.map((item) => item.network))}};
inline constexpr std::array<std::uint8_t, endpoint_count> interface_port_indices{
    ${profile.router_interfaces.map((item) => portIndex.get(item.port)).join(", ")}};
inline constexpr std::array<bool, endpoint_count> initial_interface_admin_enabled{
    ${profile.router_interfaces.map((item) => item.admin_state === "enable").join(", ")}};
inline constexpr std::array<const char*, ${profile.capture_interfaces.length}> capture_interface_names{
    ${quoted(profile.capture_interfaces)}};

}  // namespace router::profile
`;

const parameterKinds = [
  "card_slot", "mda_slot", "card_type", "mda_type", "port_id",
  "interface_name", "ipv4", "ipv4_key", "ipv4_prefix", "prefix_length", "count", "size", "mtu",
  "levels", "system_name", "description"
];
for (const kind of parameterKinds) {
  const display = cliSchema.parameters?.[kind]?.display;
  const description = cliSchema.parameters?.[kind]?.description;
  if (typeof display !== "string" || !display.length ||
      typeof description !== "string" || !description.length) {
    throw new Error(`Missing CLI help metadata for parameter ${kind}`);
  }
}
// Command IDs and token counts become enum and array extents. Validate them
// before template emission so malformed YAML cannot yield partial C++ syntax.
const commandIds = new Set();
let maximumTokens = 0;
for (const command of cliSchema.commands ?? []) {
  if (!/^[a-z][a-z0-9_]*$/.test(command.id ?? "")) throw new Error(`Invalid CLI command id: ${command.id}`);
  if (commandIds.has(command.id)) throw new Error(`Duplicate CLI command id: ${command.id}`);
  commandIds.add(command.id);
  if (!command.engines?.length || command.engines.some((engine) => !["md", "classic"].includes(engine))) {
    throw new Error(`${command.id}: invalid CLI engine list`);
  }
  if (!command.tokens?.length) throw new Error(`${command.id}: empty CLI token list`);
  maximumTokens = Math.max(maximumTokens, command.tokens.length);
  for (const token of command.tokens) {
    if (typeof token !== "string" && !parameterKinds.includes(token?.parameter)) {
      throw new Error(`${command.id}: invalid CLI parameter ${token?.parameter}`);
    }
    if (typeof token === "string" &&
        typeof cliSchema.literals?.[token] !== "string") {
      throw new Error(`${command.id}: missing help description for literal ${token}`);
    }
  }
}
if (cliSchema.release !== profile.release) {
  throw new Error(`CLI schema ${cliSchema.release} does not match profile ${profile.release}`);
}

const cppToken = (token) => typeof token === "string"
  ? `{TokenKind::literal, ${cppString(token)}, ${cppString(cliSchema.literals[token])}}`
  : `{TokenKind::${token.parameter}, ${cppString(cliSchema.parameters[token.parameter].display)}, ${cppString(cliSchema.parameters[token.parameter].description)}}`;
const cliRows = cliSchema.commands.map((command) => {
  // Engine membership is a compact bit mask in generated C++. Both engines use
  // the same grammar row while retaining separate execution semantics.
  const mask = (command.engines.includes("md") ? 1 : 0) |
    (command.engines.includes("classic") ? 2 : 0);
  const tokens = command.tokens.map(cppToken);
  while (tokens.length < maximumTokens) tokens.push("{}");
  return `    {CommandId::${command.id}, ${mask}, ${command.tokens.length}, {{${tokens.join(", ")}}}, "${command.source_id}"}`;
}).join(",\n");

const cliHeader = `#pragma once

// Generated release grammar. Execution and completion consume the same rows,
// which prevents a handwritten command catalog from drifting from sources.

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
  std::string_view description{};
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

const typescript = `// Generated browser projection of the active release profile. UI, storage
// and Worker code consume these values instead of reconstructing hardware.

export const GENERATED_PROFILE = {
  id: ${JSON.stringify(profile.id)},
  release: ${JSON.stringify(profile.release)},
  chassis: ${JSON.stringify(profile.chassis)},
  chassisSlots: ${profile.chassis_slots},
  defaultSystemName: ${JSON.stringify(profile.system.default_name)},
  control: ${JSON.stringify(profile.control)},
  lineCard: ${JSON.stringify({
    slot: profile.line_card.slot,
    type: profile.line_card.type,
    initializationMs: profile.line_card.initialization_milliseconds,
    timingStatus: profile.line_card.timing_status
  })},
  mda: ${JSON.stringify({
    slot: profile.mda.slot,
    slotsPerCard: profile.mda.slots_per_card,
    modeledType: profile.mda.modeled_type,
    supportedTypes: profile.mda.supported,
    initializationMs: profile.mda.initialization_milliseconds,
    timingStatus: profile.mda.timing_status
  })},
  ports: ${JSON.stringify({
    ids: portIds,
    count: profile.ports.count,
    initiallyEnabled: profile.ports.initially_enabled,
    speedMbps: profile.ports.speed_mbps,
    defaultMtu: profile.ports.default_mtu,
    minimumMtu: profile.ports.minimum_mtu,
    maximumMtu: profile.ports.maximum_mtu
  })},
  defaultPropagationDelayNs: ${profile.link_defaults.propagation_delay_nanoseconds},
  routerInterfaces: ${JSON.stringify(profile.router_interfaces)},
  hosts: ${JSON.stringify(profile.hosts)},
  links: ${JSON.stringify(links)},
  captureInterfaces: ${JSON.stringify(profile.capture_interfaces)},
  resources: ${JSON.stringify(profile.resources)},
  timing: ${JSON.stringify(profile.timing)},
  limits: ${JSON.stringify(profile.limits)},
  cliDefaults: ${JSON.stringify(profile.cli_defaults)},
  abi: ${JSON.stringify(profile.abi)},
  uiDefaults: ${JSON.stringify(profile.ui_defaults)},
  profileHash: ${JSON.stringify(profileHash)},
  buildHash: ${JSON.stringify(buildCompatibilityHash)}
} as const;
`;

const cmake = `# Generated from ${basename(sourcePath)}. Do not edit.\nset(ROUTER_WASM_INITIAL_MEMORY ${profile.resources.wasm_initial_memory_bytes})\nset(ROUTER_RUNTIME_WORKERS ${profile.resources.runtime_worker_count})\nset(ROUTER_PTHREAD_POOL_MIN ${profile.resources.pthread_pool_min})\nset(ROUTER_PTHREAD_POOL_MAX ${profile.resources.pthread_pool_max})\n`;
const runtimeHeader = `#pragma once

// Generated runtime management protocol. Browser and C++ consume names from
// the same versioned schema instead of duplicating command prefixes.

namespace router::runtime_protocol {
inline constexpr unsigned version = ${runtimeSchema.version};
${Object.entries(runtimeSchema.operations).map(([key, value]) => `inline constexpr char ${key}[] = ${cppString(value)};`).join("\n")}
}  // namespace router::runtime_protocol
`;
const runtimeTypescript = `// Generated runtime management protocol shared by the browser bridge.\nexport const RUNTIME_PROTOCOL = ${JSON.stringify({ version: runtimeSchema.version, ...runtimeSchema.operations }, null, 2)} as const;\n`;
const outputs = [
  [headerPath, header],
  [cliHeaderPath, cliHeader],
  [typescriptPath, typescript],
  [runtimeHeaderPath, runtimeHeader],
  [runtimeTypescriptPath, runtimeTypescript],
  [cmakePath, cmake]
];
if (process.argv.includes("--check")) {
  // CI compares every generated target byte-for-byte without writing files.
  const drift = outputs.filter(([path, expected]) => readFileSync(path, "utf8") !== expected);
  if (drift.length) {
    console.error(`Generated profile drift: ${drift.map(([path]) => path).join(", ")}`);
    process.exit(1);
  }
  console.log(`generated profile valid: ${outputs.length} targets`);
} else {
  // Development generation writes only after all validation and templates have
  // completed successfully, keeping the output set internally consistent.
  for (const [path, value] of outputs) writeFileSync(path, value);
}
