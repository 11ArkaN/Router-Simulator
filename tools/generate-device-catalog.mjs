// Offline compiler for the release-scoped multi-device hardware catalog.
// The YAML file remains the only hand-maintained compatibility source. C++
// and TypeScript receive identical flattened records from this program.

import { createHash } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";
import { parse } from "yaml";

const root = resolve(import.meta.dirname, "..");
const sourcePath = resolve(root, "profiles/catalog/26.7.R1.yaml");
const typescriptPath = resolve(root, "packages/contracts/src/generated-device-catalog.ts");
const headerPath = resolve(root, "core/include/router/generated_device_catalog.hpp");
const protocolSourcePath = resolve(root, "schemas/runtime/3.yaml");
const checkpointSourcePath = resolve(root, "schemas/checkpoint/5.yaml");
const protocolHeaderPath = resolve(root, "core/include/router/generated_lab_runtime_protocol.hpp");
const protocolTypescriptPath = resolve(root, "packages/contracts/src/generated-lab-runtime-protocol.ts");
const cmakePath = resolve(root, "core/generated-device-catalog.cmake");
const catalog = parse(readFileSync(sourcePath, "utf8"));
const protocol = parse(readFileSync(protocolSourcePath, "utf8"));
const checkpoint = parse(readFileSync(checkpointSourcePath, "utf8"));

// Sorting object keys makes hashes insensitive to YAML presentation while
// retaining array order wherever field or compatibility order is semantic.
const stableJson = (value) => {
  if (Array.isArray(value)) return `[${value.map(stableJson).join(",")}]`;
  if (value && typeof value === "object") {
    return `{${Object.keys(value).sort().map((key) =>
      `${JSON.stringify(key)}:${stableJson(value[key])}`).join(",")}}`;
  }
  return JSON.stringify(value);
};
const hash64 = (value) => createHash("sha256").update(stableJson(value))
  .digest("hex").slice(0, 16);
const catalogHash = hash64(catalog);
const protocolHash = hash64(protocol);
const checkpointHash = hash64(checkpoint);
const buildHash = hash64({ catalog, protocol, checkpoint });

// All validation failures share one prefix so CI output immediately identifies
// which source compiler rejected the profile change.
const fail = (message) => { throw new Error(`Device catalog: ${message}`); };
const exactInteger = (value, name, minimum = 0) => {
  // Safe integers prevent YAML values from being rounded before they become
  // fixed-width C++ fields. The lower bound rejects negative capacities.
  if (!Number.isSafeInteger(value) || value < minimum) fail(`${name} is outside its integer range`);
  return value;
};
// Catalog strings are embedded in a C++ header. Escape both characters that
// could terminate or alter a generated string literal.
const cppString = (value) => `"${String(value).replaceAll("\\", "\\\\").replaceAll('"', '\\"')}"`;

// Release pinning is deliberate. Mixing tables from multiple releases would
// make hardware validation appear authoritative while accepting combinations
// that never existed in one SR OS image.
if (catalog.release !== "26.7.R1") fail("release must match the pinned baseline");
if (protocol.version !== 3 || !protocol.operations || checkpoint.version !== 5)
  fail("runtime protocol 3 and checkpoint schema 5 are required");
for (const [name, value] of Object.entries(catalog.limits ?? {})) exactInteger(value, `limits.${name}`, 1);
if (catalog.limits.routers !== 16 || catalog.limits.hosts !== 16 ||
    catalog.limits.links !== 64 || catalog.limits.sessions_per_router !== 4) {
  fail("laboratory limits do not match project format 3");
}
for (const [name, value] of Object.entries(catalog.runtime ?? {}))
  exactInteger(value, `runtime.${name}`, name === "low_link_shards" ? 0 : 1);
// Missing fields must fail generation instead of becoming undefined in the
// TypeScript catalog and malformed numeric tokens in the C++ projection.
for (const name of ["wasm_initial_memory_bytes", "packet_pool_bytes",
  "capture_store_bytes", "terminal_output_arena_bytes", "terminal_result_bytes",
  "runtime_control_reserve_bytes",
  "link_queue_frames", "fabric_work_budget_frames", "static_routes_per_router", "arp_entries_per_router",
  "pending_ipv4_frames_per_router", "network_command_ring_entries",
  "network_result_ring_entries", "forwarding_ring_frames",
  "low_cpu_max", "medium_cpu_max", "low_control_shards",
  "medium_control_shards", "high_control_shards", "low_forwarding_shards",
  "medium_forwarding_shards", "high_forwarding_shards", "low_link_shards",
  "medium_link_shards", "high_link_shards", "pthread_pool_low",
  "pthread_pool_medium", "pthread_pool_high", "maximum_worker_domains",
  "candidate_keys_per_router",
  "candidate_keys_per_session", "selected_capture_points",
  "capture_point_name_bytes"]) {
  if (!(name in (catalog.runtime ?? {}))) fail(`runtime.${name} is required`);
}
if (catalog.runtime.low_cpu_max >= catalog.runtime.medium_cpu_max ||
    catalog.runtime.low_link_shards !== 0 ||
    catalog.runtime.medium_link_shards !== 1 ||
    catalog.runtime.high_link_shards !== 1 ||
    catalog.runtime.pthread_pool_low !==
      catalog.runtime.low_control_shards + catalog.runtime.low_forwarding_shards - 1 ||
    catalog.runtime.pthread_pool_medium !==
      catalog.runtime.medium_control_shards + catalog.runtime.medium_forwarding_shards +
      catalog.runtime.medium_link_shards - 1 ||
    catalog.runtime.pthread_pool_high !==
      catalog.runtime.high_control_shards + catalog.runtime.high_forwarding_shards +
      catalog.runtime.high_link_shards - 1 ||
    catalog.runtime.maximum_worker_domains <
      catalog.runtime.high_control_shards + catalog.runtime.high_forwarding_shards +
      catalog.runtime.high_link_shards) {
  fail("runtime shard counts and pthread pools are inconsistent");
}
for (const [name, value] of Object.entries(catalog.ethernet ?? {}))
  exactInteger(value, `ethernet.${name}`, 1);
if (catalog.ethernet.minimum_network_mtu > catalog.ethernet.default_network_mtu ||
    catalog.ethernet.default_network_mtu > catalog.ethernet.maximum_network_mtu)
  fail("Ethernet MTU bounds do not contain the default");
for (const [name, value] of Object.entries(catalog.protocol_defaults ?? {}))
  exactInteger(value, `protocol_defaults.${name}`, 1);

const mdaEntries = Object.entries(catalog.mdas ?? {});
// Flattened indexes replace string lookup on the runtime packet and hardware
// reconciliation paths. The generator retains the readable YAML relationship.
const mdaIndex = new Map(mdaEntries.map(([name], index) => [name, index]));
let maximumPortsPerMda = 0;
for (const [name, value] of mdaEntries) {
  // Two port groups are the ABI bound selected for this release catalog. A new
  // release requiring more groups must change the schema and generated ABI.
  if (typeof value.ethernet !== "boolean" || !Array.isArray(value.ports) || value.ports.length > 2)
    fail(`${name} has an invalid port group definition`);
  let ports = 0;
  for (const [index, group] of value.ports.entries()) {
    ports += exactInteger(group.count, `${name}.ports[${index}].count`, 1);
    if (!Array.isArray(group.speeds_mbps) || !group.speeds_mbps.length || group.speeds_mbps.length > 2)
      fail(`${name}.ports[${index}] requires one or two speeds`);
    for (const speed of group.speeds_mbps) exactInteger(speed, `${name}.ports[${index}].speed`, 1);
  }
  if (value.ethernet !== (ports > 0)) fail(`${name} ethernet flag conflicts with its ports`);
  if (ports > 255) fail(`${name} exceeds the bounded port index`);
  maximumPortsPerMda = Math.max(maximumPortsPerMda, ports);
}

const profileIds = new Set();
const flatCards = [];
const flatCardMdas = [];
const profileMaximumPorts = new Map();
let maximumMdaSlotsPerCard = 0;
for (const profile of catalog.profiles ?? []) {
  // Validate every relationship before emitting either target. This makes the
  // generation operation all-or-nothing from the caller's perspective.
  if (!profile.id || profileIds.has(profile.id)) fail(`duplicate or empty profile ID ${profile.id}`);
  profileIds.add(profile.id);
  exactInteger(profile.card_slots, `${profile.id}.card_slots`);
  if (profile.fixed !== (profile.card_slots === 0)) fail(`${profile.id} fixed flag conflicts with card slots`);
  if (!Array.isArray(profile.control?.types) || !profile.control.types.length)
    fail(`${profile.id} requires a control card type`);
  if (!Array.isArray(profile.cards) || !profile.cards.length) fail(`${profile.id} requires card records`);
  for (const card of profile.cards) {
    exactInteger(card.mda_slots, `${profile.id}.${card.type}.mda_slots`, 1);
    maximumMdaSlotsPerCard = Math.max(maximumMdaSlotsPerCard, card.mda_slots);
    if (!Array.isArray(card.mdas) || !card.mdas.length) fail(`${profile.id}.${card.type} requires MDA records`);
    const firstMda = flatCardMdas.length;
    for (const mda of card.mdas) {
      // Store a compact index rather than duplicating an MDA name in every card
      // compatibility row. Both generated languages then use the same order.
      if (!mdaIndex.has(mda)) fail(`${profile.id}.${card.type} references unknown MDA ${mda}`);
      flatCardMdas.push(mdaIndex.get(mda));
    }
    flatCards.push({ profile: profile.id, type: card.type, fixed: Boolean(card.fixed),
      mdaSlots: card.mda_slots, firstMda, mdaCount: card.mdas.length });
  }
  // Compute the largest compatible inventory rather than sizing arenas from
  // the starter hardware. Modular users may equip any documented combination.
  const maximumCardPorts = Math.max(...profile.cards.map((card) =>
    card.mda_slots * Math.max(...card.mdas.map((mda) =>
      mdaEntries[mdaIndex.get(mda)][1].ports.reduce(
        (sum, group) => sum + group.count, 0)))));
  profileMaximumPorts.set(profile.id,
    maximumCardPorts * (profile.fixed ? 1 : profile.card_slots));
  const defaultCard = profile.cards.find((card) => card.type === profile.default_hardware?.card);
  if (!defaultCard) fail(`${profile.id} default card is not compatible`);
  if (!Array.isArray(profile.default_hardware.mdas) ||
      profile.default_hardware.mdas.length > defaultCard.mda_slots ||
      profile.default_hardware.mdas.some((mda) => !defaultCard.mdas.includes(mda))) {
    fail(`${profile.id} default MDA set is not compatible with its card`);
  }
}
// The catalog is extensible. Runtime code needs at least one fixed and one
// modular platform to exercise both inventory lifecycles, but this generator
// must not carry a second hardcoded list of product identities.
if (!catalog.profiles.some((profile) => profile.fixed) ||
    !catalog.profiles.some((profile) => !profile.fixed))
  fail("the catalog requires fixed and modular hardware profiles");
const maximumPortsPerRouter = Math.max(...profileMaximumPorts.values());
const maximumCardSlots = Math.max(...catalog.profiles.map((profile) =>
  profile.fixed ? 1 : profile.card_slots));

const ts = `// Generated from profiles/catalog/26.7.R1.yaml. Do not edit.\n` +
`// Runtime and UI code use this catalog instead of chassis-specific branches.\n\n` +
`export const PROFILE_CATALOG = ${JSON.stringify(catalog, null, 2)} as const;\n` +
`export const PROFILE_CATALOG_COMPILED = ${JSON.stringify({
  maximumPortsPerRouter,
  maximumCardSlots,
  maximumMdaSlotsPerCard,
  maximumPortsPerMda
}, null, 2)} as const;\n` +
`export const PROFILE_CATALOG_HASH = ${JSON.stringify(catalogHash)} as const;\n` +
`export const LAB_BUILD_HASH = ${JSON.stringify(buildHash)} as const;\n`;

const mdaRows = mdaEntries.map(([name, value]) => {
  // Pad variable YAML groups to the fixed C++ layout. Zero-count groups are
  // inert and let the runtime traverse the array without heap allocation.
  const groups = [...value.ports, ...Array(2 - value.ports.length).fill({ count: 0, speeds_mbps: [] })];
  const portCount = value.ports.reduce((sum, group) => sum + group.count, 0);
  const groupText = groups.map((group) => {
    const speeds = [...(group.speeds_mbps ?? []), 0, 0].slice(0, 2);
    return `{${group.count ?? 0}, {{${speeds[0]}U, ${speeds[1]}U}}}`;
  }).join(", ");
  // std::array is an aggregate nested inside MdaProfile. The extra brace pair
  // initializes the array's backing C array rather than treating the second
  // PortGroup as an excess MdaProfile field on Clang and MSVC.
  return `    {${cppString(name)}, ${value.ethernet}, ${portCount}, ${value.ports.length}, {{${groupText}}}}`;
}).join(",\n");
const cardRows = flatCards.map((card) =>
  `    {${cppString(card.profile)}, ${cppString(card.type)}, ${card.fixed}, ${card.mdaSlots}, ${card.firstMda}, ${card.mdaCount}}`).join(",\n");
const cardMdaRows = flatCardMdas.map((index) => `${index}U`).join(", ");
let cardCursor = 0;
const profileRows = catalog.profiles.map((profile) => {
  // firstCard plus card_count defines a contiguous view into flatCards. This
  // avoids a pointer-rich graph in shared WebAssembly memory.
  const firstCard = cardCursor;
  cardCursor += profile.cards.length;
  const defaults = [...profile.default_hardware.mdas, "", ""].slice(0, 2);
  return `    {${cppString(profile.id)}, ${cppString(profile.chassis)}, ${cppString(catalog.release)}, ${profile.fixed}, ${profile.card_slots}, ${firstCard}, ${profile.cards.length}, ${cppString(profile.control.slot)}, ${cppString(profile.control.types[0])}, ${cppString(profile.default_hardware.card)}, {${cppString(defaults[0])}, ${cppString(defaults[1])}}, ${profileMaximumPorts.get(profile.id)}}`;
}).join(",\n");

const header = `#pragma once

// Generated release hardware catalog. The records contain only immutable
// profile metadata. Device registries own all selected and operational state.

#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <string_view>

namespace router::device_catalog {

// One release owns this entire generated catalog. Runtime capability output
// consumes this value instead of repeating the release pin in hand-written C++.
inline constexpr std::string_view release{${cppString(catalog.release)}};
inline constexpr std::uint64_t catalog_hash = 0x${catalogHash}ULL;
inline constexpr std::uint64_t checkpoint_schema_hash = 0x${checkpointHash}ULL;
inline constexpr std::uint64_t runtime_protocol_hash = 0x${protocolHash}ULL;
inline constexpr std::uint64_t build_hash = 0x${buildHash}ULL;

inline constexpr std::size_t maximum_routers = ${catalog.limits.routers};
inline constexpr std::size_t maximum_hosts = ${catalog.limits.hosts};
inline constexpr std::size_t maximum_links = ${catalog.limits.links};
inline constexpr std::size_t maximum_sessions_per_router = ${catalog.limits.sessions_per_router};
inline constexpr std::size_t maximum_ports_per_router = ${maximumPortsPerRouter};
inline constexpr std::size_t maximum_card_slots = ${maximumCardSlots};
inline constexpr std::size_t maximum_mda_slots_per_card = ${maximumMdaSlotsPerCard};
inline constexpr std::size_t maximum_ports_per_mda = ${maximumPortsPerMda};
inline constexpr std::size_t maximum_static_routes_per_router = ${catalog.runtime.static_routes_per_router};
inline constexpr std::size_t maximum_fib_routes_per_router =
    maximum_ports_per_router + maximum_static_routes_per_router;
inline constexpr std::size_t wasm_initial_memory_bytes = ${catalog.runtime.wasm_initial_memory_bytes}U;
inline constexpr std::size_t wasm_stack_bytes = ${catalog.runtime.wasm_stack_bytes}U;
inline constexpr std::size_t packet_pool_bytes = ${catalog.runtime.packet_pool_bytes}U;
inline constexpr std::size_t capture_store_bytes = ${catalog.runtime.capture_store_bytes}U;
inline constexpr std::size_t terminal_output_arena_bytes = ${catalog.runtime.terminal_output_arena_bytes}U;
inline constexpr std::size_t terminal_result_bytes = ${catalog.runtime.terminal_result_bytes}U;
inline constexpr std::size_t runtime_control_reserve_bytes = ${catalog.runtime.runtime_control_reserve_bytes}U;
inline constexpr std::size_t low_cpu_max = ${catalog.runtime.low_cpu_max};
inline constexpr std::size_t medium_cpu_max = ${catalog.runtime.medium_cpu_max};
inline constexpr std::size_t low_control_shards = ${catalog.runtime.low_control_shards};
inline constexpr std::size_t medium_control_shards = ${catalog.runtime.medium_control_shards};
inline constexpr std::size_t high_control_shards = ${catalog.runtime.high_control_shards};
inline constexpr std::size_t low_forwarding_shards = ${catalog.runtime.low_forwarding_shards};
inline constexpr std::size_t medium_forwarding_shards = ${catalog.runtime.medium_forwarding_shards};
inline constexpr std::size_t high_forwarding_shards = ${catalog.runtime.high_forwarding_shards};
inline constexpr std::size_t low_link_shards = ${catalog.runtime.low_link_shards};
inline constexpr std::size_t medium_link_shards = ${catalog.runtime.medium_link_shards};
inline constexpr std::size_t high_link_shards = ${catalog.runtime.high_link_shards};
inline constexpr std::size_t maximum_worker_domains = ${catalog.runtime.maximum_worker_domains};
inline constexpr std::size_t worker_startup_attempts = ${catalog.runtime.worker_startup_attempts};
inline constexpr std::chrono::milliseconds worker_startup_poll{
    ${catalog.runtime.worker_startup_poll_milliseconds}};
inline constexpr std::chrono::milliseconds telemetry_publish_interval{
    ${catalog.runtime.telemetry_publish_interval_milliseconds}};
inline constexpr std::size_t link_queue_capacity = ${catalog.runtime.link_queue_frames};
inline constexpr std::size_t fabric_work_budget_frames = ${catalog.runtime.fabric_work_budget_frames};
inline constexpr std::size_t arp_entries_per_router = ${catalog.runtime.arp_entries_per_router};
inline constexpr std::size_t pending_ipv4_frames_per_router = ${catalog.runtime.pending_ipv4_frames_per_router};
inline constexpr std::size_t network_command_ring_entries = ${catalog.runtime.network_command_ring_entries};
inline constexpr std::size_t network_result_ring_entries = ${catalog.runtime.network_result_ring_entries};
inline constexpr std::size_t forwarding_ring_frames = ${catalog.runtime.forwarding_ring_frames};
inline constexpr std::size_t candidate_keys_per_router = ${catalog.runtime.candidate_keys_per_router};
inline constexpr std::size_t candidate_keys_per_session = ${catalog.runtime.candidate_keys_per_session};
inline constexpr std::size_t selected_capture_points = ${catalog.runtime.selected_capture_points};
inline constexpr std::size_t capture_point_name_bytes = ${catalog.runtime.capture_point_name_bytes};
inline constexpr std::uint16_t default_network_mtu = ${catalog.ethernet.default_network_mtu};
inline constexpr std::uint16_t minimum_network_mtu = ${catalog.ethernet.minimum_network_mtu};
inline constexpr std::uint16_t maximum_network_mtu = ${catalog.ethernet.maximum_network_mtu};
inline constexpr std::uint16_t minimum_host_ipv4_mtu = ${catalog.ethernet.minimum_host_ipv4_mtu};
inline constexpr std::uint16_t default_host_ipv4_mtu = ${catalog.ethernet.default_host_ipv4_mtu};
inline constexpr std::chrono::seconds dynamic_arp_timeout{
    ${catalog.protocol_defaults.dynamic_arp_timeout_seconds}};
inline constexpr std::size_t default_ping_payload_octets =
    ${catalog.protocol_defaults.ping_payload_octets};
inline constexpr std::size_t minimum_ping_payload_octets =
    ${catalog.protocol_defaults.ping_minimum_payload_octets};
inline constexpr std::size_t maximum_ping_payload_octets =
    ${catalog.protocol_defaults.ping_maximum_payload_octets};
inline constexpr std::uint32_t maximum_ping_count =
    ${catalog.protocol_defaults.ping_maximum_count}U;
inline constexpr std::chrono::milliseconds ping_interval{
    ${catalog.protocol_defaults.ping_interval_milliseconds}};
inline constexpr std::chrono::milliseconds ping_timeout{
    ${catalog.protocol_defaults.ping_timeout_milliseconds}};

struct PortGroup {
  std::uint8_t count{};
  std::array<std::uint32_t, 2> speeds_mbps{};
};

struct MdaProfile {
  std::string_view type;
  bool ethernet{};
  std::uint8_t port_count{};
  std::uint8_t group_count{};
  std::array<PortGroup, 2> groups{};
};

struct CardProfile {
  std::string_view device_profile;
  std::string_view type;
  bool fixed{};
  std::uint8_t mda_slots{};
  std::uint16_t first_mda{};
  std::uint16_t mda_count{};
};

struct DeviceProfile {
  std::string_view id;
  std::string_view chassis;
  std::string_view release;
  bool fixed{};
  std::uint8_t card_slots{};
  std::uint16_t first_card{};
  std::uint16_t card_count{};
  std::string_view control_slot;
  std::string_view control_type;
  std::string_view default_card;
  std::array<std::string_view, 2> default_mdas{};
  std::uint16_t maximum_ports{};
};

inline constexpr std::array<MdaProfile, ${mdaEntries.length}> mdas{{
${mdaRows}
}};

inline constexpr std::array<std::uint16_t, ${flatCardMdas.length}> card_mdas{{
    ${cardMdaRows}
}};

inline constexpr std::array<CardProfile, ${flatCards.length}> cards{{
${cardRows}
}};

inline constexpr std::array<DeviceProfile, ${catalog.profiles.length}> profiles{{
${profileRows}
}};

[[nodiscard]] constexpr const DeviceProfile *find_profile(std::string_view id) noexcept {
  // Bounded generated records are cheaper and easier to validate than a mutable
  // hash index. The returned pointer targets immutable process-lifetime data.
  for (const auto &profile : profiles)
    if (profile.id == id)
      return &profile;
  return nullptr;
}

[[nodiscard]] constexpr const MdaProfile *find_mda(std::string_view type) noexcept {
  // Hardware edits run on the control shard, so a bounded catalog scan keeps
  // the generated representation compact without affecting packet throughput.
  for (const auto &mda : mdas)
    if (mda.type == type)
      return &mda;
  return nullptr;
}

[[nodiscard]] constexpr const CardProfile *
find_card(const DeviceProfile &profile, std::string_view type) noexcept {
  // Cards for a profile occupy one contiguous generated range. Restricting the
  // scan to that range prevents a same-named card from another chassis profile
  // from becoming compatible accidentally.
  for (std::size_t offset = 0; offset < profile.card_count; ++offset) {
    const auto &card = cards[profile.first_card + offset];
    if (card.type == type)
      return &card;
  }
  return nullptr;
}

[[nodiscard]] constexpr bool card_supports_mda(
    const CardProfile &card, std::string_view type) noexcept {
  // card_mdas stores indexes into immutable MDA records. The compact relation
  // is evaluated on hardware edits, never per forwarded packet.
  for (std::size_t offset = 0; offset < card.mda_count; ++offset)
    if (mdas[card_mdas[card.first_mda + offset]].type == type)
      return true;
  return false;
}

} // namespace router::device_catalog
`;

const protocolHeader = `#pragma once

// Generated protocol 3 operation identities. Payload fields use netstrings;
// packet bytes and mutable runtime addresses never cross this text boundary.

#include <string_view>

namespace router::lab_runtime_protocol {
inline constexpr unsigned version = ${protocol.version};
${Object.entries(protocol.operations).map(([name, value]) =>
  `inline constexpr std::string_view ${name}{${cppString(value)}};`).join("\n")}
} // namespace router::lab_runtime_protocol
`;
const protocolTypescript = `// Generated browser names for runtime protocol 3.\n` +
`export const LAB_RUNTIME_PROTOCOL = ${JSON.stringify({ version: protocol.version,
  snapshotAbi: checkpoint.version,
  ...protocol.operations }, null, 2)} as const;\n`;
const cmake = `# Generated from profiles/catalog/26.7.R1.yaml. Do not edit.\n` +
  `set(ROUTER_WASM_STACK_BYTES ${catalog.runtime.wasm_stack_bytes})\n` +
  `set(ROUTER_LOGICAL_CPU_LOW_MAX ${catalog.runtime.low_cpu_max})\n` +
  `set(ROUTER_LOGICAL_CPU_MEDIUM_MAX ${catalog.runtime.medium_cpu_max})\n` +
  `set(ROUTER_PTHREAD_POOL_LOW ${catalog.runtime.pthread_pool_low})\n` +
  `set(ROUTER_PTHREAD_POOL_MEDIUM ${catalog.runtime.pthread_pool_medium})\n` +
  `set(ROUTER_PTHREAD_POOL_HIGH ${catalog.runtime.pthread_pool_high})\n`;

const outputs = [[typescriptPath, ts], [headerPath, header],
  [protocolHeaderPath, protocolHeader], [protocolTypescriptPath, protocolTypescript],
  [cmakePath, cmake]];
if (process.argv.includes("--check")) {
  // Check mode never writes. It compares exact bytes so formatting drift and
  // semantic drift are detected by the same CI command.
  const drift = outputs.filter(([path, expected]) => readFileSync(path, "utf8") !== expected);
  if (drift.length) {
    console.error(`Generated device catalog drift: ${drift.map(([path]) => path).join(", ")}`);
    process.exit(1);
  }
  console.log(`generated device catalog valid: ${outputs.length} targets`);
} else {
  // Validation has completed for the entire catalog before either file is
  // replaced, preventing one target from being generated from invalid input.
  for (const [path, value] of outputs) writeFileSync(path, value);
}
