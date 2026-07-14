import { readFileSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";
import { parse } from "yaml";

const root = resolve(import.meta.dirname, "..");
const sourcePath = resolve(root, "profiles/7750-sr-7-iom4-e.yaml");
const headerPath = resolve(root, "core/include/router/generated_profile.hpp");
const typescriptPath = resolve(root, "packages/contracts/src/generated-profile.ts");
const profile = parse(readFileSync(sourcePath, "utf8"));

// This generator is the only translation boundary between human-readable YAML
// and compile-time C++ or TypeScript constants. Comparing complete output makes
// a manually edited generated value fail CI instead of creating profile drift.
const ip = (value) => value.split("/")[0].split(".").map(Number);
const prefix = (value) => Number(value.split("/")[1]);
const mac = (value) => value.split(":").map((byte) => `0x${byte.toLowerCase()}`);
const networkHex = (value) => `0x${ip(value).reduce((sum, byte) => (sum * 256 + byte) >>> 0, 0).toString(16).padStart(8, "0")}U`;
const cppBytes = (values) => `{${values.join(", ")}}`;

if (profile.router_interfaces?.length !== 2 || profile.hosts?.length !== 2 ||
    profile.capture_interfaces?.length !== 9) {
  throw new Error("The first profile requires two router interfaces, two hosts and nine capture points");
}

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
inline constexpr std::size_t port_count = ${profile.ports.count};
inline constexpr std::uint32_t port_speed_mbps = ${profile.ports.speed_mbps}U;
// These delays are an emulator profile, not a claim about physical SR-7 boot
// time. The YAML marks both values experimental so UI and snapshots can expose
// their provenance without presenting them as Nokia guarantees.
inline constexpr std::chrono::milliseconds card_initialization{
    ${profile.line_card.initialization_milliseconds}};
inline constexpr std::chrono::milliseconds mda_initialization{
    ${profile.mda.initialization_milliseconds}};
// Ethernet serialization is derived from the equipped port speed. Propagation
// is a default for newly created project links and is never folded into speed.
inline constexpr std::uint64_t port_bits_per_second =
    static_cast<std::uint64_t>(port_speed_mbps) * 1000000ULL;
inline constexpr std::chrono::nanoseconds default_link_propagation{
    ${profile.link_defaults.propagation_delay_nanoseconds}};

inline constexpr std::array<packet::Mac, 2> host_macs{{
    ${cppBytes(mac(profile.hosts[0].mac))},
    ${cppBytes(mac(profile.hosts[1].mac))},
}};
inline constexpr std::array<packet::Ipv4, 2> host_addresses{{
    ${cppBytes(ip(profile.hosts[0].address))},
    ${cppBytes(ip(profile.hosts[1].address))},
}};
inline constexpr std::array<packet::Ipv4, 2> host_gateways{{
    ${cppBytes(ip(profile.hosts[0].gateway))},
    ${cppBytes(ip(profile.hosts[1].gateway))},
}};
inline constexpr std::array<std::uint8_t, 2> host_prefix_lengths{${prefix(profile.hosts[0].address)}, ${prefix(profile.hosts[1].address)}};
inline constexpr std::array<packet::Mac, 2> router_macs{{
    ${cppBytes(mac(profile.router_interfaces[0].mac))},
    ${cppBytes(mac(profile.router_interfaces[1].mac))},
}};
inline constexpr std::array<packet::Ipv4, 2> router_addresses{{
    ${cppBytes(ip(profile.router_interfaces[0].address))},
    ${cppBytes(ip(profile.router_interfaces[1].address))},
}};
inline constexpr std::array<std::uint32_t, 2> router_networks{${networkHex(profile.router_interfaces[0].network)}, ${networkHex(profile.router_interfaces[1].network)}};
inline constexpr std::array<const char*, 10> port_ids{
    "1/1/1", "1/1/2", "1/1/3", "1/1/4", "1/1/5",
    "1/1/6", "1/1/7", "1/1/8", "1/1/9", "1/1/10"};
inline constexpr std::array<const char*, 2> interface_names{"${profile.router_interfaces[0].name}", "${profile.router_interfaces[1].name}"};
inline constexpr std::array<const char*, 2> interface_addresses{
    "${profile.router_interfaces[0].address}", "${profile.router_interfaces[1].address}"};
inline constexpr std::array<const char*, 2> interface_prefixes{
    "${profile.router_interfaces[0].network}", "${profile.router_interfaces[1].network}"};
inline constexpr std::array<const char*, ${profile.capture_interfaces.length}> capture_interface_names{
    "${profile.capture_interfaces.join('", "')}"};

}  // namespace router::profile
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
  // A project persists one value per physical link. This profile value is only
  // the initial local-lab default used by new and legacy projects.
  defaultPropagationDelayNs: ${profile.link_defaults.propagation_delay_nanoseconds},
  routerInterfaces: [
    { mac: "${profile.router_interfaces[0].mac}", address: "${profile.router_interfaces[0].address}" },
    { mac: "${profile.router_interfaces[1].mac}", address: "${profile.router_interfaces[1].address}" }
  ],
  hosts: [
    { id: "${profile.hosts[0].id}", name: "${profile.hosts[0].name}", mac: "${profile.hosts[0].mac}", address: "${profile.hosts[0].address}", gateway: "${profile.hosts[0].gateway}" },
    { id: "${profile.hosts[1].id}", name: "${profile.hosts[1].name}", mac: "${profile.hosts[1].mac}", address: "${profile.hosts[1].address}", gateway: "${profile.hosts[1].gateway}" }
  ]
} as const;
`;

const outputs = [[headerPath, header], [typescriptPath, typescript]];
if (process.argv.includes("--check")) {
  const drift = outputs.filter(([path, expected]) => readFileSync(path, "utf8") !== expected);
  if (drift.length) {
    console.error(`Generated profile drift: ${drift.map(([path]) => path).join(", ")}`);
    process.exit(1);
  }
  console.log("generated profile valid: 2 targets");
} else {
  // Explicit generation is intentionally separate from normal builds. CI uses
  // check mode so verification never modifies a developer's working tree.
  for (const [path, value] of outputs) writeFileSync(path, value);
}
