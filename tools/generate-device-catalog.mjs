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
const protocolSourcePath = resolve(root, "schemas/runtime/4.yaml");
const checkpointSourcePath = resolve(root, "schemas/checkpoint/6.yaml");
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
const cppBoolean = (value) => value ? "true" : "false";

// Release pinning is deliberate. Mixing tables from multiple releases would
// make hardware validation appear authoritative while accepting combinations
// that never existed in one SR OS image.
if (catalog.release !== "26.7.R1") fail("release must match the pinned baseline");
if (protocol.version !== 4 || protocol.snapshot_abi !== 6 ||
    !protocol.operations || checkpoint.version !== 6)
  fail("runtime protocol 4, snapshot ABI 6 and checkpoint schema 6 are required");
for (const [name, value] of Object.entries(catalog.limits ?? {})) exactInteger(value, `limits.${name}`, 1);
if (catalog.limits.routers !== 16 || catalog.limits.hosts !== 16 ||
    catalog.limits.links !== 64 || catalog.limits.sessions_per_router !== 4) {
  fail("laboratory limits do not match project format 4");
}
for (const [name, value] of Object.entries(catalog.runtime ?? {}))
  exactInteger(value, `runtime.${name}`, name === "low_link_shards" ? 0 : 1);
// Missing fields must fail generation instead of becoming undefined in the
// TypeScript catalog and malformed numeric tokens in the C++ projection.
for (const name of ["wasm_initial_memory_bytes", "wasm_maximum_memory_bytes",
  "wasm_growth_step_bytes", "packet_pool_bytes",
  "terminal_output_arena_bytes", "terminal_result_bytes",
  "runtime_control_reserve_bytes",
  "recovery_checkpoint_interval_milliseconds",
  "continuity_loss_threshold_milliseconds",
  "link_queue_frames", "fabric_work_budget_frames", "static_routes_per_router", "maximum_ecmp_paths", "arp_entries_per_router",
  "static_arp_entries_per_router",
  "pending_ipv4_frames_per_router", "ipv6_neighbor_entries_per_router",
  "ipv6_destination_entries_per_endpoint",
  "icmp6_redirect_default_maximum",
  "icmp6_redirect_default_interval_seconds",
  "icmp6_redirect_minimum_maximum",
  "icmp6_redirect_maximum_maximum",
  "icmp6_redirect_minimum_interval_seconds",
  "icmp6_redirect_maximum_interval_seconds",
  "icmp_redirect_default_maximum",
  "icmp_redirect_default_interval_seconds",
  "icmp_redirect_minimum_maximum",
  "icmp_redirect_maximum_maximum",
  "icmp_redirect_minimum_interval_seconds",
  "icmp_redirect_maximum_interval_seconds",
  "ipv6_dad_entries_per_node",
  "network_interface_ip_addresses",
  "pending_ipv6_frames_per_router", "ipv4_reassembly_entries_per_endpoint",
  "ipv4_reassembly_timeout_seconds", "ipv6_reassembly_entries_per_endpoint",
  "ipv6_reassembly_timeout_seconds", "pending_l3_frames_per_router",
  "ipv4_pmtu_entries_per_endpoint", "ipv4_pmtu_probe_interval_seconds",
  "ipv4_pmtu_probe_retry_interval_seconds",
  "ipv6_pmtu_entries_per_endpoint", "ipv6_pmtu_probe_interval_seconds",
  "udp_queued_datagrams_per_endpoint",
  "udp_datagrams_per_socket", "udp_receive_buffer_bytes_per_endpoint",
  "udp_receive_block_bytes", "udp_ephemeral_port_first",
  "udp_ephemeral_port_last", "tcp_send_buffer_default_bytes",
  "tcp_receive_buffer_default_bytes", "tcp_transmission_records_default",
  "tcp_sack_ranges_default", "tcp_listen_backlog_default",
  "tcp_ephemeral_port_first", "tcp_ephemeral_port_last",
  "dns_cache_default_bytes",
  "dns_resolver_advertised_udp_payload_bytes",
  "dns_resolver_retry_milliseconds",
  "dns_resolver_attempts_per_server",
  "dns_resolver_max_minimise_count",
  "dns_resolver_minimise_one_label_count",
  "dns_resolver_max_alias_hops",
  "dhcpv6_address_pools_per_server", "dhcpv6_prefix_pools_per_server",
  "dhcpv6_leases_per_server", "dhcpv6_relay_servers_per_interface",
  "dhcpv6_zero_t1_percent_of_preferred",
  "dhcpv6_zero_t2_percent_of_preferred", "dhcpv6_client_rate_limit_packets",
  "dhcpv6_client_rate_limit_interval_seconds",
  "ipv6_ra_prefixes_per_interface", "ipv6_rdnss_servers_per_interface",
  "ipv6_default_routers_per_host_interface", "ipv6_on_link_prefixes_per_host_interface",
  "ipv6_slaac_addresses_per_host_interface", "ipv6_rdnss_entries_per_host_interface",
  "ipv6_stable_iid_network_id_octets",
  "host_ipv6_work_budget_actions",
  "mld_groups_per_interface", "mld_sources_per_group",
  "mld_records_per_report", "mld_work_budget_actions",
  "mld_router_groups_per_interface", "mld_router_sources_per_group",
  "mld_router_group_sources_per_interface",
  "nd_work_budget_actions", "network_command_ring_entries",
  "network_result_ring_entries", "network_command_work_budget",
  "immediate_link_deadline_nanoseconds",
  "forwarding_ring_frames",
  "low_cpu_max", "medium_cpu_max", "low_control_shards",
  "medium_control_shards", "high_control_shards", "low_forwarding_shards",
  "medium_forwarding_shards", "high_forwarding_shards", "low_link_shards",
  "medium_link_shards", "high_link_shards", "pthread_pool_low",
  "pthread_pool_medium", "pthread_pool_high", "maximum_worker_domains",
  "candidate_keys_per_router",
  "candidate_keys_per_session", "maximum_active_capture_points",
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
if (catalog.runtime.recovery_checkpoint_interval_milliseconds <
      catalog.runtime.telemetry_publish_interval_milliseconds ||
    catalog.runtime.continuity_loss_threshold_milliseconds <=
      catalog.runtime.recovery_checkpoint_interval_milliseconds) {
  // A recovery image cannot be requested more frequently than the Worker
  // supervision turn, and at least one complete image must be possible before
  // an event-loop gap is classified as lost continuity.
  fail("runtime continuity recovery intervals are inconsistent");
}
if (catalog.runtime.dhcpv6_zero_t1_percent_of_preferred >=
      catalog.runtime.dhcpv6_zero_t2_percent_of_preferred ||
    catalog.runtime.dhcpv6_zero_t2_percent_of_preferred > 100) {
  fail("DHCPv6 zero T1/T2 policy must be ordered percentages at or below 100");
}
if (catalog.runtime.dhcpv6_client_rate_limit_packets < 1 ||
    catalog.runtime.dhcpv6_client_rate_limit_interval_seconds < 1 ||
    catalog.runtime.dhcpv6_client_rate_limit_packets > 65535 ||
    catalog.runtime.dhcpv6_client_rate_limit_interval_seconds > 86400) {
  fail("DHCPv6 client rate limit must fit the bounded per-interface token bucket");
}
if (catalog.runtime.ipv4_reassembly_entries_per_endpoint < 1 ||
    catalog.runtime.ipv4_reassembly_timeout_seconds < 60 ||
    catalog.runtime.ipv4_reassembly_timeout_seconds > 120) {
  fail("IPv4 reassembly requires a positive table and the RFC 1122 timeout range");
}
if (catalog.runtime.icmp6_redirect_minimum_maximum >
      catalog.runtime.icmp6_redirect_default_maximum ||
    catalog.runtime.icmp6_redirect_default_maximum >
      catalog.runtime.icmp6_redirect_maximum_maximum ||
    catalog.runtime.icmp6_redirect_minimum_interval_seconds >
      catalog.runtime.icmp6_redirect_default_interval_seconds ||
    catalog.runtime.icmp6_redirect_default_interval_seconds >
      catalog.runtime.icmp6_redirect_maximum_interval_seconds) {
  fail("ICMPv6 Redirect defaults are outside the SR OS release command ranges");
}
if (catalog.runtime.icmp_redirect_minimum_maximum >
      catalog.runtime.icmp_redirect_default_maximum ||
    catalog.runtime.icmp_redirect_default_maximum >
      catalog.runtime.icmp_redirect_maximum_maximum ||
    catalog.runtime.icmp_redirect_minimum_interval_seconds >
      catalog.runtime.icmp_redirect_default_interval_seconds ||
    catalog.runtime.icmp_redirect_default_interval_seconds >
      catalog.runtime.icmp_redirect_maximum_interval_seconds) {
  fail("ICMP Redirect defaults are outside the SR OS release command ranges");
}
if (catalog.runtime.udp_receive_buffer_bytes_per_endpoint %
      catalog.runtime.udp_receive_block_bytes !== 0 ||
    catalog.runtime.udp_queued_datagrams_per_endpoint >
      catalog.runtime.udp_receive_buffer_bytes_per_endpoint /
        catalog.runtime.udp_receive_block_bytes ||
    catalog.runtime.udp_datagrams_per_socket >
      catalog.runtime.udp_queued_datagrams_per_endpoint ||
    catalog.runtime.udp_ephemeral_port_first >
      catalog.runtime.udp_ephemeral_port_last ||
    catalog.runtime.udp_ephemeral_port_first === 0 ||
    catalog.runtime.udp_ephemeral_port_last > 65535) {
  fail("UDP receive pool and ephemeral port bounds are inconsistent");
}
if (catalog.runtime.tcp_send_buffer_default_bytes < 1 ||
    catalog.runtime.tcp_send_buffer_default_bytes > 0x40000000 ||
    catalog.runtime.tcp_receive_buffer_default_bytes < 1 ||
    catalog.runtime.tcp_receive_buffer_default_bytes > 0x40000000 ||
    catalog.runtime.tcp_transmission_records_default < 1 ||
    catalog.runtime.tcp_sack_ranges_default < 1 ||
    catalog.runtime.tcp_listen_backlog_default < 1 ||
    catalog.runtime.tcp_ephemeral_port_first < 1 ||
    catalog.runtime.tcp_ephemeral_port_first >
      catalog.runtime.tcp_ephemeral_port_last ||
    catalog.runtime.tcp_ephemeral_port_last > 65535) {
  fail("TCP socket resource defaults and ephemeral ports are inconsistent");
}
for (const [name, value] of Object.entries(catalog.ethernet ?? {}))
  exactInteger(value, `ethernet.${name}`, 1);
if (catalog.ethernet.minimum_network_mtu > catalog.ethernet.default_network_mtu ||
    catalog.ethernet.default_network_mtu > catalog.ethernet.maximum_network_mtu)
  fail("Ethernet MTU bounds do not contain the default");
// TLS profile scale and algorithm names are vendor release data. Validating
// the complete table before generation prevents a CLI token from reaching a
// different OpenSSL spelling than the runtime profile resolver uses.
for (const name of ["maximum_cert_profiles", "maximum_client_cipher_lists",
  "maximum_client_group_lists", "maximum_client_signature_lists",
  "maximum_client_tls_profiles", "maximum_server_cipher_lists",
  "maximum_server_group_lists", "maximum_server_signature_lists",
  "maximum_server_tls_profiles", "maximum_trust_anchor_profiles",
  "maximum_cert_entries_per_profile", "maximum_trust_anchors_per_profile",
  "profile_name_bytes", "certificate_file_name_bytes",
  "algorithm_index_minimum", "algorithm_index_maximum"])
  exactInteger(catalog.tls?.[name], `tls.${name}`, 1);
if (catalog.tls.algorithm_index_minimum !== 1 ||
    catalog.tls.algorithm_index_maximum !== 255 ||
    catalog.tls.maximum_cert_entries_per_profile !== 8 ||
    catalog.tls.maximum_trust_anchors_per_profile !== 8 ||
    catalog.tls.profile_name_bytes !== 32 ||
    catalog.tls.certificate_file_name_bytes !== 95) {
  fail("TLS list keys and name dimensions do not match SR OS 26.7.R1");
}
for (const name of ["maximum_cert_profiles", "maximum_client_cipher_lists",
  "maximum_client_group_lists", "maximum_client_signature_lists",
  "maximum_client_tls_profiles", "maximum_server_cipher_lists",
  "maximum_server_group_lists", "maximum_server_signature_lists",
  "maximum_server_tls_profiles", "maximum_trust_anchor_profiles"])
  if (catalog.tls[name] !== 16) fail(`tls.${name} must match the release limit`);
const validateTlsAlgorithms = (items, name) => {
  if (!Array.isArray(items) || !items.length) fail(`tls.${name} is empty`);
  const sros = new Set();
  const openssl = new Set();
  for (const [index, item] of items.entries()) {
    if (!item || typeof item.sros !== "string" || !item.sros.length ||
        typeof item.openssl !== "string" || !item.openssl.length ||
        typeof item.pqc !== "boolean")
      fail(`tls.${name}[${index}] is malformed`);
    if (sros.has(item.sros) || openssl.has(item.openssl))
      fail(`tls.${name}[${index}] duplicates an algorithm`);
    sros.add(item.sros);
    openssl.add(item.openssl);
  }
};
validateTlsAlgorithms(catalog.tls.tls13_ciphers, "tls13_ciphers");
validateTlsAlgorithms(catalog.tls.tls13_groups, "tls13_groups");
validateTlsAlgorithms(catalog.tls.tls13_signatures, "tls13_signatures");
if (catalog.tls.default_admin_state !== "disable" ||
    catalog.tls.default_protocol_version !== "tls-version-12" ||
    catalog.tls.default_status_result !== "revoked" ||
    catalog.tls.default_revocation_primary !== "crl" ||
    catalog.tls.default_revocation_secondary !== "none")
  fail("TLS defaults do not match SR OS 26.7.R1");
for (const [name, value] of Object.entries(catalog.protocol_defaults ?? {})) {
  // SR OS deliberately assigns zero to ARP timeout as the disable-aging
  // value. Every other generated protocol scalar remains strictly positive.
  const minimum = name === "arp_timeout_minimum_seconds" ? 0 : 1;
  exactInteger(value, `protocol_defaults.${name}`, minimum);
}
if (catalog.protocol_defaults.arp_timeout_minimum_seconds !== 0 ||
    catalog.protocol_defaults.dynamic_arp_timeout_seconds >
      catalog.protocol_defaults.arp_timeout_maximum_seconds ||
    catalog.protocol_defaults.dynamic_arp_retry_deciseconds <
      catalog.protocol_defaults.arp_retry_minimum_deciseconds ||
    catalog.protocol_defaults.dynamic_arp_retry_deciseconds >
      catalog.protocol_defaults.arp_retry_maximum_deciseconds) {
  fail("ARP defaults are outside the SR OS 26.7.R1 command ranges");
}
if (catalog.protocol_defaults.tcp_rto_initial_milliseconds <
      catalog.protocol_defaults.tcp_rto_minimum_milliseconds ||
    catalog.protocol_defaults.tcp_rto_initial_milliseconds >
      catalog.protocol_defaults.tcp_rto_maximum_milliseconds ||
    catalog.protocol_defaults.tcp_rto_minimum_milliseconds !== 1000 ||
    catalog.protocol_defaults.tcp_rto_maximum_milliseconds < 60000 ||
    catalog.protocol_defaults.tcp_rto_clock_granularity_milliseconds > 100 ||
    catalog.protocol_defaults.tcp_rto_after_syn_retransmission_milliseconds <
      3000) {
  fail("TCP retransmission defaults violate RFC 6298 bounds");
}
if (catalog.protocol_defaults.tcp_delayed_ack_milliseconds >= 500 ||
    catalog.protocol_defaults.tcp_sws_override_milliseconds < 100 ||
    catalog.protocol_defaults.tcp_sws_override_milliseconds > 1000 ||
    catalog.protocol_defaults.tcp_persist_maximum_milliseconds <
      catalog.protocol_defaults.tcp_rto_initial_milliseconds) {
  fail("TCP delayed ACK, SWS or persist defaults violate RFC 1122 bounds");
}
if (catalog.protocol_defaults.tcp_failure_r1_retransmissions < 3 ||
    catalog.protocol_defaults.tcp_failure_data_r2_seconds < 100 ||
    catalog.protocol_defaults.tcp_failure_syn_r2_seconds < 180) {
  // These are the RFC 9293 SHLD-10, SHLD-11 and MUST-23 floors. Keeping the
  // validation beside generation prevents C++, TypeScript and tests from
  // silently consuming a profile that closes conforming connections early.
  fail("TCP connection-failure policy violates RFC 9293 bounds");
}
if (catalog.protocol_defaults.nd_minimum_reachable_time_seconds >
      catalog.protocol_defaults.nd_default_reachable_time_seconds ||
    catalog.protocol_defaults.nd_default_reachable_time_seconds >
      catalog.protocol_defaults.nd_maximum_reachable_time_seconds ||
    catalog.protocol_defaults.nd_minimum_stale_time_seconds >
      catalog.protocol_defaults.nd_default_stale_time_seconds ||
    catalog.protocol_defaults.nd_default_stale_time_seconds >
      catalog.protocol_defaults.nd_maximum_stale_time_seconds ||
    catalog.protocol_defaults.nd_maximum_neighbor_limit !==
      catalog.runtime.ipv6_neighbor_entries_per_router ||
    !Number.isSafeInteger(
      catalog.protocol_defaults.nd_reachable_time_recalculation_seconds) ||
    catalog.protocol_defaults.nd_reachable_time_recalculation_seconds <= 0 ||
    catalog.protocol_defaults.nd_default_neighbor_limit_threshold_percent < 1 ||
    catalog.protocol_defaults.nd_default_neighbor_limit_threshold_percent > 100) {
  // The forwarding arena must cover the largest documented limit on one
  // interface. Otherwise CLI could accept a valid SR OS value and still fail
  // early because of an unrelated emulator resource ceiling.
  fail("Neighbor Discovery defaults, ranges or arena capacity are inconsistent");
}
if (catalog.protocol_defaults.mld_minimum_query_interval_seconds >
      catalog.protocol_defaults.mld_query_interval_seconds ||
    catalog.protocol_defaults.mld_query_interval_seconds >
      catalog.protocol_defaults.mld_maximum_query_interval_seconds ||
    catalog.protocol_defaults.mld_minimum_query_response_interval_seconds * 1000 >
      catalog.protocol_defaults.mld_query_response_interval_milliseconds ||
    catalog.protocol_defaults.mld_query_response_interval_milliseconds >
      catalog.protocol_defaults.mld_maximum_query_response_interval_seconds * 1000 ||
    catalog.protocol_defaults.mld_minimum_last_listener_query_interval_seconds * 1000 >
      catalog.protocol_defaults.mld_last_listener_query_interval_milliseconds ||
    catalog.protocol_defaults.mld_last_listener_query_interval_milliseconds >
      catalog.protocol_defaults.mld_maximum_last_listener_query_interval_seconds * 1000 ||
    catalog.protocol_defaults.mld_minimum_robustness_variable >
      catalog.protocol_defaults.mld_robustness_variable ||
    catalog.protocol_defaults.mld_robustness_variable >
      catalog.protocol_defaults.mld_maximum_robustness_variable ||
    catalog.protocol_defaults.mld_minimum_version >
      catalog.protocol_defaults.mld_default_version ||
    catalog.protocol_defaults.mld_default_version >
      catalog.protocol_defaults.mld_maximum_version) {
  fail("MLD defaults are outside the SR OS release command ranges");
}
if (catalog.runtime.mld_router_groups_per_interface <
      catalog.protocol_defaults.mld_maximum_number_groups ||
    catalog.runtime.mld_router_sources_per_group <
      catalog.protocol_defaults.mld_maximum_number_sources ||
    catalog.runtime.mld_router_group_sources_per_interface <
      catalog.protocol_defaults.mld_maximum_number_group_sources ||
    catalog.runtime.mld_router_group_sources_per_interface <
      catalog.runtime.mld_router_sources_per_group) {
  // The generated release grammar must never advertise a value that the
  // corresponding state owner cannot represent. This assertion prevents a
  // future profile edit from silently restoring parser-only compatibility.
  fail("MLD router resource ceilings do not cover configurable release ranges");
}

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
const maximumActiveCapturePoints = catalog.limits.links * 2 +
  catalog.limits.routers * (maximumPortsPerRouter * 2 + 1);
if (catalog.runtime.maximum_active_capture_points !== maximumActiveCapturePoints)
  fail("runtime.maximum_active_capture_points does not cover the generated topology");

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

struct TlsAlgorithmName {
  std::string_view sros;
  std::string_view openssl;
  bool pqc{};
};

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
inline constexpr std::uint16_t maximum_ecmp_paths = ${catalog.runtime.maximum_ecmp_paths};
inline constexpr std::size_t maximum_fib_routes_per_router =
    maximum_ports_per_router + maximum_static_routes_per_router;
inline constexpr std::size_t wasm_initial_memory_bytes = ${catalog.runtime.wasm_initial_memory_bytes}U;
inline constexpr std::size_t wasm_maximum_memory_bytes = ${catalog.runtime.wasm_maximum_memory_bytes}U;
inline constexpr std::size_t wasm_growth_step_bytes = ${catalog.runtime.wasm_growth_step_bytes}U;
inline constexpr std::size_t wasm_stack_bytes = ${catalog.runtime.wasm_stack_bytes}U;
inline constexpr std::size_t packet_pool_bytes = ${catalog.runtime.packet_pool_bytes}U;
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
inline constexpr std::chrono::milliseconds recovery_checkpoint_interval{
    ${catalog.runtime.recovery_checkpoint_interval_milliseconds}};
inline constexpr std::chrono::milliseconds continuity_loss_threshold{
    ${catalog.runtime.continuity_loss_threshold_milliseconds}};
inline constexpr std::size_t link_queue_capacity = ${catalog.runtime.link_queue_frames};
inline constexpr std::size_t fabric_work_budget_frames = ${catalog.runtime.fabric_work_budget_frames};
inline constexpr std::chrono::nanoseconds immediate_link_deadline{
    ${catalog.runtime.immediate_link_deadline_nanoseconds}};
inline constexpr std::size_t arp_entries_per_router = ${catalog.runtime.arp_entries_per_router};
inline constexpr std::size_t static_arp_entries_per_router = ${catalog.runtime.static_arp_entries_per_router};
inline constexpr std::size_t pending_ipv4_frames_per_router = ${catalog.runtime.pending_ipv4_frames_per_router};
inline constexpr std::size_t ipv6_neighbor_entries_per_router = ${catalog.runtime.ipv6_neighbor_entries_per_router};
inline constexpr std::size_t ipv6_destination_entries_per_endpoint = ${catalog.runtime.ipv6_destination_entries_per_endpoint};
inline constexpr std::uint16_t icmp6_redirect_default_maximum = ${catalog.runtime.icmp6_redirect_default_maximum};
inline constexpr std::chrono::seconds icmp6_redirect_default_interval{${catalog.runtime.icmp6_redirect_default_interval_seconds}};
inline constexpr std::uint16_t icmp6_redirect_minimum_maximum = ${catalog.runtime.icmp6_redirect_minimum_maximum};
inline constexpr std::uint16_t icmp6_redirect_maximum_maximum = ${catalog.runtime.icmp6_redirect_maximum_maximum};
inline constexpr std::chrono::seconds icmp6_redirect_minimum_interval{${catalog.runtime.icmp6_redirect_minimum_interval_seconds}};
inline constexpr std::chrono::seconds icmp6_redirect_maximum_interval{${catalog.runtime.icmp6_redirect_maximum_interval_seconds}};
inline constexpr std::uint16_t icmp_redirect_default_maximum = ${catalog.runtime.icmp_redirect_default_maximum};
inline constexpr std::chrono::seconds icmp_redirect_default_interval{${catalog.runtime.icmp_redirect_default_interval_seconds}};
inline constexpr std::uint16_t icmp_redirect_minimum_maximum = ${catalog.runtime.icmp_redirect_minimum_maximum};
inline constexpr std::uint16_t icmp_redirect_maximum_maximum = ${catalog.runtime.icmp_redirect_maximum_maximum};
inline constexpr std::chrono::seconds icmp_redirect_minimum_interval{${catalog.runtime.icmp_redirect_minimum_interval_seconds}};
inline constexpr std::chrono::seconds icmp_redirect_maximum_interval{${catalog.runtime.icmp_redirect_maximum_interval_seconds}};
inline constexpr std::size_t ipv6_dad_entries_per_node = ${catalog.runtime.ipv6_dad_entries_per_node};
inline constexpr std::size_t network_interface_ip_addresses = ${catalog.runtime.network_interface_ip_addresses};
inline constexpr std::size_t pending_ipv6_frames_per_router = ${catalog.runtime.pending_ipv6_frames_per_router};
inline constexpr std::size_t ipv4_reassembly_entries_per_endpoint = ${catalog.runtime.ipv4_reassembly_entries_per_endpoint};
inline constexpr std::chrono::seconds ipv4_reassembly_timeout{${catalog.runtime.ipv4_reassembly_timeout_seconds}};
inline constexpr std::size_t ipv6_reassembly_entries_per_endpoint = ${catalog.runtime.ipv6_reassembly_entries_per_endpoint};
inline constexpr std::chrono::seconds ipv6_reassembly_timeout{${catalog.runtime.ipv6_reassembly_timeout_seconds}};
inline constexpr std::size_t ipv4_pmtu_entries_per_endpoint = ${catalog.runtime.ipv4_pmtu_entries_per_endpoint};
inline constexpr std::chrono::seconds ipv4_pmtu_probe_interval{${catalog.runtime.ipv4_pmtu_probe_interval_seconds}};
inline constexpr std::chrono::seconds ipv4_pmtu_probe_retry_interval{${catalog.runtime.ipv4_pmtu_probe_retry_interval_seconds}};
inline constexpr std::size_t ipv6_pmtu_entries_per_endpoint = ${catalog.runtime.ipv6_pmtu_entries_per_endpoint};
inline constexpr std::chrono::seconds ipv6_pmtu_probe_interval{${catalog.runtime.ipv6_pmtu_probe_interval_seconds}};
inline constexpr std::size_t udp_queued_datagrams_per_endpoint = ${catalog.runtime.udp_queued_datagrams_per_endpoint};
inline constexpr std::size_t udp_datagrams_per_socket = ${catalog.runtime.udp_datagrams_per_socket};
inline constexpr std::size_t udp_receive_buffer_bytes_per_endpoint = ${catalog.runtime.udp_receive_buffer_bytes_per_endpoint};
inline constexpr std::size_t udp_receive_block_bytes = ${catalog.runtime.udp_receive_block_bytes};
inline constexpr std::uint16_t udp_ephemeral_port_first = ${catalog.runtime.udp_ephemeral_port_first};
inline constexpr std::uint16_t udp_ephemeral_port_last = ${catalog.runtime.udp_ephemeral_port_last};
inline constexpr std::size_t tcp_send_buffer_default_bytes = ${catalog.runtime.tcp_send_buffer_default_bytes};
inline constexpr std::size_t tcp_receive_buffer_default_bytes = ${catalog.runtime.tcp_receive_buffer_default_bytes};
inline constexpr std::size_t tcp_transmission_records_default = ${catalog.runtime.tcp_transmission_records_default};
inline constexpr std::size_t tcp_sack_ranges_default = ${catalog.runtime.tcp_sack_ranges_default};
inline constexpr std::size_t tcp_listen_backlog_default = ${catalog.runtime.tcp_listen_backlog_default};
inline constexpr std::uint16_t tcp_ephemeral_port_first = ${catalog.runtime.tcp_ephemeral_port_first};
inline constexpr std::uint16_t tcp_ephemeral_port_last = ${catalog.runtime.tcp_ephemeral_port_last};
inline constexpr std::size_t dns_cache_default_bytes = ${catalog.runtime.dns_cache_default_bytes};
inline constexpr std::uint16_t dns_resolver_advertised_udp_payload_bytes = ${catalog.runtime.dns_resolver_advertised_udp_payload_bytes};
inline constexpr std::uint32_t dns_resolver_retry_milliseconds = ${catalog.runtime.dns_resolver_retry_milliseconds};
inline constexpr std::uint32_t dns_resolver_attempts_per_server = ${catalog.runtime.dns_resolver_attempts_per_server};
inline constexpr std::uint32_t dns_resolver_max_minimise_count = ${catalog.runtime.dns_resolver_max_minimise_count};
inline constexpr std::uint32_t dns_resolver_minimise_one_label_count = ${catalog.runtime.dns_resolver_minimise_one_label_count};
inline constexpr std::uint32_t dns_resolver_max_alias_hops = ${catalog.runtime.dns_resolver_max_alias_hops};
inline constexpr std::size_t dhcpv6_address_pools_per_server = ${catalog.runtime.dhcpv6_address_pools_per_server};
inline constexpr std::size_t dhcpv6_prefix_pools_per_server = ${catalog.runtime.dhcpv6_prefix_pools_per_server};
inline constexpr std::size_t dhcpv6_leases_per_server = ${catalog.runtime.dhcpv6_leases_per_server};
inline constexpr std::size_t dhcpv6_relay_servers_per_interface = ${catalog.runtime.dhcpv6_relay_servers_per_interface};
inline constexpr std::uint32_t dhcpv6_zero_t1_percent_of_preferred = ${catalog.runtime.dhcpv6_zero_t1_percent_of_preferred};
inline constexpr std::uint32_t dhcpv6_zero_t2_percent_of_preferred = ${catalog.runtime.dhcpv6_zero_t2_percent_of_preferred};
inline constexpr std::uint32_t dhcpv6_client_rate_limit_packets = ${catalog.runtime.dhcpv6_client_rate_limit_packets};
inline constexpr std::uint32_t dhcpv6_client_rate_limit_interval_seconds = ${catalog.runtime.dhcpv6_client_rate_limit_interval_seconds};
inline constexpr std::size_t pending_l3_frames_per_router = ${catalog.runtime.pending_l3_frames_per_router};
inline constexpr std::size_t nd_work_budget_actions = ${catalog.runtime.nd_work_budget_actions};
inline constexpr std::size_t ipv6_ra_prefixes_per_interface = ${catalog.runtime.ipv6_ra_prefixes_per_interface};
inline constexpr std::size_t ipv6_rdnss_servers_per_interface = ${catalog.runtime.ipv6_rdnss_servers_per_interface};
inline constexpr std::size_t ipv6_default_routers_per_host_interface = ${catalog.runtime.ipv6_default_routers_per_host_interface};
inline constexpr std::size_t ipv6_on_link_prefixes_per_host_interface = ${catalog.runtime.ipv6_on_link_prefixes_per_host_interface};
inline constexpr std::size_t ipv6_slaac_addresses_per_host_interface = ${catalog.runtime.ipv6_slaac_addresses_per_host_interface};
inline constexpr std::size_t ipv6_rdnss_entries_per_host_interface = ${catalog.runtime.ipv6_rdnss_entries_per_host_interface};
inline constexpr std::size_t ipv6_stable_iid_network_id_octets = ${catalog.runtime.ipv6_stable_iid_network_id_octets};
inline constexpr std::size_t host_ipv6_work_budget_actions = ${catalog.runtime.host_ipv6_work_budget_actions};
inline constexpr std::size_t mld_groups_per_interface = ${catalog.runtime.mld_groups_per_interface};
inline constexpr std::size_t mld_sources_per_group = ${catalog.runtime.mld_sources_per_group};
inline constexpr std::size_t mld_records_per_report = ${catalog.runtime.mld_records_per_report};
inline constexpr std::size_t mld_work_budget_actions = ${catalog.runtime.mld_work_budget_actions};
inline constexpr std::size_t mld_router_groups_per_interface = ${catalog.runtime.mld_router_groups_per_interface};
inline constexpr std::size_t mld_router_sources_per_group = ${catalog.runtime.mld_router_sources_per_group};
inline constexpr std::size_t mld_router_group_sources_per_interface = ${catalog.runtime.mld_router_group_sources_per_interface};
inline constexpr std::size_t network_command_ring_entries = ${catalog.runtime.network_command_ring_entries};
inline constexpr std::size_t network_result_ring_entries = ${catalog.runtime.network_result_ring_entries};
inline constexpr std::size_t network_command_work_budget = ${catalog.runtime.network_command_work_budget};
inline constexpr std::size_t forwarding_ring_frames = ${catalog.runtime.forwarding_ring_frames};
inline constexpr std::size_t candidate_keys_per_router = ${catalog.runtime.candidate_keys_per_router};
inline constexpr std::size_t candidate_keys_per_session = ${catalog.runtime.candidate_keys_per_session};
inline constexpr std::size_t maximum_active_capture_points = ${catalog.runtime.maximum_active_capture_points};
inline constexpr std::size_t capture_point_name_bytes = ${catalog.runtime.capture_point_name_bytes};
inline constexpr std::uint16_t default_network_mtu = ${catalog.ethernet.default_network_mtu};
inline constexpr std::uint16_t minimum_network_mtu = ${catalog.ethernet.minimum_network_mtu};
inline constexpr std::uint16_t maximum_network_mtu = ${catalog.ethernet.maximum_network_mtu};
inline constexpr std::uint16_t minimum_host_ipv4_mtu = ${catalog.ethernet.minimum_host_ipv4_mtu};
inline constexpr std::uint16_t minimum_host_ipv6_mtu = ${catalog.ethernet.minimum_host_ipv6_mtu};
inline constexpr std::uint16_t default_host_ipv4_mtu = ${catalog.ethernet.default_host_ipv4_mtu};
inline constexpr std::size_t tls_maximum_cert_profiles = ${catalog.tls.maximum_cert_profiles};
inline constexpr std::size_t tls_maximum_client_cipher_lists = ${catalog.tls.maximum_client_cipher_lists};
inline constexpr std::size_t tls_maximum_client_group_lists = ${catalog.tls.maximum_client_group_lists};
inline constexpr std::size_t tls_maximum_client_signature_lists = ${catalog.tls.maximum_client_signature_lists};
inline constexpr std::size_t tls_maximum_client_profiles = ${catalog.tls.maximum_client_tls_profiles};
inline constexpr std::size_t tls_maximum_server_cipher_lists = ${catalog.tls.maximum_server_cipher_lists};
inline constexpr std::size_t tls_maximum_server_group_lists = ${catalog.tls.maximum_server_group_lists};
inline constexpr std::size_t tls_maximum_server_signature_lists = ${catalog.tls.maximum_server_signature_lists};
inline constexpr std::size_t tls_maximum_server_profiles = ${catalog.tls.maximum_server_tls_profiles};
inline constexpr std::size_t tls_maximum_trust_anchor_profiles = ${catalog.tls.maximum_trust_anchor_profiles};
inline constexpr std::size_t tls_maximum_cert_entries_per_profile = ${catalog.tls.maximum_cert_entries_per_profile};
inline constexpr std::size_t tls_maximum_trust_anchors_per_profile = ${catalog.tls.maximum_trust_anchors_per_profile};
inline constexpr std::size_t tls_profile_name_bytes = ${catalog.tls.profile_name_bytes};
inline constexpr std::size_t tls_certificate_file_name_bytes = ${catalog.tls.certificate_file_name_bytes};
inline constexpr std::uint8_t tls_algorithm_index_minimum = ${catalog.tls.algorithm_index_minimum};
inline constexpr std::uint8_t tls_algorithm_index_maximum = ${catalog.tls.algorithm_index_maximum};
inline constexpr std::array<TlsAlgorithmName, ${catalog.tls.tls13_ciphers.length}> tls13_ciphers{{
${catalog.tls.tls13_ciphers.map((item) => `    {${cppString(item.sros)}, ${cppString(item.openssl)}, ${cppBoolean(item.pqc)}}`).join(",\n")}
}};
inline constexpr std::array<TlsAlgorithmName, ${catalog.tls.tls13_groups.length}> tls13_groups{{
${catalog.tls.tls13_groups.map((item) => `    {${cppString(item.sros)}, ${cppString(item.openssl)}, ${cppBoolean(item.pqc)}}`).join(",\n")}
}};
inline constexpr std::array<TlsAlgorithmName, ${catalog.tls.tls13_signatures.length}> tls13_signatures{{
${catalog.tls.tls13_signatures.map((item) => `    {${cppString(item.sros)}, ${cppString(item.openssl)}, ${cppBoolean(item.pqc)}}`).join(",\n")}
}};
inline constexpr std::chrono::seconds dynamic_arp_timeout{
    ${catalog.protocol_defaults.dynamic_arp_timeout_seconds}};
inline constexpr std::uint32_t arp_timeout_minimum_seconds =
    ${catalog.protocol_defaults.arp_timeout_minimum_seconds}U;
inline constexpr std::uint32_t arp_timeout_maximum_seconds =
    ${catalog.protocol_defaults.arp_timeout_maximum_seconds}U;
inline constexpr std::chrono::milliseconds dynamic_arp_retry{
    ${catalog.protocol_defaults.dynamic_arp_retry_deciseconds * 100}};
inline constexpr std::uint16_t dynamic_arp_retry_deciseconds =
    ${catalog.protocol_defaults.dynamic_arp_retry_deciseconds}U;
inline constexpr std::uint16_t arp_retry_minimum_deciseconds =
    ${catalog.protocol_defaults.arp_retry_minimum_deciseconds}U;
inline constexpr std::uint16_t arp_retry_maximum_deciseconds =
    ${catalog.protocol_defaults.arp_retry_maximum_deciseconds}U;
inline constexpr std::chrono::milliseconds tcp_rto_initial{
    ${catalog.protocol_defaults.tcp_rto_initial_milliseconds}};
inline constexpr std::chrono::milliseconds tcp_rto_minimum{
    ${catalog.protocol_defaults.tcp_rto_minimum_milliseconds}};
inline constexpr std::chrono::milliseconds tcp_rto_maximum{
    ${catalog.protocol_defaults.tcp_rto_maximum_milliseconds}};
inline constexpr std::chrono::milliseconds tcp_rto_clock_granularity{
    ${catalog.protocol_defaults.tcp_rto_clock_granularity_milliseconds}};
inline constexpr std::chrono::milliseconds tcp_rto_after_syn_retransmission{
    ${catalog.protocol_defaults.tcp_rto_after_syn_retransmission_milliseconds}};
inline constexpr std::chrono::milliseconds tcp_delayed_ack{
    ${catalog.protocol_defaults.tcp_delayed_ack_milliseconds}};
inline constexpr std::chrono::milliseconds tcp_sws_override{
    ${catalog.protocol_defaults.tcp_sws_override_milliseconds}};
inline constexpr std::chrono::milliseconds tcp_persist_maximum{
    ${catalog.protocol_defaults.tcp_persist_maximum_milliseconds}};
inline constexpr std::uint32_t tcp_failure_r1_retransmissions =
    ${catalog.protocol_defaults.tcp_failure_r1_retransmissions}U;
inline constexpr std::chrono::seconds tcp_failure_data_r2{
    ${catalog.protocol_defaults.tcp_failure_data_r2_seconds}};
inline constexpr std::chrono::seconds tcp_failure_syn_r2{
    ${catalog.protocol_defaults.tcp_failure_syn_r2_seconds}};
inline constexpr std::chrono::seconds tcp_maximum_segment_lifetime{
    ${catalog.protocol_defaults.tcp_maximum_segment_lifetime_seconds}};
inline constexpr std::chrono::milliseconds nd_base_reachable_time{
    ${catalog.protocol_defaults.nd_reachable_time_milliseconds}};
inline constexpr std::uint32_t nd_default_reachable_time_seconds =
    ${catalog.protocol_defaults.nd_default_reachable_time_seconds}U;
inline constexpr std::uint32_t nd_minimum_reachable_time_seconds =
    ${catalog.protocol_defaults.nd_minimum_reachable_time_seconds}U;
inline constexpr std::uint32_t nd_maximum_reachable_time_seconds =
    ${catalog.protocol_defaults.nd_maximum_reachable_time_seconds}U;
inline constexpr std::uint32_t nd_default_stale_time_seconds =
    ${catalog.protocol_defaults.nd_default_stale_time_seconds}U;
inline constexpr std::uint32_t nd_minimum_stale_time_seconds =
    ${catalog.protocol_defaults.nd_minimum_stale_time_seconds}U;
inline constexpr std::uint32_t nd_maximum_stale_time_seconds =
    ${catalog.protocol_defaults.nd_maximum_stale_time_seconds}U;
inline constexpr std::uint32_t nd_maximum_neighbor_limit =
    ${catalog.protocol_defaults.nd_maximum_neighbor_limit}U;
inline constexpr std::uint8_t nd_default_neighbor_limit_threshold_percent =
    ${catalog.protocol_defaults.nd_default_neighbor_limit_threshold_percent}U;
inline constexpr std::chrono::seconds nd_reachable_time_recalculation{
    ${catalog.protocol_defaults.nd_reachable_time_recalculation_seconds}};
inline constexpr std::chrono::milliseconds nd_retrans_timer{
    ${catalog.protocol_defaults.nd_retrans_timer_milliseconds}};
inline constexpr std::chrono::milliseconds nd_delay_first_probe{
    ${catalog.protocol_defaults.nd_delay_first_probe_milliseconds}};
inline constexpr std::uint8_t nd_max_multicast_solicit =
    ${catalog.protocol_defaults.nd_max_multicast_solicit};
inline constexpr std::uint8_t nd_max_unicast_solicit =
    ${catalog.protocol_defaults.nd_max_unicast_solicit};
inline constexpr std::uint8_t ipv6_dad_transmits =
    ${catalog.protocol_defaults.ipv6_dad_transmits};
inline constexpr std::chrono::milliseconds ipv6_dad_max_initial_delay{
    ${catalog.protocol_defaults.ipv6_dad_max_initial_delay_milliseconds}};
inline constexpr std::uint8_t ipv6_stable_iid_dad_retries =
    ${catalog.protocol_defaults.ipv6_stable_iid_dad_retries};
inline constexpr std::chrono::milliseconds ipv6_stable_iid_dad_retry_delay{
    ${catalog.protocol_defaults.ipv6_stable_iid_dad_retry_delay_milliseconds}};
inline constexpr std::uint8_t ipv6_rs_max_solicitations =
    ${catalog.protocol_defaults.ipv6_rs_max_solicitations};
inline constexpr std::chrono::seconds ipv6_rs_interval{
    ${catalog.protocol_defaults.ipv6_rs_interval_seconds}};
inline constexpr std::chrono::milliseconds ipv6_rs_max_initial_delay{
    ${catalog.protocol_defaults.ipv6_rs_max_initial_delay_milliseconds}};
inline constexpr std::uint8_t mld_robustness_variable =
    ${catalog.protocol_defaults.mld_robustness_variable};
inline constexpr std::chrono::seconds mld_query_interval{
    ${catalog.protocol_defaults.mld_query_interval_seconds}};
inline constexpr std::chrono::milliseconds mld_query_response_interval{
    ${catalog.protocol_defaults.mld_query_response_interval_milliseconds}};
inline constexpr std::chrono::milliseconds mld_last_listener_query_interval{
    ${catalog.protocol_defaults.mld_last_listener_query_interval_milliseconds}};
inline constexpr std::chrono::milliseconds mld_unsolicited_report_interval{
    ${catalog.protocol_defaults.mld_unsolicited_report_interval_milliseconds}};
inline constexpr std::uint16_t mld_minimum_query_interval_seconds =
    ${catalog.protocol_defaults.mld_minimum_query_interval_seconds};
inline constexpr std::uint16_t mld_maximum_query_interval_seconds =
    ${catalog.protocol_defaults.mld_maximum_query_interval_seconds};
inline constexpr std::uint16_t mld_minimum_query_response_interval_seconds =
    ${catalog.protocol_defaults.mld_minimum_query_response_interval_seconds};
inline constexpr std::uint16_t mld_maximum_query_response_interval_seconds =
    ${catalog.protocol_defaults.mld_maximum_query_response_interval_seconds};
inline constexpr std::uint16_t
    mld_minimum_last_listener_query_interval_seconds =
        ${catalog.protocol_defaults.mld_minimum_last_listener_query_interval_seconds};
inline constexpr std::uint16_t
    mld_maximum_last_listener_query_interval_seconds =
        ${catalog.protocol_defaults.mld_maximum_last_listener_query_interval_seconds};
inline constexpr std::uint8_t mld_minimum_robustness_variable =
    ${catalog.protocol_defaults.mld_minimum_robustness_variable};
inline constexpr std::uint8_t mld_maximum_robustness_variable =
    ${catalog.protocol_defaults.mld_maximum_robustness_variable};
inline constexpr std::uint8_t mld_minimum_version =
    ${catalog.protocol_defaults.mld_minimum_version};
inline constexpr std::uint8_t mld_maximum_version =
    ${catalog.protocol_defaults.mld_maximum_version};
inline constexpr std::uint8_t mld_default_version =
    ${catalog.protocol_defaults.mld_default_version};
inline constexpr std::uint32_t mld_maximum_number_groups =
    ${catalog.protocol_defaults.mld_maximum_number_groups};
inline constexpr std::uint32_t mld_maximum_number_group_sources =
    ${catalog.protocol_defaults.mld_maximum_number_group_sources};
inline constexpr std::uint32_t mld_maximum_number_sources =
    ${catalog.protocol_defaults.mld_maximum_number_sources};
inline constexpr std::uint8_t default_ip_hop_limit =
    ${catalog.protocol_defaults.default_ip_hop_limit};
inline constexpr std::chrono::seconds ra_max_advertisement_interval{
    ${catalog.protocol_defaults.ra_max_advertisement_interval_seconds}};
inline constexpr std::chrono::seconds ra_min_advertisement_interval{
    ${catalog.protocol_defaults.ra_min_advertisement_interval_seconds}};
inline constexpr std::chrono::seconds ra_router_lifetime{
    ${catalog.protocol_defaults.ra_router_lifetime_seconds}};
inline constexpr std::chrono::seconds ra_minimum_max_advertisement_interval{
    ${catalog.protocol_defaults.ra_minimum_max_advertisement_interval_seconds}};
inline constexpr std::chrono::seconds ra_maximum_max_advertisement_interval{
    ${catalog.protocol_defaults.ra_maximum_max_advertisement_interval_seconds}};
inline constexpr std::chrono::seconds ra_minimum_min_advertisement_interval{
    ${catalog.protocol_defaults.ra_minimum_min_advertisement_interval_seconds}};
inline constexpr std::chrono::seconds ra_maximum_min_advertisement_interval{
    ${catalog.protocol_defaults.ra_maximum_min_advertisement_interval_seconds}};
inline constexpr std::chrono::seconds ra_minimum_nonzero_router_lifetime{
    ${catalog.protocol_defaults.ra_minimum_nonzero_router_lifetime_seconds}};
inline constexpr std::chrono::seconds ra_maximum_router_lifetime{
    ${catalog.protocol_defaults.ra_maximum_router_lifetime_seconds}};
inline constexpr std::chrono::milliseconds ra_maximum_reachable_time{
    ${catalog.protocol_defaults.ra_maximum_reachable_time_milliseconds}};
inline constexpr std::chrono::milliseconds ra_maximum_retransmit_time{
    ${catalog.protocol_defaults.ra_maximum_retransmit_time_milliseconds}};
inline constexpr std::uint16_t ra_minimum_advertised_mtu =
    ${catalog.protocol_defaults.ra_minimum_advertised_mtu};
inline constexpr std::uint16_t ra_maximum_advertised_mtu =
    ${catalog.protocol_defaults.ra_maximum_advertised_mtu};
inline constexpr std::uint32_t ra_default_prefix_preferred_lifetime =
    ${catalog.protocol_defaults.ra_default_prefix_preferred_lifetime_seconds}U;
inline constexpr std::uint32_t ra_default_prefix_valid_lifetime =
    ${catalog.protocol_defaults.ra_default_prefix_valid_lifetime_seconds}U;
inline constexpr std::uint32_t ra_minimum_rdnss_lifetime =
    ${catalog.protocol_defaults.ra_minimum_rdnss_lifetime_seconds}U;
inline constexpr std::uint32_t ra_maximum_rdnss_lifetime =
    ${catalog.protocol_defaults.ra_maximum_rdnss_lifetime_seconds}U;
inline constexpr std::uint32_t ra_infinite_lifetime =
    ${catalog.protocol_defaults.ra_infinite_lifetime_seconds}U;
inline constexpr std::chrono::milliseconds ra_max_response_delay{
    ${catalog.protocol_defaults.ra_max_response_delay_milliseconds}};
inline constexpr std::chrono::seconds ra_min_delay_between_advertisements{
    ${catalog.protocol_defaults.ra_min_delay_between_advertisements_seconds}};
inline constexpr std::chrono::seconds ra_max_initial_advertisement_interval{
    ${catalog.protocol_defaults.ra_max_initial_advertisement_interval_seconds}};
inline constexpr std::uint8_t ra_max_initial_advertisements =
    ${catalog.protocol_defaults.ra_max_initial_advertisements};
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
inline constexpr std::chrono::seconds checkpoint_max_relative_deadline{
    ${catalog.protocol_defaults.checkpoint_max_relative_deadline_seconds}};

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

// Generated protocol 4 operation identities. Payload fields use netstrings;
// packet bytes and mutable runtime addresses never cross this text boundary.

#include <string_view>

namespace router::lab_runtime_protocol {
inline constexpr unsigned version = ${protocol.version};
${Object.entries(protocol.operations).map(([name, value]) =>
  `inline constexpr std::string_view ${name}{${cppString(value)}};`).join("\n")}
} // namespace router::lab_runtime_protocol
`;
const protocolTypescript = `// Generated browser names for runtime protocol 4.\n` +
`export const LAB_RUNTIME_PROTOCOL = ${JSON.stringify({ version: protocol.version,
  snapshotAbi: protocol.snapshot_abi,
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
