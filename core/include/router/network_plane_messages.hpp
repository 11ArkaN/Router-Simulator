// Versioned control-to-network and network-to-control messages. Both directions
// use one known producer and one known consumer and therefore require SPSC
// only.

#pragma once

#include "router/generated_device_catalog.hpp"
#include "router/network_plane.hpp"
#include "router/spsc_ring.hpp"

#include <cstdint>
#include <variant>

namespace router::lab {

// Version 22 adds streamed DNS resolver, authoritative and managed-signing
// programs. An older worker cannot accept those transactions, so version
// mismatch must reject the command rather than publish a partial service.
inline constexpr std::uint32_t network_plane_message_version = 22;

struct NetworkSigningVaultInitialize {
  // Producer: control shard. Consumer: network owner. Capacity is one live
  // value plus one unused SPSC slot. The consumer uses try_pop_and_clear and
  // also erases its local copy immediately after NetworkPlane copies it.
  std::array<std::uint8_t, 32U> wrapping_key{};
  crypto::Sha256Digest project_context_digest{};
};

struct NetworkDhcpv6ClientBegin {
  std::array<std::uint8_t, packet::dhcpv6::maximum_duid_octets> duid{};
  crypto::Sha256Digest transaction_secret{};
  std::uint32_t expected_associations{};
  std::uint32_t expected_options{};
  std::uint16_t duid_octets{};
  bool rapid_commit{};
  bool information_only{};
};

struct NetworkDhcpv6ClientAssociation {
  std::uint32_t iaid{};
  dhcpv6::LeaseKind kind{dhcpv6::LeaseKind::non_temporary};
};

struct NetworkDhcpv6ServerBegin {
  std::array<std::uint8_t, packet::dhcpv6::maximum_duid_octets> duid{};
  std::uint64_t decline_hold_seconds{};
  std::uint32_t expected_dns_servers{};
  std::uint32_t expected_address_pools{};
  std::uint32_t expected_prefix_pools{};
  std::uint32_t information_refresh_time_seconds{};
  std::uint32_t solicit_maximum_retransmission_seconds{};
  std::uint32_t information_maximum_retransmission_seconds{};
  std::uint16_t duid_octets{};
  std::uint8_t preference{};
  std::uint8_t address_pool_index{};
  std::uint8_t prefix_pool_index{};
  bool rapid_commit{};
  bool has_solicit_maximum_retransmission{};
  bool has_information_maximum_retransmission{};
};

inline constexpr std::size_t network_dns_chunk_octets = 256U;

struct NetworkDnsResolverBegin {
  crypto::Sha256Digest identifier_secret{};
  std::uint32_t expected_root_hints{};
  std::uint32_t expected_trust_anchors{};
  std::uint16_t maximum_nsec3_iterations{};
  bool serve_clients{};
};

struct NetworkDnsRootHintBegin {
  packet::dns::Name server_name;
  std::uint32_t expected_addresses{};
};

struct NetworkDnsTrustAnchorBegin {
  packet::dns::Name owner;
  std::uint32_t ttl{};
  std::uint32_t expected_rdata_octets{};
  std::uint16_t record_class{packet::dns::internet_class};
};

struct NetworkDnsAuthoritativeBegin {
  std::uint64_t wall_now{};
  std::uint32_t expected_zones{};
  bool managed_signing{};
};

struct NetworkDnsZoneBegin {
  packet::dns::Name origin;
  dnssec::ManagedZoneSigningPolicy policy{};
  std::uint32_t expected_records{};
  std::uint32_t expected_keys{};
};

struct NetworkDnsSigningKeyDefinition {
  dnssec::KeySchedule schedule{};
  dnssec::SigningKeyGeneration generation{};
  dnssec::KeyRole role{dnssec::KeyRole::zone_signing};
  std::uint8_t algorithm{};
};

struct NetworkDnsRecordBegin {
  packet::dns::Name owner;
  std::uint32_t ttl{};
  std::uint32_t expected_rdata_octets{};
  std::uint16_t type{};
  std::uint16_t record_class{packet::dns::internet_class};
};

struct NetworkDnsRdataChunk {
  std::array<std::uint8_t, network_dns_chunk_octets> octets{};
  std::uint16_t size{};
};

enum class NetworkCommandKind : std::uint8_t {
  initialize_signing_vault,
  add_router,
  remove_router,
  add_host,
  remove_host,
  configure_port,
  remove_port,
  program_fib,
  program_ipv6_fib,
  begin_ipv6_address_generation,
  add_ipv6_interface_address,
  commit_ipv6_address_generation,
  abort_ipv6_address_generation,
  begin_sap_generation,
  add_sap_attachment,
  add_service_ipv6_interface,
  commit_sap_generation,
  abort_sap_generation,
  install_static_ipv6_neighbor,
  remove_static_ipv6_neighbor,
  install_static_ipv4_neighbor,
  remove_static_ipv4_neighbor,
  clear_dynamic_ipv4_neighbors,
  clear_dynamic_ipv6_neighbors,
  configure_router_advertisement,
  remove_router_advertisement,
  configure_mld_interface,
  remove_mld_interface,
  begin_dhcpv6_relay,
  add_dhcpv6_relay_interface_id,
  add_dhcpv6_relay_server,
  commit_dhcpv6_relay,
  abort_dhcpv6_relay,
  remove_dhcpv6_relay,
  clear_dhcpv6_relay_leases,
  clear_mld_database,
  clear_mld_database_all,
  clear_mld_version,
  clear_mld_statistics,
  clear_mld_statistics_all,
  edit_mld_static,
  program_mld_ssm_translation,
  program_mld_import_policy,
  clear_icmpv4_statistics_all,
  clear_icmpv4_global_statistics,
  clear_icmpv4_interface_statistics,
  clear_icmpv6_statistics_all,
  clear_icmpv6_global_statistics,
  clear_icmpv6_interface_statistics,
  clear_router_advertisement_statistics_all,
  clear_router_advertisement_interface_statistics,
  configure_host,
  begin_host_dhcpv6_client,
  add_host_dhcpv6_client_ia,
  add_host_dhcpv6_client_option,
  commit_host_dhcpv6_client,
  abort_host_dhcpv6_client,
  remove_host_dhcpv6_client,
  begin_host_dhcpv6_server,
  add_host_dhcpv6_server_dns,
  add_host_dhcpv6_server_address_pool,
  add_host_dhcpv6_server_prefix_pool,
  commit_host_dhcpv6_server,
  abort_host_dhcpv6_server,
  remove_host_dhcpv6_server,
  host_dhcpv6_client_status,
  begin_host_dns_resolver,
  begin_host_dns_root_hint,
  add_host_dns_root_address,
  commit_host_dns_root_hint,
  begin_host_dns_trust_anchor,
  add_host_dns_trust_anchor_rdata,
  commit_host_dns_trust_anchor,
  commit_host_dns_resolver,
  abort_host_dns_resolver,
  remove_host_dns_resolver,
  begin_host_dns_authoritative,
  begin_host_dns_zone,
  add_host_dns_signing_key,
  begin_host_dns_record,
  add_host_dns_rdata,
  commit_host_dns_record,
  commit_host_dns_zone,
  commit_host_dns_authoritative,
  abort_host_dns_authoritative,
  remove_host_dns_authoritative,
  configure_link,
  remove_link,
  router_ping,
  router_ipv6_ping,
  host_ping,
  router_ping_status,
  router_ipv6_ping_status,
  host_ping_status,
  active_link_count,
  configure_capture_point,
  prepare_capture,
  clear_capture,
  capture_frame_count,
  capture_drop_count,
  packet_drop_count,
  prepare_router_checkpoint,
  prepare_checkpoint,
  restore_checkpoint,
  shutdown
};

struct NetworkCommand {
  // Producer: assigned control shard. Consumer: combined forwarding and link
  // shard. The fixed payload is copied into shared memory with release
  // ordering.
  std::uint32_t version{network_plane_message_version};
  std::uint64_t id{};
  // Logical service identity is not encoded into a physical port ordinal.
  // Relay removal and later service commands use this independent field.
  std::uint64_t logical_interface_id{};
  NetworkCommandKind kind{};
  DeviceHandle device{};
  HostHandle host{};
  LinkHandle link{};
  ForwardPort port{};
  // FIB and RA programming are mutually exclusive command payloads. A variant
  // keeps the fixed SPSC slot at the largest program instead of adding the RA
  // option arrays to every route, ping and query message.
  std::variant<
      routing::FibProgram, routing::Ipv6FibProgram, Ipv6AddressGenerationBegin,
      RouterIpv6Address, StaticIpv6NeighborProgram, StaticIpv4NeighborProgram,
      RouterAdvertisementProgram, MldInterfaceProgram, SapGenerationBegin,
      service::SapAttachment, service::ServiceIpv6Interface, Dhcpv6RelayBegin,
      Dhcpv6RelayInterfaceIdChunk, dhcpv6::RelayDestination,
      Dhcpv6RelayLeaseClearProgram, NetworkDhcpv6ClientBegin,
      NetworkDhcpv6ClientAssociation, NetworkDhcpv6ServerBegin,
      dhcpv6::LeasePool, NetworkDnsResolverBegin, NetworkDnsRootHintBegin,
      dns::ServerAddress, NetworkDnsTrustAnchorBegin,
      NetworkDnsAuthoritativeBegin, NetworkDnsZoneBegin,
      NetworkDnsSigningKeyDefinition, NetworkDnsRecordBegin,
      NetworkDnsRdataChunk>
      fib{};
  HostNetworkProgram host_program{};
  NetworkLinkProgram link_program{};
  CapturePointProgram capture_program{};
  std::uint32_t destination{};
  packet::Ipv6 ipv6_destination{};
  packet::Ipv6 ipv6_source{};
  packet::Ipv4 host_destination{};
  std::uint16_t sequence{};
  std::uint16_t payload_octets{56};
  bool dont_fragment{};
  // A separate presence bit is required because physical ordinal zero is a
  // valid interface selector. The address uses destination, where zero means
  // that the command did not include an address selector.
  bool ipv4_neighbor_interface_specific{};
  // A separate presence bit is required because port ordinal zero is valid.
  // false requests a router-wide dynamic clear; true scopes it to port.ordinal.
  bool ipv6_neighbor_interface_specific{};
  bool mld_group_specific{};
  MldStaticOperation mld_static_operation{};
  MldSsmProgramOperation mld_ssm_operation{};
  MldSsmTranslation mld_ssm_translation{};
  std::uint32_t mld_ssm_expected_entries{};
  // One policy entry per command keeps the shared SPSC slot pointer-free.
  // begin carries count and default action; add carries the value; commit and
  // abort carry neither. The forwarding owner alone publishes the generation.
  mld::ImportPolicyProgramOperation mld_import_policy_operation{};
  mld::ImportPolicyEntry mld_import_policy_entry{};
  mld::ImportPolicyAction mld_import_policy_default_action{
      mld::ImportPolicyAction::accept};
  std::uint32_t mld_import_policy_expected_entries{};
  std::uint16_t dhcpv6_option_code{};
};

struct NetworkResult {
  // Producer: combined forwarding and link shard. Consumer: control shard.
  // Ring overflow is never ignored; the worker stops accepting another command
  // until the prior result can be published.
  std::uint32_t version{network_plane_message_version};
  std::uint64_t id{};
  NetworkCommandKind kind{};
  bool success{};
  // Query commands publish their scalar value here while success continues to
  // describe command validity. This avoids overloading false as both an absent
  // reply and a stale handle error.
  std::uint64_t value{};
};

struct NetworkPlaneChannels {
  // Capacity includes one deliberately unused SpscRing slot. Generated values
  // are emulator resources and not protocol or vendor scaling claims.
  SpscRing<NetworkCommand, device_catalog::network_command_ring_entries>
      commands;
  SpscRing<NetworkResult, device_catalog::network_result_ring_entries> results;
  SpscRing<NetworkSigningVaultInitialize, 2U> signing_vault;
};

} // namespace router::lab
