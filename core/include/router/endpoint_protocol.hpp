// Value contracts for one forwarding-owned host endpoint stack. The endpoint
// has no topology or router access and persists only protocol values and wire
// frames. NetworkPlane is the sole owner that may configure or checkpoint it.

#pragma once

#include "router/generated_device_catalog.hpp"
#include "router/ipv4_reassembly.hpp"
#include "router/ipv4_path_mtu.hpp"
#include "router/ipv6_dad.hpp"
#include "router/ipv6_destination_cache.hpp"
#include "router/ipv6_host_autoconfiguration.hpp"
#include "router/ipv6_fragmentation.hpp"
#include "router/ipv6_neighbor_cache.hpp"
#include "router/ipv6_path_mtu.hpp"
#include "router/mld_listener.hpp"
#include "router/packet.hpp"
#include "router/udp_transport.hpp"
#include "router/ikev2_udp_service.hpp"
#include "router/tcp_endpoint.hpp"

#include <cstddef>
#include <cstdint>
#include <optional>
#include <vector>

namespace router {

// This ABI bound is derived from two independent release facts: the smallest
// configurable host IPv4 MTU and the largest ping payload accepted by the CLI.
// Checkpoint decoding and the live endpoint arena share it so neither can
// silently retain the old four-frame starter-topology ceiling.
inline constexpr std::size_t minimum_endpoint_ipv4_fragment_payload =
    ((device_catalog::minimum_host_ipv4_mtu - 20U) / 8U) * 8U;
inline constexpr std::size_t maximum_endpoint_echo_ip_payload =
    8U + device_catalog::maximum_ping_payload_octets;
inline constexpr std::size_t maximum_endpoint_pending_ipv4_fragments =
    (maximum_endpoint_echo_ip_payload +
     minimum_endpoint_ipv4_fragment_payload - 1U) /
    minimum_endpoint_ipv4_fragment_payload;

struct NetworkEndpointConfiguration {
  // Each HostSlot owns exactly one stack, so configuration contains only its
  // protocol identity. Link and router state remain in their respective owners.
  packet::Mac endpoint_mac{};
  packet::Ipv4 endpoint_address{};
  std::uint8_t endpoint_prefix_length{};
  packet::Ipv4 endpoint_gateway{};
  std::uint16_t endpoint_mtu{device_catalog::default_host_ipv4_mtu};
  // IPv6 capability is explicit. An IPv4-only host with a sub-1280 MTU must
  // not accidentally start SLAAC merely because both families share Ethernet.
  std::uint64_t endpoint_interface_id{};
  bool endpoint_ipv6_autoconfiguration{};
  host::Ipv6InterfaceIdentifierConfiguration endpoint_ipv6_identifier{};
  crypto::Sha256Digest endpoint_transport_secret{};
};

struct NetworkStoredFrame {
  // Only the host endpoint's unresolved IPv4 batch belongs to this state.
  // Fabric and router queues have their own checkpoint owners and must not be
  // smuggled through a host record using a stage discriminator.
  packet::Ipv4 next_hop{};
  packet::Frame frame{};
};

struct NetworkEndpointState {
  bool neighbor_valid{};
  packet::Ipv4 neighbor_address{};
  packet::Mac neighbor_mac{};
  bool pending_next_hop_valid{};
  packet::Ipv4 pending_next_hop{};
  // The source ID is part of IPv4 wire behavior, not transient UI state. It is
  // advanced only after a complete fragmented batch enters the output owner.
  std::uint16_t next_ipv4_identification{1U};
  // PMTU reports are accepted only for the exact most recent locally emitted
  // DF datagram. Persisting the packet bytes retains that security property
  // across restore instead of weakening it to an address or sequence match.
  packet::Ipv4 ipv4_probe_destination{};
  packet::Frame ipv4_probe_packet{};
  bool ipv4_probe_valid{};
};

struct NetworkEndpointIpv6State {
  // Host autoconfiguration and DAD have separate state owners even though one
  // forwarding shard drives both. Their checkpoint images stay separate so a
  // future DHCPv6 owner cannot mutate SLAAC lifetime repositories directly.
  host::Ipv6HostAutoconfigurationCheckpoint autoconfiguration;
  std::vector<lab::Ipv6DadCheckpoint> dad;
  // Redirect updates two independently owned RFC 4861 repositories. Keeping
  // both images explicit prevents restore from deriving a MAC from a cached
  // next hop or silently losing the STALE reachability state required by ND.
  std::vector<lab::Ipv6NeighborCheckpoint> neighbors;
  std::vector<lab::Ipv6DestinationCheckpoint> destinations;
  std::vector<ip::Ipv6PathMtuCheckpoint> path_mtu;
  lab::MldListenerCheckpoint mld;
  // RFC 7217 assigns one DAD counter to the stable link-local prefix tuple.
  // It is endpoint-owned and persisted separately from SLAAC counters because
  // link-local creation does not belong to the RA-driven address repository.
  std::uint32_t link_local_dad_counter{};
  std::uint32_t next_fragment_identification{1U};
  bool link_local_generation_exhausted{};
  std::int64_t router_solicitation_remaining_nanoseconds{};
  std::uint8_t router_solicitations_sent{};
  bool router_solicitation_active{};
};

struct NetworkCheckpointState {
  // One checkpoint belongs to one HostSlot. Keeping one endpoint value avoids
  // multiplying an obsolete starter-topology array across all sixteen hosts.
  NetworkEndpointState endpoint{};
  std::vector<packet::Ipv4ReassemblyCheckpoint> ipv4_reassembly;
  std::vector<ip::Ipv4PathMtuCheckpoint> ipv4_path_mtu;
  NetworkEndpointIpv6State ipv6{};
  std::vector<packet::Ipv6ReassemblyCheckpoint> ipv6_reassembly;
  transport::UdpEndpointCheckpoint udp{};
  ikev2::UdpServiceCheckpoint ike_udp{};
  std::optional<transport::tcp::EndpointCheckpoint> tcp;
  std::vector<NetworkStoredFrame> frames;
};

} // namespace router
