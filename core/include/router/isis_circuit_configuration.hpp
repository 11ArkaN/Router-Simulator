// Effective Hello data shared by LAN and P2P circuit owners. Each circuit owns
// its value and allocations; dependencies point only to wire composition and
// neighbor value types. Source-backed CLI resolution precedes construction.

#pragma once

#include "router/isis_hello_builder.hpp"
#include "router/isis_circuit_destinations.hpp"
#include "router/isis_neighbor_attributes.hpp"

#include <vector>

namespace router::isis {
struct CircuitHelloConfiguration {
  packet::Mac mac{};
  packet::Mac hello_destination{};
  std::vector<NeighborArea> areas;
  std::vector<std::uint8_t> protocols;
  std::vector<packet::Ipv4> ipv4_addresses;
  std::vector<packet::Ipv6> ipv6_addresses;
  std::vector<packet::isis::TopologyComponent> topologies;
  std::optional<packet::isis::InstanceFormat> instance_format;
  std::uint16_t wire_instance{};
  std::vector<std::uint16_t> instance_topologies;
  bool emit_instance{};
  bool padding{};
  // The outer key policy selects a borrowed current key per call. Circuit
  // state never retains secret plaintext or a lease into the vault.
  bool receive_authentication{};
  bool transmit_authentication{};
  bool strict_adjacency_check{};
  std::uint8_t maximum_area_addresses{};
  std::uint16_t holding_seconds{};
  std::chrono::microseconds hello_interval{};
  std::size_t maximum_pdu_octets{};
  std::size_t peer_attribute_octets{};
  // Explicit resolved L1/L2 update groups. Absence retains the experimental
  // shared-Hello transport; production configuration must resolve this value.
  std::optional<std::array<packet::Mac, 2U>> update_destinations;
  [[nodiscard]] CircuitDestinations destinations() const noexcept {
    return {hello_destination, update_destinations.value_or(std::array{hello_destination, hello_destination})};
  }
  // The AF owner controls assignment independently of configured NLPIDs.
  // Explicit raw circuit callers supply assigned addresses by default. Managed
  // circuits clear this gate until local link-local DAD has completed.
  bool ipv6_addresses_ready{true};
  bool operator==(const CircuitHelloConfiguration &) const = default;
};

// Effective configuration already passed circuit admission; transmit-auth
// callers have acquired a key. The returned views borrow this circuit and its
// area projection only until synchronous build_hello_frame returns. No state
// or key is retained. Media-specific headers and neighbors remain with callers.
[[nodiscard]] inline HelloContents circuit_hello_contents(const CircuitHelloConfiguration &configuration,
    std::span<const std::span<const std::uint8_t>> areas,
    std::optional<AuthenticationKey> key) noexcept {
  HelloContents contents;
  contents.header.maximum_area_addresses = configuration.maximum_area_addresses;
  contents.source = configuration.mac;
  contents.destination = configuration.hello_destination;
  contents.areas = areas;
  contents.protocols = configuration.protocols;
  contents.topologies = configuration.topologies;
  contents.ipv4_addresses = configuration.ipv4_addresses;
  if (configuration.ipv6_addresses_ready) contents.ipv6_addresses = configuration.ipv6_addresses;
  if (configuration.emit_instance) contents.instance = PduInstanceOption{
      configuration.instance_format.value_or(packet::isis::InstanceFormat::standard),
      configuration.wire_instance, configuration.instance_topologies};
  if (configuration.transmit_authentication) contents.authentication = key;
  contents.maximum_pdu_octets = configuration.maximum_pdu_octets;
  contents.padding = configuration.padding;
  return contents;
}
} // namespace router::isis
