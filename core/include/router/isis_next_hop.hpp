// Bind a caller-selected IP next hop to one accepted P2P Hello and its local
// interface generation. Values own their bytes; only the instance control
// owner may supply adjacency/attribute snapshots from the same circuit turn.
// Dependencies point to packet and adjacency values, never forwarding state.

// Source: ietf.isis.adjacency_next_hop_binding

#pragma once

#include "router/isis_basic_tlvs.hpp"
#include "router/isis_p2p_adjacency.hpp"
#include "router/generated_device_catalog.hpp"

namespace router::isis {
struct NextHopInterface {
  std::uint64_t interface_id{}, configuration_generation{};
  std::uint16_t physical_port_ordinal{};
  bool operator==(const NextHopInterface &) const = default;
};
struct AdjacencyNextHop {
  NextHopInterface interface;
  packet::isis::SystemId peer{};
  ip::IpAddress address;
  std::uint8_t level{};
  bool operator==(const AdjacencyNextHop &) const = default;
};
// Requires accepted attributes and the current adjacency/configuration from
// one owner turn. The caller chooses an address; this binder never invents a
// vendor multiple-address preference. Both local and peer NLPIDs must support
// its family, the requested level must be Up and the address must occur in
// that peer's Hello. IPv6 is scoped to the stable logical interface, not just
// its physical port. IPv4 subnet equality is deliberately not required
// (RFC 1195 section 4.4). No MAC is copied or installed; ARP/ND remain separate.
// No allocation or retained views. Any invalid input, malformed trailing TLV
// or absent address returns nullopt without publishing a partial binding.
[[nodiscard]] inline std::optional<AdjacencyNextHop> bind_p2p_next_hop(
    const P2pSnapshot &adjacency, std::span<const std::uint8_t> attributes,
    std::span<const std::uint8_t> local_protocols, NextHopInterface interface,
    std::uint8_t level, const ip::IpAddress &selected) noexcept {
  using namespace packet::isis;
  if (!adjacency.present || !adjacency.iso_up || level < 1U || level > 2U ||
      !(static_cast<std::uint8_t>(adjacency.usage) & (1U << (level - 1U))) ||
      !interface.interface_id || !interface.configuration_generation ||
      interface.physical_port_ordinal >= device_catalog::maximum_ports_per_router ||
      (selected.family != ip::AddressFamily::ipv4 && selected.family != ip::AddressFamily::ipv6))
    return std::nullopt;
  if (selected.family == ip::AddressFamily::ipv4 &&
      (!selected.bytes[0U] || selected.bytes[0U] == 127U || selected.bytes[0U] >= 224U))
    return std::nullopt;
  const auto protocol = selected.family == ip::AddressFamily::ipv4 ? ipv4_nlpid : ipv6_nlpid;
  if (std::find(local_protocols.begin(), local_protocols.end(), protocol) == local_protocols.end())
    return std::nullopt;
  bool peer_supports{}, advertised{};
  TlvCursor options(attributes);
  while (const auto option = options.next()) {
    if (option->code == 129U) peer_supports = peer_supports || supports_protocol(*option, protocol);
    if (option->code == 132U) {
      FixedAddressCursor<4U> addresses(*option, 132U);
      while (const auto address = addresses.next()) {
        ip::IpAddress value;
        std::copy(address->begin(), address->end(), value.bytes.begin());
        advertised = advertised || value == selected;
      }
      if (!addresses.valid()) return std::nullopt;
    }
    if (option->code == 232U) {
      if (!valid_ipv6_interface_addresses(*option, PduType::point_to_point_hello)) return std::nullopt;
      FixedAddressCursor<16U> addresses(*option, 232U);
      while (const auto address = addresses.next())
        advertised = advertised || ip::IpAddress{ip::AddressFamily::ipv6, *address} == selected;
    }
  }
  if (!options.valid() || !peer_supports || !advertised) return std::nullopt;
  return AdjacencyNextHop{interface, adjacency.neighbor_system, selected, level};
}
} // namespace router::isis
