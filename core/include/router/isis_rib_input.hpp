// Convert copied IS-IS prefix decisions into router-owned RIB inputs. The
// protocol owner supplies effective preference and local instance identity;
// this stateless adapter neither selects addresses nor programs forwarding.

// Source: nokia.sros.26_7.isis.shared_rib_selection

#pragma once

#include "router/isis_prefix_routes.hpp"
#include "router/multi_device_routing.hpp"

#include <type_traits>

namespace router::isis {
namespace rib_detail {
// Same-shard immutable values only. Invalid family, distance class, preference,
// instance, canonical prefix or adjacency scope rejects before a value escapes.
// No allocation, retained views or default preference selection occurs here.
template <typename Input>
[[nodiscard]] std::optional<Input> convert(const PrefixRouteCandidate &candidate,
    std::uint8_t instance, std::uint16_t preference) noexcept {
  using namespace lab::routing;
  constexpr bool ipv6 = std::is_same_v<Input, Ipv6DynamicInput>;
  constexpr auto family = ipv6 ? ip::AddressFamily::ipv6 : ip::AddressFamily::ipv4;
  const auto &hop = candidate.next_hop;
  if (candidate.destination.network.family != family || hop.address.family != family ||
      candidate.destination.length > ip::address_bits(family) ||
      ip::mask(candidate.destination.network, candidate.destination.length) != candidate.destination.network ||
      !hop.interface.interface_id || !hop.interface.configuration_generation ||
      hop.interface.physical_port_ordinal >= device_catalog::maximum_ports_per_router ||
      (hop.level != 1U && hop.level != 2U) || instance > device_catalog::isis_instance_last ||
      preference < 1U || preference > 255U) return std::nullopt;
  const auto type = hop.level == 1U ?
      (candidate.external ? IsisPathType::level1_external : IsisPathType::level1_internal) :
      (candidate.external ? IsisPathType::level2_external : IsisPathType::level2_internal);
  if (!valid_route_path(RouteSource::isis, OspfPathType::none, type, candidate.distance.rank, ipv6))
    return std::nullopt;
  const auto expected_rank = ipv6 ? (hop.level == 1U ? (candidate.down ? 3U : 0U) : (candidate.down ? 2U : 1U)) :
      (hop.level == 1U ? (candidate.down ? 2U : 0U) : 1U);
  const bool external_metric = !ipv6 && candidate.distance.rank >= 3U;
  if (candidate.distance.rank != expected_rank + (external_metric ? 3U : 0U) ||
      candidate.distance.metric > packet::isis::maximum_path_metric ||
      (external_metric ? candidate.distance.metric > 63U || candidate.distance.internal_metric > 1023U :
                         candidate.distance.internal_metric != 0U)) return std::nullopt;
  Input result{};
  result.configured = result.operational = true;
  if constexpr (ipv6) {
    if (!ip::is_link_local(hop.address.bytes)) return std::nullopt;
    result.network = candidate.destination.network.bytes;
    result.next_hop = hop.address.bytes;
    result.physical_port_ordinal = hop.interface.physical_port_ordinal;
  } else {
    for (std::size_t index = 4U; index < hop.address.bytes.size(); ++index)
      if (hop.address.bytes[index] || candidate.destination.network.bytes[index]) return std::nullopt;
    if (!hop.address.bytes[0U] || hop.address.bytes[0U] == 127U || hop.address.bytes[0U] >= 224U)
      return std::nullopt;
    const auto &network = candidate.destination.network.bytes;
    const auto &next_hop = hop.address.bytes;
    result.network = ipv4(network[0U], network[1U], network[2U], network[3U]);
    result.next_hop = ipv4(next_hop[0U], next_hop[1U], next_hop[2U], next_hop[3U]);
    result.port_ordinal = hop.interface.physical_port_ordinal;
  }
  result.preference = preference;
  result.metric = candidate.distance.metric;
  result.internal_metric = candidate.distance.internal_metric;
  result.prefix_length = candidate.destination.length;
  result.source = RouteSource::isis;
  result.ospf_path_type = OspfPathType::none;
  result.protocol_instance = instance;
  result.interface_id = hop.interface.interface_id;
  result.interface_generation = hop.interface.configuration_generation;
  result.isis_path_type = type;
  result.isis_rank = candidate.distance.rank;
  return result;
}
} // namespace rib_detail
// Requires a complete current decision and binding owned by the caller. Returns
// a copied typed candidate, or nullopt on invalid input; no RIB mutation occurs.
[[nodiscard]] inline std::optional<lab::routing::DynamicInput> make_ipv4_rib_input(
    const PrefixRouteCandidate &candidate, std::uint8_t instance, std::uint16_t preference) noexcept {
  return rib_detail::convert<lab::routing::DynamicInput>(candidate, instance, preference);
}
[[nodiscard]] inline std::optional<lab::routing::Ipv6DynamicInput> make_ipv6_rib_input(
    const PrefixRouteCandidate &candidate, std::uint8_t instance, std::uint16_t preference) noexcept {
  return rib_detail::convert<lab::routing::Ipv6DynamicInput>(candidate, instance, preference);
}
} // namespace router::isis
