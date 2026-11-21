// Compact RIB feedback preserves original candidate identity through cold
// filtering. The network owner supplies committed primary selections; protocol
// attributes, template lifetimes and SPSC delivery remain separate owners.
// Source: ietf.isis.selected_interlevel_export
#include "router/isis_route_selection.hpp"
#include <algorithm>
#include <type_traits>
namespace router::routing {
namespace {
bool identity_valid(IsisSelectionIdentity identity) noexcept {
  return identity.device.generation && identity.device.index < device_catalog::maximum_routers &&
      identity.publication && identity.configuration_epoch && identity.revision;
}
template <typename Entry> bool selected_primary(std::span<const Entry> rows, const auto &candidate) noexcept {
  const auto network = [&] {
    if constexpr (std::is_integral_v<decltype(candidate.network)>)
      return candidate.network & lab::routing::prefix_mask(candidate.prefix_length);
    else return candidate.network;
  }();
  auto found = std::lower_bound(rows.begin(), rows.end(), std::pair{network, candidate.prefix_length},
      [](const auto &row, const auto &key) {
        return row.network != key.first ? row.network < key.first : row.prefix_length > key.second;
      });
  for (; found != rows.end() && found->network == network && found->prefix_length == candidate.prefix_length; ++found) {
    const bool port = [&] {
      if constexpr (requires { found->port_ordinal; }) return found->port_ordinal == candidate.port_ordinal;
      else return found->physical_port_ordinal == candidate.physical_port_ordinal;
    }();
    if (found->source == lab::routing::RouteSource::isis && found->next_hop == candidate.next_hop &&
        found->preference == candidate.preference && found->metric == candidate.metric &&
        found->protocol_instance == candidate.protocol_instance && found->isis_path_type == candidate.isis_path_type &&
        found->isis_rank == candidate.isis_rank && found->ospf_path_type == candidate.ospf_path_type && port &&
        found->interface_id == candidate.interface_id && found->interface_generation == candidate.interface_generation) return true;
  }
  return false;
}
template <typename Entry> IsisSelectionStatus project_family(const IsisSelectionInput<Entry> &input,
    const auto &table, std::span<bool> scratch, std::span<std::uint64_t> output) noexcept {
  constexpr auto capacity = device_catalog::maximum_dynamic_routes_per_router;
  if (input.original_count > capacity || input.competing.size() > capacity ||
      input.candidates.size() > capacity - input.competing.size()) return IsisSelectionStatus::capacity;
  if ((!input.ordinals.empty() && (input.ordinals.size() != input.candidates.size() ||
          input.ordinals.back() >= input.original_count || std::adjacent_find(input.ordinals.begin(), input.ordinals.end(),
              [](auto a, auto b) { return a >= b; }) != input.ordinals.end())) ||
      (input.ordinals.empty() && !input.candidates.empty() && input.original_count != input.candidates.size()) ||
      !table.last_rebuild_valid()) return IsisSelectionStatus::invalid;
  constexpr bool ipv6 = std::is_same_v<Entry, lab::routing::Ipv6DynamicInput>;
  for (const auto &entry : input.candidates)
    if (entry.source != lab::routing::RouteSource::isis || entry.prefix_length > (ipv6 ? 128U : 32U) ||
        !lab::routing::valid_route_path(entry.source, entry.ospf_path_type, entry.isis_path_type, entry.isis_rank, ipv6))
      return IsisSelectionStatus::invalid;
  const auto count = input.competing.size() + input.candidates.size();
  if (!lab::routing::select_isis_candidates(input.competing, input.candidates, scratch.first(count)))
    return IsisSelectionStatus::invalid;
  for (std::size_t index{}; index < input.candidates.size(); ++index) {
    if (!scratch[input.competing.size() + index] || !selected_primary(table.routes(), input.candidates[index])) continue;
    const auto ordinal = input.ordinals.empty() ? index : input.ordinals[index];
    output[ordinal / 64U] |= UINT64_C(1) << (ordinal % 64U);
  }
  return IsisSelectionStatus::applied;
}
}
bool valid_isis_route_selection(const IsisRouteSelection &value) noexcept {
  if (value.version != 1U || !identity_valid(value.identity)) return false;
  for (std::size_t family{}; family < value.counts.size(); ++family) {
    const auto count = value.counts[family];
    if (count > device_catalog::maximum_dynamic_routes_per_router) return false;
    const auto used = (count + 63U) / 64U;
    if (count % 64U && (value.selected[family][used - 1U] >> (count % 64U))) return false;
    if (std::any_of(value.selected[family].begin() + used, value.selected[family].end(), [](auto word) { return word != 0U; })) return false;
  }
  return true;
}
IsisSelectionStatus project_isis_route_selection(IsisSelectionIdentity identity,
    const IsisSelectionInput<lab::routing::DynamicInput> &ipv4,
    const IsisSelectionInput<lab::routing::Ipv6DynamicInput> &ipv6,
    const lab::routing::RouteTable &table4, const lab::routing::Ipv6RouteTable &table6,
    IsisRouteSelection &output) noexcept {
  if (!identity_valid(identity)) return IsisSelectionStatus::invalid;
  IsisRouteSelection result;
  result.identity = identity;
  result.counts = {ipv4.original_count, ipv6.original_count};
  std::array<bool, device_catalog::maximum_dynamic_routes_per_router> scratch{};
  for (const auto status : {project_family(ipv4, table4, scratch, result.selected[0U]),
      project_family(ipv6, table6, scratch, result.selected[1U])})
    if (status != IsisSelectionStatus::applied) return status;
  output = result;
  return IsisSelectionStatus::applied;
}
}
