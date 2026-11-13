// One forwarding writer coalesces AF readiness and retries bounded publication.
// The subscription owns keys and acknowledgements. DAD state is borrowed only
// for the current call; no protocol pointer, clock or queue storage is retained.
#include "router/ipv6_readiness_projection.hpp"
#include <algorithm>
#include <stdexcept>
#include <tuple>
namespace router::lab {
Ipv6ReadinessProjection::Ipv6ReadinessProjection(DeviceHandle device, std::uint64_t generation,
    std::span<const Ipv6ReadinessWatch> watches, std::size_t maximum_watches)
    : device_(device), configuration_generation_(generation) {
  if (!device || device.index >= device_catalog::maximum_routers || !generation ||
      watches.size() > maximum_watches) throw std::invalid_argument("IPv6 AF readiness subscription refused");
  states_.reserve(watches.size());
  for (const auto &watch : watches) {
    if (!watch.interface_id || watch.port_ordinal >= device_catalog::maximum_ports_per_router ||
        ip::is_unspecified(watch.address) || ip::is_multicast(watch.address))
      throw std::invalid_argument("IPv6 AF readiness address refused");
    states_.push_back({watch, {}, false});
  }
  const auto key = [](const State &value) { return std::tie(value.source.interface_id, value.source.address); };
  std::sort(states_.begin(), states_.end(), [&](const auto &a, const auto &b) { return key(a) < key(b); });
  if (std::adjacent_find(states_.begin(), states_.end(),
      [&](const auto &a, const auto &b) { return key(a) == key(b); }) != states_.end())
    throw std::invalid_argument("IPv6 AF readiness duplicate subscription");
}
Ipv6ReadinessPublication Ipv6ReadinessProjection::publish(const Ipv6DadTable &dad,
    void *context, Sink sink) noexcept {
  if (!sink) return Ipv6ReadinessPublication::blocked;
  if (dad.readiness_changed(observed_)) {
    for (auto &state : states_) state.desired = dad.preferred_on_port(state.source.interface_id, state.source.port_ordinal, state.source.address);
    observed_ = dad.readiness_revision(); pending_ = true;
  }
  if (!pending_) return Ipv6ReadinessPublication::idle;
  for (auto &state : states_) if (!state.published || *state.published != state.desired) {
    const Ipv6ReadinessChange change{1U, device_, configuration_generation_, state.source, state.desired};
    if (!sink(context, change)) return Ipv6ReadinessPublication::blocked;
    state.published = state.desired;
  }
  pending_ = false;
  return Ipv6ReadinessPublication::complete;
}
}
