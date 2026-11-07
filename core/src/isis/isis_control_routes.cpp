// The IS-IS pthread builds complete local route generations from its own
// accepted Hellos and revision-fenced decisions. The network owner alone installs
// them and returns an explicit receipt. No remote router state is accessible.

// Source: project.isis.route_publication

#include "router/isis_control_worker.hpp"
#include "router/isis_rib_input.hpp"

#include <algorithm>
#include <limits>

namespace router::isis {
namespace {
// RFC 1195 does not order the advertised interface addresses. The emulator's
// deterministic choice is the numerically lowest usable address, independent
// of TLV order. This does not infer an undocumented vendor address preference.
std::optional<AdjacencyNextHop> select_next_hop(const P2pSnapshot &adjacency,
    std::span<const std::uint8_t> attributes, std::span<const std::uint8_t> protocols,
    NextHopInterface interface, std::uint8_t level, ip::AddressFamily family) noexcept {
  std::optional<ip::IpAddress> selected;
  packet::isis::TlvCursor options(attributes);
  while (const auto option = options.next()) {
    if (family == ip::AddressFamily::ipv4 && option->code == 132U) {
      packet::isis::FixedAddressCursor<4U> addresses(*option, 132U);
      while (const auto address = addresses.next()) {
        if (!(*address)[0U] || (*address)[0U] == 127U || (*address)[0U] >= 224U) continue;
        ip::IpAddress value;
        std::copy(address->begin(), address->end(), value.bytes.begin());
        if (!selected || value < *selected) selected = value;
      }
      if (!addresses.valid()) return std::nullopt;
    } else if (family == ip::AddressFamily::ipv6 && option->code == 232U) {
      packet::isis::FixedAddressCursor<16U> addresses(*option, 232U);
      while (const auto address = addresses.next()) {
        if (!ip::is_link_local(*address)) continue;
        const ip::IpAddress value{family, *address};
        if (!selected || value < *selected) selected = value;
      }
      if (!addresses.valid()) return std::nullopt;
    }
  }
  return options.valid() && selected ?
      bind_p2p_next_hop(adjacency, attributes, protocols, interface, level, *selected) : std::nullopt;
}
}

void ControlWorker::complete_routes(RuntimeClock::time_point now) noexcept {
  while (const auto receipt = channels_.routes->try_completion()) {
    if (receipt->device.index >= devices_.size()) continue;
    auto &device = devices_[receipt->device.index];
    if (device.handle != receipt->device || device.route_pending != receipt->generation) continue;
    device.route_pending = 0U;
    device.route_status = receipt->status;
    if (receipt->status == ::router::routing::RouteInstallStatus::installed) {
      device.route_installed = receipt->generation;
      device.installed_routes = device.pending_routes;
      device.route_retry_at = {};
    } else device.route_retry_at = now + device.route_retry;
  }
}

RuntimeClock::time_point ControlWorker::service_routes(DeviceState &device,
    RuntimeClock::time_point now) noexcept {
  using Status = ::router::routing::RouteInstallStatus;
  const auto never = RuntimeClock::time_point::max();
  if (!device.active || device.route_pending) return never;
  RouteStamps current{};
  bool enabled{};
  auto retry = std::chrono::milliseconds::max();
  for (std::size_t index{}; index < device.instances.size(); ++index) {
    const auto &instance = device.instances[index];
    if (!instance) continue;
    std::uint8_t families{};
    for (std::size_t family{}; family < instance->configuration.routing.size(); ++family)
      if (instance->configuration.routing[family]) families |= static_cast<std::uint8_t>(1U << family);
    if (!families) continue;
    enabled = true;
    retry = std::min(retry, instance->configuration.origination->resource_retry);
    current[index] = {instance->process ? instance->process->maximum_synchronization_epoch() : device.update_fences[index],
        instance->decision_revisions, instance->status, families};
  }
  if (enabled) device.route_retry = retry;
  if ((!enabled && !device.route_generation) || current == device.installed_routes) return never;
  if (device.route_retry_at > now) return device.route_retry_at;
  const auto refuse = [&](Status status) {
    device.route_status = status;
    device.route_retry_at = now + device.route_retry;
    return device.route_retry_at;
  };
  // Every enabled family and level belongs to this exact local revision. A
  // failed calculation preserves the installed generation and retries only
  // at the explicitly configured emulator resource-recovery period.
  for (auto &instance : device.instances) if (instance && instance->status == UpdateStatus::applied) {
    for (auto &family : instance->route_families)
      for (std::size_t level{}; level < family.decisions.size(); ++level) {
        if (!family.decisions[level]) continue;
        if (family.consumed[level] != instance->decision_revisions[level]) return now;
        if (family.status[level] != DecisionStatus::applied) {
          if (device.route_status == Status::selection_failed && instance->decision_revisions[level]) {
            family.consumed[level] = 0U;
            device.route_status = Status::pending;
            return now;
          }
          return refuse(Status::selection_failed);
        }
      }
  }
  if (device.route_generation == std::numeric_limits<std::uint64_t>::max()) {
    device.route_status = Status::stale;
    return never;
  }
  const auto lease = channels_.routes->try_acquire();
  // A completion notifies this owner; a full ring must not busy-spin.
  if (!lease) return never;
  auto &output = *lease->generation;
  output.device = device.handle;
  output.generation = device.route_generation + 1U;
  output.ipv4_count = output.ipv6_count = 0U;
  Status failure = Status::pending;
  for (std::size_t index{}; index < device.instances.size() && failure == Status::pending; ++index) {
    const auto &instance = device.instances[index];
    if (!instance || instance->status != UpdateStatus::applied) continue;
    for (std::size_t family{}; family < instance->configuration.routing.size() && failure == Status::pending; ++family) {
      const auto &program = instance->configuration.routing[family];
      if (!program) continue;
      const auto &interfaces = *instance->configuration.origination->neighbors;
      for (std::size_t level{}; level < 2U && failure == Status::pending; ++level) {
        const auto &decision = instance->route_families[family].decisions[level];
        if (!decision) continue;
        std::array<std::optional<AdjacencyNextHop>, device_catalog::maximum_ecmp_paths> bindings{};
        for (const auto &owned : device.circuits) {
          if (owned.identity.instance != index) continue;
          const auto found = std::lower_bound(interfaces.begin(), interfaces.end(), owned.identity.interface_id,
              [](const auto &entry, auto id) { return entry.interface_id < id; });
          if (found == interfaces.end() || found->interface_id != owned.identity.interface_id) continue;
          const auto token = static_cast<std::size_t>(found - interfaces.begin());
          bindings[token] = select_next_hop(owned.p2p().adjacency(), owned.p2p().peer_attributes(),
              owned.p2p().configuration().protocols,
              {owned.identity.interface_id, owned.identity.configuration_generation, owned.identity.physical_port_ordinal},
              static_cast<std::uint8_t>(level + 1U), family ? ip::AddressFamily::ipv6 : ip::AddressFamily::ipv4);
        }
        const auto collected = visit_prefix_routes(*decision, std::span{bindings}.first(interfaces.size()),
            [&](std::size_t, const PrefixRouteCandidate &candidate) {
          const auto preference = candidate.external ? program->preferences[level].external : program->preferences[level].internal;
          if (family) {
            if (output.ipv6_count == output.ipv6.size()) { failure = Status::capacity; return false; }
            const auto mapped = make_ipv6_rib_input(candidate, static_cast<std::uint8_t>(index), preference);
            if (!mapped) { failure = Status::invalid; return false; }
            output.ipv6[output.ipv6_count++] = *mapped;
          } else {
            if (output.ipv4_count == output.ipv4.size()) { failure = Status::capacity; return false; }
            const auto mapped = make_ipv4_rib_input(candidate, static_cast<std::uint8_t>(index), preference);
            if (!mapped) { failure = Status::invalid; return false; }
            output.ipv4[output.ipv4_count++] = *mapped;
          }
          return true;
        });
        if (collected.status != PrefixRoutesStatus::applied && failure == Status::pending)
          failure = collected.status == PrefixRoutesStatus::capacity ? Status::capacity : Status::invalid;
      }
    }
  }
  if (failure != Status::pending) {
    if (!channels_.routes->cancel(lease->handle)) std::terminate();
    return refuse(failure);
  }
  const auto generation = output.generation;
  if (!channels_.routes->publish(lease->handle)) std::terminate();
  device.route_generation = generation;
  device.route_pending = generation;
  device.pending_routes = current;
  device.route_status = Status::pending;
  if (channels_.route_wakeup) channels_.route_wakeup(channels_.route_wakeup_context);
  return never;
}
} // namespace router::isis
