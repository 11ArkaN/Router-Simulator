// The protocol owner snapshots its accepted adjacency state in one command.
// All reads and allocation occur on that owner. The matching response release
// publishes the complete detached result without changing a protocol timer.
#include "router/isis_operational.hpp"
#include <algorithm>
#include <tuple>
namespace router::isis {
ControlError ControlWorker::query_adjacencies(const DeviceState &device, AdjacencyQuery &query) noexcept {
  const auto fail = [&](ControlError error) { query.rows.clear(); return error; };
  if (query.version != 1U || query.device != device.handle ||
      query.instance > device_catalog::isis_instance_last || !query.maximum_rows ||
      !query.maximum_attribute_octets || !query.rows.empty()) return fail(ControlError::invalid_argument);
  const auto now = RuntimeClock::now();
  const auto remaining = [&](std::optional<RuntimeClock::time_point> deadline) {
    return deadline && *deadline > now ? std::chrono::duration_cast<std::chrono::nanoseconds>(*deadline - now) :
        std::chrono::nanoseconds{};
  };
  std::size_t attributes{};
  try {
    std::size_t count{};
    for (const auto &circuit : device.circuits) if (circuit.identity.instance == query.instance) {
      if (const auto *lan = circuit.lan()) {
        for (std::size_t level{}; level < 2U; ++level) if (const auto *medium = lan->at(level)) {
          const auto peers = medium->neighbors().size();
          if (peers > query.maximum_rows - count) return fail(ControlError::capacity);
          count += peers;
        }
      } else if (circuit.p2p().adjacency().present) {
        if (count == query.maximum_rows) return fail(ControlError::capacity);
        ++count;
      }
    }
    query.rows.reserve(count);
    const auto append = [&](const CircuitIdentity &circuit, const packet::isis::SystemId &system,
        const packet::Mac &snpa, Levels usage, bool up, std::optional<RuntimeClock::time_point> deadline,
        std::span<const std::uint8_t> bytes) {
      if (query.rows.size() == query.maximum_rows || bytes.size() > query.maximum_attribute_octets - attributes) return false;
      query.rows.push_back({circuit, system, snpa, usage,
          up ? OperationalAdjacencyState::up : OperationalAdjacencyState::initializing,
          remaining(deadline), {bytes.begin(), bytes.end()}});
      attributes += bytes.size();
      return true;
    };
    for (const auto &circuit : device.circuits) {
      if (circuit.identity.instance != query.instance) continue;
      if (const auto *lan = circuit.lan()) {
        for (std::size_t level{}; level < 2U; ++level) if (const auto *medium = lan->at(level))
          for (std::size_t index{}; index < medium->neighbors().size(); ++index) {
            const auto peer = medium->neighbors().at(index);
            if (peer && peer->adjacency.present && !append(circuit.identity, peer->adjacency.system,
                peer->adjacency.mac, static_cast<Levels>(1U << level), peer->adjacency.state == LanState::up,
                medium->neighbors().holding_deadline(index), peer->attributes)) return fail(ControlError::capacity);
          }
      } else {
        const auto peer = circuit.p2p().adjacency();
        if (peer.present && !append(circuit.identity, peer.neighbor_system, peer.neighbor_mac, peer.usage,
            peer.iso_up && (!peer.uses_three_way || peer.three_way == ThreeWayState::up),
            circuit.p2p().holding_deadline(), circuit.p2p().peer_attributes())) return fail(ControlError::capacity);
      }
    }
    std::sort(query.rows.begin(), query.rows.end(), [](const auto &a, const auto &b) {
      return std::tie(a.circuit.interface_id, a.system, a.usage, a.snpa) <
          std::tie(b.circuit.interface_id, b.system, b.usage, b.snpa);
    });
    return ControlError::none;
  } catch (const std::bad_alloc &) { return fail(ControlError::capacity); }
    catch (const std::length_error &) { return fail(ControlError::capacity); }
}
}
