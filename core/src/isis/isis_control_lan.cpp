// The permanent protocol pthread drives each admitted LAN level and consumes
// encoded Hello receipts. Callback contexts live only on the current stack;
// moving cold/live aggregates cannot leave retained observer pointers behind.

#include "router/isis_control_worker.hpp"

#include <algorithm>

namespace router::isis {
LanCircuitObserver ControlWorker::lan_observer(LanObserverContext &context) noexcept {
  return {&context, lan_peer, lan_designated};
}
void ControlWorker::lan_peer(void *opaque, const LanPeerEvent &value) noexcept {
  auto &owned = static_cast<LanObserverContext *>(opaque)->circuit;
  if (value.transition.outcome == LanOutcome::up) ++owned.counters.adjacency_up;
  if (value.transition.outcome == LanOutcome::down) ++owned.counters.adjacency_down;
}
void ControlWorker::lan_designated(void *opaque, const std::optional<DisSelection> &,
    const std::optional<DisSelection> &) noexcept {
  ++static_cast<LanObserverContext *>(opaque)->circuit.counters.designated_changes;
}
void ControlWorker::circuit_down(OwnedCircuit &owned) noexcept {
  owned.transmission.cancel();
  if (auto *broadcast = owned.lan()) {
    for (std::size_t level{}; level < 2U; ++level) {
      owned.lan_transmissions[level].cancel();
      if (auto *circuit = broadcast->at(level)) {
        LanObserverContext context{owned, level};
        static_cast<void>(circuit->down(lan_observer(context)));
      }
    }
  } else static_cast<void>(owned.p2p().down(&owned, event));
}
void ControlWorker::circuit_up(OwnedCircuit &owned, RuntimeClock::time_point now) noexcept {
  if (auto *broadcast = owned.lan()) {
    for (std::size_t level{}; level < 2U; ++level)
      if (auto *circuit = broadcast->at(level)) static_cast<void>(circuit->up(now));
  } else static_cast<void>(owned.p2p().up(now));
}
RuntimeClock::time_point ControlWorker::service_lan(OwnedCircuit &owned,
    RuntimeClock::time_point now, std::size_t &budget) noexcept {
  auto deadline = RuntimeClock::time_point::max();
  auto &channel = channels_.egress[owned.identity.device.index % forwarding_shards_];
  auto *broadcast = owned.lan();
  for (std::size_t level{}; level < 2U; ++level) if (auto *circuit = broadcast->at(level)) {
    LanObserverContext context{owned, level};
    const auto observer = lan_observer(context);
    circuit->service(now, device_catalog::isis_work_budget_packets, observer);
    if (budget && channel.producer_available()) {
      const auto built = circuit->hello(output_, std::nullopt, scratch_, now, observer);
      if (built) --budget;
      if (built && *built == HelloBuildResult::encoded) {
        auto &window = owned.lan_transmissions[level];
        const auto ticket = window.begin();
        if (!ticket) { ++owned.counters.transmission_exhausted; circuit_down(owned); return deadline; }
        const auto type = circuit->configuration().type;
        const bool published = channel.try_send({owned.identity.device, owned.identity.interface_id,
            owned.identity.physical_port_ordinal, owned.identity.configuration_generation, *ticket,
            static_cast<std::uint8_t>(type), owned.identity.instance}, output_);
        if (!published) {
          window.cancel();
          static_cast<void>(circuit->complete_hello(false, now));
        } else if (channels_.egress_wakeup)
          channels_.egress_wakeup(channels_.egress_context, owned.identity.device.index % forwarding_shards_);
      }
    }
    const auto next = circuit->deadline();
    if (next > now || channel.producer_available()) deadline = std::min(deadline, next);
    else if (const auto holding = circuit->neighbors().deadline()) deadline = std::min(deadline, *holding);
  }
  return deadline;
}
} // namespace router::isis
