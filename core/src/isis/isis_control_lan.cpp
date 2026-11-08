// The permanent protocol pthread drives each admitted LAN level and consumes
// encoded Hello receipts. Callback contexts live only on the current stack;
// moving cold/live aggregates cannot leave retained observer pointers behind.

#include "router/isis_control_worker.hpp"

#include <algorithm>

namespace router::isis {
UpdateStatus ControlWorker::project_lan(OwnedCircuit &owned, OwnedInstance &instance,
    std::size_t slot, std::size_t level) noexcept {
  auto *broadcast = owned.lan();
  auto *circuit = broadcast ? broadcast->at(level) : nullptr;
  if (!circuit || !instance.process) return UpdateStatus::invalid_circuit;
  auto &peers = owned.update_peers[level];
  peers.clear();
  for (std::size_t index{}; index < circuit->neighbors().size(); ++index) {
    if (peers.size() == peers.capacity()) return UpdateStatus::capacity;
    peers.push_back(circuit->neighbors().at(index)->adjacency.mac);
  }
  const auto role = circuit->designated();
  return instance.process->lan(slot, owned.identity.configuration_generation, level,
      peers, !peers.empty() && role && role->local, instance.observer());
}
void ControlWorker::synchronize_lan(OwnedCircuit &owned, std::size_t level) noexcept {
  if (!owned.update || owned.update->status != UpdateStatus::applied) return;
  const auto result = project_lan(owned, *owned.update, owned.update_slot, level);
  if (result != UpdateStatus::applied) { owned.update->status = result; return; }
  if (!owned.update_egress) return;
  auto &egress = *owned.update_egress;
  const auto output = owned.update->process->outputs(owned.update_slot, level);
  if (egress.lan_lsp && egress.lan_lsp->level == level && (!output ||
      output->synchronization_epoch != egress.lan_lsp->epoch || !output->reservations.lsp.pending())) {
    if (egress.broadcast_scan) static_cast<void>(egress.broadcast_scan->complete(false, RuntimeClock::now()));
    egress.lan_lsp.reset();
  }
  if (egress.lan_csnp && egress.lan_csnp->level == level && (!output ||
      output->synchronization_epoch != egress.lan_csnp->epoch || !output->reservations.snp.pending()))
    egress.lan_csnp.reset();
  if (!output) {
    egress.epochs[level] = 0U;
    if (!owned.update->process->outputs(owned.update_slot, 1U - level)) egress.lan_active = false;
  }
}
void ControlWorker::classify_lan_backlog() noexcept {
  bool active{};
  for (auto &device : devices_) for (auto &owned : device.circuits) {
    owned.queued_lsp = false;
    active = active || (owned.carrier && owned.lan() && owned.update &&
        owned.update->admin_enabled && owned.update->status == UpdateStatus::applied);
  }
  if (!active) return;
  for (std::size_t shard{}; shard < forwarding_shards_; ++shard)
    static_cast<void>(channels_.ingress[shard].consumer_any_ready([&](const auto &metadata,
        const packet::Frame &frame) noexcept {
      using packet::isis::PduType;
      if (metadata.transmission_class && metadata.transmission_class != static_cast<std::uint8_t>(PduType::lsp_l1) &&
          metadata.transmission_class != static_cast<std::uint8_t>(PduType::lsp_l2)) return false;
      if (metadata.device.index >= devices_.size() || metadata.device.index % forwarding_shards_ != shard) return false;
      auto &device = devices_[metadata.device.index];
      if (!device.active || device.handle != metadata.device) return false;
      packet::isis::EthernetDecodeError error{};
      const auto wire = packet::isis::parse_ethernet_pdu(frame.view(), error);
      if (!wire || (wire->pdu.type != PduType::lsp_l1 && wire->pdu.type != PduType::lsp_l2)) return false;
      const auto level = wire->pdu.type == PduType::lsp_l1 ? 0U : 1U;
      for (auto &owned : device.circuits) {
        const auto *broadcast = owned.lan();
        if (!broadcast || !broadcast->at(level) || !owned.update || owned.update->status != UpdateStatus::applied ||
            owned.identity.interface_id != metadata.interface_id || owned.identity.instance != metadata.instance_id ||
            owned.identity.physical_port_ordinal != metadata.physical_port_ordinal ||
            owned.identity.configuration_generation != metadata.configuration_generation ||
            owned.destinations.select(wire->pdu.type) != wire->ethernet.destination) continue;
        packet::isis::InstanceError instance_error{};
        const auto selected = packet::isis::select_instance(wire->pdu, owned.format, false, instance_error);
        if (selected && selected->instance == owned.wire_instance) owned.queued_lsp = true;
      }
      // Visit the entire captured extent, retaining only same-owner booleans.
      return false;
    }));
}
LanCircuitObserver ControlWorker::lan_observer(LanObserverContext &context) noexcept {
  return {&context, lan_peer, lan_designated};
}
void ControlWorker::lan_peer(void *opaque, const LanPeerEvent &value) noexcept {
  auto &context = *static_cast<LanObserverContext *>(opaque);
  auto &owned = context.circuit;
  synchronize_lan(owned, context.level);
  if (owned.update && owned.update->status == UpdateStatus::applied &&
      ((value.before.adjacency.state == LanState::up) != (value.after.adjacency.state == LanState::up) ||
       (value.after.adjacency.state == LanState::up && !std::equal(value.before.attributes.begin(),
           value.before.attributes.end(), value.after.attributes.begin(), value.after.attributes.end()))))
    OwnedInstance::level_event(owned.update, {LevelEventKind::circuit_changed,
        context.level ? packet::isis::PduType::lsp_l2 : packet::isis::PduType::lsp_l1, std::nullopt});
  if (value.transition.outcome == LanOutcome::up) ++owned.counters.adjacency_up;
  if (value.transition.outcome == LanOutcome::down) ++owned.counters.adjacency_down;
}
void ControlWorker::lan_designated(void *opaque, const std::optional<DisSelection> &before,
    const std::optional<DisSelection> &after) noexcept {
  auto &context = *static_cast<LanObserverContext *>(opaque);
  ++context.circuit.counters.designated_changes;
  auto &previous = context.circuit.previous_dis[context.level];
  if (!after || !after->local) previous.fragment = 256U;
  const auto local_system = context.circuit.update_view().system;
  if (after && !after->local) previous.remote = after->lan[6U] &&
      !std::equal(local_system.begin(), local_system.end(), after->lan.begin())
      ? std::optional{after->lan} : std::nullopt;
  if (after && after->local && (!before || !before->local) && previous.remote) {
    previous.fragment = 0U;
    previous.retry = RuntimeClock::time_point::min();
  }
  synchronize_lan(context.circuit, context.level);
  // A remote DIS change alters the root's pseudonode edge even when this
  // router remains non-DIS and the accepted MAC catalog stays identical.
  if (context.circuit.update && context.circuit.update->status == UpdateStatus::applied)
    OwnedInstance::level_event(context.circuit.update, {LevelEventKind::circuit_changed,
        context.level ? packet::isis::PduType::lsp_l2 : packet::isis::PduType::lsp_l1, std::nullopt});
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
  if (!owned.carrier || (owned.update && !owned.update->admin_enabled)) return;
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
    // The owner turn already serviced expiration/election before origination.
    // Only a due Hello needs the circuit's standalone service/build path again.
    if (budget && channel.producer_available() && circuit->deadline() <= now) {
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
