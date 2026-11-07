// One interface control owner selects a LAN LSP from both level SRM catalogs.
// ISO 10589 7.3.15.6 pacing and queued-input inhibition commit only on matching
// physical receipts. This module borrows local databases and never copies peers.

#include "router/isis_control_worker.hpp"

#include <algorithm>

namespace router::isis {
RuntimeClock::time_point ControlWorker::emit_broadcast_lsp(OwnedCircuit &owned,
    RuntimeClock::time_point now, std::size_t &budget, std::size_t maximum_pdu) noexcept {
  const auto never = RuntimeClock::time_point::max();
  auto &instance = *owned.update;
  auto &egress = *owned.update_egress;
  if (!egress.broadcast_scan || !egress.program.pacing_burst || egress.lan_lsp) return never;
  const auto shard = owned.identity.device.index % forwarding_shards_;
  auto &channel = channels_.egress[shard];
  if (!channel.producer_available()) return never;
  std::array<BroadcastLevel, 2U> catalogs{};
  bool active{};
  for (std::size_t level{}; level < catalogs.size(); ++level) {
    const auto output = instance.process->outputs(owned.update_slot, level);
    if (!output) continue;
    if (output->reservations.lsp.pending()) { instance.status = UpdateStatus::invalid_event; return never; }
    active = true;
    catalogs[level] = {&instance.process->level(level)->database(), owned.update_slot};
  }
  if (!active) { egress.lan_active = false; return never; }
  if (!egress.lan_active) {
    if (!egress.broadcast_scan->activate(now)) return never;
    egress.lan_active = true;
    return egress.broadcast_scan->deadline(owned.queued_lsp);
  }
  if (!egress.credits) return egress.pacing;
  if (!budget) return egress.broadcast_scan->deadline(owned.queued_lsp);
  const auto selected = egress.broadcast_scan->begin(now, catalogs, owned.queued_lsp);
  if (selected.status == BroadcastScanStatus::invalid_catalog) {
    instance.status = UpdateStatus::invalid_configuration;
    return never;
  }
  if (!selected.candidate) return egress.broadcast_scan->deadline(owned.queued_lsp);
  const auto level = selected.candidate->level;
  auto output = instance.process->outputs(owned.update_slot, level);
  const auto prepared = output->reservations.lsp.prepare(selected.candidate->id, owned.common().mac,
      owned.destinations.levels[level], maximum_pdu, egress.program.transit_seconds, output_, scratch_, now);
  if (prepared.status == LspEmissionStatus::encoded) {
    --egress.credits;
    --budget;
    egress.lan_lsp = UpdateEgress::LanReservation{level, output->synchronization_epoch, prepared.ticket};
    const auto type = level ? packet::isis::PduType::lsp_l2 : packet::isis::PduType::lsp_l1;
    if (channel.try_send({owned.identity.device, owned.identity.interface_id, owned.identity.physical_port_ordinal,
        owned.identity.configuration_generation, prepared.ticket, static_cast<std::uint8_t>(type),
        owned.identity.instance, output->synchronization_epoch}, output_)) {
      if (channels_.egress_wakeup) channels_.egress_wakeup(channels_.egress_context, shard);
      return never;
    }
    static_cast<void>(output->reservations.lsp.complete(output->synchronization_epoch, prepared.ticket, false, now));
    egress.lan_lsp.reset();
    ++owned.counters.lsp_refused;
  } else if (prepared.status == LspEmissionStatus::too_large) ++owned.counters.lsp_too_large;
  else if (prepared.status == LspEmissionStatus::purge_required) {
    ++owned.counters.purge_pending;
    owned.counters.last_update = UpdateStatus::level_refused;
  } else instance.status = UpdateStatus::capacity;
  static_cast<void>(egress.broadcast_scan->complete(false, now));
  return egress.broadcast_scan->deadline(owned.queued_lsp);
}
} // namespace router::isis
