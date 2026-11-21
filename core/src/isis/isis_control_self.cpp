// Accepted encoded update input is classified against this entity's current
// local set. Local content is never copied from a received self LSP. Unknown
// local identities and foreign checksum conflicts use the shared purge owner.
// Source: iso.10589.2002.local_lsp_generation

#include "router/isis_control_worker.hpp"

#include <algorithm>

namespace router::isis {
bool ControlWorker::handle_self_lsp(OwnedCircuit &owned, const packet::isis::PduView &pdu,
    const packet::Frame &frame, UpdateReceiveResult &received, RuntimeClock::time_point now) noexcept {
  auto &instance = *owned.update;
  if (!instance.local || !instance.process || !received.local_lsp) return false;
  const auto header = *received.local_lsp;
  const auto level = received.level;
  const auto *owner = instance.process->level(level);
  if (!owner) return false;
  const auto current = owner->database().database().find(header.id, now);
  if (instance.local->contains(level, header.id)) {
    if (!header.remaining_seconds || !current || current->purge_installed || !current->header.remaining_seconds ||
        compare_lsp_headers(header, current->header) == LspRecency::newer ||
        compare_lsp_headers(header, current->header) == LspRecency::confusion)
      return instance.local->require_after(level, header.id, header.sequence, now);
    received = instance.process->receive_local_copy(owned.update_slot, owned.identity.configuration_generation,
        frame, std::nullopt, now, instance.observer());
    return received.status == UpdateStatus::applied;
  }
  static_cast<void>(instance.local->require_after(level, header.id, header.sequence, now));
  if (!header.remaining_seconds) {
    received = instance.process->receive_retired_local_purge(owned.update_slot, owned.identity.configuration_generation,
        frame, std::nullopt, now, instance.observer());
    return received.status == UpdateStatus::applied;
  }
  if (current && current->purge_installed && compare_lsp_headers(header, current->header) == LspRecency::older) {
    received = instance.process->receive_local_copy(owned.update_slot, owned.identity.configuration_generation,
        frame, std::nullopt, now, instance.observer());
    return received.status == UpdateStatus::applied;
  }
  // Runtime admission currently supports no authentication selection. Future
  // key integration must pass actual transmit/RX leases to every path here.
  const auto purged = instance.process->purge_unknown_source(level, header, pdu.maximum_area_addresses,
      {}, now, scratch_.options, scratch_.pdu, instance.observer());
  received.status = purged.status;
  if (purged.status != UpdateStatus::applied) return false;
  if (purged.origin.install == LspInstallResult::installed) return true;
  received = instance.process->receive_local_copy(owned.update_slot, owned.identity.configuration_generation,
      frame, std::nullopt, now, instance.observer());
  return received.status == UpdateStatus::applied;
}
void ControlWorker::handle_confusion(OwnedCircuit &owned, const packet::isis::PduView &pdu,
    UpdateReceiveResult &received, RuntimeClock::time_point now) noexcept {
  auto &instance = *owned.update;
  if (!instance.process) return;
  const auto apply = [&](const packet::isis::LspView &conflicting) {
    if (instance.local && instance.local->contains(received.level, conflicting.id)) {
      static_cast<void>(instance.local->require_after(received.level, conflicting.id, conflicting.sequence, now));
      return;
    }
    if (!instance.local && std::equal(instance.configuration.local.begin(), instance.configuration.local.end(), conflicting.id.begin())) {
      // Manual raw-PDU experiments have no semantic current-set owner. Keep
      // their own-source conflict explicit instead of inventing local content.
      received.status = UpdateStatus::self_originated;
      return;
    }
    if (instance.local)
      static_cast<void>(instance.local->require_after(received.level, conflicting.id, conflicting.sequence, now));
    const auto purged = instance.process->finalize_confusion(received.level, conflicting, {}, now,
        scratch_.options, scratch_.pdu, instance.observer());
    if (purged.status != UpdateStatus::applied) received.status = purged.status;
  };
  if (received.lsp.database.install == LspInstallResult::confusion) {
    if (const auto header = packet::isis::lsp(pdu)) apply(*header);
    return;
  }
  if (received.snp.database.status != SnpBatchStatus::accepted || !received.snp.database.confusions) return;
  const auto *owner = instance.process->level(received.level);
  if (!owner) return;
  packet::isis::SnpEntryCursor entries(pdu.tlvs);
  while (const auto entry = entries.next()) {
    const auto current = owner->database().database().find(entry->id, now);
    if (!current) continue;
    const packet::isis::LspView reported{entry->id, entry->remaining_seconds, entry->sequence, entry->checksum, 0U};
    if (compare_lsp_headers(reported, current->header) == LspRecency::confusion) apply(reported);
  }
}
} // namespace router::isis
