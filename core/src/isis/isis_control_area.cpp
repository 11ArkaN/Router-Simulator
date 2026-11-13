// The instance control owner derives area state from its own completed L1 SPF,
// then updates L2 metadata and L1 attachment. Queries copy a latest-event
// projection; the area owner counts every generated transition independently.
// Source: iso.10589.2002.area_addresses
#include "router/isis_control_worker.hpp"
#include <algorithm>
#include <stdexcept>
namespace router::isis {
std::unique_ptr<AreaAddressSet> ControlWorker::make_area_set(const UpdateInstanceProgram &program) {
  if (!program.origination || !program.origination->automatic_area_set) return {};
  const auto &records = program.origination->content.records;
  const auto root = std::find_if(records.begin(), records.end(), [](const auto &record) {
    return !record.level && !record.id[6U] && !record.id[7U];
  });
  if (root == records.end() || program.maximum_areas > configuration_profile::area_addresses_maximum)
    throw std::invalid_argument("IS-IS area owner has no admitted L1 root");
  std::vector<NeighborArea> manual;
  manual.reserve(program.maximum_areas);
  packet::isis::TlvCursor options(root->options);
  while (const auto option = options.next()) if (option->code == 1U) {
    packet::isis::AreaAddressCursor addresses(*option);
    while (const auto address = addresses.next()) {
      if (manual.size() == program.maximum_areas) throw std::invalid_argument("IS-IS manual area capacity refused");
      NeighborArea value{};
      value.length = static_cast<std::uint8_t>(address->size());
      std::copy(address->begin(), address->end(), value.bytes.begin());
      manual.push_back(value);
    }
    if (!addresses.valid()) throw std::invalid_argument("Malformed IS-IS manual area option");
  }
  if (!options.valid() || manual.empty()) throw std::invalid_argument("Missing IS-IS manual area identity");
  return std::make_unique<AreaAddressSet>(program.maximum_areas, manual);
}
void ControlWorker::service_area_decision(OwnedInstance &instance, RuntimeClock::time_point now) noexcept {
  auto &origin = *instance.configuration.origination;
  if (!origin.automatic_area_set || !instance.areas || !instance.process || !instance.decisions[0U] ||
      instance.decision_status[0U] != DecisionStatus::applied ||
      instance.consumed_decision_revision[0U] != instance.decision_revisions[0U]) return;
  const AreaSetObserver observer{&instance, +[](void *opaque, const ManualAreaDropped &event) noexcept {
    static_cast<OwnedInstance *>(opaque)->last_area_drop = event;
  }};
  const auto selected = instance.areas->recompute(instance.process->level(0U)->database().database(),
      *instance.decisions[0U], now, observer);
  if (!selected.valid) { instance.status = UpdateStatus::invalid_configuration; return; }
  if (selected.changed && instance.configuration.levels[1U]) instance.local_roots_dirty[1U] = true;
  if (!origin.automatic_area_attachment || !instance.decisions[1U] ||
      instance.decision_status[1U] != DecisionStatus::applied ||
      instance.consumed_decision_revision[1U] != instance.decision_revisions[1U]) return;
  const auto root = std::find_if(origin.content.records.begin(), origin.content.records.end(), [](const auto &record) {
    return !record.level && !record.id[6U] && !record.id[7U];
  });
  if (root == origin.content.records.end()) { instance.status = UpdateStatus::invalid_configuration; return; }
  const bool attached = !origin.suppress_attached_bit && reachable_other_area(
      instance.process->level(1U)->database().database(), *instance.decisions[1U], instance.areas->effective(), now, instance.configuration.local);
  const auto flags = static_cast<std::uint8_t>((root->flags & ~8U) | (attached ? 8U : 0U));
  if (flags != root->flags) { root->flags = flags; instance.local_roots_dirty[0U] = true; }
}
}
